use alloc::{
    boxed::Box,
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    vec,
    vec::Vec,
};
use core::{
    cell::RefCell,
    sync::atomic::{AtomicBool, Ordering},
};

use sha2::{Digest, Sha256};
use trnm_consensus_safety_rules::{
    FinalizedBlockRefV1, InertSafetyTransitionKindV1, InertSafetyTransitionV1,
    PureHotStuffSafetyKernelV1, SafetyRulesContextV1, SafetyRulesStateSeedV1, SafetyRulesStateV1,
};
use trnm_consensus_types::{
    validate_root_bound_regular_body_v0, Block, BlockHeader, BlockId, BlockKind,
    CanonicalSignIntentV0, CanonicalSignable, CertificateId, ConsensusParametersV0,
    ContextAuthorizedQcV0, Epoch, EpochGeometryV0, EquivocationEvidence, FinalityProofV0,
    GenesisQcApplicationBindingV0, GenesisQcV0, Height, QcRef, QcReferenceV0, QuorumCertificate,
    RootBoundRegularBodyV0, SignatureVerifier, SignedProposalV0, TimeoutCertificateV0, TimeoutVote,
    ValidationError, ValidatorId, ValidatorSet, View, Vote,
};

use crate::{
    block_tree::{Ancestry, BlockTree, PayloadTransition},
    model::{DeferredEffect, PendingPersistence},
    native_valid_result_checksum_v0, safety_state_record_config_ref_v0,
    ApplicationFinalizationReceiptRejectionV0, ApplicationFinalizationReceiptV0,
    ApplicationSealedValidV0, AuthenticatedGenesisApplicationParentV0, BarrierId,
    CoreAcceptedApplicationValidDV0, CoreConfig, CoreError,
    CoreIssuedApplicationFinalizationApplyAuthorityV0, CoreIssuedApplicationFinalizationPermitV0,
    CoreIssuedApplicationSealAuthorityV0, DurableFinalizationV0,
    DurablePayloadValidationCompletionV0, DurablePayloadValidationObligationV0,
    DurablePayloadValidationResultV1, DurableStateSyncAnchorV0, Effect, FinalizedTip, Input,
    InvalidPayloadReference, NativeFinalizationAppliedPersistenceV0,
    NativeFinalizationAppliedPostAckActionV0, NativeFinalizationAppliedRecoveryTransitionV0,
    NativeValidPostAckActionV0, OutboundMessage, PayloadTerminalFact, PayloadTerminalResult,
    PayloadValidationParentV0, PayloadValidationRequest, PayloadValidationResult,
    PayloadValidationRouteV0, PendingStandaloneQcSync, PendingTcHighQcSync, Result, SafetyHalt,
    SafetyState, SafetyStatePersistenceBindingV0, SafetyStatePersistenceV0,
    SafetyStateRecordContextV0, SafetyStateRecordLimitsV0, SignIntent,
    StateSyncAnchorOrdinaryPromotionPersistenceV0, ValidationId,
    CORE_MAX_RETAINED_VALIDATED_PROPOSAL_RESOURCE_BYTES_V1,
    CORE_SAFETY_RULES_MAX_ANCESTRY_BLOCKS_V1, SAFETY_STATE_SCHEMA_VERSION,
};

type ObservationKey = (Epoch, View, ValidatorId);

const CORE_ACCEPTED_APPLICATION_VALID_DELIVERY_DIGEST_DOMAIN_V0: &str =
    "trnm.consensus-core.application-valid-delivery.v0";
const FINALIZED_PREFIX_CHAIN_ROOT_DOMAIN_V0: &str =
    "trnm.consensus-core.finalized-prefix-chain-root.v0";
const ANCHORED_ORDINARY_REHYDRATE_DIGEST_DOMAIN_V0: &str =
    "trnm.consensus-core.anchored-ordinary-rehydrate.v0";
const PREAUTHENTICATION_CONTEXT_DIGEST_DOMAIN_V0: &str =
    "trnm.consensus-core.preauthentication-context.v0";
const PREAUTHENTICATION_INPUT_DIGEST_DOMAIN_V0: &str =
    "trnm.consensus-core.preauthentication-input.v0";
// This is a performance bound only. If one message contains more distinct
// signatures, the verifier safely falls back to the underlying verifier after
// the bound is reached; no acceptance decision depends on cache residency.
const PREAUTHENTICATION_CACHE_MAX_ENTRIES_V0: usize = 256;

fn preauthentication_hash_v0(domain: &str, parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"trnm.domain.hash.v1");
    hasher.update((domain.len() as u64).to_be_bytes());
    hasher.update(domain.as_bytes());
    for part in parts {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part);
    }
    hasher.finalize().into()
}

/// Recovery-stable commitment to the exact Core-authenticated finalized
/// prefix. This is not a per-block Merkle accumulator: the finalized block ID
/// is the canonical `BlockHeader` hash and recursively binds `parent_id`, so
/// it already commits the verified ancestor chain. The extra domain-separated
/// envelope binds that hash-linked prefix to this chain/genesis and to Core's
/// exact durable finalized coordinates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FinalizedChainRootV0([u8; 32]);

impl FinalizedChainRootV0 {
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

fn core_accepted_application_valid_delivery_digest_v0(
    state: &SafetyState,
    route: PayloadValidationRouteV0,
    validation_id: ValidationId,
    valid_result_checksum: [u8; 32],
    post_ack_action: NativeValidPostAckActionV0,
) -> [u8; 32] {
    let route = match route {
        PayloadValidationRouteV0::Proposal => [0_u8],
        PayloadValidationRouteV0::Synced => [1_u8],
    };
    let revision = state.revision().to_be_bytes();
    let validation_view = validation_id.view().get().to_be_bytes();
    let validation_generation = validation_id.generation().to_be_bytes();
    let post_ack_action = post_ack_action.code().to_be_bytes();
    let chain_id = state.chain_id();
    let block_id = validation_id.block_id();
    let parts: [&[u8]; 8] = [
        chain_id.as_str().as_bytes(),
        &route,
        block_id.as_bytes(),
        &validation_view,
        &validation_generation,
        &revision,
        &valid_result_checksum,
        &post_ack_action,
    ];
    let mut hasher = Sha256::new();
    hasher.update(b"trnm.domain.hash.v1");
    hasher.update(
        (CORE_ACCEPTED_APPLICATION_VALID_DELIVERY_DIGEST_DOMAIN_V0.len() as u64).to_be_bytes(),
    );
    hasher.update(CORE_ACCEPTED_APPLICATION_VALID_DELIVERY_DIGEST_DOMAIN_V0.as_bytes());
    for part in parts {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part);
    }
    hasher.finalize().into()
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ObservedProposal {
    proposal: SignedProposalV0,
    authenticated_parent_timestamp_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TerminalFactTransition {
    NotTerminal,
    Repeated,
    Inserted,
    Conflicting,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuthenticatedTcOutcome {
    MissingReferences,
    Complete,
}

/// A deterministic, single-threaded PoCO-BFT state machine.
///
/// `Core` owns no clock, network, database, or private key. All interaction
/// with those facilities is represented by [`Input`] and [`Effect`]. Failed
/// steps are transactional: no state is changed when `step` returns an error.
#[derive(Debug)]
struct CorePersistenceAffinityV0(Arc<()>);

pub(crate) struct CorePersistenceSealV0(());

impl CorePersistenceSealV0 {
    const fn new() -> Self {
        Self(())
    }
}

impl CorePersistenceAffinityV0 {
    fn new() -> Self {
        Self(Arc::new(()))
    }

    fn preserve(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

impl Clone for CorePersistenceAffinityV0 {
    fn clone(&self) -> Self {
        Self::new()
    }
}

impl PartialEq for CorePersistenceAffinityV0 {
    fn eq(&self, _other: &Self) -> bool {
        true
    }
}

impl Eq for CorePersistenceAffinityV0 {}

/// Process-local identity for one live Core's admission boundary.
///
/// A preauthentication token carries this identity in addition to its
/// content digests. Public Core clones and recovered Cores receive a fresh
/// identity; only the private transactional clone preserves it. Consequently
/// a token cannot become a cross-Core or cross-restart authority even when the
/// input and configuration bytes happen to be identical.
#[derive(Debug)]
struct CorePreauthenticationAffinityV0(Arc<()>);

impl CorePreauthenticationAffinityV0 {
    fn new() -> Self {
        Self(Arc::new(()))
    }

    fn preserve(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

impl Clone for CorePreauthenticationAffinityV0 {
    fn clone(&self) -> Self {
        Self::new()
    }
}

impl PartialEq for CorePreauthenticationAffinityV0 {
    fn eq(&self, _other: &Self) -> bool {
        true
    }
}

impl Eq for CorePreauthenticationAffinityV0 {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PreauthenticatedInputKindV0 {
    Proposal,
    SyncedProposal,
    Vote,
    TimeoutVote,
    QuorumCertificate,
    TimeoutCertificate,
}

/// Private, one-step admission evidence. It is deliberately not serializable,
/// not stored in `Core`/`SafetyState`, and not cloneable by callers.
#[derive(Debug)]
pub(crate) struct PreauthenticatedInputV0 {
    affinity: Arc<()>,
    kind: PreauthenticatedInputKindV0,
    context_digest: [u8; 32],
    input_digest: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct AuthenticationCacheKeyV0 {
    context_digest: [u8; 32],
    input_digest: [u8; 32],
    validator_id: ValidatorId,
    signing_root: [u8; 32],
    signature: [u8; 64],
}

/// A per-step verifier wrapper. It memoizes only successful cryptographic
/// checks, and only inside the exact token namespace. All structural,
/// ancestry, epoch, lock, and state checks continue to execute in handlers.
struct PreauthenticationVerifierV0<'a, V> {
    verifier: &'a V,
    context_digest: [u8; 32],
    input_digest: [u8; 32],
    max_entries: usize,
    verified: RefCell<BTreeSet<AuthenticationCacheKeyV0>>,
}

impl<'a, V> PreauthenticationVerifierV0<'a, V> {
    fn new(verifier: &'a V, token: &PreauthenticatedInputV0, max_entries: usize) -> Self {
        Self {
            verifier,
            context_digest: token.context_digest,
            input_digest: token.input_digest,
            max_entries: max_entries.max(1),
            verified: RefCell::new(BTreeSet::new()),
        }
    }
}

impl<V: SignatureVerifier> SignatureVerifier for PreauthenticationVerifierV0<'_, V> {
    fn verify(
        &self,
        validator: &trnm_consensus_types::Validator,
        signing_root: &trnm_consensus_types::SigningRoot,
        signature: &trnm_consensus_types::SignatureBytes,
    ) -> bool {
        let key = AuthenticationCacheKeyV0 {
            context_digest: self.context_digest,
            input_digest: self.input_digest,
            validator_id: validator.id(),
            signing_root: *signing_root.as_bytes(),
            signature: *signature.as_bytes(),
        };
        if self.verified.borrow().contains(&key) {
            return true;
        }
        if !self.verifier.verify(validator, signing_root, signature) {
            return false;
        }
        let mut verified = self.verified.borrow_mut();
        if verified.len() < self.max_entries {
            // A full cache is a performance boundary only. Returning the
            // successful result without retaining it safely falls back to a
            // fresh underlying verification on the next duplicate.
            verified.insert(key);
        }
        true
    }
}

/// Volatile identity of one exact Core-owned validation slot.
///
/// A public Core clone receives fresh identities, while the Core's private
/// transactional clone preserves them. This mirrors the persistence-affinity
/// rule and prevents a live Valid permit issued by one Core instance from
/// being replayed into a throwaway clone with otherwise equal protocol state.
#[derive(Debug)]
struct CorePayloadValidationAffinityV0(Arc<()>);

impl CorePayloadValidationAffinityV0 {
    fn new() -> Self {
        Self(Arc::new(()))
    }

    fn preserve(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

impl Clone for CorePayloadValidationAffinityV0 {
    fn clone(&self) -> Self {
        Self::new()
    }
}

impl PartialEq for CorePayloadValidationAffinityV0 {
    fn eq(&self, _other: &Self) -> bool {
        true
    }
}

impl Eq for CorePayloadValidationAffinityV0 {}

/// Volatile identity shared only by one live Core and its one installed
/// ApplicationStore seal authority.
///
/// Public Core clones receive a fresh identity and a fresh one-shot install
/// gate. Internal transactional clones preserve both so `Core::step` can
/// validate an application-sealed proof inside its private snapshot.
#[derive(Debug)]
struct CoreApplicationSealAffinityV0 {
    affinity: Arc<()>,
    authority_issued: Arc<AtomicBool>,
}

impl CoreApplicationSealAffinityV0 {
    fn new() -> Self {
        Self {
            affinity: Arc::new(()),
            authority_issued: Arc::new(AtomicBool::new(false)),
        }
    }

    fn preserve(&self) -> Self {
        Self {
            affinity: Arc::clone(&self.affinity),
            authority_issued: Arc::clone(&self.authority_issued),
        }
    }
}

impl Clone for CoreApplicationSealAffinityV0 {
    fn clone(&self) -> Self {
        Self::new()
    }
}

impl PartialEq for CoreApplicationSealAffinityV0 {
    fn eq(&self, _other: &Self) -> bool {
        true
    }
}

impl Eq for CoreApplicationSealAffinityV0 {}

/// Volatile binding between one live Core, its installed application apply
/// authority, and the current exact durable finalization queue front.
///
/// Public Core clones receive fresh store/front identities and issuance
/// gates.  Internal transactional clones preserve them.  A successful front
/// acknowledgement rotates only the front identity, keeping the installed
/// application authority valid for the next ordered entry.
#[derive(Debug)]
struct CoreApplicationFinalizationAffinityV0 {
    application_apply_affinity: Arc<()>,
    authority_issued: Arc<AtomicBool>,
    front_affinity: Arc<()>,
    front_permit_issued: Arc<AtomicBool>,
}

impl CoreApplicationFinalizationAffinityV0 {
    fn new() -> Self {
        Self {
            application_apply_affinity: Arc::new(()),
            authority_issued: Arc::new(AtomicBool::new(false)),
            front_affinity: Arc::new(()),
            front_permit_issued: Arc::new(AtomicBool::new(false)),
        }
    }

    fn preserve(&self) -> Self {
        Self {
            application_apply_affinity: Arc::clone(&self.application_apply_affinity),
            authority_issued: Arc::clone(&self.authority_issued),
            front_affinity: Arc::clone(&self.front_affinity),
            front_permit_issued: Arc::clone(&self.front_permit_issued),
        }
    }

    fn rotate_front(&mut self) {
        self.front_affinity = Arc::new(());
        self.front_permit_issued = Arc::new(AtomicBool::new(false));
    }
}

impl Clone for CoreApplicationFinalizationAffinityV0 {
    fn clone(&self) -> Self {
        Self::new()
    }
}

impl PartialEq for CoreApplicationFinalizationAffinityV0 {
    fn eq(&self, _other: &Self) -> bool {
        true
    }
}

impl Eq for CoreApplicationFinalizationAffinityV0 {}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PendingPayloadValidationV0 {
    proposal: SignedProposalV0,
    affinity: CorePayloadValidationAffinityV0,
}

impl PendingPayloadValidationV0 {
    fn new(proposal: SignedProposalV0) -> Self {
        Self {
            proposal,
            affinity: CorePayloadValidationAffinityV0::new(),
        }
    }

    fn preserve(&self) -> Self {
        Self {
            proposal: self.proposal.clone(),
            affinity: self.affinity.preserve(),
        }
    }
}

/// The trusted host's decision for one exact recovery-time validation job.
///
/// V0 deliberately supports only a job whose already-durable application
/// result is `DeterministicallyInvalid`.  `AcceptDeterministicallyInvalid` is
/// therefore not a fresh execution result: it is the trusted host's assertion
/// that its independently recovered journal contains that terminal result for
/// every fact exposed by the challenge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadValidationRecoveryDecisionV0 {
    AcceptDeterministicallyInvalid,
    Reject,
}

/// Trusted-host reconciliation boundary for a crash-surviving validation job.
///
/// The Core authenticates the durable obligation and constructs the challenge,
/// but it cannot inspect or authenticate the application's separate WAL.  A
/// production host must implement this trait by matching the complete challenge
/// against that WAL.  Returning `AcceptDeterministicallyInvalid` without such a
/// check violates the host integration contract; it does not turn caller data
/// into Core-authenticated application state.
pub trait PayloadValidationRecoveryReconcilerV0 {
    fn reconcile_deterministically_invalid_obligation_v0(
        &mut self,
        challenge: &PayloadValidationRecoveryChallengeV0,
    ) -> PayloadValidationRecoveryDecisionV0;
}

/// One Core-authenticated, process-local obligation recovery challenge.
///
/// This value is intentionally non-cloneable, has no public parts constructor,
/// and is owned by its recovery session.  Its affinity is meaningful only in
/// this process; the complete durable obligation remains the cross-process
/// identity that a trusted host must reconcile with its application journal.
#[derive(Debug)]
#[must_use = "the exact recovery challenge must be reconciled before a live Core can exist"]
pub struct PayloadValidationRecoveryChallengeV0 {
    safety_head_revision: u64,
    obligation: DurablePayloadValidationObligationV0,
    affinity: Arc<()>,
}

impl PayloadValidationRecoveryChallengeV0 {
    pub const fn safety_head_revision(&self) -> u64 {
        self.safety_head_revision
    }

    pub const fn route(&self) -> PayloadValidationRouteV0 {
        self.obligation.route()
    }

    pub const fn id(&self) -> ValidationId {
        self.obligation.id()
    }

    pub const fn proposal(&self) -> &SignedProposalV0 {
        self.obligation.proposal()
    }

    pub const fn parent(&self) -> &PayloadValidationParentV0 {
        self.obligation.parent()
    }

    pub const fn first_recorded_revision(&self) -> u64 {
        self.obligation.first_recorded_revision()
    }

    /// Compares only the process-local recovery-session affinity.
    ///
    /// This lets a trusted reconciler reject a challenge accidentally routed
    /// through another concurrently constructed recovery session without
    /// exposing or serializing the affinity itself.
    pub fn same_recovery_instance_v0(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.affinity, &other.affinity)
    }
}

/// Inert two-phase recovery session for one durable validation obligation.
///
/// No live Core is exposed by this type.  The only consuming exit invokes a
/// trusted-host reconciler over the internally owned challenge and returns a
/// Core only after an explicit deterministic-invalid acceptance.
#[derive(Debug)]
#[must_use = "dropping the session keeps payload-validation recovery fail-closed"]
pub struct PayloadValidationRecoverySessionV0 {
    core: Core,
    challenge: PayloadValidationRecoveryChallengeV0,
}

/// Inert, read-only commissioning facts for one authenticated genesis
/// application parent.
///
/// The value owns no live [`Core`] and grants no input, signing, timer,
/// networking, payload-validation, or finalization authority. Its canonical
/// SafetyState-record configuration reference binds the complete Core config,
/// verifier profile, codec layout, and record limits selected by the trusted
/// host. The downstream durable-store protocol must still install and
/// authenticate its own typed bootstrap transition before any later bounded
/// application join can occur.
///
/// This is inert comparison data, not a safety capability. The wrapper is
/// intentionally not [`Clone`] to discourage accidental duplication, but no
/// linearity or one-shot-authority claim is made: callers may freely copy or
/// clone the read-only facts returned by its accessors.
///
/// The prepared surface deliberately exposes no live Core:
///
/// ```compile_fail
/// use trnm_consensus_core::PreparedAuthenticatedGenesisApplicationBootstrapV0;
///
/// fn leak_core(prepared: &PreparedAuthenticatedGenesisApplicationBootstrapV0) {
///     let _ = prepared.core();
/// }
/// ```
///
/// The complete retained config is comparison-only and has no getter:
///
/// ```compile_fail
/// use trnm_consensus_core::PreparedAuthenticatedGenesisApplicationBootstrapV0;
///
/// fn leak_config(prepared: &PreparedAuthenticatedGenesisApplicationBootstrapV0) {
///     let _ = prepared.core_config_v0();
/// }
/// ```
///
/// It also has no consuming raw-parts escape hatch:
///
/// ```compile_fail
/// use trnm_consensus_core::PreparedAuthenticatedGenesisApplicationBootstrapV0;
///
/// fn leak_parts(prepared: PreparedAuthenticatedGenesisApplicationBootstrapV0) {
///     let _ = prepared.into_parts();
/// }
/// ```
///
/// It cannot process runtime input:
///
/// ```compile_fail
/// use trnm_consensus_core::PreparedAuthenticatedGenesisApplicationBootstrapV0;
///
/// fn drive(prepared: &mut PreparedAuthenticatedGenesisApplicationBootstrapV0) {
///     let _ = prepared.step();
/// }
/// ```
///
/// It cannot issue application authority:
///
/// ```compile_fail
/// use trnm_consensus_core::PreparedAuthenticatedGenesisApplicationBootstrapV0;
///
/// fn issue(prepared: &PreparedAuthenticatedGenesisApplicationBootstrapV0) {
///     let _ = prepared.issue_application_seal_authority_v0();
/// }
/// ```
///
/// Finally, the wrapper itself remains non-cloneable:
///
/// ```compile_fail
/// use trnm_consensus_core::PreparedAuthenticatedGenesisApplicationBootstrapV0;
///
/// fn require_clone<T: Clone>() {}
/// fn main() {
///     require_clone::<PreparedAuthenticatedGenesisApplicationBootstrapV0>();
/// }
/// ```
#[derive(Debug)]
#[must_use = "the prepared authenticated-genesis facts must be durably installed or discarded"]
pub struct PreparedAuthenticatedGenesisApplicationBootstrapV0 {
    core_config: CoreConfig,
    safety_state: SafetyState,
    authenticated_genesis_application_parent: AuthenticatedGenesisApplicationParentV0,
    safety_state_record_config_ref: [u8; 32],
}

impl PreparedAuthenticatedGenesisApplicationBootstrapV0 {
    /// Compares the complete Core configuration retained at preparation time
    /// without exposing or cloning that configuration.
    pub fn matches_core_config_v0(&self, candidate: &CoreConfig) -> bool {
        &self.core_config == candidate
    }

    /// Exact schema-v12, revision-zero inert SafetyState.
    pub const fn safety_state(&self) -> &SafetyState {
        &self.safety_state
    }

    /// Complete operator-pinned application parent carried by both the config
    /// and the prepared SafetyState.
    pub const fn authenticated_genesis_application_parent_v0(
        &self,
    ) -> AuthenticatedGenesisApplicationParentV0 {
        self.authenticated_genesis_application_parent
    }

    /// Canonical SafetyState-record configuration reference, including the
    /// trusted verifier profile and the selected record-resource envelope.
    pub const fn safety_state_record_config_ref_v0(&self) -> [u8; 32] {
        self.safety_state_record_config_ref
    }
}

/// Exact live-only phases of the bounded authenticated-genesis h1 driver.
///
/// This classifier names persistence cuts, not generic consensus modes.  No
/// value in this enum can reconstruct the private Core or authorize an input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthenticatedGenesisApplicationH1OfflinePhaseV0 {
    CommissionedRev0,
    ObligationPersistencePendingRev1,
    ValidationRequestReleasedRev1,
    CompletionPersistencePendingRev2,
    CompletedRev2,
}

/// Inert process-local consensus context retained by the bounded h1 owner.
///
/// These values are copied from the owner's already validated private
/// [`CoreConfig`]. They carry no Core, input/effect surface, persistence
/// affinity, or application authority. Construction remains private so a
/// registrar can compare this context to commissioned App/Safety facts but
/// cannot substitute caller-selected consensus material.
///
/// ```compile_fail
/// use trnm_consensus_core::AuthenticatedGenesisApplicationH1OfflineContextFactsV0;
///
/// fn forge() {
///     let _ = AuthenticatedGenesisApplicationH1OfflineContextFactsV0::new();
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedGenesisApplicationH1OfflineContextFactsV0 {
    authenticated_genesis_application_parent: AuthenticatedGenesisApplicationParentV0,
    safety_state_record_config_ref: [u8; 32],
    validator_set: ValidatorSet,
    consensus_parameters: ConsensusParametersV0,
    trusted_genesis_timestamp_ms: u64,
}

impl AuthenticatedGenesisApplicationH1OfflineContextFactsV0 {
    pub const fn authenticated_genesis_application_parent_v0(
        &self,
    ) -> AuthenticatedGenesisApplicationParentV0 {
        self.authenticated_genesis_application_parent
    }

    pub const fn safety_state_record_config_ref_v0(&self) -> [u8; 32] {
        self.safety_state_record_config_ref
    }

    pub const fn validator_set_v0(&self) -> &ValidatorSet {
        &self.validator_set
    }

    pub const fn consensus_parameters_v0(&self) -> &ConsensusParametersV0 {
        &self.consensus_parameters
    }

    pub const fn trusted_genesis_timestamp_ms_v0(&self) -> u64 {
        self.trusted_genesis_timestamp_ms
    }
}

/// Application-owned registration boundary for the bounded authenticated-
/// genesis h1 driver.
///
/// Core constructs the live driver and its sole seal-only authority together,
/// but exposes neither value through the activation bundle. A registrar must
/// consume both linear values in one call and return an application-owned
/// output which keeps them behind its own typestate surface. If registration
/// can fail, the registrar's error is responsible for retaining or
/// quarantining both values; Core cannot safely reconstruct either one.
///
/// This is a linked-host TCB boundary, not a sandbox against an adversarial
/// Rust crate. Production Node must construct only the audited App registrar
/// and must not export the bundle, registrar, or resulting owner. The opaque
/// combined owner below narrows accidental detachment; it does not make an
/// arbitrary trait implementation trustworthy.
pub trait AuthenticatedGenesisApplicationH1OfflineApplicationRegistrarV0 {
    type Output;
    type Error;

    fn register_authenticated_genesis_application_h1_offline_v0(
        self,
        owner: AuthenticatedGenesisApplicationH1OfflineApplicationOwnerV0,
    ) -> core::result::Result<Self::Output, Self::Error>;
}

/// Opaque application-owned union of the bounded h1 Core driver and its sole
/// seal authority.
///
/// Keeping both linear values behind this wrapper is essential: a public
/// registrar trait may be implemented by any downstream crate, so the
/// registrar must never receive either raw owner. The wrapper has no parts,
/// Core, authority, conversion, or dereference escape hatch. It exposes only
/// the already-bounded h1 protocol and synchronous sealing operations whose
/// authority never leaves the value.
///
/// ```compile_fail
/// use trnm_consensus_core::AuthenticatedGenesisApplicationH1OfflineApplicationOwnerV0;
/// fn leak(owner: AuthenticatedGenesisApplicationH1OfflineApplicationOwnerV0) {
///     let _ = owner.into_parts();
/// }
/// ```
///
/// ```compile_fail
/// use trnm_consensus_core::AuthenticatedGenesisApplicationH1OfflineApplicationOwnerV0;
/// fn leak(owner: &AuthenticatedGenesisApplicationH1OfflineApplicationOwnerV0) {
///     let _ = owner.application_seal_authority_v0();
/// }
/// ```
#[must_use = "the opaque h1 application owner must complete or remain durably fenced"]
pub struct AuthenticatedGenesisApplicationH1OfflineApplicationOwnerV0 {
    core: AuthenticatedGenesisApplicationH1OfflineValidationV0,
    authority: CoreIssuedApplicationSealAuthorityV0,
}

impl core::fmt::Debug for AuthenticatedGenesisApplicationH1OfflineApplicationOwnerV0 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("AuthenticatedGenesisApplicationH1OfflineApplicationOwnerV0")
            .field("phase", &self.core.phase_v0())
            .field("retains_private_core_owner", &true)
            .field("retains_private_application_authority", &true)
            .finish_non_exhaustive()
    }
}

impl AuthenticatedGenesisApplicationH1OfflineApplicationOwnerV0 {
    /// Exact retained proposal, available only after the bounded owner has
    /// reached CompletedRev2.
    ///
    /// This is inert comparison data and grants no Core, seal, persistence,
    /// callback, or application authority.
    pub fn exact_completed_h1_proposal_v0(&self) -> Option<&SignedProposalV0> {
        matches!(
            self.phase_v0(),
            Ok(AuthenticatedGenesisApplicationH1OfflinePhaseV0::CompletedRev2)
        )
        .then(|| self.core.exact_h1.as_deref())
        .flatten()
    }

    /// Exact validation identity retained by CompletedRev2.
    pub fn exact_completed_validation_id_v0(&self) -> Option<ValidationId> {
        matches!(
            self.phase_v0(),
            Ok(AuthenticatedGenesisApplicationH1OfflinePhaseV0::CompletedRev2)
        )
        .then(|| self.core.core.safety.payload_validation_completions()[0].id())
    }

    /// Reconstructs inert terminal facts from the completed bounded owner.
    /// The returned value contains no live Core or persistence affinity.
    pub fn exact_completed_facts_v0(&self) -> Option<AuthenticatedGenesisApplicationH1CompletedV0> {
        if self.phase_v0().ok()? != AuthenticatedGenesisApplicationH1OfflinePhaseV0::CompletedRev2 {
            return None;
        }
        Some(AuthenticatedGenesisApplicationH1CompletedV0 {
            proposal: self.core.exact_h1.as_ref()?.clone(),
            completion: self.core.core.safety.payload_validation_completions()[0].clone(),
            terminal_fact: self.core.core.safety.payload_terminal_facts()[0],
            authenticated_parent_binding_ref: self.core.expected_payload_parent_binding_ref,
        })
    }

    pub fn phase_v0(&self) -> Result<AuthenticatedGenesisApplicationH1OfflinePhaseV0> {
        self.core.phase_v0()
    }

    /// Borrow-only splice preflight for App's reservation boundary.
    ///
    /// Shape-equal requests from another reconstructed Core are rejected by the
    /// process-local pending-validation affinity before App claims a request or
    /// performs any durable reservation write.
    pub fn accepts_validation_request_v0(
        &self,
        request: &AuthenticatedGenesisApplicationH1ValidationRequestV0,
    ) -> bool {
        if !matches!(
            self.phase_v0(),
            Ok(AuthenticatedGenesisApplicationH1OfflinePhaseV0::ValidationRequestReleasedRev1)
        ) {
            return false;
        }
        let request = &request.request;
        let Some(pending) = self.core.core.pending_sync_validations.get(&request.id()) else {
            return false;
        };
        let [obligation] = self.core.core.safety.payload_validation_obligations() else {
            return false;
        };
        request.route() == PayloadValidationRouteV0::Synced
            && request.matches_valid_affinity_v0(&pending.affinity.0)
            && pending.proposal.block() == request.block()
            && obligation.route() == request.route()
            && obligation.id() == request.id()
            && obligation.proposal().block() == request.block()
            && obligation.parent() == request.parent()
            && obligation
                .parent_binding_ref_v0()
                .ok()
                .zip(request.parent_binding_ref_v0().ok())
                .is_some_and(|(obligation_ref, request_ref)| obligation_ref == request_ref)
    }

    /// Returns only the exact inert consensus context while this owner is
    /// still at the commissioned revision-zero boundary.
    ///
    /// Once h1 admission creates a durable obligation, consumers must use the
    /// typed request/persistence carriers instead of reminting a startup
    /// expectation from a later protocol phase.
    pub fn h1_context_facts_v0(
        &self,
    ) -> Result<AuthenticatedGenesisApplicationH1OfflineContextFactsV0> {
        if self.phase_v0()? != AuthenticatedGenesisApplicationH1OfflinePhaseV0::CommissionedRev0 {
            return Err(CoreError::AuthenticatedGenesisApplicationH1OfflineRejected(
                "h1 context facts are available only at commissioned revision zero",
            ));
        }
        let config = &self.core.core.config;
        let authenticated_parent = config
            .authenticated_genesis_application_parent_v0()
            .copied()
            .ok_or(CoreError::AuthenticatedGenesisApplicationH1OfflineRejected(
                "offline h1 Core lost its authenticated application parent",
            ))?;
        if self.core.safety_state_record_config_ref == [0; 32]
            || self
                .core
                .commissioned_rev0
                .authenticated_genesis_application_parent_v0()
                != Some(&authenticated_parent)
            || authenticated_parent.timestamp_ms() != config.trusted_genesis_timestamp_ms()
        {
            return Err(CoreError::AuthenticatedGenesisApplicationH1OfflineRejected(
                "offline h1 Core context differs from its commissioned revision-zero state",
            ));
        }
        Ok(AuthenticatedGenesisApplicationH1OfflineContextFactsV0 {
            authenticated_genesis_application_parent: authenticated_parent,
            safety_state_record_config_ref: self.core.safety_state_record_config_ref,
            validator_set: config.validator_set().clone(),
            consensus_parameters: *config.consensus_parameters(),
            trusted_genesis_timestamp_ms: config.trusted_genesis_timestamp_ms(),
        })
    }

    pub fn submit_exact_h1_synced_proposal_v0<V: SignatureVerifier>(
        &mut self,
        proposal: SignedProposalV0,
        verifier: &V,
    ) -> Result<AuthenticatedGenesisApplicationH1ObligationPersistenceV0> {
        self.core
            .submit_exact_h1_synced_proposal_v0(proposal, verifier)
    }

    pub fn issue_safety_persistence_binding_v0(
        &mut self,
    ) -> Result<AuthenticatedGenesisApplicationH1OfflineSafetyPersistenceBindingV0> {
        self.core.issue_safety_persistence_binding_v0()
    }

    pub fn acknowledge_obligation_persisted_v0<V: SignatureVerifier>(
        &mut self,
        persistence: &AuthenticatedGenesisApplicationH1ObligationPersistenceV0,
        acknowledged_barrier: BarrierId,
        verifier: &V,
    ) -> Result<AuthenticatedGenesisApplicationH1ValidationRequestV0> {
        self.core
            .acknowledge_obligation_persisted_v0(persistence, acknowledged_barrier, verifier)
    }

    pub fn seal_after_application_store_commit_v0(
        &self,
        permit: crate::CoreIssuedValidPermitV0,
        commitments: trnm_consensus_types::ValidatedBlockCommitmentsV0,
        artifact_ref: crate::ValidatedPayloadArtifactRefV0,
    ) -> ApplicationSealedValidV0 {
        self.authority
            .seal_after_application_store_commit_v0(permit, commitments, artifact_ref)
    }

    pub fn accept_application_sealed_valid_v0<V: SignatureVerifier>(
        &mut self,
        proof: &ApplicationSealedValidV0,
        verifier: &V,
    ) -> Result<AuthenticatedGenesisApplicationH1CompletionPersistenceV0> {
        self.core
            .accept_application_sealed_valid_v0(proof, verifier)
    }

    pub fn seal_authenticated_genesis_h1_native_valid_transition_v0(
        &self,
        completion: AuthenticatedGenesisApplicationH1CompletionPersistenceV0,
        facts: ApplicationNativeValidDeliveryFactsV0,
    ) -> Result<ApplicationSealedNativeValidTransitionV0> {
        self.authority
            .seal_authenticated_genesis_h1_native_valid_transition_v0(completion, facts)
    }

    pub fn acknowledge_completion_persisted_v0<V: SignatureVerifier>(
        &mut self,
        sealed_transition: &ApplicationSealedNativeValidTransitionV0,
        acknowledged_barrier: BarrierId,
        verifier: &V,
    ) -> Result<AuthenticatedGenesisApplicationH1CompletedV0> {
        self.core.acknowledge_completion_persisted_v0(
            sealed_transition.completion_persistence_v0(),
            acknowledged_barrier,
            verifier,
        )
    }

    /// Permanently retires the completed authenticated-genesis h1 owner into
    /// one proof-carrying, inert state-sync bootstrap candidate.
    ///
    /// This is deliberately a consuming boundary.  Success destroys the
    /// narrow live Core and its sole application-seal authority; failure also
    /// fails closed and does not return either authority to the caller.  The
    /// returned candidate is derived from a complete, independently verified
    /// three-certified-header proof whose finalized proposal witness exactly
    /// matches the h1 retained by this owner.  The rev2 completion facts alone
    /// are never treated as finality or recovery authority.
    ///
    /// The candidate still cannot activate a validator.  A trusted Node host
    /// must separately consume the live SafetyStore, ApplicationStore, signer,
    /// and whole-node checkpoint owners, install the proof-derived anchor, and
    /// fresh-read every joined store before any continuation owner can exist.
    pub fn retire_completed_into_h1_state_sync_promotion_v0<V: SignatureVerifier>(
        self,
        proof: FinalityProofV0,
        verifier: &V,
    ) -> Result<AuthenticatedGenesisApplicationH1StateSyncPromotionCandidateV0> {
        let Self {
            mut core,
            authority,
        } = self;
        if core.phase_v0()? != AuthenticatedGenesisApplicationH1OfflinePhaseV0::CompletedRev2 {
            return Err(CoreError::AuthenticatedGenesisApplicationH1OfflineRejected(
                "h1 state-sync promotion requires the exact completed revision-two owner",
            ));
        }

        let source_config = &core.core.config;
        let source_state = &core.core.safety;
        let exact_h1 = core.exact_h1.as_deref().ok_or(
            CoreError::AuthenticatedGenesisApplicationH1OfflineRejected(
                "completed h1 owner lost its exact signed proposal",
            ),
        )?;
        let authenticated_parent = source_config
            .authenticated_genesis_application_parent_v0()
            .copied()
            .ok_or(CoreError::AuthenticatedGenesisApplicationH1OfflineRejected(
                "completed h1 owner lost its authenticated genesis application parent",
            ))?;
        let [completion] = source_state.payload_validation_completions() else {
            return Err(CoreError::AuthenticatedGenesisApplicationH1OfflineRejected(
                "completed h1 owner lacks its unique durable validation completion",
            ));
        };
        let [terminal_fact] = source_state.payload_terminal_facts() else {
            return Err(CoreError::AuthenticatedGenesisApplicationH1OfflineRejected(
                "completed h1 owner lacks its unique durable terminal fact",
            ));
        };
        let artifact_ref = completion.result().artifact_ref().ok_or(
            CoreError::AuthenticatedGenesisApplicationH1OfflineRejected(
                "completed h1 owner lacks its exact Valid artifact reference",
            ),
        )?;
        if completion.route() != PayloadValidationRouteV0::Synced
            || completion.first_recorded_revision() != 2
            || completion.id().block_id() != exact_h1.block().id()
            || completion.id().view() != exact_h1.block().header().view()
            || terminal_fact.block_id() != exact_h1.block().id()
            || terminal_fact.valid_overlay() != Some(artifact_ref.overlay())
            || artifact_ref.overlay().parent_block_id() != source_config.genesis_block_id()
            || proof.finalized_block().header() != exact_h1.block().header()
            || proof.finalized_block().witness() != exact_h1.witness()
        {
            return Err(CoreError::AuthenticatedGenesisApplicationH1OfflineRejected(
                "h1 state-sync proof does not exactly bind the completed proposal and rev2 Valid result",
            ));
        }

        let plain_config = CoreConfig::new(
            source_config.local_validator(),
            source_config.validator_set().clone(),
            *source_config.consensus_parameters(),
            source_config.trusted_genesis_timestamp_ms(),
            source_config.max_blocks(),
            source_config.max_observed_messages(),
        )?;
        let proof_id = proof.id();
        let prepared_bootstrap =
            Core::prepare_h1_state_sync_bootstrap_v0(plain_config.clone(), proof, verifier)?;
        let target_header = exact_h1.block().header();
        let target = FinalizedTip::new(
            target_header.height(),
            target_header.view(),
            target_header.id(),
            target_header.timestamp_ms(),
        );
        let prepared_state = prepared_bootstrap.safety_state();
        if prepared_state.finalized() != target
            || prepared_state.application_applied() != target
            || prepared_state.revision() != 0
            || prepared_state
                .authenticated_genesis_application_parent_v0()
                .is_some()
            || prepared_state
                .state_sync_anchor()
                .is_none_or(|anchor| anchor.proof_id() != proof_id)
        {
            return Err(CoreError::AuthenticatedGenesisApplicationH1OfflineRejected(
                "proof-derived h1 state-sync anchor is not the exact plain-config promotion target",
            ));
        }

        let source_validation_id = completion.id();
        let source_valid_result_checksum = native_valid_result_checksum_v0(completion.result())
            .expect("the completed phase requires a canonical Valid result");
        let source_safety_state = Box::new(source_state.clone());
        let proposal = core
            .exact_h1
            .take()
            .expect("the completed phase and prior check require the exact h1 proposal");
        // The two drops are intentionally explicit: neither the bounded Core
        // owner nor its application seal authority crosses the promotion
        // boundary.  Everything returned below is inert proof-derived data.
        drop(authority);
        drop(core);
        Ok(
            AuthenticatedGenesisApplicationH1StateSyncPromotionCandidateV0 {
                plain_core_config: plain_config,
                prepared_bootstrap,
                h1_proposal: proposal,
                proof_id,
                source_authenticated_parent: authenticated_parent,
                source_validation_id,
                source_valid_result_checksum,
                source_safety_state,
            },
        )
    }
}

/// Linear handoff from Core commissioning into one application registrar.
///
/// The bundle deliberately exposes no owner, authority, generic Core, or parts
/// getter. Consuming [`Self::activate_application_v0`] is the only production
/// operation, so the seal authority cannot be detached from the application
/// registration boundary by the node host.
///
/// ```compile_fail
/// use trnm_consensus_core::AuthenticatedGenesisApplicationH1OfflineActivationBundleV0;
/// fn require_clone<T: Clone>() {}
/// require_clone::<AuthenticatedGenesisApplicationH1OfflineActivationBundleV0>();
/// ```
///
/// ```compile_fail
/// use trnm_consensus_core::AuthenticatedGenesisApplicationH1OfflineActivationBundleV0;
/// fn leak_parts(bundle: AuthenticatedGenesisApplicationH1OfflineActivationBundleV0) {
///     let _ = bundle.into_parts();
/// }
/// ```
#[must_use = "the authenticated-genesis h1 activation bundle must enter one application registrar"]
pub struct AuthenticatedGenesisApplicationH1OfflineActivationBundleV0 {
    owner: AuthenticatedGenesisApplicationH1OfflineValidationV0,
    authority: CoreIssuedApplicationSealAuthorityV0,
}

impl core::fmt::Debug for AuthenticatedGenesisApplicationH1OfflineActivationBundleV0 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("AuthenticatedGenesisApplicationH1OfflineActivationBundleV0")
            .field("contains_linear_owner", &true)
            .field("contains_linear_application_authority", &true)
            .finish_non_exhaustive()
    }
}

impl AuthenticatedGenesisApplicationH1OfflineActivationBundleV0 {
    pub fn activate_application_v0<
        R: AuthenticatedGenesisApplicationH1OfflineApplicationRegistrarV0,
    >(
        self,
        registrar: R,
    ) -> core::result::Result<R::Output, R::Error> {
        let Self { owner, authority } = self;
        registrar.register_authenticated_genesis_application_h1_offline_v0(
            AuthenticatedGenesisApplicationH1OfflineApplicationOwnerV0 {
                core: owner,
                authority,
            },
        )
    }
}

/// Process-local SafetyStore binding for the exact authenticated-genesis h1
/// driver.
///
/// The generic [`SafetyStatePersistenceBindingV0`] is deliberately not
/// exposed. A dedicated SafetyStore owner may retain this non-cloneable value
/// and use [`Self::accepts_persistence_v0`] for the two typed persistence
/// requests emitted by the wrapper. The stable comparison fields additionally
/// bind that affinity to the exact h1 proposal, validation generation,
/// authenticated application parent, and SafetyState-record configuration.
#[derive(Debug)]
#[must_use = "the exact offline h1 Safety binding must remain with its dedicated store owner"]
pub struct AuthenticatedGenesisApplicationH1OfflineSafetyPersistenceBindingV0 {
    binding: SafetyStatePersistenceBindingV0,
    authenticated_genesis_application_parent: AuthenticatedGenesisApplicationParentV0,
    safety_state_record_config_ref: [u8; 32],
    proposal: Box<SignedProposalV0>,
    validation_id: ValidationId,
}

impl AuthenticatedGenesisApplicationH1OfflineSafetyPersistenceBindingV0 {
    pub const fn authenticated_genesis_application_parent_v0(
        &self,
    ) -> AuthenticatedGenesisApplicationParentV0 {
        self.authenticated_genesis_application_parent
    }

    pub const fn safety_state_record_config_ref_v0(&self) -> [u8; 32] {
        self.safety_state_record_config_ref
    }

    pub fn proposal_v0(&self) -> &SignedProposalV0 {
        self.proposal.as_ref()
    }

    pub const fn validation_id_v0(&self) -> ValidationId {
        self.validation_id
    }

    pub fn accepts_persistence_v0(&self, request: &crate::SafetyStatePersistenceV0) -> bool {
        self.binding.accepts(request)
    }
}

/// Sole rev1 persistence request emitted after admitting the exact h1.
///
/// This carrier is non-cloneable and exposes neither a generic effect nor a
/// way to construct a different persistence request.
#[derive(Debug)]
#[must_use = "the exact rev1 obligation must be persisted before acknowledgement"]
pub struct AuthenticatedGenesisApplicationH1ObligationPersistenceV0 {
    persistence: crate::SafetyStatePersistenceV0,
    validation_id: ValidationId,
}

impl AuthenticatedGenesisApplicationH1ObligationPersistenceV0 {
    pub const fn persistence_v0(&self) -> &crate::SafetyStatePersistenceV0 {
        &self.persistence
    }

    pub const fn barrier_v0(&self) -> BarrierId {
        self.persistence.barrier()
    }

    pub const fn validation_id_v0(&self) -> ValidationId {
        self.validation_id
    }
}

/// Sole h1 payload-validation request released after the rev1 Safety ack.
///
/// The wrapper is non-cloneable. Consuming `try_claim_v0` preserves the Core's
/// existing process-local request/permit boundary without exposing raw effects.
#[derive(Debug)]
#[must_use = "the exact h1 validation request must remain with the application owner"]
pub struct AuthenticatedGenesisApplicationH1ValidationRequestV0 {
    request: PayloadValidationRequest,
}

impl AuthenticatedGenesisApplicationH1ValidationRequestV0 {
    pub const fn route_v0(&self) -> PayloadValidationRouteV0 {
        self.request.route()
    }

    pub const fn validation_id_v0(&self) -> ValidationId {
        self.request.id()
    }

    pub const fn block_v0(&self) -> &Block {
        self.request.block()
    }

    pub const fn parent_v0(&self) -> &PayloadValidationParentV0 {
        self.request.parent()
    }

    pub fn parent_binding_ref_v0(&self) -> Result<[u8; 32]> {
        self.request.parent_binding_ref_v0()
    }

    pub fn try_claim_v0(
        self,
    ) -> core::result::Result<
        crate::ClaimedPayloadValidationRequestV0,
        Box<crate::DuplicatePayloadValidationRequestV0>,
    > {
        self.request.try_claim()
    }
}

/// Authenticated SafetyStore comparison material for one durable revision-one
/// authenticated-genesis h1 obligation.
///
/// This value is deliberately cloneable and is not itself a store capability.
/// A future SafetyStore owner must retain its non-cloneable live capability and
/// present these facts through the trusted reconciler below. Core checks every
/// consensus coordinate it can derive independently before minting the opaque,
/// session-affined attestation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedGenesisApplicationH1ObligationTakeoverSafetyHeadFactsV0 {
    journal_id: [u8; 32],
    verifier_profile_ref: [u8; 32],
    core_config_ref: [u8; 32],
    tag5_state_record_checksum: [u8; 32],
    tag5_transition_context_checksum: [u8; 32],
    tag5_chain_checksum: [u8; 32],
    revision_one_state_record_checksum: [u8; 32],
    revision_one_transition_context_checksum: [u8; 32],
    revision_one_chain_checksum: [u8; 32],
    tag5_head_checksum: [u8; 32],
    revision_one_head_checksum: [u8; 32],
    barrier: BarrierId,
    validation_id: ValidationId,
    authenticated_parent_binding_ref: [u8; 32],
}

impl AuthenticatedGenesisApplicationH1ObligationTakeoverSafetyHeadFactsV0 {
    /// Builds inert comparison material from a fully authenticated SafetyStore
    /// lineage. The constructor proves shape only; live owner/path/head
    /// provenance remains the responsibility of the trusted reconciler. This
    /// cross-crate constructor is hidden from normal documentation because it
    /// is part of the linked SafetyStore host TCB, not an application API.
    #[allow(clippy::too_many_arguments)]
    #[doc(hidden)]
    pub fn from_authenticated_store_comparison_v0(
        journal_id: [u8; 32],
        verifier_profile_ref: [u8; 32],
        core_config_ref: [u8; 32],
        tag5_state_record_checksum: [u8; 32],
        tag5_transition_context_checksum: [u8; 32],
        tag5_chain_checksum: [u8; 32],
        revision_one_state_record_checksum: [u8; 32],
        revision_one_transition_context_checksum: [u8; 32],
        revision_one_chain_checksum: [u8; 32],
        tag5_head_checksum: [u8; 32],
        revision_one_head_checksum: [u8; 32],
        barrier: BarrierId,
        validation_id: ValidationId,
        authenticated_parent_binding_ref: [u8; 32],
    ) -> Result<Self> {
        if [
            journal_id,
            verifier_profile_ref,
            core_config_ref,
            tag5_state_record_checksum,
            tag5_transition_context_checksum,
            tag5_chain_checksum,
            revision_one_state_record_checksum,
            revision_one_transition_context_checksum,
            revision_one_chain_checksum,
            tag5_head_checksum,
            revision_one_head_checksum,
            authenticated_parent_binding_ref,
        ]
        .contains(&[0; 32])
            || barrier.get() == 0
            || validation_id.generation() == 0
        {
            return Err(CoreError::AuthenticatedGenesisApplicationH1OfflineRejected(
                "takeover Safety comparison facts contain a zero identity",
            ));
        }
        Ok(Self {
            journal_id,
            verifier_profile_ref,
            core_config_ref,
            tag5_state_record_checksum,
            tag5_transition_context_checksum,
            tag5_chain_checksum,
            revision_one_state_record_checksum,
            revision_one_transition_context_checksum,
            revision_one_chain_checksum,
            tag5_head_checksum,
            revision_one_head_checksum,
            barrier,
            validation_id,
            authenticated_parent_binding_ref,
        })
    }

    pub const fn journal_id_v0(&self) -> [u8; 32] {
        self.journal_id
    }

    pub const fn verifier_profile_ref_v0(&self) -> [u8; 32] {
        self.verifier_profile_ref
    }

    pub const fn core_config_ref_v0(&self) -> [u8; 32] {
        self.core_config_ref
    }

    pub const fn tag5_state_record_checksum_v0(&self) -> [u8; 32] {
        self.tag5_state_record_checksum
    }

    pub const fn tag5_transition_context_checksum_v0(&self) -> [u8; 32] {
        self.tag5_transition_context_checksum
    }

    pub const fn tag5_chain_checksum_v0(&self) -> [u8; 32] {
        self.tag5_chain_checksum
    }

    pub const fn revision_one_state_record_checksum_v0(&self) -> [u8; 32] {
        self.revision_one_state_record_checksum
    }

    pub const fn revision_one_transition_context_checksum_v0(&self) -> [u8; 32] {
        self.revision_one_transition_context_checksum
    }

    pub const fn revision_one_chain_checksum_v0(&self) -> [u8; 32] {
        self.revision_one_chain_checksum
    }

    pub const fn tag5_head_checksum_v0(&self) -> [u8; 32] {
        self.tag5_head_checksum
    }

    pub const fn revision_one_head_checksum_v0(&self) -> [u8; 32] {
        self.revision_one_head_checksum
    }

    pub const fn barrier_v0(&self) -> BarrierId {
        self.barrier
    }

    pub const fn validation_id_v0(&self) -> ValidationId {
        self.validation_id
    }

    pub const fn authenticated_parent_binding_ref_v0(&self) -> [u8; 32] {
        self.authenticated_parent_binding_ref
    }
}

/// Exact takeover challenge retained by a session whose private Core has
/// replayed h1 and remains behind the revision-one persistence barrier.
///
/// The challenge exposes only durable comparison material. It cannot clone or
/// reveal the private Core, the replay persistence carrier, a validation
/// request, or an application authority.
///
/// ```compile_fail
/// use trnm_consensus_core::
///     AuthenticatedGenesisApplicationH1ObligationTakeoverChallengeV0;
/// fn require_clone<T: Clone>() {}
/// fn main() {
///     require_clone::<AuthenticatedGenesisApplicationH1ObligationTakeoverChallengeV0>();
/// }
/// ```
///
/// ```compile_fail
/// use trnm_consensus_core::
///     AuthenticatedGenesisApplicationH1ObligationTakeoverChallengeV0;
/// fn leak(challenge: &AuthenticatedGenesisApplicationH1ObligationTakeoverChallengeV0) {
///     let _ = challenge.core();
/// }
/// ```
#[derive(Debug)]
#[must_use = "the takeover challenge must be joined to the exact live SafetyStore head"]
pub struct AuthenticatedGenesisApplicationH1ObligationTakeoverChallengeV0 {
    revision_zero: Box<SafetyState>,
    revision_one: Box<SafetyState>,
    proposal: Box<SignedProposalV0>,
    safety_state_record_config_ref: [u8; 32],
    authenticated_parent_binding_ref: [u8; 32],
    barrier: BarrierId,
    validation_id: ValidationId,
    affinity: Arc<()>,
}

impl AuthenticatedGenesisApplicationH1ObligationTakeoverChallengeV0 {
    pub fn revision_zero_state_v0(&self) -> &SafetyState {
        self.revision_zero.as_ref()
    }

    pub fn revision_one_state_v0(&self) -> &SafetyState {
        self.revision_one.as_ref()
    }

    pub fn proposal_v0(&self) -> &SignedProposalV0 {
        self.proposal.as_ref()
    }

    pub const fn safety_state_record_config_ref_v0(&self) -> [u8; 32] {
        self.safety_state_record_config_ref
    }

    pub const fn authenticated_parent_binding_ref_v0(&self) -> [u8; 32] {
        self.authenticated_parent_binding_ref
    }

    pub const fn barrier_v0(&self) -> BarrierId {
        self.barrier
    }

    pub const fn validation_id_v0(&self) -> ValidationId {
        self.validation_id
    }

    pub fn same_takeover_instance_v0(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.affinity, &other.affinity)
    }

    /// Mints a linear, session-affined attestation only after the trusted host
    /// joins this exact replay challenge to a live authenticated SafetyStore
    /// rev1 head. Public comparison facts alone never authorize the ack.
    pub fn attest_authenticated_safety_head_v0<
        R: AuthenticatedGenesisApplicationH1ObligationTakeoverSafetyReconcilerV0,
    >(
        &self,
        safety_head_facts: AuthenticatedGenesisApplicationH1ObligationTakeoverSafetyHeadFactsV0,
        reconciler: &mut R,
    ) -> Result<AuthenticatedGenesisApplicationH1ObligationTakeoverSafetyAttestationV0> {
        if safety_head_facts.core_config_ref_v0() != self.safety_state_record_config_ref
            || safety_head_facts.barrier_v0() != self.barrier
            || safety_head_facts.validation_id_v0() != self.validation_id
            || safety_head_facts.authenticated_parent_binding_ref_v0()
                != self.authenticated_parent_binding_ref
            || !reconciler.reconcile_authenticated_genesis_application_h1_obligation_takeover_v0(
                self,
                &safety_head_facts,
            )
        {
            return Err(CoreError::AuthenticatedGenesisApplicationH1OfflineRejected(
                "trusted Safety join rejected the exact revision-one takeover",
            ));
        }
        Ok(
            AuthenticatedGenesisApplicationH1ObligationTakeoverSafetyAttestationV0 {
                safety_head_facts,
                affinity: Arc::clone(&self.affinity),
            },
        )
    }
}

/// Trusted host join for a live, owner-affined SafetyStore rev1 capability.
///
/// Implementations are part of the linked host TCB. Returning `true` must mean
/// the supplied facts came from the exact configured owner/path/head and that
/// its complete tag-5 -> Ordinary lineage authenticates the challenge's
/// revision-zero and revision-one records.
pub trait AuthenticatedGenesisApplicationH1ObligationTakeoverSafetyReconcilerV0 {
    fn reconcile_authenticated_genesis_application_h1_obligation_takeover_v0(
        &mut self,
        challenge: &AuthenticatedGenesisApplicationH1ObligationTakeoverChallengeV0,
        safety_head_facts: &AuthenticatedGenesisApplicationH1ObligationTakeoverSafetyHeadFactsV0,
    ) -> bool;
}

#[derive(Debug)]
#[must_use = "the takeover Safety attestation must be consumed by its exact session"]
pub struct AuthenticatedGenesisApplicationH1ObligationTakeoverSafetyAttestationV0 {
    safety_head_facts: AuthenticatedGenesisApplicationH1ObligationTakeoverSafetyHeadFactsV0,
    affinity: Arc<()>,
}

/// Fail-closed owner for exact authenticated-genesis h1 obligation takeover.
///
/// The private Core has already replayed the complete signed h1 through the
/// existing narrow admission path and is still blocked at the revision-one
/// persistence barrier. This session has no ack, request, input, effect, seal,
/// Core, or parts escape hatch.
///
/// ```compile_fail
/// use trnm_consensus_core::
///     AuthenticatedGenesisApplicationH1ObligationTakeoverSessionV0;
/// fn require_clone<T: Clone>() {}
/// fn main() {
///     require_clone::<AuthenticatedGenesisApplicationH1ObligationTakeoverSessionV0>();
/// }
/// ```
///
/// ```compile_fail
/// use trnm_consensus_core::{
///     AuthenticatedGenesisApplicationH1ObligationTakeoverSessionV0, Input,
/// };
/// fn generic_step(
///     session: &mut AuthenticatedGenesisApplicationH1ObligationTakeoverSessionV0,
///     input: Input,
/// ) {
///     let _ = session.step(input);
/// }
/// ```
///
/// ```compile_fail
/// use trnm_consensus_core::
///     AuthenticatedGenesisApplicationH1ObligationTakeoverSessionV0;
/// fn release_without_safety(
///     session: &mut AuthenticatedGenesisApplicationH1ObligationTakeoverSessionV0,
/// ) {
///     let _ = session.acknowledge_obligation_persisted_v0();
/// }
/// ```
#[must_use = "dropping the takeover session keeps the durable obligation fail-closed"]
pub struct AuthenticatedGenesisApplicationH1ObligationTakeoverSessionV0 {
    challenge: AuthenticatedGenesisApplicationH1ObligationTakeoverChallengeV0,
    owner: AuthenticatedGenesisApplicationH1OfflineValidationV0,
    authority: CoreIssuedApplicationSealAuthorityV0,
    persistence: AuthenticatedGenesisApplicationH1ObligationPersistenceV0,
    replay_binding: AuthenticatedGenesisApplicationH1OfflineSafetyPersistenceBindingV0,
}

impl core::fmt::Debug for AuthenticatedGenesisApplicationH1ObligationTakeoverSessionV0 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("AuthenticatedGenesisApplicationH1ObligationTakeoverSessionV0")
            .field("phase", &self.owner.phase_v0())
            .field("barrier", &self.challenge.barrier)
            .field("retains_private_core_owner", &true)
            .field("retains_private_application_authority", &true)
            .finish_non_exhaustive()
    }
}

impl AuthenticatedGenesisApplicationH1ObligationTakeoverSessionV0 {
    pub const fn challenge_v0(
        &self,
    ) -> &AuthenticatedGenesisApplicationH1ObligationTakeoverChallengeV0 {
        &self.challenge
    }

    /// Consumes an exact live-Safety attestation and unlocks only the narrow
    /// barrier-ack bundle. No request is released by this operation.
    pub fn activate_after_authenticated_safety_v0(
        self,
        attestation: AuthenticatedGenesisApplicationH1ObligationTakeoverSafetyAttestationV0,
    ) -> Result<AuthenticatedGenesisApplicationH1ObligationTakeoverActivationBundleV0> {
        if !Arc::ptr_eq(&self.challenge.affinity, &attestation.affinity) {
            return Err(CoreError::AuthenticatedGenesisApplicationH1OfflineRejected(
                "takeover Safety attestation belongs to another session",
            ));
        }
        Ok(
            AuthenticatedGenesisApplicationH1ObligationTakeoverActivationBundleV0 {
                owner: self.owner,
                authority: self.authority,
                persistence: self.persistence,
                replay_binding: self.replay_binding,
                safety_head_facts: attestation.safety_head_facts,
            },
        )
    }
}

/// Post-attestation, pre-rebind gate for the exact revision-one barrier.
///
/// Its sole consuming method transfers the replay owner's real persistence
/// binding into the linked SafetyStore TCB. It deliberately cannot acknowledge
/// the barrier or release a request before that rebind succeeds.
///
/// ```compile_fail
/// use trnm_consensus_core::
///     AuthenticatedGenesisApplicationH1ObligationTakeoverActivationBundleV0;
/// fn require_clone<T: Clone>() {}
/// fn main() {
///     require_clone::<AuthenticatedGenesisApplicationH1ObligationTakeoverActivationBundleV0>();
/// }
/// ```
///
/// ```compile_fail
/// use trnm_consensus_core::
///     AuthenticatedGenesisApplicationH1ObligationTakeoverActivationBundleV0;
/// fn leak(bundle: AuthenticatedGenesisApplicationH1ObligationTakeoverActivationBundleV0) {
///     let _ = bundle.into_parts();
/// }
/// ```
///
/// ```compile_fail
/// use trnm_consensus_core::
///     AuthenticatedGenesisApplicationH1ObligationTakeoverActivationBundleV0;
/// use trnm_consensus_types::SignatureVerifier;
/// fn ack_before_live_rebind<V: SignatureVerifier>(
///     bundle: AuthenticatedGenesisApplicationH1ObligationTakeoverActivationBundleV0,
///     verifier: &V,
/// ) {
///     let _ = bundle.acknowledge_and_release_validation_request_v0(verifier);
/// }
/// ```
#[must_use = "the attested takeover bundle must enter the exact live SafetyStore rebind"]
pub struct AuthenticatedGenesisApplicationH1ObligationTakeoverActivationBundleV0 {
    owner: AuthenticatedGenesisApplicationH1OfflineValidationV0,
    authority: CoreIssuedApplicationSealAuthorityV0,
    persistence: AuthenticatedGenesisApplicationH1ObligationPersistenceV0,
    replay_binding: AuthenticatedGenesisApplicationH1OfflineSafetyPersistenceBindingV0,
    safety_head_facts: AuthenticatedGenesisApplicationH1ObligationTakeoverSafetyHeadFactsV0,
}

impl core::fmt::Debug for AuthenticatedGenesisApplicationH1ObligationTakeoverActivationBundleV0 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("AuthenticatedGenesisApplicationH1ObligationTakeoverActivationBundleV0")
            .field("phase", &self.owner.phase_v0())
            .field("barrier", &self.persistence.barrier_v0())
            .field("retains_authenticated_safety_facts", &true)
            .finish_non_exhaustive()
    }
}

impl AuthenticatedGenesisApplicationH1ObligationTakeoverActivationBundleV0 {
    pub const fn safety_head_facts_v0(
        &self,
    ) -> &AuthenticatedGenesisApplicationH1ObligationTakeoverSafetyHeadFactsV0 {
        &self.safety_head_facts
    }

    /// Transfers the replay Core's process-local persistence binding into the
    /// linked SafetyStore TCB.  The pre-rebind bundle deliberately has no
    /// acknowledgement method: a durable rev1 row alone cannot authorize a
    /// `StorageAck` for a newly reconstructed Core owner.
    pub fn rebind_live_safety_v0<
        R: AuthenticatedGenesisApplicationH1ObligationTakeoverSafetyRebindRegistrarV0,
    >(
        self,
        registrar: R,
    ) -> core::result::Result<
        AuthenticatedGenesisApplicationH1ObligationTakeoverReboundActivationV0,
        R::Error,
    > {
        registrar.rebind_authenticated_genesis_application_h1_obligation_takeover_v0(
            &self.safety_head_facts,
            &self.persistence,
            self.replay_binding,
        )?;
        Ok(
            AuthenticatedGenesisApplicationH1ObligationTakeoverReboundActivationV0 {
                owner: self.owner,
                authority: self.authority,
                persistence: self.persistence,
                safety_head_facts: self.safety_head_facts,
            },
        )
    }
}

/// Linked-host TCB boundary that must install the supplied process-local Core
/// binding only after authenticating the exact live rev1 SafetyStore lineage.
///
/// Rust has no cross-crate friend visibility, so implementations are public by
/// necessity. Production code must use the SafetyStore crate's dedicated
/// existing-rev1 bridge; implementing this trait elsewhere expands the linked
/// host TCB and is not a protocol-authorized alternative.
#[doc(hidden)]
pub trait AuthenticatedGenesisApplicationH1ObligationTakeoverSafetyRebindRegistrarV0 {
    type Error;

    fn rebind_authenticated_genesis_application_h1_obligation_takeover_v0(
        self,
        safety_head_facts: &AuthenticatedGenesisApplicationH1ObligationTakeoverSafetyHeadFactsV0,
        persistence: &AuthenticatedGenesisApplicationH1ObligationPersistenceV0,
        binding: AuthenticatedGenesisApplicationH1OfflineSafetyPersistenceBindingV0,
    ) -> core::result::Result<(), Self::Error>;
}

/// Post-rebind activation gate. Only this state can acknowledge the replayed
/// rev1 persistence barrier and release Core's exact validation request.
#[derive(Debug)]
#[must_use = "the rebound takeover must release its exact request or remain fenced"]
pub struct AuthenticatedGenesisApplicationH1ObligationTakeoverReboundActivationV0 {
    owner: AuthenticatedGenesisApplicationH1OfflineValidationV0,
    authority: CoreIssuedApplicationSealAuthorityV0,
    persistence: AuthenticatedGenesisApplicationH1ObligationPersistenceV0,
    safety_head_facts: AuthenticatedGenesisApplicationH1ObligationTakeoverSafetyHeadFactsV0,
}

impl AuthenticatedGenesisApplicationH1ObligationTakeoverReboundActivationV0 {
    pub const fn safety_head_facts_v0(
        &self,
    ) -> &AuthenticatedGenesisApplicationH1ObligationTakeoverSafetyHeadFactsV0 {
        &self.safety_head_facts
    }

    pub fn acknowledge_and_release_validation_request_v0<V: SignatureVerifier>(
        mut self,
        verifier: &V,
    ) -> Result<(
        AuthenticatedGenesisApplicationH1OfflineActivationBundleV0,
        AuthenticatedGenesisApplicationH1ValidationRequestV0,
    )> {
        let barrier = self.persistence.barrier_v0();
        let request =
            self.owner
                .acknowledge_obligation_persisted_v0(&self.persistence, barrier, verifier)?;
        Ok((
            AuthenticatedGenesisApplicationH1OfflineActivationBundleV0 {
                owner: self.owner,
                authority: self.authority,
            },
            request,
        ))
    }
}

/// Sole rev2 NativeValid persistence request emitted by the sealed callback.
#[derive(Debug)]
#[must_use = "the exact rev2 completion must be persisted before acknowledgement"]
pub struct AuthenticatedGenesisApplicationH1CompletionPersistenceV0 {
    persistence: crate::SafetyStatePersistenceV0,
    validation_id: ValidationId,
    carrier_checksum: [u8; 32],
}

impl AuthenticatedGenesisApplicationH1CompletionPersistenceV0 {
    pub const fn persistence_v0(&self) -> &crate::SafetyStatePersistenceV0 {
        &self.persistence
    }

    pub const fn barrier_v0(&self) -> BarrierId {
        self.persistence.barrier()
    }

    pub const fn validation_id_v0(&self) -> ValidationId {
        self.validation_id
    }

    /// Stable commitment to Core's exact rev2 carrier identity.
    ///
    /// The commitment binds the authenticated application parent, schema-v12
    /// record configuration, barrier, validation generation, Safety revision,
    /// durable Valid result, and post-ack action. It is comparison data only;
    /// the process-local persistence affinity remains the authority.
    pub const fn carrier_checksum_v0(&self) -> [u8; 32] {
        self.carrier_checksum
    }
}

pub const AUTHENTICATED_GENESIS_H1_COMPLETION_CARRIER_CHECKSUM_DOMAIN_V0: &str =
    "trnm.consensus-core.authenticated-genesis.h1-completion-carrier.v0";

fn authenticated_genesis_h1_completion_carrier_checksum_v0(
    safety_state_record_config_ref: [u8; 32],
    authenticated_parent_binding_ref: [u8; 32],
    persistence: &crate::SafetyStatePersistenceV0,
    validation_id: ValidationId,
) -> Result<[u8; 32]> {
    let state = persistence.state();
    let post_ack_action = persistence.native_valid_post_ack_action_v0().ok_or(
        CoreError::AuthenticatedGenesisApplicationH1OfflineRejected(
            "rev2 carrier lacks its Core-owned post-ack action",
        ),
    )?;
    authenticated_genesis_h1_stable_completion_carrier_checksum_v0(
        safety_state_record_config_ref,
        authenticated_parent_binding_ref,
        state,
        validation_id,
        persistence.barrier(),
        post_ack_action,
    )
}

fn authenticated_genesis_h1_stable_completion_carrier_checksum_v0(
    safety_state_record_config_ref: [u8; 32],
    authenticated_parent_binding_ref: [u8; 32],
    state: &SafetyState,
    validation_id: ValidationId,
    barrier: BarrierId,
    post_ack_action: NativeValidPostAckActionV0,
) -> Result<[u8; 32]> {
    let [completion] = state.payload_validation_completions() else {
        return Err(CoreError::AuthenticatedGenesisApplicationH1OfflineRejected(
            "stable rev2 carrier requires exactly one completion",
        ));
    };
    let valid_result_checksum = native_valid_result_checksum_v0(completion.result()).ok_or(
        CoreError::AuthenticatedGenesisApplicationH1OfflineRejected(
            "stable rev2 carrier requires one canonical Valid result",
        ),
    )?;
    if completion.route() != PayloadValidationRouteV0::Synced
        || completion.id() != validation_id
        || completion.first_recorded_revision() != 2
        || barrier.get() != 2
        || state.revision() != 2
        || safety_state_record_config_ref == [0; 32]
        || authenticated_parent_binding_ref == [0; 32]
    {
        return Err(CoreError::AuthenticatedGenesisApplicationH1OfflineRejected(
            "stable rev2 carrier identity is not the exact authenticated-genesis h1 completion",
        ));
    }

    let barrier = barrier.get().to_be_bytes();
    let validation_view = validation_id.view().get().to_be_bytes();
    let validation_generation = validation_id.generation().to_be_bytes();
    let safety_revision = state.revision().to_be_bytes();
    let completion_revision = completion.first_recorded_revision().to_be_bytes();
    let post_ack_action_code = post_ack_action.code().to_be_bytes();
    let validation_block_id = validation_id.block_id();
    let chain_id = state.chain_id();
    let parts: [&[u8]; 11] = [
        &safety_state_record_config_ref,
        &authenticated_parent_binding_ref,
        &barrier,
        validation_block_id.as_bytes(),
        &validation_view,
        &validation_generation,
        &safety_revision,
        &completion_revision,
        &valid_result_checksum,
        &post_ack_action_code,
        chain_id.as_str().as_bytes(),
    ];
    let mut hasher = Sha256::new();
    hasher.update(b"trnm.domain.hash.v1");
    hasher.update(
        (AUTHENTICATED_GENESIS_H1_COMPLETION_CARRIER_CHECKSUM_DOMAIN_V0.len() as u64).to_be_bytes(),
    );
    hasher.update(AUTHENTICATED_GENESIS_H1_COMPLETION_CARRIER_CHECKSUM_DOMAIN_V0.as_bytes());
    for part in parts {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part);
    }
    Ok(hasher.finalize().into())
}

/// Canonical application provenance committed by the Delivered (`D`) stage.
///
/// This value is inert scalar material. Possession of the application seal
/// authority is still required to join it to Core's exact rev2 carrier and
/// mint [`ApplicationSealedNativeValidTransitionV0`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApplicationNativeValidDeliveryFactsV0 {
    route: PayloadValidationRouteV0,
    validation_id: ValidationId,
    request_fingerprint: [u8; 32],
    job_immutable_checksum: [u8; 32],
    application_host_config_ref: [u8; 32],
    valid_result_checksum: [u8; 32],
    callback_payload_checksum: [u8; 32],
    idempotency_key: [u8; 32],
    delivery_attempt: u64,
    delivered_job_row_checksum: [u8; 32],
    outbox_checksum: [u8; 32],
    post_ack_action: NativeValidPostAckActionV0,
    completion_revision: u64,
}

impl ApplicationNativeValidDeliveryFactsV0 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        route: PayloadValidationRouteV0,
        validation_id: ValidationId,
        request_fingerprint: [u8; 32],
        job_immutable_checksum: [u8; 32],
        application_host_config_ref: [u8; 32],
        valid_result_checksum: [u8; 32],
        callback_payload_checksum: [u8; 32],
        idempotency_key: [u8; 32],
        delivery_attempt: u64,
        delivered_job_row_checksum: [u8; 32],
        outbox_checksum: [u8; 32],
        post_ack_action: NativeValidPostAckActionV0,
        completion_revision: u64,
    ) -> Result<Self> {
        if route != PayloadValidationRouteV0::Synced
            || delivery_attempt != 1
            || post_ack_action != NativeValidPostAckActionV0::None
            || completion_revision != 2
            || [
                request_fingerprint,
                job_immutable_checksum,
                application_host_config_ref,
                valid_result_checksum,
                callback_payload_checksum,
                idempotency_key,
                delivered_job_row_checksum,
                outbox_checksum,
            ]
            .contains(&[0; 32])
        {
            return Err(CoreError::AuthenticatedGenesisApplicationH1OfflineRejected(
                "application Delivered facts are not the exact bounded h1 NativeValid shape",
            ));
        }
        Ok(Self {
            route,
            validation_id,
            request_fingerprint,
            job_immutable_checksum,
            application_host_config_ref,
            valid_result_checksum,
            callback_payload_checksum,
            idempotency_key,
            delivery_attempt,
            delivered_job_row_checksum,
            outbox_checksum,
            post_ack_action,
            completion_revision,
        })
    }

    pub const fn route(&self) -> PayloadValidationRouteV0 {
        self.route
    }

    pub const fn validation_id(&self) -> ValidationId {
        self.validation_id
    }

    pub const fn request_fingerprint(&self) -> [u8; 32] {
        self.request_fingerprint
    }

    pub const fn job_immutable_checksum(&self) -> [u8; 32] {
        self.job_immutable_checksum
    }

    pub const fn application_host_config_ref(&self) -> [u8; 32] {
        self.application_host_config_ref
    }

    pub const fn valid_result_checksum(&self) -> [u8; 32] {
        self.valid_result_checksum
    }

    pub const fn callback_payload_checksum(&self) -> [u8; 32] {
        self.callback_payload_checksum
    }

    pub const fn idempotency_key(&self) -> [u8; 32] {
        self.idempotency_key
    }

    pub const fn delivery_attempt(&self) -> u64 {
        self.delivery_attempt
    }

    pub const fn delivered_job_row_checksum(&self) -> [u8; 32] {
        self.delivered_job_row_checksum
    }

    pub const fn outbox_checksum(&self) -> [u8; 32] {
        self.outbox_checksum
    }

    pub const fn post_ack_action(&self) -> NativeValidPostAckActionV0 {
        self.post_ack_action
    }

    pub const fn completion_revision(&self) -> u64 {
        self.completion_revision
    }
}

/// Opaque Core/App join for one exact authenticated-genesis h1 D transition.
///
/// The token owns Core's non-cloneable rev2 persistence carrier and the full
/// App-delivery provenance sealed by the application authority. It has no
/// public constructor or parts escape hatch. SafetyStore may borrow the exact
/// carrier and scalar facts, but only its dedicated h1 API may persist them.
///
/// ```compile_fail
/// use trnm_consensus_core::ApplicationSealedNativeValidTransitionV0;
/// fn require_clone<T: Clone>() {}
/// require_clone::<ApplicationSealedNativeValidTransitionV0>();
/// ```
///
/// ```compile_fail
/// use trnm_consensus_core::ApplicationSealedNativeValidTransitionV0;
/// fn leak_parts(token: ApplicationSealedNativeValidTransitionV0) {
///     let _ = token.into_parts_v0();
/// }
/// ```
#[must_use = "the application-sealed D transition must enter its dedicated SafetyStore"]
pub struct ApplicationSealedNativeValidTransitionV0 {
    completion: AuthenticatedGenesisApplicationH1CompletionPersistenceV0,
    facts: ApplicationNativeValidDeliveryFactsV0,
}

impl core::fmt::Debug for ApplicationSealedNativeValidTransitionV0 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ApplicationSealedNativeValidTransitionV0")
            .field("route", &self.facts.route)
            .field("validation_id", &self.facts.validation_id)
            .field("carrier_checksum", &self.completion.carrier_checksum)
            .finish_non_exhaustive()
    }
}

impl ApplicationSealedNativeValidTransitionV0 {
    pub const fn completion_persistence_v0(
        &self,
    ) -> &AuthenticatedGenesisApplicationH1CompletionPersistenceV0 {
        &self.completion
    }

    pub const fn delivery_facts_v0(&self) -> ApplicationNativeValidDeliveryFactsV0 {
        self.facts
    }

    pub const fn carrier_checksum_v0(&self) -> [u8; 32] {
        self.completion.carrier_checksum
    }
}

impl CoreIssuedApplicationSealAuthorityV0 {
    /// Seals the exact App `D` projection together with Core's exact rev2
    /// carrier. Possession of this authority is the authorization boundary;
    /// the activation bundle installs it directly into the application owner.
    pub fn seal_authenticated_genesis_h1_native_valid_transition_v0(
        &self,
        completion: AuthenticatedGenesisApplicationH1CompletionPersistenceV0,
        facts: ApplicationNativeValidDeliveryFactsV0,
    ) -> Result<ApplicationSealedNativeValidTransitionV0> {
        let persistence = completion.persistence_v0();
        let state = persistence.state();
        let [durable_completion] = state.payload_validation_completions() else {
            return Err(CoreError::AuthenticatedGenesisApplicationH1OfflineRejected(
                "application delivery seal requires exactly one rev2 completion",
            ));
        };
        let valid_result_checksum = native_valid_result_checksum_v0(durable_completion.result())
            .ok_or(CoreError::AuthenticatedGenesisApplicationH1OfflineRejected(
                "application delivery seal requires a canonical durable Valid result",
            ))?;
        if !self.accepts_application_host_persistence_v0(persistence)
            || self.chain_id() != state.chain_id()
            || completion.validation_id_v0() != facts.validation_id
            || completion.carrier_checksum_v0() == [0; 32]
            || facts.route != PayloadValidationRouteV0::Synced
            || durable_completion.route() != facts.route
            || durable_completion.id() != facts.validation_id
            || durable_completion.first_recorded_revision() != facts.completion_revision
            || valid_result_checksum != facts.valid_result_checksum
            || persistence.barrier().get() != facts.completion_revision
            || state.revision() != facts.completion_revision
            || persistence.native_valid_post_ack_action_v0() != Some(facts.post_ack_action)
            || persistence.native_finalization_applied_v0().is_some()
        {
            return Err(CoreError::AuthenticatedGenesisApplicationH1OfflineRejected(
                "application Delivered facts do not match the exact affined rev2 carrier",
            ));
        }
        Ok(ApplicationSealedNativeValidTransitionV0 { completion, facts })
    }
}

/// Inert terminal facts returned after the exact rev2 persistence ack.
///
/// The completed value contains no Core, input, effect, application authority,
/// or persistence affinity.
#[derive(Debug)]
#[must_use = "the bounded h1 completion facts should be retained by the host"]
pub struct AuthenticatedGenesisApplicationH1CompletedV0 {
    proposal: Box<SignedProposalV0>,
    completion: DurablePayloadValidationCompletionV0,
    terminal_fact: PayloadTerminalFact,
    authenticated_parent_binding_ref: [u8; 32],
}

impl AuthenticatedGenesisApplicationH1CompletedV0 {
    pub fn proposal_v0(&self) -> &SignedProposalV0 {
        self.proposal.as_ref()
    }

    pub const fn validation_id_v0(&self) -> ValidationId {
        self.completion.id()
    }

    pub const fn completion_v0(&self) -> &DurablePayloadValidationCompletionV0 {
        &self.completion
    }

    pub const fn terminal_fact_v0(&self) -> PayloadTerminalFact {
        self.terminal_fact
    }

    pub const fn authenticated_parent_binding_ref_v0(&self) -> [u8; 32] {
        self.authenticated_parent_binding_ref
    }

    pub const fn safety_revision_v0(&self) -> u64 {
        2
    }
}

/// Narrow live owner for one canonical offline h1 validation above an
/// authenticated genesis application parent.
///
/// This wrapper deliberately has no `Clone`, raw-parts conversion, Core/input/
/// effect getter, generic step, timeout, signing, networking, or finalization
/// surface. Each mutating operation is transactional and replaces the private
/// Core only after exact state and effect sanitization.
///
/// ```compile_fail
/// use trnm_consensus_core::AuthenticatedGenesisApplicationH1OfflineValidationV0;
/// fn require_clone<T: Clone>() {}
/// require_clone::<AuthenticatedGenesisApplicationH1OfflineValidationV0>();
/// ```
///
/// ```compile_fail
/// use trnm_consensus_core::AuthenticatedGenesisApplicationH1OfflineValidationV0;
/// fn leak_core(owner: &AuthenticatedGenesisApplicationH1OfflineValidationV0) {
///     let _ = owner.core();
/// }
/// ```
///
/// ```compile_fail
/// use trnm_consensus_core::AuthenticatedGenesisApplicationH1OfflineValidationV0;
/// fn generic_step(owner: &mut AuthenticatedGenesisApplicationH1OfflineValidationV0) {
///     let _ = owner.step();
/// }
/// ```
///
/// ```compile_fail
/// use trnm_consensus_core::AuthenticatedGenesisApplicationH1OfflineValidationV0;
/// fn leak_parts(owner: AuthenticatedGenesisApplicationH1OfflineValidationV0) {
///     let _ = owner.into_parts();
/// }
/// ```
///
/// ```compile_fail
/// use trnm_consensus_core::AuthenticatedGenesisApplicationH1OfflineValidationV0;
/// fn leak_effects(owner: &AuthenticatedGenesisApplicationH1OfflineValidationV0) {
///     let _ = owner.effects();
/// }
/// ```
#[derive(Debug)]
#[must_use = "the bounded offline h1 driver must complete or remain durably fenced"]
pub struct AuthenticatedGenesisApplicationH1OfflineValidationV0 {
    core: Core,
    commissioned_rev0: Box<SafetyState>,
    safety_state_record_config_ref: [u8; 32],
    expected_payload_parent_binding_ref: [u8; 32],
    exact_h1: Option<Box<SignedProposalV0>>,
    safety_binding_issued: bool,
}

impl AuthenticatedGenesisApplicationH1OfflineValidationV0 {
    pub fn phase_v0(&self) -> Result<AuthenticatedGenesisApplicationH1OfflinePhaseV0> {
        self.core
            .classify_authenticated_genesis_application_h1_offline_phase_v0(
                self.commissioned_rev0.as_ref(),
                self.exact_h1.as_deref(),
                self.expected_payload_parent_binding_ref,
            )
    }

    /// Issues one non-generic SafetyStore binding after the rev1 request has
    /// been produced. The binding cannot be converted into Core's ordinary
    /// persistence binding.
    pub fn issue_safety_persistence_binding_v0(
        &mut self,
    ) -> Result<AuthenticatedGenesisApplicationH1OfflineSafetyPersistenceBindingV0> {
        if self.phase_v0()?
            != AuthenticatedGenesisApplicationH1OfflinePhaseV0::ObligationPersistencePendingRev1
        {
            return Err(CoreError::AuthenticatedGenesisApplicationH1OfflineRejected(
                "Safety binding is available only for the pending rev1 obligation",
            ));
        }
        if self.safety_binding_issued {
            return Err(CoreError::AuthenticatedGenesisApplicationH1OfflineRejected(
                "the offline h1 Safety binding was already issued",
            ));
        }
        let proposal = self.exact_h1.as_ref().ok_or(
            CoreError::AuthenticatedGenesisApplicationH1OfflineRejected(
                "the pending rev1 obligation lacks its exact h1 proposal",
            ),
        )?;
        let obligation = self
            .core
            .safety
            .payload_validation_obligations()
            .first()
            .ok_or(CoreError::AuthenticatedGenesisApplicationH1OfflineRejected(
                "the pending rev1 obligation is absent",
            ))?;
        let parent = self
            .core
            .config
            .authenticated_genesis_application_parent_v0()
            .copied()
            .ok_or(CoreError::AuthenticatedGenesisApplicationH1OfflineRejected(
                "the offline h1 Core lost its authenticated application parent",
            ))?;
        self.safety_binding_issued = true;
        Ok(
            AuthenticatedGenesisApplicationH1OfflineSafetyPersistenceBindingV0 {
                binding: self.core.safety_state_persistence_binding_v0(),
                authenticated_genesis_application_parent: parent,
                safety_state_record_config_ref: self.safety_state_record_config_ref,
                proposal: proposal.clone(),
                validation_id: obligation.id(),
            },
        )
    }

    /// Admits exactly one canonical epoch-zero h1 SyncedProposal and returns
    /// only its rev1 persistence carrier.
    pub fn submit_exact_h1_synced_proposal_v0<V: SignatureVerifier>(
        &mut self,
        proposal: SignedProposalV0,
        verifier: &V,
    ) -> Result<AuthenticatedGenesisApplicationH1ObligationPersistenceV0> {
        if self.phase_v0()? != AuthenticatedGenesisApplicationH1OfflinePhaseV0::CommissionedRev0 {
            return Err(CoreError::AuthenticatedGenesisApplicationH1OfflineRejected(
                "h1 proposal is not permitted in the current offline phase",
            ));
        }
        self.core
            .validate_authenticated_genesis_application_exact_h1_proposal_v0(&proposal, verifier)?;

        let retained = proposal.clone();
        let input = Input::SyncedProposal(Box::new(proposal));
        self.core.reject_while_busy(&input)?;
        self.core.preauthenticate_input(&input, verifier)?;
        let previous = self.core.safety.clone();
        let mut next = self.core.transactional_clone_v0();
        let effects = next.apply(input, verifier)?;
        next.validate_runtime(verifier, false)?;
        next.validate_monotonic_transition(&previous)?;
        let phase = next.classify_authenticated_genesis_application_h1_offline_phase_v0(
            self.commissioned_rev0.as_ref(),
            Some(&retained),
            self.expected_payload_parent_binding_ref,
        )?;
        if phase
            != AuthenticatedGenesisApplicationH1OfflinePhaseV0::ObligationPersistencePendingRev1
        {
            return Err(CoreError::AuthenticatedGenesisApplicationH1OfflineRejected(
                "h1 proposal did not produce the exact rev1 obligation phase",
            ));
        }
        let validation_id = next
            .safety
            .payload_validation_obligations()
            .first()
            .expect("the exact phase classifier requires one obligation")
            .id();
        match effects.as_slice() {
            [Effect::PersistSafetyState(request)]
                if request.state() == &next.safety
                    && request.barrier().get() == 1
                    && request.native_valid_post_ack_action_v0().is_none()
                    && request.native_finalization_applied_v0().is_none() => {}
            _ => {
                return Err(CoreError::AuthenticatedGenesisApplicationH1OfflineRejected(
                    "h1 proposal exposed an effect other than its sole inert rev1 persistence",
                ));
            }
        };
        let mut effects = effects.into_iter();
        let Effect::PersistSafetyState(persistence) = effects
            .next()
            .expect("the exact effect sanitizer requires one persistence")
        else {
            unreachable!("the exact effect sanitizer fixed the effect variant")
        };
        debug_assert!(effects.next().is_none());
        self.core = next;
        self.exact_h1 = Some(Box::new(retained));
        Ok(AuthenticatedGenesisApplicationH1ObligationPersistenceV0 {
            persistence,
            validation_id,
        })
    }

    /// Releases the exact validation request only after the host acknowledges
    /// the same affined rev1 persistence carrier and barrier.
    pub fn acknowledge_obligation_persisted_v0<V: SignatureVerifier>(
        &mut self,
        persistence: &AuthenticatedGenesisApplicationH1ObligationPersistenceV0,
        acknowledged_barrier: BarrierId,
        verifier: &V,
    ) -> Result<AuthenticatedGenesisApplicationH1ValidationRequestV0> {
        if self.phase_v0()?
            != AuthenticatedGenesisApplicationH1OfflinePhaseV0::ObligationPersistencePendingRev1
            || !self.safety_binding_issued
        {
            return Err(CoreError::AuthenticatedGenesisApplicationH1OfflineRejected(
                "rev1 persistence acknowledgement is not permitted before the exact Safety binding",
            ));
        }
        let expected = self
            .core
            .safety
            .payload_validation_obligations()
            .first()
            .expect("the exact phase classifier requires one obligation")
            .id();
        if persistence.validation_id != expected
            || persistence.persistence.state() != &self.core.safety
            || acknowledged_barrier != persistence.persistence.barrier()
            || !self
                .core
                .safety_state_persistence_binding_v0()
                .accepts(&persistence.persistence)
        {
            return Err(CoreError::AuthenticatedGenesisApplicationH1OfflineRejected(
                "rev1 acknowledgement differs from the exact affined persistence carrier",
            ));
        }

        let input = Input::StorageAck {
            barrier: acknowledged_barrier,
        };
        let previous = self.core.safety.clone();
        let mut next = self.core.transactional_clone_v0();
        let effects = next.apply(input, verifier)?;
        next.validate_runtime(verifier, false)?;
        next.validate_monotonic_transition(&previous)?;
        if next.classify_authenticated_genesis_application_h1_offline_phase_v0(
            self.commissioned_rev0.as_ref(),
            self.exact_h1.as_deref(),
            self.expected_payload_parent_binding_ref,
        )? != AuthenticatedGenesisApplicationH1OfflinePhaseV0::ValidationRequestReleasedRev1
        {
            return Err(CoreError::AuthenticatedGenesisApplicationH1OfflineRejected(
                "rev1 acknowledgement did not enter the exact validation-request phase",
            ));
        }
        match effects.as_slice() {
            [Effect::ValidateSyncedPayload(request)]
                if request.route() == PayloadValidationRouteV0::Synced
                    && request.id() == expected
                    && request.block()
                        == self
                            .exact_h1
                            .as_ref()
                            .expect("the exact phase classifier requires h1")
                            .block()
                    && request.parent_binding_ref_v0()?
                        == self.expected_payload_parent_binding_ref => {}
            _ => {
                return Err(
                    CoreError::AuthenticatedGenesisApplicationH1OfflineRejected(
                        "rev1 acknowledgement exposed an effect other than its exact Synced validation request",
                    ),
                );
            }
        };
        let mut effects = effects.into_iter();
        let Effect::ValidateSyncedPayload(request) = effects
            .next()
            .expect("the exact effect sanitizer requires one validation request")
        else {
            unreachable!("the exact effect sanitizer fixed the effect variant")
        };
        debug_assert!(effects.next().is_none());
        self.core = next;
        Ok(AuthenticatedGenesisApplicationH1ValidationRequestV0 { request })
    }

    /// Accepts only an opaque App-sealed Valid callback for this exact h1 and
    /// returns only its rev2 NativeValid persistence carrier.
    pub fn accept_application_sealed_valid_v0<V: SignatureVerifier>(
        &mut self,
        proof: &ApplicationSealedValidV0,
        verifier: &V,
    ) -> Result<AuthenticatedGenesisApplicationH1CompletionPersistenceV0> {
        if self.phase_v0()?
            != AuthenticatedGenesisApplicationH1OfflinePhaseV0::ValidationRequestReleasedRev1
        {
            return Err(CoreError::AuthenticatedGenesisApplicationH1OfflineRejected(
                "sealed Valid is not permitted in the current offline phase",
            ));
        }
        let input = self.core.application_sealed_valid_input_v0(proof)?;
        let previous = self.core.safety.clone();
        let mut next = self.core.transactional_clone_v0();
        let effects = next.apply(input, verifier)?;
        next.validate_runtime(verifier, false)?;
        next.validate_monotonic_transition(&previous)?;
        if next.classify_authenticated_genesis_application_h1_offline_phase_v0(
            self.commissioned_rev0.as_ref(),
            self.exact_h1.as_deref(),
            self.expected_payload_parent_binding_ref,
        )? != AuthenticatedGenesisApplicationH1OfflinePhaseV0::CompletionPersistencePendingRev2
        {
            return Err(CoreError::AuthenticatedGenesisApplicationH1OfflineRejected(
                "sealed h1 Valid did not enter the exact rev2 completion phase",
            ));
        }
        let validation_id = proof.id();
        match effects.as_slice() {
            [Effect::PersistSafetyState(request)]
                if request.state() == &next.safety
                    && request.barrier().get() == 2
                    && request.native_valid_post_ack_action_v0()
                        == Some(NativeValidPostAckActionV0::None)
                    && request.native_finalization_applied_v0().is_none() => {}
            _ => {
                return Err(CoreError::AuthenticatedGenesisApplicationH1OfflineRejected(
                    "sealed h1 Valid exposed an effect other than its sole inert rev2 persistence",
                ));
            }
        }
        let mut effects = effects.into_iter();
        let Effect::PersistSafetyState(persistence) = effects
            .next()
            .expect("the exact effect sanitizer requires one persistence")
        else {
            unreachable!("the exact effect sanitizer fixed the effect variant")
        };
        debug_assert!(effects.next().is_none());
        let carrier_checksum = authenticated_genesis_h1_completion_carrier_checksum_v0(
            self.safety_state_record_config_ref,
            self.expected_payload_parent_binding_ref,
            &persistence,
            validation_id,
        )?;
        self.core = next;
        Ok(AuthenticatedGenesisApplicationH1CompletionPersistenceV0 {
            persistence,
            validation_id,
            carrier_checksum,
        })
    }

    /// Closes the bounded owner only when the exact affined rev2 persistence
    /// carrier is acknowledged and the Core produces no post-ack effect.
    pub fn acknowledge_completion_persisted_v0<V: SignatureVerifier>(
        &mut self,
        persistence: &AuthenticatedGenesisApplicationH1CompletionPersistenceV0,
        acknowledged_barrier: BarrierId,
        verifier: &V,
    ) -> Result<AuthenticatedGenesisApplicationH1CompletedV0> {
        if self.phase_v0()?
            != AuthenticatedGenesisApplicationH1OfflinePhaseV0::CompletionPersistencePendingRev2
        {
            return Err(CoreError::AuthenticatedGenesisApplicationH1OfflineRejected(
                "rev2 persistence acknowledgement is not permitted in the current offline phase",
            ));
        }
        let expected = self
            .core
            .safety
            .payload_validation_completions()
            .first()
            .expect("the exact phase classifier requires one completion")
            .id();
        if persistence.validation_id != expected
            || persistence.persistence.state() != &self.core.safety
            || acknowledged_barrier != persistence.persistence.barrier()
            || !self
                .core
                .safety_state_persistence_binding_v0()
                .accepts(&persistence.persistence)
        {
            return Err(CoreError::AuthenticatedGenesisApplicationH1OfflineRejected(
                "rev2 acknowledgement differs from the exact affined persistence carrier",
            ));
        }

        let previous = self.core.safety.clone();
        let mut next = self.core.transactional_clone_v0();
        let effects = next.apply(
            Input::StorageAck {
                barrier: acknowledged_barrier,
            },
            verifier,
        )?;
        next.validate_runtime(verifier, false)?;
        next.validate_monotonic_transition(&previous)?;
        if !effects.is_empty()
            || next.classify_authenticated_genesis_application_h1_offline_phase_v0(
                self.commissioned_rev0.as_ref(),
                self.exact_h1.as_deref(),
                self.expected_payload_parent_binding_ref,
            )? != AuthenticatedGenesisApplicationH1OfflinePhaseV0::CompletedRev2
        {
            return Err(CoreError::AuthenticatedGenesisApplicationH1OfflineRejected(
                "rev2 acknowledgement exposed a post-completion effect",
            ));
        }
        let completion = next.safety.payload_validation_completions()[0].clone();
        let terminal_fact = next.safety.payload_terminal_facts()[0];
        let proposal = self
            .exact_h1
            .as_ref()
            .expect("the exact phase classifier requires h1")
            .clone();
        self.core = next;
        Ok(AuthenticatedGenesisApplicationH1CompletedV0 {
            proposal,
            completion,
            terminal_fact,
            authenticated_parent_binding_ref: self.expected_payload_parent_binding_ref,
        })
    }
}

/// Inert schema-v12 SafetyState prepared from one fully verified epoch-zero,
/// genesis-anchored h1 finality proof.
///
/// The value contains no live Core and no application or signing authority. It
/// exists so a SafetyStore can install revision zero before the separately
/// authenticated ApplicationStore base and virgin signer namespace are joined
/// through [`Core::begin_state_sync_anchor_recovery_v0`].
#[derive(Debug)]
#[must_use = "the prepared h1 bootstrap must be durably installed or discarded"]
pub struct PreparedH1StateSyncBootstrapV0 {
    safety_state: SafetyState,
}

impl PreparedH1StateSyncBootstrapV0 {
    pub const fn safety_state(&self) -> &SafetyState {
        &self.safety_state
    }

    pub fn into_safety_state(self) -> SafetyState {
        self.safety_state
    }

    /// Rewraps an already Core-validated canonical h1 anchor state for a
    /// downstream deterministic record reconstruction.
    ///
    /// The returned value is still inert and cannot activate Core. This entry
    /// exists so a durable store can recompute the exact revision-zero tag-4
    /// record beneath a later authenticated successor chain without forging a
    /// historical completion or overlay.
    pub fn from_authenticated_anchor_state_v0<V: SignatureVerifier>(
        config: &CoreConfig,
        state: SafetyState,
        verifier: &V,
    ) -> Result<Self> {
        Core::validate_persisted_state_v0(config, &state, verifier)?;
        if state.revision() != 0 || state.state_sync_anchor().is_none() {
            return Err(CoreError::StateSyncAnchorRecoveryRejected(
                "historical tag-4 reconstruction requires canonical anchored rev0",
            ));
        }
        Ok(Self {
            safety_state: state,
        })
    }
}

/// Inert, proof-carrying retirement product of one completed authenticated-
/// genesis h1 application owner.
///
/// This value is intentionally not a Core, replay owner, persistence permit,
/// application capability, signer capability, or whole-node checkpoint
/// authority.  It proves only that the consumed narrow owner completed exact
/// rev2 Valid processing and that a caller-supplied complete h1 finality proof
/// independently produced the exact plain-config state-sync anchor.  The live
/// owner and its application seal authority have already been destroyed.
///
/// ```compile_fail
/// use trnm_consensus_core::AuthenticatedGenesisApplicationH1StateSyncPromotionCandidateV0;
/// fn require_clone<T: Clone>() {}
/// fn main() {
///     require_clone::<AuthenticatedGenesisApplicationH1StateSyncPromotionCandidateV0>();
/// }
/// ```
#[derive(Debug)]
#[must_use = "the inert h1 promotion candidate must be commissioned or discarded"]
pub struct AuthenticatedGenesisApplicationH1StateSyncPromotionCandidateV0 {
    plain_core_config: CoreConfig,
    prepared_bootstrap: PreparedH1StateSyncBootstrapV0,
    h1_proposal: Box<SignedProposalV0>,
    proof_id: CertificateId,
    source_authenticated_parent: AuthenticatedGenesisApplicationParentV0,
    source_validation_id: ValidationId,
    source_valid_result_checksum: [u8; 32],
    source_safety_state: Box<SafetyState>,
}

impl AuthenticatedGenesisApplicationH1StateSyncPromotionCandidateV0 {
    /// Plain continuation configuration.  It deliberately carries no
    /// authenticated-genesis application parent.
    pub const fn plain_core_config_v0(&self) -> &CoreConfig {
        &self.plain_core_config
    }

    /// Exact proof-derived, revision-zero h1 anchor awaiting durable install.
    pub const fn prepared_bootstrap_v0(&self) -> &PreparedH1StateSyncBootstrapV0 {
        &self.prepared_bootstrap
    }

    /// Complete h1 body and witness retained from the consumed source owner.
    pub fn h1_proposal_v0(&self) -> &SignedProposalV0 {
        self.h1_proposal.as_ref()
    }

    pub const fn proof_id_v0(&self) -> CertificateId {
        self.proof_id
    }

    /// Operator-pinned source application parent.  This remains comparison
    /// data only and is not copied into the plain continuation configuration.
    pub const fn source_authenticated_parent_v0(&self) -> AuthenticatedGenesisApplicationParentV0 {
        self.source_authenticated_parent
    }

    pub const fn source_validation_id_v0(&self) -> ValidationId {
        self.source_validation_id
    }

    pub const fn source_valid_result_checksum_v0(&self) -> [u8; 32] {
        self.source_valid_result_checksum
    }

    /// Exact completed rev2 state copied before the narrow live Core was
    /// destroyed.  This is comparison data only; it cannot bind or advance a
    /// SafetyStore and cannot reconstruct the consumed Core.
    pub fn source_safety_state_v0(&self) -> &SafetyState {
        self.source_safety_state.as_ref()
    }

    /// Consumes the inert candidate into the only three inputs a trusted Node
    /// commissioning host may use.  None of these values is live authority.
    pub fn into_h1_state_sync_bootstrap_parts_v0(
        self,
    ) -> (CoreConfig, PreparedH1StateSyncBootstrapV0, SignedProposalV0) {
        (
            self.plain_core_config,
            self.prepared_bootstrap,
            *self.h1_proposal,
        )
    }
}

/// Exact Core-authenticated h1 base which the trusted host must reconcile
/// against its independently authenticated ApplicationStore and signer state.
#[derive(Debug)]
#[must_use = "the h1 state-sync challenge must be reconciled before a live Core can exist"]
pub struct StateSyncAnchorRecoveryChallengeV0 {
    safety_state: Box<SafetyState>,
    local_validator: ValidatorId,
    affinity: Arc<()>,
}

impl StateSyncAnchorRecoveryChallengeV0 {
    pub fn safety_state(&self) -> &SafetyState {
        self.safety_state.as_ref()
    }

    pub fn anchor(&self) -> &DurableStateSyncAnchorV0 {
        self.safety_state
            .state_sync_anchor()
            .expect("a state-sync recovery challenge always owns its anchor")
    }

    pub fn trusted_base_header(&self) -> &BlockHeader {
        self.anchor().proof().finalized_block().header()
    }

    pub const fn local_validator(&self) -> ValidatorId {
        self.local_validator
    }

    /// Compares only this process-local recovery-session identity.
    pub fn same_recovery_instance_v0(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.affinity, &other.affinity)
    }
}

/// Trusted-host boundary for a fresh h1 bootstrap.
///
/// An implementation may return `true` only after authenticating an exact
/// ApplicationStore TrustedBase matching [`StateSyncAnchorRecoveryChallengeV0::trusted_base_header`]
/// (including its state root), confirming that no node-local h1 validation job,
/// completion, terminal fact, or overlay was installed, and binding a virgin
/// signer journal/watermark for this validator identity. A previously used key
/// is outside this fresh-only protocol even if its view watermark appears low.
pub trait StateSyncAnchorRecoveryReconcilerV0 {
    fn reconcile_state_sync_anchor_v0(
        &mut self,
        challenge: &StateSyncAnchorRecoveryChallengeV0,
    ) -> bool;
}

/// Inert owner of the only fresh h1 anchor activation path.
#[derive(Debug)]
#[must_use = "dropping the session keeps state-sync bootstrap fail-closed"]
pub struct StateSyncAnchorRecoverySessionV0 {
    core: Core,
    challenge: StateSyncAnchorRecoveryChallengeV0,
}

impl StateSyncAnchorRecoverySessionV0 {
    pub const fn challenge(&self) -> &StateSyncAnchorRecoveryChallengeV0 {
        &self.challenge
    }

    pub fn reconcile_and_activate_v0<R: StateSyncAnchorRecoveryReconcilerV0>(
        self,
        reconciler: &mut R,
    ) -> Result<Core> {
        if !reconciler.reconcile_state_sync_anchor_v0(&self.challenge)
            || !Arc::ptr_eq(&self.core.persistence_affinity.0, &self.challenge.affinity)
            || self.core.safety != *self.challenge.safety_state
        {
            return Err(CoreError::StateSyncAnchorRecoveryRejected(
                "the trusted host rejected the exact h1 base or virgin signer binding",
            ));
        }
        Ok(self.core)
    }
}

/// The five and only durable phases admitted by the epoch-zero h1 anchored
/// successor replay protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StateSyncAnchorSuccessorPhaseV0 {
    H1Bootstrap,
    H2ValidationPending,
    H2Valid,
    H3ValidationPending,
    H3Valid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StateSyncAnchorSuccessorStepV0 {
    Proposal,
    StorageAck,
    Valid,
}

/// Exact h2/h3 signed bodies for one h1 finality-proof replay.
///
/// The proof embedded in the durable anchor authenticates the two headers and
/// proposal witnesses but deliberately omits their application bodies. This
/// carrier is non-cloneable and has no raw constructor: it is produced only
/// after Core verifies both complete proposals against that exact proof.
#[derive(Debug)]
#[must_use = "the exact anchored-successor bundle must enter its dedicated recovery session or be discarded"]
pub struct H1StateSyncAnchorSuccessorBundleV0 {
    child: Box<SignedProposalV0>,
    grandchild: Box<SignedProposalV0>,
}

impl H1StateSyncAnchorSuccessorBundleV0 {
    pub fn child(&self) -> &SignedProposalV0 {
        self.child.as_ref()
    }

    pub fn grandchild(&self) -> &SignedProposalV0 {
        self.grandchild.as_ref()
    }
}

/// Reconstructs the exact canonical rev0/rev1/rev2 SafetyState prefix named by
/// one authenticated anchored-successor challenge.
///
/// This is inert deterministic material for downstream durable-chain
/// verification. It does not create a Core, validation permit, application
/// authority, persistence request, or callback. The challenge itself can only
/// originate from a successfully validated recovery session.
pub fn reconstruct_h1_state_sync_anchor_successor_prefix_v0<V: SignatureVerifier>(
    config: &CoreConfig,
    challenge: &StateSyncAnchorSuccessorRecoveryChallengeV0,
    verifier: &V,
) -> Result<[SafetyState; 3]> {
    Core::validate_state_sync_anchor_successor_bundle_v0(
        config,
        challenge.safety_state(),
        challenge
            .safety_state()
            .state_sync_anchor()
            .ok_or(CoreError::StateSyncAnchorRecoveryNotRequired)?,
        challenge.child(),
        challenge.grandchild(),
        verifier,
    )?;
    let anchor = challenge
        .safety_state()
        .state_sync_anchor()
        .ok_or(CoreError::StateSyncAnchorRecoveryNotRequired)?;
    let revision_zero = SafetyState::from_h1_state_sync_anchor(
        config.validator_set(),
        config.genesis_block_id(),
        config
            .authenticated_genesis_application_parent_v0()
            .copied(),
        anchor.clone(),
    )?;
    let mut core = Core::empty(config.clone(), revision_zero.clone(), true);
    core.restore_state_sync_anchor_successor_tree_v0(
        StateSyncAnchorSuccessorPhaseV0::H1Bootstrap,
        challenge.child(),
        challenge.grandchild(),
    )?;
    let obligation_effects =
        core.step_state_sync_anchor_successor_proposal_v0(challenge.child().clone(), verifier)?;
    let revision_one = match obligation_effects.as_slice() {
        [Effect::PersistSafetyState(request)] if request.state().revision() == 1 => {
            request.state().clone()
        }
        _ => {
            return Err(CoreError::StateSyncAnchorSuccessorRecoveryRejected(
                "successor prefix reconstruction did not produce rev1",
            ));
        }
    };
    let h2_completion = challenge
        .safety_state()
        .payload_validation_completions()
        .iter()
        .find(|completion| {
            completion.id().block_id() == challenge.child().block().id()
                && completion.first_recorded_revision() == 2
        })
        .ok_or(CoreError::StateSyncAnchorSuccessorRecoveryRejected(
            "successor prefix reconstruction lacks h2 completion",
        ))?;
    let h2_overlay = h2_completion
        .result()
        .artifact_ref()
        .ok_or(CoreError::StateSyncAnchorSuccessorRecoveryRejected(
            "successor prefix reconstruction h2 completion is not Valid",
        ))?
        .overlay();
    let revision_two = SafetyState::from_persisted_parts_v13(
        revision_zero.schema_version(),
        revision_zero.chain_id(),
        revision_zero.protocol_version(),
        revision_zero.epoch(),
        revision_zero.validator_set_id(),
        revision_zero.genesis_block_id(),
        revision_zero
            .authenticated_genesis_application_parent_v0()
            .copied(),
        revision_zero.current_view(),
        revision_zero.last_voted_view(),
        revision_zero.last_timeout_view(),
        revision_zero.high_qc().clone(),
        revision_zero.locked_qc().clone(),
        revision_zero.finalized(),
        2,
        // The rev1 successor is the first reconstructed durable transition
        // and may have authenticated/observed QCs while restoring the
        // anchored proposal.  Carry that exact persisted cache into rev2;
        // rebasing to rev0 would look like an unbounded historical deletion
        // during successor validation after the schema-v13 restart proof.
        revision_one.durable_observed_qcs().to_vec(),
        vec![PayloadTerminalFact::new_valid(h2_overlay, 2)],
        Vec::new(),
        vec![h2_completion.clone()],
        revision_zero.pending_tc_high_qc_sync().cloned(),
        revision_zero.pending_standalone_qc_sync().cloned(),
        revision_zero.pending_sign().cloned(),
        revision_zero.last_finalization().cloned(),
        revision_zero.state_sync_anchor().cloned(),
        revision_zero.application_applied(),
        revision_zero.finalization_queue().to_vec(),
        revision_zero.pending_finalize(),
        revision_zero.safety_halt().cloned(),
    );
    Core::validate_persisted_successor_v0(config, &revision_one, &revision_two, verifier)?;
    Ok([revision_zero, revision_one, revision_two])
}

/// Trusted-host challenge for the exact durable h1/h2/h3 recovery cut.
///
/// A reconciler must authenticate every durable Valid completion exposed by
/// `safety_state` against its application-owned execution commitments, exact
/// body, overlay, and artifact before returning true. Core intentionally does
/// not re-execute the application or turn inert durable commitments back into
/// a live validation capability. Revision-zero has no completion, but still
/// requires the same trusted join so a caller cannot substitute unauthenticated
/// bodies.
#[derive(Debug)]
#[must_use = "the anchored-successor challenge must be reconciled before replay can progress"]
pub struct StateSyncAnchorSuccessorRecoveryChallengeV0 {
    safety_state: Box<SafetyState>,
    phase: StateSyncAnchorSuccessorPhaseV0,
    child: Box<SignedProposalV0>,
    grandchild: Box<SignedProposalV0>,
    affinity: Arc<()>,
}

impl StateSyncAnchorSuccessorRecoveryChallengeV0 {
    pub fn safety_state(&self) -> &SafetyState {
        self.safety_state.as_ref()
    }

    pub const fn phase(&self) -> StateSyncAnchorSuccessorPhaseV0 {
        self.phase
    }

    pub fn child(&self) -> &SignedProposalV0 {
        self.child.as_ref()
    }

    pub fn grandchild(&self) -> &SignedProposalV0 {
        self.grandchild.as_ref()
    }

    pub fn same_recovery_instance_v0(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.affinity, &other.affinity)
    }
}

/// Trusted application reconciliation boundary for anchored successor replay.
///
/// Returning true asserts that every completion already present in the
/// challenge was authenticated from the exact application journal and that
/// the supplied h2/h3 bodies bind those rows. This trait grants no signing,
/// networking, timer, finalization, or generic Core authority.
pub trait StateSyncAnchorSuccessorRecoveryReconcilerV0 {
    fn reconcile_state_sync_anchor_successors_v0(
        &mut self,
        challenge: &StateSyncAnchorSuccessorRecoveryChallengeV0,
    ) -> bool;
}

/// Inert owner of one exact anchored-successor recovery attempt.
#[derive(Debug)]
#[must_use = "dropping the session keeps anchored successor replay fail-closed"]
pub struct StateSyncAnchorSuccessorRecoverySessionV0 {
    core: Core,
    challenge: StateSyncAnchorSuccessorRecoveryChallengeV0,
}

impl StateSyncAnchorSuccessorRecoverySessionV0 {
    pub const fn challenge(&self) -> &StateSyncAnchorSuccessorRecoveryChallengeV0 {
        &self.challenge
    }

    pub fn reconcile_and_activate_v0<R: StateSyncAnchorSuccessorRecoveryReconcilerV0>(
        mut self,
        reconciler: &mut R,
    ) -> Result<StateSyncAnchorSuccessorReplayV0> {
        if !reconciler.reconcile_state_sync_anchor_successors_v0(&self.challenge)
            || !Arc::ptr_eq(&self.core.persistence_affinity.0, &self.challenge.affinity)
            || self.core.safety != *self.challenge.safety_state
        {
            return Err(CoreError::StateSyncAnchorSuccessorRecoveryRejected(
                "the trusted host rejected the exact application successor closure",
            ));
        }
        if matches!(
            self.challenge.phase,
            StateSyncAnchorSuccessorPhaseV0::H2ValidationPending
                | StateSyncAnchorSuccessorPhaseV0::H3ValidationPending
        ) {
            self.core
                .validate_replayed_state_sync_anchor_successor_obligation_v0(
                    self.challenge.phase,
                )?;
        } else {
            self.core.restore_state_sync_anchor_successor_tree_v0(
                self.challenge.phase,
                self.challenge.child.as_ref(),
                self.challenge.grandchild.as_ref(),
            )?;
        }
        Ok(StateSyncAnchorSuccessorReplayV0 {
            core: self.core,
            child: self.challenge.child,
            grandchild: self.challenge.grandchild,
        })
    }
}

/// Narrow live owner for canonical h2/h3 safety replay above an h1 anchor.
///
/// This wrapper intentionally does not expose generic `Core::step`. Its only
/// mutating methods are the exact next proof proposal, its persistence ack,
/// and an opaque application-sealed Valid callback. Replay completion and all
/// timer/sign/network/finality paths remain unreachable.
#[derive(Debug)]
#[must_use = "the anchored successor replay owner must finish or remain durably fenced"]
pub struct StateSyncAnchorSuccessorReplayV0 {
    core: Core,
    child: Box<SignedProposalV0>,
    grandchild: Box<SignedProposalV0>,
}

impl StateSyncAnchorSuccessorReplayV0 {
    pub const fn config(&self) -> &CoreConfig {
        self.core.config()
    }

    pub const fn safety_state(&self) -> &SafetyState {
        self.core.safety_state()
    }

    pub fn phase(&self) -> Result<StateSyncAnchorSuccessorPhaseV0> {
        self.core.state_sync_anchor_successor_phase_v0()
    }

    pub fn safety_state_persistence_binding_v0(&self) -> SafetyStatePersistenceBindingV0 {
        self.core.safety_state_persistence_binding_v0()
    }

    pub fn issue_application_seal_authority_v0(
        &self,
    ) -> Result<CoreIssuedApplicationSealAuthorityV0> {
        self.core.issue_application_seal_authority_v0()
    }

    pub fn step_next_proposal_v0<V: SignatureVerifier>(
        &mut self,
        verifier: &V,
    ) -> Result<Vec<Effect>> {
        let proposal = match self.phase()? {
            StateSyncAnchorSuccessorPhaseV0::H1Bootstrap => self.child.as_ref().clone(),
            StateSyncAnchorSuccessorPhaseV0::H2Valid => self.grandchild.as_ref().clone(),
            StateSyncAnchorSuccessorPhaseV0::H2ValidationPending
            | StateSyncAnchorSuccessorPhaseV0::H3ValidationPending
            | StateSyncAnchorSuccessorPhaseV0::H3Valid => {
                return Err(CoreError::StateSyncAnchorSuccessorRecoveryRejected(
                    "the canonical next successor proposal is not available in this phase",
                ));
            }
        };
        self.core
            .step_state_sync_anchor_successor_proposal_v0(proposal, verifier)
    }

    pub fn step_storage_ack_v0<V: SignatureVerifier>(
        &mut self,
        barrier: BarrierId,
        verifier: &V,
    ) -> Result<Vec<Effect>> {
        self.core
            .step_state_sync_anchor_successor_input_v0(Input::StorageAck { barrier }, verifier)
    }

    /// Reissues only the exact Core-affined persistence request which was
    /// reproduced while taking over a durable revision-one or revision-three
    /// obligation.  It contains no validation permit; the real request remains
    /// fenced until [`Self::step_storage_ack_v0`] acknowledges this barrier.
    pub fn pending_obligation_persistence_v0(&self) -> Result<SafetyStatePersistenceV0> {
        self.core
            .state_sync_anchor_successor_obligation_persistence_v0()
    }

    pub fn step_application_sealed_valid_v0<V: SignatureVerifier>(
        &mut self,
        proof: &ApplicationSealedValidV0,
        verifier: &V,
    ) -> Result<Vec<Effect>> {
        self.core
            .step_state_sync_anchor_successor_sealed_valid_v0(proof, verifier)
    }

    /// Accepts the exact application-sealed anchored-successor Valid callback
    /// and returns Core's non-cloneable durable-delivery (`D`) carrier.
    pub fn step_application_sealed_valid_to_delivery_v0<V: SignatureVerifier>(
        &mut self,
        proof: &ApplicationSealedValidV0,
        verifier: &V,
    ) -> Result<CoreAcceptedApplicationValidDV0> {
        self.core
            .step_state_sync_anchor_successor_sealed_valid_to_delivery_v0(proof, verifier)
    }

    /// Persists the sole durable transition from canonical H3Valid revision
    /// four into the anchored-ordinary revision-five cut.
    ///
    /// The returned request carries a Core-owned promotion manifest.  No
    /// ordinary Core is released until the exact barrier is acknowledged by
    /// [`Self::acknowledge_ordinary_promotion_v0`].
    pub fn step_ordinary_promotion_v0<V: SignatureVerifier>(
        &mut self,
        verifier: &V,
    ) -> Result<Vec<Effect>> {
        self.core
            .step_state_sync_anchor_ordinary_promotion_v0(verifier)
    }

    /// Consumes the fenced replay owner only after revision five is durable,
    /// validates the complete restored h1→h2→h3 ancestry through Core's
    /// ordinary replay-complete path, and releases the generic Core together
    /// with its exact first timer effect.
    pub fn acknowledge_ordinary_promotion_v0<V: SignatureVerifier>(
        self,
        barrier: BarrierId,
        verifier: &V,
    ) -> Result<StateSyncAnchorOrdinaryActivationV0> {
        let mut core = self.core;
        let effects =
            core.acknowledge_state_sync_anchor_ordinary_promotion_v0(barrier, verifier)?;
        Ok(StateSyncAnchorOrdinaryActivationV0 { core, effects })
    }
}

/// Trusted-host challenge for recovering an already-promoted state-sync
/// anchored namespace.
///
/// The exact h2/h3 bodies remain external to SafetyState.  A reconciler must
/// join both bodies and every retained durable Valid fact to the application
/// store before a generic Core can be released.
#[derive(Debug)]
#[must_use = "the anchored-ordinary challenge must be reconciled before Core activation"]
pub struct StateSyncAnchorOrdinaryRecoveryChallengeV0 {
    safety_state: Box<SafetyState>,
    child: Box<SignedProposalV0>,
    grandchild: Box<SignedProposalV0>,
    affinity: Arc<()>,
}

impl StateSyncAnchorOrdinaryRecoveryChallengeV0 {
    pub fn safety_state(&self) -> &SafetyState {
        self.safety_state.as_ref()
    }

    pub fn child(&self) -> &SignedProposalV0 {
        self.child.as_ref()
    }

    pub fn grandchild(&self) -> &SignedProposalV0 {
        self.grandchild.as_ref()
    }
}

pub trait StateSyncAnchorOrdinaryRecoveryReconcilerV0 {
    fn reconcile_state_sync_anchor_ordinary_v0(
        &mut self,
        challenge: &StateSyncAnchorOrdinaryRecoveryChallengeV0,
    ) -> bool;
}

/// Untrusted archive/session envelope for one checkpoint-complete ordinary
/// ancestry replay.
///
/// These fields are inert comparison data.  In particular, digest equality
/// cannot replace possession of the application, validation-journal, or
/// external-checkpoint owners which created the durable rows.  Core binds the
/// complete envelope into [`AnchoredOrdinaryRehydrateChallengeV0`]; a trusted
/// host must join that challenge to those still-live owners before rehydrated
/// tree authority can exist.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AnchoredOrdinaryReplayArchivePlanV0 {
    core_config_ref: [u8; 32],
    recovery_challenge_digest: [u8; 32],
    archive_context_digest: [u8; 32],
    archive_sequence: u64,
    archive_record_digest: [u8; 32],
    session_id: [u8; 32],
    validation_store_id: [u8; 32],
    expected_link_count: u64,
    canonical_store_sequence: u64,
    application_history_digest: [u8; 32],
    initial_safety_revision: u64,
    initial_safety_state_checksum: [u8; 32],
    initial_safety_chain_checksum: [u8; 32],
    initial_checkpoint_scope: [u8; 32],
    initial_checkpoint_profile_ref: [u8; 32],
    initial_checkpoint_generation: u64,
    initial_checkpoint_checksum: [u8; 32],
    initial_progress_checksum: [u8; 32],
    final_progress_checksum: [u8; 32],
    durable_session_row_checksum: [u8; 32],
}

impl AnchoredOrdinaryReplayArchivePlanV0 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        core_config_ref: [u8; 32],
        recovery_challenge_digest: [u8; 32],
        archive_context_digest: [u8; 32],
        archive_sequence: u64,
        archive_record_digest: [u8; 32],
        session_id: [u8; 32],
        validation_store_id: [u8; 32],
        expected_link_count: u64,
        canonical_store_sequence: u64,
        application_history_digest: [u8; 32],
        initial_safety_revision: u64,
        initial_safety_state_checksum: [u8; 32],
        initial_safety_chain_checksum: [u8; 32],
        initial_checkpoint_scope: [u8; 32],
        initial_checkpoint_profile_ref: [u8; 32],
        initial_checkpoint_generation: u64,
        initial_checkpoint_checksum: [u8; 32],
        initial_progress_checksum: [u8; 32],
        final_progress_checksum: [u8; 32],
        durable_session_row_checksum: [u8; 32],
    ) -> Result<Self> {
        let digests = [
            core_config_ref,
            recovery_challenge_digest,
            archive_context_digest,
            archive_record_digest,
            session_id,
            validation_store_id,
            application_history_digest,
            initial_safety_state_checksum,
            initial_safety_chain_checksum,
            initial_checkpoint_scope,
            initial_checkpoint_profile_ref,
            initial_checkpoint_checksum,
            initial_progress_checksum,
            final_progress_checksum,
            durable_session_row_checksum,
        ];
        if digests.contains(&[0; 32])
            || archive_sequence == 0
            || expected_link_count == 0
            || canonical_store_sequence == 0
            || initial_safety_revision < 5
        {
            return Err(CoreError::AnchoredOrdinaryRehydrateRejected(
                "archive plan contains a zero or pre-promotion field",
            ));
        }
        initial_safety_revision
            .checked_add(expected_link_count.checked_mul(2).ok_or(
                CoreError::ArithmeticOverflow("anchored ordinary replay safety span"),
            )?)
            .ok_or(CoreError::ArithmeticOverflow(
                "anchored ordinary replay terminal safety revision",
            ))?;
        initial_checkpoint_generation
            .checked_add(expected_link_count)
            .ok_or(CoreError::ArithmeticOverflow(
                "anchored ordinary replay checkpoint span",
            ))?;
        Ok(Self {
            core_config_ref,
            recovery_challenge_digest,
            archive_context_digest,
            archive_sequence,
            archive_record_digest,
            session_id,
            validation_store_id,
            expected_link_count,
            canonical_store_sequence,
            application_history_digest,
            initial_safety_revision,
            initial_safety_state_checksum,
            initial_safety_chain_checksum,
            initial_checkpoint_scope,
            initial_checkpoint_profile_ref,
            initial_checkpoint_generation,
            initial_checkpoint_checksum,
            initial_progress_checksum,
            final_progress_checksum,
            durable_session_row_checksum,
        })
    }

    pub const fn core_config_ref_v0(self) -> [u8; 32] {
        self.core_config_ref
    }

    pub const fn recovery_challenge_digest_v0(self) -> [u8; 32] {
        self.recovery_challenge_digest
    }

    pub const fn archive_context_digest_v0(self) -> [u8; 32] {
        self.archive_context_digest
    }

    pub const fn archive_sequence_v0(self) -> u64 {
        self.archive_sequence
    }

    pub const fn archive_record_digest_v0(self) -> [u8; 32] {
        self.archive_record_digest
    }

    pub const fn session_id_v0(self) -> [u8; 32] {
        self.session_id
    }

    pub const fn validation_store_id_v0(self) -> [u8; 32] {
        self.validation_store_id
    }

    pub const fn expected_link_count_v0(self) -> u64 {
        self.expected_link_count
    }

    pub const fn canonical_store_sequence_v0(self) -> u64 {
        self.canonical_store_sequence
    }

    pub const fn application_history_digest_v0(self) -> [u8; 32] {
        self.application_history_digest
    }

    pub const fn initial_safety_revision_v0(self) -> u64 {
        self.initial_safety_revision
    }

    pub const fn initial_safety_state_checksum_v0(self) -> [u8; 32] {
        self.initial_safety_state_checksum
    }

    pub const fn initial_safety_chain_checksum_v0(self) -> [u8; 32] {
        self.initial_safety_chain_checksum
    }

    pub const fn initial_checkpoint_scope_v0(self) -> [u8; 32] {
        self.initial_checkpoint_scope
    }

    pub const fn initial_checkpoint_profile_ref_v0(self) -> [u8; 32] {
        self.initial_checkpoint_profile_ref
    }

    pub const fn initial_checkpoint_generation_v0(self) -> u64 {
        self.initial_checkpoint_generation
    }

    pub const fn initial_checkpoint_checksum_v0(self) -> [u8; 32] {
        self.initial_checkpoint_checksum
    }

    pub const fn initial_progress_checksum_v0(self) -> [u8; 32] {
        self.initial_progress_checksum
    }

    pub const fn final_progress_checksum_v0(self) -> [u8; 32] {
        self.final_progress_checksum
    }

    pub const fn durable_session_row_checksum_v0(self) -> [u8; 32] {
        self.durable_session_row_checksum
    }
}

/// Opaque comparison projection of one application- and checkpoint-confirmed
/// replay link.  Public construction is intentionally non-authoritative: the
/// later reconciler must still prove that every field came from the exact
/// non-cloneable checkpointed link owner in the named validation store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AnchoredOrdinaryCheckpointedLinkClaimV0 {
    session_id: [u8; 32],
    cursor: u64,
    source_validation_store_id: [u8; 32],
    target_validation_store_id: [u8; 32],
    target_core_validation_id: ValidationId,
    owner_id: [u8; 32],
    source_store_sequence: u64,
    source_row_revision: u64,
    source_row_checksum: [u8; 32],
    source_artifact_checksum: [u8; 32],
    source_application_history_checksum: [u8; 32],
    safety_revision: u64,
    alias_closure_checksum: [u8; 32],
    checkpoint_scope: [u8; 32],
    checkpoint_profile_ref: [u8; 32],
    checkpoint_predecessor_checksum: [u8; 32],
    checkpoint_generation: u64,
    checkpoint_checksum: [u8; 32],
    previous_progress_checksum: [u8; 32],
    progress_checksum: [u8; 32],
    link_row_revision: u64,
    link_row_checksum: [u8; 32],
}

impl AnchoredOrdinaryCheckpointedLinkClaimV0 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        session_id: [u8; 32],
        cursor: u64,
        source_validation_store_id: [u8; 32],
        target_validation_store_id: [u8; 32],
        target_core_validation_id: ValidationId,
        owner_id: [u8; 32],
        source_store_sequence: u64,
        source_row_revision: u64,
        source_row_checksum: [u8; 32],
        source_artifact_checksum: [u8; 32],
        source_application_history_checksum: [u8; 32],
        safety_revision: u64,
        alias_closure_checksum: [u8; 32],
        checkpoint_scope: [u8; 32],
        checkpoint_profile_ref: [u8; 32],
        checkpoint_predecessor_checksum: [u8; 32],
        checkpoint_generation: u64,
        checkpoint_checksum: [u8; 32],
        previous_progress_checksum: [u8; 32],
        progress_checksum: [u8; 32],
        link_row_revision: u64,
        link_row_checksum: [u8; 32],
    ) -> Result<Self> {
        let digests = [
            session_id,
            source_validation_store_id,
            target_validation_store_id,
            owner_id,
            source_row_checksum,
            source_artifact_checksum,
            source_application_history_checksum,
            alias_closure_checksum,
            checkpoint_scope,
            checkpoint_profile_ref,
            checkpoint_predecessor_checksum,
            checkpoint_checksum,
            previous_progress_checksum,
            progress_checksum,
            link_row_checksum,
        ];
        if digests.contains(&[0; 32])
            || source_validation_store_id == target_validation_store_id
            || target_core_validation_id.generation() == 0
            || source_store_sequence == 0
            || source_row_revision == 0
            || safety_revision == 0
            || checkpoint_generation == 0
            || link_row_revision == 0
        {
            return Err(CoreError::AnchoredOrdinaryRehydrateRejected(
                "checkpointed link claim contains a zero or aliased field",
            ));
        }
        Ok(Self {
            session_id,
            cursor,
            source_validation_store_id,
            target_validation_store_id,
            target_core_validation_id,
            owner_id,
            source_store_sequence,
            source_row_revision,
            source_row_checksum,
            source_artifact_checksum,
            source_application_history_checksum,
            safety_revision,
            alias_closure_checksum,
            checkpoint_scope,
            checkpoint_profile_ref,
            checkpoint_predecessor_checksum,
            checkpoint_generation,
            checkpoint_checksum,
            previous_progress_checksum,
            progress_checksum,
            link_row_revision,
            link_row_checksum,
        })
    }

    pub const fn session_id_v0(self) -> [u8; 32] {
        self.session_id
    }

    pub const fn cursor_v0(self) -> u64 {
        self.cursor
    }

    pub const fn source_validation_store_id_v0(self) -> [u8; 32] {
        self.source_validation_store_id
    }

    pub const fn target_validation_store_id_v0(self) -> [u8; 32] {
        self.target_validation_store_id
    }

    pub const fn target_core_validation_id_v0(self) -> ValidationId {
        self.target_core_validation_id
    }

    pub const fn owner_id_v0(self) -> [u8; 32] {
        self.owner_id
    }

    pub const fn source_store_sequence_v0(self) -> u64 {
        self.source_store_sequence
    }

    pub const fn source_row_revision_v0(self) -> u64 {
        self.source_row_revision
    }

    pub const fn source_row_checksum_v0(self) -> [u8; 32] {
        self.source_row_checksum
    }

    pub const fn source_artifact_checksum_v0(self) -> [u8; 32] {
        self.source_artifact_checksum
    }

    pub const fn source_application_history_checksum_v0(self) -> [u8; 32] {
        self.source_application_history_checksum
    }

    pub const fn safety_revision_v0(self) -> u64 {
        self.safety_revision
    }

    pub const fn alias_closure_checksum_v0(self) -> [u8; 32] {
        self.alias_closure_checksum
    }

    pub const fn checkpoint_scope_v0(self) -> [u8; 32] {
        self.checkpoint_scope
    }

    pub const fn checkpoint_profile_ref_v0(self) -> [u8; 32] {
        self.checkpoint_profile_ref
    }

    pub const fn checkpoint_predecessor_checksum_v0(self) -> [u8; 32] {
        self.checkpoint_predecessor_checksum
    }

    pub const fn checkpoint_generation_v0(self) -> u64 {
        self.checkpoint_generation
    }

    pub const fn checkpoint_checksum_v0(self) -> [u8; 32] {
        self.checkpoint_checksum
    }

    pub const fn previous_progress_checksum_v0(self) -> [u8; 32] {
        self.previous_progress_checksum
    }

    pub const fn progress_checksum_v0(self) -> [u8; 32] {
        self.progress_checksum
    }

    pub const fn link_row_revision_v0(self) -> u64 {
        self.link_row_revision
    }

    pub const fn link_row_checksum_v0(self) -> [u8; 32] {
        self.link_row_checksum
    }
}

/// Exact signed proposal/certifying-QC pair joined to one untrusted
/// checkpointed-link projection.  Core independently authenticates the
/// proposal, certificate, chain position, durable Safety completion, and
/// Valid overlay before exposing the later host reconciliation challenge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnchoredOrdinarySignedReplayEntryV0 {
    proposal: SignedProposalV0,
    certifying_qc: QuorumCertificate,
    checkpointed_link: AnchoredOrdinaryCheckpointedLinkClaimV0,
}

impl AnchoredOrdinarySignedReplayEntryV0 {
    pub fn new(
        proposal: SignedProposalV0,
        certifying_qc: QuorumCertificate,
        checkpointed_link: AnchoredOrdinaryCheckpointedLinkClaimV0,
    ) -> Self {
        Self {
            proposal,
            certifying_qc,
            checkpointed_link,
        }
    }

    pub const fn proposal_v0(&self) -> &SignedProposalV0 {
        &self.proposal
    }

    pub const fn certifying_qc_v0(&self) -> &QuorumCertificate {
        &self.certifying_qc
    }

    pub const fn checkpointed_link_v0(&self) -> AnchoredOrdinaryCheckpointedLinkClaimV0 {
        self.checkpointed_link
    }
}

/// Core-authenticated but still host-unreconciled ordinary replay challenge.
///
/// A raw digest or link claim never authorizes this value.  It is minted only
/// after complete proposal/QC crypto and volatile-tree reconstruction from an
/// already authenticated anchored-ordinary recovery owner.
#[derive(Debug)]
#[must_use = "the checkpointed replay challenge must be joined to its durable store owners"]
pub struct AnchoredOrdinaryRehydrateChallengeV0 {
    safety_state: Box<SafetyState>,
    plan: AnchoredOrdinaryReplayArchivePlanV0,
    entries: Vec<AnchoredOrdinarySignedReplayEntryV0>,
    rehydrate_digest: [u8; 32],
    affinity: Arc<()>,
}

impl AnchoredOrdinaryRehydrateChallengeV0 {
    pub fn safety_state_v0(&self) -> &SafetyState {
        self.safety_state.as_ref()
    }

    pub const fn plan_v0(&self) -> AnchoredOrdinaryReplayArchivePlanV0 {
        self.plan
    }

    pub fn entries_v0(&self) -> &[AnchoredOrdinarySignedReplayEntryV0] {
        &self.entries
    }

    pub const fn rehydrate_digest_v0(&self) -> [u8; 32] {
        self.rehydrate_digest
    }

    pub fn same_recovery_instance_v0(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.affinity, &other.affinity)
    }
}

/// Trusted host join for exact checkpointed replay links.
///
/// Returning `true` asserts that the complete challenge still matches the
/// non-cloneable validation-store/session owners, every canonical source K and
/// application-history row, and the exact external-checkpoint chain.  This
/// trait grants no signing, timer, ingress, or generic Core authority.
pub trait AnchoredOrdinaryRehydrateReconcilerV0 {
    fn reconcile_checkpointed_ordinary_replay_v0(
        &mut self,
        challenge: &AnchoredOrdinaryRehydrateChallengeV0,
    ) -> bool;
}

/// Process-affined session after Core crypto/tree validation but before the
/// durable application/checkpoint owners have confirmed the opaque claims.
#[derive(Debug)]
#[must_use = "dropping the session keeps ordinary replay fail-closed"]
pub struct AnchoredOrdinaryRehydrateSessionV0 {
    core: Core,
    challenge: AnchoredOrdinaryRehydrateChallengeV0,
}

impl AnchoredOrdinaryRehydrateSessionV0 {
    pub const fn challenge_v0(&self) -> &AnchoredOrdinaryRehydrateChallengeV0 {
        &self.challenge
    }

    pub fn reconcile_checkpointed_links_v0<R: AnchoredOrdinaryRehydrateReconcilerV0>(
        self,
        reconciler: &mut R,
    ) -> Result<AnchoredOrdinaryRehydratedOwnerV0> {
        if !reconciler.reconcile_checkpointed_ordinary_replay_v0(&self.challenge)
            || !Arc::ptr_eq(&self.core.persistence_affinity.0, &self.challenge.affinity)
            || self.core.safety != *self.challenge.safety_state
            || !self.core.replay_required
        {
            return Err(CoreError::AnchoredOrdinaryRehydrateRejected(
                "the trusted host rejected the exact checkpointed replay closure",
            ));
        }
        let facts = AnchoredOrdinaryRehydratedFactsV0 {
            safety_revision: self.core.safety.revision(),
            replayed_link_count: self.challenge.plan.expected_link_count,
            finalized: self.core.safety.finalized(),
            high_qc: self.core.safety.high_qc().qc_ref(),
            locked_qc: self.core.safety.locked_qc().qc_ref(),
            archive_context_digest: self.challenge.plan.archive_context_digest,
            archive_record_digest: self.challenge.plan.archive_record_digest,
            session_id: self.challenge.plan.session_id,
            final_progress_checksum: self.challenge.plan.final_progress_checksum,
            rehydrate_digest: self.challenge.rehydrate_digest,
        };
        Ok(AnchoredOrdinaryRehydratedOwnerV0 {
            _core: self.core,
            challenge: self.challenge,
            facts,
        })
    }
}

/// Descriptive facts from one exact replay-fenced tree rehydration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AnchoredOrdinaryRehydratedFactsV0 {
    safety_revision: u64,
    replayed_link_count: u64,
    finalized: FinalizedTip,
    high_qc: QcRef,
    locked_qc: QcRef,
    archive_context_digest: [u8; 32],
    archive_record_digest: [u8; 32],
    session_id: [u8; 32],
    final_progress_checksum: [u8; 32],
    rehydrate_digest: [u8; 32],
}

impl AnchoredOrdinaryRehydratedFactsV0 {
    pub const fn safety_revision_v0(self) -> u64 {
        self.safety_revision
    }

    pub const fn replayed_link_count_v0(self) -> u64 {
        self.replayed_link_count
    }

    pub const fn finalized_v0(self) -> FinalizedTip {
        self.finalized
    }

    pub const fn high_qc_v0(self) -> QcRef {
        self.high_qc
    }

    pub const fn locked_qc_v0(self) -> QcRef {
        self.locked_qc
    }

    pub const fn archive_context_digest_v0(self) -> [u8; 32] {
        self.archive_context_digest
    }

    pub const fn archive_record_digest_v0(self) -> [u8; 32] {
        self.archive_record_digest
    }

    pub const fn session_id_v0(self) -> [u8; 32] {
        self.session_id
    }

    pub const fn final_progress_checksum_v0(self) -> [u8; 32] {
        self.final_progress_checksum
    }

    pub const fn rehydrate_digest_v0(self) -> [u8; 32] {
        self.rehydrate_digest
    }
}

/// Final inert owner of a fully authenticated, replay-fenced ordinary tree.
///
/// It intentionally exposes no `Core`, effect, timer, signer, or ingress
/// extraction.  Its sole activation transition consumes the owner and accepts
/// only Core's exact replay-complete timer.  The later node host must still
/// join the returned linear activation to independent signer, deadline, and
/// peer-session authorities before driving that timer or admitting ingress.
#[derive(Debug)]
#[must_use = "rehydrated ordinary ancestry remains replay-fenced"]
pub struct AnchoredOrdinaryRehydratedOwnerV0 {
    _core: Core,
    challenge: AnchoredOrdinaryRehydrateChallengeV0,
    facts: AnchoredOrdinaryRehydratedFactsV0,
}

impl AnchoredOrdinaryRehydratedOwnerV0 {
    pub const fn facts_v0(&self) -> AnchoredOrdinaryRehydratedFactsV0 {
        self.facts
    }

    pub const fn challenge_v0(&self) -> &AnchoredOrdinaryRehydrateChallengeV0 {
        &self.challenge
    }

    /// Authority-free commitment to the exact finalized prefix retained by
    /// this replay-fenced owner. Reading it does not clear the replay fence,
    /// release the startup timer, or expose the underlying Core.
    pub fn finalized_chain_root_v0(&self) -> FinalizedChainRootV0 {
        self._core.finalized_chain_root_v0()
    }

    /// Clears Core's replay fence and releases only the exact timer belonging
    /// to the authenticated durable `epoch/current_view` cut.
    ///
    /// The transition is intentionally consuming.  A failed transition drops
    /// the process-local Core, while success returns one non-cloneable owner;
    /// neither branch can retry or fork this owner.  This operation does not
    /// activate a signer, arm a deadline, establish a peer session, or grant
    /// ingress authority.
    pub fn reconcile_and_activate_checkpointed_ordinary_v0<V: SignatureVerifier>(
        mut self,
        verifier: &V,
    ) -> Result<AnchoredOrdinaryActivatedV0> {
        let expected_facts = AnchoredOrdinaryRehydratedFactsV0 {
            safety_revision: self._core.safety.revision(),
            replayed_link_count: self.challenge.plan.expected_link_count,
            finalized: self._core.safety.finalized(),
            high_qc: self._core.safety.high_qc().qc_ref(),
            locked_qc: self._core.safety.locked_qc().qc_ref(),
            archive_context_digest: self.challenge.plan.archive_context_digest,
            archive_record_digest: self.challenge.plan.archive_record_digest,
            session_id: self.challenge.plan.session_id,
            final_progress_checksum: self.challenge.plan.final_progress_checksum,
            rehydrate_digest: self.challenge.rehydrate_digest,
        };
        if !Arc::ptr_eq(&self._core.persistence_affinity.0, &self.challenge.affinity)
            || self._core.safety != *self.challenge.safety_state
            || self.facts != expected_facts
            || !self._core.replay_required
        {
            return Err(CoreError::AnchoredOrdinaryRehydrateRejected(
                "checkpointed ordinary activation lost its exact rehydrated owner binding",
            ));
        }

        let effects = self._core.handle_replay_complete(verifier)?;
        self._core.validate_runtime(verifier, false)?;
        let startup_timer = exact_anchored_ordinary_replay_complete_timer_v0(&self._core, effects)?;
        Ok(AnchoredOrdinaryActivatedV0 {
            core: self._core,
            startup_timer,
            facts: self.facts,
        })
    }
}

/// Single-use Core-authenticated startup timer for an activated checkpointed
/// ordinary owner.
///
/// Its fields are private and it is deliberately not `Clone` or `Copy`.  Raw
/// epoch/view facts cannot construct this authority; only the consuming replay
/// completion transition above can mint it.
///
/// ```compile_fail
/// use trnm_consensus_core::AnchoredOrdinaryArmViewTimerV0;
/// use trnm_consensus_types::{Epoch, View};
/// let _forged = AnchoredOrdinaryArmViewTimerV0 {
///     epoch: Epoch::new(0),
///     view: View::new(1),
/// };
/// ```
#[derive(Debug, PartialEq, Eq)]
#[must_use = "the exact activated ordinary timer must remain linear until the node arms it"]
pub struct AnchoredOrdinaryArmViewTimerV0 {
    epoch: Epoch,
    view: View,
}

impl AnchoredOrdinaryArmViewTimerV0 {
    pub const fn epoch_v0(&self) -> Epoch {
        self.epoch
    }

    pub const fn view_v0(&self) -> View {
        self.view
    }

    /// Consumes the typed timer into Core's ordinary effect carrier.  The
    /// caller must still own the external pacemaker/deadline authority.
    pub fn into_effect_v0(self) -> Effect {
        Effect::ArmViewTimer {
            epoch: self.epoch,
            view: self.view,
        }
    }
}

/// Linear activated Core plus the sole startup timer released by replay
/// completion.
///
/// Construction and fields remain private.  No shared or mutable raw-Core
/// accessor exists; the later node integration must consume the whole owner to
/// obtain its parts exactly once.
///
/// ```compile_fail
/// use trnm_consensus_core::AnchoredOrdinaryActivatedV0;
/// fn require_clone<T: Clone>() {}
/// require_clone::<AnchoredOrdinaryActivatedV0>();
/// ```
///
/// ```compile_fail
/// use trnm_consensus_core::{
///     AnchoredOrdinaryActivatedV0, AnchoredOrdinaryArmViewTimerV0, Core,
/// };
/// fn forge(core: Core, timer: AnchoredOrdinaryArmViewTimerV0) -> AnchoredOrdinaryActivatedV0 {
///     AnchoredOrdinaryActivatedV0 {
///         core,
///         startup_timer: timer,
///         facts: unreachable!(),
///     }
/// }
/// ```
///
/// ```compile_fail
/// use trnm_consensus_core::AnchoredOrdinaryActivatedV0;
/// fn consume_twice(owner: AnchoredOrdinaryActivatedV0) {
///     let _parts = owner.into_parts_v0();
///     let _again = owner.into_parts_v0();
/// }
/// ```
#[derive(Debug)]
#[must_use = "the activated ordinary Core and its exact timer must remain together"]
pub struct AnchoredOrdinaryActivatedV0 {
    core: Core,
    startup_timer: AnchoredOrdinaryArmViewTimerV0,
    facts: AnchoredOrdinaryRehydratedFactsV0,
}

impl AnchoredOrdinaryActivatedV0 {
    pub const fn facts_v0(&self) -> AnchoredOrdinaryRehydratedFactsV0 {
        self.facts
    }

    pub const fn startup_timer_v0(&self) -> &AnchoredOrdinaryArmViewTimerV0 {
        &self.startup_timer
    }

    pub fn into_parts_v0(self) -> (Core, AnchoredOrdinaryArmViewTimerV0) {
        (self.core, self.startup_timer)
    }
}

pub(crate) fn exact_anchored_ordinary_replay_complete_timer_v0(
    core: &Core,
    effects: Vec<Effect>,
) -> Result<AnchoredOrdinaryArmViewTimerV0> {
    if core.replay_required {
        return Err(CoreError::AnchoredOrdinaryRehydrateRejected(
            "checkpointed ordinary activation retained the replay fence",
        ));
    }
    let [Effect::ArmViewTimer { epoch, view }] = effects.as_slice() else {
        return Err(CoreError::AnchoredOrdinaryRehydrateRejected(
            "checkpointed ordinary activation did not release exactly one timer",
        ));
    };
    if *epoch != core.safety.epoch() || *view != core.safety.current_view() {
        return Err(CoreError::AnchoredOrdinaryRehydrateRejected(
            "checkpointed ordinary activation timer does not match the durable cut",
        ));
    }
    Ok(AnchoredOrdinaryArmViewTimerV0 {
        epoch: *epoch,
        view: *view,
    })
}

/// Inert recovery owner for one already-promoted anchored-ordinary cut.
#[derive(Debug)]
#[must_use = "dropping the session keeps the promoted namespace fail-closed"]
pub struct StateSyncAnchorOrdinaryRecoverySessionV0 {
    core: Core,
    challenge: StateSyncAnchorOrdinaryRecoveryChallengeV0,
}

impl StateSyncAnchorOrdinaryRecoverySessionV0 {
    pub const fn challenge(&self) -> &StateSyncAnchorOrdinaryRecoveryChallengeV0 {
        &self.challenge
    }

    /// Consumes an authenticated anchored-ordinary recovery session into the
    /// process3-safe bulk ancestry rehydration boundary.
    ///
    /// The existing application reconciler first joins the permanent h1 and
    /// exact h2/h3 bodies. Core then verifies every ordinary Proposal/QC,
    /// reconstructs the complete Valid overlay tree, and proves the durable
    /// finalized/high/locked anchors against that tree. It does not call
    /// `SafetyReplayComplete`, mutate SafetyState, emit an effect, request a
    /// signature, arm a timer, or release generic Core/ingress authority.
    #[allow(clippy::too_many_arguments)]
    pub fn begin_checkpointed_ordinary_rehydrate_v0<
        R: StateSyncAnchorOrdinaryRecoveryReconcilerV0,
        V: SignatureVerifier,
    >(
        mut self,
        reconciler: &mut R,
        plan: AnchoredOrdinaryReplayArchivePlanV0,
        entries: Vec<AnchoredOrdinarySignedReplayEntryV0>,
        verifier: &V,
    ) -> Result<AnchoredOrdinaryRehydrateSessionV0> {
        if !reconciler.reconcile_state_sync_anchor_ordinary_v0(&self.challenge)
            || !Arc::ptr_eq(&self.core.persistence_affinity.0, &self.challenge.affinity)
            || self.core.safety != *self.challenge.safety_state
        {
            return Err(CoreError::AnchoredOrdinaryRehydrateRejected(
                "the trusted host rejected the promoted application successor closure",
            ));
        }
        self.core.restore_state_sync_anchor_successor_tree_v0(
            StateSyncAnchorSuccessorPhaseV0::H3Valid,
            self.challenge.child.as_ref(),
            self.challenge.grandchild.as_ref(),
        )?;
        let rehydrate_digest = self
            .core
            .rehydrate_checkpointed_ordinary_tree_v0(&plan, &entries, verifier)?;
        let affinity = Arc::clone(&self.core.persistence_affinity.0);
        let safety_state = self.challenge.safety_state;
        Ok(AnchoredOrdinaryRehydrateSessionV0 {
            core: self.core,
            challenge: AnchoredOrdinaryRehydrateChallengeV0 {
                safety_state,
                plan,
                entries,
                rehydrate_digest,
                affinity,
            },
        })
    }

    pub fn reconcile_and_activate_v0<
        R: StateSyncAnchorOrdinaryRecoveryReconcilerV0,
        V: SignatureVerifier,
    >(
        mut self,
        reconciler: &mut R,
        verifier: &V,
    ) -> Result<StateSyncAnchorOrdinaryActivationV0> {
        if !reconciler.reconcile_state_sync_anchor_ordinary_v0(&self.challenge)
            || !Arc::ptr_eq(&self.core.persistence_affinity.0, &self.challenge.affinity)
            || self.core.safety != *self.challenge.safety_state
        {
            return Err(CoreError::StateSyncAnchorSuccessorRecoveryRejected(
                "the trusted host rejected the promoted application successor closure",
            ));
        }
        self.core.restore_state_sync_anchor_successor_tree_v0(
            StateSyncAnchorSuccessorPhaseV0::H3Valid,
            self.challenge.child.as_ref(),
            self.challenge.grandchild.as_ref(),
        )?;
        let effects = if self.core.safety.revision() == 5 {
            self.core.handle_replay_complete(verifier)?
        } else {
            Vec::new()
        };
        self.core.validate_runtime(verifier, false)?;
        Ok(StateSyncAnchorOrdinaryActivationV0 {
            core: self.core,
            effects,
        })
    }
}

/// Generic Core released only after a live promotion ACK or an authenticated
/// promoted restart reconciliation.
#[derive(Debug)]
#[must_use = "the activated Core and its exact startup effects must remain together"]
pub struct StateSyncAnchorOrdinaryActivationV0 {
    core: Core,
    effects: Vec<Effect>,
}

impl StateSyncAnchorOrdinaryActivationV0 {
    pub const fn core(&self) -> &Core {
        &self.core
    }

    pub fn effects(&self) -> &[Effect] {
        &self.effects
    }

    pub fn into_parts_v0(self) -> (Core, Vec<Effect>) {
        (self.core, self.effects)
    }
}

/// Exact inert challenge for one ordinary, non-anchored NativeValid head.
///
/// The current SafetyState must contain no validation obligation and exactly
/// one terminally Valid completion first recorded at the current revision.
/// The challenge carries no application job state: a trusted host must still
/// authenticate that the matching App row is the stable Delivered or Acked
/// cut before it can mint an attestation.
#[derive(Debug)]
#[must_use = "the current NativeValid completion must be reconciled before its action can be reminted"]
pub struct NativeValidCompletionRecoveryChallengeV0 {
    safety_state: Box<SafetyState>,
    valid_result_checksum: [u8; 32],
    affinity: Arc<()>,
}

/// Authenticated SafetyStore comparison facts for the exact stable
/// authenticated-genesis h1 NativeValid head.
///
/// This cloneable value is deliberately not a store capability.  Only the
/// SafetyStore's non-cloneable confirmed-head wrapper can authenticate these
/// facts to a live journal owner; Core additionally requires a trusted
/// reconciler before it will release terminal recovery facts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedGenesisApplicationH1StableNativeValidSafetyHeadFactsV0 {
    journal_id: [u8; 32],
    verifier_profile_ref: [u8; 32],
    core_config_ref: [u8; 32],
    tag5_state_record_checksum: [u8; 32],
    tag5_transition_context_checksum: [u8; 32],
    tag5_chain_checksum: [u8; 32],
    revision_one_state_record_checksum: [u8; 32],
    revision_one_transition_context_checksum: [u8; 32],
    revision_one_chain_checksum: [u8; 32],
    revision_two_state_record_checksum: [u8; 32],
    revision_two_transition_context_checksum: [u8; 32],
    revision_two_chain_checksum: [u8; 32],
    tag5_head_checksum: [u8; 32],
    revision_two_head_checksum: [u8; 32],
    completion_carrier_checksum: [u8; 32],
    application_delivery_facts: ApplicationNativeValidDeliveryFactsV0,
}

impl AuthenticatedGenesisApplicationH1StableNativeValidSafetyHeadFactsV0 {
    /// Builds inert comparison material from a fully authenticated store
    /// lineage.  Callers must not treat this public constructor as proof of
    /// provenance; the live-owner capability remains in SafetyStore.
    #[allow(clippy::too_many_arguments)]
    pub fn from_authenticated_store_comparison_v0(
        journal_id: [u8; 32],
        verifier_profile_ref: [u8; 32],
        core_config_ref: [u8; 32],
        tag5_state_record_checksum: [u8; 32],
        tag5_transition_context_checksum: [u8; 32],
        tag5_chain_checksum: [u8; 32],
        revision_one_state_record_checksum: [u8; 32],
        revision_one_transition_context_checksum: [u8; 32],
        revision_one_chain_checksum: [u8; 32],
        revision_two_state_record_checksum: [u8; 32],
        revision_two_transition_context_checksum: [u8; 32],
        revision_two_chain_checksum: [u8; 32],
        tag5_head_checksum: [u8; 32],
        revision_two_head_checksum: [u8; 32],
        completion_carrier_checksum: [u8; 32],
        application_delivery_facts: ApplicationNativeValidDeliveryFactsV0,
    ) -> Result<Self> {
        if [
            journal_id,
            verifier_profile_ref,
            core_config_ref,
            tag5_state_record_checksum,
            tag5_transition_context_checksum,
            tag5_chain_checksum,
            revision_one_state_record_checksum,
            revision_one_transition_context_checksum,
            revision_one_chain_checksum,
            revision_two_state_record_checksum,
            revision_two_transition_context_checksum,
            revision_two_chain_checksum,
            tag5_head_checksum,
            revision_two_head_checksum,
            completion_carrier_checksum,
        ]
        .contains(&[0; 32])
        {
            return Err(CoreError::AuthenticatedGenesisApplicationH1OfflineRejected(
                "stable h1 Safety lineage contains a zero identity",
            ));
        }
        Ok(Self {
            journal_id,
            verifier_profile_ref,
            core_config_ref,
            tag5_state_record_checksum,
            tag5_transition_context_checksum,
            tag5_chain_checksum,
            revision_one_state_record_checksum,
            revision_one_transition_context_checksum,
            revision_one_chain_checksum,
            revision_two_state_record_checksum,
            revision_two_transition_context_checksum,
            revision_two_chain_checksum,
            tag5_head_checksum,
            revision_two_head_checksum,
            completion_carrier_checksum,
            application_delivery_facts,
        })
    }

    pub const fn journal_id_v0(&self) -> [u8; 32] {
        self.journal_id
    }
    pub const fn verifier_profile_ref_v0(&self) -> [u8; 32] {
        self.verifier_profile_ref
    }
    pub const fn core_config_ref_v0(&self) -> [u8; 32] {
        self.core_config_ref
    }
    pub const fn tag5_state_record_checksum_v0(&self) -> [u8; 32] {
        self.tag5_state_record_checksum
    }
    pub const fn tag5_transition_context_checksum_v0(&self) -> [u8; 32] {
        self.tag5_transition_context_checksum
    }
    pub const fn tag5_chain_checksum_v0(&self) -> [u8; 32] {
        self.tag5_chain_checksum
    }
    pub const fn revision_one_state_record_checksum_v0(&self) -> [u8; 32] {
        self.revision_one_state_record_checksum
    }
    pub const fn revision_one_transition_context_checksum_v0(&self) -> [u8; 32] {
        self.revision_one_transition_context_checksum
    }
    pub const fn revision_one_chain_checksum_v0(&self) -> [u8; 32] {
        self.revision_one_chain_checksum
    }
    pub const fn revision_two_state_record_checksum_v0(&self) -> [u8; 32] {
        self.revision_two_state_record_checksum
    }
    pub const fn revision_two_transition_context_checksum_v0(&self) -> [u8; 32] {
        self.revision_two_transition_context_checksum
    }
    pub const fn revision_two_chain_checksum_v0(&self) -> [u8; 32] {
        self.revision_two_chain_checksum
    }
    pub const fn tag5_head_checksum_v0(&self) -> [u8; 32] {
        self.tag5_head_checksum
    }
    pub const fn revision_two_head_checksum_v0(&self) -> [u8; 32] {
        self.revision_two_head_checksum
    }
    pub const fn completion_carrier_checksum_v0(&self) -> [u8; 32] {
        self.completion_carrier_checksum
    }
    pub const fn application_delivery_facts_v0(&self) -> ApplicationNativeValidDeliveryFactsV0 {
        self.application_delivery_facts
    }
}

/// Exact read-only recovery challenge for a persisted authenticated-genesis
/// empty h1 completion.  It owns the complete rev0 -> rev1 -> rev2 Core
/// lineage but exposes no Core, input, effect, seal, persistence, or runtime
/// authority.
#[derive(Debug)]
#[must_use = "the exact stable h1 challenge must be joined to SafetyStore and AppStore"]
pub struct AuthenticatedGenesisApplicationH1StableNativeValidRecoveryChallengeV0 {
    revision_zero: Box<SafetyState>,
    revision_one: Box<SafetyState>,
    revision_two: Box<SafetyState>,
    proposal: Box<SignedProposalV0>,
    safety_state_record_config_ref: [u8; 32],
    authenticated_parent_binding_ref: [u8; 32],
    completion_carrier_checksum: [u8; 32],
    affinity: Arc<()>,
}

impl AuthenticatedGenesisApplicationH1StableNativeValidRecoveryChallengeV0 {
    pub fn revision_zero_state_v0(&self) -> &SafetyState {
        self.revision_zero.as_ref()
    }
    pub fn revision_one_state_v0(&self) -> &SafetyState {
        self.revision_one.as_ref()
    }
    pub fn revision_two_state_v0(&self) -> &SafetyState {
        self.revision_two.as_ref()
    }
    pub fn proposal_v0(&self) -> &SignedProposalV0 {
        self.proposal.as_ref()
    }
    pub fn completion_v0(&self) -> &DurablePayloadValidationCompletionV0 {
        &self.revision_two.payload_validation_completions()[0]
    }
    pub fn terminal_fact_v0(&self) -> PayloadTerminalFact {
        self.revision_two.payload_terminal_facts()[0]
    }
    pub fn overlay_v0(&self) -> crate::BlockIdOverlayRefV0 {
        self.completion_v0()
            .result()
            .artifact_ref()
            .expect("private constructor requires Valid")
            .overlay()
    }
    pub const fn safety_state_record_config_ref_v0(&self) -> [u8; 32] {
        self.safety_state_record_config_ref
    }
    pub const fn authenticated_parent_binding_ref_v0(&self) -> [u8; 32] {
        self.authenticated_parent_binding_ref
    }
    pub const fn completion_carrier_checksum_v0(&self) -> [u8; 32] {
        self.completion_carrier_checksum
    }
    pub fn validation_id_v0(&self) -> ValidationId {
        self.completion_v0().id()
    }
    pub fn valid_result_checksum_v0(&self) -> [u8; 32] {
        native_valid_result_checksum_v0(self.completion_v0().result())
            .expect("private constructor requires canonical Valid")
    }
    pub fn same_recovery_instance_v0(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.affinity, &other.affinity)
    }

    pub fn attest_authenticated_reconciliation_v0<
        R: AuthenticatedGenesisApplicationH1StableNativeValidRecoveryReconcilerV0,
    >(
        &self,
        safety_head_facts: AuthenticatedGenesisApplicationH1StableNativeValidSafetyHeadFactsV0,
        reconciler: &mut R,
    ) -> Result<AuthenticatedGenesisApplicationH1StableNativeValidRecoveryAttestationV0> {
        let delivery = safety_head_facts.application_delivery_facts_v0();
        if safety_head_facts.core_config_ref_v0() != self.safety_state_record_config_ref
            || safety_head_facts.completion_carrier_checksum_v0()
                != self.completion_carrier_checksum
            || delivery.route() != PayloadValidationRouteV0::Synced
            || delivery.validation_id() != self.validation_id_v0()
            || delivery.valid_result_checksum() != self.valid_result_checksum_v0()
            || delivery.post_ack_action() != NativeValidPostAckActionV0::None
            || delivery.completion_revision() != 2
            || !reconciler.reconcile_authenticated_genesis_application_h1_stable_native_valid_v0(
                self,
                &safety_head_facts,
            )
        {
            return Err(CoreError::NativeValidCompletionRecoveryRejected(
                "trusted join rejected the authenticated-genesis h1 stable completion",
            ));
        }
        Ok(
            AuthenticatedGenesisApplicationH1StableNativeValidRecoveryAttestationV0 {
                safety_head_facts,
                affinity: Arc::clone(&self.affinity),
            },
        )
    }
}

pub trait AuthenticatedGenesisApplicationH1StableNativeValidRecoveryReconcilerV0 {
    fn reconcile_authenticated_genesis_application_h1_stable_native_valid_v0(
        &mut self,
        challenge: &AuthenticatedGenesisApplicationH1StableNativeValidRecoveryChallengeV0,
        safety_head_facts: &AuthenticatedGenesisApplicationH1StableNativeValidSafetyHeadFactsV0,
    ) -> bool;
}

#[derive(Debug)]
#[must_use = "the stable h1 attestation must be consumed by its exact session"]
pub struct AuthenticatedGenesisApplicationH1StableNativeValidRecoveryAttestationV0 {
    safety_head_facts: AuthenticatedGenesisApplicationH1StableNativeValidSafetyHeadFactsV0,
    affinity: Arc<()>,
}

/// Inert stable-completion recovery owner. It deliberately has no raw Core or
/// generic step surface.
///
/// ```compile_fail
/// use trnm_consensus_core::
///     AuthenticatedGenesisApplicationH1StableNativeValidRecoverySessionV0;
/// fn requires_clone<T: Clone>() {}
/// requires_clone::<AuthenticatedGenesisApplicationH1StableNativeValidRecoverySessionV0>();
/// ```
///
/// ```compile_fail
/// use trnm_consensus_core::{
///     AuthenticatedGenesisApplicationH1StableNativeValidRecoverySessionV0, Input,
/// };
/// fn generic_step_is_absent(
///     session: &mut AuthenticatedGenesisApplicationH1StableNativeValidRecoverySessionV0,
///     input: Input,
/// ) {
///     let _ = session.step(input);
/// }
/// ```
#[derive(Debug)]
#[must_use = "dropping the session keeps stable h1 recovery fail-closed"]
pub struct AuthenticatedGenesisApplicationH1StableNativeValidRecoverySessionV0 {
    challenge: AuthenticatedGenesisApplicationH1StableNativeValidRecoveryChallengeV0,
}

impl AuthenticatedGenesisApplicationH1StableNativeValidRecoverySessionV0 {
    pub const fn challenge_v0(
        &self,
    ) -> &AuthenticatedGenesisApplicationH1StableNativeValidRecoveryChallengeV0 {
        &self.challenge
    }

    pub fn reconcile_and_complete_v0(
        self,
        attestation: AuthenticatedGenesisApplicationH1StableNativeValidRecoveryAttestationV0,
    ) -> Result<AuthenticatedGenesisApplicationH1StableNativeValidRecoveryReplayV0> {
        if !Arc::ptr_eq(&self.challenge.affinity, &attestation.affinity) {
            return Err(CoreError::NativeValidCompletionRecoveryRejected(
                "stable h1 attestation belongs to another recovery session",
            ));
        }
        Ok(
            AuthenticatedGenesisApplicationH1StableNativeValidRecoveryReplayV0 {
                challenge: self.challenge,
                safety_head_facts: Some(attestation.safety_head_facts),
            },
        )
    }
}

#[derive(Debug)]
#[must_use = "the stable h1 recovered facts may be released only once"]
pub struct AuthenticatedGenesisApplicationH1StableNativeValidRecoveryReplayV0 {
    challenge: AuthenticatedGenesisApplicationH1StableNativeValidRecoveryChallengeV0,
    safety_head_facts: Option<AuthenticatedGenesisApplicationH1StableNativeValidSafetyHeadFactsV0>,
}

impl AuthenticatedGenesisApplicationH1StableNativeValidRecoveryReplayV0 {
    pub fn release_inert_completed_facts_v0(
        &mut self,
    ) -> Result<AuthenticatedGenesisApplicationH1StableNativeValidRecoveredFactsV0> {
        let safety_head_facts = self.safety_head_facts.take().ok_or(
            CoreError::NativeValidCompletionRecoveryRejected(
                "stable h1 completion facts were already released",
            ),
        )?;
        Ok(
            AuthenticatedGenesisApplicationH1StableNativeValidRecoveredFactsV0 {
                proposal: self.challenge.proposal.clone(),
                completion: self.challenge.completion_v0().clone(),
                terminal_fact: self.challenge.terminal_fact_v0(),
                authenticated_parent_binding_ref: self.challenge.authenticated_parent_binding_ref,
                completion_carrier_checksum: self.challenge.completion_carrier_checksum,
                safety_head_facts,
            },
        )
    }
}

#[derive(Debug)]
#[must_use = "the inert stable h1 facts should remain with the dedicated host"]
pub struct AuthenticatedGenesisApplicationH1StableNativeValidRecoveredFactsV0 {
    proposal: Box<SignedProposalV0>,
    completion: DurablePayloadValidationCompletionV0,
    terminal_fact: PayloadTerminalFact,
    authenticated_parent_binding_ref: [u8; 32],
    completion_carrier_checksum: [u8; 32],
    safety_head_facts: AuthenticatedGenesisApplicationH1StableNativeValidSafetyHeadFactsV0,
}

impl AuthenticatedGenesisApplicationH1StableNativeValidRecoveredFactsV0 {
    pub fn proposal_v0(&self) -> &SignedProposalV0 {
        self.proposal.as_ref()
    }
    pub const fn completion_v0(&self) -> &DurablePayloadValidationCompletionV0 {
        &self.completion
    }
    pub const fn terminal_fact_v0(&self) -> PayloadTerminalFact {
        self.terminal_fact
    }
    pub const fn authenticated_parent_binding_ref_v0(&self) -> [u8; 32] {
        self.authenticated_parent_binding_ref
    }
    pub const fn completion_carrier_checksum_v0(&self) -> [u8; 32] {
        self.completion_carrier_checksum
    }
    pub const fn safety_head_facts_v0(
        &self,
    ) -> &AuthenticatedGenesisApplicationH1StableNativeValidSafetyHeadFactsV0 {
        &self.safety_head_facts
    }
}

impl NativeValidCompletionRecoveryChallengeV0 {
    pub fn safety_state(&self) -> &SafetyState {
        self.safety_state.as_ref()
    }

    pub fn completion(&self) -> &DurablePayloadValidationCompletionV0 {
        exact_current_native_valid_completion_v0(self.safety_state.as_ref())
            .expect("the private constructor admits one exact current Valid completion")
    }

    pub const fn safety_head_revision_v0(&self) -> u64 {
        self.safety_state.revision()
    }

    pub fn route_v0(&self) -> PayloadValidationRouteV0 {
        self.completion().route()
    }

    pub fn validation_id_v0(&self) -> ValidationId {
        self.completion().id()
    }

    pub const fn valid_result_checksum_v0(&self) -> [u8; 32] {
        self.valid_result_checksum
    }

    pub fn same_recovery_instance_v0(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.affinity, &other.affinity)
    }

    /// Mints one session-affined attestation after the trusted host joins the
    /// exact authenticated SafetyStore record to a stable App Delivered/Acked
    /// row and its complete NativeValid transition.
    ///
    /// `safety_state_record_checksum` is opaque provenance from SafetyStore.
    /// Core refuses zero and carries it through the linear result, while the
    /// reconciler is responsible for authenticating it and every App-owned
    /// transition field. No transition preimage or application authority is
    /// created by this method.
    pub fn attest_authenticated_reconciliation_v0<R: NativeValidCompletionRecoveryReconcilerV0>(
        &self,
        authenticated_safety_state: &SafetyState,
        safety_state_record_checksum: [u8; 32],
        post_ack_action: NativeValidPostAckActionV0,
        reconciler: &mut R,
    ) -> Result<NativeValidCompletionRecoveryAttestationV0> {
        if authenticated_safety_state != self.safety_state.as_ref() {
            return Err(CoreError::NativeValidCompletionRecoveryRejected(
                "authenticated SafetyState differs from the recovery challenge",
            ));
        }
        if safety_state_record_checksum == [0; 32] {
            return Err(CoreError::NativeValidCompletionRecoveryRejected(
                "authenticated SafetyStore record checksum is zero",
            ));
        }
        exact_current_native_valid_completion_v0(authenticated_safety_state)?;
        if !native_valid_completion_recovery_action_matches_state_v0(
            post_ack_action,
            authenticated_safety_state,
        ) {
            return Err(CoreError::NativeValidCompletionRecoveryRejected(
                "the recorded post-ack action is incompatible with the durable outbox state",
            ));
        }
        if !reconciler.reconcile_native_valid_completion_v0(
            self,
            safety_state_record_checksum,
            post_ack_action,
        ) {
            return Err(CoreError::NativeValidCompletionRecoveryRejected(
                "the trusted host rejected the exact SafetyStore/ApplicationStore tuple",
            ));
        }
        Ok(NativeValidCompletionRecoveryAttestationV0 {
            safety_state_record_checksum,
            post_ack_action,
            affinity: Arc::clone(&self.affinity),
        })
    }
}

/// Trusted fixed-snapshot join for one stable NativeValid completion.
///
/// Implementations must authenticate the complete current NativeValid
/// SafetyStore transition plus exactly one matching App job. V0 admits only
/// Delivered (C+D, completed recovery-only to Acked before remint) or Acked
/// (C+K). CallbackPending, Applied, missing, duplicate, and foreign rows must
/// return false.
pub trait NativeValidCompletionRecoveryReconcilerV0 {
    fn reconcile_native_valid_completion_v0(
        &mut self,
        challenge: &NativeValidCompletionRecoveryChallengeV0,
        safety_state_record_checksum: [u8; 32],
        post_ack_action: NativeValidPostAckActionV0,
    ) -> bool;
}

/// Non-cloneable proof of one exact stable cross-store NativeValid join.
///
/// ```compile_fail
/// use trnm_consensus_core::NativeValidCompletionRecoveryAttestationV0;
/// fn requires_clone<T: Clone>() {}
/// requires_clone::<NativeValidCompletionRecoveryAttestationV0>();
/// ```
#[derive(Debug)]
#[must_use = "the NativeValid completion attestation must be consumed by its recovery session"]
pub struct NativeValidCompletionRecoveryAttestationV0 {
    safety_state_record_checksum: [u8; 32],
    post_ack_action: NativeValidPostAckActionV0,
    affinity: Arc<()>,
}

impl NativeValidCompletionRecoveryAttestationV0 {
    pub const fn safety_state_record_checksum_v0(&self) -> [u8; 32] {
        self.safety_state_record_checksum
    }

    pub const fn post_ack_action_v0(&self) -> NativeValidPostAckActionV0 {
        self.post_ack_action
    }
}

/// Inert owner of one ordinary NativeValid completion recovery attempt.
///
/// Activation consumes the unique attestation and returns only a narrow
/// replay owner. It never returns raw [`Core`] or a generic input surface.
#[derive(Debug)]
#[must_use = "dropping the session keeps NativeValid completion recovery fail-closed"]
pub struct NativeValidCompletionRecoverySessionV0 {
    core: Core,
    challenge: NativeValidCompletionRecoveryChallengeV0,
}

impl NativeValidCompletionRecoverySessionV0 {
    pub const fn challenge(&self) -> &NativeValidCompletionRecoveryChallengeV0 {
        &self.challenge
    }

    pub fn reconcile_and_activate_v0(
        self,
        attestation: NativeValidCompletionRecoveryAttestationV0,
    ) -> Result<NativeValidCompletionRecoveryReplayV0> {
        if !Arc::ptr_eq(&self.challenge.affinity, &attestation.affinity)
            || !Arc::ptr_eq(&self.core.persistence_affinity.0, &attestation.affinity)
            || self.core.safety != *self.challenge.safety_state
        {
            return Err(CoreError::NativeValidCompletionRecoveryRejected(
                "recovery attestation belongs to a different session or SafetyState",
            ));
        }
        let completion = exact_current_native_valid_completion_v0(&self.core.safety)?;
        let route = completion.route();
        let validation_id = completion.id();
        let valid_result_checksum = native_valid_result_checksum_v0(completion.result()).ok_or(
            CoreError::NativeValidCompletionRecoveryRejected(
                "the current completion is not canonically Valid",
            ),
        )?;
        if valid_result_checksum != self.challenge.valid_result_checksum
            || !native_valid_completion_recovery_action_matches_state_v0(
                attestation.post_ack_action,
                &self.core.safety,
            )
        {
            return Err(CoreError::NativeValidCompletionRecoveryRejected(
                "recovery attestation differs from the current durable NativeValid head",
            ));
        }
        Ok(NativeValidCompletionRecoveryReplayV0 {
            core: self.core,
            safety_state_record_checksum: attestation.safety_state_record_checksum,
            route,
            validation_id,
            valid_result_checksum,
            post_ack_action: Some(attestation.post_ack_action),
        })
    }
}

/// Narrow fail-closed owner for releasing one already-persisted NativeValid
/// post-ack action as inert comparison data.
///
/// This type exposes no generic Core step and never emits an [`Effect`]. One
/// instance releases at most one token. Reopening the unchanged durable tuple
/// reconstructs the same token, making a pre-side-effect retry deterministic
/// without granting signing, timer, network, or finalization authority.
#[derive(Debug)]
#[must_use = "the recovered NativeValid action must be consumed or remain inert"]
pub struct NativeValidCompletionRecoveryReplayV0 {
    core: Core,
    safety_state_record_checksum: [u8; 32],
    route: PayloadValidationRouteV0,
    validation_id: ValidationId,
    valid_result_checksum: [u8; 32],
    post_ack_action: Option<NativeValidPostAckActionV0>,
}

impl NativeValidCompletionRecoveryReplayV0 {
    pub const fn config(&self) -> &CoreConfig {
        self.core.config()
    }

    pub const fn safety_state(&self) -> &SafetyState {
        self.core.safety_state()
    }

    pub fn safety_state_persistence_binding_v0(&self) -> SafetyStatePersistenceBindingV0 {
        self.core.safety_state_persistence_binding_v0()
    }

    pub fn remint_inert_post_ack_action_v0(
        &mut self,
    ) -> Result<NativeValidCompletionRecoveredActionV0> {
        let post_ack_action =
            self.post_ack_action
                .take()
                .ok_or(CoreError::NativeValidCompletionRecoveryRejected(
                    "the exact recovered post-ack action was already reminted",
                ))?;
        Ok(NativeValidCompletionRecoveredActionV0 {
            safety_head_revision: self.core.safety.revision(),
            safety_state_record_checksum: self.safety_state_record_checksum,
            route: self.route,
            validation_id: self.validation_id,
            valid_result_checksum: self.valid_result_checksum,
            post_ack_action,
        })
    }
}

/// Linear, authority-free projection of the exact recovered action.
///
/// This value deliberately has no method that converts it into Core effects.
#[derive(Debug)]
#[must_use = "the inert recovered action must be compared by the trusted offline host"]
pub struct NativeValidCompletionRecoveredActionV0 {
    safety_head_revision: u64,
    safety_state_record_checksum: [u8; 32],
    route: PayloadValidationRouteV0,
    validation_id: ValidationId,
    valid_result_checksum: [u8; 32],
    post_ack_action: NativeValidPostAckActionV0,
}

impl NativeValidCompletionRecoveredActionV0 {
    pub const fn safety_head_revision_v0(&self) -> u64 {
        self.safety_head_revision
    }

    pub const fn safety_state_record_checksum_v0(&self) -> [u8; 32] {
        self.safety_state_record_checksum
    }

    pub const fn route_v0(&self) -> PayloadValidationRouteV0 {
        self.route
    }

    pub const fn validation_id_v0(&self) -> ValidationId {
        self.validation_id
    }

    pub const fn valid_result_checksum_v0(&self) -> [u8; 32] {
        self.valid_result_checksum
    }

    pub const fn post_ack_action_v0(&self) -> NativeValidPostAckActionV0 {
        self.post_ack_action
    }
}

/// One process-local challenge for recovering a current SafetyStore
/// codec-v0/tag-3 finalization-applied head.
///
/// The challenge owns the exact already-authenticated SafetyState supplied at
/// session creation.  It exposes no constructor and cannot itself activate a
/// Core.  A trusted host must compare its independently authenticated
/// SafetyStore transition and ApplicationStore receipt/head readback through
/// [`Self::attest_authenticated_reconciliation_v0`].
#[derive(Debug)]
#[must_use = "the exact tag-3 recovery challenge must be reconciled before a live Core can exist"]
pub struct NativeFinalizationAppliedRecoveryChallengeV0 {
    safety_state: Box<SafetyState>,
    affinity: Arc<()>,
}

/// Trusted-host authentication boundary for one exact tag-3 recovery tuple.
///
/// An implementation must accept only after independently authenticating the
/// SafetyStore current-head capability and the ApplicationStore exact
/// apply-receipt/head capability represented by the supplied comparison
/// values.  Returning `true` for caller-constructed inert rows violates the
/// host integration contract; those rows carry no Core recovery authority.
pub trait NativeFinalizationAppliedRecoveryReconcilerV0 {
    fn reconcile_native_finalization_applied_v0(
        &mut self,
        challenge: &NativeFinalizationAppliedRecoveryChallengeV0,
        transition: &NativeFinalizationAppliedRecoveryTransitionV0,
        application_readback: &crate::ApplicationFinalizationApplyReadbackV0,
    ) -> bool;
}

impl NativeFinalizationAppliedRecoveryChallengeV0 {
    pub fn safety_head_revision(&self) -> u64 {
        self.safety_state.revision()
    }

    pub fn application_applied(&self) -> FinalizedTip {
        self.safety_state.application_applied()
    }

    /// Compares only the process-local recovery-session identity.
    pub fn same_recovery_instance_v0(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.affinity, &other.affinity)
    }

    /// Reconstructs the inert ApplicationStore comparison projection for this
    /// exact recovery challenge and authenticated tag-3 transition.
    ///
    /// This recovery-only path deliberately does not reuse the live
    /// application-apply authority or a queue-front permit: tag 3 proves that
    /// the front has already been consumed.  The caller must still present an
    /// independently authenticated ApplicationStore capability to the trusted
    /// reconciler before this comparison value can mint an attestation.
    pub fn application_store_readback_for_recovery_v0(
        &self,
        authenticated_safety_state: &SafetyState,
        transition: &NativeFinalizationAppliedRecoveryTransitionV0,
    ) -> Result<crate::ApplicationFinalizationApplyReadbackV0> {
        if authenticated_safety_state != self.safety_state.as_ref() {
            return Err(CoreError::NativeFinalizationAppliedRecoveryRejected(
                "authenticated SafetyState differs from the recovery challenge",
            ));
        }
        let readback = crate::ApplicationFinalizationApplyReadbackV0::from_native_finalization_applied_recovery_transition_v0(
            transition,
        );
        validate_native_finalization_applied_recovery_reconciliation_v0(
            authenticated_safety_state,
            transition,
            &readback,
        )?;
        Ok(readback)
    }

    /// Mints one opaque, session-affined attestation after exact host
    /// reconciliation of all three durable domains.
    ///
    /// `authenticated_safety_state` must be the exact current SafetyStore
    /// head, `transition` must be its authenticated codec-v0/tag-3 context,
    /// and `application_readback` must come from the exact ApplicationStore
    /// apply receipt/head readback.  The transition projection is inert and
    /// the App readback is comparison material; neither can activate recovery
    /// without the private attestation minted here for this session.
    pub fn attest_authenticated_reconciliation_v0<
        R: NativeFinalizationAppliedRecoveryReconcilerV0,
    >(
        &self,
        authenticated_safety_state: &SafetyState,
        transition: &NativeFinalizationAppliedRecoveryTransitionV0,
        application_readback: &crate::ApplicationFinalizationApplyReadbackV0,
        reconciler: &mut R,
    ) -> Result<NativeFinalizationAppliedRecoveryAttestationV0> {
        if authenticated_safety_state != self.safety_state.as_ref() {
            return Err(CoreError::NativeFinalizationAppliedRecoveryRejected(
                "authenticated SafetyState differs from the recovery challenge",
            ));
        }
        validate_native_finalization_applied_recovery_reconciliation_v0(
            authenticated_safety_state,
            transition,
            application_readback,
        )?;
        if !reconciler.reconcile_native_finalization_applied_v0(
            self,
            transition,
            application_readback,
        ) {
            return Err(CoreError::NativeFinalizationAppliedRecoveryRejected(
                "the trusted host rejected the exact SafetyStore/ApplicationStore tuple",
            ));
        }
        Ok(NativeFinalizationAppliedRecoveryAttestationV0 {
            transition: transition.clone(),
            application_readback: application_readback.clone(),
            affinity: Arc::clone(&self.affinity),
        })
    }
}

/// Opaque proof that one exact tag-3 SafetyStore head and ApplicationStore
/// receipt/head were reconciled against a live recovery challenge.
///
/// This capability is non-cloneable, non-serializable, has no public
/// constructor, and is meaningful only to its owning recovery session.
///
/// ```compile_fail
/// use trnm_consensus_core::NativeFinalizationAppliedRecoveryAttestationV0;
///
/// fn assert_clone<T: Clone>() {}
/// fn duplicate_is_forbidden() {
///     assert_clone::<NativeFinalizationAppliedRecoveryAttestationV0>();
/// }
/// ```
#[must_use = "the reconciled tag-3 attestation must be consumed by its recovery session"]
pub struct NativeFinalizationAppliedRecoveryAttestationV0 {
    transition: NativeFinalizationAppliedRecoveryTransitionV0,
    application_readback: crate::ApplicationFinalizationApplyReadbackV0,
    affinity: Arc<()>,
}

impl core::fmt::Debug for NativeFinalizationAppliedRecoveryAttestationV0 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("NativeFinalizationAppliedRecoveryAttestationV0")
            .field(
                "transition_revision",
                &self.transition.transition_revision(),
            )
            .field("post_ack_action", &self.transition.post_ack_action_v0())
            .finish_non_exhaustive()
    }
}

/// Inert two-phase recovery owner for one current tag-3 SafetyStore head.
///
/// Dropping this value leaves recovery closed.  The sole activation path
/// consumes an opaque reconciliation attestation from the exact embedded
/// challenge; failures return both unique owners unchanged for retry.
///
/// ```compile_fail
/// use trnm_consensus_core::NativeFinalizationAppliedRecoverySessionV0;
///
/// fn assert_clone<T: Clone>() {}
/// fn duplicate_is_forbidden() {
///     assert_clone::<NativeFinalizationAppliedRecoverySessionV0>();
/// }
/// ```
#[derive(Debug)]
#[must_use = "dropping the session keeps native finalization-applied recovery fail-closed"]
pub struct NativeFinalizationAppliedRecoverySessionV0 {
    core: Core,
    challenge: NativeFinalizationAppliedRecoveryChallengeV0,
}

impl NativeFinalizationAppliedRecoverySessionV0 {
    pub const fn challenge(&self) -> &NativeFinalizationAppliedRecoveryChallengeV0 {
        &self.challenge
    }

    pub fn reconcile_and_activate_v0(
        mut self,
        attestation: NativeFinalizationAppliedRecoveryAttestationV0,
    ) -> core::result::Result<Core, NativeFinalizationAppliedRecoveryActivationRejectionV0> {
        let result = if !Arc::ptr_eq(&self.challenge.affinity, &attestation.affinity)
            || !Arc::ptr_eq(&self.core.persistence_affinity.0, &attestation.affinity)
            || self.core.safety != *self.challenge.safety_state
        {
            Err(CoreError::NativeFinalizationAppliedRecoveryRejected(
                "recovery attestation belongs to a different session or SafetyState",
            ))
        } else {
            self.core.activate_recovered_native_finalization_applied_v0(
                &attestation.transition,
                &attestation.application_readback,
                Arc::clone(&attestation.affinity),
            )
        };
        match result {
            Ok(()) => Ok(self.core),
            Err(error) => Err(NativeFinalizationAppliedRecoveryActivationRejectionV0 {
                error,
                session: Box::new(self),
                attestation: Box::new(attestation),
            }),
        }
    }
}

/// Owner-preserving tag-3 recovery activation rejection.
#[must_use = "a rejected tag-3 recovery activation retains both unique owners"]
pub struct NativeFinalizationAppliedRecoveryActivationRejectionV0 {
    error: CoreError,
    session: Box<NativeFinalizationAppliedRecoverySessionV0>,
    attestation: Box<NativeFinalizationAppliedRecoveryAttestationV0>,
}

impl core::fmt::Debug for NativeFinalizationAppliedRecoveryActivationRejectionV0 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("NativeFinalizationAppliedRecoveryActivationRejectionV0")
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}

impl NativeFinalizationAppliedRecoveryActivationRejectionV0 {
    pub const fn error(&self) -> &CoreError {
        &self.error
    }

    pub fn into_parts(
        self,
    ) -> (
        CoreError,
        NativeFinalizationAppliedRecoverySessionV0,
        NativeFinalizationAppliedRecoveryAttestationV0,
    ) {
        (self.error, *self.session, *self.attestation)
    }
}

impl PayloadValidationRecoverySessionV0 {
    pub const fn challenge(&self) -> &PayloadValidationRecoveryChallengeV0 {
        &self.challenge
    }

    pub fn reconcile_and_activate_v0<R: PayloadValidationRecoveryReconcilerV0>(
        mut self,
        reconciler: &mut R,
    ) -> Result<Core> {
        if reconciler.reconcile_deterministically_invalid_obligation_v0(&self.challenge)
            != PayloadValidationRecoveryDecisionV0::AcceptDeterministicallyInvalid
        {
            return Err(CoreError::PayloadValidationRecoveryRejected);
        }
        if !Arc::ptr_eq(&self.core.persistence_affinity.0, &self.challenge.affinity)
            || self.core.safety.revision() != self.challenge.safety_head_revision
        {
            return Err(CoreError::PayloadValidationRecoveryRejected);
        }
        self.core
            .activate_recovered_payload_validation_v0(&self.challenge.obligation)?;
        Ok(self.core)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RecoveredPayloadValidationFenceV0 {
    route: PayloadValidationRouteV0,
    id: ValidationId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RecoveredNativeFinalizationAppliedFenceV0 {
    transition: NativeFinalizationAppliedRecoveryTransitionV0,
    application_readback: crate::ApplicationFinalizationApplyReadbackV0,
    affinity: Arc<()>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Core {
    config: CoreConfig,
    safety: SafetyState,
    blocks: BlockTree,
    pending_validations: BTreeMap<ValidationId, PendingPayloadValidationV0>,
    pending_sync_validations: BTreeMap<ValidationId, PendingPayloadValidationV0>,
    pending_persistence: Option<PendingPersistence>,
    awaiting_signature: bool,
    // A terminally Valid proposal may complete while an application
    // finalization outbox is active. Retain only that exact, already-
    // authenticated proposal so the finalization acknowledgement can
    // autonomously re-run the ordinary vote checks. This is deliberately
    // volatile: recovery cannot reconstruct the canonical body, authenticated
    // parent context, or frozen runtime inputs from a durable terminal fact.
    finalization_blocked_vote: Option<SignedProposalV0>,
    observed_proposals: BTreeMap<ObservationKey, ObservedProposal>,
    observed_votes: BTreeMap<ObservationKey, Vote>,
    observed_timeouts: BTreeMap<ObservationKey, TimeoutVote>,
    observed_qcs: BTreeMap<View, QuorumCertificate>,
    next_validation_generation: u64,
    replay_required: bool,
    recovered_validation_pending: Option<RecoveredPayloadValidationFenceV0>,
    recovered_native_finalization_applied: Option<RecoveredNativeFinalizationAppliedFenceV0>,
    persistence_affinity: CorePersistenceAffinityV0,
    preauthentication_affinity: CorePreauthenticationAffinityV0,
    application_seal_affinity: CoreApplicationSealAffinityV0,
    application_finalization_affinity: CoreApplicationFinalizationAffinityV0,
}

impl Core {
    /// Returns an opaque process-local binding for this exact Core instance.
    ///
    /// Publicly cloning the Core creates a new binding. Internal transactional
    /// snapshots preserve it, so an effect from a successful step remains
    /// accepted while an effect from a throwaway clone does not.
    pub fn safety_state_persistence_binding_v0(&self) -> SafetyStatePersistenceBindingV0 {
        SafetyStatePersistenceBindingV0::new(
            Arc::clone(&self.persistence_affinity.0),
            CorePersistenceSealV0::new(),
        )
    }

    /// Issues this live Core instance's single application-store seal
    /// authority.
    ///
    /// This is a trusted node-host initialization boundary, not a consensus
    /// input. The returned non-cloneable capability must move immediately into
    /// exactly one private ApplicationStore. Public Core clones have
    /// independent affinities; transactional clones preserve this affinity.
    pub fn issue_application_seal_authority_v0(
        &self,
    ) -> Result<CoreIssuedApplicationSealAuthorityV0> {
        if self
            .application_seal_affinity
            .authority_issued
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(CoreError::ApplicationSealAuthorityAlreadyIssued);
        }
        Ok(CoreIssuedApplicationSealAuthorityV0::new(
            Arc::clone(&self.application_seal_affinity.affinity),
            Arc::clone(&self.persistence_affinity.0),
            self.config.validator_set().chain_id(),
        ))
    }

    /// Issues this live Core instance's single ApplicationStore finalization
    /// apply authority.
    ///
    /// The trusted node host installs the non-cloneable value directly into
    /// one private ApplicationStore.  A recovered Core owns a fresh process
    /// affinity and may therefore install one fresh authority; no durable
    /// carrier or caller-selected fields can reconstruct it.
    pub fn issue_application_finalization_apply_authority_v0(
        &self,
    ) -> Result<CoreIssuedApplicationFinalizationApplyAuthorityV0> {
        if self
            .application_finalization_affinity
            .authority_issued
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(CoreError::ApplicationFinalizationApplyAuthorityAlreadyIssued);
        }
        Ok(CoreIssuedApplicationFinalizationApplyAuthorityV0::new(
            Arc::clone(
                &self
                    .application_finalization_affinity
                    .application_apply_affinity,
            ),
            Arc::clone(&self.persistence_affinity.0),
            self.config.validator_set().chain_id(),
        ))
    }

    /// Issues the sole process-local permit for the authenticated exact
    /// durable finalization queue front.
    ///
    /// This works identically for a live or recovered Core: recovery first
    /// authenticates and validates the persisted queue, then `Core::empty`
    /// creates a fresh front affinity and issuance gate.  A lost permit can
    /// only be reminted by recovering a fresh Core from the still-pending
    /// authenticated front; inert comparison data is never accepted.
    pub fn issue_application_finalization_permit_v0(
        &self,
    ) -> Result<CoreIssuedApplicationFinalizationPermitV0> {
        self.reject_finalization_receipt_while_busy_v0()?;
        let finalization = self
            .safety
            .pending_finalization()
            .ok_or(CoreError::UnexpectedFinalizationAck)?;
        if self
            .application_finalization_affinity
            .front_permit_issued
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(CoreError::ApplicationFinalizationPermitAlreadyIssued);
        }
        Ok(CoreIssuedApplicationFinalizationPermitV0::new(
            finalization.clone(),
            Arc::clone(&self.application_finalization_affinity.front_affinity),
            Arc::clone(
                &self
                    .application_finalization_affinity
                    .application_apply_affinity,
            ),
        ))
    }

    pub(crate) fn transactional_clone_v0(&self) -> Self {
        let mut cloned = self.clone();
        cloned.persistence_affinity = self.persistence_affinity.preserve();
        cloned.preauthentication_affinity = self.preauthentication_affinity.preserve();
        cloned.application_seal_affinity = self.application_seal_affinity.preserve();
        cloned.application_finalization_affinity =
            self.application_finalization_affinity.preserve();
        if let Some(fence) = &mut cloned.recovered_native_finalization_applied {
            fence.affinity = Arc::clone(&self.persistence_affinity.0);
        }
        cloned.pending_validations = self
            .pending_validations
            .iter()
            .map(|(id, pending)| (*id, pending.preserve()))
            .collect();
        cloned.pending_sync_validations = self
            .pending_sync_validations
            .iter()
            .map(|(id, pending)| (*id, pending.preserve()))
            .collect();
        cloned
    }

    /// Starts a core from the exact context-authorized genesis anchor.
    pub fn new<V: SignatureVerifier>(
        config: CoreConfig,
        genesis_qc: GenesisQcV0,
        verifier: &V,
    ) -> Result<Self> {
        config.validate()?;
        if config
            .authenticated_genesis_application_parent_v0()
            .is_some()
        {
            return Err(CoreError::AuthenticatedGenesisApplicationActivationUnavailable);
        }
        if config.validator_set().epoch().get() != 0 {
            return Err(CoreError::InvalidConfig(
                "a new core must start in genesis epoch zero",
            ));
        }
        genesis_qc.matches_trusted_set(config.validator_set())?;
        let safety = SafetyState::from_genesis(
            config.validator_set(),
            genesis_qc,
            config.trusted_genesis_timestamp_ms(),
            config
                .authenticated_genesis_application_parent_v0()
                .copied(),
        )?;
        let value = Self::empty(config, safety, false);
        value.validate_runtime(verifier, true)?;
        Ok(value)
    }

    /// Prepares the exact inert revision-zero facts for an operator-pinned
    /// authenticated genesis application parent.
    ///
    /// This is a commissioning boundary, not a Core activation boundary. The
    /// returned value contains no live Core and cannot issue effects. Generic
    /// [`Self::new`], [`Self::recover`], and every generic recovery session
    /// remain hard-fenced for configurations carrying this parent.
    pub fn prepare_authenticated_genesis_application_bootstrap_v0<V: SignatureVerifier>(
        config: CoreConfig,
        genesis_qc: GenesisQcV0,
        verifier_profile_ref: [u8; 32],
        record_limits: SafetyStateRecordLimitsV0,
        verifier: &V,
    ) -> Result<PreparedAuthenticatedGenesisApplicationBootstrapV0> {
        config.validate()?;
        let authenticated_parent = config
            .authenticated_genesis_application_parent_v0()
            .copied()
            .ok_or(CoreError::InvalidConfig(
                "authenticated genesis application bootstrap requires its exact application parent",
            ))?;
        if config.validator_set().epoch() != Epoch::new(0) {
            return Err(CoreError::InvalidConfig(
                "authenticated genesis application bootstrap supports genesis epoch zero only",
            ));
        }
        if verifier_profile_ref == [0; 32] {
            return Err(CoreError::InvalidConfig(
                "authenticated genesis application bootstrap requires a nonzero verifier profile reference",
            ));
        }
        genesis_qc.matches_trusted_set(config.validator_set())?;
        let safety_state = SafetyState::from_genesis(
            config.validator_set(),
            genesis_qc.clone(),
            config.trusted_genesis_timestamp_ms(),
            Some(authenticated_parent),
        )?;
        safety_state
            .validate_exact_authenticated_genesis_application_bootstrap_v0(&config, &genesis_qc)?;
        Self::validate_persisted_state_v0(&config, &safety_state, verifier)?;

        let record_context = SafetyStateRecordContextV0::new(
            &config,
            verifier_profile_ref,
            record_limits,
        )
        .map_err(|_| {
            CoreError::InvalidConfig(
                "authenticated genesis application bootstrap safety-state record context is invalid",
            )
        })?;
        let safety_state_record_config_ref =
            safety_state_record_config_ref_v0(&record_context).map_err(|_| {
                CoreError::InvalidConfig(
                    "authenticated genesis application bootstrap safety-state config reference is unavailable",
                )
            })?;

        Ok(PreparedAuthenticatedGenesisApplicationBootstrapV0 {
            core_config: config,
            safety_state,
            authenticated_genesis_application_parent: authenticated_parent,
            safety_state_record_config_ref,
        })
    }

    /// Strict additive commissioning entry point which binds the exact
    /// configured application parent to the trusted GenesisQC before creating
    /// revision-zero facts.
    ///
    /// The raw [`GenesisQcV0`] CEV0 object and the legacy preparation method
    /// remain unchanged for fixture and wire compatibility.  Callers which
    /// need the P1 application-root/provenance check must supply the explicit
    /// [`GenesisQcApplicationBindingV0`] envelope to this method.
    pub fn prepare_authenticated_genesis_application_bootstrap_with_genesis_application_commitment_v0<
        V: SignatureVerifier,
    >(
        config: CoreConfig,
        genesis_binding: GenesisQcApplicationBindingV0,
        verifier_profile_ref: [u8; 32],
        record_limits: SafetyStateRecordLimitsV0,
        verifier: &V,
    ) -> Result<PreparedAuthenticatedGenesisApplicationBootstrapV0> {
        config.validate()?;
        let configured_parent = config
            .authenticated_genesis_application_parent_v0()
            .copied()
            .ok_or(CoreError::InvalidConfig(
                "authenticated genesis application bootstrap requires its exact application parent",
            ))?;
        genesis_binding.validate_against_trusted_set(config.validator_set())?;
        let expected_commitment = configured_parent.genesis_application_commitment_v0()?;
        if genesis_binding.application_commitment_v0() != expected_commitment {
            return Err(CoreError::AuthenticatedGenesisApplicationH1OfflineRejected(
                "GenesisQC application commitment differs from the configured application parent",
            ));
        }
        let (genesis_qc, _) = genesis_binding.into_parts();
        Self::prepare_authenticated_genesis_application_bootstrap_v0(
            config,
            genesis_qc,
            verifier_profile_ref,
            record_limits,
            verifier,
        )
    }

    /// Prepares the bounded offline h1 owner and its sole seal authority for
    /// one application-owned registration.
    ///
    /// The prepared value is consumed. Neither the owner nor its application
    /// authority is returned directly; the linear activation bundle can only
    /// be consumed by an application registrar. All generic Core construction/
    /// recovery surfaces remain hard-fenced for the same configuration.
    pub fn begin_authenticated_genesis_application_h1_offline_validation_v0<
        V: SignatureVerifier,
    >(
        config: CoreConfig,
        prepared: PreparedAuthenticatedGenesisApplicationBootstrapV0,
        verifier: &V,
    ) -> Result<AuthenticatedGenesisApplicationH1OfflineActivationBundleV0> {
        config.validate()?;
        let configured_parent = config
            .authenticated_genesis_application_parent_v0()
            .copied()
            .ok_or(CoreError::AuthenticatedGenesisApplicationH1OfflineRejected(
                "offline h1 validation requires an authenticated genesis application parent",
            ))?;
        let PreparedAuthenticatedGenesisApplicationBootstrapV0 {
            core_config: prepared_core_config,
            safety_state,
            authenticated_genesis_application_parent,
            safety_state_record_config_ref,
        } = prepared;
        if config != prepared_core_config
            || configured_parent != authenticated_genesis_application_parent
        {
            return Err(CoreError::AuthenticatedGenesisApplicationH1OfflineRejected(
                "prepared and configured authenticated application contexts differ",
            ));
        }
        let Some(ContextAuthorizedQcV0::Genesis(genesis_qc)) =
            safety_state.high_qc().as_synthetic()
        else {
            return Err(CoreError::AuthenticatedGenesisApplicationH1OfflineRejected(
                "prepared revision-zero state lacks its exact GenesisQC",
            ));
        };
        safety_state
            .validate_exact_authenticated_genesis_application_bootstrap_v0(&config, genesis_qc)?;
        Self::validate_persisted_state_v0(&config, &safety_state, verifier)?;
        let expected_payload_parent_binding_ref =
            PayloadValidationParentV0::authenticated_genesis_application(
                safety_state.finalized(),
                authenticated_genesis_application_parent,
            )?
            .binding_ref_v0()?;
        let commissioned_rev0 = Box::new(safety_state.clone());
        let core = Self::empty(config, safety_state, false);
        core.validate_runtime(verifier, true)?;
        let owner = AuthenticatedGenesisApplicationH1OfflineValidationV0 {
            core,
            commissioned_rev0,
            safety_state_record_config_ref,
            expected_payload_parent_binding_ref,
            exact_h1: None,
            safety_binding_issued: false,
        };
        if owner.phase_v0()? != AuthenticatedGenesisApplicationH1OfflinePhaseV0::CommissionedRev0 {
            return Err(CoreError::AuthenticatedGenesisApplicationH1OfflineRejected(
                "prepared state did not activate the exact commissioned revision-zero phase",
            ));
        }
        let authority = owner.core.issue_application_seal_authority_v0()?;
        Ok(AuthenticatedGenesisApplicationH1OfflineActivationBundleV0 { owner, authority })
    }

    /// Begins exact takeover of one already durable authenticated-genesis h1
    /// revision-one obligation without recovering generic Core state.
    ///
    /// Core extracts the complete signed empty h1 from the sole durable
    /// obligation, replays it from the prepared tag-5 revision-zero state
    /// through the existing narrow proposal admission path, and requires the
    /// resulting state, barrier, validation identity, parent binding, and
    /// proposal to equal the supplied durable revision-one record. The replay
    /// owner remains persistence-pending. Only a future exact live-Safety
    /// attestation can unlock its real StorageAck and request emission.
    pub fn begin_authenticated_genesis_application_h1_obligation_takeover_v0<
        V: SignatureVerifier,
    >(
        config: CoreConfig,
        prepared: PreparedAuthenticatedGenesisApplicationBootstrapV0,
        revision_one: SafetyState,
        verifier: &V,
    ) -> Result<AuthenticatedGenesisApplicationH1ObligationTakeoverSessionV0> {
        config.validate()?;
        let revision_zero = prepared.safety_state().clone();
        let safety_state_record_config_ref = prepared.safety_state_record_config_ref_v0();
        Self::validate_persisted_successor_v0(&config, &revision_zero, &revision_one, verifier)?;

        let [durable_obligation] = revision_one.payload_validation_obligations() else {
            return Err(CoreError::AuthenticatedGenesisApplicationH1OfflineRejected(
                "takeover requires exactly one durable revision-one obligation",
            ));
        };
        if revision_one.revision() != 1
            || !revision_one.payload_validation_completions().is_empty()
            || !revision_one.payload_terminal_facts().is_empty()
            || durable_obligation.route() != PayloadValidationRouteV0::Synced
            || durable_obligation.first_recorded_revision() != 1
        {
            return Err(CoreError::AuthenticatedGenesisApplicationH1OfflineRejected(
                "takeover requires the exact pending Synced revision-one cut",
            ));
        }
        let proposal = durable_obligation.proposal().clone();
        let body = validate_root_bound_regular_body_v0(
            proposal.block(),
            config.validator_set(),
            config.consensus_parameters(),
        )
        .map_err(|_| {
            CoreError::AuthenticatedGenesisApplicationH1OfflineRejected(
                "takeover h1 body is not canonically bound to its signed roots",
            )
        })?;
        if body.transaction_count() != 0 || body.evidence_count() != 0 {
            return Err(CoreError::AuthenticatedGenesisApplicationH1OfflineRejected(
                "takeover supports only the canonical empty h1 obligation",
            ));
        }
        let expected_validation_id =
            ValidationId::new(proposal.block().id(), proposal.block().header().view(), 1);
        let expected_parent = PayloadValidationParentV0::authenticated_genesis_application(
            revision_zero.finalized(),
            prepared.authenticated_genesis_application_parent_v0(),
        )?;
        let expected_parent_binding_ref = expected_parent.binding_ref_v0()?;
        if durable_obligation.id() != expected_validation_id
            || durable_obligation.parent() != &expected_parent
            || durable_obligation.parent_binding_ref_v0()? != expected_parent_binding_ref
        {
            return Err(CoreError::AuthenticatedGenesisApplicationH1OfflineRejected(
                "takeover durable obligation identity or authenticated parent differs",
            ));
        }

        let AuthenticatedGenesisApplicationH1OfflineActivationBundleV0 {
            mut owner,
            authority,
        } = Self::begin_authenticated_genesis_application_h1_offline_validation_v0(
            config, prepared, verifier,
        )?;
        let persistence = owner.submit_exact_h1_synced_proposal_v0(proposal.clone(), verifier)?;
        if persistence.persistence_v0().state() != &revision_one
            || persistence.barrier_v0() != BarrierId::new(1)
            || persistence.validation_id_v0() != expected_validation_id
            || owner.phase_v0()?
                != AuthenticatedGenesisApplicationH1OfflinePhaseV0::ObligationPersistencePendingRev1
        {
            return Err(CoreError::AuthenticatedGenesisApplicationH1OfflineRejected(
                "replayed h1 does not exactly reproduce the durable revision-one barrier",
            ));
        }
        let replay_binding = owner.issue_safety_persistence_binding_v0()?;
        if !replay_binding.accepts_persistence_v0(persistence.persistence_v0())
            || replay_binding.proposal_v0() != &proposal
            || replay_binding.validation_id_v0() != expected_validation_id
            || replay_binding.safety_state_record_config_ref_v0() != safety_state_record_config_ref
        {
            return Err(CoreError::AuthenticatedGenesisApplicationH1OfflineRejected(
                "replayed h1 persistence is not affined to the exact takeover owner",
            ));
        }

        Ok(
            AuthenticatedGenesisApplicationH1ObligationTakeoverSessionV0 {
                challenge: AuthenticatedGenesisApplicationH1ObligationTakeoverChallengeV0 {
                    revision_zero: Box::new(revision_zero),
                    revision_one: Box::new(revision_one),
                    proposal: Box::new(proposal),
                    safety_state_record_config_ref,
                    authenticated_parent_binding_ref: expected_parent_binding_ref,
                    barrier: BarrierId::new(1),
                    validation_id: expected_validation_id,
                    affinity: Arc::new(()),
                },
                owner,
                authority,
                persistence,
                replay_binding,
            },
        )
    }

    fn validate_authenticated_genesis_application_exact_h1_proposal_v0<V: SignatureVerifier>(
        &self,
        proposal: &SignedProposalV0,
        verifier: &V,
    ) -> Result<()> {
        let header = proposal.block().header();
        if self.safety.revision() != 0
            || header.epoch() != Epoch::new(0)
            || header.height() != Height::new(1)
            || header.view() != View::new(1)
            || header.block_kind() != BlockKind::Regular
            || header.parent_id() != self.config.genesis_block_id()
            || proposal.witness().justify_qc() != self.safety.high_qc()
            || proposal.witness().timeout_certificate().is_some()
            || proposal.witness().epoch_anchor_authorization().is_some()
        {
            return Err(CoreError::AuthenticatedGenesisApplicationH1OfflineRejected(
                "offline h1 must be the canonical regular epoch-zero view-one genesis child",
            ));
        }
        validate_root_bound_regular_body_v0(
            proposal.block(),
            self.config.validator_set(),
            self.config.consensus_parameters(),
        )
        .map_err(|_| {
            CoreError::AuthenticatedGenesisApplicationH1OfflineRejected(
                "offline h1 body is not canonically bound to its signed roots",
            )
        })?;
        self.verify_proposal(proposal, verifier)?;
        Ok(())
    }

    fn classify_authenticated_genesis_application_h1_offline_phase_v0(
        &self,
        commissioned_rev0: &SafetyState,
        exact_h1: Option<&SignedProposalV0>,
        expected_payload_parent_binding_ref: [u8; 32],
    ) -> Result<AuthenticatedGenesisApplicationH1OfflinePhaseV0> {
        let state = &self.safety;
        if self
            .config
            .authenticated_genesis_application_parent_v0()
            .copied()
            != commissioned_rev0
                .authenticated_genesis_application_parent_v0()
                .copied()
            || state.schema_version() != commissioned_rev0.schema_version()
            || state.chain_id() != commissioned_rev0.chain_id()
            || state.protocol_version() != commissioned_rev0.protocol_version()
            || state.epoch() != commissioned_rev0.epoch()
            || state.validator_set_id() != commissioned_rev0.validator_set_id()
            || state.genesis_block_id() != commissioned_rev0.genesis_block_id()
            || state.authenticated_genesis_application_parent_v0()
                != commissioned_rev0.authenticated_genesis_application_parent_v0()
            || state.current_view() != commissioned_rev0.current_view()
            || state.last_voted_view() != commissioned_rev0.last_voted_view()
            || state.last_timeout_view() != commissioned_rev0.last_timeout_view()
            || state.high_qc() != commissioned_rev0.high_qc()
            || state.locked_qc() != commissioned_rev0.locked_qc()
            || state.finalized() != commissioned_rev0.finalized()
            || state.pending_tc_high_qc_sync() != commissioned_rev0.pending_tc_high_qc_sync()
            || state.pending_standalone_qc_sync() != commissioned_rev0.pending_standalone_qc_sync()
            || state.pending_sign() != commissioned_rev0.pending_sign()
            || state.last_finalization() != commissioned_rev0.last_finalization()
            || state.state_sync_anchor() != commissioned_rev0.state_sync_anchor()
            || state.application_applied() != commissioned_rev0.application_applied()
            || state.finalization_queue() != commissioned_rev0.finalization_queue()
            || state.pending_finalize() != commissioned_rev0.pending_finalize()
            || state.safety_halt() != commissioned_rev0.safety_halt()
            || !self.pending_validations.is_empty()
            || self.awaiting_signature
            || self.finalization_blocked_vote.is_some()
            || !self.observed_votes.is_empty()
            || !self.observed_timeouts.is_empty()
            || !self.observed_qcs.is_empty()
            || self.replay_required
            || self.recovered_validation_pending.is_some()
            || self.recovered_native_finalization_applied.is_some()
        {
            return Err(
                CoreError::AuthenticatedGenesisApplicationH1OfflineRejected(
                    "offline h1 progression changed a frozen genesis coordinate or unrelated runtime surface",
                ),
            );
        }

        if state.revision() == 0 {
            if state != commissioned_rev0
                || exact_h1.is_some()
                || !self.pending_sync_validations.is_empty()
                || self.pending_persistence.is_some()
                || !self.observed_proposals.is_empty()
                || self.next_validation_generation != 0
            {
                return Err(CoreError::AuthenticatedGenesisApplicationH1OfflineRejected(
                    "commissioned revision-zero phase is not inert",
                ));
            }
            return Ok(AuthenticatedGenesisApplicationH1OfflinePhaseV0::CommissionedRev0);
        }

        let proposal =
            exact_h1.ok_or(CoreError::AuthenticatedGenesisApplicationH1OfflineRejected(
                "post-commissioning phase lacks its exact h1 proposal",
            ))?;
        let header = proposal.block().header();
        let observation_key = (header.epoch(), header.view(), proposal.proposer());
        let exact_observation =
            self.observed_proposals
                .get(&observation_key)
                .is_some_and(|observed| {
                    observed.proposal == *proposal
                        && observed.authenticated_parent_timestamp_ms
                            == self.config.trusted_genesis_timestamp_ms()
                });
        if self.observed_proposals.len() != 1
            || !exact_observation
            || self.blocks.header(header.id()) != Some(header)
            || self.blocks.witness(header.id()) != Some(proposal.witness())
            || self.next_validation_generation != 1
        {
            return Err(CoreError::AuthenticatedGenesisApplicationH1OfflineRejected(
                "offline h1 volatile ancestry or validation generation is not exact",
            ));
        }

        let validation_id = ValidationId::new(header.id(), header.view(), 1);
        match state.revision() {
            1 => {
                let [obligation] = state.payload_validation_obligations() else {
                    return Err(CoreError::AuthenticatedGenesisApplicationH1OfflineRejected(
                        "revision one requires exactly one durable h1 obligation",
                    ));
                };
                let exact_pending = self
                    .pending_sync_validations
                    .get(&validation_id)
                    .is_some_and(|pending| pending.proposal == *proposal);
                if !state.payload_validation_completions().is_empty()
                    || !state.payload_terminal_facts().is_empty()
                    || self.pending_sync_validations.len() != 1
                    || !exact_pending
                    || obligation.route() != PayloadValidationRouteV0::Synced
                    || obligation.id() != validation_id
                    || obligation.proposal() != proposal
                    || obligation.first_recorded_revision() != 1
                    || obligation.parent_binding_ref_v0()? != expected_payload_parent_binding_ref
                    || self.blocks.payload_is_known(header.id())
                {
                    return Err(CoreError::AuthenticatedGenesisApplicationH1OfflineRejected(
                        "revision-one h1 obligation is not canonical",
                    ));
                }
                match self.pending_persistence.as_ref() {
                    Some(PendingPersistence { barrier, deferred })
                        if barrier.get() == 1
                            && deferred.as_slice()
                                == [DeferredEffect::ValidateSyncedPayload(validation_id)] =>
                    {
                        Ok(AuthenticatedGenesisApplicationH1OfflinePhaseV0::ObligationPersistencePendingRev1)
                    }
                    None => Ok(
                        AuthenticatedGenesisApplicationH1OfflinePhaseV0::ValidationRequestReleasedRev1,
                    ),
                    Some(_) => Err(
                        CoreError::AuthenticatedGenesisApplicationH1OfflineRejected(
                            "revision-one h1 persistence barrier or deferred effect is not exact",
                        ),
                    ),
                }
            }
            2 => {
                let [completion] = state.payload_validation_completions() else {
                    return Err(CoreError::AuthenticatedGenesisApplicationH1OfflineRejected(
                        "revision two requires exactly one durable h1 completion",
                    ));
                };
                let [terminal_fact] = state.payload_terminal_facts() else {
                    return Err(CoreError::AuthenticatedGenesisApplicationH1OfflineRejected(
                        "revision two requires exactly one durable h1 terminal fact",
                    ));
                };
                let body = validate_root_bound_regular_body_v0(
                    proposal.block(),
                    self.config.validator_set(),
                    self.config.consensus_parameters(),
                )
                .map_err(|_| {
                    CoreError::AuthenticatedGenesisApplicationH1OfflineRejected(
                        "durable h1 body is not canonically bound to its signed roots",
                    )
                })?;
                let result = completion.result();
                let Some(commitments) = result.commitments() else {
                    return Err(CoreError::AuthenticatedGenesisApplicationH1OfflineRejected(
                        "revision-two h1 completion is not Valid",
                    ));
                };
                let Some(artifact_ref) = result.artifact_ref() else {
                    return Err(CoreError::AuthenticatedGenesisApplicationH1OfflineRejected(
                        "revision-two h1 completion lacks its exact artifact reference",
                    ));
                };
                let overlay = artifact_ref.overlay();
                if !state.payload_validation_obligations().is_empty()
                    || !self.pending_sync_validations.is_empty()
                    || completion.route() != PayloadValidationRouteV0::Synced
                    || completion.id() != validation_id
                    || completion.first_recorded_revision() != 2
                    || commitments.block_id() != header.id()
                    || commitments.logical_block_size() != body.logical_block_size()
                    || commitments.transaction_count() != body.transaction_count()
                    || commitments.evidence_count() != body.evidence_count()
                    || overlay.block_id() != header.id()
                    || overlay.parent_block_id() != header.parent_id()
                    || *terminal_fact != PayloadTerminalFact::new_valid(overlay, 2)
                    || self.blocks.payload_overlay_ref(header.id()) != Some(overlay)
                {
                    return Err(
                        CoreError::AuthenticatedGenesisApplicationH1OfflineRejected(
                            "revision-two h1 completion, overlay, or body commitments are not canonical",
                        ),
                    );
                }
                match self.pending_persistence.as_ref() {
                    Some(PendingPersistence { barrier, deferred })
                        if barrier.get() == 2 && deferred.is_empty() =>
                    {
                        Ok(AuthenticatedGenesisApplicationH1OfflinePhaseV0::CompletionPersistencePendingRev2)
                    }
                    None => Ok(AuthenticatedGenesisApplicationH1OfflinePhaseV0::CompletedRev2),
                    Some(_) => Err(
                        CoreError::AuthenticatedGenesisApplicationH1OfflineRejected(
                            "revision-two h1 persistence barrier or deferred effect is not exact",
                        ),
                    ),
                }
            }
            _ => Err(CoreError::AuthenticatedGenesisApplicationH1OfflineRejected(
                "offline h1 progression exceeded its bounded revision-two terminal state",
            )),
        }
    }

    /// Verifies and prepares the only state-sync bootstrap supported by v0:
    /// one regular epoch-zero h1 block directly justified by configured
    /// genesis and finalized by its complete three-certified-header proof.
    ///
    /// The resulting revision-zero SafetyState sets both consensus finality and
    /// the application-applied watermark to h1. It deliberately contains no
    /// payload-validation obligation/completion, terminal fact, overlay,
    /// finalization carrier, or application outbox for h1.
    pub fn prepare_h1_state_sync_bootstrap_v0<V: SignatureVerifier>(
        config: CoreConfig,
        proof: FinalityProofV0,
        verifier: &V,
    ) -> Result<PreparedH1StateSyncBootstrapV0> {
        config.validate()?;
        if config
            .authenticated_genesis_application_parent_v0()
            .is_some()
        {
            return Err(CoreError::InvalidConfig(
                "authenticated genesis application bootstrap and h1 state-sync bootstrap are mutually exclusive",
            ));
        }
        if config.validator_set().epoch() != Epoch::new(0) {
            return Err(CoreError::InvalidConfig(
                "h1 state-sync bootstrap supports genesis epoch zero only",
            ));
        }
        let genesis_parent = FinalizedTip::new(
            Height::new(0),
            View::new(0),
            config.genesis_block_id(),
            config.trusted_genesis_timestamp_ms(),
        );
        let anchor = DurableStateSyncAnchorV0::new(genesis_parent, proof)?;
        Self::validate_h1_state_sync_anchor_v0(&config, &anchor, verifier)?;
        let safety_state = SafetyState::from_h1_state_sync_anchor(
            config.validator_set(),
            config.genesis_block_id(),
            config
                .authenticated_genesis_application_parent_v0()
                .copied(),
            anchor,
        )?;
        Self::validate_persisted_state_v0(&config, &safety_state, verifier)?;
        Ok(PreparedH1StateSyncBootstrapV0 { safety_state })
    }

    /// Validates one decoded durable safety state without recovering a live core.
    ///
    /// This authenticates the schema, configured context, cryptographic
    /// witnesses, and every semantic invariant available in the record.
    /// Payload-validation obligations are allowed here as inert persistence
    /// facts; validation neither reissues them nor grants callback authority.
    /// A self-consistent [`SafetyState`] still cannot prove in isolation that
    /// it is the newest durable record.
    pub fn validate_persisted_state_v0<V: SignatureVerifier>(
        config: &CoreConfig,
        state: &SafetyState,
        verifier: &V,
    ) -> Result<()> {
        config.validate()?;
        let replay_required = safety_replay_required(state);
        Self::empty(config.clone(), state.clone(), replay_required).validate_runtime(verifier, true)
    }

    /// Validates the monotonic relation between two independently authenticated
    /// persisted safety states.
    ///
    /// This checks one exact revision step and every history relation expressible
    /// from the two durable states. It deliberately does not mint a live Core or
    /// prove that `current` is the newest record. For a standalone QC target that
    /// was processed and removed, the persisted form can prove only canonical
    /// queue removal and that the durable high QC subsumes the target; the
    /// process-local block tree used by live admission is not serialized.
    pub fn validate_persisted_successor_v0<V: SignatureVerifier>(
        config: &CoreConfig,
        previous: &SafetyState,
        current: &SafetyState,
        verifier: &V,
    ) -> Result<()> {
        Self::validate_persisted_state_v0(config, previous, verifier)?;
        Self::validate_persisted_state_v0(config, current, verifier)?;
        if previous.revision().checked_add(1) != Some(current.revision()) {
            return Err(CoreError::InvalidRecovery(
                "persisted successor is not exactly one revision newer",
            ));
        }
        let replay_required = safety_replay_required(current);
        Self::empty(config.clone(), current.clone(), replay_required)
            .validate_monotonic_transition_inner(previous, true)
    }

    /// Restores the durable safety state after a process restart.
    ///
    /// [`Self::validate_persisted_state_v0`] is the read-only validation
    /// boundary for storage layers that need to authenticate an inert record,
    /// including one that still contains payload-validation obligations. This
    /// recovery boundary deliberately remains stricter: obligations cannot be
    /// reissued until an authenticated replay-ticket protocol exists.
    ///
    /// If `state.pending_sign()` is present, the caller must feed `Resume` and
    /// the core will request precisely that already-persisted signing root.
    /// The volatile block tree is rebuilt by replaying verified proposals and
    /// certificates from the finalized tip through the durable high QC; stale
    /// replay inputs never cause a vote. The storage/signer integration must
    /// reject a snapshot whose revision or signing watermarks precede its
    /// append-only sign journal.
    pub fn recover<V: SignatureVerifier>(
        config: CoreConfig,
        state: SafetyState,
        verifier: &V,
    ) -> Result<Self> {
        Self::validate_persisted_state_v0(&config, &state, verifier)?;
        if config
            .authenticated_genesis_application_parent_v0()
            .is_some()
        {
            return Err(CoreError::AuthenticatedGenesisApplicationActivationUnavailable);
        }
        if state.state_sync_anchor().is_some() {
            return Err(CoreError::InvalidRecovery(
                "a state-sync anchored namespace requires its dedicated authenticated recovery session",
            ));
        }
        if !state.payload_validation_obligations().is_empty() {
            return Err(CoreError::InvalidRecovery(
                "durable payload validation obligations require an authenticated replay ticket before recovery can reissue them",
            ));
        }
        if state
            .payload_validation_completions()
            .iter()
            .any(|completion| {
                completion.first_recorded_revision() == state.revision()
                    && completion.result().is_valid()
            })
        {
            return Err(CoreError::InvalidRecovery(
                "a current NativeValid completion requires its dedicated cross-store recovery session",
            ));
        }
        let replay_required = safety_replay_required(&state);
        Ok(Self::empty(config, state, replay_required))
    }

    /// Begins the fresh-only activation of one prepared and durably installed
    /// h1 state-sync base.
    ///
    /// This session accepts only the exact revision-zero shape produced by
    /// [`Self::prepare_h1_state_sync_bootstrap_v0`]. The trusted host must bind
    /// the matching ApplicationStore TrustedBase and a virgin signer namespace
    /// before activation. The returned Core is replay-request-only: every
    /// `Resume` idempotently emits one exact `RequestSafetyReplay`, while all
    /// supplied replay and consensus inputs remain hard-fenced until an
    /// authenticated anchored-successor recovery protocol exists. In
    /// particular, this slice cannot create h1 history or persist h2 state.
    pub fn begin_state_sync_anchor_recovery_v0<V: SignatureVerifier>(
        config: CoreConfig,
        state: SafetyState,
        verifier: &V,
    ) -> Result<StateSyncAnchorRecoverySessionV0> {
        Self::validate_persisted_state_v0(&config, &state, verifier)?;
        if config
            .authenticated_genesis_application_parent_v0()
            .is_some()
        {
            return Err(CoreError::AuthenticatedGenesisApplicationActivationUnavailable);
        }
        state
            .state_sync_anchor()
            .ok_or(CoreError::StateSyncAnchorRecoveryNotRequired)?;
        let core = Self::empty(config, state.clone(), true);
        let challenge = StateSyncAnchorRecoveryChallengeV0 {
            safety_state: Box::new(state),
            local_validator: core.config.local_validator(),
            affinity: Arc::clone(&core.persistence_affinity.0),
        };
        Ok(StateSyncAnchorRecoverySessionV0 { core, challenge })
    }

    /// Authenticates the complete h2/h3 bodies named by one durable h1 anchor.
    ///
    /// The returned carrier is inert and non-cloneable. It grants no Core,
    /// validation, application, signing, timer, or networking authority; it
    /// can only be consumed by [`Self::begin_state_sync_anchor_successor_recovery_v0`].
    pub fn prepare_h1_state_sync_anchor_successor_bundle_v0<V: SignatureVerifier>(
        config: &CoreConfig,
        state: &SafetyState,
        child: SignedProposalV0,
        grandchild: SignedProposalV0,
        verifier: &V,
    ) -> Result<H1StateSyncAnchorSuccessorBundleV0> {
        Self::validate_persisted_state_v0(config, state, verifier)?;
        let anchor = state
            .state_sync_anchor()
            .ok_or(CoreError::StateSyncAnchorRecoveryNotRequired)?;
        Self::validate_state_sync_anchor_successor_bundle_v0(
            config,
            state,
            anchor,
            &child,
            &grandchild,
            verifier,
        )?;
        Ok(H1StateSyncAnchorSuccessorBundleV0 {
            child: Box::new(child),
            grandchild: Box::new(grandchild),
        })
    }

    /// Begins the dedicated Core-only h2/h3 replay protocol above a fresh h1
    /// anchor. The legacy h1 recovery entry remains permanently replay-only.
    ///
    /// Revisions zero, two, and four begin from their exact stable cut.
    /// Revisions one and three are accepted only by reconstructing the unique
    /// stable predecessor, replaying Core's canonical next proposal, and
    /// requiring the reproduced persistence request and complete SafetyState
    /// to equal the durable obligation cut.  The volatile validation permit is
    /// retained inside that replayed Core and is released only after a trusted
    /// host reconciles Safety plus the durable native application job and then
    /// acknowledges the exact reproduced barrier.
    pub fn begin_state_sync_anchor_successor_recovery_v0<V: SignatureVerifier>(
        config: CoreConfig,
        state: SafetyState,
        bundle: H1StateSyncAnchorSuccessorBundleV0,
        verifier: &V,
    ) -> Result<StateSyncAnchorSuccessorRecoverySessionV0> {
        Self::validate_persisted_state_v0(&config, &state, verifier)?;
        if config
            .authenticated_genesis_application_parent_v0()
            .is_some()
        {
            return Err(CoreError::AuthenticatedGenesisApplicationActivationUnavailable);
        }
        let anchor = state
            .state_sync_anchor()
            .ok_or(CoreError::StateSyncAnchorRecoveryNotRequired)?;
        let phase = Self::classify_state_sync_anchor_successor_phase_v0(&config, &state, anchor)?;
        Self::validate_state_sync_anchor_successor_bundle_v0(
            &config,
            &state,
            anchor,
            bundle.child.as_ref(),
            bundle.grandchild.as_ref(),
            verifier,
        )?;
        let core = match phase {
            StateSyncAnchorSuccessorPhaseV0::H2ValidationPending
            | StateSyncAnchorSuccessorPhaseV0::H3ValidationPending => {
                Self::replay_state_sync_anchor_successor_obligation_v0(
                    config,
                    &state,
                    phase,
                    bundle.child.as_ref(),
                    bundle.grandchild.as_ref(),
                    verifier,
                )?
            }
            StateSyncAnchorSuccessorPhaseV0::H1Bootstrap
            | StateSyncAnchorSuccessorPhaseV0::H2Valid
            | StateSyncAnchorSuccessorPhaseV0::H3Valid => Self::empty(config, state.clone(), true),
        };
        let affinity = Arc::clone(&core.persistence_affinity.0);
        let H1StateSyncAnchorSuccessorBundleV0 { child, grandchild } = bundle;
        let challenge = StateSyncAnchorSuccessorRecoveryChallengeV0 {
            safety_state: Box::new(state),
            phase,
            child,
            grandchild,
            affinity,
        };
        Ok(StateSyncAnchorSuccessorRecoverySessionV0 { core, challenge })
    }

    /// Consumes the already-commissioned live h1 Core into the dedicated
    /// successor replay session without replacing its process-local
    /// persistence or application-seal affinities.
    ///
    /// This entry accepts only an inert, replay-fenced stable rev0/rev2/rev4
    /// owner.  Restart cuts use
    /// [`Self::begin_state_sync_anchor_successor_recovery_v0`] instead.
    pub fn begin_live_state_sync_anchor_successor_transfer_v0<V: SignatureVerifier>(
        self,
        bundle: H1StateSyncAnchorSuccessorBundleV0,
        verifier: &V,
    ) -> Result<StateSyncAnchorSuccessorRecoverySessionV0> {
        Self::validate_persisted_state_v0(&self.config, &self.safety, verifier)?;
        if self
            .config
            .authenticated_genesis_application_parent_v0()
            .is_some()
        {
            return Err(CoreError::AuthenticatedGenesisApplicationActivationUnavailable);
        }
        let anchor = self
            .safety
            .state_sync_anchor()
            .ok_or(CoreError::StateSyncAnchorRecoveryNotRequired)?;
        let phase = Self::classify_state_sync_anchor_successor_phase_v0(
            &self.config,
            &self.safety,
            anchor,
        )?;
        if matches!(
            phase,
            StateSyncAnchorSuccessorPhaseV0::H2ValidationPending
                | StateSyncAnchorSuccessorPhaseV0::H3ValidationPending
        ) || !self.replay_required
            || self.pending_persistence.is_some()
            || self.pending_validation_count() != 0
            || self.awaiting_signature
            || self.recovered_validation_pending.is_some()
            || self.recovered_native_finalization_applied.is_some()
        {
            return Err(CoreError::StateSyncAnchorSuccessorRecoveryRejected(
                "live successor transfer requires an inert replay-fenced stable Core",
            ));
        }
        Self::validate_state_sync_anchor_successor_bundle_v0(
            &self.config,
            &self.safety,
            anchor,
            bundle.child.as_ref(),
            bundle.grandchild.as_ref(),
            verifier,
        )?;
        let affinity = Arc::clone(&self.persistence_affinity.0);
        let state = self.safety.clone();
        let H1StateSyncAnchorSuccessorBundleV0 { child, grandchild } = bundle;
        let challenge = StateSyncAnchorSuccessorRecoveryChallengeV0 {
            safety_state: Box::new(state),
            phase,
            child,
            grandchild,
            affinity,
        };
        Ok(StateSyncAnchorSuccessorRecoverySessionV0 {
            core: self,
            challenge,
        })
    }

    /// Begins recovery of a state-sync anchored namespace only after the
    /// explicit durable revision-five promotion cut has been crossed.
    ///
    /// This boundary is distinct from the bounded revision-zero-through-four
    /// successor replay session.  It retains the permanent h1 anchor, joins
    /// the exact proof-named h2/h3 bodies through a trusted reconciler, and
    /// releases a generic Core only after that join.  Exact revision five can
    /// close ordinary safety replay immediately; later revisions retain the
    /// normal replay fence for any ancestry above h3.
    pub fn begin_state_sync_anchor_ordinary_recovery_v0<V: SignatureVerifier>(
        config: CoreConfig,
        state: SafetyState,
        bundle: H1StateSyncAnchorSuccessorBundleV0,
        verifier: &V,
    ) -> Result<StateSyncAnchorOrdinaryRecoverySessionV0> {
        Self::validate_persisted_state_v0(&config, &state, verifier)?;
        if config
            .authenticated_genesis_application_parent_v0()
            .is_some()
        {
            return Err(CoreError::AuthenticatedGenesisApplicationActivationUnavailable);
        }
        let anchor = state
            .state_sync_anchor()
            .ok_or(CoreError::StateSyncAnchorRecoveryNotRequired)?;
        if state.revision() < 5 {
            return Err(CoreError::StateSyncAnchorSuccessorRecoveryUnavailable);
        }
        Self::validate_state_sync_anchor_ordinary_state_v0(&config, &state, anchor)?;
        Self::validate_state_sync_anchor_successor_bundle_v0(
            &config,
            &state,
            anchor,
            bundle.child.as_ref(),
            bundle.grandchild.as_ref(),
            verifier,
        )?;
        if !state.payload_validation_obligations().is_empty() {
            return Err(
                CoreError::StateSyncAnchorSuccessorInFlightRecoveryUnavailable {
                    revision: state.revision(),
                },
            );
        }
        let replay_required = safety_replay_required(&state);
        let core = Self::empty(config, state.clone(), replay_required);
        let affinity = Arc::clone(&core.persistence_affinity.0);
        let H1StateSyncAnchorSuccessorBundleV0 { child, grandchild } = bundle;
        let challenge = StateSyncAnchorOrdinaryRecoveryChallengeV0 {
            safety_state: Box::new(state),
            child,
            grandchild,
            affinity,
        };
        Ok(StateSyncAnchorOrdinaryRecoverySessionV0 { core, challenge })
    }

    /// Begins the bounded V0 takeover of one crash-surviving validation job.
    ///
    /// This is deliberately separate from [`Self::recover`], which continues
    /// to reject every nonempty obligation set.  The returned session is inert:
    /// it exposes no Core and can become live only through
    /// [`PayloadValidationRecoverySessionV0::reconcile_and_activate_v0`].  V0
    /// accepts exactly one durable obligation and only a trusted-host assertion
    /// that the matching application journal already contains a
    /// deterministic-invalid result.  Concurrent obligations and other result
    /// classes remain fail-closed for later protocol versions.
    pub fn begin_payload_validation_obligation_recovery_v0<V: SignatureVerifier>(
        config: CoreConfig,
        state: SafetyState,
        verifier: &V,
    ) -> Result<PayloadValidationRecoverySessionV0> {
        Self::validate_persisted_state_v0(&config, &state, verifier)?;
        if config
            .authenticated_genesis_application_parent_v0()
            .is_some()
        {
            return Err(CoreError::AuthenticatedGenesisApplicationActivationUnavailable);
        }
        if state.state_sync_anchor().is_some() {
            return Err(CoreError::InvalidRecovery(
                "state-sync anchored validation recovery requires a later authenticated protocol",
            ));
        }
        let obligation = match state.payload_validation_obligations() {
            [] => return Err(CoreError::PayloadValidationRecoveryNotRequired),
            [obligation] => obligation.clone(),
            obligations => {
                return Err(CoreError::UnsupportedPayloadValidationRecovery {
                    obligations: obligations.len(),
                });
            }
        };
        if state
            .payload_terminal_result(obligation.id().block_id())
            .is_some()
        {
            return Err(CoreError::UnsupportedPayloadValidationRecoveryState(
                "the challenged block already has a durable terminal payload fact",
            ));
        }
        let safety_head_revision = state.revision();
        let replay_required = safety_replay_required(&state);
        let core = Self::empty(config, state, replay_required);
        let challenge = PayloadValidationRecoveryChallengeV0 {
            safety_head_revision,
            obligation,
            affinity: Arc::clone(&core.persistence_affinity.0),
        };
        Ok(PayloadValidationRecoverySessionV0 { core, challenge })
    }

    /// Begins bounded recovery of one ordinary stable NativeValid completion.
    ///
    /// The durable Core record must be non-anchored, contain no obligation,
    /// and contain exactly one Valid completion first recorded at the current
    /// revision. The returned session is inert. A trusted host must join the
    /// exact authenticated SafetyStore transition to either the stable App
    /// Delivered (C+D) or Acked (C+K) row before activation. Generic
    /// [`Self::recover`] rejects this current-head shape so it cannot bypass
    /// the App acknowledgement boundary.
    pub fn begin_native_valid_completion_recovery_v0<V: SignatureVerifier>(
        config: CoreConfig,
        state: SafetyState,
        verifier: &V,
    ) -> Result<NativeValidCompletionRecoverySessionV0> {
        Self::validate_persisted_state_v0(&config, &state, verifier)?;
        if config
            .authenticated_genesis_application_parent_v0()
            .is_some()
        {
            return Err(CoreError::AuthenticatedGenesisApplicationActivationUnavailable);
        }
        if state.state_sync_anchor().is_some() {
            return Err(CoreError::NativeValidCompletionRecoveryRejected(
                "state-sync anchored NativeValid completion requires its bounded successor protocol",
            ));
        }
        if !state.payload_validation_obligations().is_empty() {
            return Err(CoreError::NativeValidCompletionRecoveryRejected(
                "NativeValid completion recovery cannot overlap a validation obligation",
            ));
        }
        let completion = exact_current_native_valid_completion_v0(&state)?;
        let valid_result_checksum = native_valid_result_checksum_v0(completion.result()).ok_or(
            CoreError::NativeValidCompletionRecoveryRejected(
                "the current completion is not canonically Valid",
            ),
        )?;
        let replay_required = safety_replay_required(&state);
        let core = Self::empty(config, state.clone(), replay_required);
        let challenge = NativeValidCompletionRecoveryChallengeV0 {
            safety_state: Box::new(state),
            valid_result_checksum,
            affinity: Arc::clone(&core.persistence_affinity.0),
        };
        Ok(NativeValidCompletionRecoverySessionV0 { core, challenge })
    }

    /// Begins read-only recovery of the only stable authenticated-genesis h1
    /// NativeValid cut admitted by V0.
    ///
    /// The complete rev0/tag-5 -> rev1/Ordinary -> rev2/NativeValid lineage is
    /// supplied as already durable comparison material.  This boundary never
    /// constructs a live Core and does not support obligation/request remint;
    /// O, O+P, and O+D remain fail-closed.
    pub fn begin_authenticated_genesis_application_h1_stable_native_valid_recovery_v0<
        V: SignatureVerifier,
    >(
        config: CoreConfig,
        prepared: PreparedAuthenticatedGenesisApplicationBootstrapV0,
        revision_one: SafetyState,
        revision_two: SafetyState,
        verifier: &V,
    ) -> Result<AuthenticatedGenesisApplicationH1StableNativeValidRecoverySessionV0> {
        config.validate()?;
        let PreparedAuthenticatedGenesisApplicationBootstrapV0 {
            core_config,
            safety_state: revision_zero,
            authenticated_genesis_application_parent,
            safety_state_record_config_ref,
        } = prepared;
        let configured_parent = config
            .authenticated_genesis_application_parent_v0()
            .copied()
            .ok_or(CoreError::NativeValidCompletionRecoveryRejected(
                "stable h1 recovery requires the authenticated genesis application parent",
            ))?;
        if config != core_config || configured_parent != authenticated_genesis_application_parent {
            return Err(CoreError::NativeValidCompletionRecoveryRejected(
                "prepared and configured authenticated-genesis contexts differ",
            ));
        }
        let Some(ContextAuthorizedQcV0::Genesis(genesis_qc)) =
            revision_zero.high_qc().as_synthetic()
        else {
            return Err(CoreError::NativeValidCompletionRecoveryRejected(
                "stable h1 recovery revision zero lacks its GenesisQC",
            ));
        };
        revision_zero
            .validate_exact_authenticated_genesis_application_bootstrap_v0(&config, genesis_qc)?;
        Self::validate_persisted_successor_v0(&config, &revision_zero, &revision_one, verifier)?;
        Self::validate_persisted_successor_v0(&config, &revision_one, &revision_two, verifier)?;

        let [obligation] = revision_one.payload_validation_obligations() else {
            return Err(CoreError::NativeValidCompletionRecoveryRejected(
                "stable h1 lineage requires exactly one revision-one obligation",
            ));
        };
        let proposal = obligation.proposal().clone();
        let header = proposal.block().header();
        let body = validate_root_bound_regular_body_v0(
            proposal.block(),
            config.validator_set(),
            config.consensus_parameters(),
        )
        .map_err(|_| {
            CoreError::NativeValidCompletionRecoveryRejected(
                "stable h1 proposal body is not canonically root-bound",
            )
        })?;
        let validation_id = ValidationId::new(header.id(), header.view(), 1);
        let expected_parent = PayloadValidationParentV0::authenticated_genesis_application(
            revision_zero.finalized(),
            configured_parent,
        )?;
        let expected_parent_binding_ref = expected_parent.binding_ref_v0()?;
        if revision_one.revision() != 1
            || revision_one.current_view() != revision_zero.current_view()
            || revision_one.last_voted_view() != revision_zero.last_voted_view()
            || revision_one.last_timeout_view() != revision_zero.last_timeout_view()
            || revision_one.high_qc() != revision_zero.high_qc()
            || revision_one.locked_qc() != revision_zero.locked_qc()
            || revision_one.finalized() != revision_zero.finalized()
            || revision_one.last_finalization() != revision_zero.last_finalization()
            || revision_one.application_applied() != revision_zero.application_applied()
            || revision_one.finalization_queue() != revision_zero.finalization_queue()
            || revision_one.state_sync_anchor() != revision_zero.state_sync_anchor()
            || revision_one.pending_sign() != revision_zero.pending_sign()
            || revision_one.pending_finalize() != revision_zero.pending_finalize()
            || revision_one.pending_tc_high_qc_sync() != revision_zero.pending_tc_high_qc_sync()
            || revision_one.pending_standalone_qc_sync()
                != revision_zero.pending_standalone_qc_sync()
            || revision_one.safety_halt() != revision_zero.safety_halt()
            || !revision_one.payload_validation_completions().is_empty()
            || !revision_one.payload_terminal_facts().is_empty()
            || obligation.route() != PayloadValidationRouteV0::Synced
            || obligation.id() != validation_id
            || obligation.parent() != &expected_parent
            || obligation.first_recorded_revision() != 1
            || header.epoch() != Epoch::new(0)
            || header.height() != Height::new(1)
            || header.view() != View::new(1)
            || header.block_kind() != BlockKind::Regular
            || header.parent_id() != configured_parent.genesis_block_id()
            || proposal.witness().justify_qc() != revision_zero.high_qc()
            || proposal.witness().timeout_certificate().is_some()
            || proposal.witness().epoch_anchor_authorization().is_some()
            || body.transaction_count() != 0
            || body.evidence_count() != 0
        {
            return Err(CoreError::NativeValidCompletionRecoveryRejected(
                "revision-one state is not the exact empty authenticated-genesis h1 obligation",
            ));
        }

        let completion = exact_current_native_valid_completion_v0(&revision_two)?;
        let terminal = revision_two
            .payload_terminal_fact(validation_id.block_id())
            .ok_or(CoreError::NativeValidCompletionRecoveryRejected(
                "stable h1 revision two lacks its exact terminal fact",
            ))?;
        let artifact = completion.result().artifact_ref().ok_or(
            CoreError::NativeValidCompletionRecoveryRejected(
                "stable h1 completion lacks its exact artifact",
            ),
        )?;
        let commitments = completion.result().commitments().ok_or(
            CoreError::NativeValidCompletionRecoveryRejected(
                "stable h1 completion lacks its exact commitments",
            ),
        )?;
        if revision_two.revision() != 2
            || revision_two.current_view() != revision_zero.current_view()
            || revision_two.last_voted_view() != revision_zero.last_voted_view()
            || revision_two.last_timeout_view() != revision_zero.last_timeout_view()
            || revision_two.high_qc() != revision_zero.high_qc()
            || revision_two.locked_qc() != revision_zero.locked_qc()
            || revision_two.finalized() != revision_zero.finalized()
            || revision_two.last_finalization() != revision_zero.last_finalization()
            || revision_two.application_applied() != revision_zero.application_applied()
            || revision_two.finalization_queue() != revision_zero.finalization_queue()
            || revision_two.state_sync_anchor() != revision_zero.state_sync_anchor()
            || revision_two.pending_sign() != revision_zero.pending_sign()
            || revision_two.pending_finalize() != revision_zero.pending_finalize()
            || revision_two.pending_tc_high_qc_sync() != revision_zero.pending_tc_high_qc_sync()
            || revision_two.pending_standalone_qc_sync()
                != revision_zero.pending_standalone_qc_sync()
            || revision_two.safety_halt() != revision_zero.safety_halt()
            || !revision_two.payload_validation_obligations().is_empty()
            || revision_two.payload_validation_completions().len() != 1
            || revision_two.payload_terminal_facts().len() != 1
            || completion.route() != PayloadValidationRouteV0::Synced
            || completion.id() != validation_id
            || completion.first_recorded_revision() != 2
            || commitments.block_id() != header.id()
            || commitments.logical_block_size() != body.logical_block_size()
            || commitments.transaction_count() != 0
            || commitments.evidence_count() != 0
            || artifact.overlay().block_id() != header.id()
            || artifact.overlay().parent_block_id() != configured_parent.genesis_block_id()
            || terminal != PayloadTerminalFact::new_valid(artifact.overlay(), 2)
            || revision_two.pending_sign().is_some()
            || revision_two.pending_finalize().is_some()
            || revision_two.pending_tc_high_qc_sync().is_some()
            || revision_two.pending_standalone_qc_sync().is_some()
            || revision_two.safety_halt().is_some()
        {
            return Err(CoreError::NativeValidCompletionRecoveryRejected(
                "revision-two state is not the exact inert authenticated-genesis h1 NativeValid completion",
            ));
        }

        let completion_carrier_checksum =
            authenticated_genesis_h1_stable_completion_carrier_checksum_v0(
                safety_state_record_config_ref,
                expected_parent_binding_ref,
                &revision_two,
                validation_id,
                BarrierId::new(2),
                NativeValidPostAckActionV0::None,
            )?;
        let challenge = AuthenticatedGenesisApplicationH1StableNativeValidRecoveryChallengeV0 {
            revision_zero: Box::new(revision_zero),
            revision_one: Box::new(revision_one),
            revision_two: Box::new(revision_two),
            proposal: Box::new(proposal),
            safety_state_record_config_ref,
            authenticated_parent_binding_ref: expected_parent_binding_ref,
            completion_carrier_checksum,
            affinity: Arc::new(()),
        };
        Ok(AuthenticatedGenesisApplicationH1StableNativeValidRecoverySessionV0 { challenge })
    }

    /// Begins exact recovery of a current SafetyStore codec-v0/tag-3
    /// finalization-applied head.
    ///
    /// The returned session is inert and exposes no live Core.  The trusted
    /// host must first obtain authenticated exact readbacks from SafetyStore
    /// and ApplicationStore, then bind them through the session challenge.
    /// Generic [`Self::recover`] does not inspect transition context and must
    /// not be used by a host whose current journal head is tag 3.
    ///
    /// This Core-only slice deliberately supplies no node or ApplicationStore
    /// reconciliation wiring; production activation remains closed until that
    /// downstream owner can provide the required exact readbacks.
    pub fn begin_native_finalization_applied_recovery_v0<V: SignatureVerifier>(
        config: CoreConfig,
        state: SafetyState,
        verifier: &V,
    ) -> Result<NativeFinalizationAppliedRecoverySessionV0> {
        Self::validate_persisted_state_v0(&config, &state, verifier)?;
        if config
            .authenticated_genesis_application_parent_v0()
            .is_some()
        {
            return Err(CoreError::AuthenticatedGenesisApplicationActivationUnavailable);
        }
        if state.state_sync_anchor().is_some() {
            return Err(CoreError::NativeFinalizationAppliedRecoveryRejected(
                "state-sync anchored tag-3 recovery requires a later combined reconciliation protocol",
            ));
        }
        if !state.payload_validation_obligations().is_empty() {
            return Err(CoreError::NativeFinalizationAppliedRecoveryRejected(
                "tag-3 recovery cannot overlap a payload-validation obligation",
            ));
        }
        let replay_required = safety_replay_required(&state);
        let core = Self::empty(config, state.clone(), replay_required);
        let challenge = NativeFinalizationAppliedRecoveryChallengeV0 {
            safety_state: Box::new(state),
            affinity: Arc::clone(&core.persistence_affinity.0),
        };
        Ok(NativeFinalizationAppliedRecoverySessionV0 { core, challenge })
    }

    pub const fn config(&self) -> &CoreConfig {
        &self.config
    }

    pub const fn safety_state(&self) -> &SafetyState {
        &self.safety
    }

    #[cfg(test)]
    pub(crate) fn observe_qc_for_test(
        &mut self,
        certificate: &QuorumCertificate,
    ) -> Result<Option<crate::SafetyHalt>> {
        self.observe_qc(certificate)
    }

    #[cfg(test)]
    pub(crate) fn observed_qc_views_for_test(&self) -> Vec<View> {
        self.observed_qcs.keys().copied().collect()
    }

    /// Commits the complete hash-linked prefix ending at Core's exact durable
    /// finalized tip. Core admits that tip only after validating the complete
    /// ancestor-ordered finalization suffix; recovery authenticates the same
    /// `SafetyState`, making this projection stable across process restart.
    pub fn finalized_chain_root_v0(&self) -> FinalizedChainRootV0 {
        let finalized = self.safety.finalized();
        let height = finalized.height().get().to_be_bytes();
        let view = finalized.view().get().to_be_bytes();
        let timestamp_ms = finalized.timestamp_ms().to_be_bytes();
        let chain_id = self.safety.chain_id();
        let genesis_block_id = self.safety.genesis_block_id();
        let finalized_block_id = finalized.block_id();
        let parts: [&[u8]; 6] = [
            chain_id.as_str().as_bytes(),
            genesis_block_id.as_bytes(),
            &height,
            &view,
            finalized_block_id.as_bytes(),
            &timestamp_ms,
        ];
        let mut hasher = Sha256::new();
        hasher.update(b"trnm.domain.hash.v1");
        hasher.update((FINALIZED_PREFIX_CHAIN_ROOT_DOMAIN_V0.len() as u64).to_be_bytes());
        hasher.update(FINALIZED_PREFIX_CHAIN_ROOT_DOMAIN_V0.as_bytes());
        for part in parts {
            hasher.update((part.len() as u64).to_be_bytes());
            hasher.update(part);
        }
        FinalizedChainRootV0(hasher.finalize().into())
    }

    pub fn pending_validation_count(&self) -> usize {
        self.pending_validations.len() + self.pending_sync_validations.len()
    }

    fn payload_validation_slot_count(&self) -> Result<usize> {
        self.safety
            .payload_validation_obligations()
            .len()
            .checked_add(self.safety.payload_validation_completions().len())
            .ok_or(CoreError::ArithmeticOverflow(
                "payload validation durable slots",
            ))
    }

    /// Freezes the only parent authority which may accompany this exact
    /// payload-validation generation.
    ///
    /// A speculative parent is recovered from the already-authenticated block
    /// tree. A positive-height finalized parent is recovered from the durable
    /// finalization proof rather than from caller input. The synthetic genesis
    /// anchor intentionally carries no invented state root.
    fn payload_validation_parent(
        &self,
        id: ValidationId,
        block: &Block,
    ) -> Result<PayloadValidationParentV0> {
        let header = block.header();
        let block_id = block.id();
        if id.block_id() != block_id {
            return Err(CoreError::ValidationCapabilityMismatch {
                expected: block_id,
                received: id.block_id(),
            });
        }
        if id.view() != header.view() {
            return Err(CoreError::WrongView {
                expected: header.view(),
                received: id.view(),
            });
        }

        let finalized = self.safety.finalized();
        let parent = if header.parent_id() == finalized.block_id() {
            if finalized.height().get() == 0 {
                match self
                    .config
                    .authenticated_genesis_application_parent_v0()
                    .copied()
                {
                    Some(application_parent) => {
                        PayloadValidationParentV0::authenticated_genesis_application(
                            finalized,
                            application_parent,
                        )?
                    }
                    None => PayloadValidationParentV0::trusted_genesis(finalized),
                }
            } else {
                let exact = if let Some(durable) = self.safety.last_finalization() {
                    durable.proof().finalized_block().header()
                } else if let Some(anchor) = self.safety.state_sync_anchor() {
                    anchor.proof().finalized_block().header()
                } else {
                    return Err(CoreError::InvalidRecovery(
                        "positive finalized payload parent lacks durable finalization or state-sync provenance",
                    ));
                };
                if exact.id() != finalized.block_id()
                    || exact.height() != finalized.height()
                    || exact.view() != finalized.view()
                    || exact.timestamp_ms() != finalized.timestamp_ms()
                {
                    return Err(CoreError::InvalidRecovery(
                        "durable finalization header differs from payload parent tip",
                    ));
                }
                PayloadValidationParentV0::from_finalized_exact_header(exact.clone())
            }
        } else {
            let exact = self
                .blocks
                .header(header.parent_id())
                .ok_or(CoreError::MissingBlock(header.parent_id()))?;
            let overlay = self
                .blocks
                .payload_overlay_ref(header.parent_id())
                .ok_or(CoreError::UnsafeProposal)?;
            if overlay.block_id() != exact.id() || overlay.parent_block_id() != exact.parent_id() {
                return Err(CoreError::ConflictingPayloadValidation(exact.id()));
            }
            PayloadValidationParentV0::from_speculative_exact_header(exact.clone(), overlay)
        };

        let tip = parent.tip();
        if header.parent_id() != tip.block_id()
            || header.height() != tip.height().checked_next()?
            || header.genesis_hash() != self.config.validator_set().genesis_hash()
            || header.chain_id() != self.config.validator_set().chain_id()
            || header.protocol_version() != self.config.validator_set().protocol_version()
            || header.epoch() != self.config.validator_set().epoch()
            || header.validator_set_id() != self.config.validator_set().id()
            || header.consensus_parameters_hash() != self.config.consensus_parameters().hash()
        {
            return Err(CoreError::UnsafeProposal);
        }
        if let Some(exact) = parent.exact_header() {
            if exact.id() != tip.block_id()
                || exact.height() != tip.height()
                || exact.view() != tip.view()
                || exact.timestamp_ms() != tip.timestamp_ms()
                || !payload_parent_context_matches_target_v0(header, exact)?
            {
                return Err(CoreError::UnsafeProposal);
            }
        }
        Ok(parent)
    }

    fn payload_validation_request_from_obligation(
        &self,
        route: PayloadValidationRouteV0,
        id: ValidationId,
    ) -> Result<PayloadValidationRequest> {
        let obligation = self
            .safety
            .payload_validation_obligations()
            .binary_search_by_key(&id, DurablePayloadValidationObligationV0::id)
            .ok()
            .and_then(|index| self.safety.payload_validation_obligations().get(index))
            .filter(|obligation| obligation.route() == route)
            .ok_or(CoreError::InvalidRecovery(
                "deferred payload validation has no exact durable obligation",
            ))?;
        let pending = match route {
            PayloadValidationRouteV0::Proposal => self.pending_validations.get(&id),
            PayloadValidationRouteV0::Synced => self.pending_sync_validations.get(&id),
        }
        .ok_or(CoreError::InvalidRecovery(
            "deferred payload validation has no exact volatile proposal",
        ))?;
        if &pending.proposal != obligation.proposal() {
            return Err(CoreError::InvalidRecovery(
                "deferred payload validation proposal differs from its durable obligation",
            ));
        }
        Ok(PayloadValidationRequest::new(
            route,
            id,
            obligation.proposal().block().clone(),
            obligation.parent().clone(),
            Arc::clone(&pending.affinity.0),
        ))
    }

    fn activate_recovered_payload_validation_v0(
        &mut self,
        challenged: &DurablePayloadValidationObligationV0,
    ) -> Result<()> {
        if self.recovered_validation_pending.is_some()
            || self.pending_validation_count() != 0
            || self.pending_persistence.is_some()
            || self.awaiting_signature
        {
            return Err(CoreError::InvalidRecovery(
                "payload-validation recovery session was not inert at activation",
            ));
        }
        let durable = self
            .safety
            .payload_validation_obligations()
            .first()
            .filter(|durable| *durable == challenged)
            .cloned()
            .ok_or(CoreError::InvalidRecovery(
                "payload-validation recovery challenge differs from the durable obligation",
            ))?;
        if self.safety.payload_validation_obligations().len() != 1 {
            return Err(CoreError::UnsupportedPayloadValidationRecovery {
                obligations: self.safety.payload_validation_obligations().len(),
            });
        }

        let proposal = durable.proposal().clone();
        let block_id = proposal.block().id();
        let header = proposal.block().header();
        let parent = durable.parent();
        let parent_binding_is_exact = match parent.exact_header() {
            Some(exact) => {
                exact.id() == parent.tip().block_id()
                    && exact.height() == parent.tip().height()
                    && exact.view() == parent.tip().view()
                    && exact.timestamp_ms() == parent.tip().timestamp_ms()
                    && payload_parent_context_matches_target_v0(header, exact)?
            }
            None => payload_genesis_parent_matches_config_v0(parent, &self.config),
        };
        if durable.id().block_id() != block_id
            || durable.id().view() != header.view()
            || header.parent_id() != parent.tip().block_id()
            || header.height() != parent.tip().height().checked_next()?
            || !parent_binding_is_exact
        {
            return Err(CoreError::PayloadValidationRecoveryRejected);
        }
        let protected = self.protected_blocks();
        self.blocks
            .insert_verified_proposal(&proposal, &protected)?;
        self.restore_durable_payload_fact(block_id)?;
        match durable.route() {
            PayloadValidationRouteV0::Proposal => {
                self.pending_validations
                    .insert(durable.id(), PendingPayloadValidationV0::new(proposal));
            }
            PayloadValidationRouteV0::Synced => {
                self.pending_sync_validations
                    .insert(durable.id(), PendingPayloadValidationV0::new(proposal));
            }
        }
        self.recovered_validation_pending = Some(RecoveredPayloadValidationFenceV0 {
            route: durable.route(),
            id: durable.id(),
        });
        self.validate_recovered_payload_validation_fence_v0()
    }

    fn restore_state_sync_anchor_successor_tree_v0(
        &mut self,
        phase: StateSyncAnchorSuccessorPhaseV0,
        child: &SignedProposalV0,
        grandchild: &SignedProposalV0,
    ) -> Result<()> {
        if self.pending_validation_count() != 0
            || self.pending_persistence.is_some()
            || self.awaiting_signature
            || self.recovered_validation_pending.is_some()
            || self.recovered_native_finalization_applied.is_some()
        {
            return Err(CoreError::StateSyncAnchorSuccessorRecoveryRejected(
                "anchored successor recovery did not begin from an inert Core",
            ));
        }
        let restored_count = match phase {
            StateSyncAnchorSuccessorPhaseV0::H1Bootstrap => 0,
            StateSyncAnchorSuccessorPhaseV0::H2Valid => 1,
            StateSyncAnchorSuccessorPhaseV0::H3Valid => 2,
            StateSyncAnchorSuccessorPhaseV0::H2ValidationPending
            | StateSyncAnchorSuccessorPhaseV0::H3ValidationPending => {
                return Err(
                    CoreError::StateSyncAnchorSuccessorInFlightRecoveryUnavailable {
                        revision: self.safety.revision(),
                    },
                );
            }
        };
        for proposal in [child, grandchild].into_iter().take(restored_count) {
            let block_id = proposal.block().id();
            let completion = self
                .safety
                .payload_validation_completions()
                .iter()
                .find(|completion| completion.id().block_id() == block_id)
                .ok_or(CoreError::StateSyncAnchorSuccessorRecoveryRejected(
                    "recovery lacks the exact durable Valid completion",
                ))?;
            let result = completion.result();
            result
                .commitments()
                .ok_or(CoreError::StateSyncAnchorSuccessorRecoveryRejected(
                    "recovered successor completion is not Valid",
                ))?;
            let artifact_ref = result.artifact_ref().ok_or(
                CoreError::StateSyncAnchorSuccessorRecoveryRejected(
                    "recovered successor completion lacks its artifact reference",
                ),
            )?;
            let protected = self.protected_blocks();
            self.blocks.insert_verified_proposal(proposal, &protected)?;
            self.blocks
                .restore_authenticated_valid_overlay_v0(proposal, artifact_ref.overlay())?;
        }
        Ok(())
    }

    /// Rebuilds only volatile ordinary ancestry above the permanent h1/h2/h3
    /// prefix. Every durable Safety field remains byte-for-byte unchanged.
    fn rehydrate_checkpointed_ordinary_tree_v0<V: SignatureVerifier>(
        &mut self,
        plan: &AnchoredOrdinaryReplayArchivePlanV0,
        entries: &[AnchoredOrdinarySignedReplayEntryV0],
        verifier: &V,
    ) -> Result<[u8; 32]> {
        let original_safety = self.safety.clone();
        if !self.replay_required
            || self.safety.revision() <= 5
            || self.pending_validation_count() != 0
            || self.pending_persistence.is_some()
            || self.awaiting_signature
            || self.recovered_validation_pending.is_some()
            || self.recovered_native_finalization_applied.is_some()
            || self.safety.safety_halt().is_some()
            || self.safety.pending_sign().is_some()
            || self.safety.pending_finalize().is_some()
            || self.safety.pending_finalization().is_some()
            || self.safety.pending_tc_high_qc_sync().is_some()
            || self.safety.pending_standalone_qc_sync().is_some()
            || !self.safety.finalization_queue().is_empty()
            || !self.safety.payload_validation_obligations().is_empty()
            || self.safety.finalized() != self.safety.application_applied()
        {
            return Err(CoreError::AnchoredOrdinaryRehydrateRejected(
                "rehydration requires one stable replay-fenced terminal cut",
            ));
        }

        let entry_count = u64::try_from(entries.len()).map_err(|_| {
            CoreError::AnchoredOrdinaryRehydrateRejected(
                "ordinary replay entry count does not fit u64",
            )
        })?;
        let minimum_archive_entries =
            entry_count
                .checked_mul(2)
                .ok_or(CoreError::ArithmeticOverflow(
                    "ordinary replay minimum archive entry count",
                ))?;
        let required_tree_nodes =
            entries
                .len()
                .checked_add(2)
                .ok_or(CoreError::ArithmeticOverflow(
                    "ordinary replay volatile tree node count",
                ))?;
        if entry_count != plan.expected_link_count
            || entries.is_empty()
            || plan.archive_sequence < minimum_archive_entries
            || required_tree_nodes > self.config.max_blocks()
            || plan
                .initial_safety_revision
                .checked_add(
                    entry_count
                        .checked_mul(2)
                        .ok_or(CoreError::ArithmeticOverflow(
                            "ordinary replay safety revision span",
                        ))?,
                )
                != Some(self.safety.revision())
        {
            return Err(CoreError::AnchoredOrdinaryRehydrateRejected(
                "archive/session inventory differs from the terminal Safety cut",
            ));
        }

        let anchor = self
            .safety
            .state_sync_anchor()
            .ok_or(CoreError::StateSyncAnchorRecoveryNotRequired)?;
        let proof = anchor.proof();
        let h1 = proof.finalized_block().header();
        let h2 = proof.child().header();
        let h3 = proof.grandchild().header();
        let mut previous_block_id = h3.id();
        let mut previous_height = h3.height().get();
        let mut previous_timestamp_ms = h3.timestamp_ms();
        let mut previous_certificate = QcRef::from(proof.grandchild().certifying_qc());
        let mut previous_checkpoint_checksum = plan.initial_checkpoint_checksum;
        let mut previous_checkpoint_generation = plan.initial_checkpoint_generation;
        let mut previous_progress_checksum = plan.initial_progress_checksum;
        let mut previous_link_row_revision = 0_u64;
        let mut source_ids = Vec::with_capacity(entries.len());
        let mut target_ids = Vec::with_capacity(entries.len());

        for (index, entry) in entries.iter().enumerate() {
            let cursor = u64::try_from(index).map_err(|_| {
                CoreError::AnchoredOrdinaryRehydrateRejected(
                    "ordinary replay cursor does not fit u64",
                )
            })?;
            let claim = entry.checkpointed_link;
            let expected_height =
                previous_height
                    .checked_add(1)
                    .ok_or(CoreError::ArithmeticOverflow(
                        "ordinary replay successor height",
                    ))?;
            let expected_safety_revision = plan
                .initial_safety_revision
                .checked_add(
                    cursor
                        .checked_add(1)
                        .and_then(|value| value.checked_mul(2))
                        .ok_or(CoreError::ArithmeticOverflow(
                            "ordinary replay cursor safety revision",
                        ))?,
                )
                .ok_or(CoreError::ArithmeticOverflow(
                    "ordinary replay link safety revision",
                ))?;
            let expected_checkpoint_generation =
                previous_checkpoint_generation.checked_add(1).ok_or(
                    CoreError::ArithmeticOverflow("ordinary replay checkpoint generation"),
                )?;
            let proposal = &entry.proposal;
            let header = proposal.block().header();
            let certificate = &entry.certifying_qc;
            let target_id = claim.target_core_validation_id;

            if claim.session_id != plan.session_id
                || claim.cursor != cursor
                || claim.source_store_sequence != plan.canonical_store_sequence
                || claim.safety_revision != expected_safety_revision
                || claim.checkpoint_scope != plan.initial_checkpoint_scope
                || claim.checkpoint_profile_ref != plan.initial_checkpoint_profile_ref
                || claim.checkpoint_predecessor_checksum != previous_checkpoint_checksum
                || claim.checkpoint_generation != expected_checkpoint_generation
                || claim.previous_progress_checksum != previous_progress_checksum
                || claim.checkpoint_checksum == previous_checkpoint_checksum
                || claim.progress_checksum == previous_progress_checksum
                || claim.link_row_revision <= previous_link_row_revision
                || source_ids.contains(&claim.source_validation_store_id)
                || target_ids.contains(&claim.target_validation_store_id)
                || target_id.block_id() != proposal.block().id()
                || target_id.view() != header.view()
                || target_id.generation().checked_add(1) != Some(expected_safety_revision)
                || header.parent_id() != previous_block_id
                || header.height().get() != expected_height
                || header.timestamp_ms() <= previous_timestamp_ms
                || proposal.witness().justify_qc().qc_ref() != previous_certificate
                || certificate.block_id() != proposal.block().id()
                || certificate.height() != header.height()
                || certificate.view() != header.view()
            {
                return Err(CoreError::AnchoredOrdinaryRehydrateRejected(
                    "ordinary replay order, link frontier, or signed coordinates differ",
                ));
            }

            self.verify_proposal(proposal, verifier)?;
            self.verify_ordinary_qc(certificate, verifier)?;

            let completion = self
                .safety
                .payload_validation_completions()
                .iter()
                .find(|completion| {
                    completion.route() == PayloadValidationRouteV0::Synced
                        && completion.id() == target_id
                })
                .ok_or(CoreError::AnchoredOrdinaryRehydrateRejected(
                    "checkpointed link lacks its exact durable Synced completion",
                ))?;
            let DurablePayloadValidationResultV1::Valid {
                commitments,
                artifact_ref,
            } = completion.result()
            else {
                return Err(CoreError::AnchoredOrdinaryRehydrateRejected(
                    "checkpointed link completion is not Valid",
                ));
            };
            let logical_block_size =
                u64::try_from(proposal.block().logical_block_size()).map_err(|_| {
                    CoreError::AnchoredOrdinaryRehydrateRejected(
                        "ordinary replay block size does not fit u64",
                    )
                })?;
            let evidence_count =
                u32::try_from(proposal.block().evidence_objects().len()).map_err(|_| {
                    CoreError::AnchoredOrdinaryRehydrateRejected(
                        "ordinary replay evidence count does not fit u32",
                    )
                })?;
            if completion.first_recorded_revision() != expected_safety_revision
                || commitments.block_id() != proposal.block().id()
                || commitments.logical_block_size() != logical_block_size
                || commitments.evidence_count() != evidence_count
                || artifact_ref.source_artifact_checksum() != claim.source_artifact_checksum
                || artifact_ref.overlay().block_id() != proposal.block().id()
                || artifact_ref.overlay().parent_block_id() != previous_block_id
                || self
                    .safety
                    .payload_terminal_fact(proposal.block().id())
                    .and_then(PayloadTerminalFact::valid_overlay)
                    != Some(artifact_ref.overlay())
            {
                return Err(CoreError::AnchoredOrdinaryRehydrateRejected(
                    "checkpointed link differs from its durable Valid completion or artifact",
                ));
            }

            let protected = self.protected_blocks();
            self.blocks.insert_verified_proposal(proposal, &protected)?;
            self.blocks
                .restore_authenticated_valid_overlay_v0(proposal, artifact_ref.overlay())?;
            self.blocks.validate_certificate_binding(certificate)?;

            source_ids.push(claim.source_validation_store_id);
            target_ids.push(claim.target_validation_store_id);
            previous_block_id = proposal.block().id();
            previous_height = header.height().get();
            previous_timestamp_ms = header.timestamp_ms();
            previous_certificate = QcRef::from(certificate);
            previous_checkpoint_checksum = claim.checkpoint_checksum;
            previous_checkpoint_generation = claim.checkpoint_generation;
            previous_progress_checksum = claim.progress_checksum;
            previous_link_row_revision = claim.link_row_revision;
        }

        if previous_certificate != self.safety.high_qc().qc_ref()
            || previous_progress_checksum != plan.final_progress_checksum
            || previous_checkpoint_generation
                != plan
                    .initial_checkpoint_generation
                    .checked_add(entry_count)
                    .ok_or(CoreError::ArithmeticOverflow(
                        "ordinary replay terminal checkpoint generation",
                    ))?
            || !state_sync_anchor_replay_reference_is_exact_v0(
                self.safety.locked_qc(),
                proof,
                entries,
            )
            || !state_sync_anchor_replay_reference_is_exact_v0(
                self.safety.high_qc(),
                proof,
                entries,
            )
        {
            return Err(CoreError::AnchoredOrdinaryRehydrateRejected(
                "ordinary replay terminal certificate, checkpoint, or Safety anchor differs",
            ));
        }

        let high_qc = self.safety.high_qc().as_ordinary().ok_or(
            CoreError::AnchoredOrdinaryRehydrateRejected(
                "anchored ordinary high QC is not an ordinary certificate",
            ),
        )?;
        if !self
            .blocks
            .detect_three_chain_suffix(
                high_qc,
                self.config.validator_set(),
                self.config.consensus_parameters(),
                self.safety.finalized(),
            )?
            .is_empty()
        {
            return Err(CoreError::AnchoredOrdinaryRehydrateRejected(
                "replayed high QC implies a finalization absent from the terminal cut",
            ));
        }

        let finalized = self.safety.finalized();
        let finalized_header = [h1, h2, h3]
            .into_iter()
            .chain(entries.iter().map(|entry| entry.proposal.block().header()))
            .find(|header| header.id() == finalized.block_id())
            .ok_or(CoreError::AnchoredOrdinaryRehydrateRejected(
                "durable finalized block is absent from the authenticated replay prefix",
            ))?;
        if finalized_header.height() != finalized.height()
            || finalized_header.view() != finalized.view()
            || finalized_header.timestamp_ms() != finalized.timestamp_ms()
        {
            return Err(CoreError::AnchoredOrdinaryRehydrateRejected(
                "durable finalized coordinates differ from the authenticated replay header",
            ));
        }

        self.validate_replayed_safety_anchors_v0()?;
        self.validate_runtime(verifier, false)?;
        if self.safety != original_safety
            || self.pending_validation_count() != 0
            || self.pending_persistence.is_some()
            || self.awaiting_signature
        {
            return Err(CoreError::AnchoredOrdinaryRehydrateRejected(
                "ordinary tree reconstruction changed durable Safety or released an effect",
            ));
        }
        anchored_ordinary_rehydrate_digest_v0(plan, entries)
    }

    fn replay_state_sync_anchor_successor_obligation_v0<V: SignatureVerifier>(
        config: CoreConfig,
        durable: &SafetyState,
        phase: StateSyncAnchorSuccessorPhaseV0,
        child: &SignedProposalV0,
        grandchild: &SignedProposalV0,
        verifier: &V,
    ) -> Result<Self> {
        let (stable_phase, proposal, predecessor_revision) = match phase {
            StateSyncAnchorSuccessorPhaseV0::H2ValidationPending => {
                (StateSyncAnchorSuccessorPhaseV0::H1Bootstrap, child, 0)
            }
            StateSyncAnchorSuccessorPhaseV0::H3ValidationPending => {
                (StateSyncAnchorSuccessorPhaseV0::H2Valid, grandchild, 2)
            }
            StateSyncAnchorSuccessorPhaseV0::H1Bootstrap
            | StateSyncAnchorSuccessorPhaseV0::H2Valid
            | StateSyncAnchorSuccessorPhaseV0::H3Valid => {
                return Err(CoreError::StateSyncAnchorSuccessorRecoveryRejected(
                    "only an in-flight anchored successor has an obligation replay",
                ));
            }
        };
        let predecessor =
            Self::state_sync_anchor_obligation_predecessor_v0(durable, predecessor_revision);
        let anchor = predecessor
            .state_sync_anchor()
            .ok_or(CoreError::StateSyncAnchorRecoveryNotRequired)?;
        if Self::classify_state_sync_anchor_successor_phase_v0(&config, &predecessor, anchor)?
            != stable_phase
        {
            return Err(CoreError::StateSyncAnchorSuccessorRecoveryRejected(
                "the reconstructed obligation predecessor is not canonical",
            ));
        }
        Self::validate_persisted_successor_v0(&config, &predecessor, durable, verifier)?;

        let mut core = Self::empty(config, predecessor, true);
        core.restore_state_sync_anchor_successor_tree_v0(stable_phase, child, grandchild)?;
        let effects =
            core.step_state_sync_anchor_successor_proposal_v0(proposal.clone(), verifier)?;
        if !matches!(
            effects.as_slice(),
            [Effect::PersistSafetyState(request)]
                if request.state() == durable
                    && request.barrier().get() == durable.revision()
                    && request.native_valid_post_ack_action_v0().is_none()
                    && request.native_finalization_applied_v0().is_none()
                    && request.state_sync_anchor_ordinary_promotion_v0().is_none()
        ) || core.safety != *durable
        {
            return Err(CoreError::StateSyncAnchorSuccessorRecoveryRejected(
                "Core replay did not exactly reproduce the durable successor obligation",
            ));
        }
        core.validate_replayed_state_sync_anchor_successor_obligation_v0(phase)?;
        Ok(core)
    }

    fn validate_replayed_state_sync_anchor_successor_obligation_v0(
        &self,
        expected_phase: StateSyncAnchorSuccessorPhaseV0,
    ) -> Result<()> {
        let [obligation] = self.safety.payload_validation_obligations() else {
            return Err(CoreError::StateSyncAnchorSuccessorRecoveryRejected(
                "replayed in-flight Core lacks its unique durable obligation",
            ));
        };
        let pending = self.pending_persistence.as_ref().ok_or(
            CoreError::StateSyncAnchorSuccessorRecoveryRejected(
                "replayed in-flight Core lacks its exact persistence barrier",
            ),
        )?;
        let validation = self.pending_sync_validations.get(&obligation.id()).ok_or(
            CoreError::StateSyncAnchorSuccessorRecoveryRejected(
                "replayed in-flight Core lacks its exact Synced validation slot",
            ),
        )?;
        if self.state_sync_anchor_successor_phase_v0()? != expected_phase
            || !matches!(
                expected_phase,
                StateSyncAnchorSuccessorPhaseV0::H2ValidationPending
                    | StateSyncAnchorSuccessorPhaseV0::H3ValidationPending
            )
            || pending.barrier.get() != self.safety.revision()
            || pending.deferred.as_slice()
                != [DeferredEffect::ValidateSyncedPayload(obligation.id())]
            || &validation.proposal != obligation.proposal()
            || self.pending_sync_validations.len() != 1
            || !self.pending_validations.is_empty()
            || self.awaiting_signature
            || !self.replay_required
            || self.recovered_validation_pending.is_some()
            || self.recovered_native_finalization_applied.is_some()
        {
            return Err(CoreError::StateSyncAnchorSuccessorRecoveryRejected(
                "replayed in-flight Core differs from its exact durable obligation cut",
            ));
        }
        Ok(())
    }

    fn state_sync_anchor_successor_obligation_persistence_v0(
        &self,
    ) -> Result<SafetyStatePersistenceV0> {
        let phase = self.state_sync_anchor_successor_phase_v0()?;
        self.validate_replayed_state_sync_anchor_successor_obligation_v0(phase)?;
        let pending = self
            .pending_persistence
            .as_ref()
            .expect("validated replayed obligation has pending persistence");
        Ok(SafetyStatePersistenceV0::new(
            pending.barrier,
            Box::new(self.safety.clone()),
            None,
            None,
            None,
            Arc::clone(&self.persistence_affinity.0),
            CorePersistenceSealV0::new(),
        ))
    }

    fn state_sync_anchor_obligation_predecessor_v0(
        state: &SafetyState,
        revision: u64,
    ) -> SafetyState {
        // The virgin H1 cut predates every QC observed while replaying the
        // successor bundle.  Do not backdate those durable observations into
        // revision zero; the replayed transition must observe and persist
        // them at the same boundary as the original owner.  Later cuts are
        // allowed to carry the evidence already durable at that cut.
        let durable_observed_qcs = if revision == 0 {
            Vec::new()
        } else {
            state.durable_observed_qcs().to_vec()
        };
        SafetyState::from_persisted_parts_v13(
            state.schema_version(),
            state.chain_id(),
            state.protocol_version(),
            state.epoch(),
            state.validator_set_id(),
            state.genesis_block_id(),
            state.authenticated_genesis_application_parent_v0().copied(),
            state.current_view(),
            state.last_voted_view(),
            state.last_timeout_view(),
            state.high_qc().clone(),
            state.locked_qc().clone(),
            state.finalized(),
            revision,
            durable_observed_qcs,
            state.payload_terminal_facts().to_vec(),
            Vec::new(),
            state.payload_validation_completions().to_vec(),
            state.pending_tc_high_qc_sync().cloned(),
            state.pending_standalone_qc_sync().cloned(),
            state.pending_sign().cloned(),
            state.last_finalization().cloned(),
            state.state_sync_anchor().cloned(),
            state.application_applied(),
            state.finalization_queue().to_vec(),
            state.pending_finalize(),
            state.safety_halt().cloned(),
        )
    }

    fn validate_recovered_payload_validation_fence_v0(&self) -> Result<()> {
        let Some(fence) = self.recovered_validation_pending else {
            return Ok(());
        };
        let [obligation] = self.safety.payload_validation_obligations() else {
            return Err(CoreError::InvalidRecovery(
                "recovered payload-validation fence lacks its unique durable obligation",
            ));
        };
        if obligation.route() != fence.route || obligation.id() != fence.id {
            return Err(CoreError::InvalidRecovery(
                "recovered payload-validation fence differs from its durable obligation",
            ));
        }
        let proposal = match fence.route {
            PayloadValidationRouteV0::Proposal => self.pending_validations.get(&fence.id),
            PayloadValidationRouteV0::Synced => self.pending_sync_validations.get(&fence.id),
        }
        .map(|pending| &pending.proposal);
        if proposal != Some(obligation.proposal()) || self.pending_validation_count() != 1 {
            return Err(CoreError::InvalidRecovery(
                "recovered payload-validation fence lacks its exact volatile route",
            ));
        }
        let block_id = obligation.proposal().block().id();
        if self.blocks.header(block_id) != Some(obligation.proposal().block().header())
            || self.blocks.witness(block_id) != Some(obligation.proposal().witness())
        {
            return Err(CoreError::InvalidRecovery(
                "recovered payload-validation target or witness differs from its obligation",
            ));
        }
        Ok(())
    }

    fn activate_recovered_native_finalization_applied_v0(
        &mut self,
        transition: &NativeFinalizationAppliedRecoveryTransitionV0,
        application_readback: &crate::ApplicationFinalizationApplyReadbackV0,
        affinity: Arc<()>,
    ) -> Result<()> {
        if self.recovered_native_finalization_applied.is_some()
            || self.recovered_validation_pending.is_some()
            || self.pending_validation_count() != 0
            || self.pending_persistence.is_some()
            || self.awaiting_signature
        {
            return Err(CoreError::NativeFinalizationAppliedRecoveryRejected(
                "tag-3 recovery session was not inert at activation",
            ));
        }
        if !Arc::ptr_eq(&self.persistence_affinity.0, &affinity) {
            return Err(CoreError::NativeFinalizationAppliedRecoveryRejected(
                "tag-3 recovery attestation has foreign process affinity",
            ));
        }
        validate_native_finalization_applied_recovery_reconciliation_v0(
            &self.safety,
            transition,
            application_readback,
        )?;
        self.recovered_native_finalization_applied =
            Some(RecoveredNativeFinalizationAppliedFenceV0 {
                transition: transition.clone(),
                application_readback: application_readback.clone(),
                affinity,
            });
        self.validate_recovered_native_finalization_applied_fence_v0()
    }

    fn validate_recovered_native_finalization_applied_fence_v0(&self) -> Result<()> {
        let Some(fence) = &self.recovered_native_finalization_applied else {
            return Ok(());
        };
        if !Arc::ptr_eq(&fence.affinity, &self.persistence_affinity.0) {
            return Err(CoreError::NativeFinalizationAppliedRecoveryRejected(
                "tag-3 recovery fence belongs to a different Core instance",
            ));
        }
        validate_native_finalization_applied_recovery_reconciliation_v0(
            &self.safety,
            &fence.transition,
            &fence.application_readback,
        )
    }

    fn remint_recovered_native_finalization_applied_v0(&mut self) -> Result<Vec<Effect>> {
        let fence = self.recovered_native_finalization_applied.as_ref().ok_or(
            CoreError::NativeFinalizationAppliedRecoveryRejected(
                "tag-3 recovery has no active fence",
            ),
        )?;
        if !Arc::ptr_eq(&fence.affinity, &self.persistence_affinity.0) {
            return Err(CoreError::NativeFinalizationAppliedRecoveryRejected(
                "tag-3 recovery fence belongs to a different Core instance",
            ));
        }
        validate_native_finalization_applied_recovery_reconciliation_v0(
            &self.safety,
            &fence.transition,
            &fence.application_readback,
        )?;
        let effects = self.effects_for_native_finalization_applied_action_v0(
            fence.transition.post_ack_action_v0(),
        )?;
        // This is the crash-after-SafetyStore-commit/before-StorageAck path:
        // no SafetyState transition or persistence barrier is created.  The
        // exact recorded action is released once and the fence is consumed.
        self.recovered_native_finalization_applied = None;
        Ok(effects)
    }

    fn effects_for_native_finalization_applied_action_v0(
        &mut self,
        action: NativeFinalizationAppliedPostAckActionV0,
    ) -> Result<Vec<Effect>> {
        let timer = || Effect::ArmViewTimer {
            epoch: self.safety.epoch(),
            view: self.safety.current_view(),
        };
        let signature = || {
            let intent = self.safety.pending_sign().ok_or(
                CoreError::NativeFinalizationAppliedRecoveryRejected(
                    "recorded signature action has no exact durable sign intent",
                ),
            )?;
            self.signature_effect(intent)
        };
        let finalize = || {
            let proof_id = self.safety.pending_finalize().ok_or(
                CoreError::NativeFinalizationAppliedRecoveryRejected(
                    "recorded finalization action has no exact durable queue front",
                ),
            )?;
            self.finalize_effect(proof_id)
        };
        let tc = || self.tc_high_qc_sync_effect();
        let standalone = || self.standalone_qc_sync_effect();
        let effects = match action {
            NativeFinalizationAppliedPostAckActionV0::None => Vec::new(),
            NativeFinalizationAppliedPostAckActionV0::ArmViewTimer => vec![timer()],
            NativeFinalizationAppliedPostAckActionV0::RequestSignature => vec![signature()?],
            NativeFinalizationAppliedPostAckActionV0::ArmViewTimerThenRequestSignature => {
                vec![timer(), signature()?]
            }
            NativeFinalizationAppliedPostAckActionV0::Finalize => vec![finalize()?],
            NativeFinalizationAppliedPostAckActionV0::ArmViewTimerThenFinalize => {
                vec![timer(), finalize()?]
            }
            NativeFinalizationAppliedPostAckActionV0::RequestTcHighQcSync => vec![tc()?],
            NativeFinalizationAppliedPostAckActionV0::RequestStandaloneQcSync => {
                vec![standalone()?]
            }
            NativeFinalizationAppliedPostAckActionV0::ArmViewTimerThenRequestStandaloneQcSync => {
                vec![timer(), standalone()?]
            }
        };
        if matches!(
            action,
            NativeFinalizationAppliedPostAckActionV0::RequestSignature
                | NativeFinalizationAppliedPostAckActionV0::ArmViewTimerThenRequestSignature
        ) {
            self.awaiting_signature = true;
        }
        Ok(effects)
    }

    #[cfg(test)]
    pub(crate) fn native_finalization_applied_recovery_effects_for_test_v0(
        &mut self,
        action: NativeFinalizationAppliedPostAckActionV0,
    ) -> Result<Vec<Effect>> {
        if !native_finalization_applied_recovery_action_matches_state_v0(action, &self.safety) {
            return Err(CoreError::NativeFinalizationAppliedRecoveryRejected(
                "recorded tag-3 action does not match its durable outbox",
            ));
        }
        self.effects_for_native_finalization_applied_action_v0(action)
    }

    #[cfg(test)]
    pub(crate) const fn retained_validated_proposal_bytes_for_test_v1(&self) -> usize {
        self.blocks.retained_validated_proposal_bytes()
    }

    #[cfg(test)]
    pub(crate) fn set_validated_proposal_retention_budget_for_test_v1(&mut self, maximum: usize) {
        self.blocks.set_retention_budget_for_test(maximum);
    }

    #[cfg(test)]
    pub(crate) fn retained_proposal_allocation_is_shared_for_test_v1(
        &self,
        other: &Self,
        block_id: BlockId,
    ) -> bool {
        match (
            self.blocks.validated_proposal_arc_for_test(block_id),
            other.blocks.validated_proposal_arc_for_test(block_id),
        ) {
            (Some(left), Some(right)) => Arc::ptr_eq(left, right),
            _ => false,
        }
    }

    #[cfg(test)]
    pub(crate) fn retained_proposal_accounting_is_exact_for_test_v1(&self) -> bool {
        self.blocks.retention_accounting_is_exact_for_test()
    }

    /// Applies one deterministic input and returns ordered effects.
    fn preauthentication_context_digest_v0(&self) -> Result<[u8; 32]> {
        let validator_set = self.config.validator_set().try_cev0_bytes()?;
        let parameters_hash = self.config.consensus_parameters().hash();
        let local_validator = self.config.local_validator();
        let trusted_timestamp = self.config.trusted_genesis_timestamp_ms().to_be_bytes();
        let max_blocks = (self.config.max_blocks() as u64).to_be_bytes();
        let max_observed = (self.config.max_observed_messages() as u64).to_be_bytes();
        let max_block_bytes = (self.config.max_block_bytes() as u64).to_be_bytes();
        let max_time_step = self.config.max_block_time_step_ms().to_be_bytes();
        let parent_binding = self
            .config
            .authenticated_genesis_application_parent_v0()
            .map(|parent| parent.binding_ref_v0())
            .unwrap_or([0; 32]);
        let parent_present = [u8::from(
            self.config
                .authenticated_genesis_application_parent_v0()
                .is_some(),
        )];
        Ok(preauthentication_hash_v0(
            PREAUTHENTICATION_CONTEXT_DIGEST_DOMAIN_V0,
            &[
                &validator_set,
                self.config.validator_set().chain_id().as_bytes(),
                self.config.validator_set().genesis_hash().as_bytes(),
                self.config.validator_set().id().as_bytes(),
                self.config
                    .validator_set()
                    .protocol_version()
                    .get()
                    .to_be_bytes()
                    .as_slice(),
                parameters_hash.as_bytes(),
                local_validator.as_bytes(),
                &trusted_timestamp,
                &max_blocks,
                &max_observed,
                &max_block_bytes,
                &max_time_step,
                &parent_present,
                &parent_binding,
            ],
        ))
    }

    fn preauthentication_descriptor_v0(
        &self,
        input: &Input,
    ) -> Result<Option<(PreauthenticatedInputKindV0, [u8; 32])>> {
        let descriptor = match input {
            Input::Proposal(proposal) => {
                let kind = [0_u8];
                let block_id = proposal.block().id();
                let signing_root = proposal.proposal_signing_root();
                let proposer = proposal.proposer();
                (
                    PreauthenticatedInputKindV0::Proposal,
                    preauthentication_hash_v0(
                        PREAUTHENTICATION_INPUT_DIGEST_DOMAIN_V0,
                        &[
                            &kind,
                            block_id.as_bytes(),
                            signing_root.as_bytes(),
                            proposer.as_bytes(),
                            proposal.witness().proposer_signature().as_bytes(),
                        ],
                    ),
                )
            }
            Input::SyncedProposal(proposal) => {
                let kind = [1_u8];
                let block_id = proposal.block().id();
                let signing_root = proposal.proposal_signing_root();
                let proposer = proposal.proposer();
                (
                    PreauthenticatedInputKindV0::SyncedProposal,
                    preauthentication_hash_v0(
                        PREAUTHENTICATION_INPUT_DIGEST_DOMAIN_V0,
                        &[
                            &kind,
                            block_id.as_bytes(),
                            signing_root.as_bytes(),
                            proposer.as_bytes(),
                            proposal.witness().proposer_signature().as_bytes(),
                        ],
                    ),
                )
            }
            Input::Vote(vote) => {
                let kind = [2_u8];
                (
                    PreauthenticatedInputKindV0::Vote,
                    preauthentication_hash_v0(
                        PREAUTHENTICATION_INPUT_DIGEST_DOMAIN_V0,
                        &[
                            &kind,
                            vote.signing_root().as_bytes(),
                            vote.author().as_bytes(),
                            vote.signature().as_bytes(),
                        ],
                    ),
                )
            }
            Input::TimeoutVote(vote) => {
                let kind = [3_u8];
                (
                    PreauthenticatedInputKindV0::TimeoutVote,
                    preauthentication_hash_v0(
                        PREAUTHENTICATION_INPUT_DIGEST_DOMAIN_V0,
                        &[
                            &kind,
                            vote.signing_root().as_bytes(),
                            vote.author().as_bytes(),
                            vote.signature().as_bytes(),
                        ],
                    ),
                )
            }
            Input::QuorumCertificate(certificate) => {
                let kind = [4_u8];
                (
                    PreauthenticatedInputKindV0::QuorumCertificate,
                    preauthentication_hash_v0(
                        PREAUTHENTICATION_INPUT_DIGEST_DOMAIN_V0,
                        &[&kind, certificate.id().as_bytes()],
                    ),
                )
            }
            Input::TimeoutCertificate(certificate) => {
                let kind = [5_u8];
                (
                    PreauthenticatedInputKindV0::TimeoutCertificate,
                    preauthentication_hash_v0(
                        PREAUTHENTICATION_INPUT_DIGEST_DOMAIN_V0,
                        &[&kind, certificate.id().as_bytes()],
                    ),
                )
            }
            Input::Resume
            | Input::LocalTimeout { .. }
            | Input::PayloadValidated { .. }
            | Input::SyncedPayloadValidated { .. }
            | Input::CancelSyncedPayloadValidation { .. }
            | Input::StorageAck { .. }
            | Input::SafetyReplayComplete
            | Input::SignatureReady { .. } => return Ok(None),
        };
        Ok(Some(descriptor))
    }

    pub(crate) fn preauthentication_token_v0(
        &self,
        input: &Input,
    ) -> Result<Option<PreauthenticatedInputV0>> {
        let Some((kind, input_digest)) = self.preauthentication_descriptor_v0(input)? else {
            return Ok(None);
        };
        Ok(Some(PreauthenticatedInputV0 {
            affinity: Arc::clone(&self.preauthentication_affinity.0),
            kind,
            context_digest: self.preauthentication_context_digest_v0()?,
            input_digest,
        }))
    }

    pub(crate) fn validate_preauthentication_token_v0(
        &self,
        input: &Input,
        token: &PreauthenticatedInputV0,
    ) -> Result<()> {
        let Some((kind, input_digest)) = self.preauthentication_descriptor_v0(input)? else {
            return Err(CoreError::InvalidRecovery(
                "preauthentication token supplied for a non-peer input",
            ));
        };
        if !Arc::ptr_eq(&token.affinity, &self.preauthentication_affinity.0)
            || token.kind != kind
            || token.input_digest != input_digest
            || token.context_digest != self.preauthentication_context_digest_v0()?
        {
            return Err(CoreError::InvalidRecovery(
                "preauthentication token does not bind this Core, input, and configuration",
            ));
        }
        Ok(())
    }

    fn apply_authenticated<V: SignatureVerifier>(
        &mut self,
        input: Input,
        verifier: &V,
        token: &PreauthenticatedInputV0,
    ) -> Result<Vec<Effect>> {
        self.validate_preauthentication_token_v0(&input, token)?;
        self.apply(input, verifier)
    }

    fn step_with_preauthenticated_token_v0<V: SignatureVerifier>(
        &mut self,
        input: Input,
        verifier: &V,
        token: &PreauthenticatedInputV0,
    ) -> Result<Vec<Effect>> {
        let cached = PreauthenticationVerifierV0::new(
            verifier,
            token,
            PREAUTHENTICATION_CACHE_MAX_ENTRIES_V0,
        );
        // Keep the original admission-before-clone boundary. A malformed or
        // unauthenticated peer message never causes a transactional snapshot
        // or any bounded-state clone.
        self.preauthenticate_input(&input, &cached)?;
        let previous_safety = self.safety.clone();
        let mut next = self.transactional_clone_v0();
        let effects = next.apply_authenticated(input, &cached, token)?;
        next.validate_runtime(&cached, false)?;
        next.validate_monotonic_transition(&previous_safety)?;
        *self = next;
        Ok(effects)
    }

    pub fn step<V: SignatureVerifier>(
        &mut self,
        input: Input,
        verifier: &V,
    ) -> Result<Vec<Effect>> {
        self.reject_state_sync_anchor_successor_input_v0(&input)?;
        // Reject busy/stale inputs before cloning bounded protocol state.
        // This is both a DoS boundary and a guarantee that a rejected input
        // cannot perturb volatile observation caches.
        self.reject_while_busy(&input)?;
        // Authenticate peer-supplied consensus messages before cloning the
        // transactional state snapshot. Handlers still repeat all structural,
        // ancestry, and state checks after the clone; the private verifier
        // wrapper only suppresses duplicate successful crypto calls.
        let token = self.preauthentication_token_v0(&input)?;
        match token.as_ref() {
            Some(token) => self.step_with_preauthenticated_token_v0(input, verifier, token),
            None => {
                self.preauthenticate_input(&input, verifier)?;
                let previous_safety = self.safety.clone();
                let mut next = self.transactional_clone_v0();
                let effects = next.apply(input, verifier)?;
                next.validate_runtime(verifier, false)?;
                next.validate_monotonic_transition(&previous_safety)?;
                *self = next;
                Ok(effects)
            }
        }
    }

    /// Transactional step used only by the narrow anchored-successor owner.
    /// The generic h1 entry continues to reject every non-Resume input.
    fn step_state_sync_anchor_successor_proposal_v0<V: SignatureVerifier>(
        &mut self,
        proposal: SignedProposalV0,
        verifier: &V,
    ) -> Result<Vec<Effect>> {
        let phase = self.state_sync_anchor_successor_phase_v0()?;
        let anchor = self
            .safety
            .state_sync_anchor()
            .expect("anchored successor replay owns an anchor");
        let expected = match phase {
            StateSyncAnchorSuccessorPhaseV0::H1Bootstrap => anchor.proof().child(),
            StateSyncAnchorSuccessorPhaseV0::H2Valid => anchor.proof().grandchild(),
            StateSyncAnchorSuccessorPhaseV0::H2ValidationPending
            | StateSyncAnchorSuccessorPhaseV0::H3ValidationPending
            | StateSyncAnchorSuccessorPhaseV0::H3Valid => {
                return Err(CoreError::StateSyncAnchorSuccessorRecoveryRejected(
                    "the canonical next successor proposal is not available in this phase",
                ));
            }
        };
        if proposal.block().header() != expected.header()
            || proposal.witness() != expected.witness()
        {
            return Err(CoreError::StateSyncAnchorSuccessorRecoveryRejected(
                "successor proposal differs from the exact finality-proof header or witness",
            ));
        }
        self.step_state_sync_anchor_successor_input_v0(
            Input::SyncedProposal(Box::new(proposal)),
            verifier,
        )
    }

    fn step_state_sync_anchor_successor_input_v0<V: SignatureVerifier>(
        &mut self,
        input: Input,
        verifier: &V,
    ) -> Result<Vec<Effect>> {
        let before_phase = self.state_sync_anchor_successor_phase_v0()?;
        let step = match &input {
            Input::SyncedProposal(_) => StateSyncAnchorSuccessorStepV0::Proposal,
            Input::StorageAck { .. } => StateSyncAnchorSuccessorStepV0::StorageAck,
            _ => {
                return Err(CoreError::StateSyncAnchorSuccessorRecoveryRejected(
                    "input is not permitted by the anchored-successor replay owner",
                ));
            }
        };
        match (&input, before_phase) {
            (Input::SyncedProposal(_), StateSyncAnchorSuccessorPhaseV0::H1Bootstrap) => {}
            (Input::SyncedProposal(_), StateSyncAnchorSuccessorPhaseV0::H2Valid) => {}
            (Input::StorageAck { barrier }, _)
                if self
                    .pending_persistence
                    .as_ref()
                    .is_some_and(|pending| pending.barrier == *barrier) => {}
            _ => {
                return Err(CoreError::StateSyncAnchorSuccessorRecoveryRejected(
                    "input is not permitted in the current anchored-successor phase",
                ));
            }
        }
        self.reject_while_busy(&input)?;
        self.preauthenticate_input(&input, verifier)?;
        let previous_safety = self.safety.clone();
        let mut next = self.transactional_clone_v0();
        let effects = next.apply(input, verifier)?;
        next.validate_runtime(verifier, false)?;
        next.validate_monotonic_transition(&previous_safety)?;
        next.validate_state_sync_anchor_successor_effects_v0(before_phase, step, &effects)?;
        *self = next;
        Ok(effects)
    }

    /// Admits one opaque application-sealed Valid proof only when both its
    /// installed store binding and retained request permit belong to this
    /// exact live Core and pending slot.
    ///
    /// The callback accepts neither a raw permit nor caller-selected
    /// commitments/artifact references. Rejected calls borrow (rather than
    /// consume) the proof so the same application owner can retry against the
    /// issuing Core.
    ///
    /// ```compile_fail
    /// use trnm_consensus_core::{Core, CoreIssuedValidPermitV0};
    /// use trnm_consensus_types::SignatureVerifier;
    ///
    /// fn permit_alone_cannot_call_core<V: SignatureVerifier>(
    ///     core: &mut Core,
    ///     permit: &CoreIssuedValidPermitV0,
    ///     verifier: &V,
    /// ) {
    ///     let _ = core.step_application_sealed_valid_v0(permit, verifier);
    /// }
    /// ```
    pub fn step_application_sealed_valid_v0<V: SignatureVerifier>(
        &mut self,
        proof: &ApplicationSealedValidV0,
        verifier: &V,
    ) -> Result<Vec<Effect>> {
        self.reject_state_sync_anchor_successor_progression_v0()?;
        let input = self.application_sealed_valid_input_v0(proof)?;
        self.step(input, verifier)
    }

    /// Atomically accepts one application-sealed Valid callback and returns
    /// the sole opaque Core authority for the durable-delivery (`D`) stage.
    ///
    /// The public `Vec<Effect>` surface is deliberately closed here. The
    /// transition is first executed on a private transactional clone, then
    /// checked for one exact `PersistSafetyState` effect, an exact revision
    /// increment, removal of the matching obligation, one matching durable
    /// Valid completion/terminal fact, and a Core-owned post-ack action. Only
    /// after every check passes is the live Core replaced. The returned
    /// non-cloneable carrier retains the affined persistence request; it is
    /// not a Safety confirmation and cannot emit `StorageAck`, a signature
    /// request, a signature, or a broadcast.
    pub fn step_application_sealed_valid_to_delivery_v0<V: SignatureVerifier>(
        &mut self,
        proof: &ApplicationSealedValidV0,
        verifier: &V,
    ) -> Result<CoreAcceptedApplicationValidDV0> {
        let before_revision = self.safety.revision();
        let route = proof.route();
        let validation_id = proof.id();
        let commitments = proof.commitments();
        let artifact_ref = proof.artifact_ref();

        let mut next = self.transactional_clone_v0();
        let effects = next.step_application_sealed_valid_v0(proof, verifier)?;
        let persistence = match effects.as_slice() {
            [Effect::PersistSafetyState(_)] => match effects.into_iter().next() {
                Some(Effect::PersistSafetyState(value)) => value,
                _ => unreachable!("the exact effect shape was checked"),
            },
            _ => {
                return Err(CoreError::ApplicationValidDeliveryInvariant(
                    "the Valid callback did not emit exactly one Safety persistence request",
                ));
            }
        };
        let state = persistence.state();
        if state != &next.safety {
            return Err(CoreError::ApplicationValidDeliveryInvariant(
                "the persistence request differs from the transactional Core state",
            ));
        }
        let expected_revision =
            before_revision
                .checked_add(1)
                .ok_or(CoreError::ApplicationValidDeliveryInvariant(
                    "the Safety revision overflowed",
                ))?;
        if state.revision() != expected_revision || persistence.barrier().get() != expected_revision
        {
            return Err(CoreError::ApplicationValidDeliveryInvariant(
                "the callback did not advance exactly one persistence revision",
            ));
        }
        if state
            .payload_validation_obligations()
            .iter()
            .any(|obligation| obligation.id() == validation_id)
        {
            return Err(CoreError::ApplicationValidDeliveryInvariant(
                "the accepted validation obligation remains durable",
            ));
        }

        let mut matching = state
            .payload_validation_completions()
            .iter()
            .filter(|completion| completion.id() == validation_id);
        let completion = matching
            .next()
            .ok_or(CoreError::ApplicationValidDeliveryInvariant(
                "the accepted validation completion is missing",
            ))?;
        let completion_matches = match completion.result() {
            DurablePayloadValidationResultV1::Valid {
                commitments: durable,
                artifact_ref: durable_artifact,
            } => {
                durable.block_id() == commitments.block_id()
                    && durable.logical_block_size() == commitments.logical_block_size()
                    && durable.transaction_count() == commitments.transaction_count()
                    && durable.evidence_count() == commitments.evidence_count()
                    && durable_artifact == artifact_ref
            }
            DurablePayloadValidationResultV1::Unavailable
            | DurablePayloadValidationResultV1::DeterministicallyInvalid => false,
        };
        if matching.next().is_some()
            || completion.route() != route
            || completion.first_recorded_revision() != expected_revision
            || !completion_matches
        {
            return Err(CoreError::ApplicationValidDeliveryInvariant(
                "the durable completion differs from the sealed Valid proof",
            ));
        }
        let terminal = state
            .payload_terminal_fact(validation_id.block_id())
            .ok_or(CoreError::ApplicationValidDeliveryInvariant(
                "the accepted Valid terminal fact is missing",
            ))?;
        if terminal.result() != PayloadTerminalResult::Valid
            || terminal.valid_overlay() != Some(artifact_ref.overlay())
            || terminal.first_recorded_revision() > expected_revision
        {
            return Err(CoreError::ApplicationValidDeliveryInvariant(
                "the terminal fact differs from the sealed Valid proof",
            ));
        }
        let valid_result_checksum = native_valid_result_checksum_v0(completion.result()).ok_or(
            CoreError::ApplicationValidDeliveryInvariant(
                "the accepted Valid result has no canonical checksum",
            ),
        )?;
        let post_ack_action = persistence.native_valid_post_ack_action_v0().ok_or(
            CoreError::ApplicationValidDeliveryInvariant(
                "the persistence request lacks its Core-owned post-ack action",
            ),
        )?;
        if persistence.native_finalization_applied_v0().is_some() {
            return Err(CoreError::ApplicationValidDeliveryInvariant(
                "the Valid callback unexpectedly carries a finalization-applied manifest",
            ));
        }
        let delivery_digest = core_accepted_application_valid_delivery_digest_v0(
            state,
            route,
            validation_id,
            valid_result_checksum,
            post_ack_action,
        );
        if delivery_digest == [0; 32] {
            return Err(CoreError::ApplicationValidDeliveryInvariant(
                "the Core delivery digest is zero",
            ));
        }
        *self = next;
        Ok(CoreAcceptedApplicationValidDV0::new(
            route,
            validation_id,
            persistence,
            expected_revision,
            valid_result_checksum,
            delivery_digest,
        ))
    }

    fn step_state_sync_anchor_successor_sealed_valid_to_delivery_v0<V: SignatureVerifier>(
        &mut self,
        proof: &ApplicationSealedValidV0,
        verifier: &V,
    ) -> Result<CoreAcceptedApplicationValidDV0> {
        let before_revision = self.safety.revision();
        let route = proof.route();
        let validation_id = proof.id();
        let commitments = proof.commitments();
        let artifact_ref = proof.artifact_ref();

        let mut next = self.transactional_clone_v0();
        let effects = next.step_state_sync_anchor_successor_sealed_valid_v0(proof, verifier)?;
        let persistence = match effects.as_slice() {
            [Effect::PersistSafetyState(_)] => match effects.into_iter().next() {
                Some(Effect::PersistSafetyState(value)) => value,
                _ => unreachable!("the exact effect shape was checked"),
            },
            _ => {
                return Err(CoreError::ApplicationValidDeliveryInvariant(
                    "the anchored Valid callback did not emit exactly one Safety persistence request",
                ));
            }
        };
        let state = persistence.state();
        if state != &next.safety {
            return Err(CoreError::ApplicationValidDeliveryInvariant(
                "the anchored persistence request differs from the transactional Core state",
            ));
        }
        let expected_revision =
            before_revision
                .checked_add(1)
                .ok_or(CoreError::ApplicationValidDeliveryInvariant(
                    "the anchored Safety revision overflowed",
                ))?;
        if state.revision() != expected_revision || persistence.barrier().get() != expected_revision
        {
            return Err(CoreError::ApplicationValidDeliveryInvariant(
                "the anchored callback did not advance exactly one persistence revision",
            ));
        }
        if state
            .payload_validation_obligations()
            .iter()
            .any(|obligation| obligation.id() == validation_id)
        {
            return Err(CoreError::ApplicationValidDeliveryInvariant(
                "the accepted anchored validation obligation remains durable",
            ));
        }

        let mut matching = state
            .payload_validation_completions()
            .iter()
            .filter(|completion| completion.id() == validation_id);
        let completion = matching
            .next()
            .ok_or(CoreError::ApplicationValidDeliveryInvariant(
                "the accepted anchored validation completion is missing",
            ))?;
        let completion_matches = match completion.result() {
            DurablePayloadValidationResultV1::Valid {
                commitments: durable,
                artifact_ref: durable_artifact,
            } => {
                durable.block_id() == commitments.block_id()
                    && durable.logical_block_size() == commitments.logical_block_size()
                    && durable.transaction_count() == commitments.transaction_count()
                    && durable.evidence_count() == commitments.evidence_count()
                    && durable_artifact == artifact_ref
            }
            DurablePayloadValidationResultV1::Unavailable
            | DurablePayloadValidationResultV1::DeterministicallyInvalid => false,
        };
        if matching.next().is_some()
            || completion.route() != route
            || route != PayloadValidationRouteV0::Synced
            || completion.first_recorded_revision() != expected_revision
            || !completion_matches
        {
            return Err(CoreError::ApplicationValidDeliveryInvariant(
                "the durable anchored completion differs from the sealed Valid proof",
            ));
        }
        let terminal = state
            .payload_terminal_fact(validation_id.block_id())
            .ok_or(CoreError::ApplicationValidDeliveryInvariant(
                "the accepted anchored Valid terminal fact is missing",
            ))?;
        if terminal.result() != PayloadTerminalResult::Valid
            || terminal.valid_overlay() != Some(artifact_ref.overlay())
            || terminal.first_recorded_revision() > expected_revision
        {
            return Err(CoreError::ApplicationValidDeliveryInvariant(
                "the anchored terminal fact differs from the sealed Valid proof",
            ));
        }
        let valid_result_checksum = native_valid_result_checksum_v0(completion.result()).ok_or(
            CoreError::ApplicationValidDeliveryInvariant(
                "the accepted anchored Valid result has no canonical checksum",
            ),
        )?;
        let post_ack_action = persistence.native_valid_post_ack_action_v0().ok_or(
            CoreError::ApplicationValidDeliveryInvariant(
                "the anchored persistence request lacks its Core-owned post-ack action",
            ),
        )?;
        if post_ack_action != NativeValidPostAckActionV0::None
            || persistence.native_finalization_applied_v0().is_some()
            || persistence
                .state_sync_anchor_ordinary_promotion_v0()
                .is_some()
        {
            return Err(CoreError::ApplicationValidDeliveryInvariant(
                "the anchored Valid callback carries a forbidden post-ack manifest",
            ));
        }
        let delivery_digest = core_accepted_application_valid_delivery_digest_v0(
            state,
            route,
            validation_id,
            valid_result_checksum,
            post_ack_action,
        );
        if delivery_digest == [0; 32] {
            return Err(CoreError::ApplicationValidDeliveryInvariant(
                "the anchored Core delivery digest is zero",
            ));
        }
        *self = next;
        Ok(CoreAcceptedApplicationValidDV0::new(
            route,
            validation_id,
            persistence,
            expected_revision,
            valid_result_checksum,
            delivery_digest,
        ))
    }

    fn application_sealed_valid_input_v0(&self, proof: &ApplicationSealedValidV0) -> Result<Input> {
        if !proof.matches_application_seal_affinity_v0(&self.application_seal_affinity.affinity) {
            return Err(CoreError::ApplicationSealedValidMismatch(
                proof.id().block_id(),
            ));
        }
        let pending = match proof.route() {
            PayloadValidationRouteV0::Proposal => self.pending_validations.get(&proof.id()),
            PayloadValidationRouteV0::Synced => self.pending_sync_validations.get(&proof.id()),
        }
        .ok_or(CoreError::UnknownValidation(proof.id().block_id()))?;
        if !proof.matches_valid_affinity_v0(&pending.affinity.0) {
            return Err(CoreError::ValidPayloadPermitMismatch(proof.id().block_id()));
        }
        let result =
            PayloadValidationResult::authorized_valid_v0(proof.commitments(), proof.artifact_ref());
        let input = match proof.route() {
            PayloadValidationRouteV0::Proposal => Input::PayloadValidated {
                id: proof.id(),
                result,
            },
            PayloadValidationRouteV0::Synced => Input::SyncedPayloadValidated {
                id: proof.id(),
                result,
            },
        };
        Ok(input)
    }

    fn step_state_sync_anchor_successor_sealed_valid_v0<V: SignatureVerifier>(
        &mut self,
        proof: &ApplicationSealedValidV0,
        verifier: &V,
    ) -> Result<Vec<Effect>> {
        let before_phase = self.state_sync_anchor_successor_phase_v0()?;
        if !matches!(
            before_phase,
            StateSyncAnchorSuccessorPhaseV0::H2ValidationPending
                | StateSyncAnchorSuccessorPhaseV0::H3ValidationPending
        ) {
            return Err(CoreError::StateSyncAnchorSuccessorRecoveryRejected(
                "Valid callback is not permitted in the current anchored-successor phase",
            ));
        }
        let input = self.application_sealed_valid_input_v0(proof)?;
        let previous_safety = self.safety.clone();
        let mut next = self.transactional_clone_v0();
        let effects = next.apply(input, verifier)?;
        next.validate_runtime(verifier, false)?;
        next.validate_monotonic_transition(&previous_safety)?;
        next.validate_state_sync_anchor_successor_effects_v0(
            before_phase,
            StateSyncAnchorSuccessorStepV0::Valid,
            &effects,
        )?;
        *self = next;
        Ok(effects)
    }

    fn step_state_sync_anchor_ordinary_promotion_v0<V: SignatureVerifier>(
        &mut self,
        verifier: &V,
    ) -> Result<Vec<Effect>> {
        if self.state_sync_anchor_successor_phase_v0()? != StateSyncAnchorSuccessorPhaseV0::H3Valid
            || self.pending_persistence.is_some()
        {
            return Err(CoreError::StateSyncAnchorSuccessorRecoveryRejected(
                "anchored-ordinary promotion requires stable H3Valid revision four",
            ));
        }
        let previous = self.safety.clone();
        let mut next = self.transactional_clone_v0();
        let anchor = next
            .safety
            .state_sync_anchor()
            .ok_or(CoreError::StateSyncAnchorRecoveryNotRequired)?;
        let manifest = StateSyncAnchorOrdinaryPromotionPersistenceV0::new(
            anchor.proof_id(),
            previous
                .revision()
                .checked_add(1)
                .ok_or(CoreError::ArithmeticOverflow("safety-state revision"))?,
        );
        let mut effects = next.persist(Vec::new())?;
        match effects.as_mut_slice() {
            [Effect::PersistSafetyState(request)]
                if request.state() == &next.safety
                    && request.barrier().get() == 5
                    && request.native_valid_post_ack_action_v0().is_none()
                    && request.native_finalization_applied_v0().is_none()
                    && request.state_sync_anchor_ordinary_promotion_v0().is_none() =>
            {
                request.bind_state_sync_anchor_ordinary_promotion_v0(manifest);
            }
            _ => {
                return Err(CoreError::StateSyncAnchorSuccessorRecoveryRejected(
                    "anchored-ordinary promotion did not produce one exact revision-five persistence request",
                ));
            }
        }
        next.validate_runtime(verifier, false)?;
        next.validate_monotonic_transition(&previous)?;
        if !matches!(
            effects.as_slice(),
            [Effect::PersistSafetyState(request)]
                if request.state() == &next.safety
                    && request.state_sync_anchor_ordinary_promotion_v0() == Some(manifest)
        ) {
            return Err(CoreError::StateSyncAnchorSuccessorRecoveryRejected(
                "anchored-ordinary promotion manifest was not bound to its exact state",
            ));
        }
        *self = next;
        Ok(effects)
    }

    fn acknowledge_state_sync_anchor_ordinary_promotion_v0<V: SignatureVerifier>(
        &mut self,
        barrier: BarrierId,
        verifier: &V,
    ) -> Result<Vec<Effect>> {
        let anchor = self
            .safety
            .state_sync_anchor()
            .ok_or(CoreError::StateSyncAnchorRecoveryNotRequired)?;
        Self::validate_state_sync_anchor_ordinary_state_v0(&self.config, &self.safety, anchor)?;
        if self.safety.revision() != 5
            || !Self::is_exact_state_sync_anchor_ordinary_promotion_cut_v0(
                &self.config,
                &self.safety,
                anchor,
            )?
            || self
                .pending_persistence
                .as_ref()
                .is_none_or(|pending| pending.barrier != barrier || !pending.deferred.is_empty())
        {
            return Err(CoreError::StateSyncAnchorSuccessorRecoveryRejected(
                "ordinary Core cannot be released before the exact promotion barrier acknowledgement",
            ));
        }
        let previous = self.safety.clone();
        let mut next = self.transactional_clone_v0();
        if !next.handle_storage_ack(barrier)?.is_empty() {
            return Err(CoreError::StateSyncAnchorSuccessorRecoveryRejected(
                "promotion acknowledgement exposed a deferred side effect",
            ));
        }
        let effects = next.handle_replay_complete(verifier)?;
        next.validate_runtime(verifier, false)?;
        next.validate_monotonic_transition(&previous)?;
        if !matches!(
            effects.as_slice(),
            [Effect::ArmViewTimer { epoch, view }]
                if *epoch == next.safety.epoch() && *view == next.safety.current_view()
        ) || next.replay_required
            || next.pending_persistence.is_some()
        {
            return Err(CoreError::StateSyncAnchorSuccessorRecoveryRejected(
                "promotion acknowledgement did not release one exact ordinary timer",
            ));
        }
        *self = next;
        Ok(effects)
    }

    /// Applies one opaque ApplicationStore exact-readback finalization receipt.
    ///
    /// Unlike ordinary [`Input`], the receipt cannot originate from network or
    /// caller-selected comparison fields.  Both process affinities and the
    /// complete durable queue-front carrier must match this exact Core.  A
    /// rejected call returns the unchanged sole receipt owner for retry; a
    /// successful call consumes it and rotates the queue-front affinity before
    /// the next permit can be issued.
    ///
    /// ```compile_fail
    /// use trnm_consensus_core::{Core, DurableFinalizationV0};
    /// use trnm_consensus_types::SignatureVerifier;
    ///
    /// fn inert_carrier_cannot_acknowledge<V: SignatureVerifier>(
    ///     core: &mut Core,
    ///     carrier: DurableFinalizationV0,
    ///     verifier: &V,
    /// ) {
    ///     let _ = core.step_application_finalization_receipt_v0(carrier, verifier);
    /// }
    /// ```
    pub fn step_application_finalization_receipt_v0<V: SignatureVerifier>(
        &mut self,
        receipt: ApplicationFinalizationReceiptV0,
        verifier: &V,
    ) -> core::result::Result<Vec<Effect>, ApplicationFinalizationReceiptRejectionV0> {
        let result = self.try_step_application_finalization_receipt_v0(&receipt, verifier);
        match result {
            Ok(effects) => Ok(effects),
            Err(error) => Err(ApplicationFinalizationReceiptRejectionV0::new(
                error,
                Box::new(receipt),
            )),
        }
    }

    fn try_step_application_finalization_receipt_v0<V: SignatureVerifier>(
        &mut self,
        receipt: &ApplicationFinalizationReceiptV0,
        verifier: &V,
    ) -> Result<Vec<Effect>> {
        self.reject_state_sync_anchor_successor_progression_v0()?;
        self.reject_finalization_receipt_while_busy_v0()?;
        let readback = receipt.application_store_readback_v0();
        let pending = self.safety.pending_finalization();
        let exact_source_count = self
            .safety
            .payload_validation_completions()
            .iter()
            .filter(|completion| {
                completion.route() == readback.source_route()
                    && completion.id() == readback.source_validation_id()
                    && completion.result().artifact_ref().is_some_and(|artifact| {
                        artifact.source_artifact_checksum() == readback.source_artifact_checksum()
                            && artifact.overlay() == receipt.finalization().target_overlay_ref()
                    })
            })
            .count();
        if !receipt.matches_application_apply_affinity_v0(
            &self
                .application_finalization_affinity
                .application_apply_affinity,
        ) || !receipt
            .matches_front_affinity_v0(&self.application_finalization_affinity.front_affinity)
            || pending != Some(receipt.finalization())
            || exact_source_count != 1
            || pending.is_none_or(|finalization| {
                let target = finalization.proof().finalized_block().header();
                finalization.authenticated_parent() != self.safety.application_applied()
                    || crate::native_finalization_applied_checksum_v0(finalization)
                        != Ok(readback.finalization_checksum())
                    || readback.source_validation_id().block_id() != target.id()
                    || readback.source_validation_id().view() != target.view()
                    || readback.ordinal() != target.height().get()
            })
        {
            return Err(CoreError::ApplicationFinalizationReceiptMismatch);
        }

        let previous_safety = self.safety.clone();
        let mut next = self.transactional_clone_v0();
        let effects = next.handle_finalization_applied(receipt, verifier)?;
        next.validate_runtime(verifier, false)?;
        next.validate_monotonic_transition(&previous_safety)?;
        next.application_finalization_affinity.rotate_front();
        *self = next;
        Ok(effects)
    }

    fn reject_finalization_receipt_while_busy_v0(&self) -> Result<()> {
        if self.recovered_native_finalization_applied.is_some() {
            return Err(CoreError::Busy(
                "the exact recovered finalization-applied action must be reminted before another application receipt",
            ));
        }
        if self.recovered_validation_pending.is_some() {
            return Err(CoreError::Busy(
                "a recovered deterministic-invalid validation must be durably consumed before consensus resumes",
            ));
        }
        if self.pending_persistence.is_some() {
            return Err(CoreError::Busy(
                "waiting for durable safety-state acknowledgement",
            ));
        }
        if self.safety.safety_halt().is_some() {
            return Err(CoreError::Busy(
                "consensus is safety-halted pending operator recovery",
            ));
        }
        if self.awaiting_signature {
            return Err(CoreError::Busy("waiting for the requested signature"));
        }
        if self.safety.pending_sign().is_some() {
            return Err(CoreError::Busy("persisted signing intent must be resumed"));
        }
        Ok(())
    }

    fn reject_state_sync_anchor_successor_progression_v0(&self) -> Result<()> {
        if self.safety.state_sync_anchor().is_some() && self.safety.revision() < 5 {
            return Err(CoreError::StateSyncAnchorSuccessorRecoveryUnavailable);
        }
        Ok(())
    }

    fn reject_state_sync_anchor_successor_input_v0(&self, input: &Input) -> Result<()> {
        if self.safety.state_sync_anchor().is_some()
            && self.safety.revision() < 5
            && !matches!(input, Input::Resume)
        {
            return Err(CoreError::StateSyncAnchorSuccessorRecoveryUnavailable);
        }
        Ok(())
    }

    fn empty(config: CoreConfig, safety: SafetyState, replay_required: bool) -> Self {
        let max_blocks = config.max_blocks();
        // Every validation request is released only after a safety-state
        // persistence barrier. Seeding the volatile counter from the durable
        // revision keeps delayed pre-restart validation results from matching
        // a newly issued request.
        let next_validation_generation = safety
            .payload_validation_obligations()
            .iter()
            .map(DurablePayloadValidationObligationV0::id)
            .chain(
                safety
                    .payload_validation_completions()
                    .iter()
                    .map(DurablePayloadValidationCompletionV0::id),
            )
            .map(|id| id.generation())
            .fold(safety.revision(), core::cmp::max);
        let mut observed_qcs: BTreeMap<View, QuorumCertificate> = BTreeMap::new();
        for certificate in safety.durable_observed_qcs() {
            match observed_qcs.get(&certificate.view()) {
                Some(existing)
                    if existing.block_id() == certificate.block_id()
                        && existing.id() >= certificate.id() => {}
                _ => {
                    observed_qcs.insert(certificate.view(), certificate.clone());
                }
            }
        }
        Self {
            config,
            safety,
            blocks: BlockTree::new(
                max_blocks,
                CORE_MAX_RETAINED_VALIDATED_PROPOSAL_RESOURCE_BYTES_V1,
            ),
            pending_validations: BTreeMap::new(),
            pending_sync_validations: BTreeMap::new(),
            pending_persistence: None,
            awaiting_signature: false,
            finalization_blocked_vote: None,
            observed_proposals: BTreeMap::new(),
            observed_votes: BTreeMap::new(),
            observed_timeouts: BTreeMap::new(),
            observed_qcs,
            next_validation_generation,
            replay_required,
            recovered_validation_pending: None,
            recovered_native_finalization_applied: None,
            persistence_affinity: CorePersistenceAffinityV0::new(),
            preauthentication_affinity: CorePreauthenticationAffinityV0::new(),
            application_seal_affinity: CoreApplicationSealAffinityV0::new(),
            application_finalization_affinity: CoreApplicationFinalizationAffinityV0::new(),
        }
    }

    fn apply<V: SignatureVerifier>(&mut self, input: Input, verifier: &V) -> Result<Vec<Effect>> {
        let mut effects = match input {
            Input::Resume => self.resume(verifier),
            Input::Proposal(proposal) => self.handle_proposal(*proposal, verifier),
            Input::SyncedProposal(proposal) => self.handle_synced_proposal(*proposal, verifier),
            Input::Vote(vote) => self.handle_vote(vote, verifier),
            Input::TimeoutVote(vote) => self.handle_timeout_vote(vote, verifier),
            Input::QuorumCertificate(certificate) => self.handle_qc(certificate, verifier),
            Input::TimeoutCertificate(certificate) => self.handle_tc(certificate, verifier),
            Input::LocalTimeout { epoch, view } => self.handle_local_timeout(epoch, view, verifier),
            Input::PayloadValidated { id, result } => {
                self.handle_payload_validated(id, result, verifier)
            }
            Input::SyncedPayloadValidated { id, result } => {
                self.handle_synced_payload_validated(id, result, verifier)
            }
            Input::CancelSyncedPayloadValidation { id } => {
                self.handle_cancel_synced_payload_validation(id)
            }
            Input::StorageAck { barrier } => self.handle_storage_ack(barrier),
            Input::SafetyReplayComplete => self.handle_replay_complete(verifier),
            Input::SignatureReady { id, signature } => {
                self.handle_signature(id, signature, verifier)
            }
        }?;
        // Every newly authenticated QC observation must cross a SafetyState
        // persistence barrier before any caller-visible side effect.  Paths
        // which already persisted use `persist`, which snapshots this cache;
        // no-op/stale paths are forced through one empty durable revision here.
        if self.observed_qcs_needs_persistence_v0()? {
            let mut persistence = self.persist(Vec::new())?;
            persistence.append(&mut effects);
            effects = persistence;
        }
        Ok(effects)
    }

    fn preauthenticate_input<V: SignatureVerifier>(
        &self,
        input: &Input,
        verifier: &V,
    ) -> Result<()> {
        match input {
            Input::Proposal(proposal) => self
                .verify_proposal_or_missing_parent(proposal, verifier)
                .map(|_| ()),
            Input::SyncedProposal(proposal) => self.verify_proposal(proposal, verifier).map(|_| ()),
            Input::Vote(vote) => {
                vote.verify(self.config.validator_set(), verifier)?;
                self.require_epoch(vote.epoch())?;
                self.require_pre_checkpoint_height(vote.height())
            }
            Input::TimeoutVote(vote) => {
                vote.verify(self.config.validator_set(), verifier)?;
                self.require_epoch(vote.epoch())?;
                self.require_pre_checkpoint_height(vote.high_qc().height())
            }
            Input::QuorumCertificate(certificate) => self.verify_ordinary_qc(certificate, verifier),
            Input::TimeoutCertificate(certificate) => {
                self.require_epoch(certificate.epoch())?;
                for referenced in certificate.referenced_qcs() {
                    self.reject_epoch_anchor(referenced)?;
                }
                certificate.verify(self.config.validator_set(), None, verifier)?;
                Ok(())
            }
            Input::Resume
            | Input::LocalTimeout { .. }
            | Input::PayloadValidated { .. }
            | Input::SyncedPayloadValidated { .. }
            | Input::CancelSyncedPayloadValidation { .. }
            | Input::StorageAck { .. }
            | Input::SafetyReplayComplete
            | Input::SignatureReady { .. } => Ok(()),
        }
    }

    fn reject_while_busy(&self, input: &Input) -> Result<()> {
        if let Some(fence) = &self.recovered_native_finalization_applied {
            if !Arc::ptr_eq(&fence.affinity, &self.persistence_affinity.0) {
                return Err(CoreError::NativeFinalizationAppliedRecoveryRejected(
                    "the exact tag-3 recovery fence belongs to a different Core instance",
                ));
            }
            if !matches!(input, Input::Resume) {
                return Err(CoreError::Busy(
                    "only Resume may consume the exact recovered finalization-applied action",
                ));
            }
        }
        if let Some(fence) = self.recovered_validation_pending {
            let exact_terminal_callback = match (fence.route, input) {
                (PayloadValidationRouteV0::Proposal, Input::PayloadValidated { id, result })
                | (
                    PayloadValidationRouteV0::Synced,
                    Input::SyncedPayloadValidated { id, result },
                ) => *id == fence.id && result.is_deterministically_invalid(),
                _ => false,
            };
            if !matches!(input, Input::Resume) && !exact_terminal_callback {
                return Err(CoreError::Busy(
                    "a recovered deterministic-invalid validation must be durably consumed before consensus resumes",
                ));
            }
        }
        if let Input::CancelSyncedPayloadValidation { id } = input {
            if !self.pending_sync_validations.contains_key(id) {
                return Err(CoreError::UnknownValidation(id.block_id()));
            }
        }
        // A host callback can be safety-critical even while another durable
        // outbox is active. Widen the busy gate only for the exact, still-
        // registered generation; arbitrary callback IDs remain unable to
        // interrupt signing, finalization, or TC sync.
        let registered_validation = match input {
            Input::PayloadValidated { id, .. } => {
                self.pending_validations.contains_key(id)
                    || self
                        .payload_validation_completion(PayloadValidationRouteV0::Proposal, *id)
                        .is_some()
            }
            Input::SyncedPayloadValidated { id, .. } => {
                self.pending_sync_validations.contains_key(id)
                    || self
                        .payload_validation_completion(PayloadValidationRouteV0::Synced, *id)
                        .is_some()
            }
            Input::CancelSyncedPayloadValidation { id } => {
                self.pending_sync_validations.contains_key(id)
            }
            _ => false,
        };
        // This is only an admission probe over not-yet-authenticated bytes. It
        // can widen the busy gate, never authorize a transition: `step` still
        // performs full preauthentication before the transactional clone.
        let durable_conflict_probe = match input {
            Input::QuorumCertificate(certificate) => {
                self.payload_is_deterministically_invalid(certificate.block_id())
                    || self
                        .durable_qcs()
                        .into_iter()
                        .chain(self.safety.durable_observed_qcs().iter())
                        .any(|durable| {
                            durable.view() == certificate.view()
                                && durable.block_id() != certificate.block_id()
                        })
            }
            Input::TimeoutCertificate(certificate) => {
                let durable_qcs = self.durable_qcs();
                let durable_observed_qcs = self.safety.durable_observed_qcs();
                certificate
                    .referenced_qcs()
                    .iter()
                    .filter_map(QcReferenceV0::as_ordinary)
                    .any(|referenced| {
                        self.payload_is_deterministically_invalid(referenced.block_id())
                            || durable_qcs
                                .iter()
                                .copied()
                                .chain(durable_observed_qcs.iter())
                                .any(|durable| {
                                    durable.view() == referenced.view()
                                        && durable.block_id() != referenced.block_id()
                                })
                    })
            }
            Input::Proposal(proposal) | Input::SyncedProposal(proposal) => {
                let durable_qcs = self.durable_qcs();
                let durable_observed_qcs = self.safety.durable_observed_qcs();
                proposal_referenced_qcs(proposal)
                    .into_iter()
                    .any(|referenced| {
                        self.payload_is_deterministically_invalid(referenced.block_id())
                            || durable_qcs
                                .iter()
                                .copied()
                                .chain(durable_observed_qcs.iter())
                                .any(|durable| {
                                    durable.view() == referenced.view()
                                        && durable.block_id() != referenced.block_id()
                                })
                    })
            }
            _ => false,
        };
        if self.pending_persistence.is_some() && !matches!(input, Input::StorageAck { .. }) {
            return Err(CoreError::Busy(
                "waiting for durable safety-state acknowledgement",
            ));
        }
        if self.safety.safety_halt().is_some()
            && !matches!(
                input,
                Input::Resume
                    | Input::StorageAck { .. }
                    | Input::CancelSyncedPayloadValidation { .. }
            )
        {
            return Err(CoreError::Busy(
                "consensus is safety-halted pending operator recovery",
            ));
        }
        if self.awaiting_signature
            && !matches!(
                input,
                Input::SignatureReady { .. } | Input::StorageAck { .. } | Input::Resume
            )
            && !registered_validation
            && !durable_conflict_probe
        {
            return Err(CoreError::Busy("waiting for the requested signature"));
        }
        if self.safety.pending_sign().is_some()
            && !self.awaiting_signature
            && self.pending_persistence.is_none()
            && !matches!(input, Input::Resume)
            && !registered_validation
            && !durable_conflict_probe
        {
            return Err(CoreError::Busy("persisted signing intent must be resumed"));
        }
        if self.safety.pending_finalize().is_some()
            && !matches!(input, Input::Resume | Input::StorageAck { .. })
            && !registered_validation
            && !durable_conflict_probe
        {
            return Err(CoreError::Busy(
                "waiting for application finalization acknowledgement",
            ));
        }
        if self.safety.pending_tc_high_qc_sync().is_some()
            && !matches!(
                input,
                Input::Resume
                    | Input::Proposal(_)
                    | Input::SyncedProposal(_)
                    | Input::StorageAck { .. }
                    | Input::SafetyReplayComplete
                    | Input::QuorumCertificate(_)
                    | Input::TimeoutCertificate(_)
                    | Input::LocalTimeout { .. }
                    | Input::SignatureReady { .. }
            )
            && !registered_validation
            && !durable_conflict_probe
        {
            return Err(CoreError::Busy(
                "only the durable TC high-QC sync target may progress",
            ));
        }
        if self.safety.pending_standalone_qc_sync().is_some()
            && !matches!(
                input,
                Input::Resume
                    | Input::Proposal(_)
                    | Input::SyncedProposal(_)
                    | Input::StorageAck { .. }
                    | Input::SafetyReplayComplete
                    | Input::QuorumCertificate(_)
                    | Input::TimeoutCertificate(_)
                    | Input::LocalTimeout { .. }
                    | Input::SignatureReady { .. }
            )
            && !registered_validation
            && !durable_conflict_probe
        {
            return Err(CoreError::Busy(
                "only durable certified-block sync obligations may progress",
            ));
        }
        if self.replay_required
            && !durable_conflict_probe
            && !matches!(
                input,
                Input::Resume
                    | Input::SyncedProposal(_)
                    | Input::StorageAck { .. }
                    | Input::SafetyReplayComplete
                    | Input::SignatureReady { .. }
            )
            && !registered_validation
        {
            return Err(CoreError::Busy(
                "only safety replay and durable outbox recovery are allowed until every persisted anchor is verified",
            ));
        }
        Ok(())
    }

    fn resume<V: SignatureVerifier>(&mut self, verifier: &V) -> Result<Vec<Effect>> {
        if self.safety.state_sync_anchor().is_some() && self.safety.revision() < 5 {
            return Ok(vec![Effect::RequestSafetyReplay {
                finalized: self.safety.finalized(),
                high_qc: self.safety.high_qc().qc_ref(),
                locked_qc: self.safety.locked_qc().qc_ref(),
            }]);
        }
        if self.recovered_native_finalization_applied.is_some() {
            return self.remint_recovered_native_finalization_applied_v0();
        }
        if self.recovered_validation_pending.is_some() {
            // Reconciliation established that the application already owns an
            // exact deterministic-invalid result.  Resume is an idempotent
            // probe only; it must not emit timers, signing, replay, or a second
            // validation capability before that result crosses a persistence
            // barrier through its exact callback route.
            return Ok(Vec::new());
        }
        if let Some(halt) = self.safety.safety_halt().cloned() {
            return Ok(vec![Effect::SafetyHalted(Box::new(halt))]);
        }
        if let Some(intent) = self.safety.pending_sign().cloned() {
            self.awaiting_signature = true;
            return Ok(vec![self.signature_effect(&intent)?]);
        }
        if let Some(proof_id) = self.safety.pending_finalize() {
            return Ok(vec![self.finalize_effect(proof_id)?]);
        }
        if self.replay_required {
            return Ok(vec![Effect::RequestSafetyReplay {
                finalized: self.safety.finalized(),
                high_qc: self.safety.high_qc().qc_ref(),
                locked_qc: self.safety.locked_qc().qc_ref(),
            }]);
        }
        if self.safety.pending_tc_high_qc_sync().is_some() {
            let mut effects = self.try_complete_pending_tc_high_qc_sync(verifier)?;
            if matches!(effects.as_slice(), [Effect::RequestTcHighQcSync { .. }]) {
                effects.insert(
                    0,
                    Effect::ArmViewTimer {
                        epoch: self.safety.epoch(),
                        view: self.safety.current_view(),
                    },
                );
            }
            return Ok(effects);
        }
        if self.safety.pending_standalone_qc_sync().is_some() {
            let mut effects = self.try_complete_pending_standalone_qc_sync(verifier)?;
            if matches!(effects.as_slice(), [Effect::RequestStandaloneQcSync { .. }]) {
                effects.insert(
                    0,
                    Effect::ArmViewTimer {
                        epoch: self.safety.epoch(),
                        view: self.safety.current_view(),
                    },
                );
            }
            return Ok(effects);
        }
        Ok(vec![Effect::ArmViewTimer {
            epoch: self.safety.epoch(),
            view: self.safety.current_view(),
        }])
    }

    fn handle_proposal<V: SignatureVerifier>(
        &mut self,
        proposal: SignedProposalV0,
        verifier: &V,
    ) -> Result<Vec<Effect>> {
        let parent_timestamp_ms = self.verify_proposal_or_missing_parent(&proposal, verifier)?;
        let mut side_effects = Vec::new();
        if let Some(parent_timestamp_ms) = parent_timestamp_ms {
            if let Some(evidence) = self.observe_proposal(&proposal, parent_timestamp_ms)? {
                side_effects.push(Effect::Evidence(evidence));
            }
        }
        for referenced_qc in proposal_referenced_qcs(&proposal) {
            for vote in referenced_qc.votes() {
                if let Some(evidence) = self.observe_vote(vote)? {
                    side_effects.push(Effect::Evidence(evidence));
                }
            }
            if let Some(halt) = self.observe_qc(referenced_qc)? {
                let mut effects = self.persist_safety_halt(halt)?;
                effects.extend(side_effects);
                return Ok(effects);
            }
        }
        if let Some(certificate) = proposal.witness().timeout_certificate() {
            side_effects.extend(
                self.observe_timeout_certificate(certificate)?
                    .into_iter()
                    .map(Effect::Evidence),
            );
        }
        if let Some(certificate) = proposal_referenced_qcs(&proposal)
            .into_iter()
            .find(|certificate| self.payload_is_deterministically_invalid(certificate.block_id()))
        {
            let mut effects =
                self.persist_proposal_invalid_payload(&proposal, certificate.clone())?;
            effects.extend(side_effects);
            return Ok(effects);
        }

        let before = self.safety.clone();
        if let Some(certificate) = proposal.witness().timeout_certificate().cloned() {
            let had_pending_tc = self.safety.pending_tc_high_qc_sync().is_some();
            match self.apply_authenticated_tc(&certificate, verifier)? {
                AuthenticatedTcOutcome::MissingReferences => {
                    if self.safety == before {
                        side_effects.push(self.tc_high_qc_sync_effect()?);
                        return Ok(side_effects);
                    }
                    let mut deferred = Vec::new();
                    if self.safety.current_view() > before.current_view() {
                        deferred.push(DeferredEffect::ArmViewTimer);
                    }
                    deferred.push(DeferredEffect::RequestTcHighQcSync);
                    let mut effects = self.persist(deferred)?;
                    effects.extend(side_effects);
                    return Ok(effects);
                }
                AuthenticatedTcOutcome::Complete
                    if had_pending_tc || self.safety.pending_standalone_qc_sync().is_some() =>
                {
                    // A previously durable TC or older standalone obligation
                    // completes/rotates before the dependent child is admitted.
                    return self.persist_carried_qc_transition(&before, side_effects);
                }
                AuthenticatedTcOutcome::Complete => {}
            }
        } else if let Some(certificate) = proposal.witness().justify_qc().as_ordinary().cloned() {
            let ready = self.qc_is_ready_for_adoption(&certificate)?;
            if self.safety.pending_tc_high_qc_sync().is_some()
                || self.safety.pending_standalone_qc_sync().is_some()
                || !ready
            {
                // A proposal independently authenticates its exact justify QC.
                // If that QC cannot complete §6 locally, give it precisely the
                // direct-QC durable active/backlog treatment and stop before
                // inserting or voting for the dependent child.
                return self.handle_authenticated_qc(certificate, verifier, side_effects);
            }
            self.process_verified_ready_qc(&certificate, verifier)?;
        } else if self.safety.pending_tc_high_qc_sync().is_some() {
            side_effects.push(self.tc_high_qc_sync_effect()?);
            return Ok(side_effects);
        } else if self.safety.pending_standalone_qc_sync().is_some() {
            side_effects.push(self.standalone_qc_sync_effect()?);
            return Ok(side_effects);
        }

        if let Some(certificate) = proposal.witness().justify_qc().as_ordinary() {
            let durably_subsumed = self.qc_is_durably_subsumed(certificate)?;
            if durably_subsumed && certificate.block_id() != self.safety.finalized().block_id() {
                // A locally-known stale competing prefix is operationally the
                // same as a pruned one.  The authenticated carrier may have
                // advanced view through its TC, but it must never extend that
                // prefix merely because its header/body remain cached.
                return self.persist_carried_qc_transition(&before, side_effects);
            }
        }

        if parent_timestamp_ms.is_none() {
            // The only missing-parent QC that reaches this point was already
            // classified as durably subsumed at or below finality. Learning it
            // is an idempotent observation; the stale carrier itself needs no
            // body, timestamp, or child admission and must not create a sync
            // loop.
            return self.persist_carried_qc_transition(&before, side_effects);
        }
        let header = proposal.block().header();
        if header.view() < self.safety.current_view()
            || header.height() <= self.safety.finalized().height()
        {
            return self.persist_carried_qc_transition(&before, side_effects);
        }
        match self.blocks.validate_proposal_parent(
            header,
            proposal.witness().justify_qc().qc_ref(),
            self.safety.finalized(),
            self.config.max_block_time_step_ms(),
        ) {
            Ancestry::Descends => {}
            // An ordinary justify which reached this point was already proved
            // ready against the same tree and finalized tip. Synthetic anchors
            // are exact trusted context, so Unknown is always fail-closed.
            Ancestry::Unknown => return Err(CoreError::MissingBlock(header.parent_id())),
            Ancestry::Conflicts => return Err(CoreError::UnsafeProposal),
        }
        if self
            .blocks
            .has_different_fixed_witness(header, proposal.witness())?
        {
            return self.persist_carried_qc_transition(&before, side_effects);
        }
        let protected = self.protected_blocks();
        self.blocks
            .insert_verified_proposal(&proposal, &protected)?;
        self.restore_durable_payload_fact(proposal.block().id())?;

        if header.view() > self.safety.current_view() {
            self.safety.set_current_view(header.view());
        }

        let validation = if self.blocks.payload_is_known(proposal.block().id()) {
            None
        } else {
            Some(self.register_validation(&proposal)?)
        };

        let safety_changed = self.safety != before;
        if safety_changed || validation.is_some_and(|(_, is_new)| is_new) {
            let mut deferred = Vec::new();
            if safety_changed {
                deferred.push(DeferredEffect::ArmViewTimer);
            }
            if self.safety.pending_finalize().is_some() && before.pending_finalize().is_none() {
                deferred.push(DeferredEffect::Finalize);
            }
            if let Some((id, true)) = validation {
                deferred.push(DeferredEffect::ValidatePayload(id));
            }
            let mut effects = self.persist(deferred)?;
            effects.extend(side_effects);
            return Ok(effects);
        }
        if validation.is_none() && self.blocks.payload_is_valid(proposal.block().id()) {
            if let Some(mut effects) =
                self.persist_observed_qc_for_validated_block(proposal.block().id(), verifier)?
            {
                effects.extend(side_effects);
                return Ok(effects);
            }
            let mut effects = self.try_vote_validated_proposal(&proposal, verifier)?;
            effects.extend(side_effects);
            return Ok(effects);
        }
        Ok(side_effects)
    }

    fn persist_carried_qc_transition(
        &mut self,
        before: &SafetyState,
        mut side_effects: Vec<Effect>,
    ) -> Result<Vec<Effect>> {
        if &self.safety == before {
            return Ok(side_effects);
        }
        let mut deferred = vec![DeferredEffect::ArmViewTimer];
        if self.safety.pending_finalize().is_some() && before.pending_finalize().is_none() {
            deferred.push(DeferredEffect::Finalize);
        } else if self.safety.pending_standalone_qc_sync().is_some() {
            deferred.push(DeferredEffect::RequestStandaloneQcSync);
        }
        let mut effects = self.persist(deferred)?;
        effects.append(&mut side_effects);
        Ok(effects)
    }

    /// Installs verified replay ancestry and schedules execution validation.
    /// This path deliberately never learns a QC, changes view, or votes.
    fn handle_synced_proposal<V: SignatureVerifier>(
        &mut self,
        proposal: SignedProposalV0,
        verifier: &V,
    ) -> Result<Vec<Effect>> {
        let parent_timestamp_ms = self.verify_proposal(&proposal, verifier)?;
        let mut side_effects = Vec::new();
        if let Some(evidence) = self.observe_proposal(&proposal, parent_timestamp_ms)? {
            side_effects.push(Effect::Evidence(evidence));
        }
        for referenced_qc in proposal_referenced_qcs(&proposal) {
            for vote in referenced_qc.votes() {
                if let Some(evidence) = self.observe_vote(vote)? {
                    side_effects.push(Effect::Evidence(evidence));
                }
            }
            if let Some(halt) = self.observe_qc(referenced_qc)? {
                let mut effects = self.persist_safety_halt(halt)?;
                effects.extend(side_effects);
                return Ok(effects);
            }
        }
        if let Some(certificate) = proposal.witness().timeout_certificate() {
            side_effects.extend(
                self.observe_timeout_certificate(certificate)?
                    .into_iter()
                    .map(Effect::Evidence),
            );
        }
        if let Some(certificate) = proposal_referenced_qcs(&proposal)
            .into_iter()
            .find(|certificate| self.payload_is_deterministically_invalid(certificate.block_id()))
        {
            let mut effects =
                self.persist_proposal_invalid_payload(&proposal, certificate.clone())?;
            effects.extend(side_effects);
            return Ok(effects);
        }
        let header = proposal.block().header();
        if header.height() <= self.safety.finalized().height() {
            return Ok(side_effects);
        }
        if self.replay_required {
            if header.height().get() > self.replay_max_height() {
                return Err(CoreError::StaleInput);
            }
        } else if let Some(pending) = self.safety.pending_tc_high_qc_sync() {
            if header.height().get() > pending_tc_sync_max_height(pending) {
                return Err(CoreError::StaleInput);
            }
        } else if let Some(pending) = self.safety.pending_standalone_qc_sync() {
            if header.height().get() > pending_standalone_sync_max_height(pending) {
                return Err(CoreError::StaleInput);
            }
        }
        match self.blocks.validate_proposal_parent(
            header,
            proposal.witness().justify_qc().qc_ref(),
            self.safety.finalized(),
            self.config.max_block_time_step_ms(),
        ) {
            Ancestry::Descends => {}
            Ancestry::Unknown => return Err(CoreError::MissingBlock(header.parent_id())),
            Ancestry::Conflicts => return Err(CoreError::UnsafeProposal),
        }
        if self
            .blocks
            .has_different_fixed_witness(header, proposal.witness())?
        {
            return Ok(side_effects);
        }
        let protected = self.protected_blocks();
        self.blocks
            .insert_verified_proposal(&proposal, &protected)?;
        self.restore_durable_payload_fact(proposal.block().id())?;
        if self.blocks.payload_is_known(proposal.block().id()) {
            let mut effects = if self.blocks.payload_is_valid(proposal.block().id()) {
                if self.replay_required {
                    Vec::new()
                } else if self.safety.pending_tc_high_qc_sync().is_some() {
                    self.try_complete_pending_tc_high_qc_sync(verifier)?
                } else if self.safety.pending_standalone_qc_sync().is_some() {
                    self.try_complete_pending_standalone_qc_sync(verifier)?
                } else {
                    self.persist_observed_qc_for_validated_block(proposal.block().id(), verifier)?
                        .unwrap_or_default()
                }
            } else {
                Vec::new()
            };
            effects.extend(side_effects);
            return Ok(effects);
        }
        let (id, is_new) = self.register_sync_validation(&proposal)?;
        if !is_new {
            return Ok(side_effects);
        }
        let mut effects = self.persist(vec![DeferredEffect::ValidateSyncedPayload(id)])?;
        effects.extend(side_effects);
        Ok(effects)
    }

    fn ensure_payload_validation_proposal_resource_bound(
        &self,
        proposal: &SignedProposalV0,
    ) -> Result<()> {
        let actual = proposal.durable_validation_resource_size_v0()?;
        let maximum = self
            .config
            .consensus_parameters()
            .max_consensus_message_bytes() as usize;
        if actual > maximum {
            return Err(CoreError::PayloadValidationResourceTooLarge { actual, maximum });
        }
        Ok(())
    }

    fn verify_proposal<V: SignatureVerifier>(
        &self,
        proposal: &SignedProposalV0,
        verifier: &V,
    ) -> Result<u64> {
        if proposal.block().logical_block_size() > self.config.max_block_bytes() {
            return Err(CoreError::BlockTooLarge {
                actual: proposal.block().logical_block_size(),
                maximum: self.config.max_block_bytes(),
            });
        }
        self.ensure_payload_validation_proposal_resource_bound(proposal)?;
        let header = proposal.block().header();
        self.require_supported_proposal_header(header)?;
        self.reject_epoch_anchor(proposal.witness().justify_qc())?;
        if proposal.witness().epoch_anchor_authorization().is_some() {
            return Err(CoreError::UnsupportedEpochAnchor);
        }
        if let Some(certificate) = proposal.witness().timeout_certificate() {
            for referenced in certificate.referenced_qcs() {
                self.reject_epoch_anchor(referenced)?;
            }
        }
        let parent_timestamp_ms = match proposal.witness().justify_qc().as_synthetic() {
            Some(ContextAuthorizedQcV0::Genesis(_)) => self.config.trusted_genesis_timestamp_ms(),
            Some(ContextAuthorizedQcV0::Epoch(_)) => return Err(CoreError::UnsupportedEpochAnchor),
            None if header.parent_id() == self.safety.finalized().block_id() => {
                self.safety.finalized().timestamp_ms()
            }
            None => self
                .blocks
                .header(header.parent_id())
                .map(BlockHeader::timestamp_ms)
                .ok_or(CoreError::MissingBlock(header.parent_id()))?,
        };
        proposal.verify(
            self.config.validator_set(),
            None,
            self.config.consensus_parameters(),
            parent_timestamp_ms,
            verifier,
        )?;
        Ok(parent_timestamp_ms)
    }

    /// Authenticates a network proposal even when its certified parent header
    /// is not local yet. Only the parent-relative timestamp check is deferred;
    /// the complete envelope shape, exact parent-QC relation, leader, ordinary
    /// certificates, optional TC, and proposer signature are verified first.
    fn verify_proposal_or_missing_parent<V: SignatureVerifier>(
        &self,
        proposal: &SignedProposalV0,
        verifier: &V,
    ) -> Result<Option<u64>> {
        match self.verify_proposal(proposal, verifier) {
            Ok(parent_timestamp_ms) => Ok(Some(parent_timestamp_ms)),
            Err(CoreError::MissingBlock(block_id))
                if proposal
                    .witness()
                    .justify_qc()
                    .as_ordinary()
                    .is_some_and(|certificate| {
                        certificate.block_id() == block_id
                            && proposal.block().header().parent_id() == block_id
                    }) =>
            {
                self.verify_proposal_without_parent_context(proposal, verifier)?;
                Ok(None)
            }
            Err(error) => Err(error),
        }
    }

    fn verify_proposal_without_parent_context<V: SignatureVerifier>(
        &self,
        proposal: &SignedProposalV0,
        verifier: &V,
    ) -> Result<()> {
        if proposal.block().logical_block_size() > self.config.max_block_bytes() {
            return Err(CoreError::BlockTooLarge {
                actual: proposal.block().logical_block_size(),
                maximum: self.config.max_block_bytes(),
            });
        }
        self.ensure_payload_validation_proposal_resource_bound(proposal)?;
        let header = proposal.block().header();
        self.require_supported_proposal_header(header)?;
        if proposal.witness().epoch_anchor_authorization().is_some() {
            return Err(CoreError::UnsupportedEpochAnchor);
        }
        proposal.validate_shape(self.config.validator_set(), None)?;
        if leader_for(self.config.validator_set(), header.view()) != header.proposer_id() {
            return Err(CoreError::Protocol(ValidationError::InvalidProposal(
                "proposer is not the scheduled leader",
            )));
        }

        self.verify_qc_reference(proposal.witness().justify_qc(), verifier)?;
        if let Some(certificate) = proposal.witness().timeout_certificate() {
            self.require_epoch(certificate.epoch())?;
            for referenced in certificate.referenced_qcs() {
                self.reject_epoch_anchor(referenced)?;
            }
            certificate.verify(self.config.validator_set(), None, verifier)?;
        }

        let proposer = self
            .config
            .validator_set()
            .validator(header.proposer_id())
            .ok_or_else(|| {
                CoreError::Protocol(ValidationError::UnknownValidator(Box::new(
                    header.proposer_id(),
                )))
            })?;
        if !verifier.verify(
            proposer,
            &proposal.proposal_signing_root(),
            proposal.witness().proposer_signature(),
        ) {
            return Err(CoreError::Protocol(ValidationError::InvalidSignature(
                Box::new(header.proposer_id()),
            )));
        }
        Ok(())
    }

    fn reject_epoch_anchor(&self, reference: &QcReferenceV0) -> Result<()> {
        if let Some(certificate) = reference.as_ordinary() {
            if certificate.view().get() == 0 || certificate.height().get() == 0 {
                return Err(CoreError::InvalidOrdinaryCertificate);
            }
            self.require_pre_checkpoint_height(certificate.height())?;
            return Ok(());
        }
        match reference.as_synthetic() {
            Some(ContextAuthorizedQcV0::Epoch(_)) => Err(CoreError::UnsupportedEpochAnchor),
            Some(ContextAuthorizedQcV0::Genesis(anchor)) => {
                anchor.matches_trusted_set(self.config.validator_set())?;
                Ok(())
            }
            None => Err(CoreError::InvalidOrdinaryCertificate),
        }
    }

    fn handle_payload_validated<V: SignatureVerifier>(
        &mut self,
        id: ValidationId,
        result: PayloadValidationResult,
        verifier: &V,
    ) -> Result<Vec<Effect>> {
        Self::validate_payload_capability(id, result)?;
        let route = PayloadValidationRouteV0::Proposal;
        if let Some(effects) = self.handle_resolved_validation(route, id, result)? {
            return Ok(effects);
        }
        let pending = self
            .pending_validations
            .get(&id)
            .ok_or(CoreError::UnknownValidation(id.block_id()))?;
        let proposal = pending.proposal.clone();
        let pending_block_id = proposal.block().id();
        if pending_block_id != id.block_id() {
            return Err(CoreError::ValidationCapabilityMismatch {
                expected: pending_block_id,
                received: id.block_id(),
            });
        }
        Self::validate_payload_artifact_parent(&proposal, result)?;
        self.require_payload_validation_obligation(route, id, &proposal)?;
        self.consume_recovered_payload_validation_fence_v0(route, id, result)?;
        self.pending_validations.remove(&id);
        self.remove_payload_validation_obligation(route, id)?;
        self.record_payload_validation_completion(route, id, result)?;
        let block_id = proposal.block().id();
        let transition = self
            .blocks
            .record_payload_validation_for_proposal(&proposal, result)?;
        let fact_transition = self.record_payload_terminal_fact(block_id, result)?;
        if transition == PayloadTransition::ConflictingValidOverlay {
            return Err(CoreError::ConflictingPayloadValidation(block_id));
        }
        if transition == PayloadTransition::ConflictingTerminalResult
            || fact_transition == TerminalFactTransition::Conflicting
        {
            let effects = self.persist_payload_safety_halt(
                SafetyHalt::conflicting_payload_validation(block_id),
            )?;
            return if result.is_valid() {
                self.bind_native_valid_post_ack_manifest_v0(effects)
            } else {
                Ok(effects)
            };
        }
        if result.is_deterministically_invalid() {
            if let Some(reference) = self.invalid_payload_reference(block_id) {
                let halt = SafetyHalt::deterministically_invalid_payload(block_id, reference)?;
                return self.persist_payload_safety_halt(halt);
            }
            // A terminally invalid ordinary proposal which is not certified or
            // named by durable safety state remains only a bounded negative
            // cache entry. Persist it before accepting more consensus input so
            // crash or block-tree eviction cannot make it validation-unknown.
            return self.persist(Vec::new());
        }
        if result.is_unavailable() {
            // Consume this source-scoped generation, but preserve the header.
            // A TC target must remain durable and be requested again exactly.
            if self.safety.pending_tc_high_qc_sync().is_some() {
                return self.persist(vec![DeferredEffect::RequestTcHighQcSync]);
            }
            if self.safety.pending_standalone_qc_sync().is_some() {
                return self.persist(vec![DeferredEffect::RequestStandaloneQcSync]);
            }
            return self.persist(Vec::new());
        }
        if self.safety.pending_tc_high_qc_sync().is_some() {
            // A Valid result may satisfy one of the pending TC's references,
            // but may not create a concurrent safety transition while another
            // durable outbox is active.
            if self.safety.pending_sign().is_some()
                || self.safety.pending_finalize().is_some()
                || self.awaiting_signature
            {
                return self.persist_native_valid_v0(Vec::new());
            }
            let effects = self.try_complete_pending_tc_high_qc_sync(verifier)?;
            return self.ensure_native_valid_cleanup_barrier_v0(effects);
        }
        if self.safety.pending_standalone_qc_sync().is_some() {
            if self.safety.pending_sign().is_some()
                || self.safety.pending_finalize().is_some()
                || self.awaiting_signature
            {
                return self.persist_native_valid_v0(Vec::new());
            }
            let effects = self.try_complete_pending_standalone_qc_sync(verifier)?;
            return self.ensure_native_valid_cleanup_barrier_v0(effects);
        }
        if self.safety.pending_sign().is_some()
            || self.safety.pending_finalize().is_some()
            || self.awaiting_signature
        {
            if self.safety.pending_finalize().is_some()
                && self.safety.pending_sign().is_none()
                && !self.awaiting_signature
            {
                self.remember_finalization_blocked_vote(&proposal);
            }
            return self.persist_native_valid_v0(Vec::new());
        }
        if let Some(effects) = self.persist_observed_qc_for_validated_block(block_id, verifier)? {
            return self.bind_native_valid_post_ack_manifest_v0(effects);
        }
        let effects = self.try_vote_validated_proposal(&proposal, verifier)?;
        self.ensure_native_valid_cleanup_barrier_v0(effects)
    }

    fn remember_finalization_blocked_vote(&mut self, proposal: &SignedProposalV0) {
        let header = proposal.block().header();
        if header.view() != self.safety.current_view()
            || self.safety.payload_terminal_result(proposal.block().id())
                != Some(PayloadTerminalResult::Valid)
            || !self.blocks.payload_is_valid(proposal.block().id())
            || !self.validated_overlay_gate_v0(proposal).unwrap_or(false)
            || !self.is_exact_observed_proposal(proposal)
        {
            return;
        }

        // A validator set has one scheduled leader per view and the
        // observation cache retains that leader's first authenticated
        // proposal. Consequently this option is a complete, deterministic
        // bound rather than a lossy queue.
        self.finalization_blocked_vote = Some(proposal.clone());
    }

    fn is_exact_observed_proposal(&self, proposal: &SignedProposalV0) -> bool {
        let header = proposal.block().header();
        let key = (header.epoch(), header.view(), proposal.proposer());
        self.observed_proposals
            .get(&key)
            .is_some_and(|observed| observed.proposal == *proposal)
    }

    fn try_vote_validated_proposal<V: SignatureVerifier>(
        &mut self,
        proposal: &SignedProposalV0,
        verifier: &V,
    ) -> Result<Vec<Effect>> {
        let Some(shadow_transition) = self.stage_vote_validated_proposal(proposal, verifier)?
        else {
            return Ok(Vec::new());
        };
        self.persist_with_safety_rules_shadow_transition(
            vec![DeferredEffect::RequestSignature],
            Some(shadow_transition),
        )
    }

    fn stage_vote_validated_proposal<V: SignatureVerifier>(
        &mut self,
        proposal: &SignedProposalV0,
        verifier: &V,
    ) -> Result<Option<InertSafetyTransitionV1>> {
        if self.safety.pending_standalone_qc_sync().is_some() {
            return Ok(None);
        }
        if proposal.block().header().view() != self.safety.current_view() {
            return Ok(None);
        }
        if self.replay_required {
            return Err(CoreError::Busy(
                "safety ancestry replay must complete before a new signing intent",
            ));
        }
        if self
            .safety
            .last_voted_view()
            .is_some_and(|view| view >= proposal.block().header().view())
        {
            return Ok(None);
        }
        if self.safety.pending_sign().is_some() {
            return Err(CoreError::ConcurrentSignIntent);
        }
        if !self.validated_overlay_gate_v0(proposal)? {
            return Ok(None);
        }
        if !self.is_exact_observed_proposal(proposal) {
            return Ok(None);
        }

        let justify = proposal.witness().justify_qc().qc_ref();
        if justify.block_id() != self.safety.finalized().block_id()
            && !self.blocks.contains_header(justify.block_id())
        {
            // A QC proves votes for an identifier, not availability or the
            // certified parent's header. Never unlock/vote across that gap.
            return Ok(None);
        }
        match self.blocks.validated_ancestry(
            proposal.block().id(),
            self.safety.finalized(),
            self.config.max_block_time_step_ms(),
        ) {
            Ancestry::Descends => {}
            Ancestry::Unknown | Ancestry::Conflicts => return Ok(None),
        }
        let extends_lock = self.blocks.extends(
            proposal.block().id(),
            self.safety.locked_qc().qc_ref().block_id(),
        );
        let unlocks = justify.view() > self.safety.locked_qc().qc_ref().view();
        if !extends_lock && !unlocks {
            return Ok(None);
        }

        let header = proposal.block().header();
        self.require_supported_proposal_header(header)?;
        let root = Vote::signing_root_for_set(
            self.config.validator_set(),
            header.view(),
            header.height(),
            proposal.block().id(),
        )?;
        let authorizing_safety_revision = self
            .safety
            .revision()
            .checked_add(1)
            .ok_or(CoreError::ArithmeticOverflow("safety-state revision"))?;
        let legacy_intent = SignIntent::Vote {
            authorizing_safety_revision,
            view: header.view(),
            height: header.height(),
            block_id: proposal.block().id(),
            signing_root: root,
        };
        let shadow_transition =
            self.verify_vote_safety_shadow_v1(proposal, &legacy_intent, verifier)?;
        self.safety.set_last_voted(header.view());
        self.safety.set_pending_sign(Some(legacy_intent));
        Ok(Some(shadow_transition))
    }

    /// Final route-independent application gate before a Vote intent exists.
    ///
    /// Both the volatile BlockTree and the durable block-scoped terminal fact
    /// must name the same sealed overlay, and that overlay must bind the exact
    /// proposal edge. A missing fact is ordinary unavailable ancestry; a
    /// disagreement is an integration conflict and must not be retried as a
    /// different overlay for the same signed block.
    fn validated_overlay_gate_v0(&self, proposal: &SignedProposalV0) -> Result<bool> {
        let header = proposal.block().header();
        let block_id = header.id();
        let Some(tree_overlay) = self.blocks.payload_overlay_ref(block_id) else {
            return Ok(false);
        };
        let Some(terminal_overlay) = self
            .safety
            .payload_terminal_fact(block_id)
            .and_then(PayloadTerminalFact::valid_overlay)
        else {
            return Ok(false);
        };
        if tree_overlay != terminal_overlay
            || tree_overlay.block_id() != block_id
            || tree_overlay.parent_block_id() != header.parent_id()
        {
            return Err(CoreError::ConflictingPayloadValidation(block_id));
        }
        Ok(true)
    }

    /// Reconstructs the pure kernel's complete immutable context from the
    /// already-validated Core configuration. The fixed v1 safety-kernel bound
    /// is an additional fail-closed liveness limit: a larger BlockTree may
    /// admit a longer path, but this shadow never truncates or approves it.
    fn safety_rules_shadow_context_v1(&self) -> Result<SafetyRulesContextV1> {
        SafetyRulesContextV1::new(
            self.config.validator_set().clone(),
            *self.config.consensus_parameters(),
            self.config.local_validator(),
            self.config.trusted_genesis_timestamp_ms(),
            CORE_SAFETY_RULES_MAX_ANCESTRY_BLOCKS_V1,
        )
        .map_err(|_| {
            CoreError::SafetyRulesShadowMismatch(
                "the pure kernel rejected the exact Core consensus context",
            )
        })
    }

    /// Builds the exact finalized coordinate consumed by the shadow. Genesis
    /// is reconstructed only from trusted configuration. Every positive-height
    /// reference comes from the complete durable finalization/anchor header,
    /// never from the compact FinalizedTip alone.
    fn safety_rules_shadow_finalized_ref_v1(
        &self,
        context: &SafetyRulesContextV1,
    ) -> Result<FinalizedBlockRefV1> {
        let finalized = self.safety.finalized();
        let reference = if finalized.height() == Height::new(0) {
            FinalizedBlockRefV1::trusted_genesis(context)
        } else {
            // `validate_runtime` requires `last_finalization`, when present,
            // to bind the current finalized tip exactly. The anchor proof is
            // therefore used only by the validated anchor-only generation.
            let exact = if let Some(finalization) = self.safety.last_finalization() {
                finalization.proof().finalized_block().header()
            } else if let Some(anchor) = self.safety.state_sync_anchor() {
                anchor.proof().finalized_block().header()
            } else {
                return Err(CoreError::SafetyRulesShadowMismatch(
                    "positive finalized tip lacks its exact durable header",
                ));
            };
            if exact.height() != finalized.height()
                || exact.view() != finalized.view()
                || exact.id() != finalized.block_id()
                || exact.timestamp_ms() != finalized.timestamp_ms()
            {
                return Err(CoreError::SafetyRulesShadowMismatch(
                    "durable finalized header differs from the Core finalized tip",
                ));
            }
            FinalizedBlockRefV1::from_header(exact).map_err(|_| {
                CoreError::SafetyRulesShadowMismatch(
                    "the pure kernel rejected the exact durable finalized header",
                )
            })?
        };
        if reference.height() != finalized.height()
            || reference.view() != finalized.view()
            || reference.block_id() != finalized.block_id()
            || reference.timestamp_ms() != finalized.timestamp_ms()
        {
            return Err(CoreError::SafetyRulesShadowMismatch(
                "reconstructed finalized reference differs from the Core finalized tip",
            ));
        }
        Ok(reference)
    }

    /// Rebuilds and freshly verifies the pure kernel's predecessor state. The
    /// resulting value is transient comparison data and is never persisted.
    fn safety_rules_shadow_state_v1<V: SignatureVerifier>(
        &self,
        context: &SafetyRulesContextV1,
        verifier: &V,
    ) -> Result<SafetyRulesStateV1> {
        let finalized = self.safety_rules_shadow_finalized_ref_v1(context)?;
        SafetyRulesStateV1::new(
            context,
            SafetyRulesStateSeedV1::new(
                self.safety.current_view(),
                self.safety.last_voted_view(),
                self.safety.last_timeout_view(),
                self.safety.high_qc().clone(),
                self.safety.locked_qc().clone(),
                finalized,
                self.safety.revision(),
            ),
            verifier,
        )
        .map_err(|_| {
            CoreError::SafetyRulesShadowMismatch(
                "the pure kernel rejected the exact Core safety predecessor",
            )
        })
    }

    fn canonical_sign_intent_for_legacy_v1(
        &self,
        intent: &SignIntent,
    ) -> Result<CanonicalSignIntentV0> {
        match intent {
            SignIntent::Vote {
                authorizing_safety_revision,
                view,
                height,
                block_id,
                ..
            } => CanonicalSignIntentV0::vote(
                self.config.validator_set(),
                self.config.local_validator(),
                *authorizing_safety_revision,
                *view,
                *height,
                *block_id,
            )
            .map_err(CoreError::from),
            SignIntent::TimeoutVote {
                authorizing_safety_revision,
                view,
                high_qc,
                ..
            } => CanonicalSignIntentV0::timeout_vote(
                self.config.validator_set(),
                self.config.local_validator(),
                *authorizing_safety_revision,
                *view,
                *high_qc,
            )
            .map_err(CoreError::from),
        }
    }

    /// Runs only after the existing application-Valid, observation, ancestry,
    /// lock, epoch, and watermark gates have admitted an imminent legacy Vote.
    /// The pure transition is discarded after exact comparison.
    fn verify_vote_safety_shadow_v1<V: SignatureVerifier>(
        &self,
        proposal: &SignedProposalV0,
        legacy_intent: &SignIntent,
        verifier: &V,
    ) -> Result<InertSafetyTransitionV1> {
        let context = self.safety_rules_shadow_context_v1()?;
        let state = self.safety_rules_shadow_state_v1(&context, verifier)?;
        let mut ancestry = self
            .blocks
            .exact_validated_proposal_path(
                proposal.block().id(),
                self.safety.finalized(),
                context.max_ancestry_blocks() as usize,
                self.config.max_block_time_step_ms(),
            )
            .ok_or(CoreError::SafetyRulesShadowMismatch(
                "exact application-Valid ancestry is missing, unfrozen, or exceeds the shadow bound",
            ))?;
        let exact_target = ancestry.pop().ok_or(CoreError::SafetyRulesShadowMismatch(
            "exact application-Valid ancestry omitted the target",
        ))?;
        if exact_target != proposal {
            return Err(CoreError::SafetyRulesShadowMismatch(
                "frozen ancestry target differs from the imminent legacy Vote",
            ));
        }

        let (authorizing_safety_revision, view, height, block_id, legacy_signing_root) =
            match legacy_intent {
                SignIntent::Vote {
                    authorizing_safety_revision,
                    view,
                    height,
                    block_id,
                    signing_root,
                } => (
                    *authorizing_safety_revision,
                    *view,
                    *height,
                    *block_id,
                    *signing_root,
                ),
                SignIntent::TimeoutVote { .. } => {
                    return Err(CoreError::SafetyRulesShadowMismatch(
                        "an imminent legacy Vote carried a timeout intent",
                    ));
                }
            };
        let legacy_canonical = self
            .canonical_sign_intent_for_legacy_v1(legacy_intent)
            .map_err(|_| {
                CoreError::SafetyRulesShadowMismatch(
                    "the imminent legacy Vote has no canonical signer intent",
                )
            })?;
        let transition = PureHotStuffSafetyKernelV1::prepare_vote_from_refs(
            &context, &state, &ancestry, proposal, verifier,
        )
        .map_err(|_| {
            CoreError::SafetyRulesShadowMismatch("the pure kernel rejected an imminent legacy Vote")
        })?;
        let successor = transition.successor_state();
        if transition.kind() != InertSafetyTransitionKindV1::Vote
            || transition.predecessor_state_digest() != state.digest()
            || transition.vote_block_id() != Some(block_id)
            || view != proposal.block().header().view()
            || height != proposal.block().header().height()
            || block_id != proposal.block().id()
            || legacy_signing_root != legacy_canonical.signing_root()
            || transition.canonical_intent() != &legacy_canonical
            || successor.current_view() != self.safety.current_view()
            || successor.last_voted_view() != Some(view)
            || successor.last_timeout_view() != self.safety.last_timeout_view()
            || successor.high_qc() != self.safety.high_qc()
            || successor.locked_qc() != self.safety.locked_qc()
            || successor.finalized() != state.finalized()
            || successor.revision() != authorizing_safety_revision
        {
            return Err(CoreError::SafetyRulesShadowMismatch(
                "pure and legacy Vote successors differ",
            ));
        }
        Ok(transition)
    }

    /// Freshly verifies both retained QCs and rebuilds the exact timeout
    /// successor/intent after the legacy timeout gates have admitted it.
    fn verify_timeout_safety_shadow_v1<V: SignatureVerifier>(
        &self,
        legacy_intent: &SignIntent,
        verifier: &V,
    ) -> Result<InertSafetyTransitionV1> {
        let context = self.safety_rules_shadow_context_v1()?;
        let state = self.safety_rules_shadow_state_v1(&context, verifier)?;
        let (authorizing_safety_revision, view, high_qc, legacy_signing_root) = match legacy_intent
        {
            SignIntent::TimeoutVote {
                authorizing_safety_revision,
                view,
                high_qc,
                signing_root,
            } => (*authorizing_safety_revision, *view, *high_qc, *signing_root),
            SignIntent::Vote { .. } => {
                return Err(CoreError::SafetyRulesShadowMismatch(
                    "an imminent legacy TimeoutVote carried a Vote intent",
                ));
            }
        };
        let legacy_canonical = self
            .canonical_sign_intent_for_legacy_v1(legacy_intent)
            .map_err(|_| {
                CoreError::SafetyRulesShadowMismatch(
                    "the imminent legacy TimeoutVote has no canonical signer intent",
                )
            })?;
        let transition = PureHotStuffSafetyKernelV1::prepare_timeout(&context, &state, verifier)
            .map_err(|_| {
                CoreError::SafetyRulesShadowMismatch(
                    "the pure kernel rejected an imminent legacy TimeoutVote",
                )
            })?;
        let successor = transition.successor_state();
        if transition.kind() != InertSafetyTransitionKindV1::TimeoutVote
            || transition.predecessor_state_digest() != state.digest()
            || transition.vote_block_id().is_some()
            || view != self.safety.current_view()
            || high_qc != self.safety.high_qc().qc_ref()
            || legacy_signing_root != legacy_canonical.signing_root()
            || transition.canonical_intent() != &legacy_canonical
            || successor.current_view() != self.safety.current_view()
            || successor.last_voted_view() != self.safety.last_voted_view()
            || successor.last_timeout_view() != Some(view)
            || successor.high_qc() != self.safety.high_qc()
            || successor.locked_qc() != self.safety.locked_qc()
            || successor.finalized() != state.finalized()
            || successor.revision() != authorizing_safety_revision
        {
            return Err(CoreError::SafetyRulesShadowMismatch(
                "pure and legacy TimeoutVote successors differ",
            ));
        }
        Ok(transition)
    }

    /// Test-only entry to the real pre-persistence Vote staging boundary.
    /// Tests invoke it only on an isolated Core clone; it emits no signer or
    /// persistence effect by itself.
    #[cfg(test)]
    pub(crate) fn stage_vote_validated_proposal_for_test_v1<V: SignatureVerifier>(
        &mut self,
        proposal: &SignedProposalV0,
        verifier: &V,
    ) -> Result<bool> {
        self.stage_vote_validated_proposal(proposal, verifier)
            .map(|transition| transition.is_some())
    }

    #[cfg(test)]
    pub(crate) fn forget_validated_proposal_for_test_v1(
        &mut self,
        block_id: BlockId,
    ) -> Result<bool> {
        self.blocks.forget_validated_proposal_for_test(block_id)
    }

    fn try_stage_finalization_blocked_vote<V: SignatureVerifier>(
        &mut self,
        verifier: &V,
    ) -> Result<Option<InertSafetyTransitionV1>> {
        let Some(proposal) = self.finalization_blocked_vote.take() else {
            return Ok(None);
        };
        if self.replay_required
            || self.awaiting_signature
            || self.safety.pending_sign().is_some()
            || self.safety.pending_finalize().is_some()
            || self.safety.pending_tc_high_qc_sync().is_some()
            || self.safety.pending_standalone_qc_sync().is_some()
            || proposal.block().header().view() != self.safety.current_view()
            || self.safety.payload_terminal_result(proposal.block().id())
                != Some(PayloadTerminalResult::Valid)
            || !self.blocks.payload_is_valid(proposal.block().id())
            || !self.validated_overlay_gate_v0(&proposal).unwrap_or(false)
            || !self.is_exact_observed_proposal(&proposal)
        {
            return Ok(None);
        }

        // Finality may have advanced the authenticated parent context or made
        // the proposal stale. Re-run the complete envelope/leader/signature
        // verification, then the ordinary ancestry, lock, and watermark rules.
        // A failed re-check only drops this volatile liveness hint; it must not
        // roll back an already-applied application finalization.
        let Ok(parent_timestamp_ms) = self.verify_proposal(&proposal, verifier) else {
            return Ok(None);
        };
        let header = proposal.block().header();
        let key = (header.epoch(), header.view(), proposal.proposer());
        if self.observed_proposals.get(&key).is_none_or(|observed| {
            observed.proposal != proposal
                || observed.authenticated_parent_timestamp_ms != parent_timestamp_ms
        }) {
            return Ok(None);
        }
        self.stage_vote_validated_proposal(&proposal, verifier)
    }

    fn persist_observed_qc_for_validated_block<V: SignatureVerifier>(
        &mut self,
        block_id: BlockId,
        verifier: &V,
    ) -> Result<Option<Vec<Effect>>> {
        let Some(certificate) = self
            .observed_qcs
            .values()
            .filter(|certificate| certificate.block_id() == block_id)
            .max_by_key(|certificate| qc_order_key(certificate))
            .cloned()
        else {
            return Ok(None);
        };
        let before = self.safety.clone();
        self.process_verified_ready_qc(&certificate, verifier)?;
        if self.safety == before {
            return Ok(None);
        }
        let mut deferred = vec![DeferredEffect::ArmViewTimer];
        if self.safety.pending_finalize().is_some() && before.pending_finalize().is_none() {
            deferred.push(DeferredEffect::Finalize);
        }
        self.persist(deferred).map(Some)
    }

    fn handle_synced_payload_validated<V: SignatureVerifier>(
        &mut self,
        id: ValidationId,
        result: PayloadValidationResult,
        verifier: &V,
    ) -> Result<Vec<Effect>> {
        Self::validate_payload_capability(id, result)?;
        let route = PayloadValidationRouteV0::Synced;
        if let Some(effects) = self.handle_resolved_validation(route, id, result)? {
            return Ok(effects);
        }
        let pending = self
            .pending_sync_validations
            .get(&id)
            .ok_or(CoreError::UnknownValidation(id.block_id()))?;
        let proposal = pending.proposal.clone();
        let pending_block_id = proposal.block().id();
        if pending_block_id != id.block_id() {
            return Err(CoreError::ValidationCapabilityMismatch {
                expected: pending_block_id,
                received: id.block_id(),
            });
        }
        Self::validate_payload_artifact_parent(&proposal, result)?;
        self.require_payload_validation_obligation(route, id, &proposal)?;
        self.consume_recovered_payload_validation_fence_v0(route, id, result)?;
        self.pending_sync_validations.remove(&id);
        self.remove_payload_validation_obligation(route, id)?;
        self.record_payload_validation_completion(route, id, result)?;
        let block_id = proposal.block().id();
        let transition = self
            .blocks
            .record_payload_validation_for_proposal(&proposal, result)?;
        let fact_transition = self.record_payload_terminal_fact(block_id, result)?;
        if transition == PayloadTransition::ConflictingValidOverlay {
            return Err(CoreError::ConflictingPayloadValidation(block_id));
        }
        if transition == PayloadTransition::ConflictingTerminalResult
            || fact_transition == TerminalFactTransition::Conflicting
        {
            let effects = self.persist_payload_safety_halt(
                SafetyHalt::conflicting_payload_validation(block_id),
            )?;
            return if result.is_valid() {
                self.bind_native_valid_post_ack_manifest_v0(effects)
            } else {
                Ok(effects)
            };
        }
        if result.is_deterministically_invalid() {
            if let Some(reference) = self.invalid_payload_reference(block_id) {
                let halt = SafetyHalt::deterministically_invalid_payload(block_id, reference)?;
                return self.persist_payload_safety_halt(halt);
            }
            return self.persist(Vec::new());
        }
        if result.is_unavailable() {
            if self.replay_required {
                return self.persist(Vec::new());
            }
            if self.safety.pending_tc_high_qc_sync().is_some() {
                return self.persist(vec![DeferredEffect::RequestTcHighQcSync]);
            }
            if self.safety.pending_standalone_qc_sync().is_some() {
                return self.persist(vec![DeferredEffect::RequestStandaloneQcSync]);
            }
            return self.persist(Vec::new());
        }
        if self.safety.pending_sign().is_some()
            || self.safety.pending_finalize().is_some()
            || self.awaiting_signature
        {
            return self.persist_native_valid_v0(Vec::new());
        }
        if self.replay_required {
            return self.persist_native_valid_v0(Vec::new());
        }
        if self.safety.pending_tc_high_qc_sync().is_some() {
            let effects = self.try_complete_pending_tc_high_qc_sync(verifier)?;
            return self.ensure_native_valid_cleanup_barrier_v0(effects);
        }
        if self.safety.pending_standalone_qc_sync().is_some() {
            let effects = self.try_complete_pending_standalone_qc_sync(verifier)?;
            return self.ensure_native_valid_cleanup_barrier_v0(effects);
        }
        if let Some(effects) = self.persist_observed_qc_for_validated_block(block_id, verifier)? {
            return self.bind_native_valid_post_ack_manifest_v0(effects);
        }
        self.persist_native_valid_v0(Vec::new())
    }

    fn handle_cancel_synced_payload_validation(&mut self, id: ValidationId) -> Result<Vec<Effect>> {
        let proposal = self
            .pending_sync_validations
            .get(&id)
            .map(|pending| pending.proposal.clone())
            .ok_or(CoreError::UnknownValidation(id.block_id()))?;
        self.require_payload_validation_obligation(
            PayloadValidationRouteV0::Synced,
            id,
            &proposal,
        )?;
        self.pending_sync_validations.remove(&id);
        self.remove_payload_validation_obligation(PayloadValidationRouteV0::Synced, id)?;
        self.persist(Vec::new())
    }

    fn consume_recovered_payload_validation_fence_v0(
        &mut self,
        route: PayloadValidationRouteV0,
        id: ValidationId,
        result: PayloadValidationResult,
    ) -> Result<()> {
        let Some(fence) = self.recovered_validation_pending else {
            return Ok(());
        };
        if fence.route != route || fence.id != id || !result.is_deterministically_invalid() {
            return Err(CoreError::InvalidRecovery(
                "recovered payload-validation callback differs from its reconciled deterministic-invalid job",
            ));
        }
        self.recovered_validation_pending = None;
        Ok(())
    }

    fn handle_local_timeout<V: SignatureVerifier>(
        &mut self,
        epoch: Epoch,
        view: View,
        verifier: &V,
    ) -> Result<Vec<Effect>> {
        self.require_epoch(epoch)?;
        if view != self.safety.current_view() {
            return Err(CoreError::WrongView {
                expected: self.safety.current_view(),
                received: view,
            });
        }
        if self
            .safety
            .last_timeout_view()
            .is_some_and(|last| last >= view)
        {
            return Ok(Vec::new());
        }
        if self.safety.pending_sign().is_some() {
            return Err(CoreError::ConcurrentSignIntent);
        }
        let high_qc = self.safety.high_qc().qc_ref();
        self.require_pre_checkpoint_height(high_qc.height())?;
        let root = TimeoutVote::signing_root_for_set(self.config.validator_set(), view, high_qc)?;
        let authorizing_safety_revision = self
            .safety
            .revision()
            .checked_add(1)
            .ok_or(CoreError::ArithmeticOverflow("safety-state revision"))?;
        let legacy_intent = SignIntent::TimeoutVote {
            authorizing_safety_revision,
            view,
            high_qc,
            signing_root: root,
        };
        let shadow_transition = self.verify_timeout_safety_shadow_v1(&legacy_intent, verifier)?;
        self.safety.set_last_timeout(view);
        self.safety.set_pending_sign(Some(legacy_intent));
        self.persist_with_safety_rules_shadow_transition(
            vec![DeferredEffect::RequestSignature],
            Some(shadow_transition),
        )
    }

    fn handle_storage_ack(&mut self, barrier: BarrierId) -> Result<Vec<Effect>> {
        let pending = self
            .pending_persistence
            .take()
            .ok_or(CoreError::UnexpectedStorageAck)?;
        if pending.barrier != barrier {
            return Err(CoreError::UnexpectedStorageAck);
        }
        let mut effects = Vec::with_capacity(pending.deferred.len());
        for effect in pending.deferred {
            match effect {
                DeferredEffect::RequestSignature => {
                    let intent = self
                        .safety
                        .pending_sign()
                        .cloned()
                        .ok_or(CoreError::UnexpectedSignature)?;
                    self.awaiting_signature = true;
                    effects.push(self.signature_effect(&intent)?);
                }
                DeferredEffect::ArmViewTimer => effects.push(Effect::ArmViewTimer {
                    epoch: self.safety.epoch(),
                    view: self.safety.current_view(),
                }),
                DeferredEffect::ValidatePayload(id) => {
                    effects.push(Effect::ValidatePayload(
                        self.payload_validation_request_from_obligation(
                            PayloadValidationRouteV0::Proposal,
                            id,
                        )?,
                    ));
                }
                DeferredEffect::ValidateSyncedPayload(id) => {
                    effects.push(Effect::ValidateSyncedPayload(
                        self.payload_validation_request_from_obligation(
                            PayloadValidationRouteV0::Synced,
                            id,
                        )?,
                    ));
                }
                DeferredEffect::RequestTcHighQcSync => {
                    effects.push(self.tc_high_qc_sync_effect()?);
                }
                DeferredEffect::RequestStandaloneQcSync => {
                    effects.push(self.standalone_qc_sync_effect()?);
                }
                DeferredEffect::SafetyHalted => {
                    let halt = self
                        .safety
                        .safety_halt()
                        .cloned()
                        .ok_or(CoreError::ConflictingCertificate)?;
                    effects.push(Effect::SafetyHalted(Box::new(halt)));
                }
                DeferredEffect::Finalize => {
                    let proof_id = self
                        .safety
                        .pending_finalize()
                        .ok_or(CoreError::UnexpectedFinalizationAck)?;
                    effects.push(self.finalize_effect(proof_id)?);
                }
            }
        }
        Ok(effects)
    }

    fn handle_finalization_applied<V: SignatureVerifier>(
        &mut self,
        receipt: &ApplicationFinalizationReceiptV0,
        verifier: &V,
    ) -> Result<Vec<Effect>> {
        let receipt_finalization = receipt.finalization();
        let pending_id = self
            .safety
            .pending_finalize()
            .ok_or(CoreError::UnexpectedFinalizationAck)?;
        let durable = self
            .safety
            .pending_finalization()
            .ok_or(CoreError::UnexpectedFinalizationAck)?;
        if durable.proof_id() != pending_id || durable != receipt_finalization {
            return Err(CoreError::UnexpectedFinalizationAck);
        }
        let predecessor = self.safety.application_applied();
        if durable.authenticated_parent() != predecessor {
            return Err(CoreError::UnexpectedFinalizationAck);
        }
        let committed = durable.proof().finalized_block().header();
        let exact_target = FinalizedTip::new(
            committed.height(),
            committed.view(),
            committed.id(),
            committed.timestamp_ms(),
        );
        let mut queue = self.safety.finalization_queue().to_vec();
        queue.remove(0);
        self.safety.set_application_applied(exact_target);
        self.safety
            .set_pending_finalize(queue.first().map(DurableFinalizationV0::proof_id));
        self.safety.set_finalization_queue(queue);
        let drained_standalone = if self.safety.pending_tc_high_qc_sync().is_none() {
            self.drain_ready_pending_standalone_qcs(verifier)?
        } else {
            false
        };
        let mut deferred = Vec::new();
        if drained_standalone {
            deferred.push(DeferredEffect::ArmViewTimer);
        }
        if self.safety.pending_tc_high_qc_sync().is_some() {
            self.finalization_blocked_vote = None;
            deferred.push(DeferredEffect::RequestTcHighQcSync);
        } else if self.safety.pending_finalize().is_some() {
            // The next ancestor-ordered finalization remains the sole blocker.
            // Keep the volatile candidate for that exact acknowledgement.
            deferred.push(DeferredEffect::Finalize);
        } else if self.safety.pending_standalone_qc_sync().is_some() {
            self.finalization_blocked_vote = None;
            deferred.push(DeferredEffect::RequestStandaloneQcSync);
        }
        let shadow_transition = if self.safety.pending_finalize().is_none()
            && self.safety.pending_tc_high_qc_sync().is_none()
            && self.safety.pending_standalone_qc_sync().is_none()
        {
            // Clearing the finalization outbox and creating the vote intent
            // share one safety-state write. The signer is requested only by
            // the resulting StorageAck.
            let transition = self.try_stage_finalization_blocked_vote(verifier)?;
            if transition.is_some() {
                deferred.push(DeferredEffect::RequestSignature);
            }
            transition
        } else {
            None
        };
        self.persist_native_finalization_applied_v0(
            receipt.application_store_readback_v0().clone(),
            predecessor,
            exact_target,
            deferred,
            shadow_transition,
        )
    }

    fn validate_replayed_safety_anchors_v0(&self) -> Result<()> {
        if self.replay_required {
            let high_ref = self.safety.high_qc().qc_ref();
            let locked_ref = self.safety.locked_qc().qc_ref();
            let mut anchors = vec![high_ref.block_id()];
            if locked_ref.block_id() != self.safety.finalized().block_id() {
                anchors.push(locked_ref.block_id());
            }
            for reference in [self.safety.high_qc(), self.safety.locked_qc()] {
                if let Some(certificate) = reference.as_ordinary() {
                    if certificate.block_id() != self.safety.finalized().block_id() {
                        self.blocks
                            .validate_certificate_binding(certificate)
                            .map_err(|_| {
                                CoreError::InvalidRecovery(
                                    "replayed safety anchor does not match its durable certificate",
                                )
                            })?;
                    }
                }
            }
            for block_id in anchors {
                if block_id == self.safety.finalized().block_id() {
                    continue;
                }
                match self.blocks.validated_ancestry(
                    block_id,
                    self.safety.finalized(),
                    self.config.max_block_time_step_ms(),
                ) {
                    Ancestry::Descends => {}
                    Ancestry::Conflicts => {
                        return Err(CoreError::InvalidRecovery(
                            "replayed safety anchor conflicts with finalized tip",
                        ));
                    }
                    Ancestry::Unknown => {
                        return Err(CoreError::InvalidRecovery(
                            "replayed ancestry does not reach every safety anchor",
                        ));
                    }
                }
            }
        }
        Ok(())
    }

    fn handle_replay_complete<V: SignatureVerifier>(
        &mut self,
        verifier: &V,
    ) -> Result<Vec<Effect>> {
        self.validate_replayed_safety_anchors_v0()?;
        self.replay_required = false;
        if self.safety.pending_tc_high_qc_sync().is_some() {
            return self.try_complete_pending_tc_high_qc_sync(verifier);
        }
        if self.safety.pending_standalone_qc_sync().is_some() {
            return self.try_complete_pending_standalone_qc_sync(verifier);
        }
        Ok(vec![Effect::ArmViewTimer {
            epoch: self.safety.epoch(),
            view: self.safety.current_view(),
        }])
    }

    fn handle_signature<V: SignatureVerifier>(
        &mut self,
        id: crate::SignId,
        signature: trnm_consensus_types::SignatureBytes,
        verifier: &V,
    ) -> Result<Vec<Effect>> {
        if !self.awaiting_signature {
            return Err(CoreError::UnexpectedSignature);
        }
        let intent = self
            .safety
            .pending_sign()
            .cloned()
            .ok_or(CoreError::UnexpectedSignature)?;
        if intent.id() != id {
            return Err(CoreError::SignIdMismatch);
        }
        self.require_supported_sign_intent(&intent)?;
        let outbound = match intent {
            SignIntent::Vote {
                view,
                height,
                block_id,
                signing_root,
                ..
            } => {
                if signing_root != id.signing_root() {
                    return Err(CoreError::SignIdMismatch);
                }
                let vote = Vote::new(
                    self.safety.chain_id(),
                    self.safety.protocol_version(),
                    self.safety.epoch(),
                    view,
                    height,
                    block_id,
                    self.safety.validator_set_id(),
                    self.config.local_validator(),
                    signature,
                    self.config.validator_set(),
                )?;
                vote.verify(self.config.validator_set(), verifier)?;
                OutboundMessage::Vote(vote)
            }
            SignIntent::TimeoutVote {
                view,
                high_qc,
                signing_root,
                ..
            } => {
                if signing_root != id.signing_root() {
                    return Err(CoreError::SignIdMismatch);
                }
                let vote = TimeoutVote::new(
                    self.safety.chain_id(),
                    self.safety.protocol_version(),
                    self.safety.epoch(),
                    view,
                    self.safety.validator_set_id(),
                    high_qc,
                    self.config.local_validator(),
                    signature,
                    self.config.validator_set(),
                )?;
                vote.verify(self.config.validator_set(), verifier)?;
                OutboundMessage::TimeoutVote(vote)
            }
        };
        self.awaiting_signature = false;
        self.safety.set_pending_sign(None);
        let mut effects = vec![Effect::Broadcast(outbound)];
        if self.safety.pending_tc_high_qc_sync().is_some() {
            effects.extend(self.try_complete_pending_tc_high_qc_sync(verifier)?);
        } else if self.safety.pending_standalone_qc_sync().is_some() {
            effects.extend(self.try_complete_pending_standalone_qc_sync(verifier)?);
        }
        Ok(effects)
    }

    fn handle_vote<V: SignatureVerifier>(
        &mut self,
        vote: Vote,
        verifier: &V,
    ) -> Result<Vec<Effect>> {
        vote.verify(self.config.validator_set(), verifier)?;
        self.require_epoch(vote.epoch())?;
        self.require_pre_checkpoint_height(vote.height())?;
        Ok(self
            .observe_vote(&vote)?
            .map(|evidence| vec![Effect::Evidence(evidence)])
            .unwrap_or_default())
    }

    fn handle_timeout_vote<V: SignatureVerifier>(
        &mut self,
        vote: TimeoutVote,
        verifier: &V,
    ) -> Result<Vec<Effect>> {
        vote.verify(self.config.validator_set(), verifier)?;
        self.require_epoch(vote.epoch())?;
        self.require_pre_checkpoint_height(vote.high_qc().height())?;
        Ok(self
            .observe_timeout(&vote)?
            .map(|evidence| vec![Effect::Evidence(evidence)])
            .unwrap_or_default())
    }

    fn handle_qc<V: SignatureVerifier>(
        &mut self,
        certificate: QuorumCertificate,
        verifier: &V,
    ) -> Result<Vec<Effect>> {
        self.verify_ordinary_qc(&certificate, verifier)?;
        let mut side_effects = Vec::new();
        for vote in certificate.votes() {
            if let Some(evidence) = self.observe_vote(vote)? {
                side_effects.push(Effect::Evidence(evidence));
            }
        }
        if let Some(halt) = self.observe_qc(&certificate)? {
            let mut effects = self.persist_safety_halt(halt)?;
            effects.extend(side_effects);
            return Ok(effects);
        }
        if self.payload_is_deterministically_invalid(certificate.block_id()) {
            let mut effects = self.persist_certified_invalid_payload(certificate)?;
            effects.extend(side_effects);
            return Ok(effects);
        }

        self.handle_authenticated_qc(certificate, verifier, side_effects)
    }

    /// Applies an already-authenticated and already-observed ordinary QC.
    ///
    /// Proposal carriers use this after observing every certificate in their
    /// signed witness, so the exact justify QC shares the direct-QC durable
    /// catch-up path without double-counting votes or equivocation evidence.
    fn handle_authenticated_qc<V: SignatureVerifier>(
        &mut self,
        certificate: QuorumCertificate,
        verifier: &V,
        mut side_effects: Vec<Effect>,
    ) -> Result<Vec<Effect>> {
        if self
            .safety
            .pending_tc_high_qc_sync()
            .is_some_and(|pending| pending_tc_contains_qc(pending, &certificate))
        {
            let mut effects = self.try_complete_pending_tc_high_qc_sync(verifier)?;
            effects.extend(side_effects);
            return Ok(effects);
        }

        if self.safety.pending_tc_high_qc_sync().is_some()
            && self.safety.pending_standalone_qc_sync().is_none()
            && self.qc_is_durably_subsumed(&certificate)?
        {
            // An unrelated historical QC must not become a new standalone
            // obligation merely because a different TC obligation is active.
            return Ok(side_effects);
        }

        if self.safety.pending_standalone_qc_sync().is_some() {
            let names_active = self
                .safety
                .pending_standalone_qc_sync()
                .is_some_and(|pending| same_qc_coordinates(pending.active(), &certificate));
            if names_active && self.qc_is_ready_for_adoption(&certificate)? {
                let mut effects = self.try_complete_pending_standalone_qc_sync(verifier)?;
                effects.extend(side_effects);
                return Ok(effects);
            }
            if !names_active && self.qc_is_durably_subsumed(&certificate)? {
                return Ok(side_effects);
            }
            if self.remember_pending_standalone_qc(certificate)? {
                let deferred = if self.safety.pending_tc_high_qc_sync().is_some() {
                    vec![DeferredEffect::RequestTcHighQcSync]
                } else {
                    vec![DeferredEffect::RequestStandaloneQcSync]
                };
                let mut effects = self.persist(deferred)?;
                effects.extend(side_effects);
                return Ok(effects);
            }
            let request = if self.safety.pending_tc_high_qc_sync().is_some() {
                self.tc_high_qc_sync_effect()?
            } else {
                self.standalone_qc_sync_effect()?
            };
            side_effects.push(request);
            return Ok(side_effects);
        }

        let ready = self.qc_is_ready_for_adoption(&certificate)?;
        if !ready || self.safety.pending_tc_high_qc_sync().is_some() {
            self.safety
                .set_pending_standalone_qc_sync(Some(PendingStandaloneQcSync::new(certificate)));
            let deferred = if self.safety.pending_tc_high_qc_sync().is_some() {
                vec![DeferredEffect::RequestTcHighQcSync]
            } else {
                vec![DeferredEffect::RequestStandaloneQcSync]
            };
            let mut effects = self.persist(deferred)?;
            effects.extend(side_effects);
            return Ok(effects);
        }

        let before = self.safety.clone();
        self.process_verified_ready_qc(&certificate, verifier)?;
        let mut deferred = vec![DeferredEffect::ArmViewTimer];
        if self.safety.pending_finalize().is_some() && before.pending_finalize().is_none() {
            deferred.push(DeferredEffect::Finalize);
        }

        if self.safety != before {
            let mut effects = self.persist(deferred)?;
            effects.extend(side_effects);
            Ok(effects)
        } else {
            Ok(side_effects)
        }
    }

    /// Applies the complete §6 QC transition for a certificate whose
    /// signatures, block binding, ancestry, and payload are already available.
    /// Persistence is deliberately owned by the caller so a TC can process all
    /// of its referenced QCs and cross one durability boundary.
    fn process_verified_ready_qc<V: SignatureVerifier>(
        &mut self,
        certificate: &QuorumCertificate,
        verifier: &V,
    ) -> Result<()> {
        if self.qc_is_durably_subsumed(certificate)? {
            return Ok(());
        }
        if self.payload_is_deterministically_invalid(certificate.block_id()) {
            return Err(CoreError::ConflictingCertificate);
        }
        self.blocks.validate_certificate_binding(certificate)?;
        let mut finalizations = self.blocks.detect_three_chain_suffix(
            certificate,
            self.config.validator_set(),
            self.config.consensus_parameters(),
            self.safety.finalized(),
        )?;
        let queue_len = self
            .safety
            .finalization_queue()
            .len()
            .checked_add(finalizations.len())
            .ok_or(CoreError::ArithmeticOverflow(
                "application finalization queue length",
            ))?;
        if queue_len > self.config.max_blocks() {
            return Err(CoreError::FinalizationQueueFull);
        }

        // Authenticate the complete finalized-tip suffix before mutating any
        // finalization field. A high QC can arrive several blocks above the
        // durable tip, but every intermediate target must still have its own
        // exact parent, terminal overlay, proof, and validated ancestry.
        let mut expected_parent = self.safety.finalized();
        let mut suffix_is_ready = true;
        for finalization in &finalizations {
            if finalization.authenticated_parent() != expected_parent {
                return Err(CoreError::ConflictingCertificate);
            }
            finalization.proof().verify(
                self.config.validator_set(),
                None,
                self.config.consensus_parameters(),
                finalization.authenticated_parent().timestamp_ms(),
                verifier,
            )?;
            let committed = finalization.proof().finalized_block().header();
            let terminal_overlay = self
                .safety
                .payload_terminal_fact(committed.id())
                .and_then(PayloadTerminalFact::valid_overlay)
                .ok_or(CoreError::ConflictingPayloadValidation(committed.id()))?;
            if terminal_overlay != finalization.target_overlay_ref() {
                return Err(CoreError::ConflictingPayloadValidation(committed.id()));
            }
            match self.blocks.validated_ancestry(
                committed.id(),
                expected_parent,
                self.config.max_block_time_step_ms(),
            ) {
                Ancestry::Descends => {}
                Ancestry::Conflicts => return Err(CoreError::ConflictingCertificate),
                // Recovery deliberately starts with an empty volatile tree.
                // Withhold the entire suffix until stale verified proposals
                // and QCs replay every missing edge; never append a prefix.
                Ancestry::Unknown => suffix_is_ready = false,
            }
            expected_parent = durable_finalization_target(finalization);
        }
        if !suffix_is_ready {
            finalizations.clear();
        }

        self.learn_qc(certificate.clone())?;
        self.safety
            .set_current_view(certificate.view().checked_next()?);

        if let Some(last) = finalizations.last().cloned() {
            let queue_was_empty = self.safety.finalization_queue().is_empty();
            let first_proof_id = finalizations
                .first()
                .expect("a finalization suffix with a tail has a front")
                .proof_id();
            let finalized = durable_finalization_target(&last);
            let mut queue = self.safety.finalization_queue().to_vec();
            queue.extend(finalizations);
            self.safety.set_finalized(finalized);
            self.safety.set_finalization_queue(queue);
            self.safety.set_last_finalization(last);
            if queue_was_empty {
                self.safety.set_pending_finalize(Some(first_proof_id));
            }
            let protected = self.protected_blocks();
            self.blocks
                .prune_below(finalized.height().get(), finalized.block_id(), &protected)?;
        }
        Ok(())
    }

    fn handle_tc<V: SignatureVerifier>(
        &mut self,
        certificate: TimeoutCertificateV0,
        verifier: &V,
    ) -> Result<Vec<Effect>> {
        self.require_epoch(certificate.epoch())?;
        for referenced in certificate.referenced_qcs() {
            self.reject_epoch_anchor(referenced)?;
        }
        certificate.verify(self.config.validator_set(), None, verifier)?;
        let mut side_effects = Vec::new();
        for referenced in certificate.referenced_qcs() {
            if let Some(referenced_qc) = referenced.as_ordinary() {
                for vote in referenced_qc.votes() {
                    if let Some(evidence) = self.observe_vote(vote)? {
                        side_effects.push(Effect::Evidence(evidence));
                    }
                }
                if let Some(halt) = self.observe_qc(referenced_qc)? {
                    let mut effects = self.persist_safety_halt(halt)?;
                    effects.extend(side_effects);
                    return Ok(effects);
                }
            }
        }
        side_effects.extend(
            self.observe_timeout_certificate(&certificate)?
                .into_iter()
                .map(Effect::Evidence),
        );
        if let Some(block_id) = certificate
            .referenced_qcs()
            .iter()
            .filter_map(QcReferenceV0::as_ordinary)
            .find(|referenced| self.payload_is_deterministically_invalid(referenced.block_id()))
            .map(QuorumCertificate::block_id)
        {
            // TC view advancement is independently authenticated and is not
            // rolled back merely because one certified payload violates the
            // execution-validity assumption. Same-view QC conflicts above
            // take precedence because their complete signed witness must be
            // retained before any durable obligation is cleared.
            self.safety
                .set_current_view(certificate.timed_out_view().checked_next()?);
            let halt = SafetyHalt::deterministically_invalid_payload(
                block_id,
                InvalidPayloadReference::TimeoutCertificate(Box::new(certificate)),
            )?;
            let mut effects = self.persist_payload_safety_halt(halt)?;
            effects.extend(side_effects);
            return Ok(effects);
        }

        self.handle_authenticated_tc(certificate, verifier, side_effects)
    }

    /// Applies a fully verified and already-observed timeout certificate.
    /// Proposal carriers call this same path after observing their complete
    /// witness, so every referenced ordinary QC and the full TC survive the
    /// same persistence and recovery contract as direct TC ingress.
    fn handle_authenticated_tc<V: SignatureVerifier>(
        &mut self,
        certificate: TimeoutCertificateV0,
        verifier: &V,
        mut side_effects: Vec<Effect>,
    ) -> Result<Vec<Effect>> {
        let before = self.safety.clone();
        let outcome = self.apply_authenticated_tc(&certificate, verifier)?;

        if outcome == AuthenticatedTcOutcome::MissingReferences {
            if self.safety == before {
                side_effects.push(self.tc_high_qc_sync_effect()?);
                return Ok(side_effects);
            }
            let mut deferred = Vec::new();
            if self.safety.current_view() > before.current_view() {
                deferred.push(DeferredEffect::ArmViewTimer);
            }
            deferred.push(DeferredEffect::RequestTcHighQcSync);
            let mut effects = self.persist(deferred)?;
            effects.extend(side_effects);
            return Ok(effects);
        }

        if self.safety != before {
            let mut deferred = vec![DeferredEffect::ArmViewTimer];
            if self.safety.pending_finalize().is_some() && before.pending_finalize().is_none() {
                deferred.push(DeferredEffect::Finalize);
            } else if self.safety.pending_standalone_qc_sync().is_some() {
                deferred.push(DeferredEffect::RequestStandaloneQcSync);
            }
            let mut effects = self.persist(deferred)?;
            effects.extend(side_effects);
            Ok(effects)
        } else if self.safety.pending_standalone_qc_sync().is_some() {
            side_effects.push(self.standalone_qc_sync_effect()?);
            Ok(side_effects)
        } else {
            Ok(side_effects)
        }
    }

    /// Runs the authenticated TC state transition without choosing a
    /// persistence boundary. This lets a first-arrival proposal carrier combine
    /// a ready TC transition with dependent-child admission atomically, while
    /// direct ingress and pending-TC recovery persist through the wrapper above.
    fn apply_authenticated_tc<V: SignatureVerifier>(
        &mut self,
        certificate: &TimeoutCertificateV0,
        verifier: &V,
    ) -> Result<AuthenticatedTcOutcome> {
        let pending = PendingTcHighQcSync::from_timeout_certificate(certificate.clone())?;
        if let Some(existing) = self.safety.pending_tc_high_qc_sync() {
            if existing != &pending {
                return Err(CoreError::ConflictingTcHighQcSyncTarget);
            }
        }

        self.safety
            .set_current_view(certificate.timed_out_view().checked_next()?);

        // TC verification learns every referenced ordinary QC, not only the
        // deterministic maximum. Delay all §6 QC processing until every
        // referenced block/witness/payload is ready; otherwise processing only
        // the selected high QC could miss a lock or finality transition carried
        // by a lower-view referenced QC.
        let referenced_qcs = ordinary_qcs_in_processing_order(certificate);
        let Some(staged) = self.stage_tc_referenced_qcs(&referenced_qcs, verifier)? else {
            if self.safety.pending_tc_high_qc_sync().is_none() {
                self.safety.set_pending_tc_high_qc_sync(Some(pending));
            }
            return Ok(AuthenticatedTcOutcome::MissingReferences);
        };
        *self = staged;
        self.safety.set_pending_tc_high_qc_sync(None);
        self.drain_ready_pending_standalone_qcs(verifier)?;
        Ok(AuthenticatedTcOutcome::Complete)
    }

    fn verify_ordinary_qc<V: SignatureVerifier>(
        &self,
        certificate: &QuorumCertificate,
        verifier: &V,
    ) -> Result<()> {
        self.require_epoch(certificate.epoch())?;
        if certificate.view().get() == 0 || certificate.height().get() == 0 {
            return Err(CoreError::InvalidOrdinaryCertificate);
        }
        self.require_pre_checkpoint_height(certificate.height())?;
        certificate.verify(self.config.validator_set(), verifier)?;
        Ok(())
    }

    fn verify_qc_reference<V: SignatureVerifier>(
        &self,
        reference: &QcReferenceV0,
        verifier: &V,
    ) -> Result<()> {
        match reference {
            QcReferenceV0::Ordinary(certificate) => self.verify_ordinary_qc(certificate, verifier),
            QcReferenceV0::Synthetic(synthetic) => match synthetic.as_ref() {
                ContextAuthorizedQcV0::Genesis(anchor) => {
                    anchor.matches_trusted_set(self.config.validator_set())?;
                    Ok(())
                }
                ContextAuthorizedQcV0::Epoch(_) => Err(CoreError::UnsupportedEpochAnchor),
            },
        }
    }

    fn qc_is_ready_for_adoption(&self, certificate: &QuorumCertificate) -> Result<bool> {
        if self.qc_is_durably_subsumed(certificate)? {
            return Ok(true);
        }
        let finalized = self.safety.finalized();
        if self.payload_is_deterministically_invalid(certificate.block_id()) {
            return Err(CoreError::ConflictingCertificate);
        }
        match self.blocks.validate_certificate_binding(certificate) {
            Ok(()) => {}
            Err(CoreError::MissingBlock(_)) => return Ok(false),
            Err(error) => return Err(error),
        }
        match self.blocks.validated_ancestry(
            certificate.block_id(),
            finalized,
            self.config.max_block_time_step_ms(),
        ) {
            Ancestry::Descends => Ok(true),
            Ancestry::Unknown => Ok(false),
            Ancestry::Conflicts => Err(CoreError::ConflictingCertificate),
        }
    }

    /// A verified QC at or below the irreversible finalized height can no
    /// longer affect high-QC, lock, or finality and its pruned block need not
    /// be reconstructed. Network ingress must observe same-view QC conflicts
    /// before calling this classifier. At the finalized height, a different
    /// block from another view is therefore harmless historical competition,
    /// while the finalized block with mismatched coordinates is malformed.
    fn qc_is_durably_subsumed(&self, certificate: &QuorumCertificate) -> Result<bool> {
        let finalized = self.safety.finalized();
        if certificate.block_id() == finalized.block_id() {
            return if certificate.height() == finalized.height()
                && certificate.view() == finalized.view()
            {
                Ok(true)
            } else {
                Err(CoreError::ConflictingCertificate)
            };
        }
        if certificate.height() <= finalized.height() {
            return Ok(true);
        }
        Ok(false)
    }

    /// Evaluates a complete TC reference table on a private core snapshot.
    ///
    /// Readiness is intentionally re-evaluated after each ascending QC: a
    /// lower-view three-chain may advance finality and thereby make a later
    /// same-height competing QC durably subsumed. If any later reference is
    /// still unavailable, discarding the snapshot prevents partial lock,
    /// finality, or pruning changes from escaping before the full TC can be
    /// processed atomically.
    fn stage_tc_referenced_qcs<V: SignatureVerifier>(
        &self,
        referenced_qcs: &[QuorumCertificate],
        verifier: &V,
    ) -> Result<Option<Self>> {
        let mut staged = self.transactional_clone_v0();
        for certificate in referenced_qcs {
            if !staged.qc_is_ready_for_adoption(certificate)? {
                return Ok(None);
            }
            staged.process_verified_ready_qc(certificate, verifier)?;
        }
        Ok(Some(staged))
    }

    fn try_complete_pending_tc_high_qc_sync<V: SignatureVerifier>(
        &mut self,
        verifier: &V,
    ) -> Result<Vec<Effect>> {
        let Some(pending) = self.safety.pending_tc_high_qc_sync().cloned() else {
            return Ok(Vec::new());
        };
        let referenced_qcs = ordinary_qcs_in_processing_order(pending.timeout_certificate());
        let Some(staged) = self.stage_tc_referenced_qcs(&referenced_qcs, verifier)? else {
            return Ok(vec![self.tc_high_qc_sync_effect()?]);
        };

        let before = self.safety.clone();
        *self = staged;
        self.safety
            .set_current_view(pending.timed_out_view().checked_next()?);
        self.safety.set_pending_tc_high_qc_sync(None);
        self.drain_ready_pending_standalone_qcs(verifier)?;
        let mut deferred = vec![DeferredEffect::ArmViewTimer];
        if self.safety.pending_finalize().is_some() && before.pending_finalize().is_none() {
            deferred.push(DeferredEffect::Finalize);
        } else if self.safety.pending_standalone_qc_sync().is_some() {
            deferred.push(DeferredEffect::RequestStandaloneQcSync);
        }
        self.persist(deferred)
    }

    fn remember_pending_standalone_qc(&mut self, certificate: QuorumCertificate) -> Result<bool> {
        let mut pending =
            self.safety
                .pending_standalone_qc_sync()
                .cloned()
                .ok_or(CoreError::InvalidRecovery(
                    "standalone QC backlog has no active target",
                ))?;
        for existing in core::iter::once(pending.active()).chain(pending.backlog()) {
            if same_qc_coordinates(existing, &certificate) {
                return Ok(false);
            }
            if existing.block_id() == certificate.block_id() {
                return Err(CoreError::ConflictingCertificate);
            }
        }
        if pending.backlog().len().saturating_add(1) >= self.config.max_observed_messages() {
            return Err(CoreError::TooManyPendingStandaloneQcs);
        }
        let mut backlog = pending.backlog().to_vec();
        backlog.push(certificate);
        backlog.sort_by_key(qc_order_key);
        pending.set_backlog(backlog);
        self.safety.set_pending_standalone_qc_sync(Some(pending));
        Ok(true)
    }

    fn try_complete_pending_standalone_qc_sync<V: SignatureVerifier>(
        &mut self,
        verifier: &V,
    ) -> Result<Vec<Effect>> {
        if self.safety.pending_tc_high_qc_sync().is_some() {
            return Ok(vec![self.tc_high_qc_sync_effect()?]);
        }
        if self.safety.pending_standalone_qc_sync().is_none() {
            return Ok(Vec::new());
        }

        let before = self.safety.clone();
        if !self.drain_ready_pending_standalone_qcs(verifier)? {
            return Ok(vec![self.standalone_qc_sync_effect()?]);
        }

        let mut deferred = vec![DeferredEffect::ArmViewTimer];
        if self.safety.pending_finalize().is_some() && before.pending_finalize().is_none() {
            deferred.push(DeferredEffect::Finalize);
        } else if self.safety.pending_standalone_qc_sync().is_some() {
            deferred.push(DeferredEffect::RequestStandaloneQcSync);
        }
        self.persist(deferred)
    }

    /// Atomically normalizes every standalone target that no longer needs an
    /// external replay. A TC or another ready certificate path may have made
    /// several queued QCs locally processable, and a finality advance may have
    /// subsumed entries anywhere in the queue. Draining the maximal ready
    /// prefix here prevents an already-local or below-finality target from
    /// producing an empty replay followed by the identical request forever.
    fn drain_ready_pending_standalone_qcs<V: SignatureVerifier>(
        &mut self,
        verifier: &V,
    ) -> Result<bool> {
        let mut changed = self.discard_durably_subsumed_standalone_qcs()?;
        while let Some(pending) = self.safety.pending_standalone_qc_sync().cloned() {
            if !self.qc_is_ready_for_adoption(pending.active())? {
                break;
            }

            self.process_verified_ready_qc(pending.active(), verifier)?;
            let mut backlog = pending.backlog().to_vec();
            if backlog.is_empty() {
                self.safety.set_pending_standalone_qc_sync(None);
            } else {
                let next = backlog.remove(0);
                self.safety.set_pending_standalone_qc_sync(Some(
                    PendingStandaloneQcSync::from_persisted_parts(next, backlog),
                ));
            }
            changed = true;
            changed |= self.discard_durably_subsumed_standalone_qcs()?;
        }
        Ok(changed)
    }

    fn discard_durably_subsumed_standalone_qcs(&mut self) -> Result<bool> {
        let Some(pending) = self.safety.pending_standalone_qc_sync().cloned() else {
            return Ok(false);
        };
        let mut retained = Vec::new();
        for certificate in
            core::iter::once(pending.active().clone()).chain(pending.backlog().iter().cloned())
        {
            if !self.qc_is_durably_subsumed(&certificate)? {
                retained.push(certificate);
            }
        }
        if retained.len() == pending.backlog().len().saturating_add(1) {
            return Ok(false);
        }
        if retained.is_empty() {
            self.safety.set_pending_standalone_qc_sync(None);
        } else {
            let active = retained.remove(0);
            self.safety.set_pending_standalone_qc_sync(Some(
                PendingStandaloneQcSync::from_persisted_parts(active, retained),
            ));
        }
        Ok(true)
    }

    fn register_validation(&mut self, proposal: &SignedProposalV0) -> Result<(ValidationId, bool)> {
        if let Some(id) = pending_validation_id(&self.pending_validations, proposal) {
            return Ok((id, false));
        }
        if self.payload_validation_slot_count()? >= self.config.max_observed_messages() {
            return Err(CoreError::TooManyPendingValidations);
        }
        let id = self.next_validation_id(proposal)?;
        self.insert_payload_validation_obligation(
            PayloadValidationRouteV0::Proposal,
            id,
            proposal,
        )?;
        self.pending_validations
            .insert(id, PendingPayloadValidationV0::new(proposal.clone()));
        Ok((id, true))
    }

    fn payload_validation_completion(
        &self,
        route: PayloadValidationRouteV0,
        id: ValidationId,
    ) -> Option<&DurablePayloadValidationCompletionV0> {
        let key = (route, id);
        self.safety
            .payload_validation_completions()
            .binary_search_by_key(&key, DurablePayloadValidationCompletionV0::key)
            .ok()
            .map(|index| &self.safety.payload_validation_completions()[index])
    }

    fn record_payload_validation_completion(
        &mut self,
        route: PayloadValidationRouteV0,
        id: ValidationId,
        result: PayloadValidationResult,
    ) -> Result<()> {
        let durable_result = DurablePayloadValidationResultV1::from_live(result);
        for previous in self
            .safety
            .payload_validation_completions()
            .iter()
            .filter(|completion| completion.id().block_id() == id.block_id())
        {
            if matches!(
                (previous.result(), durable_result),
                (
                    DurablePayloadValidationResultV1::Valid {
                        commitments: first_commitments,
                        artifact_ref: first_artifact,
                    },
                    DurablePayloadValidationResultV1::Valid {
                        commitments: second_commitments,
                        artifact_ref: second_artifact,
                    }
                ) if first_commitments != second_commitments
                    || first_artifact.overlay() != second_artifact.overlay()
            ) {
                return Err(CoreError::ConflictingPayloadValidation(id.block_id()));
            }
        }
        if self
            .safety
            .payload_validation_completions()
            .iter()
            .any(|completion| completion.id() == id)
        {
            return Err(CoreError::InvalidRecovery(
                "payload validation completion was duplicated or reused across routes",
            ));
        }
        if self.payload_validation_slot_count()? >= self.config.max_observed_messages() {
            return Err(CoreError::InvalidRecovery(
                "payload validation completion has no pre-reserved durable slot",
            ));
        }
        let key = (route, id);
        let first_recorded_revision =
            self.safety
                .revision()
                .checked_add(1)
                .ok_or(CoreError::ArithmeticOverflow(
                    "payload validation completion revision",
                ))?;
        let mut completions = self.safety.payload_validation_completions().to_vec();
        let index = completions
            .binary_search_by_key(&key, DurablePayloadValidationCompletionV0::key)
            .unwrap_or_else(|index| index);
        completions.insert(
            index,
            DurablePayloadValidationCompletionV0::new(
                route,
                id,
                durable_result,
                first_recorded_revision,
            ),
        );
        self.safety.set_payload_validation_completions(completions);
        Ok(())
    }

    fn record_payload_terminal_fact(
        &mut self,
        block_id: BlockId,
        result: PayloadValidationResult,
    ) -> Result<TerminalFactTransition> {
        let (terminal, valid_overlay) = match result {
            PayloadValidationResult::Valid(valid) => (
                PayloadTerminalResult::Valid,
                Some(valid.artifact_ref().overlay()),
            ),
            PayloadValidationResult::DeterministicallyInvalid => {
                (PayloadTerminalResult::DeterministicallyInvalid, None)
            }
            PayloadValidationResult::Unavailable => {
                return Ok(TerminalFactTransition::NotTerminal);
            }
        };
        if self
            .safety
            .payload_validation_completions()
            .iter()
            .filter(|completion| completion.id().block_id() == block_id)
            .filter_map(|completion| match completion.result() {
                DurablePayloadValidationResultV1::Valid { .. } => {
                    Some(PayloadTerminalResult::Valid)
                }
                DurablePayloadValidationResultV1::DeterministicallyInvalid => {
                    Some(PayloadTerminalResult::DeterministicallyInvalid)
                }
                DurablePayloadValidationResultV1::Unavailable => None,
            })
            .any(|previous| previous != terminal)
        {
            return Ok(TerminalFactTransition::Conflicting);
        }
        let mut facts = self.safety.payload_terminal_facts().to_vec();
        match facts.binary_search_by_key(&block_id, |fact| fact.block_id()) {
            Ok(index) if facts[index].result() == terminal => {
                if facts[index].valid_overlay() == valid_overlay {
                    return Ok(TerminalFactTransition::Repeated);
                }
                return Err(CoreError::ConflictingPayloadValidation(block_id));
            }
            Ok(_) => return Ok(TerminalFactTransition::Conflicting),
            Err(_) => {}
        }

        let maximum = self.config.max_observed_messages();
        if facts.len() >= maximum {
            // Prefer forgetting an uncertified/non-anchor cache entry. This
            // keeps every currently safety-relevant fact stable across ordinary
            // block-tree eviction while preserving a strict durable bound.
            let protected = durable_payload_fact_blocks(&self.safety);
            let victim = facts
                .iter()
                .enumerate()
                .filter(|(_, fact)| !protected.contains(&fact.block_id()))
                .min_by_key(|(_, fact)| (fact.first_recorded_revision(), fact.block_id()))
                .map(|(index, _)| index)
                .ok_or(CoreError::PayloadTerminalFactCacheFull)?;
            facts.remove(victim);
        }
        let index = facts
            .binary_search_by_key(&block_id, |fact| fact.block_id())
            .unwrap_or_else(|index| index);
        let first_recorded_revision =
            self.safety
                .revision()
                .checked_add(1)
                .ok_or(CoreError::ArithmeticOverflow(
                    "payload terminal fact revision",
                ))?;
        let fact = match valid_overlay {
            Some(overlay) => PayloadTerminalFact::new_valid(overlay, first_recorded_revision),
            None => PayloadTerminalFact::new_deterministically_invalid(
                block_id,
                first_recorded_revision,
            ),
        };
        facts.insert(index, fact);
        self.safety.set_payload_terminal_facts(facts);
        Ok(TerminalFactTransition::Inserted)
    }

    fn restore_durable_payload_fact(&mut self, block_id: BlockId) -> Result<()> {
        let Some(result) = self.safety.payload_terminal_result(block_id) else {
            return Ok(());
        };
        match result {
            // A durable Valid fact detects cross-restart terminal conflicts,
            // but the current schema does not retain the canonical body,
            // authenticated parent state, or frozen runtime handle. A newly
            // sourced body must therefore cross the host boundary again before
            // the volatile tree becomes vote-ready.
            PayloadTerminalResult::Valid => return Ok(()),
            PayloadTerminalResult::DeterministicallyInvalid => {}
        }
        if self.blocks.record_deterministically_invalid(block_id)?
            == PayloadTransition::ConflictingTerminalResult
        {
            return Err(CoreError::InvalidRecovery(
                "durable payload fact conflicts with the volatile block tree",
            ));
        }
        Ok(())
    }

    fn payload_is_deterministically_invalid(&self, block_id: BlockId) -> bool {
        self.safety.payload_terminal_result(block_id)
            == Some(PayloadTerminalResult::DeterministicallyInvalid)
            || self.blocks.payload_is_invalid(block_id)
    }

    fn handle_resolved_validation(
        &mut self,
        route: PayloadValidationRouteV0,
        id: ValidationId,
        result: PayloadValidationResult,
    ) -> Result<Option<Vec<Effect>>> {
        if self
            .safety
            .payload_validation_completions()
            .iter()
            .any(|completion| completion.id() == id && completion.route() != route)
        {
            return Err(CoreError::InvalidRecovery(
                "payload validation callback route differs from its durable completion",
            ));
        }
        let Some(previous) = self
            .payload_validation_completion(route, id)
            .map(DurablePayloadValidationCompletionV0::result)
        else {
            return Ok(None);
        };
        if previous.matches_live(result) {
            return Ok(Some(Vec::new()));
        }
        let terminal_conflict = matches!(
            (previous, result),
            (
                DurablePayloadValidationResultV1::Valid { .. },
                PayloadValidationResult::DeterministicallyInvalid
            ) | (
                DurablePayloadValidationResultV1::DeterministicallyInvalid,
                PayloadValidationResult::Valid(_)
            )
        );
        if terminal_conflict {
            return self
                .persist_payload_safety_halt(SafetyHalt::conflicting_payload_validation(
                    id.block_id(),
                ))
                .map(Some);
        }
        Err(CoreError::ConflictingPayloadValidation(id.block_id()))
    }

    fn validate_payload_capability(
        id: ValidationId,
        result: PayloadValidationResult,
    ) -> Result<()> {
        let Some(commitments) = result.commitments() else {
            return Ok(());
        };
        let artifact_ref =
            result
                .artifact_ref()
                .ok_or(CoreError::ValidationCapabilityMismatch {
                    expected: id.block_id(),
                    received: commitments.block_id(),
                })?;
        if commitments.block_id() != id.block_id()
            || artifact_ref.overlay().block_id() != id.block_id()
        {
            return Err(CoreError::ValidationCapabilityMismatch {
                expected: id.block_id(),
                received: if commitments.block_id() != id.block_id() {
                    commitments.block_id()
                } else {
                    artifact_ref.overlay().block_id()
                },
            });
        }
        Ok(())
    }

    fn validate_payload_artifact_parent(
        proposal: &SignedProposalV0,
        result: PayloadValidationResult,
    ) -> Result<()> {
        let Some(artifact_ref) = result.artifact_ref() else {
            return Ok(());
        };
        let block_id = proposal.block().id();
        let overlay = artifact_ref.overlay();
        if overlay.block_id() != block_id
            || overlay.parent_block_id() != proposal.block().header().parent_id()
        {
            return Err(CoreError::ConflictingPayloadValidation(block_id));
        }
        Ok(())
    }

    fn validate_durable_payload_completion(
        id: ValidationId,
        result: DurablePayloadValidationResultV1,
    ) -> Result<()> {
        let Some(commitments) = result.commitments() else {
            return Ok(());
        };
        let artifact_ref =
            result
                .artifact_ref()
                .ok_or(CoreError::ValidationCapabilityMismatch {
                    expected: id.block_id(),
                    received: commitments.block_id(),
                })?;
        if commitments.block_id() != id.block_id()
            || artifact_ref.overlay().block_id() != id.block_id()
        {
            return Err(CoreError::ValidationCapabilityMismatch {
                expected: id.block_id(),
                received: if commitments.block_id() != id.block_id() {
                    commitments.block_id()
                } else {
                    artifact_ref.overlay().block_id()
                },
            });
        }
        Ok(())
    }

    fn register_sync_validation(
        &mut self,
        proposal: &SignedProposalV0,
    ) -> Result<(ValidationId, bool)> {
        if let Some(id) = pending_validation_id(&self.pending_sync_validations, proposal) {
            return Ok((id, false));
        }
        if self.payload_validation_slot_count()? >= self.config.max_observed_messages() {
            return Err(CoreError::TooManyPendingValidations);
        }
        let id = self.next_validation_id(proposal)?;
        self.insert_payload_validation_obligation(PayloadValidationRouteV0::Synced, id, proposal)?;
        self.pending_sync_validations
            .insert(id, PendingPayloadValidationV0::new(proposal.clone()));
        Ok((id, true))
    }

    fn next_validation_id(&mut self, proposal: &SignedProposalV0) -> Result<ValidationId> {
        self.next_validation_generation =
            core::cmp::max(self.next_validation_generation, self.safety.revision())
                .checked_add(1)
                .ok_or(CoreError::ArithmeticOverflow("validation generation"))?;
        Ok(ValidationId::new(
            proposal.block().id(),
            proposal.block().header().view(),
            self.next_validation_generation,
        ))
    }

    fn insert_payload_validation_obligation(
        &mut self,
        route: PayloadValidationRouteV0,
        id: ValidationId,
        proposal: &SignedProposalV0,
    ) -> Result<()> {
        let parent = self.payload_validation_parent(id, proposal.block())?;
        let first_recorded_revision =
            self.safety
                .revision()
                .checked_add(1)
                .ok_or(CoreError::ArithmeticOverflow(
                    "payload validation obligation revision",
                ))?;
        let obligation = DurablePayloadValidationObligationV0::new(
            route,
            id,
            proposal.clone(),
            parent,
            first_recorded_revision,
        );
        let mut obligations = self.safety.payload_validation_obligations().to_vec();
        let aggregate_resource_size = obligations
            .iter()
            .chain(core::iter::once(&obligation))
            .try_fold(0usize, |aggregate, obligation| {
                aggregate
                    .checked_add(Self::payload_validation_obligation_resource_size_v0(
                        obligation,
                    )?)
                    .ok_or(CoreError::ArithmeticOverflow(
                        "payload validation obligation resource bytes",
                    ))
            })?;
        let maximum = self
            .config
            .consensus_parameters()
            .max_consensus_message_bytes() as usize;
        if aggregate_resource_size > maximum {
            return Err(CoreError::PayloadValidationResourceTooLarge {
                actual: aggregate_resource_size,
                maximum,
            });
        }
        let index =
            match obligations.binary_search_by_key(&id, DurablePayloadValidationObligationV0::id) {
                Ok(_) => {
                    return Err(CoreError::InvalidRecovery(
                        "payload validation obligation was duplicated",
                    ));
                }
                Err(index) => index,
            };
        obligations.insert(index, obligation);
        self.safety.set_payload_validation_obligations(obligations);
        Ok(())
    }

    /// Computes one deterministic, process-local resource weight for the
    /// complete durable obligation. This is not a wire encoding or a new
    /// consensus-validity size: the fixed frames merely ensure that every
    /// retained authority-bearing field contributes to the bounded
    /// SafetyState footprint.
    fn payload_validation_obligation_resource_size_v0(
        obligation: &DurablePayloadValidationObligationV0,
    ) -> Result<usize> {
        // route u8 + ValidationId (BlockId + view + generation) + proposal
        // frame + parent tip (height + view + BlockId + timestamp) + parent
        // provenance + exact-header presence + first-recorded revision.
        const FIXED_BYTES: usize = 1 + (32 + 8 + 8) + 4 + (8 + 8 + 32 + 8) + 1 + 1 + 8;
        let mut size = obligation
            .proposal()
            .durable_validation_resource_size_v0()?
            .checked_add(FIXED_BYTES)
            .ok_or(CoreError::ArithmeticOverflow(
                "payload validation obligation resource bytes",
            ))?;
        if let Some(header) = obligation.parent().exact_header() {
            let header_size = header.try_cev0_bytes()?.len();
            size = size
                .checked_add(4)
                .and_then(|size| size.checked_add(header_size))
                .ok_or(CoreError::ArithmeticOverflow(
                    "payload validation obligation parent header bytes",
                ))?;
        }
        if obligation
            .parent()
            .authenticated_genesis_application_parent_v0()
            .is_some()
        {
            // Closed carrier tag + block ID + timestamp + state version/root
            // + descriptor/profile references.
            size = size.checked_add(1 + 32 + 8 + 8 + 32 + 32 + 32).ok_or(
                CoreError::ArithmeticOverflow(
                    "payload validation obligation genesis application parent bytes",
                ),
            )?;
        }
        if matches!(
            obligation.parent().provenance(),
            crate::PayloadValidationParentProvenanceV0::Speculative(_)
        ) {
            size = size
                .checked_add(32 + 32 + 32)
                .ok_or(CoreError::ArithmeticOverflow(
                    "payload validation obligation parent overlay bytes",
                ))?;
        }
        Ok(size)
    }

    fn require_payload_validation_obligation(
        &self,
        route: PayloadValidationRouteV0,
        id: ValidationId,
        proposal: &SignedProposalV0,
    ) -> Result<()> {
        let obligations = self.safety.payload_validation_obligations();
        let index = obligations
            .binary_search_by_key(&id, DurablePayloadValidationObligationV0::id)
            .map_err(|_| {
                CoreError::InvalidRecovery(
                    "a volatile payload validation has no durable obligation",
                )
            })?;
        let obligation = &obligations[index];
        if obligation.route() != route || obligation.proposal() != proposal {
            return Err(CoreError::InvalidRecovery(
                "a payload validation callback differs from its durable route or proposal",
            ));
        }
        Ok(())
    }

    fn remove_payload_validation_obligation(
        &mut self,
        route: PayloadValidationRouteV0,
        id: ValidationId,
    ) -> Result<()> {
        let mut obligations = self.safety.payload_validation_obligations().to_vec();
        let index = obligations
            .binary_search_by_key(&id, DurablePayloadValidationObligationV0::id)
            .map_err(|_| {
                CoreError::InvalidRecovery("payload validation cleanup has no durable obligation")
            })?;
        if obligations[index].route() != route {
            return Err(CoreError::InvalidRecovery(
                "payload validation cleanup used the wrong durable route",
            ));
        }
        obligations.remove(index);
        self.safety.set_payload_validation_obligations(obligations);
        Ok(())
    }

    fn ensure_payload_validation_cleanup_barrier(
        &mut self,
        effects: Vec<Effect>,
    ) -> Result<Vec<Effect>> {
        if let Some(pending) = &self.pending_persistence {
            return match effects.as_slice() {
                [Effect::PersistSafetyState(request)]
                    if request.barrier() == pending.barrier && request.state() == &self.safety =>
                {
                    Ok(effects)
                }
                _ => Err(CoreError::InvalidRecovery(
                    "payload validation cleanup exposed a non-persistence effect beside an active barrier",
                )),
            };
        }
        let mut deferred = Vec::with_capacity(effects.len());
        for effect in effects {
            match effect {
                Effect::RequestTcHighQcSync { .. } => {
                    deferred.push(DeferredEffect::RequestTcHighQcSync);
                }
                Effect::RequestStandaloneQcSync { .. } => {
                    deferred.push(DeferredEffect::RequestStandaloneQcSync);
                }
                _ => {
                    return Err(CoreError::InvalidRecovery(
                        "payload validation cleanup exposed an effect before persistence",
                    ));
                }
            }
        }
        self.persist(deferred)
    }

    fn ensure_native_valid_cleanup_barrier_v0(
        &mut self,
        effects: Vec<Effect>,
    ) -> Result<Vec<Effect>> {
        let effects = self.ensure_payload_validation_cleanup_barrier(effects)?;
        self.bind_native_valid_post_ack_manifest_v0(effects)
    }

    fn observe_proposal(
        &mut self,
        proposal: &SignedProposalV0,
        authenticated_parent_timestamp_ms: u64,
    ) -> Result<Option<EquivocationEvidence>> {
        let header = proposal.block().header();
        let key = (header.epoch(), header.view(), proposal.proposer());
        if let Some(first) = self.observed_proposals.get(&key).cloned() {
            if first.proposal.conflicts_with(proposal) {
                return Ok(Some(EquivocationEvidence::proposal(
                    first.proposal,
                    proposal.clone(),
                    self.config.validator_set(),
                    None,
                    self.config.consensus_parameters(),
                    first.authenticated_parent_timestamp_ms,
                    authenticated_parent_timestamp_ms,
                )?));
            }
            return Ok(None);
        }
        bounded_insert(
            &mut self.observed_proposals,
            key,
            ObservedProposal {
                proposal: proposal.clone(),
                authenticated_parent_timestamp_ms,
            },
            self.config.max_observed_messages(),
        );
        Ok(None)
    }

    fn observe_vote(&mut self, vote: &Vote) -> Result<Option<EquivocationEvidence>> {
        let key = (vote.epoch(), vote.view(), vote.author());
        if let Some(first) = self.observed_votes.get(&key).cloned() {
            if first.conflicts_with(vote) {
                return Ok(Some(EquivocationEvidence::vote(
                    first,
                    vote.clone(),
                    self.config.validator_set(),
                )?));
            }
            return Ok(None);
        }
        bounded_insert(
            &mut self.observed_votes,
            key,
            vote.clone(),
            self.config.max_observed_messages(),
        );
        Ok(None)
    }

    fn observe_timeout(&mut self, vote: &TimeoutVote) -> Result<Option<EquivocationEvidence>> {
        let key = (vote.epoch(), vote.view(), vote.author());
        if let Some(first) = self.observed_timeouts.get(&key).cloned() {
            if first.conflicts_with(vote) {
                return Ok(Some(EquivocationEvidence::timeout(
                    first,
                    vote.clone(),
                    self.config.validator_set(),
                )?));
            }
            return Ok(None);
        }
        bounded_insert(
            &mut self.observed_timeouts,
            key,
            vote.clone(),
            self.config.max_observed_messages(),
        );
        Ok(None)
    }

    fn observe_timeout_certificate(
        &mut self,
        certificate: &TimeoutCertificateV0,
    ) -> Result<Vec<EquivocationEvidence>> {
        let mut evidence = Vec::new();
        for entry in certificate.entries() {
            let vote = TimeoutVote::new(
                certificate.chain_id(),
                certificate.protocol_version(),
                certificate.epoch(),
                certificate.timed_out_view(),
                certificate.validator_set_hash(),
                entry.high_qc(),
                entry.signer_id(),
                *entry.signature(),
                self.config.validator_set(),
            )?;
            if let Some(conflict) = self.observe_timeout(&vote)? {
                evidence.push(conflict);
            }
        }
        Ok(evidence)
    }

    fn observe_qc(&mut self, certificate: &QuorumCertificate) -> Result<Option<crate::SafetyHalt>> {
        // `durable_qcs()` covers contextual references (high/lock, pending
        // syncs, anchors, and finality proofs).  Schema-v13 also retains the
        // bounded ordinary observation set specifically for same-view
        // conflict continuity; it is not a contextual reference and must be
        // checked explicitly before a post-restart ingress can replace or
        // ignore its witness.
        for durable in self
            .durable_qcs()
            .into_iter()
            .chain(self.safety.durable_observed_qcs().iter())
        {
            if durable.view() == certificate.view() && durable.block_id() != certificate.block_id()
            {
                return Ok(Some(crate::SafetyHalt::from_conflicting_qcs(
                    durable.clone(),
                    certificate.clone(),
                )?));
            }
        }
        if let Some(first) = self.observed_qcs.get(&certificate.view()).cloned() {
            if first.block_id() != certificate.block_id() {
                return Ok(Some(crate::SafetyHalt::from_conflicting_qcs(
                    first,
                    certificate.clone(),
                )?));
            }
            if certificate.id() > first.id() {
                self.observed_qcs
                    .insert(certificate.view(), certificate.clone());
            }
            return Ok(None);
        }
        // Historical certificates at or below finalized height are already
        // covered by the durable finalized prefix.  They still pass through
        // the conflict checks above (including schema-v13 observations), and
        // the first witness is retained in the bounded cache.  That witness
        // is safety evidence: the apply wrapper must persist it before the
        // ingress returns, otherwise a crash between two same-view carriers
        // would erase the only pair from which a halt can be reconstructed.
        // A full cache may still evict a lowest-view entry which finality now
        // subsumes.  If no such safe prefix exists, admission is fail-closed;
        // silently dropping the new witness would reintroduce the exact
        // cross-restart evidence hole schema-v13 closes.
        let durably_subsumed = self.qc_is_durably_subsumed(certificate)?;
        if durably_subsumed {
            let maximum = self.config.max_observed_messages();
            while self.observed_qcs.len() >= maximum {
                let Some((&oldest_view, oldest)) = self.observed_qcs.first_key_value() else {
                    return Err(CoreError::ObservedQcRetentionFull);
                };
                if !self.qc_is_durably_subsumed(oldest)? {
                    return Err(CoreError::ObservedQcRetentionFull);
                }
                self.observed_qcs.remove(&oldest_view);
            }
            self.observed_qcs
                .insert(certificate.view(), certificate.clone());
            return Ok(None);
        }

        // Unlike proposals/votes, an ordinary QC observation is safety
        // evidence: silently dropping an active lowest-view witness lets a
        // later same-view competitor arrive after restart without a pair to
        // halt on.  Only a lowest-view *prefix* which finality now subsumes
        // may be removed.  If that prefix is not available, reject the new
        // authenticated message and leave the Core unchanged (the public
        // step wrapper is transactional).
        let maximum = self.config.max_observed_messages();
        while self.observed_qcs.len() >= maximum {
            let Some((&oldest_view, oldest)) = self.observed_qcs.first_key_value() else {
                return Err(CoreError::ObservedQcRetentionFull);
            };
            if !self.qc_is_durably_subsumed(oldest)? {
                return Err(CoreError::ObservedQcRetentionFull);
            }
            self.observed_qcs.remove(&oldest_view);
        }
        self.observed_qcs
            .insert(certificate.view(), certificate.clone());
        Ok(None)
    }

    fn observed_qcs_needs_persistence_v0(&self) -> Result<bool> {
        let durable = self.safety.durable_observed_qcs();
        let changed = self.observed_qcs.len() != durable.len()
            || self
                .observed_qcs
                .iter()
                .zip(durable)
                .any(|((view, certificate), previous)| {
                    *view != previous.view() || certificate != previous
                });
        if !changed {
            return Ok(false);
        }

        // Every retained witness, including one below irreversible finality,
        // is part of the durable same-view conflict evidence.  Do not filter
        // "subsumed" entries here: doing so makes the first historical QC
        // volatile again and lets a crash erase the conflict pair.
        Ok(true)
    }

    fn snapshot_observed_qcs_v0(&mut self) {
        let certificates = self.observed_qcs.values().cloned().collect();
        self.safety.set_durable_observed_qcs(certificates);
    }

    fn learn_qc(&mut self, certificate: QuorumCertificate) -> Result<()> {
        self.require_descendant_of_finalized(&certificate)?;
        if certificate.block_id() != self.safety.finalized().block_id() {
            if self.payload_is_deterministically_invalid(certificate.block_id()) {
                return Err(CoreError::ConflictingCertificate);
            }
            if !self.blocks.payload_is_valid(certificate.block_id()) {
                return Err(CoreError::MissingBlock(certificate.block_id()));
            }
            let justify = self
                .blocks
                .justify_qc(certificate.block_id())
                .cloned()
                .ok_or(CoreError::MissingBlock(certificate.block_id()))?;
            self.reject_epoch_anchor(&justify)?;
            let justify_ref = justify.qc_ref();
            let locked_ref = self.safety.locked_qc().qc_ref();
            if justify_ref.view() == locked_ref.view()
                && justify_ref.block_id() != locked_ref.block_id()
            {
                return Err(CoreError::ConflictingCertificate);
            }
            if qc_order_key_ref(&justify) > qc_order_key_ref(self.safety.locked_qc()) {
                self.safety.set_locked_qc(justify);
            }
        }
        self.adopt_high_qc(certificate)
    }

    fn adopt_high_qc(&mut self, certificate: QuorumCertificate) -> Result<()> {
        self.require_descendant_of_finalized(&certificate)?;
        let current = self.safety.high_qc();
        let candidate = QcReferenceV0::ordinary(certificate);
        let candidate_ref = candidate.qc_ref();
        let current_ref = current.qc_ref();
        if candidate_ref.view() == current_ref.view()
            && candidate_ref.block_id() != current_ref.block_id()
        {
            return Err(CoreError::ConflictingCertificate);
        }
        if qc_order_key_ref(&candidate) > qc_order_key_ref(current) {
            self.safety.set_high_qc(candidate);
        }
        Ok(())
    }

    fn require_descendant_of_finalized(&self, certificate: &QuorumCertificate) -> Result<()> {
        let finalized = self.safety.finalized();
        if certificate.block_id() == finalized.block_id() {
            if certificate.height() == finalized.height() && certificate.view() == finalized.view()
            {
                return Ok(());
            }
            return Err(CoreError::ConflictingCertificate);
        }
        match self.blocks.validated_ancestry(
            certificate.block_id(),
            finalized,
            self.config.max_block_time_step_ms(),
        ) {
            Ancestry::Descends => Ok(()),
            Ancestry::Conflicts => Err(CoreError::ConflictingCertificate),
            Ancestry::Unknown => Err(CoreError::MissingBlock(certificate.block_id())),
        }
    }

    fn durable_qc_references(&self) -> Vec<&QcReferenceV0> {
        let mut references = vec![self.safety.high_qc(), self.safety.locked_qc()];
        if let Some(pending) = self.safety.pending_tc_high_qc_sync() {
            references.extend(pending.timeout_certificate().referenced_qcs());
        }
        if let Some(anchor) = self.safety.state_sync_anchor() {
            for certified in [
                anchor.proof().finalized_block(),
                anchor.proof().child(),
                anchor.proof().grandchild(),
            ] {
                references.push(certified.justify_qc());
                if let Some(timeout) = certified.timeout_certificate() {
                    references.extend(timeout.referenced_qcs());
                }
            }
        }
        for finalization in self.safety.finalization_queue().iter().chain(
            self.safety
                .last_finalization()
                .into_iter()
                .filter(|latest| self.safety.finalization_queue().last() != Some(*latest)),
        ) {
            let proof = finalization.proof();
            for certified in [proof.finalized_block(), proof.child(), proof.grandchild()] {
                references.push(certified.justify_qc());
                if let Some(timeout) = certified.timeout_certificate() {
                    references.extend(timeout.referenced_qcs());
                }
            }
        }
        references
    }

    fn durable_qcs(&self) -> Vec<&QuorumCertificate> {
        let mut certificates = Vec::new();
        certificates.extend(
            [self.safety.high_qc(), self.safety.locked_qc()]
                .into_iter()
                .filter_map(QcReferenceV0::as_ordinary),
        );
        if let Some(pending) = self.safety.pending_tc_high_qc_sync() {
            certificates.extend(
                pending
                    .timeout_certificate()
                    .referenced_qcs()
                    .iter()
                    .filter_map(QcReferenceV0::as_ordinary),
            );
        }
        if let Some(pending) = self.safety.pending_standalone_qc_sync() {
            certificates.extend(core::iter::once(pending.active()).chain(pending.backlog()));
        }
        if let Some(anchor) = self.safety.state_sync_anchor() {
            for certified in [
                anchor.proof().finalized_block(),
                anchor.proof().child(),
                anchor.proof().grandchild(),
            ] {
                certificates.push(certified.certifying_qc());
                if let Some(justify) = certified.justify_qc().as_ordinary() {
                    certificates.push(justify);
                }
                if let Some(timeout) = certified.timeout_certificate() {
                    certificates.extend(
                        timeout
                            .referenced_qcs()
                            .iter()
                            .filter_map(QcReferenceV0::as_ordinary),
                    );
                }
            }
        }
        for finalization in self.safety.finalization_queue().iter().chain(
            self.safety
                .last_finalization()
                .into_iter()
                .filter(|latest| self.safety.finalization_queue().last() != Some(*latest)),
        ) {
            let proof = finalization.proof();
            for certified in [proof.finalized_block(), proof.child(), proof.grandchild()] {
                certificates.push(certified.certifying_qc());
                if let Some(justify) = certified.justify_qc().as_ordinary() {
                    certificates.push(justify);
                }
                if let Some(timeout) = certified.timeout_certificate() {
                    certificates.extend(
                        timeout
                            .referenced_qcs()
                            .iter()
                            .filter_map(QcReferenceV0::as_ordinary),
                    );
                }
            }
        }
        certificates
    }

    /// Returns the strongest independently recoverable reference which names
    /// `block_id`. Volatile QCs are copied into the durable halt diagnostic so
    /// recovery never depends on the observation cache which saw them.
    fn invalid_payload_reference(&self, block_id: BlockId) -> Option<InvalidPayloadReference> {
        if let Some(certificate) = self
            .safety
            .pending_tc_high_qc_sync()
            .map(PendingTcHighQcSync::timeout_certificate)
            .filter(|certificate| {
                certificate
                    .referenced_qcs()
                    .iter()
                    .filter_map(QcReferenceV0::as_ordinary)
                    .any(|referenced| referenced.block_id() == block_id)
            })
        {
            return Some(InvalidPayloadReference::TimeoutCertificate(Box::new(
                certificate.clone(),
            )));
        }
        let certificate = self
            .durable_qcs()
            .into_iter()
            .chain(self.observed_qcs.values())
            .chain(self.safety.durable_observed_qcs().iter())
            .filter(|certificate| certificate.block_id() == block_id)
            .min_by_key(|certificate| qc_order_key(certificate))
            .cloned();
        if let Some(certificate) = certificate {
            return Some(InvalidPayloadReference::QuorumCertificate(Box::new(
                certificate,
            )));
        }
        match self.safety.pending_sign() {
            Some(
                intent @ SignIntent::Vote {
                    block_id: pending_block,
                    ..
                },
            ) if *pending_block == block_id => Some(InvalidPayloadReference::PendingVote(
                Box::new(intent.clone()),
            )),
            Some(SignIntent::Vote { .. }) | Some(SignIntent::TimeoutVote { .. }) | None => None,
        }
    }

    fn persist_certified_invalid_payload(
        &mut self,
        certificate: QuorumCertificate,
    ) -> Result<Vec<Effect>> {
        let block_id = certificate.block_id();
        let halt = SafetyHalt::deterministically_invalid_payload(
            block_id,
            InvalidPayloadReference::QuorumCertificate(Box::new(certificate)),
        )?;
        self.persist_payload_safety_halt(halt)
    }

    fn persist_proposal_invalid_payload(
        &mut self,
        proposal: &SignedProposalV0,
        certificate: QuorumCertificate,
    ) -> Result<Vec<Effect>> {
        let block_id = certificate.block_id();
        if let Some(timeout) = proposal
            .witness()
            .timeout_certificate()
            .filter(|timeout| {
                timeout
                    .referenced_qcs()
                    .iter()
                    .filter_map(QcReferenceV0::as_ordinary)
                    .any(|referenced| referenced.block_id() == block_id)
            })
            .cloned()
        {
            self.safety
                .set_current_view(timeout.timed_out_view().checked_next()?);
            let halt = SafetyHalt::deterministically_invalid_payload(
                block_id,
                InvalidPayloadReference::TimeoutCertificate(Box::new(timeout)),
            )?;
            return self.persist_payload_safety_halt(halt);
        }
        self.persist_certified_invalid_payload(certificate)
    }

    /// Cancels all dependent durable/volatile outboxes and crosses exactly one
    /// persistence barrier before exposing `SafetyHalted`. A late signer or
    /// application acknowledgement is subsequently rejected by the halt gate.
    fn persist_payload_safety_halt(&mut self, halt: SafetyHalt) -> Result<Vec<Effect>> {
        self.persist_safety_halt(halt)
    }

    fn persist_safety_halt(&mut self, halt: SafetyHalt) -> Result<Vec<Effect>> {
        self.safety.set_pending_sign(None);
        // Application finalizations which were already consensus-finalized
        // remain durable across a later safety halt. The halt suppresses their
        // emission, but must never erase or coalesce the ordered queue.
        self.safety.set_pending_tc_high_qc_sync(None);
        self.safety.set_pending_standalone_qc_sync(None);
        self.safety.set_safety_halt(Some(halt));
        self.awaiting_signature = false;
        self.replay_required = false;
        self.finalization_blocked_vote = None;
        self.pending_validations.clear();
        self.pending_sync_validations.clear();
        self.safety.set_payload_validation_obligations(Vec::new());
        self.persist(vec![DeferredEffect::SafetyHalted])
    }

    fn persist(&mut self, deferred: Vec<DeferredEffect>) -> Result<Vec<Effect>> {
        self.persist_with_safety_rules_shadow_transition(deferred, None)
    }

    fn persist_with_safety_rules_shadow_transition(
        &mut self,
        deferred: Vec<DeferredEffect>,
        safety_rules_shadow_transition: Option<InertSafetyTransitionV1>,
    ) -> Result<Vec<Effect>> {
        if self.pending_persistence.is_some() {
            return Err(CoreError::Busy("a safety-state write is already pending"));
        }
        self.snapshot_observed_qcs_v0();
        let barrier = self.safety.next_revision()?;
        self.pending_persistence = Some(PendingPersistence { barrier, deferred });
        Ok(vec![Effect::PersistSafetyState(
            crate::SafetyStatePersistenceV0::new(
                barrier,
                Box::new(self.safety.clone()),
                safety_rules_shadow_transition,
                None,
                None,
                Arc::clone(&self.persistence_affinity.0),
                CorePersistenceSealV0::new(),
            ),
        )])
    }

    /// Marks the one exact persistence request produced by a live Valid
    /// callback with Core's closed post-ack action manifest.
    ///
    /// Ordinary consensus, invalid, unavailable, cancellation, and recovery
    /// transitions deliberately retain `None` even when their deferred effect
    /// sequence happens to have the same shape.
    fn bind_native_valid_post_ack_manifest_v0(
        &self,
        mut effects: Vec<Effect>,
    ) -> Result<Vec<Effect>> {
        let pending = self
            .pending_persistence
            .as_ref()
            .ok_or(CoreError::InvalidRecovery(
                "native Valid callback has no persistence barrier",
            ))?;
        let action = NativeValidPostAckActionV0::from_deferred_v0(&pending.deferred).ok_or(
            CoreError::InvalidRecovery("native Valid callback has an unsupported post-ack action"),
        )?;
        match effects.as_mut_slice() {
            [Effect::PersistSafetyState(request)]
                if request.barrier() == pending.barrier && request.state() == &self.safety =>
            {
                request.bind_native_valid_post_ack_action_v0(action);
                Ok(effects)
            }
            _ => Err(CoreError::InvalidRecovery(
                "native Valid callback did not expose its exact persistence request",
            )),
        }
    }

    fn persist_native_valid_v0(&mut self, deferred: Vec<DeferredEffect>) -> Result<Vec<Effect>> {
        let effects = self.persist(deferred)?;
        self.bind_native_valid_post_ack_manifest_v0(effects)
    }

    fn persist_native_finalization_applied_v0(
        &mut self,
        readback: crate::ApplicationFinalizationApplyReadbackV0,
        predecessor: FinalizedTip,
        successor: FinalizedTip,
        deferred: Vec<DeferredEffect>,
        safety_rules_shadow_transition: Option<InertSafetyTransitionV1>,
    ) -> Result<Vec<Effect>> {
        let action = NativeFinalizationAppliedPostAckActionV0::from_deferred_v0(&deferred).ok_or(
            CoreError::InvalidRecovery(
                "application-finalization receipt has an unsupported post-ack action",
            ),
        )?;
        let mut effects = self.persist_with_safety_rules_shadow_transition(
            deferred,
            safety_rules_shadow_transition,
        )?;
        let pending = self
            .pending_persistence
            .as_ref()
            .ok_or(CoreError::InvalidRecovery(
                "application-finalization receipt has no persistence barrier",
            ))?;
        match effects.as_mut_slice() {
            [Effect::PersistSafetyState(request)] => {
                if request.barrier() != pending.barrier || request.state() != &self.safety {
                    return Err(CoreError::InvalidRecovery(
                        "application-finalization persistence request differs from Core state",
                    ));
                }
                request.bind_native_finalization_applied_v0(
                    NativeFinalizationAppliedPersistenceV0::new(
                        readback,
                        predecessor,
                        successor,
                        action,
                    ),
                );
                Ok(effects)
            }
            _ => Err(CoreError::InvalidRecovery(
                "application-finalization receipt did not expose its exact persistence request",
            )),
        }
    }

    fn signature_effect(&self, intent: &SignIntent) -> Result<Effect> {
        self.require_supported_sign_intent(intent)?;
        let canonical = self.canonical_sign_intent_for_legacy_v1(intent)?;
        if canonical.signing_root() != intent.signing_root() {
            return Err(CoreError::InvalidRecovery(
                "persisted sign intent root does not match its canonical preimage",
            ));
        }
        Ok(Effect::RequestSignature { intent: canonical })
    }

    fn tc_high_qc_sync_effect(&self) -> Result<Effect> {
        let pending = self
            .safety
            .pending_tc_high_qc_sync()
            .ok_or(CoreError::InvalidRecovery(
                "TC high-QC sync effect has no durable target",
            ))?;
        let mut target = None;
        for certificate in ordinary_qcs_in_processing_order(pending.timeout_certificate()) {
            if !self.qc_is_ready_for_adoption(&certificate)? {
                target = Some(QcRef::from(&certificate));
                break;
            }
        }
        let target = target.ok_or(CoreError::InvalidRecovery(
            "TC QC sync effect has no unready referenced QC",
        ))?;
        Ok(Effect::RequestTcHighQcSync {
            certificate_id: pending.certificate_id(),
            timed_out_view: pending.timed_out_view(),
            target,
            finalized: self.safety.finalized(),
        })
    }

    fn standalone_qc_sync_effect(&self) -> Result<Effect> {
        let pending =
            self.safety
                .pending_standalone_qc_sync()
                .ok_or(CoreError::InvalidRecovery(
                    "standalone QC sync effect has no durable target",
                ))?;
        Ok(Effect::RequestStandaloneQcSync {
            certificate_id: pending.active().id(),
            target: QcRef::from(pending.active()),
            finalized: self.safety.finalized(),
        })
    }

    fn finalize_effect(&self, proof_id: CertificateId) -> Result<Effect> {
        let durable = self
            .safety
            .pending_finalization()
            .ok_or(CoreError::UnexpectedFinalizationAck)?;
        if durable.proof_id() != proof_id || self.safety.pending_finalize() != Some(proof_id) {
            return Err(CoreError::UnexpectedFinalizationAck);
        }
        Ok(Effect::Finalize(Box::new(durable.clone())))
    }

    fn protected_blocks(&self) -> Vec<trnm_consensus_types::BlockId> {
        let mut protected = vec![
            self.safety.high_qc().qc_ref().block_id(),
            self.safety.locked_qc().qc_ref().block_id(),
            self.safety.finalized().block_id(),
        ];
        if let Some(pending) = self.safety.pending_tc_high_qc_sync() {
            protected.extend(
                pending
                    .timeout_certificate()
                    .referenced_qcs()
                    .iter()
                    .map(|reference| reference.qc_ref().block_id()),
            );
        }
        if let Some(pending) = self.safety.pending_standalone_qc_sync() {
            protected.extend(
                core::iter::once(pending.active())
                    .chain(pending.backlog())
                    .map(QuorumCertificate::block_id),
            );
        }
        if let Some(anchor) = self.safety.state_sync_anchor() {
            let proof = anchor.proof();
            protected.extend([
                proof.finalized_block().header().id(),
                proof.child().header().id(),
                proof.grandchild().header().id(),
            ]);
        }
        for finalization in self.safety.finalization_queue().iter().chain(
            self.safety
                .last_finalization()
                .into_iter()
                .filter(|latest| self.safety.finalization_queue().last() != Some(*latest)),
        ) {
            let proof = finalization.proof();
            protected.extend([
                proof.finalized_block().header().id(),
                proof.child().header().id(),
                proof.grandchild().header().id(),
            ]);
        }
        if let Some(SignIntent::Vote { block_id, .. }) = self.safety.pending_sign() {
            protected.push(*block_id);
        }
        if let Some(proposal) = &self.finalization_blocked_vote {
            protected.push(proposal.block().id());
        }
        if let Some(block_id) = self
            .safety
            .safety_halt()
            .and_then(SafetyHalt::payload_block_id)
        {
            protected.push(block_id);
        }
        protected.extend(
            self.pending_validations
                .keys()
                .map(|validation| validation.block_id()),
        );
        protected.extend(
            self.pending_sync_validations
                .keys()
                .map(|validation| validation.block_id()),
        );
        protected
    }

    fn replay_max_height(&self) -> u64 {
        core::cmp::max(
            self.safety.high_qc().qc_ref().height().get(),
            self.safety.locked_qc().qc_ref().height().get(),
        )
    }

    fn require_epoch(&self, epoch: Epoch) -> Result<()> {
        if epoch != self.safety.epoch() {
            return Err(CoreError::WrongEpoch {
                expected: self.safety.epoch(),
                received: epoch,
            });
        }
        Ok(())
    }

    fn active_epoch_geometry(&self) -> Result<EpochGeometryV0> {
        Ok(EpochGeometryV0::new(
            self.safety.epoch(),
            self.config.consensus_parameters(),
        )?)
    }

    /// The current core implements only the ordinary pre-checkpoint segment
    /// of epoch zero. Checkpoint, seal, and handoff authorization must remain
    /// unreachable until the full transition preimage and ancestry proof are
    /// authenticated atomically.
    fn require_pre_checkpoint_height(&self, height: Height) -> Result<()> {
        let checkpoint_height = self.active_epoch_geometry()?.checkpoint_height();
        if height >= checkpoint_height {
            return Err(CoreError::EpochBoundaryUnsupported {
                height,
                checkpoint_height,
            });
        }
        Ok(())
    }

    fn require_supported_proposal_header(&self, header: &BlockHeader) -> Result<()> {
        self.require_epoch(header.epoch())?;
        // Preserve the existing fail-closed classification for every
        // non-regular block kind. A regular header still cannot cross into the
        // heights reserved for the epoch-transition protocol.
        if header.block_kind() != BlockKind::Regular {
            return Err(CoreError::UnsupportedBlockKind);
        }
        self.require_pre_checkpoint_height(header.height())
    }

    fn require_supported_sign_intent(&self, intent: &SignIntent) -> Result<()> {
        match intent {
            SignIntent::Vote { height, .. } => self.require_pre_checkpoint_height(*height),
            SignIntent::TimeoutVote { high_qc, .. } => {
                self.require_pre_checkpoint_height(high_qc.height())
            }
        }
    }

    fn validate_epoch_boundary_fence(&self) -> Result<()> {
        self.require_pre_checkpoint_height(self.safety.finalized().height())?;

        // Include synthetic references here as well as the ordinary QCs below
        // so a decoded high/lock/finality record cannot evade the height fence
        // merely by changing its authorization variant.
        for reference in self.durable_qc_references() {
            self.require_pre_checkpoint_height(reference.qc_ref().height())?;
        }
        for certificate in self.durable_qcs() {
            self.require_pre_checkpoint_height(certificate.height())?;
        }
        for certificate in self.safety.durable_observed_qcs() {
            self.require_pre_checkpoint_height(certificate.height())?;
        }

        if let Some(intent) = self.safety.pending_sign() {
            self.require_supported_sign_intent(intent)?;
        }
        if let Some(halt) = self.safety.safety_halt() {
            match halt {
                SafetyHalt::ConflictingQuorumCertificates { first, second } => {
                    self.require_pre_checkpoint_height(first.height())?;
                    self.require_pre_checkpoint_height(second.height())?;
                }
                SafetyHalt::ConflictingPayloadValidation { .. } => {}
                SafetyHalt::DeterministicallyInvalidPayload { reference, .. } => match reference {
                    InvalidPayloadReference::QuorumCertificate(certificate) => {
                        self.require_pre_checkpoint_height(certificate.height())?;
                    }
                    InvalidPayloadReference::TimeoutCertificate(certificate) => {
                        self.require_epoch(certificate.epoch())?;
                        for referenced in certificate.referenced_qcs() {
                            self.reject_epoch_anchor(referenced)?;
                        }
                    }
                    InvalidPayloadReference::PendingVote(intent) => {
                        self.require_supported_sign_intent(intent)?;
                    }
                },
            }
        }
        Ok(())
    }

    fn validate_payload_validation_obligations<V: SignatureVerifier>(
        &self,
        verifier: &V,
        verify_durable_crypto: bool,
    ) -> Result<()> {
        let obligations = self.safety.payload_validation_obligations();
        if obligations.len() > self.config.max_observed_messages() {
            return Err(CoreError::InvalidRecovery(
                "durable payload validation obligations exceed the configured bound",
            ));
        }
        if obligations
            .windows(2)
            .any(|pair| pair[0].id() >= pair[1].id())
        {
            return Err(CoreError::InvalidRecovery(
                "durable payload validation obligations are not uniquely sorted by full id",
            ));
        }

        let mut aggregate_resource_bytes = 0usize;
        for obligation in obligations {
            let id = obligation.id();
            let proposal = obligation.proposal();
            let block = proposal.block();
            let header = block.header();
            if id.block_id() != block.id() || id.view() != header.view() {
                return Err(CoreError::InvalidRecovery(
                    "durable payload validation id differs from its signed proposal",
                ));
            }
            if obligation.first_recorded_revision() == 0
                || obligation.first_recorded_revision() > self.safety.revision()
            {
                return Err(CoreError::InvalidRecovery(
                    "durable payload validation obligation has an impossible first revision",
                ));
            }
            if id.generation() != obligation.first_recorded_revision() {
                return Err(CoreError::InvalidRecovery(
                    "durable payload validation generation differs from its first revision",
                ));
            }
            if block.logical_block_size() > self.config.max_block_bytes() {
                return Err(CoreError::InvalidRecovery(
                    "durable payload validation obligation exceeds max block bytes",
                ));
            }
            aggregate_resource_bytes = aggregate_resource_bytes
                .checked_add(Self::payload_validation_obligation_resource_size_v0(
                    obligation,
                )?)
                .ok_or(CoreError::InvalidRecovery(
                    "durable payload validation obligation resource bytes overflow",
                ))?;
            if aggregate_resource_bytes
                > self
                    .config
                    .consensus_parameters()
                    .max_consensus_message_bytes() as usize
            {
                return Err(CoreError::InvalidRecovery(
                    "durable payload validation obligation resources exceed the bounded SafetyState budget",
                ));
            }

            self.require_supported_proposal_header(header)?;
            let parent = obligation.parent();
            let tip = parent.tip();
            if header.parent_id() != tip.block_id()
                || header.height() != tip.height().checked_next()?
                || header.genesis_hash() != self.config.validator_set().genesis_hash()
                || header.chain_id() != self.config.validator_set().chain_id()
                || header.protocol_version() != self.config.validator_set().protocol_version()
                || header.epoch() != self.config.validator_set().epoch()
                || header.validator_set_id() != self.config.validator_set().id()
                || header.consensus_parameters_hash() != self.config.consensus_parameters().hash()
            {
                return Err(CoreError::InvalidRecovery(
                    "durable payload validation target differs from its authenticated context",
                ));
            }
            match (parent.provenance(), parent.exact_header()) {
                (crate::PayloadValidationParentProvenanceV0::Speculative(overlay), Some(exact))
                    if overlay.block_id() == exact.id()
                        && overlay.parent_block_id() == exact.parent_id()
                        && exact.id() == tip.block_id()
                        && exact.height() == tip.height()
                        && exact.view() == tip.view()
                        && exact.timestamp_ms() == tip.timestamp_ms()
                        && payload_parent_context_matches_target_v0(header, exact)? => {}
                (crate::PayloadValidationParentProvenanceV0::Speculative(_), _) => {
                    return Err(CoreError::InvalidRecovery(
                        "durable speculative payload parent is inconsistent",
                    ));
                }
                (crate::PayloadValidationParentProvenanceV0::Finalized, Some(exact))
                    if exact.id() == tip.block_id()
                        && exact.height() == tip.height()
                        && exact.view() == tip.view()
                        && exact.timestamp_ms() == tip.timestamp_ms()
                        && payload_parent_context_matches_target_v0(header, exact)? => {}
                (crate::PayloadValidationParentProvenanceV0::Finalized, Some(_)) => {
                    return Err(CoreError::InvalidRecovery(
                        "durable payload validation exact parent is inconsistent",
                    ));
                }
                (crate::PayloadValidationParentProvenanceV0::Finalized, None)
                    if payload_genesis_parent_matches_config_v0(parent, &self.config) => {}
                (crate::PayloadValidationParentProvenanceV0::Finalized, None)
                    if parent
                        .authenticated_genesis_application_parent_v0()
                        .is_some()
                        || self
                            .config
                            .authenticated_genesis_application_parent_v0()
                            .is_some() =>
                {
                    return Err(CoreError::InvalidRecovery(
                        "durable authenticated genesis application parent differs from core configuration",
                    ));
                }
                (crate::PayloadValidationParentProvenanceV0::Finalized, None) => {
                    return Err(CoreError::InvalidRecovery(
                        "durable payload validation lacks a non-genesis parent header",
                    ));
                }
            }
            if verify_durable_crypto {
                proposal.verify(
                    self.config.validator_set(),
                    None,
                    self.config.consensus_parameters(),
                    tip.timestamp_ms(),
                    verifier,
                )?;
            }
        }

        let volatile_count = self.pending_validation_count();
        // Recovery validates the detached durable record before the explicit
        // nonempty-obligation fail-closed check in `Core::recover`. Every live
        // transition, however, must retain an exact volatile mirror for each
        // durable obligation so an in-process map loss cannot pass unnoticed.
        if !verify_durable_crypto || obligations.is_empty() {
            if volatile_count != obligations.len() {
                return Err(CoreError::InvalidRecovery(
                    "volatile payload validations differ from durable obligations",
                ));
            }
            for obligation in obligations {
                let pending = match obligation.route() {
                    PayloadValidationRouteV0::Proposal => {
                        self.pending_validations.get(&obligation.id())
                    }
                    PayloadValidationRouteV0::Synced => {
                        self.pending_sync_validations.get(&obligation.id())
                    }
                };
                if pending.map(|pending| &pending.proposal) != Some(obligation.proposal()) {
                    return Err(CoreError::InvalidRecovery(
                        "volatile payload validation route or proposal differs from durable obligation",
                    ));
                }
            }
        }
        if self.next_validation_generation
            < obligations
                .iter()
                .map(|obligation| obligation.id().generation())
                .chain(
                    self.safety
                        .payload_validation_completions()
                        .iter()
                        .map(|completion| completion.id().generation()),
                )
                .max()
                .unwrap_or(0)
        {
            return Err(CoreError::InvalidRecovery(
                "validation generation is behind a durable validation record",
            ));
        }
        Ok(())
    }

    fn validate_payload_validation_completions(&self) -> Result<()> {
        let completions = self.safety.payload_validation_completions();
        let durable_slots = self
            .safety
            .payload_validation_obligations()
            .len()
            .checked_add(completions.len())
            .ok_or(CoreError::InvalidRecovery(
                "durable payload validation slot count overflow",
            ))?;
        if durable_slots > self.config.max_observed_messages() {
            return Err(CoreError::InvalidRecovery(
                "durable payload validation records exceed the configured bound",
            ));
        }
        if completions
            .windows(2)
            .any(|pair| pair[0].key() >= pair[1].key())
        {
            return Err(CoreError::InvalidRecovery(
                "durable payload validation completions are not uniquely sorted by route and full id",
            ));
        }

        let mut routes_by_id = BTreeMap::new();
        let mut terminal_results_by_block = BTreeMap::new();
        for completion in completions {
            let id = completion.id();
            Self::validate_durable_payload_completion(id, completion.result()).map_err(|_| {
                CoreError::InvalidRecovery(
                    "durable payload validation completion result differs from its full id",
                )
            })?;
            if id.generation() == 0
                || completion.first_recorded_revision() == 0
                || id.generation() > completion.first_recorded_revision()
                || completion.first_recorded_revision() > self.safety.revision()
            {
                return Err(CoreError::InvalidRecovery(
                    "durable payload validation completion has an impossible generation or first revision",
                ));
            }
            if routes_by_id.insert(id, completion.route()).is_some() {
                return Err(CoreError::InvalidRecovery(
                    "durable payload validation completion reused one full id across routes",
                ));
            }
            if self
                .safety
                .payload_validation_obligations()
                .binary_search_by_key(&id, DurablePayloadValidationObligationV0::id)
                .is_ok()
            {
                return Err(CoreError::InvalidRecovery(
                    "durable payload validation completion overlaps a live obligation",
                ));
            }
            if completion.result().is_unavailable() {
                continue;
            }
            let completion_terminal = if completion.result().is_valid() {
                PayloadTerminalResult::Valid
            } else {
                PayloadTerminalResult::DeterministicallyInvalid
            };
            let matching_halt = matches!(
                self.safety.safety_halt(),
                Some(SafetyHalt::ConflictingPayloadValidation { block_id, .. })
                    if *block_id == id.block_id()
            );
            if self
                .safety
                .payload_terminal_result(id.block_id())
                .is_some_and(|terminal| terminal != completion_terminal)
                && !matching_halt
            {
                return Err(CoreError::InvalidRecovery(
                    "durable payload validation completion conflicts with its terminal fact",
                ));
            }
            if let DurablePayloadValidationResultV1::Valid { artifact_ref, .. } =
                completion.result()
            {
                if self
                    .safety
                    .payload_terminal_fact(id.block_id())
                    .and_then(PayloadTerminalFact::valid_overlay)
                    .is_some_and(|terminal_overlay| terminal_overlay != artifact_ref.overlay())
                {
                    return Err(CoreError::InvalidRecovery(
                        "durable Valid completion disagrees with its terminal overlay",
                    ));
                }
            }
            if let Some(previous) =
                terminal_results_by_block.insert(id.block_id(), completion.result())
            {
                // Source-artifact checksums are route-scoped and therefore may
                // differ across Proposal/Synced completions. They never select
                // the finalization target: all routes must converge on the
                // same commitments and route-stable overlay below, and the
                // queue binds only that terminal overlay. The opaque live
                // AppStore apply receipt now gates queue consumption, while a
                // future durable App schema still must bind the accepted
                // source row in its exact-readback receipt.
                let valid_commitment_conflict = matches!(
                    (previous, completion.result()),
                    (
                        DurablePayloadValidationResultV1::Valid {
                            commitments: first_commitments,
                            artifact_ref: first_artifact,
                        },
                        DurablePayloadValidationResultV1::Valid {
                            commitments: second_commitments,
                            artifact_ref: second_artifact,
                        }
                    ) if first_commitments != second_commitments
                        || first_artifact.overlay() != second_artifact.overlay()
                );
                if valid_commitment_conflict {
                    return Err(CoreError::InvalidRecovery(
                        "durable payload validation completions disagree on valid commitments or overlay",
                    ));
                }
                let terminal_conflict = previous.is_valid() != completion.result().is_valid();
                if terminal_conflict && !matching_halt {
                    return Err(CoreError::InvalidRecovery(
                        "conflicting durable payload validation completions lack their exact safety halt",
                    ));
                }
            }
        }
        Ok(())
    }

    fn validate_h1_state_sync_anchor_v0<V: SignatureVerifier>(
        config: &CoreConfig,
        anchor: &DurableStateSyncAnchorV0,
        verifier: &V,
    ) -> Result<()> {
        let expected_parent = FinalizedTip::new(
            Height::new(0),
            View::new(0),
            config.genesis_block_id(),
            config.trusted_genesis_timestamp_ms(),
        );
        if anchor.authenticated_parent() != expected_parent {
            return Err(CoreError::InvalidRecovery(
                "state-sync anchor parent is not the exact configured genesis tip",
            ));
        }
        let reconstructed =
            DurableStateSyncAnchorV0::new(anchor.authenticated_parent(), anchor.proof().clone())?;
        if &reconstructed != anchor {
            return Err(CoreError::InvalidRecovery(
                "state-sync anchor is not canonically bound to its parent",
            ));
        }
        let proof = anchor.proof();
        let target = proof.finalized_block().header();
        let headers = [target, proof.child().header(), proof.grandchild().header()];
        if target.height() != Height::new(1)
            || target.parent_id() != config.genesis_block_id()
            || headers.iter().any(|header| {
                header.epoch() != Epoch::new(0) || header.block_kind() != BlockKind::Regular
            })
        {
            return Err(CoreError::InvalidRecovery(
                "state-sync anchor is not a regular epoch-zero h1 three-chain",
            ));
        }
        let Some(ContextAuthorizedQcV0::Genesis(genesis)) =
            proof.finalized_block().justify_qc().as_synthetic()
        else {
            return Err(CoreError::InvalidRecovery(
                "state-sync h1 is not directly justified by configured genesis",
            ));
        };
        genesis.matches_trusted_set(config.validator_set())?;
        let geometry = EpochGeometryV0::new(Epoch::new(0), config.consensus_parameters())?;
        if let Some(header) = headers
            .into_iter()
            .find(|header| header.height() >= geometry.checkpoint_height())
        {
            return Err(CoreError::EpochBoundaryUnsupported {
                height: header.height(),
                checkpoint_height: geometry.checkpoint_height(),
            });
        }
        proof.verify(
            config.validator_set(),
            None,
            config.consensus_parameters(),
            config.trusted_genesis_timestamp_ms(),
            verifier,
        )?;
        Ok(())
    }

    fn validate_state_sync_anchor_successor_bundle_v0<V: SignatureVerifier>(
        config: &CoreConfig,
        state: &SafetyState,
        anchor: &DurableStateSyncAnchorV0,
        child: &SignedProposalV0,
        grandchild: &SignedProposalV0,
        verifier: &V,
    ) -> Result<()> {
        let proof = anchor.proof();
        if child.block().header() != proof.child().header()
            || child.witness() != proof.child().witness()
            || grandchild.block().header() != proof.grandchild().header()
            || grandchild.witness() != proof.grandchild().witness()
        {
            return Err(CoreError::StateSyncAnchorSuccessorRecoveryRejected(
                "h2/h3 body carriers differ from the exact finality-proof headers or witnesses",
            ));
        }
        for proposal in [child, grandchild] {
            if proposal.block().logical_block_size() > config.max_block_bytes() {
                return Err(CoreError::BlockTooLarge {
                    actual: proposal.block().logical_block_size(),
                    maximum: config.max_block_bytes(),
                });
            }
            let actual = proposal.durable_validation_resource_size_v0()?;
            let maximum = config.consensus_parameters().max_consensus_message_bytes() as usize;
            if actual > maximum {
                return Err(CoreError::PayloadValidationResourceTooLarge { actual, maximum });
            }
            let body = validate_root_bound_regular_body_v0(
                proposal.block(),
                config.validator_set(),
                config.consensus_parameters(),
            )
            .map_err(|_| {
                CoreError::StateSyncAnchorSuccessorRecoveryRejected(
                    "successor body bytes do not match the authenticated payload/evidence roots",
                )
            })?;
            Self::validate_state_sync_anchor_successor_completion_body_facts_v0(state, body)?;
        }
        child.verify(
            config.validator_set(),
            None,
            config.consensus_parameters(),
            proof.finalized_block().header().timestamp_ms(),
            verifier,
        )?;
        grandchild.verify(
            config.validator_set(),
            None,
            config.consensus_parameters(),
            child.block().header().timestamp_ms(),
            verifier,
        )?;
        Ok(())
    }

    fn validate_state_sync_anchor_successor_completion_body_facts_v0(
        state: &SafetyState,
        body: RootBoundRegularBodyV0,
    ) -> Result<()> {
        let mut completions = state
            .payload_validation_completions()
            .iter()
            .filter(|completion| completion.id().block_id() == body.block_id());
        let Some(completion) = completions.next() else {
            return Ok(());
        };
        let commitments = completion.result().commitments().ok_or(
            CoreError::StateSyncAnchorSuccessorRecoveryRejected(
                "successor completion is not Valid",
            ),
        )?;
        if completions.next().is_some()
            || commitments.block_id() != body.block_id()
            || commitments.logical_block_size() != body.logical_block_size()
            || commitments.transaction_count() != body.transaction_count()
            || commitments.evidence_count() != body.evidence_count()
        {
            return Err(CoreError::StateSyncAnchorSuccessorRecoveryRejected(
                "successor completion differs from its exact root-bound body facts",
            ));
        }
        Ok(())
    }

    fn validate_state_sync_anchor_successor_effects_v0(
        &self,
        before: StateSyncAnchorSuccessorPhaseV0,
        step: StateSyncAnchorSuccessorStepV0,
        effects: &[Effect],
    ) -> Result<()> {
        match (step, before) {
            (
                StateSyncAnchorSuccessorStepV0::Proposal,
                StateSyncAnchorSuccessorPhaseV0::H1Bootstrap
                | StateSyncAnchorSuccessorPhaseV0::H2Valid,
            ) => {
                let expected = match before {
                    StateSyncAnchorSuccessorPhaseV0::H1Bootstrap => {
                        StateSyncAnchorSuccessorPhaseV0::H2ValidationPending
                    }
                    StateSyncAnchorSuccessorPhaseV0::H2Valid => {
                        StateSyncAnchorSuccessorPhaseV0::H3ValidationPending
                    }
                    _ => unreachable!(),
                };
                if self.state_sync_anchor_successor_phase_v0()? != expected
                    || !matches!(
                        effects,
                        [Effect::PersistSafetyState(request)]
                            if request.state() == &self.safety
                                && request.native_valid_post_ack_action_v0().is_none()
                                && request.native_finalization_applied_v0().is_none()
                    )
                {
                    return Err(CoreError::StateSyncAnchorSuccessorRecoveryRejected(
                        "successor proposal did not produce one inert obligation persistence",
                    ));
                }
            }
            (
                StateSyncAnchorSuccessorStepV0::StorageAck,
                StateSyncAnchorSuccessorPhaseV0::H2ValidationPending
                | StateSyncAnchorSuccessorPhaseV0::H3ValidationPending,
            ) => {
                if self.state_sync_anchor_successor_phase_v0()? != before
                    || !matches!(effects, [Effect::ValidateSyncedPayload(_)])
                {
                    return Err(CoreError::StateSyncAnchorSuccessorRecoveryRejected(
                        "successor obligation acknowledgement did not release one exact validation request",
                    ));
                }
            }
            (
                StateSyncAnchorSuccessorStepV0::Valid,
                StateSyncAnchorSuccessorPhaseV0::H2ValidationPending
                | StateSyncAnchorSuccessorPhaseV0::H3ValidationPending,
            ) => {
                let expected = match before {
                    StateSyncAnchorSuccessorPhaseV0::H2ValidationPending => {
                        StateSyncAnchorSuccessorPhaseV0::H2Valid
                    }
                    StateSyncAnchorSuccessorPhaseV0::H3ValidationPending => {
                        StateSyncAnchorSuccessorPhaseV0::H3Valid
                    }
                    _ => unreachable!(),
                };
                if self.state_sync_anchor_successor_phase_v0()? != expected
                    || !matches!(
                        effects,
                        [Effect::PersistSafetyState(request)]
                            if request.state() == &self.safety
                                && request.native_valid_post_ack_action_v0()
                                    == Some(NativeValidPostAckActionV0::None)
                                && request.native_finalization_applied_v0().is_none()
                    )
                {
                    return Err(CoreError::StateSyncAnchorSuccessorRecoveryRejected(
                        "successor Valid callback did not produce one inert completion persistence",
                    ));
                }
            }
            (
                StateSyncAnchorSuccessorStepV0::StorageAck,
                StateSyncAnchorSuccessorPhaseV0::H2Valid | StateSyncAnchorSuccessorPhaseV0::H3Valid,
            ) => {
                if self.state_sync_anchor_successor_phase_v0()? != before || !effects.is_empty() {
                    return Err(CoreError::StateSyncAnchorSuccessorRecoveryRejected(
                        "successor completion acknowledgement exposed a side effect",
                    ));
                }
            }
            _ => {
                return Err(CoreError::StateSyncAnchorSuccessorRecoveryRejected(
                    "anchored successor step does not match its durable phase",
                ));
            }
        }
        if effects.iter().any(|effect| {
            matches!(
                effect,
                Effect::RequestSignature { .. }
                    | Effect::Broadcast(_)
                    | Effect::ArmViewTimer { .. }
                    | Effect::RequestSafetyReplay { .. }
                    | Effect::RequestTcHighQcSync { .. }
                    | Effect::RequestStandaloneQcSync { .. }
                    | Effect::SafetyHalted(_)
                    | Effect::Finalize(_)
                    | Effect::Evidence(_)
                    | Effect::ValidatePayload(_)
            )
        }) {
            return Err(CoreError::StateSyncAnchorSuccessorRecoveryRejected(
                "anchored successor replay exposed a forbidden side effect",
            ));
        }
        Ok(())
    }

    fn state_sync_anchor_successor_phase_v0(&self) -> Result<StateSyncAnchorSuccessorPhaseV0> {
        let anchor = self
            .safety
            .state_sync_anchor()
            .ok_or(CoreError::StateSyncAnchorRecoveryNotRequired)?;
        Self::classify_state_sync_anchor_successor_phase_v0(&self.config, &self.safety, anchor)
    }

    fn canonical_anchor_successor_completion_v0(
        state: &SafetyState,
        block_id: BlockId,
        view: View,
        generation: u64,
        first_recorded_revision: u64,
        parent_id: BlockId,
    ) -> Result<&DurablePayloadValidationCompletionV0> {
        let mut matches = state
            .payload_validation_completions()
            .iter()
            .filter(|completion| completion.id().block_id() == block_id);
        let completion = matches.next().ok_or(CoreError::InvalidRecovery(
            "anchored successor phase lacks its exact Valid completion",
        ))?;
        if matches.next().is_some()
            || completion.route() != PayloadValidationRouteV0::Synced
            || completion.id() != ValidationId::new(block_id, view, generation)
            || completion.first_recorded_revision() != first_recorded_revision
            || !completion.result().is_valid()
        {
            return Err(CoreError::InvalidRecovery(
                "anchored successor completion has a noncanonical route, generation, result, or revision",
            ));
        }
        let artifact = completion
            .result()
            .artifact_ref()
            .ok_or(CoreError::InvalidRecovery(
                "anchored successor Valid completion lacks its artifact reference",
            ))?;
        if artifact.overlay().block_id() != block_id
            || artifact.overlay().parent_block_id() != parent_id
        {
            return Err(CoreError::InvalidRecovery(
                "anchored successor completion has a noncanonical overlay edge",
            ));
        }
        Ok(completion)
    }

    fn classify_state_sync_anchor_successor_phase_v0(
        config: &CoreConfig,
        state: &SafetyState,
        anchor: &DurableStateSyncAnchorV0,
    ) -> Result<StateSyncAnchorSuccessorPhaseV0> {
        let base = SafetyState::from_h1_state_sync_anchor(
            config.validator_set(),
            config.genesis_block_id(),
            config
                .authenticated_genesis_application_parent_v0()
                .copied(),
            anchor.clone(),
        )?;
        if state.schema_version() != base.schema_version()
            || state.chain_id() != base.chain_id()
            || state.protocol_version() != base.protocol_version()
            || state.epoch() != base.epoch()
            || state.validator_set_id() != base.validator_set_id()
            || state.genesis_block_id() != base.genesis_block_id()
            || state.authenticated_genesis_application_parent_v0()
                != base.authenticated_genesis_application_parent_v0()
            || state.current_view() != base.current_view()
            || state.last_voted_view().is_some()
            || state.last_timeout_view().is_some()
            || state.high_qc() != base.high_qc()
            || state.locked_qc() != base.locked_qc()
            || state.finalized() != base.finalized()
            || state.pending_tc_high_qc_sync().is_some()
            || state.pending_standalone_qc_sync().is_some()
            || state.pending_sign().is_some()
            || state.last_finalization().is_some()
            || state.state_sync_anchor() != Some(anchor)
            || state.application_applied() != base.application_applied()
            || !state.finalization_queue().is_empty()
            || state.pending_finalize().is_some()
            || state.safety_halt().is_some()
        {
            return Err(CoreError::InvalidRecovery(
                "anchored successor replay changed a frozen h1 safety coordinate or outbox",
            ));
        }

        let proof = anchor.proof();
        let h1 = proof.finalized_block().header();
        let h2 = proof.child().header();
        let h3 = proof.grandchild().header();
        if state
            .payload_terminal_facts()
            .iter()
            .any(|fact| fact.block_id() == h1.id())
            || state
                .payload_validation_obligations()
                .iter()
                .any(|obligation| obligation.id().block_id() == h1.id())
            || state
                .payload_validation_completions()
                .iter()
                .any(|completion| completion.id().block_id() == h1.id())
        {
            return Err(CoreError::InvalidRecovery(
                "anchored successor replay invented local h1 validation history",
            ));
        }

        let h2_completion = || {
            Self::canonical_anchor_successor_completion_v0(state, h2.id(), h2.view(), 1, 2, h1.id())
        };
        let h3_completion = || {
            Self::canonical_anchor_successor_completion_v0(state, h3.id(), h3.view(), 3, 4, h2.id())
        };
        let exact_valid_fact = |header: &BlockHeader,
                                completion: &DurablePayloadValidationCompletionV0,
                                first_revision: u64|
         -> bool {
            state
                .payload_terminal_fact(header.id())
                .is_some_and(|fact| {
                    fact.result() == PayloadTerminalResult::Valid
                        && fact.first_recorded_revision() == first_revision
                        && fact.valid_overlay()
                            == completion
                                .result()
                                .artifact_ref()
                                .map(|artifact| artifact.overlay())
                })
        };
        let exact_obligation = |obligation: &DurablePayloadValidationObligationV0,
                                proposal: &trnm_consensus_types::CertifiedHeaderV0,
                                generation: u64,
                                parent: PayloadValidationParentV0,
                                first_revision: u64|
         -> bool {
            obligation.route() == PayloadValidationRouteV0::Synced
                && obligation.id()
                    == ValidationId::new(
                        proposal.header().id(),
                        proposal.header().view(),
                        generation,
                    )
                && obligation.proposal().block().header() == proposal.header()
                && obligation.proposal().witness() == proposal.witness()
                && validate_root_bound_regular_body_v0(
                    obligation.proposal().block(),
                    config.validator_set(),
                    config.consensus_parameters(),
                )
                .is_ok()
                && obligation.parent() == &parent
                && obligation.first_recorded_revision() == first_revision
        };

        match state.revision() {
            0 if state == &base => Ok(StateSyncAnchorSuccessorPhaseV0::H1Bootstrap),
            1 => {
                let [obligation] = state.payload_validation_obligations() else {
                    return Err(CoreError::InvalidRecovery(
                        "anchored h2 pending phase requires exactly one obligation",
                    ));
                };
                if !state.payload_validation_completions().is_empty()
                    || !state.payload_terminal_facts().is_empty()
                    || !exact_obligation(
                        obligation,
                        proof.child(),
                        1,
                        PayloadValidationParentV0::from_finalized_exact_header(h1.clone()),
                        1,
                    )
                {
                    return Err(CoreError::InvalidRecovery(
                        "anchored h2 pending phase is not canonical",
                    ));
                }
                Ok(StateSyncAnchorSuccessorPhaseV0::H2ValidationPending)
            }
            2 => {
                let completion = h2_completion()?;
                if !state.payload_validation_obligations().is_empty()
                    || state.payload_validation_completions().len() != 1
                    || state.payload_terminal_facts().len() != 1
                    || !exact_valid_fact(h2, completion, 2)
                {
                    return Err(CoreError::InvalidRecovery(
                        "anchored h2 Valid phase is not canonical",
                    ));
                }
                Ok(StateSyncAnchorSuccessorPhaseV0::H2Valid)
            }
            3 => {
                let completion = h2_completion()?;
                let [obligation] = state.payload_validation_obligations() else {
                    return Err(CoreError::InvalidRecovery(
                        "anchored h3 pending phase requires exactly one obligation",
                    ));
                };
                if state.payload_validation_completions().len() != 1
                    || state.payload_terminal_facts().len() != 1
                    || !exact_valid_fact(h2, completion, 2)
                    || !exact_obligation(
                        obligation,
                        proof.grandchild(),
                        3,
                        PayloadValidationParentV0::from_speculative_exact_header(
                            h2.clone(),
                            completion
                                .result()
                                .artifact_ref()
                                .expect("canonical h2 completion is Valid")
                                .overlay(),
                        ),
                        3,
                    )
                {
                    return Err(CoreError::InvalidRecovery(
                        "anchored h3 pending phase is not canonical",
                    ));
                }
                Ok(StateSyncAnchorSuccessorPhaseV0::H3ValidationPending)
            }
            4 => {
                let h2_completion = h2_completion()?;
                let h3_completion = h3_completion()?;
                if !state.payload_validation_obligations().is_empty()
                    || state.payload_validation_completions().len() != 2
                    || state.payload_terminal_facts().len() != 2
                    || !exact_valid_fact(h2, h2_completion, 2)
                    || !exact_valid_fact(h3, h3_completion, 4)
                {
                    return Err(CoreError::InvalidRecovery(
                        "anchored h3 Valid phase is not canonical",
                    ));
                }
                Ok(StateSyncAnchorSuccessorPhaseV0::H3Valid)
            }
            _ => Err(CoreError::InvalidRecovery(
                "state-sync anchor requires one of the five canonical successor replay phases",
            )),
        }
    }

    fn state_sync_anchor_state_at_revision_v0(state: &SafetyState, revision: u64) -> SafetyState {
        SafetyState::from_persisted_parts_v13(
            state.schema_version(),
            state.chain_id(),
            state.protocol_version(),
            state.epoch(),
            state.validator_set_id(),
            state.genesis_block_id(),
            state.authenticated_genesis_application_parent_v0().copied(),
            state.current_view(),
            state.last_voted_view(),
            state.last_timeout_view(),
            state.high_qc().clone(),
            state.locked_qc().clone(),
            state.finalized(),
            revision,
            state.durable_observed_qcs().to_vec(),
            state.payload_terminal_facts().to_vec(),
            state.payload_validation_obligations().to_vec(),
            state.payload_validation_completions().to_vec(),
            state.pending_tc_high_qc_sync().cloned(),
            state.pending_standalone_qc_sync().cloned(),
            state.pending_sign().cloned(),
            state.last_finalization().cloned(),
            state.state_sync_anchor().cloned(),
            state.application_applied(),
            state.finalization_queue().to_vec(),
            state.pending_finalize(),
            state.safety_halt().cloned(),
        )
    }

    fn is_exact_state_sync_anchor_ordinary_promotion_cut_v0(
        config: &CoreConfig,
        state: &SafetyState,
        anchor: &DurableStateSyncAnchorV0,
    ) -> Result<bool> {
        if state.revision() != 5 {
            return Ok(false);
        }
        let predecessor = Self::state_sync_anchor_state_at_revision_v0(state, 4);
        Ok(
            Self::classify_state_sync_anchor_successor_phase_v0(config, &predecessor, anchor)?
                == StateSyncAnchorSuccessorPhaseV0::H3Valid,
        )
    }

    fn validate_state_sync_anchor_ordinary_state_v0(
        config: &CoreConfig,
        state: &SafetyState,
        anchor: &DurableStateSyncAnchorV0,
    ) -> Result<()> {
        if state.revision() < 5 {
            return Err(CoreError::InvalidRecovery(
                "anchored-ordinary state precedes the durable promotion revision",
            ));
        }
        let proof = anchor.proof();
        let h1 = proof.finalized_block().header();
        let h2 = proof.child().header();
        let h3 = proof.grandchild().header();
        if state
            .payload_terminal_facts()
            .iter()
            .any(|fact| fact.block_id() == h1.id())
            || state
                .payload_validation_obligations()
                .iter()
                .any(|obligation| obligation.id().block_id() == h1.id())
            || state
                .payload_validation_completions()
                .iter()
                .any(|completion| completion.id().block_id() == h1.id())
        {
            return Err(CoreError::InvalidRecovery(
                "anchored-ordinary state invented local h1 validation history",
            ));
        }
        let h2_completion = Self::canonical_anchor_successor_completion_v0(
            state,
            h2.id(),
            h2.view(),
            1,
            2,
            h1.id(),
        )?;
        let h3_completion = Self::canonical_anchor_successor_completion_v0(
            state,
            h3.id(),
            h3.view(),
            3,
            4,
            h2.id(),
        )?;
        for (header, completion, first_revision) in
            [(h2, h2_completion, 2_u64), (h3, h3_completion, 4_u64)]
        {
            if state.payload_terminal_fact(header.id()).is_none_or(|fact| {
                fact.result() != PayloadTerminalResult::Valid
                    || fact.first_recorded_revision() != first_revision
                    || fact.valid_overlay()
                        != completion
                            .result()
                            .artifact_ref()
                            .map(|artifact| artifact.overlay())
            }) {
                return Err(CoreError::InvalidRecovery(
                    "anchored-ordinary state lost a canonical h2/h3 Valid fact",
                ));
            }
        }
        if state.revision() == 5
            && !Self::is_exact_state_sync_anchor_ordinary_promotion_cut_v0(config, state, anchor)?
        {
            return Err(CoreError::InvalidRecovery(
                "anchored-ordinary revision five is not the exact H3Valid promotion cut",
            ));
        }
        Ok(())
    }

    fn validate_state_sync_anchor_state_v0<V: SignatureVerifier>(
        &self,
        verifier: &V,
        verify_durable_crypto: bool,
    ) -> Result<()> {
        let Some(anchor) = self.safety.state_sync_anchor() else {
            return Ok(());
        };
        if self
            .config
            .authenticated_genesis_application_parent_v0()
            .is_some()
        {
            return Err(CoreError::InvalidRecovery(
                "authenticated genesis application bootstrap and h1 state-sync bootstrap are mutually exclusive",
            ));
        }
        if verify_durable_crypto {
            Self::validate_h1_state_sync_anchor_v0(&self.config, anchor, verifier)?;
        }
        if self.safety.revision() < 5 {
            Self::classify_state_sync_anchor_successor_phase_v0(
                &self.config,
                &self.safety,
                anchor,
            )?;
        } else {
            Self::validate_state_sync_anchor_ordinary_state_v0(&self.config, &self.safety, anchor)?;
        }
        Ok(())
    }

    fn validate_runtime<V: SignatureVerifier>(
        &self,
        verifier: &V,
        verify_durable_crypto: bool,
    ) -> Result<()> {
        self.config.validate()?;
        let set = self.config.validator_set();
        if self.safety.schema_version() != SAFETY_STATE_SCHEMA_VERSION {
            return Err(CoreError::InvalidRecovery(
                "unsupported safety-state schema version",
            ));
        }
        self.validate_state_sync_anchor_state_v0(verifier, verify_durable_crypto)?;
        self.validate_payload_validation_obligations(verifier, verify_durable_crypto)?;
        self.validate_payload_validation_completions()?;
        self.validate_recovered_payload_validation_fence_v0()?;
        self.validate_recovered_native_finalization_applied_fence_v0()?;
        if self.safety.payload_terminal_facts().len() > self.config.max_observed_messages() {
            return Err(CoreError::InvalidRecovery(
                "durable payload terminal facts exceed the configured bound",
            ));
        }
        if self
            .safety
            .payload_terminal_facts()
            .windows(2)
            .any(|pair| pair[0].block_id() >= pair[1].block_id())
        {
            return Err(CoreError::InvalidRecovery(
                "durable payload terminal facts are not uniquely sorted",
            ));
        }
        if self.safety.payload_terminal_facts().iter().any(|fact| {
            fact.first_recorded_revision() == 0
                || fact.first_recorded_revision() > self.safety.revision()
                || match (fact.result(), fact.valid_overlay()) {
                    (PayloadTerminalResult::Valid, Some(overlay)) => {
                        overlay.block_id() != fact.block_id()
                    }
                    (PayloadTerminalResult::DeterministicallyInvalid, None) => false,
                    (PayloadTerminalResult::Valid, None)
                    | (PayloadTerminalResult::DeterministicallyInvalid, Some(_)) => true,
                }
        }) {
            return Err(CoreError::InvalidRecovery(
                "durable payload terminal fact has an impossible revision or overlay binding",
            ));
        }
        if set.epoch() != Epoch::new(0) {
            return Err(CoreError::InvalidRecovery(
                "epoch transition is not implemented by this core",
            ));
        }
        if self.safety.chain_id() != set.chain_id() {
            return Err(CoreError::InvalidRecovery(
                "chain id does not match validator set",
            ));
        }
        if self.safety.protocol_version() != set.protocol_version() {
            return Err(CoreError::InvalidRecovery(
                "protocol version does not match validator set",
            ));
        }
        if self.safety.epoch() != set.epoch() {
            return Err(CoreError::InvalidRecovery(
                "epoch does not match validator set",
            ));
        }
        if self.safety.validator_set_id() != set.id() {
            return Err(CoreError::InvalidRecovery(
                "validator-set id does not match validator set",
            ));
        }
        if self.safety.genesis_block_id() != self.config.genesis_block_id() {
            return Err(CoreError::InvalidRecovery(
                "trusted genesis block does not match core configuration",
            ));
        }
        if self
            .safety
            .authenticated_genesis_application_parent_v0()
            .copied()
            != self
                .config
                .authenticated_genesis_application_parent_v0()
                .copied()
        {
            return Err(CoreError::InvalidRecovery(
                "durable authenticated genesis application parent differs from core configuration",
            ));
        }

        self.validate_epoch_boundary_fence()?;

        let durable_observed_qcs = self.safety.durable_observed_qcs();
        if durable_observed_qcs.len() > self.config.max_observed_messages() {
            return Err(CoreError::InvalidRecovery(
                "durable observed QC set exceeds the configured bound",
            ));
        }
        if durable_observed_qcs
            .windows(2)
            .any(|pair| pair[0].view() >= pair[1].view())
        {
            return Err(CoreError::InvalidRecovery(
                "durable observed QC set is not strictly ordered by view",
            ));
        }
        for certificate in durable_observed_qcs {
            self.require_epoch(certificate.epoch())?;
            if certificate.view().get() == 0 || certificate.height().get() == 0 {
                return Err(CoreError::InvalidRecovery(
                    "durable observed QC has an invalid ordinary coordinate",
                ));
            }
            if verify_durable_crypto {
                self.verify_ordinary_qc(certificate, verifier)?;
            }
        }

        // Every durable contextual reference is checked in its own trust
        // domain. Ordinary certificates receive full signature verification;
        // GenesisQC must exactly match the trusted set; EpochAnchorQC remains
        // fail-closed until atomic epoch transition is implemented.
        if verify_durable_crypto {
            for reference in self.durable_qc_references() {
                self.verify_qc_reference(reference, verifier)?;
            }
        }
        if let Some(pending) = self.safety.pending_tc_high_qc_sync() {
            for reference in pending.timeout_certificate().referenced_qcs() {
                self.reject_epoch_anchor(reference)?;
            }
            if verify_durable_crypto {
                pending.timeout_certificate().verify(set, None, verifier)?;
            }
            let reconstructed = PendingTcHighQcSync::from_timeout_certificate(
                pending.timeout_certificate().clone(),
            )?;
            if &reconstructed != pending {
                return Err(CoreError::InvalidRecovery(
                    "pending TC sync target differs from its certificate selection",
                ));
            }
            if pending.selected_high_qc().as_ordinary().is_none() {
                return Err(CoreError::InvalidRecovery(
                    "a synthetic high QC never requires block synchronization",
                ));
            }
            if self.safety.current_view() < pending.timed_out_view().checked_next()? {
                return Err(CoreError::InvalidRecovery(
                    "pending TC sync did not durably advance through the certified timeout view",
                ));
            }
        }
        if let Some(pending) = self.safety.pending_standalone_qc_sync() {
            let certificates: Vec<_> = core::iter::once(pending.active())
                .chain(pending.backlog())
                .collect();
            if certificates.len() > self.config.max_observed_messages() {
                return Err(CoreError::InvalidRecovery(
                    "standalone QC sync backlog exceeds the configured bound",
                ));
            }
            if pending
                .backlog()
                .windows(2)
                .any(|pair| qc_order_key(&pair[0]) >= qc_order_key(&pair[1]))
            {
                return Err(CoreError::InvalidRecovery(
                    "standalone QC sync backlog is not canonically sorted",
                ));
            }
            for certificate in &certificates {
                self.require_epoch(certificate.epoch())?;
                if certificate.view().get() == 0 || certificate.height().get() == 0 {
                    return Err(CoreError::InvalidRecovery(
                        "standalone QC sync contains an invalid ordinary certificate",
                    ));
                }
                if verify_durable_crypto {
                    self.verify_ordinary_qc(certificate, verifier)?;
                }
            }
            for (index, first) in certificates.iter().enumerate() {
                if certificates
                    .iter()
                    .skip(index + 1)
                    .any(|second| same_qc_coordinates(first, second))
                {
                    return Err(CoreError::InvalidRecovery(
                        "standalone QC sync contains duplicate certificate coordinates",
                    ));
                }
            }
        }

        match self.safety.last_finalization() {
            Some(durable) => {
                let reconstructed = crate::DurableFinalizationV0::new(
                    durable.authenticated_parent(),
                    durable.proof().clone(),
                    durable.target_overlay_ref(),
                )?;
                if &reconstructed != durable {
                    return Err(CoreError::InvalidRecovery(
                        "durable finalization is not canonically bound to its parent",
                    ));
                }
                if self
                    .safety
                    .payload_terminal_fact(durable.proof().finalized_block().header().id())
                    .and_then(PayloadTerminalFact::valid_overlay)
                    != Some(durable.target_overlay_ref())
                {
                    return Err(CoreError::InvalidRecovery(
                        "durable finalization target overlay differs from its terminal Valid fact",
                    ));
                }
                if verify_durable_crypto {
                    durable.proof().verify(
                        set,
                        None,
                        self.config.consensus_parameters(),
                        durable.authenticated_parent().timestamp_ms(),
                        verifier,
                    )?;
                }
                let committed = durable.proof().finalized_block().header();
                if committed.height() != self.safety.finalized().height()
                    || committed.view() != self.safety.finalized().view()
                    || committed.id() != self.safety.finalized().block_id()
                    || committed.timestamp_ms() != self.safety.finalized().timestamp_ms()
                {
                    return Err(CoreError::InvalidRecovery(
                        "last finalization proof does not bind the finalized tip",
                    ));
                }
            }
            None => match self.safety.state_sync_anchor() {
                Some(anchor) => {
                    let target = anchor.proof().finalized_block().header();
                    let exact = FinalizedTip::new(
                        target.height(),
                        target.view(),
                        target.id(),
                        target.timestamp_ms(),
                    );
                    if self.safety.finalized() != exact {
                        return Err(CoreError::InvalidRecovery(
                                "an anchor-only finalization state must use the exact state-sync h1 tip",
                            ));
                    }
                }
                None => {
                    if self.safety.finalized().height().get() != 0
                        || self.safety.finalized().view().get() != 0
                        || self.safety.finalized().block_id() != self.safety.genesis_block_id()
                        || self.safety.finalized().timestamp_ms()
                            != self.config.trusted_genesis_timestamp_ms()
                    {
                        return Err(CoreError::InvalidRecovery(
                            "a finalization-free state must use the exact trusted genesis tip",
                        ));
                    }
                }
            },
        }

        let applied = self.safety.application_applied();
        let finalized = self.safety.finalized();
        if applied.height() > finalized.height()
            || (applied.height() == finalized.height() && applied != finalized)
        {
            return Err(CoreError::InvalidRecovery(
                "application-applied watermark is ahead of or conflicts with consensus finality",
            ));
        }
        if self.safety.finalization_queue().len() > self.config.max_blocks() {
            return Err(CoreError::InvalidRecovery(
                "application-finalization queue exceeds the configured block bound",
            ));
        }
        let mut expected_parent = applied;
        for durable in self.safety.finalization_queue() {
            let reconstructed = DurableFinalizationV0::new(
                durable.authenticated_parent(),
                durable.proof().clone(),
                durable.target_overlay_ref(),
            )?;
            if reconstructed != *durable || durable.authenticated_parent() != expected_parent {
                return Err(CoreError::InvalidRecovery(
                    "application-finalization queue is not canonically ancestor ordered",
                ));
            }
            if self
                .safety
                .payload_terminal_fact(durable.proof().finalized_block().header().id())
                .and_then(PayloadTerminalFact::valid_overlay)
                != Some(durable.target_overlay_ref())
            {
                return Err(CoreError::InvalidRecovery(
                    "application-finalization queue target overlay differs from its terminal Valid fact",
                ));
            }
            if verify_durable_crypto {
                durable.proof().verify(
                    set,
                    None,
                    self.config.consensus_parameters(),
                    durable.authenticated_parent().timestamp_ms(),
                    verifier,
                )?;
            }
            expected_parent = durable_finalization_target(durable);
        }
        if expected_parent != finalized {
            return Err(CoreError::InvalidRecovery(
                "application-finalization queue does not exactly cover the applied-to-finalized gap",
            ));
        }
        let expected_pending = self
            .safety
            .pending_finalization()
            .map(DurableFinalizationV0::proof_id);
        if self.safety.pending_finalize() != expected_pending {
            return Err(CoreError::InvalidRecovery(
                "finalization outbox does not name the exact queue front",
            ));
        }
        if let Some(last_queued) = self.safety.finalization_queue().last() {
            if self.safety.last_finalization() != Some(last_queued) {
                return Err(CoreError::InvalidRecovery(
                    "latest permanent finalization differs from the ordered queue tail",
                ));
            }
        }

        let durable_qcs = self.durable_qcs();
        for (index, first) in durable_qcs.iter().enumerate() {
            for second in durable_qcs.iter().skip(index + 1) {
                if first.view() == second.view() && first.block_id() != second.block_id() {
                    return Err(CoreError::InvalidRecovery(
                        "durable state contains conflicting QCs at one view",
                    ));
                }
                if first.block_id() == second.block_id()
                    && (first.view() != second.view() || first.height() != second.height())
                {
                    return Err(CoreError::InvalidRecovery(
                        "durable QCs assign different coordinates to one block",
                    ));
                }
            }
        }
        for (index, first) in self.safety.durable_observed_qcs().iter().enumerate() {
            for second in self.safety.durable_observed_qcs().iter().skip(index + 1) {
                if first.view() == second.view() && first.block_id() != second.block_id() {
                    return Err(CoreError::InvalidRecovery(
                        "durable observed QCs contain conflicting blocks at one view",
                    ));
                }
                if first.block_id() == second.block_id()
                    && (first.view() != second.view() || first.height() != second.height())
                {
                    return Err(CoreError::InvalidRecovery(
                        "durable observed QCs assign different coordinates to one block",
                    ));
                }
            }
        }
        // Schema-v13 carries two independently durable ordinary-QC domains:
        // contextual references (high/lock, sync targets, finality proofs,
        // and anchors) and the bounded observation cache.  Each domain is
        // checked above, but a spliced record can otherwise put a conflicting
        // witness in the other domain and pass those per-domain checks.  The
        // domains must therefore be cross-checked before recovery; runtime
        // observation is too late to make such a record safe.
        for durable in durable_qcs.iter() {
            for observed in self.safety.durable_observed_qcs() {
                if durable.view() == observed.view() && durable.block_id() != observed.block_id() {
                    return Err(CoreError::InvalidRecovery(
                        "durable contextual and observed QCs conflict at one view",
                    ));
                }
                if durable.block_id() == observed.block_id()
                    && (durable.view() != observed.view() || durable.height() != observed.height())
                {
                    return Err(CoreError::InvalidRecovery(
                        "durable contextual and observed QCs assign different coordinates to one block",
                    ));
                }
            }
        }
        for fact in self
            .safety
            .payload_terminal_facts()
            .iter()
            .filter(|fact| fact.result() == PayloadTerminalResult::DeterministicallyInvalid)
        {
            if self.invalid_payload_reference(fact.block_id()).is_some()
                && self
                    .safety
                    .safety_halt()
                    .and_then(SafetyHalt::payload_block_id)
                    != Some(fact.block_id())
            {
                return Err(CoreError::InvalidRecovery(
                    "durable invalid payload collides with an active safety reference without a halt",
                ));
            }
        }

        if let Some(proof) = self.safety.last_finalization_proof() {
            if qc_order_key_ref(self.safety.high_qc())
                < qc_order_key(proof.grandchild().certifying_qc())
            {
                return Err(CoreError::InvalidRecovery(
                    "high QC is behind the permanent finalization proof",
                ));
            }
            if qc_order_key_ref(self.safety.locked_qc())
                < qc_order_key(proof.child().certifying_qc())
            {
                return Err(CoreError::InvalidRecovery(
                    "locked QC is behind the permanent finalization proof",
                ));
            }
        }

        let high = self.safety.high_qc().qc_ref();
        let locked = self.safety.locked_qc().qc_ref();
        let finalized = self.safety.finalized();
        if locked.view() == high.view() && locked.block_id() != high.block_id() {
            return Err(CoreError::InvalidRecovery(
                "equal-view locked and high QCs certify different blocks",
            ));
        }
        if locked.block_id() == high.block_id()
            && (locked.view() != high.view() || locked.height() != high.height())
        {
            return Err(CoreError::InvalidRecovery(
                "locked and high QCs assign different coordinates to one block",
            ));
        }
        if qc_order_key_ref(self.safety.locked_qc()) > qc_order_key_ref(self.safety.high_qc()) {
            return Err(CoreError::InvalidRecovery("locked QC is ahead of high QC"));
        }
        if self.safety.current_view() <= high.view() {
            return Err(CoreError::InvalidRecovery(
                "current view must be ahead of the high QC",
            ));
        }
        if finalized.height() > high.height() || finalized.view() > high.view() {
            return Err(CoreError::InvalidRecovery(
                "finalized tip is ahead of the high QC",
            ));
        }
        if finalized.height() > locked.height() || finalized.view() > locked.view() {
            return Err(CoreError::InvalidRecovery(
                "locked QC is behind the finalized tip",
            ));
        }
        if finalized.height() == high.height() && finalized.block_id() != high.block_id() {
            return Err(CoreError::InvalidRecovery(
                "equal-height finalized tip and high QC identify different blocks",
            ));
        }
        if finalized.height() == locked.height() && finalized.block_id() != locked.block_id() {
            return Err(CoreError::InvalidRecovery(
                "equal-height locked QC conflicts with finalized tip",
            ));
        }
        for reference in [high, locked] {
            if reference.block_id() == finalized.block_id()
                && (reference.height() != finalized.height()
                    || reference.view() != finalized.view())
            {
                return Err(CoreError::InvalidRecovery(
                    "QC coordinates do not match the finalized anchor",
                ));
            }
        }

        if self
            .safety
            .last_voted_view()
            .is_some_and(|view| view > self.safety.current_view())
        {
            return Err(CoreError::InvalidRecovery(
                "last voted view is in the future",
            ));
        }
        if self
            .safety
            .last_timeout_view()
            .is_some_and(|view| view > self.safety.current_view())
        {
            return Err(CoreError::InvalidRecovery(
                "last timeout view is in the future",
            ));
        }
        if self.awaiting_signature && self.safety.pending_sign().is_none() {
            return Err(CoreError::InvalidRecovery(
                "signature request has no durable signing intent",
            ));
        }
        if self.safety.pending_sign().is_some() && self.safety.pending_finalize().is_some() {
            return Err(CoreError::InvalidRecovery(
                "signing and finalization outboxes cannot both be active",
            ));
        }
        if self.safety.pending_tc_high_qc_sync().is_some() {
            if self.safety.pending_finalize().is_some() {
                return Err(CoreError::InvalidRecovery(
                    "TC QC sync cannot overlap a finalization outbox",
                ));
            }
            if matches!(self.safety.pending_sign(), Some(SignIntent::Vote { .. })) {
                return Err(CoreError::InvalidRecovery(
                    "TC QC sync cannot overlap a proposal-vote outbox",
                ));
            }
        }
        if self.safety.pending_standalone_qc_sync().is_some()
            && matches!(self.safety.pending_sign(), Some(SignIntent::Vote { .. }))
        {
            return Err(CoreError::InvalidRecovery(
                "standalone QC sync cannot overlap a proposal-vote outbox",
            ));
        }
        if let Some(intent) = self.safety.pending_sign() {
            if intent.authorizing_safety_revision() == 0
                || intent.authorizing_safety_revision() > self.safety.revision()
            {
                return Err(CoreError::InvalidRecovery(
                    "pending signing intent has an invalid authorizing revision",
                ));
            }
            if intent.view() != self.safety.current_view() {
                return Err(CoreError::InvalidRecovery(
                    "pending signing intent is not for the current view",
                ));
            }
            let expected = match intent {
                SignIntent::Vote {
                    view,
                    height,
                    block_id,
                    ..
                } => {
                    if self.safety.last_voted_view() != Some(*view) {
                        return Err(CoreError::InvalidRecovery(
                            "vote intent does not match last voted view",
                        ));
                    }
                    let Some(terminal_overlay) = self
                        .safety
                        .payload_terminal_fact(*block_id)
                        .and_then(PayloadTerminalFact::valid_overlay)
                    else {
                        return Err(CoreError::InvalidRecovery(
                            "vote intent has no durable Valid overlay fact",
                        ));
                    };
                    let exact_overlay_completion = self
                        .safety
                        .payload_validation_completions()
                        .iter()
                        .filter(|completion| completion.id().block_id() == *block_id)
                        .any(|completion| {
                            matches!(
                                completion.result(),
                                DurablePayloadValidationResultV1::Valid {
                                    artifact_ref,
                                    ..
                                } if artifact_ref.overlay() == terminal_overlay
                            )
                        });
                    if !exact_overlay_completion {
                        return Err(CoreError::InvalidRecovery(
                            "vote intent has no durable completion for its Valid overlay",
                        ));
                    }
                    Vote::signing_root_for_set(set, *view, *height, *block_id)?
                }
                SignIntent::TimeoutVote { view, high_qc, .. } => {
                    if self.safety.last_timeout_view() != Some(*view) {
                        return Err(CoreError::InvalidRecovery(
                            "timeout intent does not match last timeout view",
                        ));
                    }
                    if *high_qc != self.safety.high_qc().qc_ref() {
                        return Err(CoreError::InvalidRecovery(
                            "timeout intent does not reference the durable high QC",
                        ));
                    }
                    TimeoutVote::signing_root_for_set(set, *view, *high_qc)?
                }
            };
            if expected != intent.signing_root() {
                return Err(CoreError::InvalidRecovery(
                    "persisted signing root is incorrect",
                ));
            }
        }
        if let Some(proof_id) = self.safety.pending_finalize() {
            let durable = self
                .safety
                .pending_finalization()
                .ok_or(CoreError::InvalidRecovery(
                    "finalization outbox has no ordered queue front",
                ))?;
            if durable.proof_id() != proof_id {
                return Err(CoreError::InvalidRecovery(
                    "finalization outbox id is not the ordered queue-front proof id",
                ));
            }
            if durable.authenticated_parent() != self.safety.application_applied() {
                return Err(CoreError::InvalidRecovery(
                    "finalization outbox does not directly extend the application-applied watermark",
                ));
            }
        }
        if let Some(halt) = self.safety.safety_halt() {
            match halt {
                SafetyHalt::ConflictingQuorumCertificates { first, second } => {
                    if verify_durable_crypto {
                        self.verify_ordinary_qc(first, verifier)?;
                        self.verify_ordinary_qc(second, verifier)?;
                    }
                    let canonical = SafetyHalt::from_conflicting_qcs(
                        first.as_ref().clone(),
                        second.as_ref().clone(),
                    )?;
                    if &canonical != halt {
                        return Err(CoreError::InvalidRecovery(
                            "safety-halt QC pair is not canonically encoded",
                        ));
                    }
                }
                SafetyHalt::ConflictingPayloadValidation { first, second, .. } => {
                    // The two local terminal execution results are not network
                    // certificates. The durable halt itself is the fail-closed
                    // record and can never authorize recovery signing.
                    if (*first, *second)
                        != (
                            crate::PayloadTerminalResult::Valid,
                            crate::PayloadTerminalResult::DeterministicallyInvalid,
                        )
                    {
                        return Err(CoreError::InvalidRecovery(
                            "payload terminal conflict is not canonically encoded",
                        ));
                    }
                    let block_id = halt.payload_block_id().ok_or(CoreError::InvalidRecovery(
                        "payload-validation halt has no block identifier",
                    ))?;
                    if self.safety.payload_terminal_result(block_id).is_none() {
                        return Err(CoreError::InvalidRecovery(
                            "payload terminal conflict has no durable first fact",
                        ));
                    }
                }
                SafetyHalt::DeterministicallyInvalidPayload {
                    block_id,
                    reference,
                } => {
                    if self.safety.payload_terminal_result(*block_id)
                        != Some(PayloadTerminalResult::DeterministicallyInvalid)
                    {
                        return Err(CoreError::InvalidRecovery(
                            "invalid-payload halt has no durable invalid fact",
                        ));
                    }
                    match reference {
                        InvalidPayloadReference::QuorumCertificate(certificate) => {
                            if certificate.block_id() != *block_id {
                                return Err(CoreError::InvalidRecovery(
                                    "invalid-payload QC witness names a different block",
                                ));
                            }
                            if verify_durable_crypto {
                                self.verify_ordinary_qc(certificate, verifier)?;
                            }
                        }
                        InvalidPayloadReference::TimeoutCertificate(certificate) => {
                            let names_block = certificate
                                .referenced_qcs()
                                .iter()
                                .filter_map(QcReferenceV0::as_ordinary)
                                .any(|referenced| referenced.block_id() == *block_id);
                            if !names_block {
                                return Err(CoreError::InvalidRecovery(
                                    "invalid-payload TC witness does not reference the block",
                                ));
                            }
                            if self.safety.current_view()
                                < certificate.timed_out_view().checked_next()?
                            {
                                return Err(CoreError::InvalidRecovery(
                                    "invalid-payload TC witness is ahead of the durable view",
                                ));
                            }
                            if verify_durable_crypto {
                                certificate.verify(set, None, verifier)?;
                            }
                        }
                        InvalidPayloadReference::PendingVote(intent) => {
                            let SignIntent::Vote {
                                authorizing_safety_revision,
                                view,
                                height,
                                block_id: intent_block_id,
                                signing_root,
                            } = intent.as_ref()
                            else {
                                return Err(CoreError::InvalidRecovery(
                                    "invalid-payload halt cites a timeout-vote intent",
                                ));
                            };
                            if *authorizing_safety_revision == 0
                                || *authorizing_safety_revision > self.safety.revision()
                                || intent_block_id != block_id
                                || Vote::signing_root_for_set(
                                    set,
                                    *view,
                                    *height,
                                    *intent_block_id,
                                )? != *signing_root
                            {
                                return Err(CoreError::InvalidRecovery(
                                    "invalid-payload vote witness is malformed",
                                ));
                            }
                        }
                    }
                    let canonical = SafetyHalt::deterministically_invalid_payload(
                        *block_id,
                        reference.clone(),
                    )?;
                    if &canonical != halt {
                        return Err(CoreError::InvalidRecovery(
                            "invalid-payload halt is not canonically encoded",
                        ));
                    }
                }
            }
            if self.safety.pending_sign().is_some()
                || self.safety.pending_tc_high_qc_sync().is_some()
                || self.safety.pending_standalone_qc_sync().is_some()
                || !self.safety.payload_validation_obligations().is_empty()
            {
                return Err(CoreError::InvalidRecovery(
                    "safety-halted state contains an active signing/sync outbox or validation obligation",
                ));
            }
        }
        Ok(())
    }

    fn validate_monotonic_transition(&self, previous: &SafetyState) -> Result<()> {
        self.validate_monotonic_transition_inner(previous, false)
    }

    fn validate_monotonic_transition_inner(
        &self,
        previous: &SafetyState,
        persisted_pair: bool,
    ) -> Result<()> {
        if self.safety.authenticated_genesis_application_parent_v0()
            != previous.authenticated_genesis_application_parent_v0()
        {
            return Err(CoreError::InvalidRecovery(
                "authenticated genesis application parent was installed, removed, or changed by a live transition",
            ));
        }
        if self.safety.state_sync_anchor() != previous.state_sync_anchor() {
            return Err(CoreError::InvalidRecovery(
                "state-sync anchor was installed, removed, or changed by a live transition",
            ));
        }
        if let Some(anchor) = self.safety.state_sync_anchor() {
            let previous_promoted = previous.revision() >= 5;
            let current_promoted = self.safety.revision() >= 5;
            if !previous_promoted && current_promoted {
                let exact_predecessor =
                    Self::state_sync_anchor_state_at_revision_v0(&self.safety, 4);
                if previous.revision() != 4
                    || self.safety.revision() != 5
                    || &exact_predecessor != previous
                    || !Self::is_exact_state_sync_anchor_ordinary_promotion_cut_v0(
                        &self.config,
                        &self.safety,
                        anchor,
                    )?
                {
                    return Err(CoreError::InvalidRecovery(
                        "state-sync anchor promotion is not the exact revision-four to revision-five cut",
                    ));
                }
            } else if previous_promoted && !current_promoted {
                return Err(CoreError::InvalidRecovery(
                    "state-sync anchored ordinary promotion regressed",
                ));
            }
        }
        if self.safety.current_view() < previous.current_view() {
            return Err(CoreError::InvalidRecovery("current view regressed"));
        }
        if option_regressed(previous.last_voted_view(), self.safety.last_voted_view()) {
            return Err(CoreError::InvalidRecovery("last voted view regressed"));
        }
        if option_regressed(
            previous.last_timeout_view(),
            self.safety.last_timeout_view(),
        ) {
            return Err(CoreError::InvalidRecovery("last timeout view regressed"));
        }
        let high = self.safety.high_qc().qc_ref();
        let previous_high = previous.high_qc().qc_ref();
        if high.view() == previous_high.view() && high.block_id() != previous_high.block_id() {
            return Err(CoreError::InvalidRecovery(
                "high QC changed block at the same view",
            ));
        }
        if high.block_id() == previous_high.block_id()
            && (high.view() != previous_high.view() || high.height() != previous_high.height())
        {
            return Err(CoreError::InvalidRecovery(
                "high QC changed coordinates for one block",
            ));
        }
        if qc_order_key_ref(self.safety.high_qc()) < qc_order_key_ref(previous.high_qc()) {
            return Err(CoreError::InvalidRecovery("high QC regressed"));
        }

        let locked = self.safety.locked_qc().qc_ref();
        let previous_locked = previous.locked_qc().qc_ref();
        if locked.view() == previous_locked.view()
            && locked.block_id() != previous_locked.block_id()
        {
            return Err(CoreError::InvalidRecovery(
                "locked QC changed block at the same view",
            ));
        }
        if locked.block_id() == previous_locked.block_id()
            && (locked.view() != previous_locked.view()
                || locked.height() != previous_locked.height())
        {
            return Err(CoreError::InvalidRecovery(
                "locked QC changed coordinates for one block",
            ));
        }
        if qc_order_key_ref(self.safety.locked_qc()) < qc_order_key_ref(previous.locked_qc()) {
            return Err(CoreError::InvalidRecovery("locked QC regressed"));
        }
        if self.safety.finalized().height() < previous.finalized().height()
            || self.safety.finalized().view() < previous.finalized().view()
        {
            return Err(CoreError::InvalidRecovery("finalized tip regressed"));
        }
        if self.safety.finalized().height() == previous.finalized().height()
            && self.safety.finalized() != previous.finalized()
        {
            return Err(CoreError::InvalidRecovery(
                "finalized tip changed at the same height",
            ));
        }
        if self.safety.finalized() == previous.finalized()
            && self.safety.last_finalization() != previous.last_finalization()
        {
            return Err(CoreError::InvalidRecovery(
                "permanent finalization carrier changed without advancing finality",
            ));
        }
        if self.safety.revision() < previous.revision()
            || self.safety.revision().saturating_sub(previous.revision()) > 1
        {
            return Err(CoreError::InvalidRecovery(
                "safety-state revision is not monotonic",
            ));
        }
        if self.safety.pending_sign() != previous.pending_sign() {
            if let Some(intent) = self.safety.pending_sign() {
                if intent.authorizing_safety_revision() != self.safety.revision() {
                    return Err(CoreError::InvalidRecovery(
                        "new signing intent is not authorized by its persistence revision",
                    ));
                }
                let watermark_advanced = match intent {
                    SignIntent::Vote { view, .. } => previous
                        .last_voted_view()
                        .is_none_or(|previous_view| previous_view < *view),
                    SignIntent::TimeoutVote { view, .. } => previous
                        .last_timeout_view()
                        .is_none_or(|previous_view| previous_view < *view),
                };
                if !watermark_advanced {
                    return Err(CoreError::InvalidRecovery(
                        "pending signing intent was introduced without advancing its watermark",
                    ));
                }
            }
        }
        let previous_queue = previous.finalization_queue();
        let current_queue = self.safety.finalization_queue();
        let retained_previous = if self.safety.application_applied()
            == previous.application_applied()
        {
            previous_queue
        } else {
            let Some(previous_front) = previous_queue.first() else {
                return Err(CoreError::InvalidRecovery(
                    "application-applied watermark changed without a prior queue front",
                ));
            };
            if self.safety.application_applied() != durable_finalization_target(previous_front) {
                return Err(CoreError::InvalidRecovery(
                    "application-applied watermark did not consume the exact queue front",
                ));
            }
            &previous_queue[1..]
        };
        if !current_queue.starts_with(retained_previous) {
            return Err(CoreError::InvalidRecovery(
                "application-finalization queue removed, reordered, or replaced a non-front entry",
            ));
        }
        let appended = &current_queue[retained_previous.len()..];
        let finality_advanced = self.safety.finalized().height() > previous.finalized().height();
        if appended.is_empty() == finality_advanced {
            return Err(CoreError::InvalidRecovery(
                "consensus finality and the ordered application queue did not advance together",
            ));
        }
        if let Some(first) = appended.first() {
            if first.authenticated_parent() != previous.finalized()
                || durable_finalization_target(appended.last().expect("nonempty appended queue"))
                    != self.safety.finalized()
            {
                return Err(CoreError::InvalidRecovery(
                    "new application finalizations do not exactly span the consensus-finality advance",
                ));
            }
        }
        match (
            previous.pending_tc_high_qc_sync(),
            self.safety.pending_tc_high_qc_sync(),
        ) {
            (Some(previous), Some(current)) if previous != current => {
                return Err(CoreError::InvalidRecovery(
                    "pending TC high-QC sync target changed",
                ));
            }
            (Some(previous), None) if self.safety.safety_halt().is_none() => {
                let selected_is_subsumed = match previous.selected_high_qc().as_ordinary() {
                    Some(certificate) => self.qc_is_durably_subsumed(certificate)?,
                    None => false,
                };
                if (!selected_is_subsumed
                    && qc_order_key_ref(self.safety.high_qc())
                        < qc_order_key_ref(previous.selected_high_qc()))
                    || self.safety.current_view() < previous.timed_out_view().checked_next()?
                {
                    return Err(CoreError::InvalidRecovery(
                        "pending TC sync cleared before adopting or subsuming its target",
                    ));
                }
            }
            _ => {}
        }
        let previous_standalone = previous.pending_standalone_qc_sync();
        let current_standalone = self.safety.pending_standalone_qc_sync();
        if previous_standalone != current_standalone
            && self.safety.revision() != previous.revision().saturating_add(1)
        {
            return Err(CoreError::InvalidRecovery(
                "standalone QC sync changed without a durable transition",
            ));
        }
        match (previous_standalone, current_standalone) {
            (None, Some(current)) if !current.backlog().is_empty() => {
                return Err(CoreError::InvalidRecovery(
                    "standalone QC sync was created with a backlog",
                ));
            }
            (Some(previous), current) if self.safety.safety_halt().is_none() => {
                let previous_queue: Vec<_> = core::iter::once(previous.active())
                    .chain(previous.backlog())
                    .collect();
                let current_queue: Vec<_> = current
                    .into_iter()
                    .flat_map(|pending| core::iter::once(pending.active()).chain(pending.backlog()))
                    .collect();
                let added: Vec<_> = current_queue
                    .iter()
                    .copied()
                    .filter(|certificate| !previous_queue.contains(certificate))
                    .collect();
                let removed: Vec<_> = previous_queue
                    .iter()
                    .copied()
                    .filter(|certificate| !current_queue.contains(certificate))
                    .collect();
                if !added.is_empty() {
                    if !removed.is_empty()
                        || added.len() > 1
                        || current.is_none_or(|pending| pending.active() != previous.active())
                        || !qc_sequence_is_subsequence(&previous_queue, &current_queue)
                    {
                        return Err(CoreError::InvalidRecovery(
                            "standalone QC backlog insertion replaced an existing target",
                        ));
                    }
                } else if !removed.is_empty() {
                    if !qc_sequence_is_subsequence(&current_queue, &previous_queue) {
                        return Err(CoreError::InvalidRecovery(
                            "standalone QC targets changed order while being cleared",
                        ));
                    }
                    let first_retained_index = previous_queue
                        .iter()
                        .position(|certificate| current_queue.contains(certificate))
                        .unwrap_or(previous_queue.len());
                    for (index, certificate) in previous_queue.iter().copied().enumerate() {
                        if !removed.contains(&certificate) {
                            continue;
                        }
                        let subsumed = self.qc_is_durably_subsumed(certificate)?;
                        let processed_ready_prefix = index < first_retained_index
                            && qc_order_key_ref(self.safety.high_qc()) >= qc_order_key(certificate)
                            && if persisted_pair {
                                !self.payload_is_deterministically_invalid(certificate.block_id())
                            } else {
                                self.qc_is_ready_for_adoption(certificate)?
                            };
                        if !subsumed && !processed_ready_prefix {
                            return Err(CoreError::InvalidRecovery(
                                "standalone QC target was removed before processing or finality subsumption",
                            ));
                        }
                    }
                } else if previous_queue != current_queue {
                    return Err(CoreError::InvalidRecovery(
                        "standalone QC targets were replaced or reordered",
                    ));
                }
            }
            (None, None) | (None, Some(_)) | (Some(_), None) | (Some(_), Some(_)) => {}
        }
        if previous.safety_halt().is_some() && self.safety.safety_halt() != previous.safety_halt() {
            return Err(CoreError::InvalidRecovery(
                "safety halt was cleared or changed",
            ));
        }
        let previous_obligations = previous.payload_validation_obligations();
        let current_obligations = self.safety.payload_validation_obligations();
        for previous_obligation in previous_obligations {
            if let Ok(index) = current_obligations.binary_search_by_key(
                &previous_obligation.id(),
                DurablePayloadValidationObligationV0::id,
            ) {
                if &current_obligations[index] != previous_obligation {
                    return Err(CoreError::InvalidRecovery(
                        "durable payload validation obligation changed in place",
                    ));
                }
            }
        }
        let added_obligations: Vec<_> = current_obligations
            .iter()
            .filter(|obligation| {
                previous_obligations
                    .binary_search_by_key(
                        &obligation.id(),
                        DurablePayloadValidationObligationV0::id,
                    )
                    .is_err()
            })
            .collect();
        let removed_obligations: Vec<_> = previous_obligations
            .iter()
            .filter(|obligation| {
                current_obligations
                    .binary_search_by_key(
                        &obligation.id(),
                        DurablePayloadValidationObligationV0::id,
                    )
                    .is_err()
            })
            .collect();
        if !added_obligations.is_empty() || !removed_obligations.is_empty() {
            if self.safety.revision() != previous.revision().saturating_add(1) {
                return Err(CoreError::InvalidRecovery(
                    "payload validation obligations changed without one durable transition",
                ));
            }
            if added_obligations.len() > 1
                || added_obligations.iter().any(|obligation| {
                    obligation.first_recorded_revision() != self.safety.revision()
                })
            {
                return Err(CoreError::InvalidRecovery(
                    "payload validation obligations were not inserted canonically",
                ));
            }
            if self.safety.safety_halt().is_none()
                && (!added_obligations.is_empty() && !removed_obligations.is_empty()
                    || removed_obligations.len() > 1)
            {
                return Err(CoreError::InvalidRecovery(
                    "payload validation obligations were replaced or removed in bulk",
                ));
            }
        }
        let previous_completions = previous.payload_validation_completions();
        let current_completions = self.safety.payload_validation_completions();
        for previous_completion in previous_completions {
            if let Ok(index) = current_completions.binary_search_by_key(
                &previous_completion.key(),
                DurablePayloadValidationCompletionV0::key,
            ) {
                if &current_completions[index] != previous_completion {
                    return Err(CoreError::InvalidRecovery(
                        "durable payload validation completion changed in place",
                    ));
                }
            }
        }
        let added_completions: Vec<_> = current_completions
            .iter()
            .filter(|completion| {
                previous_completions
                    .binary_search_by_key(
                        &completion.key(),
                        DurablePayloadValidationCompletionV0::key,
                    )
                    .is_err()
            })
            .collect();
        let removed_completions: Vec<_> = previous_completions
            .iter()
            .filter(|completion| {
                current_completions
                    .binary_search_by_key(
                        &completion.key(),
                        DurablePayloadValidationCompletionV0::key,
                    )
                    .is_err()
            })
            .collect();
        if !removed_completions.is_empty() {
            return Err(CoreError::InvalidRecovery(
                "durable payload validation completion was removed without an acknowledged outbox retirement",
            ));
        }
        if !added_completions.is_empty() {
            if self.safety.revision() != previous.revision().saturating_add(1)
                || added_completions.len() != 1
                || added_completions[0].first_recorded_revision() != self.safety.revision()
            {
                return Err(CoreError::InvalidRecovery(
                    "payload validation completion was not inserted canonically in one durable transition",
                ));
            }
            let completion = added_completions[0];
            if !added_obligations.is_empty()
                || !removed_obligations.iter().any(|obligation| {
                    obligation.route() == completion.route() && obligation.id() == completion.id()
                })
            {
                return Err(CoreError::InvalidRecovery(
                    "payload validation completion did not consume its exact durable obligation",
                ));
            }
        } else if self.safety.safety_halt().is_none()
            && !removed_obligations.is_empty()
            && (!added_obligations.is_empty()
                || removed_obligations.len() != 1
                || removed_obligations[0].route() != PayloadValidationRouteV0::Synced)
        {
            return Err(CoreError::InvalidRecovery(
                    "payload validation obligation was removed without a completion or exact synced cancellation",
                ));
        }
        for previous_fact in previous.payload_terminal_facts() {
            if let Some(current) = self
                .safety
                .payload_terminal_facts()
                .iter()
                .find(|current| current.block_id() == previous_fact.block_id())
            {
                if current != previous_fact {
                    return Err(CoreError::InvalidRecovery(
                        "durable payload terminal fact changed",
                    ));
                }
            }
        }
        let removed: Vec<_> = previous
            .payload_terminal_facts()
            .iter()
            .filter(|previous_fact| {
                self.safety
                    .payload_terminal_result(previous_fact.block_id())
                    .is_none()
            })
            .collect();
        let added: Vec<_> = self
            .safety
            .payload_terminal_facts()
            .iter()
            .filter(|current_fact| {
                previous
                    .payload_terminal_result(current_fact.block_id())
                    .is_none()
            })
            .collect();
        if added.len() > 1
            || added
                .iter()
                .any(|fact| fact.first_recorded_revision() != self.safety.revision())
        {
            return Err(CoreError::InvalidRecovery(
                "payload terminal facts were not inserted by one durable transition",
            ));
        }
        if removed.is_empty() {
            if !added.is_empty()
                && previous.payload_terminal_facts().len() >= self.config.max_observed_messages()
            {
                return Err(CoreError::InvalidRecovery(
                    "full payload terminal cache grew without canonical eviction",
                ));
            }
        } else {
            if removed.len() != 1
                || added.len() != 1
                || previous.payload_terminal_facts().len() != self.config.max_observed_messages()
                || self.safety.payload_terminal_facts().len() != self.config.max_observed_messages()
            {
                return Err(CoreError::InvalidRecovery(
                    "payload terminal fact deletion is not a bounded replacement",
                ));
            }
            let protected = durable_payload_fact_blocks(previous);
            let expected = previous
                .payload_terminal_facts()
                .iter()
                .filter(|fact| !protected.contains(&fact.block_id()))
                .min_by_key(|fact| (fact.first_recorded_revision(), fact.block_id()))
                .map(|fact| fact.block_id())
                .ok_or(CoreError::InvalidRecovery(
                    "payload terminal replacement evicted a protected fact",
                ))?;
            if removed[0].block_id() != expected {
                return Err(CoreError::InvalidRecovery(
                    "payload terminal replacement did not evict the canonical oldest fact",
                ));
            }
        }
        // The observation cache is allowed to learn several certificates in
        // one authenticated carrier (for example, a TC), and a stronger
        // encoding for an already-known coordinate may replace the prior
        // witness.  Validate the durable delta as the exact bounded-BTreeMap
        // operation rather than assuming one QC per input.  In particular,
        // removals may only be the lowest-view prefix evicted by the bound;
        // no arbitrary historical entry can disappear across a restart.
        let previous_observed = previous.durable_observed_qcs();
        let current_observed = self.safety.durable_observed_qcs();
        if previous_observed != current_observed {
            if self.safety.revision() != previous.revision().saturating_add(1) {
                return Err(CoreError::InvalidRecovery(
                    "durable observed QC set changed without one durable transition",
                ));
            }
            let maximum = self.config.max_observed_messages();
            if current_observed.len() > maximum
                || current_observed
                    .windows(2)
                    .any(|pair| pair[0].view() >= pair[1].view())
            {
                return Err(CoreError::InvalidRecovery(
                    "durable observed QC set is not a bounded ordered set",
                ));
            }

            let mut removed_count = 0usize;
            let mut added_count = 0usize;
            for (index, previous_certificate) in previous_observed.iter().enumerate() {
                match current_observed
                    .iter()
                    .find(|candidate| candidate.view() == previous_certificate.view())
                {
                    Some(current_certificate) => {
                        if index < removed_count {
                            return Err(CoreError::InvalidRecovery(
                                "durable observed QC removed a non-prefix entry",
                            ));
                        }
                        if current_certificate.block_id() != previous_certificate.block_id()
                            || current_certificate.height() != previous_certificate.height()
                            || current_certificate.epoch() != previous_certificate.epoch()
                            || current_certificate.id() < previous_certificate.id()
                            || (current_certificate.id() == previous_certificate.id()
                                && current_certificate != previous_certificate)
                        {
                            return Err(CoreError::InvalidRecovery(
                                "durable observed QC changed coordinates or regressed its digest",
                            ));
                        }
                    }
                    None => removed_count = removed_count.saturating_add(1),
                }
            }
            for current_certificate in current_observed {
                if !previous_observed
                    .iter()
                    .any(|candidate| candidate.view() == current_certificate.view())
                {
                    added_count = added_count.saturating_add(1);
                }
            }
            if removed_count > 0 {
                if previous_observed.len() != maximum
                    || current_observed.len() != maximum
                    || removed_count > added_count
                {
                    return Err(CoreError::InvalidRecovery(
                        "durable observed QC eviction was not a bounded replacement",
                    ));
                }
                for previous_certificate in previous_observed.iter().skip(removed_count) {
                    if !current_observed
                        .iter()
                        .any(|candidate| candidate.view() == previous_certificate.view())
                    {
                        return Err(CoreError::InvalidRecovery(
                            "durable observed QC eviction removed a non-prefix entry",
                        ));
                    }
                }
            }
            if current_observed.len()
                != previous_observed
                    .len()
                    .saturating_sub(removed_count)
                    .saturating_add(added_count)
            {
                return Err(CoreError::InvalidRecovery(
                    "durable observed QC delta does not match bounded insertion",
                ));
            }
        }
        Ok(())
    }
}

/// Checks only the parent/target context relation already implied by an exact
/// authenticated ancestry edge. Epoch-anchor authorization remains a separate
/// proposal-admission prerequisite; this helper must not make an epoch handoff
/// impossible by requiring its new context to equal the terminal old context.
pub(crate) fn payload_parent_context_matches_target_v0(
    target: &BlockHeader,
    parent: &BlockHeader,
) -> Result<bool> {
    if target.genesis_hash() != parent.genesis_hash() || target.chain_id() != parent.chain_id() {
        return Ok(false);
    }
    if target.block_kind() == BlockKind::EpochHandoff {
        return Ok(parent.block_kind() == BlockKind::EpochSeal2
            && target.epoch() == parent.epoch().checked_next()?);
    }
    Ok(target.protocol_version() == parent.protocol_version()
        && target.epoch() == parent.epoch()
        && target.validator_set_id() == parent.validator_set_id()
        && target.consensus_parameters_hash() == parent.consensus_parameters_hash())
}

fn payload_genesis_parent_matches_config_v0(
    parent: &PayloadValidationParentV0,
    config: &CoreConfig,
) -> bool {
    let tip = parent.tip();
    if !matches!(
        parent.provenance(),
        crate::PayloadValidationParentProvenanceV0::Finalized
    ) || tip.height().get() != 0
        || tip.view().get() != 0
        || tip.block_id() != config.genesis_block_id()
        || tip.timestamp_ms() != config.trusted_genesis_timestamp_ms()
    {
        return false;
    }
    match (
        parent.authenticated_genesis_application_parent_v0(),
        config
            .authenticated_genesis_application_parent_v0()
            .copied(),
    ) {
        (Some(parent), Some(configured)) => parent == configured,
        (None, None) => parent.is_legacy_trusted_genesis_v0(),
        (Some(_), None) | (None, Some(_)) => false,
    }
}

/// Selects leaders by round-robin over the validator set's canonical order.
pub fn leader_for(validator_set: &ValidatorSet, view: View) -> ValidatorId {
    let validators = validator_set.validators();
    debug_assert!(!validators.is_empty());
    let index = (view.get().saturating_sub(1) % validators.len() as u64) as usize;
    validators[index].id()
}

fn proposal_referenced_qcs(proposal: &SignedProposalV0) -> Vec<&QuorumCertificate> {
    let mut certificates = Vec::new();
    if let Some(certificate) = proposal.witness().justify_qc().as_ordinary() {
        certificates.push(certificate);
    }
    if let Some(timeout) = proposal.witness().timeout_certificate() {
        for reference in timeout.referenced_qcs() {
            if let Some(certificate) = reference.as_ordinary() {
                if !certificates
                    .iter()
                    .any(|existing| existing.id() == certificate.id())
                {
                    certificates.push(certificate);
                }
            }
        }
    }
    certificates
}

fn ordinary_qcs_in_processing_order(certificate: &TimeoutCertificateV0) -> Vec<QuorumCertificate> {
    let mut certificates: Vec<_> = certificate
        .referenced_qcs()
        .iter()
        .filter_map(QcReferenceV0::as_ordinary)
        .cloned()
        .collect();
    certificates.sort_by_key(qc_order_key);
    certificates
}

fn pending_tc_sync_max_height(pending: &PendingTcHighQcSync) -> u64 {
    pending
        .timeout_certificate()
        .referenced_qcs()
        .iter()
        .map(|reference| reference.qc_ref().height().get())
        .max()
        .unwrap_or_else(|| pending.selected_high_qc().qc_ref().height().get())
}

fn pending_tc_contains_qc(pending: &PendingTcHighQcSync, certificate: &QuorumCertificate) -> bool {
    pending
        .timeout_certificate()
        .referenced_qcs()
        .iter()
        .filter_map(QcReferenceV0::as_ordinary)
        .any(|referenced| same_qc_coordinates(referenced, certificate))
}

fn pending_standalone_sync_max_height(pending: &PendingStandaloneQcSync) -> u64 {
    core::iter::once(pending.active())
        .chain(pending.backlog())
        .map(|certificate| certificate.height().get())
        .max()
        .unwrap_or_else(|| pending.active().height().get())
}

fn durable_finalization_target(finalization: &DurableFinalizationV0) -> FinalizedTip {
    let committed = finalization.proof().finalized_block().header();
    FinalizedTip::new(
        committed.height(),
        committed.view(),
        committed.id(),
        committed.timestamp_ms(),
    )
}

fn same_qc_coordinates(first: &QuorumCertificate, second: &QuorumCertificate) -> bool {
    first.view() == second.view()
        && first.height() == second.height()
        && first.block_id() == second.block_id()
}

fn qc_sequence_is_subsequence(
    candidate: &[&QuorumCertificate],
    sequence: &[&QuorumCertificate],
) -> bool {
    let mut matched = 0usize;
    for certificate in sequence {
        if candidate.get(matched) == Some(certificate) {
            matched = matched.saturating_add(1);
        }
    }
    matched == candidate.len()
}

fn durable_payload_fact_blocks(state: &SafetyState) -> Vec<BlockId> {
    let mut protected = vec![
        state.high_qc().qc_ref().block_id(),
        state.locked_qc().qc_ref().block_id(),
        state.finalized().block_id(),
    ];
    if let Some(pending) = state.pending_tc_high_qc_sync() {
        protected.extend(
            pending
                .timeout_certificate()
                .referenced_qcs()
                .iter()
                .map(|reference| reference.qc_ref().block_id()),
        );
    }
    if let Some(pending) = state.pending_standalone_qc_sync() {
        protected.extend(
            core::iter::once(pending.active())
                .chain(pending.backlog())
                .map(QuorumCertificate::block_id),
        );
    }
    if let Some(anchor) = state.state_sync_anchor() {
        let proof = anchor.proof();
        for certified in [proof.finalized_block(), proof.child(), proof.grandchild()] {
            protected.push(certified.header().id());
            protected.push(certified.justify_qc().qc_ref().block_id());
            if let Some(timeout) = certified.timeout_certificate() {
                protected.extend(
                    timeout
                        .referenced_qcs()
                        .iter()
                        .map(|reference| reference.qc_ref().block_id()),
                );
            }
        }
    }
    for finalization in state.finalization_queue().iter().chain(
        state
            .last_finalization()
            .into_iter()
            .filter(|latest| state.finalization_queue().last() != Some(*latest)),
    ) {
        let proof = finalization.proof();
        for certified in [proof.finalized_block(), proof.child(), proof.grandchild()] {
            protected.push(certified.header().id());
            protected.push(certified.justify_qc().qc_ref().block_id());
            if let Some(timeout) = certified.timeout_certificate() {
                protected.extend(
                    timeout
                        .referenced_qcs()
                        .iter()
                        .map(|reference| reference.qc_ref().block_id()),
                );
            }
        }
    }
    if let Some(SignIntent::Vote { block_id, .. }) = state.pending_sign() {
        protected.push(*block_id);
    }
    if let Some(block_id) = state.safety_halt().and_then(SafetyHalt::payload_block_id) {
        protected.push(block_id);
    }
    protected.sort_unstable();
    protected.dedup();
    protected
}

fn exact_current_native_valid_completion_v0(
    state: &SafetyState,
) -> Result<&DurablePayloadValidationCompletionV0> {
    let mut current = state
        .payload_validation_completions()
        .iter()
        .filter(|completion| completion.first_recorded_revision() == state.revision());
    let completion = match (current.next(), current.next()) {
        (None, _) => return Err(CoreError::NativeValidCompletionRecoveryNotRequired),
        (Some(completion), None) => completion,
        (Some(_), Some(_)) => {
            return Err(CoreError::NativeValidCompletionRecoveryRejected(
                "bounded recovery requires exactly one completion first recorded at the current revision",
            ));
        }
    };
    let result = completion.result();
    let Some(artifact) = result.artifact_ref() else {
        return Err(CoreError::NativeValidCompletionRecoveryRejected(
            "the current durable completion is not Valid",
        ));
    };
    let Some(terminal) = state.payload_terminal_fact(completion.id().block_id()) else {
        return Err(CoreError::NativeValidCompletionRecoveryRejected(
            "the current Valid completion lacks its terminal fact",
        ));
    };
    if terminal.result() != PayloadTerminalResult::Valid
        || terminal.valid_overlay() != Some(artifact.overlay())
        || state
            .payload_validation_obligations()
            .iter()
            .any(|obligation| {
                obligation.route() == completion.route() && obligation.id() == completion.id()
            })
        || native_valid_result_checksum_v0(result).is_none()
    {
        return Err(CoreError::NativeValidCompletionRecoveryRejected(
            "the current Valid completion is not exactly congruent with durable Core state",
        ));
    }
    Ok(completion)
}

fn native_valid_completion_recovery_action_matches_state_v0(
    action: NativeValidPostAckActionV0,
    state: &SafetyState,
) -> bool {
    let has_halt = state.safety_halt().is_some();
    let has_sign = state.pending_sign().is_some();
    let has_fresh_vote = state.pending_sign().is_some_and(|intent| {
        matches!(intent, SignIntent::Vote { .. })
            && intent.authorizing_safety_revision() == state.revision()
    });
    let has_finalize = state.pending_finalize().is_some()
        && state.pending_finalize()
            == state
                .pending_finalization()
                .map(DurableFinalizationV0::proof_id);
    let has_tc = state.pending_tc_high_qc_sync().is_some();
    let has_standalone = state.pending_standalone_qc_sync().is_some();
    match action {
        // These two action shapes carry no independently derivable durable
        // discriminator between them. Their exact distinction is
        // authenticated by the SafetyStore transition and trusted App
        // reconciler, but neither may mask another durable outbox.
        NativeValidPostAckActionV0::None | NativeValidPostAckActionV0::ArmViewTimer => {
            !has_halt && !has_sign && !has_finalize && !has_tc && !has_standalone
        }
        NativeValidPostAckActionV0::RequestSignature => {
            !has_halt && has_fresh_vote && !has_finalize && !has_tc && !has_standalone
        }
        NativeValidPostAckActionV0::ArmViewTimerThenFinalize => {
            !has_halt && !has_sign && has_finalize && !has_tc && !has_standalone
        }
        NativeValidPostAckActionV0::RequestTcHighQcSync => {
            !has_halt && !has_sign && !has_finalize && has_tc && !has_standalone
        }
        NativeValidPostAckActionV0::RequestStandaloneQcSync
        | NativeValidPostAckActionV0::ArmViewTimerThenRequestStandaloneQcSync => {
            !has_halt && !has_sign && !has_finalize && !has_tc && has_standalone
        }
        NativeValidPostAckActionV0::SafetyHaltedConflict => {
            has_halt && !has_sign && !has_finalize && !has_tc && !has_standalone
        }
    }
}

fn validate_native_finalization_applied_recovery_reconciliation_v0(
    state: &SafetyState,
    transition: &NativeFinalizationAppliedRecoveryTransitionV0,
    readback: &crate::ApplicationFinalizationApplyReadbackV0,
) -> Result<()> {
    let applied = state.application_applied();
    let exact_source_count = state
        .payload_validation_completions()
        .iter()
        .filter(|completion| {
            completion.route() == readback.source_route()
                && completion.id() == readback.source_validation_id()
                && completion.result().artifact_ref().is_some_and(|artifact| {
                    artifact.source_artifact_checksum() == readback.source_artifact_checksum()
                        && artifact.overlay().block_id() == applied.block_id()
                        && artifact.overlay().parent_block_id() == transition.parent_block_id()
                        && artifact.overlay().overlay_checksum() == transition.overlay_checksum()
                })
        })
        .count();
    if transition.transition_revision() != state.revision()
        || transition.ordinal() != applied.height().get()
        || transition.target_block_id() != applied.block_id()
        || transition.source_route() != readback.source_route()
        || transition.source_validation_id() != readback.source_validation_id()
        || transition.source_validation_id().block_id() != applied.block_id()
        || transition.source_validation_id().view() != applied.view()
        || transition.application_host_config_ref() != readback.application_host_config_ref()
        || transition.finalization_checksum() != readback.finalization_checksum()
        || transition.source_artifact_checksum() != readback.source_artifact_checksum()
        || transition.accepted_source_checksum() != readback.accepted_source_checksum()
        || transition.applied_job_row_checksum() != readback.applied_job_row_checksum()
        || transition.prior_head_checksum() != readback.prior_head_checksum()
        || transition.new_head_checksum() != readback.new_head_checksum()
        || transition.application_receipt_row_checksum() != readback.receipt_row_checksum()
        || transition.parent_block_id() == transition.target_block_id()
        || transition.overlay_checksum() == [0; 32]
        || transition.proof_id().is_zero()
        || exact_source_count != 1
        || !native_finalization_applied_recovery_action_matches_state_v0(
            transition.post_ack_action_v0(),
            state,
        )
    {
        return Err(CoreError::NativeFinalizationAppliedRecoveryRejected(
            "tag-3 transition, SafetyState, and ApplicationStore readback are not exactly congruent",
        ));
    }
    Ok(())
}

fn native_finalization_applied_recovery_action_matches_state_v0(
    action: NativeFinalizationAppliedPostAckActionV0,
    state: &SafetyState,
) -> bool {
    if state.safety_halt().is_some() {
        return false;
    }
    let has_sign = state.pending_sign().is_some();
    let has_fresh_vote = state.pending_sign().is_some_and(|intent| {
        matches!(intent, SignIntent::Vote { .. })
            && intent.authorizing_safety_revision() == state.revision()
    });
    let has_tc = state.pending_tc_high_qc_sync().is_some();
    let has_standalone = state.pending_standalone_qc_sync().is_some();
    let has_finalize = state.pending_finalize().is_some()
        && state.pending_finalize()
            == state
                .pending_finalization()
                .map(DurableFinalizationV0::proof_id);
    match action {
        NativeFinalizationAppliedPostAckActionV0::None
        | NativeFinalizationAppliedPostAckActionV0::ArmViewTimer => {
            !has_sign && !has_tc && !has_standalone && !has_finalize
        }
        NativeFinalizationAppliedPostAckActionV0::RequestSignature
        | NativeFinalizationAppliedPostAckActionV0::ArmViewTimerThenRequestSignature => {
            has_fresh_vote && !has_tc && !has_standalone && !has_finalize
        }
        NativeFinalizationAppliedPostAckActionV0::Finalize
        | NativeFinalizationAppliedPostAckActionV0::ArmViewTimerThenFinalize => {
            !has_sign && !has_tc && has_finalize
        }
        NativeFinalizationAppliedPostAckActionV0::RequestTcHighQcSync => {
            !has_sign && has_tc && !has_finalize
        }
        NativeFinalizationAppliedPostAckActionV0::RequestStandaloneQcSync
        | NativeFinalizationAppliedPostAckActionV0::ArmViewTimerThenRequestStandaloneQcSync => {
            !has_sign && !has_tc && has_standalone && !has_finalize
        }
    }
}

fn state_sync_anchor_replay_reference_is_exact_v0(
    reference: &QcReferenceV0,
    proof: &FinalityProofV0,
    entries: &[AnchoredOrdinarySignedReplayEntryV0],
) -> bool {
    let Some(certificate) = reference.as_ordinary() else {
        return false;
    };
    [
        proof.finalized_block().certifying_qc(),
        proof.child().certifying_qc(),
        proof.grandchild().certifying_qc(),
    ]
    .into_iter()
    .any(|candidate| candidate == certificate)
        || entries
            .iter()
            .any(|entry| &entry.certifying_qc == certificate)
}

fn update_anchored_ordinary_rehydrate_digest_v0(hasher: &mut Sha256, part: &[u8]) {
    hasher.update((part.len() as u64).to_be_bytes());
    hasher.update(part);
}

fn anchored_ordinary_rehydrate_digest_v0(
    plan: &AnchoredOrdinaryReplayArchivePlanV0,
    entries: &[AnchoredOrdinarySignedReplayEntryV0],
) -> Result<[u8; 32]> {
    let mut hasher = Sha256::new();
    hasher.update(b"trnm.domain.hash.v1");
    update_anchored_ordinary_rehydrate_digest_v0(
        &mut hasher,
        ANCHORED_ORDINARY_REHYDRATE_DIGEST_DOMAIN_V0.as_bytes(),
    );
    for part in [
        plan.core_config_ref.as_slice(),
        plan.recovery_challenge_digest.as_slice(),
        plan.archive_context_digest.as_slice(),
        plan.archive_record_digest.as_slice(),
        plan.session_id.as_slice(),
        plan.validation_store_id.as_slice(),
        plan.application_history_digest.as_slice(),
        plan.initial_safety_state_checksum.as_slice(),
        plan.initial_safety_chain_checksum.as_slice(),
        plan.initial_checkpoint_scope.as_slice(),
        plan.initial_checkpoint_profile_ref.as_slice(),
        plan.initial_checkpoint_checksum.as_slice(),
        plan.initial_progress_checksum.as_slice(),
        plan.final_progress_checksum.as_slice(),
        plan.durable_session_row_checksum.as_slice(),
    ] {
        update_anchored_ordinary_rehydrate_digest_v0(&mut hasher, part);
    }
    for scalar in [
        plan.archive_sequence,
        plan.expected_link_count,
        plan.canonical_store_sequence,
        plan.initial_safety_revision,
        plan.initial_checkpoint_generation,
    ] {
        update_anchored_ordinary_rehydrate_digest_v0(&mut hasher, &scalar.to_be_bytes());
    }
    for entry in entries {
        let proposal = &entry.proposal;
        let claim = entry.checkpointed_link;
        let target_core_block_id = claim.target_core_validation_id.block_id();
        update_anchored_ordinary_rehydrate_digest_v0(&mut hasher, proposal.block().id().as_bytes());
        update_anchored_ordinary_rehydrate_digest_v0(
            &mut hasher,
            proposal.proposal_signing_root().as_bytes(),
        );
        update_anchored_ordinary_rehydrate_digest_v0(
            &mut hasher,
            proposal.witness().proposer_signature().as_bytes(),
        );
        update_anchored_ordinary_rehydrate_digest_v0(
            &mut hasher,
            entry.certifying_qc.id().as_bytes(),
        );
        for part in [
            claim.session_id.as_slice(),
            claim.source_validation_store_id.as_slice(),
            claim.target_validation_store_id.as_slice(),
            target_core_block_id.as_bytes(),
            claim.owner_id.as_slice(),
            claim.source_row_checksum.as_slice(),
            claim.source_artifact_checksum.as_slice(),
            claim.source_application_history_checksum.as_slice(),
            claim.alias_closure_checksum.as_slice(),
            claim.checkpoint_scope.as_slice(),
            claim.checkpoint_profile_ref.as_slice(),
            claim.checkpoint_predecessor_checksum.as_slice(),
            claim.checkpoint_checksum.as_slice(),
            claim.previous_progress_checksum.as_slice(),
            claim.progress_checksum.as_slice(),
            claim.link_row_checksum.as_slice(),
        ] {
            update_anchored_ordinary_rehydrate_digest_v0(&mut hasher, part);
        }
        for scalar in [
            claim.cursor,
            claim.target_core_validation_id.view().get(),
            claim.target_core_validation_id.generation(),
            claim.source_store_sequence,
            claim.source_row_revision,
            claim.safety_revision,
            claim.checkpoint_generation,
            claim.link_row_revision,
        ] {
            update_anchored_ordinary_rehydrate_digest_v0(&mut hasher, &scalar.to_be_bytes());
        }
    }
    let digest: [u8; 32] = hasher.finalize().into();
    if digest == [0; 32] {
        return Err(CoreError::AnchoredOrdinaryRehydrateRejected(
            "ordinary replay rehydrate digest is zero",
        ));
    }
    Ok(digest)
}

fn safety_replay_required(state: &SafetyState) -> bool {
    state.high_qc().qc_ref().block_id() != state.finalized().block_id()
        || state.locked_qc().qc_ref().block_id() != state.finalized().block_id()
}

fn qc_order_key(certificate: &QuorumCertificate) -> (View, BlockId, CertificateId) {
    (certificate.view(), certificate.block_id(), certificate.id())
}

fn qc_order_key_ref(reference: &QcReferenceV0) -> (View, BlockId, CertificateId) {
    let summary = reference.qc_ref();
    (summary.view(), summary.block_id(), summary.qc_digest())
}

fn pending_validation_id(
    pending: &BTreeMap<ValidationId, PendingPayloadValidationV0>,
    proposal: &SignedProposalV0,
) -> Option<ValidationId> {
    pending
        .iter()
        .find(|(id, _)| {
            id.block_id() == proposal.block().id() && id.view() == proposal.block().header().view()
        })
        .map(|(id, _)| *id)
}

fn bounded_insert<K: Ord + Copy, V>(map: &mut BTreeMap<K, V>, key: K, value: V, maximum: usize) {
    if map.len() >= maximum && !map.contains_key(&key) {
        if let Some(oldest) = map.keys().next().copied() {
            map.remove(&oldest);
        }
    }
    map.insert(key, value);
}

fn option_regressed(previous: Option<View>, current: Option<View>) -> bool {
    match (previous, current) {
        (Some(previous), Some(current)) => current < previous,
        (Some(_), None) => true,
        (None, _) => false,
    }
}
