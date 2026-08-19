//! Development-only, offline owner for the PoCO-BFT persistence domains.
//!
//! This is deliberately an existing-only recovery host. It owns one Core,
//! SafetyStore, ApplicationStore facade and signer journal for their complete
//! process lifetimes, but executes none of the inert Core effects it retains.
//! It has no producer, network, pacemaker, raw-store getter, `into_parts`, or
//! caller-selected `Core::step` surface.
//!
//! The original h1 state-sync entry remains a permanent offline replay fence:
//! it authenticates and exposes exactly one inert `RequestSafetyReplay`,
//! installs no application authority, and keeps the virgin signer pinned. A
//! separate existing-only entry may instead select the dedicated h1/h2/h3
//! anchored-successor owner before SafetyStore binding. That bounded path
//! admits stable revisions zero, two, and four, executes empty h2/h3
//! application bodies through the native speculative overlay pipeline, never
//! installs finalization authority, and still never signs, networks, or arms a
//! timer. Revision four reconstructs and authenticates the pruned h2 Safety
//! transition against the retained rev3 predecessor chain checksum before the
//! Core recovery session can activate.
//!
//! An ordinary, non-anchored current NativeValid head has a third narrow
//! offline owner. It admits only stable C+D or C+K, closes D to K through the
//! authenticated application recovery kernel, and retains the exact recorded
//! post-ack action only as sanitized inert comparison data. It never rebuilds
//! a callback owner, `StorageAck`, `Effect`, application authority, or signer
//! authority; obligation/P/Applied and ambiguous multi-job shapes remain
//! fail-closed.
//!
//! Configuration rewrites all three store paths through canonical parents and
//! pins their directory device/inode identities. Those identities are checked
//! between owner-open stages and again immediately before signer activation.
//! The underlying stores do not yet expose a common pinned-directory identity
//! projection, so this is not claimed to defeat a privileged instantaneous
//! remount race; production activation remains disabled.
//!
//! Authenticated genesis application commissioning is not one of these
//! recovery modes. It has a structurally separate inert owner, and every
//! generic process configuration/open surface rejects that Core configuration
//! before any SafetyStore, ApplicationStore, signer, or external watermark
//! access.

use std::{
    fmt,
    path::{Path, PathBuf},
};

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

use trnm_consensus_app::{
    ConsensusAppConfig, NativeConsensusApplicationAppliedKindV0,
    NativeConsensusApplicationHostConfigV0, NativeConsensusApplicationHostErrorV0,
    NativeConsensusApplicationHostV0, NativeConsensusApplicationValidCompletionSourceV0,
    NativeValidationRecoveredAckedFactsV0, NativeValidationRecoveredInvalidCallbackFactsV0,
    NativeValidationRecoveredInvalidStateV0, NativeValidationRecoveryReconcileFailureV0,
    NativeValidationRecoveryTransitionFailureV0,
    PreparedNativeApplicationH1ProjectionExpectationV0,
};
use trnm_consensus_core::{
    Core, CoreConfig, DurablePayloadValidationResultV1, Effect, Input,
    NativeValidCompletionRecoveredActionV0, NativeValidCompletionRecoveryReplayV0,
    NativeValidPostAckActionV0, PayloadValidationResult, PayloadValidationRouteV0, SafetyState,
    SafetyStatePersistenceV0, SignIntent, StateSyncAnchorRecoveryChallengeV0,
    StateSyncAnchorRecoveryReconcilerV0, StateSyncAnchorSuccessorPhaseV0,
    StateSyncAnchorSuccessorRecoveryChallengeV0, StateSyncAnchorSuccessorRecoveryReconcilerV0,
    StateSyncAnchorSuccessorReplayV0, ValidationId,
};
use trnm_consensus_crypto::StrictEd25519Verifier;
use trnm_consensus_safety_store::{
    state_sync_anchor_checksum_v0, ConfirmedNativeDeterministicInvalidHeadV0,
    ConfirmedNativeValidHeadV0, ConfirmedStateSyncCheckpointBootstrapHeadV0,
    NativeDeterministicInvalidTransitionV0, RecoveredSafetyStateV0, SafetyTransitionContextV0,
    SqliteSafetyStateStoreV0,
};
use trnm_consensus_signer_journal::{
    ConfirmedSignerNodeCheckpointFactsV0, ExternalMonotonicWatermarkV0, JournalCapacityV0,
    PinnedSqliteSignerJournalV0, SignerExternalWatermarkRelationV0, SignerJournalErrorV0,
    SignerJournalReconciliationFactsV0, SignerJournalTailFactsV0, SignerPreparedIntentFactsV0,
    SqliteSignerJournalV0,
};
use trnm_consensus_types::{CanonicalSignIntentV0, RolloutPhase, SignedProposalV0};

use crate::PocoNodeStartConfigV0;

// SafetyState record authentication is intentionally a deep, exact decoder.
// Run the complete existing-only startup transaction on one bounded worker so
// callers do not inherit that decoder's debug-build stack frame. The worker is
// joined before any owner is returned and no startup work survives this call.
const PROCESS_HOST_STARTUP_AUDIT_STACK_BYTES_V0: usize = 32 * 1024 * 1024;

/// Existing-only configuration for the unified offline owner.
#[derive(Debug)]
pub struct PocoNodeProcessConfigV0 {
    node: PocoNodeStartConfigV0,
    application: ConsensusAppConfig,
    store_parents: ProcessStoreParentIdentitiesV0,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ProcessStoreParentIdentityV0 {
    device: u64,
    inode: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ProcessStoreParentIdentitiesV0 {
    pub(crate) safety: ProcessStoreParentIdentityV0,
    pub(crate) signer: ProcessStoreParentIdentityV0,
    pub(crate) application: ProcessStoreParentIdentityV0,
}

impl PocoNodeProcessConfigV0 {
    pub fn new(
        mut node: PocoNodeStartConfigV0,
        mut application: ConsensusAppConfig,
    ) -> Result<Self, PocoNodeProcessHostErrorV0> {
        reject_authenticated_genesis_commissioning_v0(node.core_config())?;
        application
            .validate()
            .map_err(|_| PocoNodeProcessHostErrorV0::InvalidApplicationConfig)?;
        if application.chain_id != node.core_config().validator_set().chain_id().as_str() {
            return Err(PocoNodeProcessHostErrorV0::ApplicationChainMismatch);
        }
        let application_path = application
            .state_path
            .as_deref()
            .ok_or(PocoNodeProcessHostErrorV0::ApplicationStatePathRequired)?;
        if !application_path.is_absolute() {
            return Err(PocoNodeProcessHostErrorV0::ApplicationStatePathNotAbsolute);
        }
        let (safety_path, safety) = canonical_process_store_path_v0(node.safety_store_path())?;
        let (signer_path, signer) = canonical_process_store_path_v0(node.signer_journal_path())?;
        let (application_path, application_identity) =
            canonical_process_store_path_v0(application_path)?;
        validate_distinct_store_parents_v0(&safety_path, &signer_path, &application_path)?;
        let store_parents = ProcessStoreParentIdentitiesV0 {
            safety,
            signer,
            application: application_identity,
        };
        validate_distinct_store_parent_identities_v0(store_parents)?;
        node.safety_store_path = safety_path;
        node.signer_journal_path = signer_path;
        application.state_path = Some(application_path);
        Ok(Self {
            node,
            application,
            store_parents,
        })
    }

    pub const fn node_config(&self) -> &PocoNodeStartConfigV0 {
        &self.node
    }

    pub const fn application_config(&self) -> &ConsensusAppConfig {
        &self.application
    }

    #[cfg(test)]
    #[allow(dead_code)]
    pub(crate) fn new_for_authenticated_genesis_fence_test_v0(
        node: PocoNodeStartConfigV0,
        application: ConsensusAppConfig,
    ) -> Self {
        let unused = ProcessStoreParentIdentityV0 {
            device: u64::MAX,
            inode: u64::MAX,
        };
        Self {
            node,
            application,
            store_parents: ProcessStoreParentIdentitiesV0 {
                safety: unused,
                signer: unused,
                application: unused,
            },
        }
    }
}

pub(crate) fn canonical_process_store_path_v0(
    path: &Path,
) -> Result<(PathBuf, ProcessStoreParentIdentityV0), PocoNodeProcessHostErrorV0> {
    let file_name = path
        .file_name()
        .ok_or(PocoNodeProcessHostErrorV0::InvalidStorePath)?;
    let parent = std::fs::canonicalize(
        path.parent()
            .ok_or(PocoNodeProcessHostErrorV0::InvalidStorePath)?,
    )
    .map_err(|_| PocoNodeProcessHostErrorV0::StoreParentUnavailable)?;
    let metadata = std::fs::metadata(&parent)
        .map_err(|_| PocoNodeProcessHostErrorV0::StoreParentUnavailable)?;
    if !metadata.is_dir() {
        return Err(PocoNodeProcessHostErrorV0::StoreParentUnavailable);
    }
    let identity = process_store_parent_identity_v0(&metadata)?;
    Ok((parent.join(file_name), identity))
}

#[cfg(unix)]
fn process_store_parent_identity_v0(
    metadata: &std::fs::Metadata,
) -> Result<ProcessStoreParentIdentityV0, PocoNodeProcessHostErrorV0> {
    Ok(ProcessStoreParentIdentityV0 {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

#[cfg(not(unix))]
fn process_store_parent_identity_v0(
    _metadata: &std::fs::Metadata,
) -> Result<ProcessStoreParentIdentityV0, PocoNodeProcessHostErrorV0> {
    Err(PocoNodeProcessHostErrorV0::UnsupportedPlatform)
}

pub(crate) fn validate_distinct_store_parent_identities_v0(
    identities: ProcessStoreParentIdentitiesV0,
) -> Result<(), PocoNodeProcessHostErrorV0> {
    if identities.safety == identities.signer
        || identities.safety == identities.application
        || identities.signer == identities.application
    {
        return Err(PocoNodeProcessHostErrorV0::OverlappingStoreNamespaces);
    }
    Ok(())
}

pub(crate) fn revalidate_process_store_paths_v0(
    safety_path: &Path,
    signer_path: &Path,
    application_path: &Path,
    expected: ProcessStoreParentIdentitiesV0,
) -> Result<(), PocoNodeProcessHostErrorV0> {
    let (safety, safety_identity) = canonical_process_store_path_v0(safety_path)?;
    let (signer, signer_identity) = canonical_process_store_path_v0(signer_path)?;
    let (application, application_identity) = canonical_process_store_path_v0(application_path)?;
    if safety != safety_path || signer != signer_path || application != application_path {
        return Err(PocoNodeProcessHostErrorV0::StoreParentIdentityChanged);
    }
    validate_distinct_store_parents_v0(&safety, &signer, &application)?;
    let actual = ProcessStoreParentIdentitiesV0 {
        safety: safety_identity,
        signer: signer_identity,
        application: application_identity,
    };
    validate_distinct_store_parent_identities_v0(actual)?;
    if actual != expected {
        return Err(PocoNodeProcessHostErrorV0::StoreParentIdentityChanged);
    }
    Ok(())
}

pub(crate) fn validate_distinct_store_parents_v0(
    safety: &Path,
    signer: &Path,
    application: &Path,
) -> Result<(), PocoNodeProcessHostErrorV0> {
    let safety = std::fs::canonicalize(
        safety
            .parent()
            .ok_or(PocoNodeProcessHostErrorV0::InvalidStorePath)?,
    )
    .map_err(|_| PocoNodeProcessHostErrorV0::StoreParentUnavailable)?;
    let signer = std::fs::canonicalize(
        signer
            .parent()
            .ok_or(PocoNodeProcessHostErrorV0::InvalidStorePath)?,
    )
    .map_err(|_| PocoNodeProcessHostErrorV0::StoreParentUnavailable)?;
    let application = std::fs::canonicalize(
        application
            .parent()
            .ok_or(PocoNodeProcessHostErrorV0::InvalidStorePath)?,
    )
    .map_err(|_| PocoNodeProcessHostErrorV0::StoreParentUnavailable)?;
    let overlap = |left: &Path, right: &Path| left.starts_with(right) || right.starts_with(left);
    if overlap(&safety, &signer) || overlap(&safety, &application) || overlap(&signer, &application)
    {
        return Err(PocoNodeProcessHostErrorV0::OverlappingStoreNamespaces);
    }
    Ok(())
}

/// The currently implemented existing-state recovery branches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PocoNodeProcessBootstrapModeV0 {
    Ordinary,
    StateSyncCheckpointBootstrap,
    StateSyncAnchorSuccessor,
    NativeValidCompletionRecoveryOffline,
    DeterministicInvalidObligation,
    DeterministicInvalidCompletion,
    NativeFinalizationApplied,
}

/// A sanitized description of one exact Core effect retained in memory.
///
/// The value carries no message, intent, certificate, timer, or store
/// authority. Order in the enclosing slice is the Core order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PocoNodeInertEffectKindV0 {
    RequestSafetyReplay,
    RequestSignature,
    ArmViewTimer,
    Finalize,
    RequestTcHighQcSync,
    RequestStandaloneQcSync,
    SafetyHalted,
}

/// Copy-only startup evidence. It grants no Core or store authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PocoNodeProcessBootstrapFactsV0 {
    mode: PocoNodeProcessBootstrapModeV0,
    safety_revision: u64,
    application_kind: NativeConsensusApplicationAppliedKindV0,
    application_height: u64,
    application_receipt_count: u64,
    application_valid_completion_count: u64,
    signer: SignerJournalReconciliationFactsV0,
    application_authorities_installed: bool,
    application_seal_authority_installed: bool,
    application_finalization_authority_installed: bool,
    signer_activated: bool,
    native_valid_completion_source: Option<NativeConsensusApplicationValidCompletionSourceV0>,
}

impl PocoNodeProcessBootstrapFactsV0 {
    pub const fn mode(self) -> PocoNodeProcessBootstrapModeV0 {
        self.mode
    }

    pub const fn safety_revision(self) -> u64 {
        self.safety_revision
    }

    pub const fn application_kind(self) -> NativeConsensusApplicationAppliedKindV0 {
        self.application_kind
    }

    pub const fn application_height(self) -> u64 {
        self.application_height
    }

    pub const fn application_receipt_count(self) -> u64 {
        self.application_receipt_count
    }

    pub const fn application_valid_completion_count(self) -> u64 {
        self.application_valid_completion_count
    }

    pub const fn signer(self) -> SignerJournalReconciliationFactsV0 {
        self.signer
    }

    pub const fn application_authorities_installed(self) -> bool {
        self.application_authorities_installed
    }

    pub const fn application_seal_authority_installed(self) -> bool {
        self.application_seal_authority_installed
    }

    pub const fn application_finalization_authority_installed(self) -> bool {
        self.application_finalization_authority_installed
    }

    pub const fn signer_activated(self) -> bool {
        self.signer_activated
    }

    /// Original stable App cut observed by the ordinary NativeValid recovery
    /// branch. `Delivered` means the recovery-only App kernel durably closed
    /// C+D to C+K before the host was returned; `Acked` means C+K was already
    /// stable and was confirmed without a write.
    pub const fn native_valid_completion_source(
        self,
    ) -> Option<NativeConsensusApplicationValidCompletionSourceV0> {
        self.native_valid_completion_source
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PocoNodeProcessLifecyclePhaseV0 {
    ReconciledOffline,
    StateSyncReplayFencedOffline,
    StateSyncAnchorSuccessorOffline,
    NativeValidCompletionRecoveryOffline,
}

/// Unique process owner for the four persistence domains.
///
/// ```compile_fail
/// use trnm_poco_node::PocoNodeProcessHostV0;
/// fn assert_clone<T: Clone>() {}
/// fn host_is_linear<W>() { assert_clone::<PocoNodeProcessHostV0<W>>(); }
/// ```
///
/// ```compile_fail
/// use trnm_poco_node::PocoNodeProcessHostV0;
/// fn raw_parts_are_not_exposed<W>(host: PocoNodeProcessHostV0<W>) {
///     let _ = host.into_parts();
/// }
/// ```
///
/// ```compile_fail
/// use trnm_poco_node::PocoNodeProcessHostV0;
/// fn raw_core_is_not_exposed<W>(host: &PocoNodeProcessHostV0<W>) {
///     let _ = host.core();
/// }
/// ```
///
/// ```compile_fail
/// use trnm_poco_node::PocoNodeProcessHostV0;
/// fn signer_is_not_exposed<W>(host: &PocoNodeProcessHostV0<W>) {
///     let _ = host.signer_journal();
/// }
/// ```
#[must_use = "the unified process host pins all reconciled persistence owners"]
pub struct PocoNodeProcessHostV0<W> {
    core_owner: ProcessCoreOwnerV0,
    safety_store: SqliteSafetyStateStoreV0<StrictEd25519Verifier>,
    application_host: NativeConsensusApplicationHostV0,
    signer_owner: ProcessSignerOwnerV0<W>,
    bootstrap: PocoNodeProcessBootstrapFactsV0,
    pending_inert_effects: Vec<Effect>,
    pending_native_valid_action: Option<NativeValidPostAckActionV0>,
}

enum ProcessCoreOwnerV0 {
    Ordinary(Core),
    AnchorSuccessor(StateSyncAnchorSuccessorReplayV0),
    NativeValidCompletionRecoveryOffline(NativeValidCompletionRecoveryReplayV0),
}

impl fmt::Debug for ProcessCoreOwnerV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ordinary(core) => {
                let _ = core;
                formatter.write_str("Ordinary")
            }
            Self::AnchorSuccessor(replay) => {
                let _ = replay;
                formatter.write_str("AnchorSuccessor")
            }
            Self::NativeValidCompletionRecoveryOffline(replay) => {
                let _ = replay;
                formatter.write_str("NativeValidCompletionRecoveryOffline")
            }
        }
    }
}

enum ProcessSignerOwnerV0<W> {
    Pinned(Box<PinnedSqliteSignerJournalV0<W>>),
    Activated(Box<SqliteSignerJournalV0<W>>),
}

impl<W> fmt::Debug for ProcessSignerOwnerV0<W> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pinned(owner) => {
                let _ = owner;
                formatter.write_str("Pinned")
            }
            Self::Activated(owner) => {
                let _ = owner;
                formatter.write_str("Activated")
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ProcessPostRecoveryPolicyV0 {
    install_application_authorities: bool,
    resume_core: bool,
    activate_signer: bool,
}

fn process_post_recovery_policy_v0(
    mode: PocoNodeProcessBootstrapModeV0,
) -> ProcessPostRecoveryPolicyV0 {
    match mode {
        PocoNodeProcessBootstrapModeV0::StateSyncCheckpointBootstrap => {
            ProcessPostRecoveryPolicyV0 {
                install_application_authorities: false,
                resume_core: true,
                activate_signer: false,
            }
        }
        PocoNodeProcessBootstrapModeV0::StateSyncAnchorSuccessor => ProcessPostRecoveryPolicyV0 {
            install_application_authorities: false,
            resume_core: false,
            activate_signer: false,
        },
        PocoNodeProcessBootstrapModeV0::NativeValidCompletionRecoveryOffline => {
            ProcessPostRecoveryPolicyV0 {
                install_application_authorities: false,
                resume_core: false,
                activate_signer: false,
            }
        }
        PocoNodeProcessBootstrapModeV0::NativeFinalizationApplied => ProcessPostRecoveryPolicyV0 {
            install_application_authorities: true,
            resume_core: true,
            activate_signer: true,
        },
        PocoNodeProcessBootstrapModeV0::Ordinary
        | PocoNodeProcessBootstrapModeV0::DeterministicInvalidObligation
        | PocoNodeProcessBootstrapModeV0::DeterministicInvalidCompletion => {
            ProcessPostRecoveryPolicyV0 {
                install_application_authorities: true,
                resume_core: false,
                activate_signer: true,
            }
        }
    }
}

struct ExactStateSyncCheckpointProcessReconcilerV0<'a> {
    application_host: &'a NativeConsensusApplicationHostV0,
    application_expectation: Option<PreparedNativeApplicationH1ProjectionExpectationV0>,
    safety: &'a ConfirmedStateSyncCheckpointBootstrapHeadV0,
    signer: SignerJournalReconciliationFactsV0,
}

impl StateSyncAnchorRecoveryReconcilerV0 for ExactStateSyncCheckpointProcessReconcilerV0<'_> {
    fn reconcile_state_sync_anchor_v0(
        &mut self,
        challenge: &StateSyncAnchorRecoveryChallengeV0,
    ) -> bool {
        let Some(expectation) = self.application_expectation.take() else {
            return false;
        };
        let Ok(application) = self
            .application_host
            .confirm_state_sync_anchor_v0(challenge, expectation)
        else {
            return false;
        };
        confirmed_state_sync_checkpoint_matches_challenge_v0(challenge, self.safety)
            && validate_virgin_state_sync_signer_v0(self.signer).is_ok()
            && self
                .application_host
                .state_sync_anchor_confirmation_matches_v0(challenge, &application)
    }
}

struct ExactStateSyncAnchorSuccessorProcessReconcilerV0<'a> {
    application_host: &'a NativeConsensusApplicationHostV0,
    safety_store: &'a SqliteSafetyStateStoreV0<StrictEd25519Verifier>,
    application_expectation: Option<PreparedNativeApplicationH1ProjectionExpectationV0>,
    current_native_valid: Option<&'a ConfirmedNativeValidHeadV0>,
    signer: SignerJournalReconciliationFactsV0,
}

impl StateSyncAnchorSuccessorRecoveryReconcilerV0
    for ExactStateSyncAnchorSuccessorProcessReconcilerV0<'_>
{
    fn reconcile_state_sync_anchor_successors_v0(
        &mut self,
        challenge: &StateSyncAnchorSuccessorRecoveryChallengeV0,
    ) -> bool {
        let Some(expectation) = self.application_expectation.take() else {
            return false;
        };
        let Ok(application) = self
            .application_host
            .confirm_state_sync_anchor_successors_v0(
                challenge,
                expectation,
                self.current_native_valid,
            )
        else {
            return false;
        };
        let historical_safety_exact = match challenge.phase() {
            StateSyncAnchorSuccessorPhaseV0::H3Valid => self
                .application_host
                .confirm_rev4_historical_h2_safety_v0(challenge, &application, self.safety_store)
                .is_ok(),
            StateSyncAnchorSuccessorPhaseV0::H1Bootstrap
            | StateSyncAnchorSuccessorPhaseV0::H2Valid => true,
            StateSyncAnchorSuccessorPhaseV0::H2ValidationPending
            | StateSyncAnchorSuccessorPhaseV0::H3ValidationPending => false,
        };
        validate_virgin_state_sync_signer_v0(self.signer).is_ok()
            && historical_safety_exact
            && self
                .application_host
                .state_sync_anchor_successor_confirmation_matches_v0(challenge, &application)
    }
}

impl<W: ExternalMonotonicWatermarkV0> PocoNodeProcessHostV0<W> {
    /// Opens and reconciles an existing development-only namespace.
    ///
    /// Where activation is allowed, signer activation is deliberately the
    /// final externally mutable startup step. Before it, the signer namespace
    /// is pinned/read-only and only copied facts are compared with the
    /// authenticated SafetyState. State-sync and NativeValid completion
    /// recovery branches permanently retain that pin and never activate it.
    pub fn open_existing_v0(
        config: PocoNodeProcessConfigV0,
        external_watermark: W,
    ) -> Result<Self, PocoNodeProcessHostErrorV0>
    where
        W: Send,
    {
        reject_authenticated_genesis_commissioning_v0(config.node_config().core_config())?;
        std::thread::scope(|scope| {
            let worker = std::thread::Builder::new()
                .name("poco-node-process-startup-audit-v0".to_string())
                .stack_size(PROCESS_HOST_STARTUP_AUDIT_STACK_BYTES_V0)
                .spawn_scoped(scope, move || {
                    Self::open_existing_on_startup_audit_stack_v0(config, external_watermark)
                })
                .map_err(|_| PocoNodeProcessHostErrorV0::StartupAuditWorkerUnavailable)?;
            worker
                .join()
                .map_err(|_| PocoNodeProcessHostErrorV0::StartupAuditWorkerUnavailable)?
        })
    }

    /// Opens only the bounded h1/h2/h3 anchored-successor replay owner.
    ///
    /// Selection happens before SafetyStore is bound to any live Core. The
    /// supplied complete h2/h3 proposals must be the exact bodies named by
    /// the h1 finality proof. Revision one and three fail before the
    /// application or signer owner is opened. Stable revision zero, two, and
    /// four can cross the application fixed-snapshot join; revision four must
    /// additionally reconstruct the pruned h2 transition against Safety's
    /// authenticated rev3 predecessor checksum.
    pub fn open_existing_state_sync_anchor_successors_v0(
        config: PocoNodeProcessConfigV0,
        external_watermark: W,
        child: SignedProposalV0,
        grandchild: SignedProposalV0,
    ) -> Result<Self, PocoNodeProcessHostErrorV0>
    where
        W: Send,
    {
        reject_authenticated_genesis_commissioning_v0(config.node_config().core_config())?;
        std::thread::scope(|scope| {
            let worker = std::thread::Builder::new()
                .name("poco-node-anchor-successor-startup-audit-v0".to_string())
                .stack_size(PROCESS_HOST_STARTUP_AUDIT_STACK_BYTES_V0)
                .spawn_scoped(scope, move || {
                    Self::open_existing_state_sync_anchor_successors_on_startup_audit_stack_v0(
                        config,
                        external_watermark,
                        child,
                        grandchild,
                    )
                })
                .map_err(|_| PocoNodeProcessHostErrorV0::StartupAuditWorkerUnavailable)?;
            worker
                .join()
                .map_err(|_| PocoNodeProcessHostErrorV0::StartupAuditWorkerUnavailable)?
        })
    }

    fn open_existing_state_sync_anchor_successors_on_startup_audit_stack_v0(
        config: PocoNodeProcessConfigV0,
        external_watermark: W,
        child: SignedProposalV0,
        grandchild: SignedProposalV0,
    ) -> Result<Self, PocoNodeProcessHostErrorV0> {
        validate_inert_configuration_v0(config.node_config().core_config())?;
        let PocoNodeProcessConfigV0 {
            node,
            application,
            store_parents,
        } = config;
        let application_path = application
            .state_path
            .as_ref()
            .expect("validated process config retains its application path")
            .clone();
        revalidate_process_store_paths_v0(
            node.safety_store_path(),
            node.signer_journal_path(),
            &application_path,
            store_parents,
        )?;
        let core_config = node.core_config().clone();
        let PocoNodeStartConfigV0 {
            safety_store_path,
            safety_store_profile,
            signer_journal_path,
            signer_journal_profile,
        } = node;
        let verifier = StrictEd25519Verifier;
        let mut safety_store = SqliteSafetyStateStoreV0::open_existing(
            &safety_store_path,
            safety_store_profile,
            verifier,
        )
        .map_err(PocoNodeProcessHostErrorV0::SafetyStore)?;
        revalidate_process_store_paths_v0(
            safety_store_path.as_path(),
            signer_journal_path.as_path(),
            &application_path,
            store_parents,
        )?;
        let safety_head = safety_store
            .head()
            .map_err(PocoNodeProcessHostErrorV0::SafetyStore)?;

        // Both body authentication and stable-cut classification occur before
        // opening the application or signer namespace. In particular, rev1
        // and rev3 cannot install an authority or touch an external watermark.
        let bundle = Core::prepare_h1_state_sync_anchor_successor_bundle_v0(
            &core_config,
            safety_head.state(),
            child,
            grandchild,
            &verifier,
        )
        .map_err(PocoNodeProcessHostErrorV0::Core)?;
        let session = match Core::begin_state_sync_anchor_successor_recovery_v0(
            core_config.clone(),
            safety_head.state().clone(),
            bundle,
            &verifier,
        ) {
            Ok(session) => session,
            Err(trnm_consensus_core::CoreError::StateSyncAnchorSuccessorInFlightRecoveryUnavailable {
                revision,
            }) => {
                return Err(
                    PocoNodeProcessHostErrorV0::AnchorSuccessorInFlightRecoveryUnavailable {
                        revision,
                    },
                )
            }
            Err(error) => return Err(PocoNodeProcessHostErrorV0::Core(error)),
        };
        let phase = session.challenge().phase();
        let current_native_valid = match phase {
            StateSyncAnchorSuccessorPhaseV0::H1Bootstrap => {
                if safety_head.revision() != 0
                    || !matches!(
                        safety_head.transition_context(),
                        SafetyTransitionContextV0::StateSyncCheckpointBootstrap(_)
                    )
                {
                    return Err(PocoNodeProcessHostErrorV0::UnexpectedAnchorSuccessorPhase {
                        revision: safety_head.revision(),
                    });
                }
                let _confirmed_bootstrap = safety_store
                    .confirmed_state_sync_checkpoint_bootstrap_head_exact_v0(
                        session.challenge().safety_state(),
                    )
                    .map_err(PocoNodeProcessHostErrorV0::SafetyStore)?;
                None
            }
            StateSyncAnchorSuccessorPhaseV0::H2Valid | StateSyncAnchorSuccessorPhaseV0::H3Valid => {
                if !matches!(
                    safety_head.transition_context(),
                    SafetyTransitionContextV0::NativeValid(_)
                ) {
                    return Err(PocoNodeProcessHostErrorV0::UnexpectedAnchorSuccessorPhase {
                        revision: safety_head.revision(),
                    });
                }
                Some(
                    safety_store
                        .confirmed_native_valid_head_v0()
                        .map_err(PocoNodeProcessHostErrorV0::SafetyStore)?,
                )
            }
            StateSyncAnchorSuccessorPhaseV0::H2ValidationPending
            | StateSyncAnchorSuccessorPhaseV0::H3ValidationPending => {
                return Err(
                    PocoNodeProcessHostErrorV0::AnchorSuccessorInFlightRecoveryUnavailable {
                        revision: safety_head.revision(),
                    },
                )
            }
        };
        let h1_projection_expectation =
            NativeConsensusApplicationHostV0::prepare_h1_projection_expectation_v0(
                &core_config,
                &application,
            )
            .map_err(PocoNodeProcessHostErrorV0::Application)?;
        let application_config =
            NativeConsensusApplicationHostConfigV0::from_authenticated_safety_store_v0(
                application,
                &safety_store,
            )
            .map_err(PocoNodeProcessHostErrorV0::Application)?;
        let application_host =
            NativeConsensusApplicationHostV0::open_existing_v0(application_config)
                .map_err(PocoNodeProcessHostErrorV0::Application)?;
        revalidate_process_store_paths_v0(
            safety_store_path.as_path(),
            signer_journal_path.as_path(),
            &application_path,
            store_parents,
        )?;

        // Pin-only signer admission loads but never advances the external CAS.
        let pinned_signer = SqliteSignerJournalV0::pin_existing_v0(
            &signer_journal_path,
            signer_journal_profile,
            external_watermark,
        )
        .map_err(PocoNodeProcessHostErrorV0::SignerJournal)?;
        let signer_facts = pinned_signer.reconciliation_facts();
        validate_pinned_signer_against_safety_v0(signer_facts, safety_head.state(), &core_config)?;
        validate_virgin_state_sync_signer_v0(signer_facts)?;

        let mut reconciler = ExactStateSyncAnchorSuccessorProcessReconcilerV0 {
            application_host: &application_host,
            safety_store: &safety_store,
            application_expectation: Some(h1_projection_expectation),
            current_native_valid: current_native_valid.as_ref(),
            signer: signer_facts,
        };
        let replay = session
            .reconcile_and_activate_v0(&mut reconciler)
            .map_err(PocoNodeProcessHostErrorV0::Core)?;
        if replay.safety_state() != safety_head.state() || replay.phase().ok() != Some(phase) {
            return Err(PocoNodeProcessHostErrorV0::RecoveredHeadMismatch);
        }
        safety_store
            .bind_core_v0(replay.safety_state_persistence_binding_v0())
            .map_err(PocoNodeProcessHostErrorV0::SafetyStore)?;

        let application_seal_authority_installed = match phase {
            StateSyncAnchorSuccessorPhaseV0::H1Bootstrap
            | StateSyncAnchorSuccessorPhaseV0::H2Valid => {
                application_host
                    .install_state_sync_anchor_successor_seal_authority_v0(&replay)
                    .map_err(PocoNodeProcessHostErrorV0::Application)?;
                true
            }
            StateSyncAnchorSuccessorPhaseV0::H3Valid => {
                application_host
                    .retire_state_sync_anchor_successor_seal_authority_v0(&replay)
                    .map_err(PocoNodeProcessHostErrorV0::Application)?;
                false
            }
            StateSyncAnchorSuccessorPhaseV0::H2ValidationPending
            | StateSyncAnchorSuccessorPhaseV0::H3ValidationPending => unreachable!(
                "the dedicated Core recovery session rejects in-flight anchored successors"
            ),
        };
        let final_head = safety_store
            .head()
            .map_err(PocoNodeProcessHostErrorV0::SafetyStore)?;
        if final_head.state() != replay.safety_state() {
            return Err(PocoNodeProcessHostErrorV0::RecoveredHeadMismatch);
        }
        let application_facts = application_host
            .reconcile_current_application_applied_v0(final_head.state())
            .map_err(PocoNodeProcessHostErrorV0::Application)?;
        validate_pinned_signer_against_safety_v0(
            signer_facts,
            final_head.state(),
            replay.config(),
        )?;
        validate_virgin_state_sync_signer_v0(signer_facts)?;
        revalidate_process_store_paths_v0(
            safety_store_path.as_path(),
            signer_journal_path.as_path(),
            &application_path,
            store_parents,
        )?;

        Ok(Self {
            core_owner: ProcessCoreOwnerV0::AnchorSuccessor(replay),
            safety_store,
            application_host,
            signer_owner: ProcessSignerOwnerV0::Pinned(Box::new(pinned_signer)),
            bootstrap: PocoNodeProcessBootstrapFactsV0 {
                mode: PocoNodeProcessBootstrapModeV0::StateSyncAnchorSuccessor,
                safety_revision: final_head.revision(),
                application_kind: application_facts.kind(),
                application_height: application_facts.height(),
                application_receipt_count: application_facts.receipt_count(),
                application_valid_completion_count: application_facts
                    .matched_valid_completion_count(),
                signer: signer_facts,
                application_authorities_installed: false,
                application_seal_authority_installed,
                application_finalization_authority_installed: false,
                signer_activated: false,
                native_valid_completion_source: None,
            },
            pending_inert_effects: Vec::new(),
            pending_native_valid_action: None,
        })
    }

    fn open_existing_on_startup_audit_stack_v0(
        config: PocoNodeProcessConfigV0,
        external_watermark: W,
    ) -> Result<Self, PocoNodeProcessHostErrorV0> {
        validate_inert_configuration_v0(config.node_config().core_config())?;
        let PocoNodeProcessConfigV0 {
            node,
            application,
            store_parents,
        } = config;
        let application_path = application
            .state_path
            .as_ref()
            .expect("validated process config retains its application path")
            .clone();
        revalidate_process_store_paths_v0(
            node.safety_store_path(),
            node.signer_journal_path(),
            &application_path,
            store_parents,
        )?;
        let core_config = node.core_config().clone();
        let PocoNodeStartConfigV0 {
            safety_store_path,
            safety_store_profile,
            signer_journal_path,
            signer_journal_profile,
        } = node;

        let verifier = StrictEd25519Verifier;
        let mut safety_store = SqliteSafetyStateStoreV0::open_existing(
            &safety_store_path,
            safety_store_profile,
            verifier,
        )
        .map_err(PocoNodeProcessHostErrorV0::SafetyStore)?;
        revalidate_process_store_paths_v0(
            safety_store_path.as_path(),
            signer_journal_path.as_path(),
            &application_path,
            store_parents,
        )?;
        let safety_head = safety_store
            .head()
            .map_err(PocoNodeProcessHostErrorV0::SafetyStore)?;

        // A current ordinary NativeValid completion cannot cross generic
        // Core recovery or the ordinary authority-install path. Select its
        // narrow offline owner immediately after authenticating Safety so the
        // signer can be pinned before the only permitted App mutation (D->K).
        if matches!(
            safety_head.transition_context(),
            SafetyTransitionContextV0::NativeValid(_)
        ) {
            return Self::open_existing_native_valid_completion_on_startup_audit_stack_v0(
                core_config,
                application,
                store_parents,
                safety_store_path,
                signer_journal_path,
                signer_journal_profile,
                application_path,
                safety_store,
                safety_head,
                external_watermark,
            );
        }

        // Build the only accepted h1 application projection from the trusted
        // Core/app configuration before opening the application database. The
        // linear value can be consumed only by the state-sync branch below.
        let h1_projection_expectation = if matches!(
            safety_head.transition_context(),
            SafetyTransitionContextV0::StateSyncCheckpointBootstrap(_)
        ) {
            Some(
                NativeConsensusApplicationHostV0::prepare_h1_projection_expectation_v0(
                    &core_config,
                    &application,
                )
                .map_err(PocoNodeProcessHostErrorV0::Application)?,
            )
        } else {
            None
        };

        let application_config =
            NativeConsensusApplicationHostConfigV0::from_authenticated_safety_store_v0(
                application,
                &safety_store,
            )
            .map_err(PocoNodeProcessHostErrorV0::Application)?;
        let mut application_host =
            NativeConsensusApplicationHostV0::open_existing_v0(application_config)
                .map_err(PocoNodeProcessHostErrorV0::Application)?;
        let active_valid_jobs = application_host
            .active_valid_recovery_job_count_v0()
            .map_err(PocoNodeProcessHostErrorV0::Application)?;
        if active_valid_jobs != 0 {
            return Err(
                PocoNodeProcessHostErrorV0::ActiveNativeValidRecoveryUnavailable {
                    revision: safety_head.revision(),
                    jobs: active_valid_jobs,
                },
            );
        }
        revalidate_process_store_paths_v0(
            safety_store_path.as_path(),
            signer_journal_path.as_path(),
            &application_path,
            store_parents,
        )?;

        // Pin before any Core activation or replay. This loads and audits the
        // external watermark but performs no compare-and-advance.
        let pinned_signer = SqliteSignerJournalV0::pin_existing_v0(
            &signer_journal_path,
            signer_journal_profile,
            external_watermark,
        )
        .map_err(PocoNodeProcessHostErrorV0::SignerJournal)?;
        revalidate_process_store_paths_v0(
            safety_store_path.as_path(),
            signer_journal_path.as_path(),
            &application_path,
            store_parents,
        )?;
        let signer_facts = pinned_signer.reconciliation_facts();
        validate_pinned_signer_against_safety_v0(signer_facts, safety_head.state(), &core_config)?;

        application_host
            .reconcile_current_application_applied_v0(safety_head.state())
            .map_err(PocoNodeProcessHostErrorV0::Application)?;

        let obligation_count = safety_head.state().payload_validation_obligations().len();
        let (mut core, mode, mut pending_inert_effects, safety_already_bound) =
            match (safety_head.transition_context(), obligation_count) {
                (SafetyTransitionContextV0::Ordinary, 0) => {
                    if head_has_current_invalid_completion_v0(safety_head.state()) {
                        return Err(PocoNodeProcessHostErrorV0::OrdinaryInvalidCompletion {
                            revision: safety_head.revision(),
                        });
                    }
                    validate_ordinary_clean_state_v0(safety_head.state())?;
                    (
                        Core::recover(core_config, safety_head.state().clone(), &verifier)
                            .map_err(PocoNodeProcessHostErrorV0::Core)?,
                        PocoNodeProcessBootstrapModeV0::Ordinary,
                        Vec::new(),
                        false,
                    )
                }
                (SafetyTransitionContextV0::Ordinary, 1) => recover_one_invalid_obligation_v0(
                    core_config,
                    &safety_head,
                    &mut safety_store,
                    &mut application_host,
                    &verifier,
                )?,
                (SafetyTransitionContextV0::Ordinary, count) => {
                    return Err(
                        PocoNodeProcessHostErrorV0::UnsupportedValidationObligationCount { count },
                    );
                }
                (SafetyTransitionContextV0::NativeFinalizationApplied(_), 0) => {
                    let session = Core::begin_native_finalization_applied_recovery_v0(
                        core_config,
                        safety_head.state().clone(),
                        &verifier,
                    )
                    .map_err(PocoNodeProcessHostErrorV0::Core)?;
                    let confirmed = safety_store
                        .confirmed_native_finalization_applied_head_v0()
                        .map_err(PocoNodeProcessHostErrorV0::SafetyStore)?;
                    let application_confirmed = application_host
                        .confirm_native_finalization_applied_v0(session.challenge(), confirmed)
                        .map_err(PocoNodeProcessHostErrorV0::Application)?;
                    let attestation = application_host
                        .attest_native_finalization_applied_recovery_v0(
                            session.challenge(),
                            application_confirmed,
                        )
                        .map_err(PocoNodeProcessHostErrorV0::Application)?;
                    let core =
                        session
                            .reconcile_and_activate_v0(attestation)
                            .map_err(|failure| {
                                PocoNodeProcessHostErrorV0::Core(failure.error().clone())
                            })?;
                    (
                        core,
                        PocoNodeProcessBootstrapModeV0::NativeFinalizationApplied,
                        Vec::new(),
                        false,
                    )
                }
                (SafetyTransitionContextV0::StateSyncCheckpointBootstrap(_), 0)
                    if safety_head.revision() == 0 =>
                {
                    let session = Core::begin_state_sync_anchor_recovery_v0(
                        core_config,
                        safety_head.state().clone(),
                        &verifier,
                    )
                    .map_err(PocoNodeProcessHostErrorV0::Core)?;
                    let confirmed_safety = safety_store
                        .confirmed_state_sync_checkpoint_bootstrap_head_exact_v0(
                            session.challenge().safety_state(),
                        )
                        .map_err(PocoNodeProcessHostErrorV0::SafetyStore)?;
                    let mut reconciler = ExactStateSyncCheckpointProcessReconcilerV0 {
                        application_host: &application_host,
                        application_expectation: h1_projection_expectation,
                        safety: &confirmed_safety,
                        signer: signer_facts,
                    };
                    let core = session
                        .reconcile_and_activate_v0(&mut reconciler)
                        .map_err(PocoNodeProcessHostErrorV0::Core)?;
                    (
                        core,
                        PocoNodeProcessBootstrapModeV0::StateSyncCheckpointBootstrap,
                        Vec::new(),
                        false,
                    )
                }
                (SafetyTransitionContextV0::StateSyncCheckpointBootstrap(_), obligations) => {
                    return Err(PocoNodeProcessHostErrorV0::InvalidStateSyncBootstrapHead {
                        revision: safety_head.revision(),
                        obligations,
                    });
                }
                (SafetyTransitionContextV0::NativeValid(_), _) => {
                    return Err(PocoNodeProcessHostErrorV0::NativeValidRecoveryUnavailable {
                        revision: safety_head.revision(),
                    });
                }
                (SafetyTransitionContextV0::NativeDeterministicInvalid(_), 0) => {
                    recover_invalid_completion_v0(
                        core_config,
                        &safety_store,
                        &mut application_host,
                        &verifier,
                    )?
                }
                (_, _) => {
                    return Err(PocoNodeProcessHostErrorV0::UnexpectedRecoveryState {
                        revision: safety_head.revision(),
                        obligations: obligation_count,
                    });
                }
            };

        if core.safety_state() != safety_head.state() {
            let current = safety_store
                .head()
                .map_err(PocoNodeProcessHostErrorV0::SafetyStore)?;
            if current.state() != core.safety_state() {
                return Err(PocoNodeProcessHostErrorV0::RecoveredHeadMismatch);
            }
        }
        if !safety_already_bound {
            safety_store
                .bind_core_v0(core.safety_state_persistence_binding_v0())
                .map_err(PocoNodeProcessHostErrorV0::SafetyStore)?;
        }
        let post_recovery_policy = process_post_recovery_policy_v0(mode);
        if post_recovery_policy.install_application_authorities {
            let seal = core
                .issue_application_seal_authority_v0()
                .map_err(PocoNodeProcessHostErrorV0::Core)?;
            let finalization = core
                .issue_application_finalization_apply_authority_v0()
                .map_err(PocoNodeProcessHostErrorV0::Core)?;
            application_host
                .install_core_authorities_v0(seal, finalization)
                .map_err(|rejection| PocoNodeProcessHostErrorV0::Application(rejection.error()))?;
        }

        if post_recovery_policy.resume_core {
            pending_inert_effects = core
                .step(Input::Resume, &verifier)
                .map_err(PocoNodeProcessHostErrorV0::Core)?;
        }
        match mode {
            PocoNodeProcessBootstrapModeV0::Ordinary => {
                sanitize_ordinary_effects_v0(&pending_inert_effects)?
            }
            PocoNodeProcessBootstrapModeV0::NativeFinalizationApplied => {
                sanitize_tag3_effects_v0(&pending_inert_effects)?
            }
            PocoNodeProcessBootstrapModeV0::StateSyncCheckpointBootstrap => {
                sanitize_state_sync_checkpoint_bootstrap_effects_v0(
                    &pending_inert_effects,
                    core.safety_state(),
                )?
            }
            PocoNodeProcessBootstrapModeV0::StateSyncAnchorSuccessor => {
                if !pending_inert_effects.is_empty() {
                    return Err(PocoNodeProcessHostErrorV0::UnexpectedAnchorSuccessorEffects);
                }
            }
            PocoNodeProcessBootstrapModeV0::NativeValidCompletionRecoveryOffline => {
                return Err(PocoNodeProcessHostErrorV0::NativeValidRecoveryUnavailable {
                    revision: core.safety_state().revision(),
                });
            }
            PocoNodeProcessBootstrapModeV0::DeterministicInvalidObligation
            | PocoNodeProcessBootstrapModeV0::DeterministicInvalidCompletion => {
                sanitize_invalid_effects_v0(&pending_inert_effects)?
            }
        };
        let final_head = safety_store
            .head()
            .map_err(PocoNodeProcessHostErrorV0::SafetyStore)?;
        if final_head.state() != core.safety_state() {
            return Err(PocoNodeProcessHostErrorV0::RecoveredHeadMismatch);
        }
        application_host
            .final_invalid_recovery_audit_v0()
            .map_err(PocoNodeProcessHostErrorV0::ApplicationRecoveryTransition)?;
        let application_facts = application_host
            .reconcile_current_application_applied_v0(final_head.state())
            .map_err(PocoNodeProcessHostErrorV0::Application)?;
        if mode == PocoNodeProcessBootstrapModeV0::StateSyncCheckpointBootstrap {
            validate_state_sync_application_facts_v0(application_facts, final_head.state())?;
        }
        let active_valid_jobs = application_host
            .active_valid_recovery_job_count_v0()
            .map_err(PocoNodeProcessHostErrorV0::Application)?;
        if active_valid_jobs != 0 {
            return Err(
                PocoNodeProcessHostErrorV0::ActiveNativeValidRecoveryUnavailable {
                    revision: final_head.revision(),
                    jobs: active_valid_jobs,
                },
            );
        }
        validate_pinned_signer_against_safety_v0(signer_facts, final_head.state(), core.config())?;
        revalidate_process_store_paths_v0(
            safety_store_path.as_path(),
            signer_journal_path.as_path(),
            &application_path,
            store_parents,
        )?;

        // The h1 replay fence deliberately retains the read-only signer pin.
        // The ordinary NativeValid completion mode returned through its early
        // branch above is likewise permanently pinned; only the legacy
        // ordinary/tag-3/invalid branches reach this optional activation.
        let signer_owner = if post_recovery_policy.activate_signer {
            ProcessSignerOwnerV0::Activated(Box::new(pinned_signer.activate_v0().map_err(
                |failure| PocoNodeProcessHostErrorV0::SignerJournal(failure.into_error()),
            )?))
        } else {
            ProcessSignerOwnerV0::Pinned(Box::new(pinned_signer))
        };

        // No fallible operation is permitted after the optional signer
        // activation.
        Ok(Self {
            core_owner: ProcessCoreOwnerV0::Ordinary(core),
            safety_store,
            application_host,
            signer_owner,
            bootstrap: PocoNodeProcessBootstrapFactsV0 {
                mode,
                safety_revision: final_head.revision(),
                application_kind: application_facts.kind(),
                application_height: application_facts.height(),
                application_receipt_count: application_facts.receipt_count(),
                application_valid_completion_count: application_facts
                    .matched_valid_completion_count(),
                signer: signer_facts,
                application_authorities_installed: post_recovery_policy
                    .install_application_authorities,
                application_seal_authority_installed: post_recovery_policy
                    .install_application_authorities,
                application_finalization_authority_installed: post_recovery_policy
                    .install_application_authorities,
                signer_activated: post_recovery_policy.activate_signer,
                native_valid_completion_source: None,
            },
            pending_inert_effects,
            pending_native_valid_action: None,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn open_existing_native_valid_completion_on_startup_audit_stack_v0(
        core_config: CoreConfig,
        application: ConsensusAppConfig,
        store_parents: ProcessStoreParentIdentitiesV0,
        safety_store_path: PathBuf,
        signer_journal_path: PathBuf,
        signer_journal_profile: trnm_consensus_signer_journal::SignerJournalProfileV0,
        application_path: PathBuf,
        mut safety_store: SqliteSafetyStateStoreV0<StrictEd25519Verifier>,
        safety_head: RecoveredSafetyStateV0,
        external_watermark: W,
    ) -> Result<Self, PocoNodeProcessHostErrorV0> {
        let verifier = StrictEd25519Verifier;
        let signer_core_config = core_config.clone();
        let session = Core::begin_native_valid_completion_recovery_v0(
            core_config,
            safety_head.state().clone(),
            &verifier,
        )
        .map_err(PocoNodeProcessHostErrorV0::Core)?;
        let expected_revision = session.challenge().safety_head_revision_v0();
        let expected_route = session.challenge().route_v0();
        let expected_validation_id = session.challenge().validation_id_v0();
        let expected_valid_result_checksum = session.challenge().valid_result_checksum_v0();
        let expected_state_record_checksum = safety_head.state_record_checksum();
        let expected_chain_checksum = safety_head.chain_checksum();

        let application_config =
            NativeConsensusApplicationHostConfigV0::from_authenticated_safety_store_v0(
                application,
                &safety_store,
            )
            .map_err(PocoNodeProcessHostErrorV0::Application)?;
        let application_host =
            NativeConsensusApplicationHostV0::open_existing_v0(application_config)
                .map_err(PocoNodeProcessHostErrorV0::Application)?;
        revalidate_process_store_paths_v0(
            safety_store_path.as_path(),
            signer_journal_path.as_path(),
            &application_path,
            store_parents,
        )?;

        // Pin and reconcile the signer before asking App to close C+D to C+K.
        // This performs no external compare-and-advance and is intentionally
        // never activated by this recovery mode.
        let mut pinned_signer = SqliteSignerJournalV0::pin_existing_v0(
            &signer_journal_path,
            signer_journal_profile,
            external_watermark,
        )
        .map_err(PocoNodeProcessHostErrorV0::SignerJournal)?;
        revalidate_process_store_paths_v0(
            safety_store_path.as_path(),
            signer_journal_path.as_path(),
            &application_path,
            store_parents,
        )?;
        let signer_facts = pinned_signer.reconciliation_facts();
        validate_pinned_signer_against_safety_v0(
            signer_facts,
            safety_head.state(),
            &signer_core_config,
        )?;

        let active_valid_jobs = application_host
            .active_valid_recovery_job_count_v0()
            .map_err(PocoNodeProcessHostErrorV0::Application)?;
        if active_valid_jobs != 1 {
            return Err(
                PocoNodeProcessHostErrorV0::ActiveNativeValidRecoveryUnavailable {
                    revision: expected_revision,
                    jobs: active_valid_jobs,
                },
            );
        }

        let confirmed_safety = safety_store
            .confirmed_native_valid_head_exact_v0(
                session.challenge().safety_state(),
                safety_head.transition_context(),
            )
            .map_err(PocoNodeProcessHostErrorV0::SafetyStore)?;
        let expected_post_ack_action = confirmed_safety.post_ack_action_v0();
        let application_confirmation = application_host
            .recover_native_valid_completion_v0(
                session.challenge(),
                &safety_store,
                safety_store_path.as_path(),
                confirmed_safety,
            )
            .map_err(PocoNodeProcessHostErrorV0::Application)?;
        let application_source = application_confirmation.source_v0();
        let attestation = application_host
            .attest_native_valid_completion_recovery_v0(
                session.challenge(),
                &safety_store,
                safety_store_path.as_path(),
                application_confirmation,
            )
            .map_err(PocoNodeProcessHostErrorV0::Application)?;
        let mut replay = session
            .reconcile_and_activate_v0(attestation)
            .map_err(PocoNodeProcessHostErrorV0::Core)?;
        if replay.safety_state() != safety_head.state() {
            return Err(PocoNodeProcessHostErrorV0::RecoveredHeadMismatch);
        }
        safety_store
            .bind_core_v0(replay.safety_state_persistence_binding_v0())
            .map_err(PocoNodeProcessHostErrorV0::SafetyStore)?;
        let recovered = replay
            .remint_inert_post_ack_action_v0()
            .map_err(PocoNodeProcessHostErrorV0::Core)?;
        validate_native_valid_recovered_action_v0(
            &recovered,
            expected_revision,
            expected_state_record_checksum,
            expected_route,
            expected_validation_id,
            expected_valid_result_checksum,
            expected_post_ack_action,
        )?;

        // The App attestation above performs a fresh exact K readback after a
        // possible D->K commit. Re-audit all three owners and their canonical
        // parent identities before returning the inert, pinned process owner.
        let final_head = safety_store
            .head()
            .map_err(PocoNodeProcessHostErrorV0::SafetyStore)?;
        if final_head.state() != replay.safety_state()
            || final_head.transition_context() != safety_head.transition_context()
            || final_head.state_record_checksum() != expected_state_record_checksum
            || final_head.chain_checksum() != expected_chain_checksum
        {
            return Err(PocoNodeProcessHostErrorV0::RecoveredHeadMismatch);
        }
        let _final_confirmed_safety = safety_store
            .confirmed_native_valid_head_exact_v0(
                final_head.state(),
                final_head.transition_context(),
            )
            .map_err(PocoNodeProcessHostErrorV0::SafetyStore)?;
        application_host
            .final_invalid_recovery_audit_v0()
            .map_err(PocoNodeProcessHostErrorV0::ApplicationRecoveryTransition)?;
        let application_facts = application_host
            .reconcile_current_application_applied_v0(final_head.state())
            .map_err(PocoNodeProcessHostErrorV0::Application)?;
        let final_active_valid_jobs = application_host
            .active_valid_recovery_job_count_v0()
            .map_err(PocoNodeProcessHostErrorV0::Application)?;
        let expected_valid_completions = durable_valid_completion_count_v0(final_head.state())?;
        if final_active_valid_jobs != 1 {
            return Err(
                PocoNodeProcessHostErrorV0::ActiveNativeValidRecoveryUnavailable {
                    revision: final_head.revision(),
                    jobs: final_active_valid_jobs,
                },
            );
        }
        if application_facts.matched_valid_completion_count() != expected_valid_completions {
            return Err(
                PocoNodeProcessHostErrorV0::NativeValidApplicationCompletionCountMismatch {
                    expected: expected_valid_completions,
                    actual: application_facts.matched_valid_completion_count(),
                },
            );
        }
        // D->K can outlive the startup watermark observation. Reload the
        // independent watermark and revalidate the pinned local journal now;
        // the resulting linear capability is consumed only for this final
        // Safety join and never stored, activated, or used for a CAS.
        let confirmed_signer = pinned_signer
            .confirm_node_checkpoint_head_exact_v0()
            .map_err(PocoNodeProcessHostErrorV0::SignerJournal)?;
        validate_confirmed_pinned_signer_against_safety_v0(
            &confirmed_signer,
            &pinned_signer,
            signer_journal_path.as_path(),
            final_head.state(),
            replay.config(),
        )?;
        drop(confirmed_signer);
        revalidate_process_store_paths_v0(
            safety_store_path.as_path(),
            signer_journal_path.as_path(),
            &application_path,
            store_parents,
        )?;

        Ok(Self {
            core_owner: ProcessCoreOwnerV0::NativeValidCompletionRecoveryOffline(replay),
            safety_store,
            application_host,
            signer_owner: ProcessSignerOwnerV0::Pinned(Box::new(pinned_signer)),
            bootstrap: PocoNodeProcessBootstrapFactsV0 {
                mode: PocoNodeProcessBootstrapModeV0::NativeValidCompletionRecoveryOffline,
                safety_revision: final_head.revision(),
                application_kind: application_facts.kind(),
                application_height: application_facts.height(),
                application_receipt_count: application_facts.receipt_count(),
                application_valid_completion_count: application_facts
                    .matched_valid_completion_count(),
                signer: signer_facts,
                application_authorities_installed: false,
                application_seal_authority_installed: false,
                application_finalization_authority_installed: false,
                signer_activated: false,
                native_valid_completion_source: Some(application_source),
            },
            pending_inert_effects: Vec::new(),
            pending_native_valid_action: Some(expected_post_ack_action),
        })
    }

    pub const fn lifecycle_phase(&self) -> PocoNodeProcessLifecyclePhaseV0 {
        match self.bootstrap.mode {
            PocoNodeProcessBootstrapModeV0::StateSyncCheckpointBootstrap => {
                PocoNodeProcessLifecyclePhaseV0::StateSyncReplayFencedOffline
            }
            PocoNodeProcessBootstrapModeV0::StateSyncAnchorSuccessor => {
                PocoNodeProcessLifecyclePhaseV0::StateSyncAnchorSuccessorOffline
            }
            PocoNodeProcessBootstrapModeV0::NativeValidCompletionRecoveryOffline => {
                PocoNodeProcessLifecyclePhaseV0::NativeValidCompletionRecoveryOffline
            }
            _ => PocoNodeProcessLifecyclePhaseV0::ReconciledOffline,
        }
    }

    pub const fn bootstrap_facts(&self) -> PocoNodeProcessBootstrapFactsV0 {
        self.bootstrap
    }

    /// Consumes this owner to close exactly one empty h2 or h3 successor.
    ///
    /// The transition is strictly O→P→D→C→K followed by Core StorageAck. Any
    /// failure drops all live process-local owners, so a caller cannot continue
    /// from an unclassified partial cut in the same process. A successful h2
    /// returns a rev2 owner with seal-only authority; successful h3 returns a
    /// rev4 owner after that authority has been retired.
    pub fn complete_next_state_sync_anchor_successor_v0(
        self,
    ) -> Result<Self, PocoNodeProcessHostErrorV0> {
        let Self {
            core_owner,
            mut safety_store,
            application_host,
            signer_owner,
            mut bootstrap,
            pending_inert_effects,
            pending_native_valid_action,
        } = self;
        if !pending_inert_effects.is_empty() || pending_native_valid_action.is_some() {
            return Err(PocoNodeProcessHostErrorV0::UnexpectedAnchorSuccessorEffects);
        }
        let mut replay = match core_owner {
            ProcessCoreOwnerV0::AnchorSuccessor(replay) => replay,
            ProcessCoreOwnerV0::Ordinary(_) => {
                return Err(PocoNodeProcessHostErrorV0::UnexpectedAnchorSuccessorPhase {
                    revision: bootstrap.safety_revision,
                })
            }
            ProcessCoreOwnerV0::NativeValidCompletionRecoveryOffline(_) => {
                return Err(PocoNodeProcessHostErrorV0::UnexpectedAnchorSuccessorPhase {
                    revision: bootstrap.safety_revision,
                })
            }
        };
        let before = replay.phase().map_err(PocoNodeProcessHostErrorV0::Core)?;
        let expected = match before {
            StateSyncAnchorSuccessorPhaseV0::H1Bootstrap => {
                StateSyncAnchorSuccessorPhaseV0::H2Valid
            }
            StateSyncAnchorSuccessorPhaseV0::H2Valid => StateSyncAnchorSuccessorPhaseV0::H3Valid,
            _ => {
                return Err(PocoNodeProcessHostErrorV0::UnexpectedAnchorSuccessorPhase {
                    revision: replay.safety_state().revision(),
                })
            }
        };
        let persistence = take_exact_anchor_successor_persistence_v0(
            replay
                .step_next_proposal_v0(&StrictEd25519Verifier)
                .map_err(PocoNodeProcessHostErrorV0::Core)?,
        )?;
        safety_store
            .persist_exact_v0(&persistence, &SafetyTransitionContextV0::ordinary())
            .map_err(PocoNodeProcessHostErrorV0::SafetyStore)?;
        let obligation_head = safety_store
            .head()
            .map_err(PocoNodeProcessHostErrorV0::SafetyStore)?;
        if obligation_head.state() != persistence.state()
            || obligation_head.transition_context() != &SafetyTransitionContextV0::Ordinary
            || replay.safety_state() != persistence.state()
        {
            return Err(PocoNodeProcessHostErrorV0::RecoveredHeadMismatch);
        }
        let validation_effect = take_exact_anchor_successor_validation_effect_v0(
            replay
                .step_storage_ack_v0(persistence.barrier(), &StrictEd25519Verifier)
                .map_err(PocoNodeProcessHostErrorV0::Core)?,
        )?;
        let facts = application_host
            .complete_state_sync_anchor_successor_empty_synced_validation_v0(
                &mut replay,
                &mut safety_store,
                validation_effect,
                &StrictEd25519Verifier,
            )
            .map_err(PocoNodeProcessHostErrorV0::Application)?;
        let after = replay.phase().map_err(PocoNodeProcessHostErrorV0::Core)?;
        let expected_revision = match expected {
            StateSyncAnchorSuccessorPhaseV0::H2Valid => 2,
            StateSyncAnchorSuccessorPhaseV0::H3Valid => 4,
            _ => unreachable!("only stable Valid successor phases are expected"),
        };
        if after != expected
            || replay.safety_state().revision() != expected_revision
            || facts.accepted_core_revision() != expected_revision
            || !facts.job_acked()
            || !facts.effects_empty()
            || (after == StateSyncAnchorSuccessorPhaseV0::H3Valid
                && !facts.seal_authority_retired())
        {
            return Err(PocoNodeProcessHostErrorV0::AnchorSuccessorValidationFactsMismatch);
        }
        let final_head = safety_store
            .head()
            .map_err(PocoNodeProcessHostErrorV0::SafetyStore)?;
        if final_head.state() != replay.safety_state()
            || !matches!(
                final_head.transition_context(),
                SafetyTransitionContextV0::NativeValid(_)
            )
        {
            return Err(PocoNodeProcessHostErrorV0::RecoveredHeadMismatch);
        }
        let application_facts = application_host
            .reconcile_current_application_applied_v0(final_head.state())
            .map_err(PocoNodeProcessHostErrorV0::Application)?;
        let signer_facts = bootstrap.signer;
        validate_pinned_signer_against_safety_v0(
            signer_facts,
            final_head.state(),
            replay.config(),
        )?;
        validate_virgin_state_sync_signer_v0(signer_facts)?;

        bootstrap.safety_revision = final_head.revision();
        bootstrap.application_kind = application_facts.kind();
        bootstrap.application_height = application_facts.height();
        bootstrap.application_receipt_count = application_facts.receipt_count();
        bootstrap.application_valid_completion_count =
            application_facts.matched_valid_completion_count();
        bootstrap.application_authorities_installed = false;
        bootstrap.application_seal_authority_installed =
            after == StateSyncAnchorSuccessorPhaseV0::H2Valid;
        bootstrap.application_finalization_authority_installed = false;
        bootstrap.signer_activated = false;
        Ok(Self {
            core_owner: ProcessCoreOwnerV0::AnchorSuccessor(replay),
            safety_store,
            application_host,
            signer_owner,
            bootstrap,
            pending_inert_effects: Vec::new(),
            pending_native_valid_action: None,
        })
    }

    pub fn pending_inert_effect_kinds(&self) -> Vec<PocoNodeInertEffectKindV0> {
        if let Some(action) = self.pending_native_valid_action {
            debug_assert!(self.pending_inert_effects.is_empty());
            return native_valid_action_effect_kinds_v0(action).to_vec();
        }
        self.pending_inert_effects
            .iter()
            .map(|effect| inert_effect_kind_v0(effect).expect("constructor sanitized effects"))
            .collect()
    }

    pub fn pending_inert_effect_count(&self) -> usize {
        self.pending_inert_effects.len()
            + self.pending_native_valid_action.map_or(0, |action| {
                native_valid_action_effect_kinds_v0(action).len()
            })
    }

    pub fn production_activation_check(&self) -> Result<(), crate::ProductionActivationBlockedV0> {
        crate::production_activation_gate_v0()
    }
}

fn take_exact_anchor_successor_persistence_v0(
    effects: Vec<Effect>,
) -> Result<SafetyStatePersistenceV0, PocoNodeProcessHostErrorV0> {
    match effects.as_slice() {
        [Effect::PersistSafetyState(_)] => {}
        _ => return Err(PocoNodeProcessHostErrorV0::UnexpectedAnchorSuccessorEffects),
    }
    match effects.into_iter().next() {
        Some(Effect::PersistSafetyState(request))
            if request.native_valid_post_ack_action_v0().is_none()
                && request.native_finalization_applied_v0().is_none() =>
        {
            Ok(request)
        }
        _ => Err(PocoNodeProcessHostErrorV0::UnexpectedAnchorSuccessorEffects),
    }
}

fn take_exact_anchor_successor_validation_effect_v0(
    effects: Vec<Effect>,
) -> Result<Effect, PocoNodeProcessHostErrorV0> {
    if !matches!(effects.as_slice(), [Effect::ValidateSyncedPayload(_)]) {
        return Err(PocoNodeProcessHostErrorV0::UnexpectedAnchorSuccessorEffects);
    }
    effects
        .into_iter()
        .next()
        .ok_or(PocoNodeProcessHostErrorV0::UnexpectedAnchorSuccessorEffects)
}

type ProcessRecoveryPartsV0 = (Core, PocoNodeProcessBootstrapModeV0, Vec<Effect>, bool);

fn recover_invalid_completion_v0(
    core_config: CoreConfig,
    safety_store: &SqliteSafetyStateStoreV0<StrictEd25519Verifier>,
    application: &mut NativeConsensusApplicationHostV0,
    verifier: &StrictEd25519Verifier,
) -> Result<ProcessRecoveryPartsV0, PocoNodeProcessHostErrorV0> {
    let active = application.active_invalid_recovery_job_count_v0();
    if active > 1 {
        return Err(PocoNodeProcessHostErrorV0::UnexpectedActiveInvalidJobs {
            expected: 1,
            actual: active,
        });
    }
    let confirmed = safety_store
        .confirmed_native_deterministic_invalid_head_v0()
        .map_err(PocoNodeProcessHostErrorV0::SafetyStore)?;
    let source = application
        .recover_confirmed_invalid_completion_v0(&confirmed)
        .map_err(PocoNodeProcessHostErrorV0::ApplicationRecoveryTransition)?;
    let expected_active = match source {
        NativeValidationRecoveredInvalidStateV0::Delivered => 1,
        NativeValidationRecoveredInvalidStateV0::Acked => 0,
        NativeValidationRecoveredInvalidStateV0::CallbackPending => {
            return Err(PocoNodeProcessHostErrorV0::UnexpectedInvalidApplicationState)
        }
    };
    if active != expected_active {
        return Err(PocoNodeProcessHostErrorV0::UnexpectedActiveInvalidJobs {
            expected: expected_active,
            actual: active,
        });
    }
    let acked = application
        .acknowledge_recovered_invalid_completion_v0(&confirmed)
        .map_err(PocoNodeProcessHostErrorV0::ApplicationRecoveryTransition)?;
    validate_invalid_acked_v0(&acked, &confirmed)?;
    let core = Core::recover(core_config, confirmed.state().clone(), verifier)
        .map_err(PocoNodeProcessHostErrorV0::Core)?;
    Ok((
        core,
        PocoNodeProcessBootstrapModeV0::DeterministicInvalidCompletion,
        Vec::new(),
        false,
    ))
}

fn recover_one_invalid_obligation_v0(
    core_config: CoreConfig,
    head: &RecoveredSafetyStateV0,
    safety_store: &mut SqliteSafetyStateStoreV0<StrictEd25519Verifier>,
    application: &mut NativeConsensusApplicationHostV0,
    verifier: &StrictEd25519Verifier,
) -> Result<ProcessRecoveryPartsV0, PocoNodeProcessHostErrorV0> {
    let active = application.active_invalid_recovery_job_count_v0();
    if active != 1 {
        return Err(PocoNodeProcessHostErrorV0::UnexpectedActiveInvalidJobs {
            expected: 1,
            actual: active,
        });
    }
    let session = Core::begin_payload_validation_obligation_recovery_v0(
        core_config,
        head.state().clone(),
        verifier,
    )
    .map_err(PocoNodeProcessHostErrorV0::Core)?;
    let route = session.challenge().route();
    let validation_id = session.challenge().id();
    let mut core = match session.reconcile_and_activate_v0(application) {
        Ok(core) => core,
        Err(error) => {
            if let Some(failure) = application.last_invalid_reconcile_failure_v0() {
                return Err(PocoNodeProcessHostErrorV0::ApplicationRecoveryReconcile(
                    failure,
                ));
            }
            return Err(PocoNodeProcessHostErrorV0::Core(error));
        }
    };
    let source = application
        .recovered_invalid_obligation_state_v0()
        .ok_or(PocoNodeProcessHostErrorV0::MissingReconciledInvalidOwner)?;
    if !matches!(
        source,
        NativeValidationRecoveredInvalidStateV0::CallbackPending
            | NativeValidationRecoveredInvalidStateV0::Delivered
    ) {
        return Err(PocoNodeProcessHostErrorV0::UnexpectedInvalidApplicationState);
    }
    let callback = application
        .recovered_invalid_obligation_callback_facts_v0()
        .ok_or(PocoNodeProcessHostErrorV0::MissingReconciledInvalidOwner)?;
    validate_invalid_callback_v0(&callback, route, validation_id)?;
    let input = match route {
        PayloadValidationRouteV0::Proposal => Input::PayloadValidated {
            id: validation_id,
            result: PayloadValidationResult::DeterministicallyInvalid,
        },
        PayloadValidationRouteV0::Synced => Input::SyncedPayloadValidated {
            id: validation_id,
            result: PayloadValidationResult::DeterministicallyInvalid,
        },
    };
    let persistence = take_exact_invalid_persistence_v0(
        core.step(input, verifier)
            .map_err(PocoNodeProcessHostErrorV0::Core)?,
    )?;
    let accepted = application
        .record_recovered_invalid_core_acceptance_v0(&persistence)
        .map_err(PocoNodeProcessHostErrorV0::ApplicationRecoveryTransition)?;
    validate_invalid_callback_v0(&accepted, route, validation_id)?;
    application
        .final_invalid_recovery_audit_v0()
        .map_err(PocoNodeProcessHostErrorV0::ApplicationRecoveryTransition)?;

    let context = native_invalid_transition_context_v0(&accepted, persistence.state().revision())?;
    safety_store
        .bind_core_v0(core.safety_state_persistence_binding_v0())
        .map_err(PocoNodeProcessHostErrorV0::SafetyStore)?;
    safety_store
        .persist_exact_v0(&persistence, &context)
        .map_err(PocoNodeProcessHostErrorV0::SafetyStore)?;
    let confirmed = safety_store
        .confirmed_native_deterministic_invalid_head_exact_v0(persistence.state(), &context)
        .map_err(PocoNodeProcessHostErrorV0::SafetyStore)?;
    let completion_state = application
        .recover_confirmed_invalid_completion_v0(&confirmed)
        .map_err(PocoNodeProcessHostErrorV0::ApplicationRecoveryTransition)?;
    if completion_state != NativeValidationRecoveredInvalidStateV0::Delivered {
        return Err(PocoNodeProcessHostErrorV0::UnexpectedInvalidApplicationState);
    }
    let acked = application
        .acknowledge_recovered_invalid_completion_v0(&confirmed)
        .map_err(PocoNodeProcessHostErrorV0::ApplicationRecoveryTransition)?;
    validate_invalid_acked_v0(&acked, &confirmed)?;
    application
        .final_invalid_recovery_audit_v0()
        .map_err(PocoNodeProcessHostErrorV0::ApplicationRecoveryTransition)?;
    let effects = core
        .step(
            Input::StorageAck {
                barrier: persistence.barrier(),
            },
            verifier,
        )
        .map_err(PocoNodeProcessHostErrorV0::Core)?;
    if core.safety_state() != confirmed.state() {
        return Err(PocoNodeProcessHostErrorV0::RecoveredHeadMismatch);
    }
    Ok((
        core,
        PocoNodeProcessBootstrapModeV0::DeterministicInvalidObligation,
        effects,
        true,
    ))
}

fn take_exact_invalid_persistence_v0(
    effects: Vec<Effect>,
) -> Result<SafetyStatePersistenceV0, PocoNodeProcessHostErrorV0> {
    if effects.len() != 1 {
        return Err(PocoNodeProcessHostErrorV0::UnexpectedInvalidEffectSet {
            expected: 1,
            actual: effects.len(),
        });
    }
    match effects.into_iter().next().expect("exact count checked") {
        Effect::PersistSafetyState(request) => Ok(request),
        _ => Err(PocoNodeProcessHostErrorV0::UnexpectedInvalidEffectShape),
    }
}

fn validate_invalid_callback_v0(
    facts: &NativeValidationRecoveredInvalidCallbackFactsV0,
    route: PayloadValidationRouteV0,
    validation_id: ValidationId,
) -> Result<(), PocoNodeProcessHostErrorV0> {
    if facts.route() != route || facts.validation_id() != validation_id {
        return Err(PocoNodeProcessHostErrorV0::InvalidCallbackIdentityMismatch);
    }
    Ok(())
}

fn native_invalid_transition_context_v0(
    facts: &NativeValidationRecoveredInvalidCallbackFactsV0,
    completion_revision: u64,
) -> Result<SafetyTransitionContextV0, PocoNodeProcessHostErrorV0> {
    let transition = NativeDeterministicInvalidTransitionV0::new(
        facts.route(),
        facts.validation_id(),
        facts.request_fingerprint(),
        facts.immutable_checksum(),
        facts.host_config_ref(),
        facts.reason().code_v0(),
        facts.artifact_checksum(),
        facts.callback_payload_checksum(),
        facts.idempotency_key(),
        facts.delivery_attempt(),
        facts.row_checksum(),
        facts.outbox_checksum(),
        completion_revision,
    )
    .map_err(PocoNodeProcessHostErrorV0::SafetyStore)?;
    Ok(SafetyTransitionContextV0::native_deterministic_invalid(
        transition,
    ))
}

fn validate_invalid_acked_v0(
    acked: &NativeValidationRecoveredAckedFactsV0,
    confirmed: &ConfirmedNativeDeterministicInvalidHeadV0,
) -> Result<(), PocoNodeProcessHostErrorV0> {
    let transition = confirmed.transition();
    if acked.route() != transition.route()
        || acked.validation_id() != transition.validation_id()
        || acked.request_fingerprint() != transition.request_fingerprint()
        || acked.immutable_checksum() != transition.job_immutable_checksum()
        || acked.host_config_ref() != transition.application_host_config_ref()
        || acked.reason().code_v0() != transition.reason_code()
        || acked.artifact_checksum() != transition.artifact_checksum()
        || acked.callback_payload_checksum() != transition.callback_payload_checksum()
        || acked.accepted_core_revision() != transition.completion_revision()
        || acked.predecessor_idempotency_key() != transition.idempotency_key()
        || acked.predecessor_delivery_attempt() != transition.delivery_attempt()
        || acked.predecessor_delivered_row_checksum() != transition.delivered_job_row_checksum()
        || acked.predecessor_outbox_checksum() != transition.outbox_checksum()
    {
        return Err(PocoNodeProcessHostErrorV0::InvalidAcknowledgementMismatch);
    }
    Ok(())
}

fn head_has_current_invalid_completion_v0(state: &SafetyState) -> bool {
    state
        .payload_validation_completions()
        .iter()
        .any(|completion| {
            completion.first_recorded_revision() == state.revision()
                && completion.result() == DurablePayloadValidationResultV1::DeterministicallyInvalid
        })
}

impl<W> fmt::Debug for PocoNodeProcessHostV0<W> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = (&self.core_owner, &self.safety_store, &self.application_host);
        formatter
            .debug_struct("PocoNodeProcessHostV0")
            .field("bootstrap", &self.bootstrap)
            .field("signer_owner", &self.signer_owner)
            .field(
                "pending_inert_effect_count",
                &(self.pending_inert_effects.len()
                    + self.pending_native_valid_action.map_or(0, |action| {
                        native_valid_action_effect_kinds_v0(action).len()
                    })),
            )
            .finish_non_exhaustive()
    }
}

fn validate_inert_configuration_v0(config: &CoreConfig) -> Result<(), PocoNodeProcessHostErrorV0> {
    reject_authenticated_genesis_commissioning_v0(config)?;
    if config.consensus_parameters().production_activation() {
        return Err(PocoNodeProcessHostErrorV0::ProductionActivationRequested);
    }
    if config.consensus_parameters().rollout_phase() != RolloutPhase::Shadow {
        return Err(PocoNodeProcessHostErrorV0::NonShadowRolloutRequested);
    }
    if config.validator_set().epoch().get() != 0 {
        return Err(PocoNodeProcessHostErrorV0::UnsupportedEpoch {
            epoch: config.validator_set().epoch().get(),
        });
    }
    Ok(())
}

fn reject_authenticated_genesis_commissioning_v0(
    config: &CoreConfig,
) -> Result<(), PocoNodeProcessHostErrorV0> {
    if config
        .authenticated_genesis_application_parent_v0()
        .is_some()
    {
        return Err(
            PocoNodeProcessHostErrorV0::AuthenticatedGenesisCommissioningRequiresDedicatedHost,
        );
    }
    Ok(())
}

fn validate_pinned_signer_against_safety_v0(
    facts: SignerJournalReconciliationFactsV0,
    safety: &SafetyState,
    config: &CoreConfig,
) -> Result<(), PocoNodeProcessHostErrorV0> {
    // Pinned activation can repair LocalOneAhead with an external CAS before
    // later SQLite activation checks complete.  This offline coordinator
    // promises that every failed startup leaves the external domain intact,
    // so it deliberately supports only the already-exact case.
    if facts.external_relation() != SignerExternalWatermarkRelationV0::Exact {
        return Err(PocoNodeProcessHostErrorV0::SignerExternalRepairRequired);
    }
    validate_signer_lifecycle_against_safety_v0(
        facts.capacity(),
        facts.tail(),
        facts.pending_intent(),
        safety,
        config,
    )
}

fn validate_confirmed_pinned_signer_against_safety_v0<W: ExternalMonotonicWatermarkV0>(
    facts: &ConfirmedSignerNodeCheckpointFactsV0,
    pinned: &PinnedSqliteSignerJournalV0<W>,
    expected_path: &Path,
    safety: &SafetyState,
    config: &CoreConfig,
) -> Result<(), PocoNodeProcessHostErrorV0> {
    if !facts.belongs_to_pinned_journal_at_path_v0(pinned, expected_path) {
        return Err(PocoNodeProcessHostErrorV0::SignerHeadReconfirmationMismatch);
    }
    let profile = pinned.profile();
    let identity = facts.identity();
    let validator_set = config.validator_set();
    if facts.profile_checksum() != profile.profile_checksum()
        || identity.chain_id() != profile.chain_id()
        || identity.protocol_version() != profile.protocol_version()
        || identity.epoch() != profile.epoch()
        || identity.validator_set_id() != profile.validator_set_id()
        || identity.author() != profile.author()
        || identity.signer_profile_ref() != profile.signer_profile_ref()
        || identity.external_watermark_scope() != profile.external_watermark_scope()
        || identity.chain_id() != validator_set.chain_id()
        || identity.protocol_version() != validator_set.protocol_version()
        || identity.epoch() != validator_set.epoch()
        || identity.validator_set_id() != validator_set.id()
        || identity.author() != config.local_validator()
        || facts.exact_watermark().scope() != identity.external_watermark_scope()
        || facts.exact_watermark().journal_id() != facts.journal_id()
    {
        return Err(PocoNodeProcessHostErrorV0::SignerHeadReconfirmationMismatch);
    }
    validate_signer_lifecycle_against_safety_v0(
        facts.capacity(),
        facts.tail(),
        facts.pending_intent(),
        safety,
        config,
    )
}

fn validate_signer_lifecycle_against_safety_v0(
    capacity: JournalCapacityV0,
    tail: Option<SignerJournalTailFactsV0>,
    pending_intent: Option<SignerPreparedIntentFactsV0>,
    safety: &SafetyState,
    config: &CoreConfig,
) -> Result<(), PocoNodeProcessHostErrorV0> {
    if let Some(revision) = capacity.maximum_safety_revision() {
        if revision > safety.revision() {
            return Err(PocoNodeProcessHostErrorV0::SignerAheadOfSafety {
                signer_revision: revision,
                safety_revision: safety.revision(),
            });
        }
    }
    let canonical_pending = safety
        .pending_sign()
        .map(|intent| canonical_sign_intent_v0(config, intent))
        .transpose()?;
    let expected_vote_view = safety.last_voted_view().map(|view| view.get());
    let expected_timeout_view = safety.last_timeout_view().map(|view| view.get());
    let maximum_vote_view = capacity.maximum_vote_view();
    let maximum_timeout_view = capacity.maximum_timeout_view();
    let journaled_pending = match canonical_pending.as_ref().map(|intent| intent.preimage()) {
        None => {
            require_signer_view_exact_v0(maximum_vote_view, expected_vote_view, true)?;
            require_signer_view_exact_v0(maximum_timeout_view, expected_timeout_view, false)?;
            false
        }
        Some(trnm_consensus_types::CanonicalSignPreimageV0::Vote(value)) => {
            let pending_view = value.view().get();
            if expected_vote_view != Some(pending_view)
                || maximum_vote_view.is_some_and(|view| view > pending_view)
            {
                return Err(PocoNodeProcessHostErrorV0::SignerVoteViewMismatch {
                    signer_view: maximum_vote_view,
                    safety_view: expected_vote_view,
                });
            }
            require_signer_view_exact_v0(maximum_timeout_view, expected_timeout_view, false)?;
            maximum_vote_view == Some(pending_view)
        }
        Some(trnm_consensus_types::CanonicalSignPreimageV0::TimeoutVote(value)) => {
            let pending_view = value.view().get();
            if expected_timeout_view != Some(pending_view)
                || maximum_timeout_view.is_some_and(|view| view > pending_view)
            {
                return Err(PocoNodeProcessHostErrorV0::SignerTimeoutViewMismatch {
                    signer_view: maximum_timeout_view,
                    safety_view: expected_timeout_view,
                });
            }
            require_signer_view_exact_v0(maximum_vote_view, expected_vote_view, true)?;
            maximum_timeout_view == Some(pending_view)
        }
    };
    match (pending_intent, canonical_pending.as_ref()) {
        (Some(pending), Some(intent))
            if pending.fingerprint() == intent.fingerprint().into_bytes()
                && pending.epoch() == intent.epoch().get()
                && pending.view()
                    == match intent.preimage() {
                        trnm_consensus_types::CanonicalSignPreimageV0::Vote(value) => {
                            value.view().get()
                        }
                        trnm_consensus_types::CanonicalSignPreimageV0::TimeoutVote(value) => {
                            value.view().get()
                        }
                    }
                && pending.kind()
                    == if matches!(
                        intent.preimage(),
                        trnm_consensus_types::CanonicalSignPreimageV0::Vote(_)
                    ) {
                        0
                    } else {
                        1
                    }
                && pending.safety_revision() == intent.authorizing_safety_revision()
                && pending.signing_root() == intent.signing_root().into_bytes() => {}
        (None, _) => {}
        (Some(_), None) => {
            return Err(PocoNodeProcessHostErrorV0::PreparedSignerWithoutSafetyIntent)
        }
        (Some(_), Some(_)) => return Err(PocoNodeProcessHostErrorV0::PreparedSignerIntentMismatch),
    }
    if canonical_pending.is_some() && !journaled_pending && pending_intent.is_some() {
        return Err(PocoNodeProcessHostErrorV0::PendingSignerTailMismatch);
    }
    if let Some(intent) = canonical_pending.as_ref().filter(|_| journaled_pending) {
        let tail = tail.ok_or(PocoNodeProcessHostErrorV0::PendingSafetyIntentWithoutSignerTail)?;
        let (view, kind) = match intent.preimage() {
            trnm_consensus_types::CanonicalSignPreimageV0::Vote(value) => (value.view().get(), 0),
            trnm_consensus_types::CanonicalSignPreimageV0::TimeoutVote(value) => {
                (value.view().get(), 1)
            }
        };
        if tail.fingerprint() != intent.fingerprint().into_bytes()
            || tail.epoch() != intent.epoch().get()
            || tail.view() != view
            || tail.kind() != kind
            || tail.safety_revision() != intent.authorizing_safety_revision()
            || tail.signing_root() != intent.signing_root().into_bytes()
        {
            return Err(PocoNodeProcessHostErrorV0::PendingSignerTailMismatch);
        }
    }
    Ok(())
}

fn validate_virgin_state_sync_signer_v0(
    facts: SignerJournalReconciliationFactsV0,
) -> Result<(), PocoNodeProcessHostErrorV0> {
    let capacity = facts.capacity();
    let shape = StateSyncSignerShapeV0 {
        external_relation: facts.external_relation(),
        intent_count: capacity.intent_count(),
        event_count: capacity.event_count(),
        intent_bytes: capacity.intent_bytes(),
        maximum_safety_revision: capacity.maximum_safety_revision(),
        maximum_vote_view: capacity.maximum_vote_view(),
        maximum_timeout_view: capacity.maximum_timeout_view(),
        has_tail: facts.tail().is_some(),
        has_pending_intent: facts.pending_intent().is_some(),
    };
    if !state_sync_signer_shape_is_virgin_v0(shape) {
        return Err(PocoNodeProcessHostErrorV0::StateSyncSignerNotVirgin);
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct StateSyncSignerShapeV0 {
    external_relation: SignerExternalWatermarkRelationV0,
    intent_count: u64,
    event_count: u64,
    intent_bytes: u64,
    maximum_safety_revision: Option<u64>,
    maximum_vote_view: Option<u64>,
    maximum_timeout_view: Option<u64>,
    has_tail: bool,
    has_pending_intent: bool,
}

fn state_sync_signer_shape_is_virgin_v0(shape: StateSyncSignerShapeV0) -> bool {
    shape.external_relation == SignerExternalWatermarkRelationV0::Exact
        && shape.intent_count == 0
        && shape.event_count == 0
        && shape.intent_bytes == 0
        && shape.maximum_safety_revision.is_none()
        && shape.maximum_vote_view.is_none()
        && shape.maximum_timeout_view.is_none()
        && !shape.has_tail
        && !shape.has_pending_intent
}

fn confirmed_state_sync_checkpoint_matches_challenge_v0(
    challenge: &StateSyncAnchorRecoveryChallengeV0,
    confirmed: &ConfirmedStateSyncCheckpointBootstrapHeadV0,
) -> bool {
    let header = challenge.trusted_base_header();
    let transition = confirmed.transition();
    confirmed.revision() == 0
        && confirmed.state() == challenge.safety_state()
        && transition.transition_revision() == 0
        && transition.state_record_checksum() == confirmed.state_record_checksum()
        && transition.anchor_checksum() == state_sync_anchor_checksum_v0(challenge.anchor())
        && transition.proof_id() == challenge.anchor().proof_id()
        && transition.target_block_id() == header.id()
        && transition.target_state_root() == header.state_root()
        && transition.target_height() == header.height()
        && transition.target_view() == header.view()
        && transition.target_timestamp_ms() == header.timestamp_ms()
}

fn validate_state_sync_application_facts_v0(
    facts: trnm_consensus_app::ConfirmedNativeApplicationAppliedFactsV0,
    safety: &SafetyState,
) -> Result<(), PocoNodeProcessHostErrorV0> {
    let Some(anchor) = safety.state_sync_anchor() else {
        return Err(PocoNodeProcessHostErrorV0::StateSyncApplicationClosureMismatch);
    };
    let header = anchor.proof().finalized_block().header();
    if facts.kind() != NativeConsensusApplicationAppliedKindV0::TrustedBase
        || facts.block_id() != header.id()
        || facts.height() != header.height().get()
        || facts.state_root() != *header.state_root().as_bytes()
        || facts.view() != header.view().get()
        || facts.timestamp_ms() != header.timestamp_ms()
        || facts.overlay_checksum().is_some()
        || facts.proof_id().is_some()
        || facts.receipt_count() != 0
        || facts.matched_valid_completion_count() != 0
    {
        return Err(PocoNodeProcessHostErrorV0::StateSyncApplicationClosureMismatch);
    }
    Ok(())
}

fn require_signer_view_exact_v0(
    signer_view: Option<u64>,
    safety_view: Option<u64>,
    vote: bool,
) -> Result<(), PocoNodeProcessHostErrorV0> {
    if signer_view == safety_view {
        return Ok(());
    }
    if vote {
        Err(PocoNodeProcessHostErrorV0::SignerVoteViewMismatch {
            signer_view,
            safety_view,
        })
    } else {
        Err(PocoNodeProcessHostErrorV0::SignerTimeoutViewMismatch {
            signer_view,
            safety_view,
        })
    }
}

fn canonical_sign_intent_v0(
    config: &CoreConfig,
    intent: &SignIntent,
) -> Result<CanonicalSignIntentV0, PocoNodeProcessHostErrorV0> {
    match intent {
        SignIntent::Vote {
            authorizing_safety_revision,
            view,
            height,
            block_id,
            ..
        } => CanonicalSignIntentV0::vote(
            config.validator_set(),
            config.local_validator(),
            *authorizing_safety_revision,
            *view,
            *height,
            *block_id,
        ),
        SignIntent::TimeoutVote {
            authorizing_safety_revision,
            view,
            high_qc,
            ..
        } => CanonicalSignIntentV0::timeout_vote(
            config.validator_set(),
            config.local_validator(),
            *authorizing_safety_revision,
            *view,
            *high_qc,
        ),
    }
    .map_err(|_| PocoNodeProcessHostErrorV0::PreparedSignerIntentMismatch)
}

fn validate_ordinary_clean_state_v0(
    safety: &SafetyState,
) -> Result<(), PocoNodeProcessHostErrorV0> {
    if safety.pending_sign().is_some()
        || safety.pending_finalize().is_some()
        || !safety.finalization_queue().is_empty()
        || safety.pending_tc_high_qc_sync().is_some()
        || safety.pending_standalone_qc_sync().is_some()
        || safety.safety_halt().is_some()
        || safety.high_qc().qc_ref().block_id() != safety.finalized().block_id()
        || safety.locked_qc().qc_ref().block_id() != safety.finalized().block_id()
    {
        return Err(PocoNodeProcessHostErrorV0::OrdinaryStateNotClean);
    }
    Ok(())
}

fn inert_effect_kind_v0(effect: &Effect) -> Option<PocoNodeInertEffectKindV0> {
    match effect {
        Effect::RequestSafetyReplay { .. } => Some(PocoNodeInertEffectKindV0::RequestSafetyReplay),
        Effect::RequestSignature { .. } => Some(PocoNodeInertEffectKindV0::RequestSignature),
        Effect::ArmViewTimer { .. } => Some(PocoNodeInertEffectKindV0::ArmViewTimer),
        Effect::Finalize(_) => Some(PocoNodeInertEffectKindV0::Finalize),
        Effect::RequestTcHighQcSync { .. } => Some(PocoNodeInertEffectKindV0::RequestTcHighQcSync),
        Effect::RequestStandaloneQcSync { .. } => {
            Some(PocoNodeInertEffectKindV0::RequestStandaloneQcSync)
        }
        Effect::SafetyHalted(_) => Some(PocoNodeInertEffectKindV0::SafetyHalted),
        _ => None,
    }
}

fn native_valid_action_effect_kinds_v0(
    action: NativeValidPostAckActionV0,
) -> &'static [PocoNodeInertEffectKindV0] {
    use NativeValidPostAckActionV0 as Action;
    use PocoNodeInertEffectKindV0 as Kind;

    match action {
        Action::None => &[],
        Action::RequestSignature => &[Kind::RequestSignature],
        Action::ArmViewTimer => &[Kind::ArmViewTimer],
        Action::ArmViewTimerThenFinalize => &[Kind::ArmViewTimer, Kind::Finalize],
        Action::RequestTcHighQcSync => &[Kind::RequestTcHighQcSync],
        Action::RequestStandaloneQcSync => &[Kind::RequestStandaloneQcSync],
        Action::ArmViewTimerThenRequestStandaloneQcSync => {
            &[Kind::ArmViewTimer, Kind::RequestStandaloneQcSync]
        }
        Action::SafetyHaltedConflict => &[Kind::SafetyHalted],
    }
}

#[allow(clippy::too_many_arguments)]
fn validate_native_valid_recovered_action_v0(
    recovered: &NativeValidCompletionRecoveredActionV0,
    expected_revision: u64,
    expected_state_record_checksum: [u8; 32],
    expected_route: PayloadValidationRouteV0,
    expected_validation_id: ValidationId,
    expected_valid_result_checksum: [u8; 32],
    expected_post_ack_action: NativeValidPostAckActionV0,
) -> Result<(), PocoNodeProcessHostErrorV0> {
    if recovered.safety_head_revision_v0() != expected_revision
        || recovered.safety_state_record_checksum_v0() != expected_state_record_checksum
        || recovered.route_v0() != expected_route
        || recovered.validation_id_v0() != expected_validation_id
        || recovered.valid_result_checksum_v0() != expected_valid_result_checksum
        || recovered.post_ack_action_v0() != expected_post_ack_action
    {
        return Err(PocoNodeProcessHostErrorV0::NativeValidRecoveredActionMismatch);
    }
    Ok(())
}

fn durable_valid_completion_count_v0(
    safety: &SafetyState,
) -> Result<u64, PocoNodeProcessHostErrorV0> {
    u64::try_from(
        safety
            .payload_validation_completions()
            .iter()
            .filter(|completion| completion.result().is_valid())
            .count(),
    )
    .map_err(|_| PocoNodeProcessHostErrorV0::NativeValidCompletionCountOverflow)
}

fn sanitize_state_sync_checkpoint_bootstrap_effects_v0(
    effects: &[Effect],
    safety: &SafetyState,
) -> Result<(), PocoNodeProcessHostErrorV0> {
    match effects {
        [Effect::RequestSafetyReplay {
            finalized,
            high_qc,
            locked_qc,
        }] if *finalized == safety.finalized()
            && *high_qc == safety.high_qc().qc_ref()
            && *locked_qc == safety.locked_qc().qc_ref() =>
        {
            Ok(())
        }
        _ => Err(PocoNodeProcessHostErrorV0::UnexpectedStateSyncBootstrapEffectShape),
    }
}

#[cfg(test)]
fn canonical_state_sync_checkpoint_bootstrap_effect_kinds_v0(
    kinds: &[PocoNodeInertEffectKindV0],
) -> bool {
    matches!(kinds, [PocoNodeInertEffectKindV0::RequestSafetyReplay])
}

fn sanitize_ordinary_effects_v0(effects: &[Effect]) -> Result<(), PocoNodeProcessHostErrorV0> {
    if effects.is_empty() {
        Ok(())
    } else {
        Err(PocoNodeProcessHostErrorV0::UnexpectedOrdinaryEffects)
    }
}

fn sanitize_invalid_effects_v0(effects: &[Effect]) -> Result<(), PocoNodeProcessHostErrorV0> {
    if matches!(effects, [] | [Effect::SafetyHalted(_)]) {
        Ok(())
    } else {
        Err(PocoNodeProcessHostErrorV0::UnexpectedInvalidEffectShape)
    }
}

fn sanitize_tag3_effects_v0(effects: &[Effect]) -> Result<(), PocoNodeProcessHostErrorV0> {
    let kinds = effects
        .iter()
        .map(inert_effect_kind_v0)
        .collect::<Option<Vec<_>>>()
        .ok_or(PocoNodeProcessHostErrorV0::UnexpectedTag3EffectShape)?;
    if canonical_tag3_effect_kinds_v0(kinds.as_slice()) {
        Ok(())
    } else {
        Err(PocoNodeProcessHostErrorV0::UnexpectedTag3EffectShape)
    }
}

fn canonical_tag3_effect_kinds_v0(kinds: &[PocoNodeInertEffectKindV0]) -> bool {
    matches!(
        kinds,
        [] | [PocoNodeInertEffectKindV0::ArmViewTimer]
            | [PocoNodeInertEffectKindV0::RequestSignature]
            | [
                PocoNodeInertEffectKindV0::ArmViewTimer,
                PocoNodeInertEffectKindV0::RequestSignature
            ]
            | [PocoNodeInertEffectKindV0::Finalize]
            | [
                PocoNodeInertEffectKindV0::ArmViewTimer,
                PocoNodeInertEffectKindV0::Finalize
            ]
            | [PocoNodeInertEffectKindV0::RequestTcHighQcSync]
            | [PocoNodeInertEffectKindV0::RequestStandaloneQcSync]
            | [
                PocoNodeInertEffectKindV0::ArmViewTimer,
                PocoNodeInertEffectKindV0::RequestStandaloneQcSync
            ]
    )
}

#[derive(Debug)]
pub enum PocoNodeProcessHostErrorV0 {
    StartupAuditWorkerUnavailable,
    InvalidApplicationConfig,
    ApplicationChainMismatch,
    ApplicationStatePathRequired,
    ApplicationStatePathNotAbsolute,
    InvalidStorePath,
    StoreParentUnavailable,
    StoreParentIdentityChanged,
    UnsupportedPlatform,
    OverlappingStoreNamespaces,
    AuthenticatedGenesisCommissioningRequiresDedicatedHost,
    ProductionActivationRequested,
    NonShadowRolloutRequested,
    UnsupportedEpoch {
        epoch: u64,
    },
    ValidationObligationRecoveryUnavailable {
        revision: u64,
    },
    UnsupportedValidationObligationCount {
        count: usize,
    },
    UnexpectedRecoveryState {
        revision: u64,
        obligations: usize,
    },
    InvalidStateSyncBootstrapHead {
        revision: u64,
        obligations: usize,
    },
    OrdinaryInvalidCompletion {
        revision: u64,
    },
    NativeValidRecoveryUnavailable {
        revision: u64,
    },
    AnchorSuccessorInFlightRecoveryUnavailable {
        revision: u64,
    },
    UnexpectedAnchorSuccessorPhase {
        revision: u64,
    },
    ActiveNativeValidRecoveryUnavailable {
        revision: u64,
        jobs: usize,
    },
    UnexpectedActiveInvalidJobs {
        expected: usize,
        actual: usize,
    },
    MissingReconciledInvalidOwner,
    UnexpectedInvalidApplicationState,
    InvalidCallbackIdentityMismatch,
    InvalidAcknowledgementMismatch,
    UnexpectedInvalidEffectSet {
        expected: usize,
        actual: usize,
    },
    UnexpectedInvalidEffectShape,
    SignerAheadOfSafety {
        signer_revision: u64,
        safety_revision: u64,
    },
    SignerExternalRepairRequired,
    SignerHeadReconfirmationMismatch,
    SignerVoteViewMismatch {
        signer_view: Option<u64>,
        safety_view: Option<u64>,
    },
    SignerTimeoutViewMismatch {
        signer_view: Option<u64>,
        safety_view: Option<u64>,
    },
    PreparedSignerWithoutSafetyIntent,
    PreparedSignerIntentMismatch,
    PendingSafetyIntentWithoutSignerTail,
    PendingSignerTailMismatch,
    StateSyncSignerNotVirgin,
    StateSyncApplicationClosureMismatch,
    RecoveredHeadMismatch,
    UnexpectedOrdinaryEffects,
    OrdinaryStateNotClean,
    UnexpectedStateSyncBootstrapEffectShape,
    UnexpectedAnchorSuccessorEffects,
    AnchorSuccessorValidationFactsMismatch,
    NativeValidRecoveredActionMismatch,
    NativeValidCompletionCountOverflow,
    NativeValidApplicationCompletionCountMismatch {
        expected: u64,
        actual: u64,
    },
    UnexpectedTag3EffectShape,
    Core(trnm_consensus_core::CoreError),
    SafetyStore(trnm_consensus_safety_store::SafetyStoreErrorV0),
    Application(NativeConsensusApplicationHostErrorV0),
    ApplicationRecoveryReconcile(NativeValidationRecoveryReconcileFailureV0),
    ApplicationRecoveryTransition(NativeValidationRecoveryTransitionFailureV0),
    SignerJournal(SignerJournalErrorV0),
}

impl fmt::Display for PocoNodeProcessHostErrorV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StartupAuditWorkerUnavailable => formatter.write_str(
                "bounded unified-host startup audit worker is unavailable",
            ),
            Self::InvalidApplicationConfig => formatter.write_str("invalid application config"),
            Self::ApplicationChainMismatch => {
                formatter.write_str("application and Core chain IDs differ")
            }
            Self::ApplicationStatePathRequired => {
                formatter.write_str("unified offline host requires an existing application path")
            }
            Self::ApplicationStatePathNotAbsolute => {
                formatter.write_str("application state path must be absolute")
            }
            Self::InvalidStorePath => formatter.write_str("store path has no parent"),
            Self::StoreParentUnavailable => {
                formatter.write_str("store parent is absent or not canonical")
            }
            Self::StoreParentIdentityChanged => {
                formatter.write_str("store parent path or filesystem identity changed")
            }
            Self::UnsupportedPlatform => {
                formatter.write_str("unified offline host requires Unix directory identities")
            }
            Self::OverlappingStoreNamespaces => {
                formatter.write_str("store parent namespaces overlap")
            }
            Self::AuthenticatedGenesisCommissioningRequiresDedicatedHost => formatter.write_str(
                "authenticated genesis application commissioning requires the dedicated inert commissioning host",
            ),
            Self::ProductionActivationRequested => {
                formatter.write_str("development-only host refuses production activation")
            }
            Self::NonShadowRolloutRequested => {
                formatter.write_str("development-only host requires shadow rollout")
            }
            Self::UnsupportedEpoch { epoch } => write!(formatter, "unsupported epoch {epoch}"),
            Self::ValidationObligationRecoveryUnavailable { revision } => write!(
                formatter,
                "Safety revision {revision} requires an obligation recovery branch"
            ),
            Self::UnsupportedValidationObligationCount { count } => write!(
                formatter,
                "deterministic-invalid recovery supports exactly one obligation, got {count}"
            ),
            Self::UnexpectedRecoveryState {
                revision,
                obligations,
            } => write!(
                formatter,
                "Safety revision {revision} has unsupported recovery context with {obligations} obligation(s)"
            ),
            Self::InvalidStateSyncBootstrapHead {
                revision,
                obligations,
            } => write!(
                formatter,
                "state-sync checkpoint bootstrap requires revision zero and no obligations, got revision {revision} with {obligations} obligation(s)"
            ),
            Self::OrdinaryInvalidCompletion { revision } => write!(
                formatter,
                "Safety revision {revision} records a fresh invalid completion with ordinary context"
            ),
            Self::NativeValidRecoveryUnavailable { revision } => write!(
                formatter,
                "Safety revision {revision} is outside the exact non-anchored NativeValid C+D/C+K recovery boundary"
            ),
            Self::AnchorSuccessorInFlightRecoveryUnavailable { revision } => write!(
                formatter,
                "anchored-successor Safety revision {revision} contains an unrecoverable in-flight application obligation"
            ),
            Self::UnexpectedAnchorSuccessorPhase { revision } => write!(
                formatter,
                "Safety revision {revision} is not a stable h1/h2/h3 anchored-successor cut"
            ),
            Self::NativeValidRecoveredActionMismatch => formatter.write_str(
                "recovered NativeValid action differs from its authenticated Safety/App tuple",
            ),
            Self::NativeValidCompletionCountOverflow => formatter.write_str(
                "durable NativeValid completion count exceeds the host fact representation",
            ),
            Self::NativeValidApplicationCompletionCountMismatch { expected, actual } => write!(
                formatter,
                "application closure matches {actual} NativeValid completion(s), expected all {expected} durable Safety completion(s)"
            ),
            Self::ActiveNativeValidRecoveryUnavailable { revision, jobs } => write!(
                formatter,
                "Safety revision {revision} has {jobs} active application Valid recovery job(s), but the stable offline boundary requires exactly one"
            ),
            Self::UnexpectedActiveInvalidJobs { expected, actual } => write!(
                formatter,
                "deterministic-invalid recovery expected {expected} active job(s), got {actual}"
            ),
            Self::MissingReconciledInvalidOwner => {
                formatter.write_str("invalid recovery did not retain its exact application owner")
            }
            Self::UnexpectedInvalidApplicationState => {
                formatter.write_str("invalid recovery found an unsupported application lifecycle state")
            }
            Self::InvalidCallbackIdentityMismatch => {
                formatter.write_str("invalid callback differs from the Core recovery challenge")
            }
            Self::InvalidAcknowledgementMismatch => {
                formatter.write_str("invalid acknowledgement differs from the Safety transition")
            }
            Self::UnexpectedInvalidEffectSet { expected, actual } => write!(
                formatter,
                "invalid recovery expected {expected} persistence effect, got {actual}"
            ),
            Self::UnexpectedInvalidEffectShape => {
                formatter.write_str("invalid recovery emitted an unsupported effect shape")
            }
            Self::SignerAheadOfSafety { signer_revision, safety_revision } => write!(
                formatter,
                "signer Safety revision {signer_revision} is ahead of SafetyStore revision {safety_revision}"
            ),
            Self::SignerExternalRepairRequired => formatter.write_str(
                "unified offline startup refuses a signer external-watermark repair window",
            ),
            Self::SignerHeadReconfirmationMismatch => formatter.write_str(
                "fresh signer confirmation differs from its pinned owner, profile, or Core scope",
            ),
            Self::SignerVoteViewMismatch {
                signer_view,
                safety_view,
            } => write!(
                formatter,
                "signer vote watermark {signer_view:?} differs from SafetyState {safety_view:?}"
            ),
            Self::SignerTimeoutViewMismatch {
                signer_view,
                safety_view,
            } => write!(
                formatter,
                "signer timeout watermark {signer_view:?} differs from SafetyState {safety_view:?}"
            ),
            Self::PreparedSignerWithoutSafetyIntent => {
                formatter.write_str("prepared signer tail has no durable Safety intent")
            }
            Self::PreparedSignerIntentMismatch => {
                formatter.write_str("prepared signer tail differs from durable Safety intent")
            }
            Self::PendingSafetyIntentWithoutSignerTail => {
                formatter.write_str("durable Safety sign intent has no signer-journal tail")
            }
            Self::PendingSignerTailMismatch => {
                formatter.write_str("signer-journal tail differs from durable Safety sign intent")
            }
            Self::StateSyncSignerNotVirgin => formatter.write_str(
                "fresh h1 state-sync bootstrap requires an exact virgin signer namespace",
            ),
            Self::StateSyncApplicationClosureMismatch => formatter.write_str(
                "fresh h1 state-sync bootstrap application closure differs from its authenticated TrustedBase",
            ),
            Self::RecoveredHeadMismatch => {
                formatter.write_str("recovered owners differ from authenticated Safety head")
            }
            Self::UnexpectedOrdinaryEffects => {
                formatter.write_str("ordinary offline bootstrap emitted effects")
            }
            Self::OrdinaryStateNotClean => formatter.write_str(
                "ordinary offline bootstrap requires no pending sign, finalization, sync, halt, or safety replay",
            ),
            Self::UnexpectedStateSyncBootstrapEffectShape => formatter.write_str(
                "state-sync checkpoint bootstrap must emit exactly one safety-replay request",
            ),
            Self::UnexpectedAnchorSuccessorEffects => formatter.write_str(
                "anchored-successor replay exposed an effect outside its exact validation bridge",
            ),
            Self::AnchorSuccessorValidationFactsMismatch => formatter.write_str(
                "anchored-successor application validation facts differ from the exact replay phase",
            ),
            Self::UnexpectedTag3EffectShape => {
                formatter.write_str("tag-3 recovery emitted a non-canonical effect shape")
            }
            Self::Core(error) => write!(formatter, "Core recovery failed: {error}"),
            Self::SafetyStore(error) => write!(formatter, "SafetyStore recovery failed: {error}"),
            Self::Application(error) => write!(formatter, "ApplicationStore recovery failed: {error}"),
            Self::ApplicationRecoveryReconcile(error) => {
                write!(formatter, "application invalid reconciliation failed: {error:?}")
            }
            Self::ApplicationRecoveryTransition(error) => {
                write!(formatter, "application invalid transition failed: {error:?}")
            }
            Self::SignerJournal(error) => write!(formatter, "signer journal recovery failed: {error}"),
        }
    }
}

impl std::error::Error for PocoNodeProcessHostErrorV0 {}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::TempDir;

    use super::{
        canonical_process_store_path_v0, canonical_state_sync_checkpoint_bootstrap_effect_kinds_v0,
        canonical_tag3_effect_kinds_v0, native_valid_action_effect_kinds_v0,
        process_post_recovery_policy_v0, revalidate_process_store_paths_v0,
        state_sync_signer_shape_is_virgin_v0, validate_distinct_store_parents_v0,
        PocoNodeInertEffectKindV0 as Kind, PocoNodeProcessBootstrapModeV0,
        PocoNodeProcessHostErrorV0, ProcessStoreParentIdentitiesV0, StateSyncSignerShapeV0,
    };
    use trnm_consensus_core::NativeValidPostAckActionV0 as ValidAction;
    use trnm_consensus_signer_journal::SignerExternalWatermarkRelationV0;

    #[test]
    fn state_sync_checkpoint_policy_never_installs_operational_authority() {
        let policy = process_post_recovery_policy_v0(
            PocoNodeProcessBootstrapModeV0::StateSyncCheckpointBootstrap,
        );
        assert!(policy.resume_core);
        assert!(!policy.install_application_authorities);
        assert!(!policy.activate_signer);
    }

    #[test]
    fn native_valid_completion_policy_is_pinned_inert_and_shape_exact() {
        let policy = process_post_recovery_policy_v0(
            PocoNodeProcessBootstrapModeV0::NativeValidCompletionRecoveryOffline,
        );
        assert!(!policy.resume_core);
        assert!(!policy.install_application_authorities);
        assert!(!policy.activate_signer);

        let shapes: &[(ValidAction, &[Kind])] = &[
            (ValidAction::None, &[]),
            (ValidAction::RequestSignature, &[Kind::RequestSignature]),
            (ValidAction::ArmViewTimer, &[Kind::ArmViewTimer]),
            (
                ValidAction::ArmViewTimerThenFinalize,
                &[Kind::ArmViewTimer, Kind::Finalize],
            ),
            (
                ValidAction::RequestTcHighQcSync,
                &[Kind::RequestTcHighQcSync],
            ),
            (
                ValidAction::RequestStandaloneQcSync,
                &[Kind::RequestStandaloneQcSync],
            ),
            (
                ValidAction::ArmViewTimerThenRequestStandaloneQcSync,
                &[Kind::ArmViewTimer, Kind::RequestStandaloneQcSync],
            ),
            (ValidAction::SafetyHaltedConflict, &[Kind::SafetyHalted]),
        ];
        for (action, expected) in shapes {
            assert_eq!(native_valid_action_effect_kinds_v0(*action), *expected);
        }
    }

    #[test]
    fn state_sync_checkpoint_requires_every_virgin_signer_dimension() {
        let virgin = StateSyncSignerShapeV0 {
            external_relation: SignerExternalWatermarkRelationV0::Exact,
            intent_count: 0,
            event_count: 0,
            intent_bytes: 0,
            maximum_safety_revision: None,
            maximum_vote_view: None,
            maximum_timeout_view: None,
            has_tail: false,
            has_pending_intent: false,
        };
        assert!(state_sync_signer_shape_is_virgin_v0(virgin));

        let rejected = [
            StateSyncSignerShapeV0 {
                external_relation: SignerExternalWatermarkRelationV0::LocalOneAhead,
                ..virgin
            },
            StateSyncSignerShapeV0 {
                intent_count: 1,
                ..virgin
            },
            StateSyncSignerShapeV0 {
                event_count: 1,
                ..virgin
            },
            StateSyncSignerShapeV0 {
                intent_bytes: 1,
                ..virgin
            },
            StateSyncSignerShapeV0 {
                maximum_safety_revision: Some(0),
                ..virgin
            },
            StateSyncSignerShapeV0 {
                maximum_vote_view: Some(0),
                ..virgin
            },
            StateSyncSignerShapeV0 {
                maximum_timeout_view: Some(0),
                ..virgin
            },
            StateSyncSignerShapeV0 {
                has_tail: true,
                ..virgin
            },
            StateSyncSignerShapeV0 {
                has_pending_intent: true,
                ..virgin
            },
        ];
        for shape in rejected {
            assert!(!state_sync_signer_shape_is_virgin_v0(shape), "{shape:?}");
        }
    }

    #[test]
    fn state_sync_checkpoint_sanitizer_accepts_only_one_safety_replay_request() {
        assert!(canonical_state_sync_checkpoint_bootstrap_effect_kinds_v0(
            &[Kind::RequestSafetyReplay]
        ));
        for rejected in [
            Vec::new(),
            vec![Kind::ArmViewTimer],
            vec![Kind::RequestSafetyReplay, Kind::RequestSafetyReplay],
            vec![Kind::RequestSafetyReplay, Kind::ArmViewTimer],
        ] {
            assert!(
                !canonical_state_sync_checkpoint_bootstrap_effect_kinds_v0(&rejected),
                "{rejected:?}"
            );
        }
    }

    #[test]
    fn tag3_sanitizer_accepts_only_the_nine_canonical_ordered_shapes() {
        let accepted: &[&[Kind]] = &[
            &[],
            &[Kind::ArmViewTimer],
            &[Kind::RequestSignature],
            &[Kind::ArmViewTimer, Kind::RequestSignature],
            &[Kind::Finalize],
            &[Kind::ArmViewTimer, Kind::Finalize],
            &[Kind::RequestTcHighQcSync],
            &[Kind::RequestStandaloneQcSync],
            &[Kind::ArmViewTimer, Kind::RequestStandaloneQcSync],
        ];
        for shape in accepted {
            assert!(canonical_tag3_effect_kinds_v0(shape), "{shape:?}");
        }
        let rejected: &[&[Kind]] = &[
            &[Kind::RequestSafetyReplay],
            &[Kind::SafetyHalted],
            &[Kind::RequestSignature, Kind::ArmViewTimer],
            &[Kind::Finalize, Kind::ArmViewTimer],
            &[Kind::ArmViewTimer, Kind::RequestTcHighQcSync],
            &[Kind::ArmViewTimer, Kind::ArmViewTimer],
            &[Kind::RequestStandaloneQcSync, Kind::Finalize],
        ];
        for shape in rejected {
            assert!(!canonical_tag3_effect_kinds_v0(shape), "{shape:?}");
        }
    }

    #[test]
    fn process_store_namespaces_must_be_canonical_and_non_overlapping() {
        let root = TempDir::new().expect("create process-host path fixture");
        let safety = root.path().join("safety");
        let signer = root.path().join("signer");
        let application = root.path().join("application");
        for directory in [&safety, &signer, &application] {
            fs::create_dir(directory).expect("create canonical store parent");
        }
        assert!(validate_distinct_store_parents_v0(
            &safety.join("safety.sqlite3"),
            &signer.join("signer.sqlite3"),
            &application.join("application.json"),
        )
        .is_ok());

        let nested = application.join("nested");
        fs::create_dir(&nested).expect("create nested store parent");
        assert!(matches!(
            validate_distinct_store_parents_v0(
                &safety.join("safety.sqlite3"),
                &application.join("signer.sqlite3"),
                &nested.join("application.json"),
            ),
            Err(PocoNodeProcessHostErrorV0::OverlappingStoreNamespaces)
        ));
    }

    #[test]
    fn process_store_parent_identity_is_rechecked_before_owner_activation() {
        let root = TempDir::new().expect("create process-host identity fixture");
        let safety = root.path().join("safety");
        let signer = root.path().join("signer");
        let application = root.path().join("application");
        for directory in [&safety, &signer, &application] {
            fs::create_dir(directory).expect("create canonical store parent");
        }
        let safety_path = safety.join("safety.sqlite3");
        let signer_path = signer.join("signer.sqlite3");
        let application_path = application.join("application.json");
        let (_, safety_identity) =
            canonical_process_store_path_v0(&safety_path).expect("capture safety parent");
        let (_, signer_identity) =
            canonical_process_store_path_v0(&signer_path).expect("capture signer parent");
        let (_, application_identity) =
            canonical_process_store_path_v0(&application_path).expect("capture application parent");
        let identities = ProcessStoreParentIdentitiesV0 {
            safety: safety_identity,
            signer: signer_identity,
            application: application_identity,
        };
        assert!(revalidate_process_store_paths_v0(
            &safety_path,
            &signer_path,
            &application_path,
            identities,
        )
        .is_ok());

        fs::rename(&application, root.path().join("application-old"))
            .expect("replace application parent");
        fs::create_dir(&application).expect("create replacement application parent");
        assert!(matches!(
            revalidate_process_store_paths_v0(
                &safety_path,
                &signer_path,
                &application_path,
                identities,
            ),
            Err(PocoNodeProcessHostErrorV0::StoreParentIdentityChanged)
        ));
    }

    #[test]
    fn process_host_does_not_change_package_activation_truth() {
        const {
            assert!(!crate::PRODUCTION_CANDIDATE_V0);
            assert!(!crate::HOST_IMPLEMENTATION_COMPLETE_V0);
        }
        assert!(crate::production_activation_gate_v0().is_err());
    }
}
