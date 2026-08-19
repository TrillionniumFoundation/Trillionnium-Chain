use std::{
    env,
    ffi::{CString, OsString},
    fs::{self, File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    mem::ManuallyDrop,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

use fs2::FileExt;
use rusqlite::{params, Connection, OpenFlags, OptionalExtension, TransactionBehavior};
use sha2::{Digest, Sha256};
use trnm_consensus_core::{
    decode_safety_state_record_v0_exact, encode_safety_state_record_v0,
    native_finalization_applied_checksum_v0, reconstruct_h1_state_sync_anchor_successor_prefix_v0,
    safety_state_record_config_ref_v0, ApplicationNativeValidDeliveryFactsV0,
    ApplicationSealedNativeValidTransitionV0,
    AuthenticatedGenesisApplicationH1CompletionPersistenceV0,
    AuthenticatedGenesisApplicationH1ObligationPersistenceV0,
    AuthenticatedGenesisApplicationH1ObligationTakeoverActivationBundleV0,
    AuthenticatedGenesisApplicationH1ObligationTakeoverChallengeV0,
    AuthenticatedGenesisApplicationH1ObligationTakeoverReboundActivationV0,
    AuthenticatedGenesisApplicationH1ObligationTakeoverSafetyHeadFactsV0,
    AuthenticatedGenesisApplicationH1ObligationTakeoverSafetyRebindRegistrarV0,
    AuthenticatedGenesisApplicationH1ObligationTakeoverSafetyReconcilerV0,
    AuthenticatedGenesisApplicationH1ObligationTakeoverSessionV0,
    AuthenticatedGenesisApplicationH1OfflineSafetyPersistenceBindingV0,
    AuthenticatedGenesisApplicationH1StableNativeValidRecoveryChallengeV0,
    AuthenticatedGenesisApplicationH1StableNativeValidSafetyHeadFactsV0, BarrierId, Core,
    CoreConfig, DurableFinalizationV0, NativeFinalizationAppliedPersistenceV0,
    NativeFinalizationAppliedPostAckActionV0, NativeFinalizationAppliedRecoveryTransitionV0,
    NativeValidPostAckActionV0, PayloadTerminalResult, PayloadValidationParentProvenanceV0,
    PayloadValidationRouteV0, PreparedAuthenticatedGenesisApplicationBootstrapV0,
    PreparedH1StateSyncBootstrapV0, SafetyState, SafetyStatePersistenceBindingV0,
    SafetyStatePersistenceV0, SafetyStateRecordContextV0, SafetyStateRecordLimitsV0, SignIntent,
    StateSyncAnchorSuccessorPhaseV0, StateSyncAnchorSuccessorRecoveryChallengeV0,
    SAFETY_STATE_RECORD_CODEC_VERSION_V0, SAFETY_STATE_RECORD_SAFETY_SCHEMA_VERSION_V0,
};
use trnm_consensus_types::SignatureVerifier;

use crate::transition_context::validate_transition_context_record_identity_v0;
use crate::{
    decode_transition_context_v0_exact, encode_transition_context_v0,
    error::{SafetyStoreConflictV0, SafetyStoreErrorV0},
    hash::hash_domain,
    schema::{
        validate_canonical_schema, JOURNAL_SAFETY_SCHEMA_VERSION_V6, JOURNAL_SCHEMA_SQL_V6,
        JOURNAL_SCHEMA_VERSION_V6, MAXIMUM_SQL_STATE_RECORD_BYTES,
        MAXIMUM_TRANSITION_CONTEXT_BYTES_V0, TRANSITION_CONTEXT_CODEC_V0,
    },
    state_sync_anchor_checksum_v0, transition_context_checksum_v0,
    validate_transition_context_against_state_v0,
    AuthenticatedGenesisApplicationBootstrapTransitionV0, NativeDeterministicInvalidTransitionV0,
    NativeFinalizationAppliedTransitionV0, NativeValidTransitionV0, SafetyTransitionContextV0,
    StateSyncAnchorOrdinaryPromotionTransitionV0, StateSyncCheckpointBootstrapTransitionV0,
};

const LOCK_MAGIC_V0: &[u8; 8] = b"TRNMSLK\0";
const LOCK_VERSION_V0: u16 = 0;
// Sequences alternate between two independently checksummed slots placed in
// separate 4 KiB regions. This prevents one region rewrite from directly
// overlapping both payloads; it is not a claim about every storage device's
// atomic-write geometry. A Stable
// slot names one exact database head. A HeadIntent names both the last Stable
// head and its one-revision successor, so recovery can distinguish a commit
// that did not apply from one that applied before the final Stable rewrite.
// A third disjoint 4 KiB region holds a terminal halt latch without ever
// overwriting either recoverable head payload.
const LOCK_SLOT_BYTES_V0: usize = 184;
const LOCK_SLOT_REGION_BYTES_V0: usize = 4096;
const LOCK_SLOT_COUNT_V0: usize = 2;
const LOCK_HALT_LATCH_REGION_V0: usize = LOCK_SLOT_COUNT_V0;
const LOCK_FILE_REGION_COUNT_V0: usize = LOCK_SLOT_COUNT_V0 + 1;
const LOCK_FILE_BYTES_V0: usize = LOCK_SLOT_REGION_BYTES_V0 * LOCK_FILE_REGION_COUNT_V0;
const LOCK_KIND_STABLE_V0: u8 = 0;
const LOCK_KIND_HEAD_INTENT_V0: u8 = 1;
const LOCK_SLOT_CHECKSUM_OFFSET_V0: usize = 152;
const HALT_LATCH_MAGIC_V0: &[u8; 8] = b"TRNMSHL\0";
const HALT_LATCH_VERSION_V0: u16 = 0;
const HALT_LATCH_BYTES_V0: usize = 224;
const HALT_LATCH_CHECKSUM_OFFSET_V0: usize = 192;
const LOCK_CHECKSUM_DOMAIN_V0: &str = "trnm.consensus-safety-store.lock.v0";
const INITIALIZATION_INTENT_MAGIC_V0: &[u8; 8] = b"TRNMSIN\0";
const INITIALIZATION_INTENT_VERSION_V0: u16 = 0;
const INITIALIZATION_INTENT_KIND_H1_STATE_SYNC_V0: u8 = 4;
const INITIALIZATION_INTENT_KIND_AUTHENTICATED_GENESIS_APPLICATION_V0: u8 = 5;
const INITIALIZATION_INTENT_BYTES_V0: usize = 256;
const INITIALIZATION_INTENT_CHECKSUM_OFFSET_V0: usize = 224;
const INITIALIZATION_INTENT_CHECKSUM_DOMAIN_V0: &str =
    "trnm.consensus-safety-store.initialization-intent.v0";
const METADATA_DOMAIN_V0: &str = "trnm.consensus-safety-store.metadata.v0";
const CHAIN_DOMAIN_V0: &str = "trnm.consensus-safety-store.record-chain.v0";
const HEAD_DOMAIN_V0: &str = "trnm.consensus-safety-store.head.v0";
const HALT_DOMAIN_V0: &str = "trnm.consensus-safety-store.halt.v0";
const DATABASE_OVERHEAD_BYTES_V0: usize = 16 * 1024 * 1024;
const DEFAULT_BUSY_TIMEOUT: Duration = Duration::from_secs(5);

/// Owned configuration and resource boundary for one safety-state journal.
#[derive(Debug, Clone)]
pub struct SafetyStateStoreProfileV0 {
    core_config: CoreConfig,
    verifier_profile_ref: [u8; 32],
    record_limits: SafetyStateRecordLimitsV0,
    maximum_database_bytes: usize,
}

impl SafetyStateStoreProfileV0 {
    pub fn new(
        core_config: CoreConfig,
        verifier_profile_ref: [u8; 32],
        record_limits: SafetyStateRecordLimitsV0,
        maximum_database_bytes: usize,
    ) -> Result<Self, SafetyStoreErrorV0> {
        if SAFETY_STATE_RECORD_SAFETY_SCHEMA_VERSION_V0 != JOURNAL_SAFETY_SCHEMA_VERSION_V6 {
            return Err(SafetyStoreErrorV0::InvalidProfile(
                "Core safety schema is incompatible with journal v6",
            ));
        }
        SafetyStateRecordContextV0::new(&core_config, verifier_profile_ref, record_limits)
            .map_err(|error| SafetyStoreErrorV0::record("profile capacity preflight", error))?;
        if verifier_profile_ref == [0; 32]
            || record_limits.maximum_record_bytes() > MAXIMUM_SQL_STATE_RECORD_BYTES
        {
            return Err(SafetyStoreErrorV0::InvalidProfile(
                "verifier profile or SQL record bound",
            ));
        }
        let retained_bytes = record_limits
            .maximum_record_bytes()
            .checked_mul(2)
            .and_then(|value| value.checked_add(2 * MAXIMUM_TRANSITION_CONTEXT_BYTES_V0))
            .and_then(|value| value.checked_add(DATABASE_OVERHEAD_BYTES_V0))
            .ok_or(SafetyStoreErrorV0::InvalidProfile(
                "database budget overflow",
            ))?;
        if maximum_database_bytes < retained_bytes || maximum_database_bytes > i64::MAX as usize {
            return Err(SafetyStoreErrorV0::InvalidProfile(
                "database budget cannot retain two records and WAL overhead",
            ));
        }
        Ok(Self {
            core_config,
            verifier_profile_ref,
            record_limits,
            maximum_database_bytes,
        })
    }

    pub const fn core_config(&self) -> &CoreConfig {
        &self.core_config
    }

    pub const fn verifier_profile_ref(&self) -> [u8; 32] {
        self.verifier_profile_ref
    }

    pub const fn record_limits(&self) -> SafetyStateRecordLimitsV0 {
        self.record_limits
    }

    pub const fn maximum_database_bytes(&self) -> usize {
        self.maximum_database_bytes
    }

    fn record_context(&self) -> Result<SafetyStateRecordContextV0<'_>, SafetyStoreErrorV0> {
        SafetyStateRecordContextV0::new(
            &self.core_config,
            self.verifier_profile_ref,
            self.record_limits,
        )
        .map_err(|error| SafetyStoreErrorV0::record("construct record context", error))
    }

    fn core_config_ref(&self) -> Result<[u8; 32], SafetyStoreErrorV0> {
        safety_state_record_config_ref_v0(&self.record_context()?)
            .map_err(|error| SafetyStoreErrorV0::record("derive Core config reference", error))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SafetyPersistDispositionV0 {
    Inserted,
    Existing,
    ConfirmedAfterCommitError,
}

/// Exact outcome of the fresh-only h1 initialization/resume protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StateSyncCheckpointInitializationDispositionV0 {
    /// This call durably created the initialization intent and completed the
    /// exact revision-zero tag-4 journal.
    Initialized,
    /// A prior call durably wrote the exact intent but had not created a
    /// database whose committed contents were visible.
    ResumedBeforeDatabaseCommit,
    /// The exact revision-zero tag-4 database was already committed, but the
    /// Stable watermark and/or marker retirement had not completed.
    ResumedAfterDatabaseCommit,
    /// The marker was already retired and the exact completed journal was
    /// opened without changing its initialization state.
    Existing,
}

/// Durable initialization-intent discriminator. The numeric values are the
/// corresponding canonical transition-context tags and are frozen in the
/// version-zero 256-byte intent format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SafetyBootstrapInitializationKindV0 {
    StateSyncCheckpoint = INITIALIZATION_INTENT_KIND_H1_STATE_SYNC_V0,
    AuthenticatedGenesisApplication =
        INITIALIZATION_INTENT_KIND_AUTHENTICATED_GENESIS_APPLICATION_V0,
}

impl SafetyBootstrapInitializationKindV0 {
    const fn from_byte_v0(value: u8) -> Option<Self> {
        match value {
            INITIALIZATION_INTENT_KIND_H1_STATE_SYNC_V0 => Some(Self::StateSyncCheckpoint),
            INITIALIZATION_INTENT_KIND_AUTHENTICATED_GENESIS_APPLICATION_V0 => {
                Some(Self::AuthenticatedGenesisApplication)
            }
            _ => None,
        }
    }

    const fn tag_v0(self) -> u8 {
        self as u8
    }
}

/// Exact outcome of authenticated-genesis application journal commissioning.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthenticatedGenesisApplicationInitializationDispositionV0 {
    Initialized,
    ResumedBeforeDatabaseCommit,
    ResumedAfterDatabaseCommit,
    Existing,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BootstrapInitializationDispositionV0 {
    Initialized,
    ResumedBeforeDatabaseCommit,
    ResumedAfterDatabaseCommit,
    Existing,
}

impl From<BootstrapInitializationDispositionV0> for StateSyncCheckpointInitializationDispositionV0 {
    fn from(value: BootstrapInitializationDispositionV0) -> Self {
        match value {
            BootstrapInitializationDispositionV0::Initialized => Self::Initialized,
            BootstrapInitializationDispositionV0::ResumedBeforeDatabaseCommit => {
                Self::ResumedBeforeDatabaseCommit
            }
            BootstrapInitializationDispositionV0::ResumedAfterDatabaseCommit => {
                Self::ResumedAfterDatabaseCommit
            }
            BootstrapInitializationDispositionV0::Existing => Self::Existing,
        }
    }
}

impl From<BootstrapInitializationDispositionV0>
    for AuthenticatedGenesisApplicationInitializationDispositionV0
{
    fn from(value: BootstrapInitializationDispositionV0) -> Self {
        match value {
            BootstrapInitializationDispositionV0::Initialized => Self::Initialized,
            BootstrapInitializationDispositionV0::ResumedBeforeDatabaseCommit => {
                Self::ResumedBeforeDatabaseCommit
            }
            BootstrapInitializationDispositionV0::ResumedAfterDatabaseCommit => {
                Self::ResumedAfterDatabaseCommit
            }
            BootstrapInitializationDispositionV0::Existing => Self::Existing,
        }
    }
}

/// Non-forgeable, inert projection of one exact Core-issued native Valid
/// persistence request under this already-open journal's profile.
///
/// Construction validates the process-local Core binding and canonical Core
/// state-record codec without beginning a SQLite transaction or creating any
/// filesystem namespace.  The journal/profile identities let the same-process
/// delivery typestate reject a later readback from a different SafetyStore.
#[derive(Debug)]
#[must_use = "native Valid preflight facts must remain joined to the accepted Core owner"]
pub struct NativeValidSafetyStatePreflightV0 {
    journal_id: [u8; 32],
    verifier_profile_ref: [u8; 32],
    revision: u64,
    state_record_checksum: [u8; 32],
    post_ack_action: NativeValidPostAckActionV0,
}

impl NativeValidSafetyStatePreflightV0 {
    pub const fn journal_id_v0(&self) -> [u8; 32] {
        self.journal_id
    }

    pub const fn verifier_profile_ref_v0(&self) -> [u8; 32] {
        self.verifier_profile_ref
    }

    pub const fn revision_v0(&self) -> u64 {
        self.revision
    }

    pub const fn state_record_checksum_v0(&self) -> [u8; 32] {
        self.state_record_checksum
    }

    pub const fn post_ack_action_v0(&self) -> NativeValidPostAckActionV0 {
        self.post_ack_action
    }
}

/// Non-forgeable preflight projection of one bound Core finalization-applied
/// persistence request under this journal's exact profile.
#[derive(Debug)]
#[must_use = "native finalization-applied preflight must remain joined to the accepted Core owner"]
pub struct NativeFinalizationAppliedSafetyStatePreflightV0 {
    journal_id: [u8; 32],
    verifier_profile_ref: [u8; 32],
    revision: u64,
    state_record_checksum: [u8; 32],
    manifest: NativeFinalizationAppliedPersistenceV0,
}

impl NativeFinalizationAppliedSafetyStatePreflightV0 {
    pub const fn journal_id_v0(&self) -> [u8; 32] {
        self.journal_id
    }

    pub const fn verifier_profile_ref_v0(&self) -> [u8; 32] {
        self.verifier_profile_ref
    }

    pub const fn revision_v0(&self) -> u64 {
        self.revision
    }

    pub const fn state_record_checksum_v0(&self) -> [u8; 32] {
        self.state_record_checksum
    }

    pub const fn manifest_v0(&self) -> &NativeFinalizationAppliedPersistenceV0 {
        &self.manifest
    }

    /// Projects the only canonical tag-3 context accepted for this preflight.
    pub fn transition_context_v0(&self) -> Result<SafetyTransitionContextV0, SafetyStoreErrorV0> {
        let readback = self.manifest.application_store_readback_v0();
        Ok(SafetyTransitionContextV0::native_finalization_applied(
            NativeFinalizationAppliedTransitionV0::new(
                readback.source_route(),
                readback.source_validation_id(),
                readback.ordinal(),
                readback.application_host_config_ref(),
                readback.finalization_checksum(),
                readback.prior_head_checksum(),
                readback.new_head_checksum(),
                readback.source_artifact_checksum(),
                readback.accepted_source_checksum(),
                readback.applied_job_row_checksum(),
                readback.receipt_row_checksum(),
                self.manifest.post_ack_action_v0().code(),
                self.revision,
            )?,
        ))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExactSafetyStateConfirmationV0 {
    Exact,
    Absent,
    Conflict,
}

/// A semantically checked but inert journal head.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveredSafetyStateV0 {
    state: SafetyState,
    transition_context: SafetyTransitionContextV0,
    state_record_checksum: [u8; 32],
    transition_context_checksum: [u8; 32],
    chain_checksum: [u8; 32],
}

impl RecoveredSafetyStateV0 {
    pub const fn state(&self) -> &SafetyState {
        &self.state
    }

    pub const fn transition_context(&self) -> &SafetyTransitionContextV0 {
        &self.transition_context
    }

    pub const fn revision(&self) -> u64 {
        self.state.revision()
    }

    pub const fn state_record_checksum(&self) -> [u8; 32] {
        self.state_record_checksum
    }

    pub const fn transition_context_checksum(&self) -> [u8; 32] {
        self.transition_context_checksum
    }

    pub const fn chain_checksum(&self) -> [u8; 32] {
        self.chain_checksum
    }

    pub fn requires_authenticated_obligation_replay(&self) -> bool {
        !self.state.payload_validation_obligations().is_empty()
    }
}

/// One-shot projection of the current fully authenticated SafetyStore head for
/// a future external node-checkpoint join.
///
/// The capability intentionally implements neither `Clone` nor `Copy`, has no
/// public constructor, and has no serde representation. It can be produced
/// only by [`SqliteSafetyStateStoreV0::confirm_node_checkpoint_head_exact_v0`]
/// after the complete authenticated-head validation path succeeds and the
/// decoded state equals the caller-held exact [`SafetyState`]. The projected
/// values are comparison facts only: they mint no Core, persistence, signing,
/// application, recovery, or activation authority.
///
/// ```compile_fail
/// use trnm_consensus_safety_store::ConfirmedSafetyNodeCheckpointFactsV0;
/// fn requires_clone<T: Clone>() {}
/// requires_clone::<ConfirmedSafetyNodeCheckpointFactsV0>();
/// ```
///
/// ```compile_fail
/// use trnm_consensus_safety_store::{
///     ConfirmedSafetyNodeCheckpointFactsV0, RecoveredSafetyStateV0,
/// };
/// fn forge(head: RecoveredSafetyStateV0) -> ConfirmedSafetyNodeCheckpointFactsV0 {
///     ConfirmedSafetyNodeCheckpointFactsV0 {
///         journal_id: [1; 32],
///         verifier_profile_ref: [2; 32],
///         core_config_ref: [3; 32],
///         head,
///     }
/// }
/// ```
#[derive(Debug)]
#[must_use = "confirmed Safety facts must be consumed by the trusted node-checkpoint join"]
pub struct ConfirmedSafetyNodeCheckpointFactsV0 {
    journal_id: [u8; 32],
    verifier_profile_ref: [u8; 32],
    core_config_ref: [u8; 32],
    head: RecoveredSafetyStateV0,
    owner_affinity: Arc<()>,
}

impl ConfirmedSafetyNodeCheckpointFactsV0 {
    fn from_authenticated_head(
        journal_id: [u8; 32],
        verifier_profile_ref: [u8; 32],
        core_config_ref: [u8; 32],
        head: RecoveredSafetyStateV0,
        owner_affinity: Arc<()>,
    ) -> Self {
        Self {
            journal_id,
            verifier_profile_ref,
            core_config_ref,
            head,
            owner_affinity,
        }
    }

    /// Confirms that these detached facts came from this exact still-live
    /// owner and that its canonical namespace remains at `expected_path`.
    pub fn belongs_to_store_at_path_v0<V: SignatureVerifier>(
        &self,
        store: &SqliteSafetyStateStoreV0<V>,
        expected_path: &Path,
    ) -> bool {
        Arc::ptr_eq(&self.owner_affinity, &store.owner_affinity)
            && store.path() == expected_path
            && store.ensure_file_identity().is_ok()
    }

    /// Exact decoded SafetyState retained from the same authenticated-head
    /// validation which produced every projected checkpoint fact.
    pub const fn state_v0(&self) -> &SafetyState {
        self.head.state()
    }

    pub const fn journal_id_v0(&self) -> [u8; 32] {
        self.journal_id
    }

    pub const fn verifier_profile_ref_v0(&self) -> [u8; 32] {
        self.verifier_profile_ref
    }

    /// Exact record-context configuration reference authenticated by the
    /// SafetyStore metadata and every retained state record.
    pub const fn core_config_ref_v0(&self) -> [u8; 32] {
        self.core_config_ref
    }

    pub const fn revision_v0(&self) -> u64 {
        self.head.revision()
    }

    pub const fn state_record_checksum_v0(&self) -> [u8; 32] {
        self.head.state_record_checksum()
    }

    pub const fn transition_context_checksum_v0(&self) -> [u8; 32] {
        self.head.transition_context_checksum()
    }

    pub const fn chain_checksum_v0(&self) -> [u8; 32] {
        self.head.chain_checksum()
    }
}

/// Non-cloneable proof that the fully authenticated journal head is the exact
/// revision-zero tag-4 state-sync bootstrap row.
///
/// This capability freezes journal/profile identity and complete state/context
/// readback. It remains inert comparison material: it does not activate Core,
/// attest an ApplicationStore snapshot, or prove that a signer namespace is
/// virgin.
#[derive(Debug)]
#[must_use = "the confirmed state-sync bootstrap head must be joined to App and signer attestations"]
pub struct ConfirmedStateSyncCheckpointBootstrapHeadV0 {
    journal_id: [u8; 32],
    verifier_profile_ref: [u8; 32],
    head: RecoveredSafetyStateV0,
}

impl ConfirmedStateSyncCheckpointBootstrapHeadV0 {
    fn from_authenticated_head(
        journal_id: [u8; 32],
        verifier_profile_ref: [u8; 32],
        head: RecoveredSafetyStateV0,
    ) -> Result<Self, SafetyStoreErrorV0> {
        if head
            .transition_context()
            .state_sync_checkpoint_bootstrap_transition()
            .is_none()
        {
            return Err(
                SafetyStoreErrorV0::MissingStateSyncCheckpointBootstrapTransition {
                    revision: head.revision(),
                },
            );
        }
        Ok(Self {
            journal_id,
            verifier_profile_ref,
            head,
        })
    }

    pub const fn journal_id_v0(&self) -> [u8; 32] {
        self.journal_id
    }

    pub const fn verifier_profile_ref_v0(&self) -> [u8; 32] {
        self.verifier_profile_ref
    }

    pub const fn state(&self) -> &SafetyState {
        self.head.state()
    }

    pub const fn transition_context(&self) -> &SafetyTransitionContextV0 {
        self.head.transition_context()
    }

    pub fn transition(&self) -> &StateSyncCheckpointBootstrapTransitionV0 {
        self.head
            .transition_context()
            .state_sync_checkpoint_bootstrap_transition()
            .expect("private constructor requires a state-sync bootstrap transition")
    }

    pub const fn revision(&self) -> u64 {
        self.head.revision()
    }

    pub const fn state_record_checksum(&self) -> [u8; 32] {
        self.head.state_record_checksum()
    }

    pub const fn chain_checksum(&self) -> [u8; 32] {
        self.head.chain_checksum()
    }
}

/// One-shot proof that this still-live store owns the exact revision-zero
/// tag-5 authenticated-genesis application bootstrap head.
///
/// The capability implements neither `Clone` nor `Copy`, has no public
/// constructor, and exposes comparison facts only. It grants no Core input,
/// application, signer, timer, network, finalization, or production authority.
///
/// ```compile_fail
/// use trnm_consensus_safety_store::ConfirmedAuthenticatedGenesisApplicationBootstrapHeadV0;
/// fn requires_clone<T: Clone>() {}
/// requires_clone::<ConfirmedAuthenticatedGenesisApplicationBootstrapHeadV0>();
/// ```
#[derive(Debug)]
#[must_use = "the confirmed authenticated-genesis head must be consumed by one live-owner join"]
pub struct ConfirmedAuthenticatedGenesisApplicationBootstrapHeadV0 {
    database_path: PathBuf,
    journal_id: [u8; 32],
    verifier_profile_ref: [u8; 32],
    core_config_ref: [u8; 32],
    head: RecoveredSafetyStateV0,
    owner_affinity: Arc<()>,
}

impl ConfirmedAuthenticatedGenesisApplicationBootstrapHeadV0 {
    fn from_authenticated_head(
        database_path: PathBuf,
        journal_id: [u8; 32],
        verifier_profile_ref: [u8; 32],
        core_config_ref: [u8; 32],
        head: RecoveredSafetyStateV0,
        owner_affinity: Arc<()>,
    ) -> Result<Self, SafetyStoreErrorV0> {
        if head
            .transition_context()
            .authenticated_genesis_application_bootstrap_transition()
            .is_none()
        {
            return Err(
                SafetyStoreErrorV0::MissingAuthenticatedGenesisApplicationBootstrapTransition {
                    revision: head.revision(),
                },
            );
        }
        Ok(Self {
            database_path,
            journal_id,
            verifier_profile_ref,
            core_config_ref,
            head,
            owner_affinity,
        })
    }

    pub fn belongs_to_store_at_path_v0<V: SignatureVerifier>(
        &self,
        store: &SqliteSafetyStateStoreV0<V>,
        expected_path: &Path,
    ) -> bool {
        Arc::ptr_eq(&self.owner_affinity, &store.owner_affinity)
            && self.database_path.as_path() == expected_path
            && store.path() == expected_path
            && store.ensure_file_identity().is_ok()
    }

    pub fn database_path_v0(&self) -> &Path {
        self.database_path.as_path()
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

    pub const fn state_v0(&self) -> &SafetyState {
        self.head.state()
    }

    pub const fn transition_context_v0(&self) -> &SafetyTransitionContextV0 {
        self.head.transition_context()
    }

    pub fn transition_v0(&self) -> &AuthenticatedGenesisApplicationBootstrapTransitionV0 {
        self.head
            .transition_context()
            .authenticated_genesis_application_bootstrap_transition()
            .expect("private constructor requires an authenticated-genesis transition")
    }

    pub const fn revision_v0(&self) -> u64 {
        self.head.revision()
    }

    pub const fn state_record_checksum_v0(&self) -> [u8; 32] {
        self.head.state_record_checksum()
    }

    pub const fn transition_context_checksum_v0(&self) -> [u8; 32] {
        self.head.transition_context_checksum()
    }

    pub const fn chain_checksum_v0(&self) -> [u8; 32] {
        self.head.chain_checksum()
    }

    pub fn head_checksum_v0(&self) -> [u8; 32] {
        head_checksum(
            self.journal_id,
            self.head.revision(),
            self.head.chain_checksum(),
            0,
        )
    }
}

/// Non-forgeable proof that one fully authenticated journal head carries the
/// native deterministic-invalid transition context returned with that exact
/// state revision.
///
/// This value is deliberately non-`Clone` and has no public constructor or
/// parts conversion. It can be created only by [`SqliteSafetyStateStoreV0`]
/// after the complete `head()` validation path succeeds. The capability proves
/// exact SafetyStore readback and freezes the issuing journal/profile identity;
/// it does not by itself grant application, callback, or Core authority. The
/// journal identifier distinguishes an unrelated freshly initialized store,
/// but copying or rolling back the complete journal namespace also copies that
/// identifier and remains outside this store's protection boundary.
#[derive(Debug)]
#[must_use = "the confirmed native-invalid head must remain paired with its exact state/context"]
pub struct ConfirmedNativeDeterministicInvalidHeadV0 {
    journal_id: [u8; 32],
    verifier_profile_ref: [u8; 32],
    head: RecoveredSafetyStateV0,
}

impl ConfirmedNativeDeterministicInvalidHeadV0 {
    fn from_authenticated_head(
        journal_id: [u8; 32],
        verifier_profile_ref: [u8; 32],
        head: RecoveredSafetyStateV0,
    ) -> Result<Self, SafetyStoreErrorV0> {
        if head.transition_context.native_invalid().is_none() {
            return Err(
                SafetyStoreErrorV0::MissingNativeDeterministicInvalidTransition {
                    revision: head.revision(),
                },
            );
        }
        Ok(Self {
            journal_id,
            verifier_profile_ref,
            head,
        })
    }

    /// Identifier frozen from the issuing store, never from caller-supplied
    /// expected state or transition values.
    pub const fn journal_id_v0(&self) -> [u8; 32] {
        self.journal_id
    }

    /// Verifier/profile identity frozen from the issuing store profile.
    pub const fn verifier_profile_ref_v0(&self) -> [u8; 32] {
        self.verifier_profile_ref
    }

    pub const fn state(&self) -> &SafetyState {
        self.head.state()
    }

    pub const fn transition_context(&self) -> &SafetyTransitionContextV0 {
        self.head.transition_context()
    }

    pub fn transition(&self) -> &NativeDeterministicInvalidTransitionV0 {
        self.head
            .transition_context()
            .native_invalid()
            .expect("private constructor requires a native deterministic-invalid transition")
    }

    pub const fn revision(&self) -> u64 {
        self.head.revision()
    }

    pub const fn state_record_checksum(&self) -> [u8; 32] {
        self.head.state_record_checksum()
    }

    pub const fn chain_checksum(&self) -> [u8; 32] {
        self.head.chain_checksum()
    }
}

/// Non-forgeable proof that one fully authenticated journal head carries the
/// native Valid transition context returned with that exact state revision.
///
/// This value is deliberately non-`Clone` and has no public constructor or
/// parts conversion. It can be created only by [`SqliteSafetyStateStoreV0`]
/// after the complete `head()` validation path succeeds. The capability proves
/// exact SafetyStore readback and freezes the issuing journal/profile identity;
/// it does not recreate a request permit, application seal, Core callback,
/// StorageAck, or deferred effect. The journal identifier distinguishes an
/// unrelated freshly initialized store, but copying or rolling back the whole
/// journal namespace also copies that identifier and remains outside this
/// store's protection boundary.
///
/// ```compile_fail
/// use trnm_consensus_safety_store::ConfirmedNativeValidHeadV0;
/// fn requires_clone<T: Clone>() {}
/// requires_clone::<ConfirmedNativeValidHeadV0>();
/// ```
///
/// ```compile_fail
/// use trnm_consensus_safety_store::{
///     ConfirmedNativeValidHeadV0, RecoveredSafetyStateV0,
/// };
/// fn forge(head: RecoveredSafetyStateV0) -> ConfirmedNativeValidHeadV0 {
///     ConfirmedNativeValidHeadV0 {
///         journal_id: [1; 32],
///         verifier_profile_ref: [2; 32],
///         head,
///     }
/// }
/// ```
#[derive(Debug)]
#[must_use = "the confirmed native Valid head must remain paired with its exact state/context"]
pub struct ConfirmedNativeValidHeadV0 {
    journal_id: [u8; 32],
    verifier_profile_ref: [u8; 32],
    head: RecoveredSafetyStateV0,
    owner_affinity: Arc<()>,
}

/// Dedicated inert tag-5/rev1 readback used only to construct Core's
/// authenticated-genesis h1 obligation-takeover challenge. It grants no
/// persistence, acknowledgement, request, application, or activation
/// authority and cannot be minted through the generic open path.
#[derive(Debug)]
#[must_use = "the h1 obligation lineage readback must enter the dedicated Core takeover boundary"]
pub struct AuthenticatedGenesisApplicationH1ObligationLineageReadbackV0 {
    revision_zero: SafetyState,
    revision_one: SafetyState,
}

impl AuthenticatedGenesisApplicationH1ObligationLineageReadbackV0 {
    pub fn into_core_states_v0(self) -> (SafetyState, SafetyState) {
        (self.revision_zero, self.revision_one)
    }
}

/// One-shot proof that a live SafetyStore owns the exact tag-5 -> Ordinary
/// revision-one lineage joined by Core's authenticated-genesis h1 obligation
/// takeover challenge. It deliberately implements neither `Clone` nor `Copy`
/// and exposes no persistence binding, Core, acknowledgement, or request.
///
/// ```compile_fail
/// use trnm_consensus_safety_store::
///     ConfirmedAuthenticatedGenesisApplicationH1ObligationHeadV0;
/// fn requires_clone<T: Clone>() {}
/// requires_clone::<ConfirmedAuthenticatedGenesisApplicationH1ObligationHeadV0>();
/// ```
#[derive(Debug)]
#[must_use = "the confirmed h1 obligation head must be consumed by one takeover join"]
pub struct ConfirmedAuthenticatedGenesisApplicationH1ObligationHeadV0 {
    database_path: PathBuf,
    safety_head_facts: AuthenticatedGenesisApplicationH1ObligationTakeoverSafetyHeadFactsV0,
    state: SafetyState,
    transition_context: SafetyTransitionContextV0,
    live_revision: u64,
    live_chain_checksum: [u8; 32],
    live_floor: u64,
    lock_watermark: LockWatermarkV0,
    owner_affinity: Arc<()>,
}

impl ConfirmedAuthenticatedGenesisApplicationH1ObligationHeadV0 {
    pub fn belongs_to_store_at_path_v0<V: SignatureVerifier>(
        &self,
        store: &SqliteSafetyStateStoreV0<V>,
        expected_path: &Path,
    ) -> bool {
        if !Arc::ptr_eq(&self.owner_affinity, &store.owner_affinity)
            || self.database_path.as_path() != expected_path
            || store.path() != expected_path
            || store.journal_id != self.safety_head_facts.journal_id_v0()
            || store.observed_head_revision != self.live_revision
            || store.observed_head_chain_checksum != self.live_chain_checksum
            || store.observed_lock_watermark != self.lock_watermark
            || store.ensure_file_identity().is_err()
        {
            return false;
        }
        matches!(
            read_head(&store.connection, store.journal_id),
            Ok((revision, chain_checksum, floor))
                if revision == self.live_revision
                    && chain_checksum == self.live_chain_checksum
                    && floor == self.live_floor
        )
    }

    pub const fn safety_head_facts_v0(
        &self,
    ) -> &AuthenticatedGenesisApplicationH1ObligationTakeoverSafetyHeadFactsV0 {
        &self.safety_head_facts
    }

    pub const fn state_v0(&self) -> &SafetyState {
        &self.state
    }

    pub const fn transition_context_v0(&self) -> &SafetyTransitionContextV0 {
        &self.transition_context
    }

    pub const fn journal_id_v0(&self) -> [u8; 32] {
        self.safety_head_facts.journal_id_v0()
    }

    pub const fn verifier_profile_ref_v0(&self) -> [u8; 32] {
        self.safety_head_facts.verifier_profile_ref_v0()
    }

    pub const fn core_config_ref_v0(&self) -> [u8; 32] {
        self.safety_head_facts.core_config_ref_v0()
    }

    pub const fn state_record_checksum_v0(&self) -> [u8; 32] {
        self.safety_head_facts
            .revision_one_state_record_checksum_v0()
    }

    pub const fn chain_checksum_v0(&self) -> [u8; 32] {
        self.safety_head_facts.revision_one_chain_checksum_v0()
    }
}

/// Dedicated inert rev1/rev2 readback used only to construct Core's stable
/// authenticated-genesis h1 recovery challenge.  It grants no persistence or
/// activation authority and cannot be minted through the generic open path.
#[derive(Debug)]
#[must_use = "the stable h1 lineage readback must enter the dedicated Core recovery boundary"]
pub struct AuthenticatedGenesisApplicationH1StableNativeValidLineageReadbackV0 {
    revision_one: SafetyState,
    revision_two: SafetyState,
}

impl AuthenticatedGenesisApplicationH1StableNativeValidLineageReadbackV0 {
    pub fn into_core_states_v0(self) -> (SafetyState, SafetyState) {
        (self.revision_one, self.revision_two)
    }
}

/// Exact configured-parent h1 cut selected by one existing-only open.
///
/// Classification is performed from one fully authenticated head/retained
/// record snapshot.  Callers therefore never infer the durable cut by trying
/// one specialized opener and branching on its error.  Neither variant grants
/// a Core acknowledgement, validation request, persistence binding, callback,
/// or application authority.  In particular the stable variant proves the
/// exact retained rev1 -> rev2 cut under the configured authenticated parent;
/// the later Core stable challenge and live capability join still reconstruct
/// and authenticate the already-pruned tag-5 record.
#[derive(Debug)]
#[must_use = "the typed h1 cut must enter its dedicated obligation or stable recovery owner"]
pub enum AuthenticatedGenesisApplicationH1ExistingCutV0 {
    ObligationRev1(AuthenticatedGenesisApplicationH1ObligationLineageReadbackV0),
    StableNativeValidRev2(AuthenticatedGenesisApplicationH1StableNativeValidLineageReadbackV0),
}

/// One-shot proof that a live SafetyStore owns the exact tag-5 -> Ordinary ->
/// tag-2 lineage joined by Core's authenticated-genesis h1 recovery challenge.
/// It deliberately implements neither `Clone` nor `Copy` and exposes no store
/// handle, persistence binding, Core, or generic activation surface.
///
/// ```compile_fail
/// use trnm_consensus_safety_store::
///     ConfirmedAuthenticatedGenesisApplicationH1StableNativeValidHeadV0;
/// fn requires_clone<T: Clone>() {}
/// requires_clone::<ConfirmedAuthenticatedGenesisApplicationH1StableNativeValidHeadV0>();
/// ```
#[derive(Debug)]
#[must_use = "the confirmed stable h1 head must be consumed by one cross-store join"]
pub struct ConfirmedAuthenticatedGenesisApplicationH1StableNativeValidHeadV0 {
    database_path: PathBuf,
    safety_head_facts: AuthenticatedGenesisApplicationH1StableNativeValidSafetyHeadFactsV0,
    state: SafetyState,
    transition_context: SafetyTransitionContextV0,
    owner_affinity: Arc<()>,
}

impl ConfirmedAuthenticatedGenesisApplicationH1StableNativeValidHeadV0 {
    pub fn belongs_to_store_at_path_v0<V: SignatureVerifier>(
        &self,
        store: &SqliteSafetyStateStoreV0<V>,
        expected_path: &Path,
    ) -> bool {
        Arc::ptr_eq(&self.owner_affinity, &store.owner_affinity)
            && self.database_path.as_path() == expected_path
            && store.path() == expected_path
            && store.ensure_file_identity().is_ok()
    }

    pub const fn safety_head_facts_v0(
        &self,
    ) -> &AuthenticatedGenesisApplicationH1StableNativeValidSafetyHeadFactsV0 {
        &self.safety_head_facts
    }

    pub const fn application_delivery_facts_v0(&self) -> ApplicationNativeValidDeliveryFactsV0 {
        self.safety_head_facts.application_delivery_facts_v0()
    }

    pub const fn state_v0(&self) -> &SafetyState {
        &self.state
    }

    pub const fn transition_context_v0(&self) -> &SafetyTransitionContextV0 {
        &self.transition_context
    }

    pub const fn journal_id_v0(&self) -> [u8; 32] {
        self.safety_head_facts.journal_id_v0()
    }

    pub const fn verifier_profile_ref_v0(&self) -> [u8; 32] {
        self.safety_head_facts.verifier_profile_ref_v0()
    }

    pub const fn core_config_ref_v0(&self) -> [u8; 32] {
        self.safety_head_facts.core_config_ref_v0()
    }

    pub const fn state_record_checksum_v0(&self) -> [u8; 32] {
        self.safety_head_facts
            .revision_two_state_record_checksum_v0()
    }

    pub const fn chain_checksum_v0(&self) -> [u8; 32] {
        self.safety_head_facts.revision_two_chain_checksum_v0()
    }
}

/// Non-cloneable proof that a caller-supplied historical h2 NativeValid
/// transition is the exact preimage committed by a current anchored rev4
/// journal chain.
///
/// Journal v6 retains only the current record and its immediate predecessor.
/// At rev4 that means rev3/rev4, so the rev2 transition row is no longer
/// present. The rev3 record nevertheless permanently names rev2's chain
/// checksum. This capability reconstructs canonical rev0, rev1, and rev2
/// state records and transition checksums, then requires their derived rev2
/// chain checksum to equal that authenticated rev3 predecessor. It does not
/// mint callback, persistence, application, signer, or Core authority.
#[derive(Debug)]
#[must_use = "the reconstructed h2 transition proof must be consumed by one exact cross-store join"]
pub struct ConfirmedAnchoredSuccessorHistoricalValidV0 {
    journal_id: [u8; 32],
    verifier_profile_ref: [u8; 32],
    current_state_record_checksum: [u8; 32],
    current_chain_checksum: [u8; 32],
    reconstructed_state_record_checksum: [u8; 32],
    transition: NativeValidTransitionV0,
    transition_checksum: [u8; 32],
    reconstructed_chain_checksum: [u8; 32],
}

impl ConfirmedAnchoredSuccessorHistoricalValidV0 {
    pub const fn journal_id_v0(&self) -> [u8; 32] {
        self.journal_id
    }

    pub const fn verifier_profile_ref_v0(&self) -> [u8; 32] {
        self.verifier_profile_ref
    }

    pub const fn current_state_record_checksum_v0(&self) -> [u8; 32] {
        self.current_state_record_checksum
    }

    pub const fn current_chain_checksum_v0(&self) -> [u8; 32] {
        self.current_chain_checksum
    }

    pub const fn reconstructed_state_record_checksum_v0(&self) -> [u8; 32] {
        self.reconstructed_state_record_checksum
    }

    pub const fn transition_v0(&self) -> &NativeValidTransitionV0 {
        &self.transition
    }

    pub const fn transition_checksum_v0(&self) -> [u8; 32] {
        self.transition_checksum
    }

    pub const fn reconstructed_chain_checksum_v0(&self) -> [u8; 32] {
        self.reconstructed_chain_checksum
    }
}

impl ConfirmedNativeValidHeadV0 {
    fn from_authenticated_head(
        journal_id: [u8; 32],
        verifier_profile_ref: [u8; 32],
        head: RecoveredSafetyStateV0,
        owner_affinity: Arc<()>,
    ) -> Result<Self, SafetyStoreErrorV0> {
        if head.transition_context.native_valid_transition().is_none() {
            return Err(SafetyStoreErrorV0::MissingNativeValidTransition {
                revision: head.revision(),
            });
        }
        Ok(Self {
            journal_id,
            verifier_profile_ref,
            head,
            owner_affinity,
        })
    }

    /// Confirms that these detached facts came from this exact still-live
    /// SafetyStore owner and that its canonical namespace remains at
    /// `expected_path`.
    ///
    /// This is an owner-affinity check, not a freshness check. A trusted host
    /// must still call `confirmed_native_valid_head_exact_v0` immediately
    /// before consuming the capability in a cross-store recovery join.
    pub fn belongs_to_store_at_path_v0<V: SignatureVerifier>(
        &self,
        store: &SqliteSafetyStateStoreV0<V>,
        expected_path: &Path,
    ) -> bool {
        Arc::ptr_eq(&self.owner_affinity, &store.owner_affinity)
            && store.path() == expected_path
            && store.ensure_file_identity().is_ok()
    }

    /// Identifier frozen from the issuing store, never from caller-supplied
    /// expected state or transition values.
    pub const fn journal_id_v0(&self) -> [u8; 32] {
        self.journal_id
    }

    /// Verifier/profile identity frozen from the issuing store profile.
    pub const fn verifier_profile_ref_v0(&self) -> [u8; 32] {
        self.verifier_profile_ref
    }

    pub const fn state(&self) -> &SafetyState {
        self.head.state()
    }

    pub const fn transition_context(&self) -> &SafetyTransitionContextV0 {
        self.head.transition_context()
    }

    pub fn transition(&self) -> &NativeValidTransitionV0 {
        self.head
            .transition_context()
            .native_valid_transition()
            .expect("private constructor requires a native Valid transition")
    }

    /// Exact inert Core post-ack action authenticated by this transition.
    pub fn post_ack_action_v0(&self) -> NativeValidPostAckActionV0 {
        NativeValidPostAckActionV0::from_code(self.transition().post_ack_action_code())
            .expect("private constructor authenticates the closed NativeValid action code")
    }

    pub const fn revision(&self) -> u64 {
        self.head.revision()
    }

    pub const fn state_record_checksum(&self) -> [u8; 32] {
        self.head.state_record_checksum()
    }

    pub const fn chain_checksum(&self) -> [u8; 32] {
        self.head.chain_checksum()
    }
}

/// Non-cloneable proof that the fully authenticated journal head carries one
/// exact native finalization-applied transition.
///
/// It freezes journal/profile identity and exact state/context readback, but
/// deliberately cannot recreate Core's process-local queue receipt,
/// `StorageAck`, or post-ack effects.
#[derive(Debug)]
#[must_use = "the confirmed native finalization-applied head must remain paired with its exact state/context"]
pub struct ConfirmedNativeFinalizationAppliedHeadV0 {
    journal_id: [u8; 32],
    verifier_profile_ref: [u8; 32],
    head: RecoveredSafetyStateV0,
    consumed_finalization: DurableFinalizationV0,
}

impl ConfirmedNativeFinalizationAppliedHeadV0 {
    fn from_authenticated_head(
        journal_id: [u8; 32],
        verifier_profile_ref: [u8; 32],
        head: RecoveredSafetyStateV0,
        consumed_finalization: DurableFinalizationV0,
    ) -> Result<Self, SafetyStoreErrorV0> {
        let Some(transition) = head
            .transition_context
            .native_finalization_applied_transition()
        else {
            return Err(
                SafetyStoreErrorV0::MissingNativeFinalizationAppliedTransition {
                    revision: head.revision(),
                },
            );
        };
        let target = consumed_finalization.proof().finalized_block().header();
        if native_finalization_applied_checksum_v0(&consumed_finalization)
            != Ok(transition.finalization_checksum())
            || consumed_finalization.authenticated_parent().block_id()
                == consumed_finalization.target_overlay_ref().block_id()
            || target.id() != head.state().application_applied().block_id()
            || target.height() != head.state().application_applied().height()
            || target.view() != head.state().application_applied().view()
            || target.timestamp_ms() != head.state().application_applied().timestamp_ms()
            || consumed_finalization.target_overlay_ref().block_id() != target.id()
            || consumed_finalization.target_overlay_ref().parent_block_id()
                != consumed_finalization.authenticated_parent().block_id()
        {
            return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                "confirmed tag-3 head differs from its authenticated consumed queue front",
            ));
        }
        Ok(Self {
            journal_id,
            verifier_profile_ref,
            head,
            consumed_finalization,
        })
    }

    pub const fn journal_id_v0(&self) -> [u8; 32] {
        self.journal_id
    }

    pub const fn verifier_profile_ref_v0(&self) -> [u8; 32] {
        self.verifier_profile_ref
    }

    pub const fn state(&self) -> &SafetyState {
        self.head.state()
    }

    pub const fn transition_context(&self) -> &SafetyTransitionContextV0 {
        self.head.transition_context()
    }

    /// Exact queue front consumed by this tag-3 transition.
    ///
    /// The value is retained from the authenticated predecessor/current
    /// journal pair.  It is inert comparison material and grants no Core or
    /// ApplicationStore authority.
    pub const fn consumed_finalization_v0(&self) -> &DurableFinalizationV0 {
        &self.consumed_finalization
    }

    pub fn transition(&self) -> &NativeFinalizationAppliedTransitionV0 {
        self.head
            .transition_context()
            .native_finalization_applied_transition()
            .expect("private constructor requires a native finalization-applied transition")
    }

    /// Combines the fixed 328-byte tag-3 context with the exact consumed
    /// predecessor front into Core's complete recovery comparison projection.
    ///
    /// No persistent codec fields are added: proof/parent/target/overlay facts
    /// come from the already-authenticated retained predecessor, while App
    /// checksums and source identity come from the canonical tag-3 context.
    pub fn recovery_transition_v0(&self) -> NativeFinalizationAppliedRecoveryTransitionV0 {
        let context = self.transition();
        let consumed = self.consumed_finalization_v0();
        NativeFinalizationAppliedRecoveryTransitionV0::from_persisted_parts(
            context.ordinal(),
            consumed.proof_id(),
            consumed.authenticated_parent().block_id(),
            consumed.proof().finalized_block().header().id(),
            consumed.target_overlay_ref().overlay_checksum(),
            context.source_route(),
            context.source_validation_id(),
            context.application_host_config_ref(),
            context.finalization_checksum(),
            context.source_artifact_checksum(),
            context.accepted_source_checksum(),
            context.applied_job_row_checksum(),
            context.prior_head_checksum(),
            context.new_head_checksum(),
            context.receipt_row_checksum(),
            NativeFinalizationAppliedPostAckActionV0::from_code(context.post_ack_action_code())
                .expect("authenticated tag-3 context has one canonical action"),
            context.completion_revision(),
        )
    }

    pub const fn revision(&self) -> u64 {
        self.head.revision()
    }

    pub const fn state_record_checksum(&self) -> [u8; 32] {
        self.head.state_record_checksum()
    }

    pub const fn chain_checksum(&self) -> [u8; 32] {
        self.head.chain_checksum()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FileIdentityV0 {
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(not(unix))]
    canonical_path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FileImageCommitmentV0 {
    length: u64,
    checksum: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RecoverableCurrentJournalWalV0 {
    /// The bytes are not one supported, checksum-valid WAL image. Callers
    /// must distinguish this from an ordinary header/tail with no committed
    /// transaction so unsupported authoritative formats cannot reach the live
    /// SQLite namespace.
    Invalid(&'static str),
    /// SQLite has no checksum-valid committed transaction to apply. The
    /// checkpointed main database is therefore the complete recovery image.
    NoCommit,
    /// The exact byte boundary immediately after the last checksum-valid
    /// commit. A later torn or uncommitted tail is deliberately excluded.
    Committed { prefix_bytes: u64 },
}

struct InitializationAuditDirectoryV0 {
    parent_path: PathBuf,
    parent_file: File,
    parent_identity: FileIdentityV0,
    directory_name: OsString,
    directory_file: File,
    directory_identity: FileIdentityV0,
}

impl InitializationAuditDirectoryV0 {
    #[cfg(target_os = "linux")]
    fn database_path_v0(&self) -> PathBuf {
        use std::os::fd::AsRawFd;

        PathBuf::from(format!(
            "/proc/self/fd/{}/audit.sqlite",
            self.directory_file.as_raw_fd()
        ))
    }

    #[cfg(not(target_os = "linux"))]
    fn database_path_v0(&self) -> PathBuf {
        self.parent_path
            .join(&self.directory_name)
            .join("audit.sqlite")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StoredRecordV0 {
    revision: u64,
    predecessor_revision: Option<u64>,
    predecessor_chain_checksum: Option<[u8; 32]>,
    state_record_bytes: Vec<u8>,
    state_record_checksum: [u8; 32],
    transition_context_bytes: Vec<u8>,
    transition_context_checksum: [u8; 32],
    chain_checksum: [u8; 32],
}

#[derive(Clone)]
struct PreparedRecordV0 {
    revision: u64,
    state_record_bytes: Vec<u8>,
    state_record_checksum: [u8; 32],
    transition_context_bytes: Vec<u8>,
    transition_context_checksum: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct H1StateSyncInitializationIntentV0 {
    kind: SafetyBootstrapInitializationKindV0,
    journal_id: [u8; 32],
    metadata_checksum: [u8; 32],
    state_record_bytes: u64,
    transition_context_bytes: u64,
    state_record_checksum: [u8; 32],
    transition_context_checksum: [u8; 32],
    chain_checksum: [u8; 32],
    head_checksum: [u8; 32],
}

struct PreparedH1StateSyncInitializationV0 {
    record: PreparedRecordV0,
    stored: StoredRecordV0,
    intent: H1StateSyncInitializationIntentV0,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InitializationLockStateV0 {
    Empty,
    RecoverableTornStable,
    Stable(LockWatermarkV0),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ImmutableInitializationMainStateV0 {
    PreCommit,
    ExactPostCommit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InitializationWalShadowStateV0 {
    PreCommit,
    ExactPostCommit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ValidatedInitializationWalV0 {
    contains_commit: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InitializationDatabaseStateV0 {
    Absent,
    PreCommit,
    ExactPostCommit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct InitializationAuxiliaryStateV0 {
    wal_bytes: Option<u64>,
    shm_bytes: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RetainedRecordSummaryV0 {
    revision: u64,
    predecessor_revision: Option<u64>,
    predecessor_chain_checksum: Option<[u8; 32]>,
    chain_checksum: [u8; 32],
}

#[derive(Debug)]
struct ValidatedRetainedRecordsV0 {
    consumed_finalization: Option<DurableFinalizationV0>,
    records: Vec<RetainedRecordSummaryV0>,
    recovered_records: Vec<RecoveredSafetyStateV0>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DurableHaltFactV0 {
    reason_code: i64,
    revision: Option<u64>,
    evidence_checksum: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LockWatermarkV0 {
    Stable {
        sequence: u64,
        journal_id: [u8; 32],
        revision: u64,
        chain_checksum: [u8; 32],
    },
    HeadIntent {
        sequence: u64,
        journal_id: [u8; 32],
        source_revision: u64,
        source_chain_checksum: [u8; 32],
        target_revision: u64,
        target_chain_checksum: [u8; 32],
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DurableHaltLatchV0 {
    head_watermark: LockWatermarkV0,
    halt: DurableHaltFactV0,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ValidatedOpenWatermarkV0 {
    revision: u64,
    chain_checksum: [u8; 32],
    needs_head_resolution: bool,
}

#[derive(Debug)]
enum SafetyStatePersistenceBindingModeV0 {
    Ordinary(SafetyStatePersistenceBindingV0),
    // This mode is installed only by the dedicated authenticated-genesis h1
    // offline entry point. Generic persistence must never consume it: doing so
    // would turn the otherwise inert tag-5 journal into an ordinary live Core
    // activation surface.
    AuthenticatedGenesisApplicationH1Offline(
        Box<AuthenticatedGenesisApplicationH1OfflineBindingV0>,
    ),
}

#[derive(Debug)]
struct AuthenticatedGenesisApplicationH1OfflineBindingV0 {
    binding: AuthenticatedGenesisApplicationH1OfflineSafetyPersistenceBindingV0,
    carrier_binding_ref: [u8; 32],
    safety_state_record_config_ref: [u8; 32],
    tag5_state_record_checksum: [u8; 32],
    tag5_transition_context_checksum: [u8; 32],
    tag5_chain_checksum: [u8; 32],
}

struct AuthenticatedGenesisApplicationH1ObligationTakeoverRebindRegistrarV0<'a, V> {
    store: &'a mut SqliteSafetyStateStoreV0<V>,
    confirmed: ConfirmedAuthenticatedGenesisApplicationH1ObligationHeadV0,
}

/// Private production join between one replayed Core session and the exact
/// live rev1 SafetyStore capability minted from this owner.
///
/// Keeping this reconciler inside the SafetyStore crate prevents production
/// callers from implementing the public cross-crate `bool` TCB hook merely to
/// reach the process-local rebind. The lower-level hook remains available for
/// focused conformance tests.
struct AuthenticatedGenesisApplicationH1ObligationTakeoverReconcilerV0<'a, V> {
    store: &'a SqliteSafetyStateStoreV0<V>,
    confirmed: &'a ConfirmedAuthenticatedGenesisApplicationH1ObligationHeadV0,
}

impl<V: SignatureVerifier> AuthenticatedGenesisApplicationH1ObligationTakeoverSafetyReconcilerV0
    for AuthenticatedGenesisApplicationH1ObligationTakeoverReconcilerV0<'_, V>
{
    fn reconcile_authenticated_genesis_application_h1_obligation_takeover_v0(
        &mut self,
        challenge: &AuthenticatedGenesisApplicationH1ObligationTakeoverChallengeV0,
        safety_head_facts: &AuthenticatedGenesisApplicationH1ObligationTakeoverSafetyHeadFactsV0,
    ) -> bool {
        self.confirmed
            .belongs_to_store_at_path_v0(self.store, self.store.path())
            && self.confirmed.safety_head_facts_v0() == safety_head_facts
            && self.confirmed.state_v0() == challenge.revision_one_state_v0()
            && self.confirmed.transition_context_v0() == &SafetyTransitionContextV0::Ordinary
            && safety_head_facts.validation_id_v0() == challenge.validation_id_v0()
            && safety_head_facts.authenticated_parent_binding_ref_v0()
                == challenge.authenticated_parent_binding_ref_v0()
    }
}

impl<V: SignatureVerifier>
    AuthenticatedGenesisApplicationH1ObligationTakeoverSafetyRebindRegistrarV0
    for AuthenticatedGenesisApplicationH1ObligationTakeoverRebindRegistrarV0<'_, V>
{
    type Error = SafetyStoreErrorV0;

    fn rebind_authenticated_genesis_application_h1_obligation_takeover_v0(
        self,
        safety_head_facts: &AuthenticatedGenesisApplicationH1ObligationTakeoverSafetyHeadFactsV0,
        persistence: &AuthenticatedGenesisApplicationH1ObligationPersistenceV0,
        binding: AuthenticatedGenesisApplicationH1OfflineSafetyPersistenceBindingV0,
    ) -> Result<(), Self::Error> {
        self.store
            .install_authenticated_genesis_application_h1_obligation_takeover_binding_exact_v0(
                self.confirmed,
                safety_head_facts,
                persistence,
                binding,
            )
    }
}

#[derive(Debug, Clone, Copy)]
struct OrdinaryOpenPreflightFactsV0<'a, V> {
    profile: &'a SafetyStateStoreProfileV0,
    verifier: &'a V,
    journal_id: [u8; 32],
    lock_watermark: LockWatermarkV0,
    halt_latch: Option<DurableHaltLatchV0>,
}

impl LockWatermarkV0 {
    const fn sequence(self) -> u64 {
        match self {
            Self::Stable { sequence, .. } | Self::HeadIntent { sequence, .. } => sequence,
        }
    }

    const fn journal_id(self) -> [u8; 32] {
        match self {
            Self::Stable { journal_id, .. } | Self::HeadIntent { journal_id, .. } => journal_id,
        }
    }
}

type StoredMetadataRowV0 = (
    i64,
    Vec<u8>,
    i64,
    i64,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    i64,
    Vec<u8>,
);
type StoredHaltRowV0 = (i64, Option<Vec<u8>>, Vec<u8>, Vec<u8>);

/// Non-cloneable authoritative handle for one node-local safety journal.
///
/// # Process ownership contract
///
/// One process may own at most one SQLite/VFS connection graph for this exact
/// main-database/SHM inode pair. No raw or second `rusqlite` connection to the
/// same journal may remain live while this handle is opened or retained, and
/// no independently opened descriptor for the same SHM inode may be closed
/// between ordinary preflight and SQLite's live VFS takeover. POSIX record
/// locks are process-scoped, and SQLite reuses one `unixShmNode` per process;
/// neither condition can be proven by `F_GETLK` from inside this API. A
/// production host must therefore place each journal behind one dedicated
/// process owner rather than treating the byte-128 SHM guard as an
/// intra-process exclusion primitive.
pub struct SqliteSafetyStateStoreV0<V> {
    database_path: PathBuf,
    lock_path: PathBuf,
    directory_path: PathBuf,
    database_identity: FileIdentityV0,
    lock_identity: FileIdentityV0,
    directory_identity: FileIdentityV0,
    wal_identity: FileIdentityV0,
    shm_identity: FileIdentityV0,
    connection: ManuallyDrop<Connection>,
    database_file: ManuallyDrop<File>,
    lock_file: ManuallyDrop<File>,
    wal_file: ManuallyDrop<File>,
    shm_file: ManuallyDrop<File>,
    directory_file: ManuallyDrop<File>,
    profile: SafetyStateStoreProfileV0,
    verifier: V,
    core_binding: Option<SafetyStatePersistenceBindingModeV0>,
    journal_id: [u8; 32],
    observed_lock_watermark: LockWatermarkV0,
    observed_halt_latch: Option<DurableHaltLatchV0>,
    observed_head_revision: u64,
    observed_head_chain_checksum: [u8; 32],
    owner_pid: u32,
    owner_affinity: Arc<()>,
    sticky_halt: AtomicBool,
}

impl<V: SignatureVerifier> SqliteSafetyStateStoreV0<V> {
    pub fn initialize_new(
        database_path: impl AsRef<Path>,
        profile: SafetyStateStoreProfileV0,
        verifier: V,
        genesis_state: &SafetyState,
    ) -> Result<Self, SafetyStoreErrorV0> {
        ensure_supported_file_identity()?;
        if profile
            .core_config()
            .authenticated_genesis_application_parent_v0()
            .is_some()
            || genesis_state
                .authenticated_genesis_application_parent_v0()
                .is_some()
        {
            return Err(SafetyStoreErrorV0::AuthenticatedGenesisApplicationActivationUnavailable);
        }
        if genesis_state.revision() != 0 {
            return Err(SafetyStoreErrorV0::InvalidProfile(
                "initial SafetyState revision is not zero",
            ));
        }
        Core::validate_persisted_state_v0(profile.core_config(), genesis_state, &verifier)
            .map_err(|error| SafetyStoreErrorV0::core("validate initial state", error))?;
        Core::recover(
            profile.core_config().clone(),
            genesis_state.clone(),
            &verifier,
        )
        .map_err(|error| SafetyStoreErrorV0::core("prove initial state recoverable", error))?;

        Self::initialize_prevalidated_new_v0(
            database_path,
            profile,
            verifier,
            genesis_state,
            &SafetyTransitionContextV0::Ordinary,
        )
    }

    /// Initializes journal v6 from Core's sole fresh-validator h1 state-sync
    /// bootstrap carrier.
    ///
    /// This path authenticates the complete schema-v12 anchor using Core's
    /// dedicated recovery entry point, then stores revision zero with the
    /// canonical tag-4 context. It does not activate the returned recovery
    /// session and therefore grants no Core, application, signer, or network
    /// authority. Core does not prepare this carrier for a config-pinned
    /// authenticated genesis application parent: genesis application bootstrap
    /// and h1 state-sync bootstrap are mutually exclusive. Generic
    /// [`Self::initialize_new`] remains genesis-only.
    pub fn initialize_h1_state_sync_v0(
        database_path: impl AsRef<Path>,
        profile: SafetyStateStoreProfileV0,
        verifier: V,
        bootstrap: &PreparedH1StateSyncBootstrapV0,
    ) -> Result<Self, SafetyStoreErrorV0> {
        Self::initialize_or_resume_h1_state_sync_exact_v0(
            database_path,
            profile,
            verifier,
            bootstrap,
        )
        .map(|(store, _)| store)
    }

    /// Initializes or resumes only the exact fresh h1/tag-4 bundle.
    ///
    /// Before the database namespace can be created, this entry persists and
    /// fsyncs a fixed checksummed initialization intent binding the random
    /// journal identity, complete profile metadata checksum, canonical state
    /// record, tag-4 context, record chain, and revision-zero head. A retry may
    /// continue only that exact bundle. If SQLite committed before the Stable
    /// watermark was written, a read-only full audit must reproduce the intent
    /// exactly before this method checkpoints the commit and finishes Stable.
    /// The marker is removed and its parent fsynced only after the complete
    /// store validates; ordinary [`Self::open_existing`] refuses it while it is
    /// present.
    pub fn initialize_or_resume_h1_state_sync_exact_v0(
        database_path: impl AsRef<Path>,
        profile: SafetyStateStoreProfileV0,
        verifier: V,
        bootstrap: &PreparedH1StateSyncBootstrapV0,
    ) -> Result<(Self, StateSyncCheckpointInitializationDispositionV0), SafetyStoreErrorV0> {
        ensure_supported_file_identity()?;
        let prepared_record =
            prepare_h1_state_sync_bootstrap_record_v0(&profile, &verifier, bootstrap)?;
        Self::initialize_or_resume_prepared_h1_state_sync_exact_v0(
            database_path.as_ref(),
            profile,
            verifier,
            bootstrap,
            prepared_record,
        )
    }

    /// Initializes journal v6/schema 12 with the exact inert authenticated-
    /// genesis application bootstrap facts prepared by Core.
    ///
    /// This path never calls generic `Core::recover`, never writes Ordinary or
    /// tag-4 context, and never exposes a live Core. It installs only the
    /// revision-zero tag-5 record and then confirms its complete readback.
    pub fn initialize_authenticated_genesis_application_v0(
        database_path: impl AsRef<Path>,
        profile: SafetyStateStoreProfileV0,
        verifier: V,
        bootstrap: &PreparedAuthenticatedGenesisApplicationBootstrapV0,
    ) -> Result<Self, SafetyStoreErrorV0> {
        Self::initialize_or_resume_authenticated_genesis_application_exact_v0(
            database_path,
            profile,
            verifier,
            bootstrap,
        )
        .map(|(store, _)| store)
    }

    /// Initializes or resumes only the exact revision-zero/tag-5 bundle.
    pub fn initialize_or_resume_authenticated_genesis_application_exact_v0(
        database_path: impl AsRef<Path>,
        profile: SafetyStateStoreProfileV0,
        verifier: V,
        bootstrap: &PreparedAuthenticatedGenesisApplicationBootstrapV0,
    ) -> Result<
        (
            Self,
            AuthenticatedGenesisApplicationInitializationDispositionV0,
        ),
        SafetyStoreErrorV0,
    > {
        ensure_supported_file_identity()?;
        let prepared_record = prepare_authenticated_genesis_application_bootstrap_record_v0(
            &profile, &verifier, bootstrap,
        )?;
        Self::initialize_or_resume_prepared_bootstrap_exact_v0(
            database_path.as_ref(),
            profile,
            verifier,
            prepared_record,
            SafetyBootstrapInitializationKindV0::AuthenticatedGenesisApplication,
        )
        .and_then(|(store, disposition)| {
            let confirmed = store
                .confirmed_authenticated_genesis_application_bootstrap_head_exact_v0(bootstrap)?;
            drop(confirmed);
            Ok((store, disposition.into()))
        })
    }

    fn initialize_or_resume_prepared_h1_state_sync_exact_v0(
        requested_database_path: &Path,
        profile: SafetyStateStoreProfileV0,
        verifier: V,
        bootstrap: &PreparedH1StateSyncBootstrapV0,
        prepared_record: PreparedRecordV0,
    ) -> Result<(Self, StateSyncCheckpointInitializationDispositionV0), SafetyStoreErrorV0> {
        Self::initialize_or_resume_prepared_bootstrap_exact_v0(
            requested_database_path,
            profile,
            verifier,
            prepared_record,
            SafetyBootstrapInitializationKindV0::StateSyncCheckpoint,
        )
        .and_then(|(store, disposition)| {
            let confirmed = store.confirmed_state_sync_checkpoint_bootstrap_head_exact_v0(
                bootstrap.safety_state(),
            )?;
            drop(confirmed);
            Ok((store, disposition.into()))
        })
    }

    fn initialize_or_resume_prepared_bootstrap_exact_v0(
        requested_database_path: &Path,
        profile: SafetyStateStoreProfileV0,
        verifier: V,
        prepared_record: PreparedRecordV0,
        initialization_kind: SafetyBootstrapInitializationKindV0,
    ) -> Result<(Self, BootstrapInitializationDispositionV0), SafetyStoreErrorV0> {
        let database_path = canonical_new_path(requested_database_path)?;
        let directory_path = database_path
            .parent()
            .ok_or(SafetyStoreErrorV0::InvalidProfile("database parent"))?
            .to_path_buf();
        let directory_file = File::open(&directory_path)
            .map_err(|error| SafetyStoreErrorV0::io("pin safety-store directory", error))?;
        let pinned_directory_identity =
            directory_handle_identity(&directory_file, &directory_path)?;
        let lock_path = lock_path_for(&database_path)?;
        let initialization_path = initialization_intent_path_for(&database_path)?;
        let initialization_temporary_path =
            initialization_intent_temporary_path_for(&database_path)?;
        let database_exists = path_exists_v0(&database_path, "inspect initialization database")?;
        let lock_exists = path_exists_v0(&lock_path, "inspect initialization lock sidecar")?;
        let initialization_exists =
            path_exists_v0(&initialization_path, "inspect h1 initialization intent")?;
        let initialization_temporary_exists = path_exists_v0(
            &initialization_temporary_path,
            "inspect h1 initialization intent temporary",
        )?;
        let initial_auxiliary_state = inspect_initialization_auxiliary_state_v0(
            &database_path,
            profile.maximum_database_bytes(),
        )?;

        if initialization_exists && initialization_temporary_exists {
            return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                "h1 initialization has both published and temporary intents",
            ));
        }
        if !initialization_exists
            && !initialization_temporary_exists
            && (database_exists
                || lock_exists
                || initial_auxiliary_state.wal_bytes.is_some()
                || initial_auxiliary_state.shm_bytes.is_some())
        {
            preflight_unowned_initialization_namespace_v0(
                &database_path,
                database_exists,
                lock_exists,
                initial_auxiliary_state,
                profile.maximum_database_bytes(),
            )?;
        }

        let mut initialization_file = None;
        let mut initialization_identity = None;
        let marker_preexisted = initialization_exists || initialization_temporary_exists;
        let mut prepared_from_intent = None;

        if initialization_exists {
            let file =
                open_existing_private_file(&initialization_path, "open h1 initialization intent")?;
            acquire_lifetime_lock(&file)?;
            let identity = file_handle_identity(&file, &initialization_path)?;
            let intent = read_h1_state_sync_initialization_intent_v0(&file, &initialization_path)?;
            let prepared = prepare_h1_state_sync_initialization_v0(
                &profile,
                intent.journal_id,
                &prepared_record,
                initialization_kind,
            )?;
            if intent != prepared.intent {
                return Err(SafetyStoreErrorV0::StateSyncInitializationIntentMismatch);
            }
            initialization_identity = Some(identity);
            initialization_file = Some(file);
            prepared_from_intent = Some(prepared);
        } else if initialization_temporary_exists {
            if database_exists
                || lock_exists
                || initial_auxiliary_state.wal_bytes.is_some()
                || initial_auxiliary_state.shm_bytes.is_some()
            {
                return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                    "unpublished h1 initialization intent has later namespace state",
                ));
            }
            let mut file = open_existing_private_file(
                &initialization_temporary_path,
                "open h1 initialization intent temporary",
            )?;
            acquire_lifetime_lock(&file)?;
            let identity = file_handle_identity(&file, &initialization_temporary_path)?;
            // No published authority or later namespace exists. A crash may
            // therefore have left any prefix in this private temporary inode;
            // truncate and rewrite it with a fresh identity before publishing.
            let new_journal_id = new_journal_id(&database_path)?;
            let prepared = prepare_h1_state_sync_initialization_v0(
                &profile,
                new_journal_id,
                &prepared_record,
                initialization_kind,
            )?;
            rewrite_unpublished_h1_state_sync_initialization_intent_v0(
                &mut file,
                identity.clone(),
                &initialization_temporary_path,
                &initialization_path,
                prepared.intent,
            )?;
            publish_h1_state_sync_initialization_intent_v0(
                &file,
                identity.clone(),
                &initialization_temporary_path,
                &initialization_path,
                &directory_file,
            )?;
            initialization_identity = Some(identity);
            initialization_file = Some(file);
            prepared_from_intent = Some(prepared);
        } else if !database_exists
            && !lock_exists
            && initial_auxiliary_state.wal_bytes.is_none()
            && initial_auxiliary_state.shm_bytes.is_none()
        {
            let new_journal_id = new_journal_id(&database_path)?;
            let prepared = prepare_h1_state_sync_initialization_v0(
                &profile,
                new_journal_id,
                &prepared_record,
                initialization_kind,
            )?;
            let mut file = create_new_private_file(
                &initialization_temporary_path,
                "create h1 initialization intent temporary",
            )?;
            acquire_lifetime_lock(&file)?;
            write_h1_state_sync_initialization_intent_v0(
                &mut file,
                &initialization_path,
                prepared.intent,
            )?;
            let identity = file_handle_identity(&file, &initialization_temporary_path)?;
            publish_h1_state_sync_initialization_intent_v0(
                &file,
                identity.clone(),
                &initialization_temporary_path,
                &initialization_path,
                &directory_file,
            )?;
            initialization_identity = Some(identity);
            initialization_file = Some(file);
            prepared_from_intent = Some(prepared);
        }

        let (
            prepared,
            journal_id,
            expected_stable,
            mut lock_file,
            lock_identity,
            lock_state,
            database_file,
            database_identity,
            database_state,
            disposition,
        ) = if let Some(prepared) = prepared_from_intent {
            let journal_id = prepared.intent.journal_id;
            let expected_stable = LockWatermarkV0::Stable {
                sequence: 0,
                journal_id,
                revision: 0,
                chain_checksum: prepared.stored.chain_checksum,
            };
            let fresh_auxiliary_state = inspect_initialization_auxiliary_state_v0(
                &database_path,
                profile.maximum_database_bytes(),
            )?;
            if !database_exists
                && (fresh_auxiliary_state.wal_bytes.is_some()
                    || fresh_auxiliary_state.shm_bytes.is_some())
            {
                return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                    "h1 initialization has SQLite auxiliary state without main database",
                ));
            }
            let (lock_file, lock_state) = if lock_exists {
                let mut file =
                    open_existing_private_file(&lock_path, "open initialization lock sidecar")?;
                acquire_lifetime_lock(&file)?;
                if !database_exists
                    && fresh_auxiliary_state.wal_bytes.is_none()
                    && fresh_auxiliary_state.shm_bytes.is_none()
                {
                    complete_owned_initialization_prestate_lock_v0(&mut file)?;
                    (file, InitializationLockStateV0::Empty)
                } else {
                    let state =
                        read_marker_bound_initialization_lock_state_v0(&file, expected_stable)?;
                    (file, state)
                }
            } else {
                if database_exists
                    || fresh_auxiliary_state.wal_bytes.is_some()
                    || fresh_auxiliary_state.shm_bytes.is_some()
                {
                    return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                        "h1 initialization lock is missing after database creation",
                    ));
                }
                let mut file =
                    create_new_private_file(&lock_path, "create initialization lock sidecar")?;
                acquire_lifetime_lock(&file)?;
                initialize_lock_file(&mut file)?;
                sync_directory_handle(&directory_file)?;
                (file, InitializationLockStateV0::Empty)
            };
            let lock_identity = file_handle_identity(&lock_file, &lock_path)?;
            let database_file = if database_exists {
                open_existing_private_file(&database_path, "pin initializing database")?
            } else {
                create_new_private_file(&database_path, "create initializing database")?
            };
            acquire_lifetime_lock(&database_file)?;
            let database_identity = file_handle_identity(&database_file, &database_path)?;
            let database_state = if database_exists {
                classify_marker_bound_h1_initialization_database_v0(
                    &database_path,
                    &database_file,
                    &profile,
                    &verifier,
                    &prepared,
                )?
            } else {
                InitializationDatabaseStateV0::Absent
            };
            match (database_state, lock_state) {
                (
                    InitializationDatabaseStateV0::Absent
                    | InitializationDatabaseStateV0::PreCommit,
                    InitializationLockStateV0::Empty,
                )
                | (
                    InitializationDatabaseStateV0::ExactPostCommit,
                    InitializationLockStateV0::Empty
                    | InitializationLockStateV0::RecoverableTornStable,
                ) => {}
                (
                    InitializationDatabaseStateV0::ExactPostCommit,
                    InitializationLockStateV0::Stable(watermark),
                ) if watermark == expected_stable => {}
                _ => {
                    return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                        "h1 initialization database and lock states are contradictory",
                    ));
                }
            }
            let disposition = if marker_preexisted {
                if database_state == InitializationDatabaseStateV0::ExactPostCommit {
                    BootstrapInitializationDispositionV0::ResumedAfterDatabaseCommit
                } else {
                    BootstrapInitializationDispositionV0::ResumedBeforeDatabaseCommit
                }
            } else {
                BootstrapInitializationDispositionV0::Initialized
            };
            (
                prepared,
                journal_id,
                expected_stable,
                lock_file,
                lock_identity,
                lock_state,
                database_file,
                database_identity,
                database_state,
                disposition,
            )
        } else {
            if !database_exists
                || !lock_exists
                || initial_auxiliary_state.wal_bytes.is_none()
                || initial_auxiliary_state.shm_bytes.is_none()
            {
                return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                    "h1 initialization namespace has no exact intent or complete store",
                ));
            }
            let lock_file =
                open_existing_private_file(&lock_path, "open completed initialization lock")?;
            acquire_lifetime_lock(&lock_file)?;
            let lock_identity = file_handle_identity(&lock_file, &lock_path)?;
            let lock_state = read_exact_initialization_lock_state_v0(&lock_file)?;
            let InitializationLockStateV0::Stable(stable) = lock_state else {
                return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                    "completed h1 initialization has no exact Stable watermark",
                ));
            };
            let journal_id = stable.journal_id();
            let prepared = prepare_h1_state_sync_initialization_v0(
                &profile,
                journal_id,
                &prepared_record,
                initialization_kind,
            )?;
            let expected_stable = LockWatermarkV0::Stable {
                sequence: 0,
                journal_id,
                revision: 0,
                chain_checksum: prepared.stored.chain_checksum,
            };
            if stable != expected_stable || initial_auxiliary_state.wal_bytes != Some(0) {
                return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                    "completed h1 initialization namespace differs from revision-zero Stable",
                ));
            }
            let database_file =
                open_existing_private_file(&database_path, "pin completed h1 database")?;
            acquire_lifetime_lock(&database_file)?;
            let database_identity = file_handle_identity(&database_file, &database_path)?;
            if classify_immutable_h1_initialization_main_v0(
                &database_path,
                &profile,
                &verifier,
                &prepared,
            )? != ImmutableInitializationMainStateV0::ExactPostCommit
            {
                return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                    "completed h1 initialization database is not the exact checkpointed head",
                ));
            }
            (
                prepared,
                journal_id,
                expected_stable,
                lock_file,
                lock_identity,
                lock_state,
                database_file,
                database_identity,
                InitializationDatabaseStateV0::ExactPostCommit,
                BootstrapInitializationDispositionV0::Existing,
            )
        };

        let mut connection = Connection::open_with_flags(
            &database_path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .map_err(|error| SafetyStoreErrorV0::sqlite("open h1 initialization database", error))?;
        if database_state == InitializationDatabaseStateV0::ExactPostCommit {
            configure_connection(&connection, false, profile.maximum_database_bytes())?;
            validate_exact_h1_state_sync_initialization_connection_v0(
                &connection,
                &profile,
                &verifier,
                &prepared,
                true,
            )?;
        } else {
            if database_state == InitializationDatabaseStateV0::PreCommit
                && sqlite_schema_object_count_v0(&connection)? != 0
            {
                return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                    "h1 initialization pre-commit database became nonempty",
                ));
            }
            configure_connection(&connection, true, profile.maximum_database_bytes())?;
            validate_sqlite_auxiliary_files(&database_path, profile.maximum_database_bytes())?;
            if let Err(commit_error) =
                initialize_schema(&mut connection, &profile, journal_id, &prepared.record)
            {
                drop(connection);
                match classify_marker_bound_h1_initialization_database_v0(
                    &database_path,
                    &database_file,
                    &profile,
                    &verifier,
                    &prepared,
                )? {
                    InitializationDatabaseStateV0::ExactPostCommit => {
                        connection = Connection::open_with_flags(
                            &database_path,
                            OpenFlags::SQLITE_OPEN_READ_WRITE
                                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
                        )
                        .map_err(|error| {
                            SafetyStoreErrorV0::sqlite(
                                "reopen exact h1 database after uncertain commit",
                                error,
                            )
                        })?;
                        configure_connection(&connection, false, profile.maximum_database_bytes())?;
                        validate_exact_h1_state_sync_initialization_connection_v0(
                            &connection,
                            &profile,
                            &verifier,
                            &prepared,
                            true,
                        )?;
                    }
                    InitializationDatabaseStateV0::Absent
                    | InitializationDatabaseStateV0::PreCommit => return Err(commit_error),
                }
            }
        }

        if !matches!(lock_state, InitializationLockStateV0::Stable(_)) {
            checkpoint_and_sync_initialization(&connection, &database_file, &directory_file)?;
            validate_exact_h1_state_sync_initialization_connection_v0(
                &connection,
                &profile,
                &verifier,
                &prepared,
                true,
            )?;
            write_lock_watermark(&mut lock_file, expected_stable)?;
            sync_directory_handle(&directory_file)?;
        }
        materialize_sqlite_auxiliary_files(&connection)?;
        let (wal_file, wal_identity, shm_file, shm_identity) =
            pin_sqlite_auxiliary_files(&database_path, profile.maximum_database_bytes())?;
        sync_directory_handle(&directory_file)?;
        if !canonical_path_is_stable(&database_path)?
            || !canonical_path_is_stable(&lock_path)?
            || file_identity(&database_path)? != database_identity
            || file_identity(&lock_path)? != lock_identity
            || directory_identity(&directory_path)? != pinned_directory_identity
        {
            return Err(SafetyStoreErrorV0::Conflict(
                SafetyStoreConflictV0::FileIdentityChanged,
            ));
        }

        let store = Self {
            database_identity,
            lock_identity,
            directory_identity: pinned_directory_identity,
            wal_identity,
            shm_identity,
            database_path,
            lock_path,
            directory_path,
            connection: ManuallyDrop::new(connection),
            database_file: ManuallyDrop::new(database_file),
            lock_file: ManuallyDrop::new(lock_file),
            wal_file: ManuallyDrop::new(wal_file),
            shm_file: ManuallyDrop::new(shm_file),
            directory_file: ManuallyDrop::new(directory_file),
            profile,
            verifier,
            core_binding: None,
            journal_id,
            observed_lock_watermark: expected_stable,
            observed_halt_latch: None,
            observed_head_revision: 0,
            observed_head_chain_checksum: prepared.stored.chain_checksum,
            owner_pid: std::process::id(),
            owner_affinity: Arc::new(()),
            sticky_halt: AtomicBool::new(false),
        };
        store.validate_database()?;
        if let (Some(mut file), Some(identity)) =
            (initialization_file.take(), initialization_identity.take())
        {
            retire_h1_state_sync_initialization_intent_v0(
                &mut file,
                identity,
                &initialization_path,
                &store.directory_file,
                prepared.intent,
            )?;
        }
        Ok((store, disposition))
    }

    fn initialize_prevalidated_new_v0(
        database_path: impl AsRef<Path>,
        profile: SafetyStateStoreProfileV0,
        verifier: V,
        initial_state: &SafetyState,
        initial_transition_context: &SafetyTransitionContextV0,
    ) -> Result<Self, SafetyStoreErrorV0> {
        let database_path = canonical_new_path(database_path.as_ref())?;
        let directory_path = database_path
            .parent()
            .ok_or(SafetyStoreErrorV0::InvalidProfile("database parent"))?
            .to_path_buf();
        let directory_file = File::open(&directory_path)
            .map_err(|error| SafetyStoreErrorV0::io("pin safety-store directory", error))?;
        let directory_identity = directory_handle_identity(&directory_file, &directory_path)?;
        let lock_path = lock_path_for(&database_path)?;
        let initialization_path = initialization_intent_path_for(&database_path)?;
        let initialization_temporary_path =
            initialization_intent_temporary_path_for(&database_path)?;
        if path_exists_v0(&database_path, "inspect generic initialization database")? {
            return Err(SafetyStoreErrorV0::AlreadyExists("database"));
        }
        if path_exists_v0(&lock_path, "inspect generic initialization lock")? {
            return Err(SafetyStoreErrorV0::AlreadyExists("lock sidecar"));
        }
        if secure_private_file_exists_v0(
            &initialization_path,
            "inspect generic published h1 initialization intent",
        )? || secure_private_file_exists_v0(
            &initialization_temporary_path,
            "inspect generic temporary h1 initialization intent",
        )? {
            return Err(SafetyStoreErrorV0::StateSyncInitializationPending);
        }
        ensure_sqlite_auxiliary_files_absent(&database_path)?;
        let journal_id = new_journal_id(&database_path)?;
        let mut lock_file = create_new_private_file(&lock_path, "create lock sidecar")?;
        acquire_lifetime_lock(&lock_file)?;
        initialize_lock_file(&mut lock_file)?;
        sync_directory_handle(&directory_file)?;
        let database_file = create_new_private_file(&database_path, "create database")?;
        acquire_lifetime_lock(&database_file)?;
        let database_identity = file_handle_identity(&database_file, &database_path)?;

        let mut connection = Connection::open_with_flags(
            &database_path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .map_err(|error| SafetyStoreErrorV0::sqlite("open new database", error))?;
        configure_connection(&connection, true, profile.maximum_database_bytes())?;
        validate_sqlite_auxiliary_files(&database_path, profile.maximum_database_bytes())?;
        let prepared = prepare_record(
            &profile,
            &verifier,
            BarrierId::new(0),
            initial_state,
            initial_transition_context,
        )?;
        initialize_schema(&mut connection, &profile, journal_id, &prepared)?;
        checkpoint_and_sync_initialization(&connection, &database_file, &directory_file)?;
        let (observed_head_revision, observed_head_chain_checksum, _) =
            read_head(&connection, journal_id)?;
        let observed_lock_watermark = LockWatermarkV0::Stable {
            sequence: 0,
            journal_id,
            revision: observed_head_revision,
            chain_checksum: observed_head_chain_checksum,
        };
        write_lock_watermark(&mut lock_file, observed_lock_watermark)?;
        sync_directory_handle(&directory_file)?;
        materialize_sqlite_auxiliary_files(&connection)?;
        let (wal_file, wal_identity, shm_file, shm_identity) =
            pin_sqlite_auxiliary_files(&database_path, profile.maximum_database_bytes())?;
        // WAL/SHM creation is namespace state. Pinning proves which inodes we
        // opened; syncing the pinned parent makes their directory entries
        // durable before initialization is reported complete.
        sync_directory_handle(&directory_file)?;
        let lock_identity = file_handle_identity(&lock_file, &lock_path)?;
        if !canonical_path_is_stable(&database_path)?
            || !canonical_path_is_stable(&lock_path)?
            || file_identity(&database_path)? != database_identity
            || file_identity(&lock_path)? != lock_identity
        {
            return Err(SafetyStoreErrorV0::Conflict(
                SafetyStoreConflictV0::FileIdentityChanged,
            ));
        }
        let store = Self {
            database_identity,
            lock_identity,
            directory_identity,
            wal_identity,
            shm_identity,
            database_path,
            lock_path,
            directory_path,
            connection: ManuallyDrop::new(connection),
            database_file: ManuallyDrop::new(database_file),
            lock_file: ManuallyDrop::new(lock_file),
            wal_file: ManuallyDrop::new(wal_file),
            shm_file: ManuallyDrop::new(shm_file),
            directory_file: ManuallyDrop::new(directory_file),
            profile,
            verifier,
            core_binding: None,
            journal_id,
            observed_lock_watermark,
            observed_halt_latch: None,
            observed_head_revision,
            observed_head_chain_checksum,
            owner_pid: std::process::id(),
            owner_affinity: Arc::new(()),
            sticky_halt: AtomicBool::new(false),
        };
        store.validate_database()?;
        Ok(store)
    }

    /// Opens one existing journal under the process-singleton SQLite owner
    /// contract documented on [`SqliteSafetyStateStoreV0`].
    ///
    /// The ordinary preflight claims SQLite's SHM deadman-switch byte before
    /// reading the namespace and keeps that process-scoped lock live until the
    /// bundled Unix VFS resets/rebuilds the wal-index. A caller which already
    /// holds another same-inode SQLite connection would cause the VFS to reuse
    /// its process-global `unixShmNode`, so such a caller is outside the
    /// certified deployment boundary and must use a dedicated owner process.
    pub fn open_existing(
        database_path: impl AsRef<Path>,
        profile: SafetyStateStoreProfileV0,
        verifier: V,
    ) -> Result<Self, SafetyStoreErrorV0> {
        if profile
            .core_config()
            .authenticated_genesis_application_parent_v0()
            .is_some()
        {
            return Err(SafetyStoreErrorV0::AuthenticatedGenesisApplicationActivationUnavailable);
        }
        Self::open_existing_with_authenticated_genesis_mode_v0(database_path, profile, verifier)
    }

    fn open_existing_with_authenticated_genesis_mode_v0(
        database_path: impl AsRef<Path>,
        profile: SafetyStateStoreProfileV0,
        verifier: V,
    ) -> Result<Self, SafetyStoreErrorV0> {
        ensure_supported_file_identity()?;
        let database_path = canonical_existing_database_path(database_path.as_ref())?;
        if secure_private_file_exists_v0(
            &initialization_intent_path_for(&database_path)?,
            "inspect h1 initialization intent before ordinary open",
        )? || secure_private_file_exists_v0(
            &initialization_intent_temporary_path_for(&database_path)?,
            "inspect h1 initialization temporary before ordinary open",
        )? {
            return Err(SafetyStoreErrorV0::StateSyncInitializationPending);
        }
        let directory_path = database_path
            .parent()
            .ok_or(SafetyStoreErrorV0::InvalidProfile("database parent"))?
            .to_path_buf();
        let directory_file = File::open(&directory_path)
            .map_err(|error| SafetyStoreErrorV0::io("pin safety-store directory", error))?;
        let directory_identity = directory_handle_identity(&directory_file, &directory_path)?;
        validate_sqlite_auxiliary_files(&database_path, profile.maximum_database_bytes())?;
        require_persistent_sqlite_auxiliary_files(&database_path)?;
        let lock_path = lock_path_for(&database_path)?;
        let lock_file = open_existing_private_file(&lock_path, "open lock sidecar")?;
        acquire_lifetime_lock(&lock_file)?;
        let lock_watermark = read_lock_watermark(&lock_file)?;
        let halt_latch = read_halt_latch(&lock_file)?;
        let journal_id = lock_watermark.journal_id();
        let lock_identity = file_handle_identity(&lock_file, &lock_path)?;
        if !canonical_path_is_stable(&lock_path)? || file_identity(&lock_path)? != lock_identity {
            return Err(SafetyStoreErrorV0::Conflict(
                SafetyStoreConflictV0::FileIdentityChanged,
            ));
        }
        let database_file = open_existing_private_file(&database_path, "pin existing database")?;
        acquire_lifetime_lock(&database_file)?;
        let database_identity = file_handle_identity(&database_file, &database_path)?;
        let (wal_file, wal_identity, shm_file, shm_identity) =
            pin_sqlite_auxiliary_files(&database_path, profile.maximum_database_bytes())?;
        // Classify both the checkpointed main database and any authoritative
        // committed WAL shadow before opening the live namespace through
        // SQLite read-write or applying any PRAGMA which can rewrite the
        // database header/WAL/SHM. Journal v2/v3/v4/v5 records encode older
        // Core safety schemas and have no implicit migration to v6/schema 12.
        preflight_current_journal_namespace_v0(
            &database_path,
            &database_file,
            &wal_file,
            &shm_file,
            OrdinaryOpenPreflightFactsV0 {
                profile: &profile,
                verifier: &verifier,
                journal_id,
                lock_watermark,
                halt_latch,
            },
        )?;
        if file_identity(&database_path)? != database_identity
            || file_identity(&lock_path)? != lock_identity
            || file_identity(&sqlite_auxiliary_path(&database_path, "-wal"))? != wal_identity
            || file_identity(&sqlite_auxiliary_path(&database_path, "-shm"))? != shm_identity
        {
            return Err(SafetyStoreErrorV0::Conflict(
                SafetyStoreConflictV0::FileIdentityChanged,
            ));
        }
        let connection = Connection::open_with_flags(
            &database_path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .map_err(|error| SafetyStoreErrorV0::sqlite("open existing database", error))?;
        configure_connection(&connection, false, profile.maximum_database_bytes())?;
        materialize_sqlite_auxiliary_files(&connection)?;
        validate_sqlite_auxiliary_files(&database_path, profile.maximum_database_bytes())?;
        if file_identity(&database_path)? != database_identity
            || file_identity(&lock_path)? != lock_identity
            || file_identity(&sqlite_auxiliary_path(&database_path, "-wal"))? != wal_identity
            || file_identity(&sqlite_auxiliary_path(&database_path, "-shm"))? != shm_identity
        {
            return Err(SafetyStoreErrorV0::Conflict(
                SafetyStoreConflictV0::FileIdentityChanged,
            ));
        }
        let (observed_head_revision, observed_head_chain_checksum) = match lock_watermark {
            LockWatermarkV0::Stable {
                revision,
                chain_checksum,
                ..
            }
            | LockWatermarkV0::HeadIntent {
                source_revision: revision,
                source_chain_checksum: chain_checksum,
                ..
            } => (revision, chain_checksum),
        };
        let mut store = Self {
            database_identity,
            lock_identity,
            directory_identity,
            wal_identity,
            shm_identity,
            database_path,
            lock_path,
            directory_path,
            connection: ManuallyDrop::new(connection),
            database_file: ManuallyDrop::new(database_file),
            lock_file: ManuallyDrop::new(lock_file),
            wal_file: ManuallyDrop::new(wal_file),
            shm_file: ManuallyDrop::new(shm_file),
            directory_file: ManuallyDrop::new(directory_file),
            profile,
            verifier,
            core_binding: None,
            journal_id,
            observed_lock_watermark: lock_watermark,
            observed_halt_latch: halt_latch,
            observed_head_revision,
            observed_head_chain_checksum,
            owner_pid: std::process::id(),
            owner_affinity: Arc::new(()),
            sticky_halt: AtomicBool::new(false),
        };
        store.resolve_open_watermark()?;
        store.validate_database()?;
        if durable_halt_present(&store.connection)? {
            store.sticky_halt.store(true, Ordering::Release);
            return Err(SafetyStoreErrorV0::DurableHalt);
        }
        Ok(store)
    }

    /// Reopens an existing tag-5 journal without crossing the generic Core
    /// activation surface, then confirms exact Core-prepared readback.
    pub fn open_existing_authenticated_genesis_application_exact_v0(
        database_path: impl AsRef<Path>,
        profile: SafetyStateStoreProfileV0,
        verifier: V,
        expected: &PreparedAuthenticatedGenesisApplicationBootstrapV0,
    ) -> Result<Self, SafetyStoreErrorV0> {
        if profile
            .core_config()
            .authenticated_genesis_application_parent_v0()
            .copied()
            != Some(expected.authenticated_genesis_application_parent_v0())
            || profile.core_config_ref()? != expected.safety_state_record_config_ref_v0()
        {
            return Err(SafetyStoreErrorV0::InvalidProfile(
                "authenticated-genesis reopen profile differs from prepared Core facts",
            ));
        }
        let store = Self::open_existing_internal_v0(database_path, profile, verifier)?;
        let confirmed =
            store.confirmed_authenticated_genesis_application_bootstrap_head_exact_v0(expected)?;
        drop(confirmed);
        Ok(store)
    }

    /// Reopens only an authenticated-genesis h1 journal whose current head is
    /// the exact revision-one Ordinary validation obligation. Generic
    /// `open_existing` remains fenced for this Core configuration, and this
    /// entry does not bind a Core or acknowledge the durable barrier.
    pub fn open_existing_authenticated_genesis_application_h1_obligation_v0(
        database_path: impl AsRef<Path>,
        profile: SafetyStateStoreProfileV0,
        verifier: V,
    ) -> Result<Self, SafetyStoreErrorV0> {
        if profile
            .core_config()
            .authenticated_genesis_application_parent_v0()
            .is_none()
        {
            return Err(SafetyStoreErrorV0::InvalidProfile(
                "authenticated-genesis h1 obligation reopen requires its configured parent",
            ));
        }
        let store = Self::open_existing_internal_v0(database_path, profile, verifier)?;
        let readback =
            store.authenticated_genesis_application_h1_obligation_lineage_readback_v0()?;
        drop(readback);
        Ok(store)
    }

    /// Opens one existing authenticated-genesis h1 journal and returns its
    /// exact supported configured-parent cut from the same authenticated
    /// owner.
    ///
    /// Only the still-pending revision-one obligation and the stable
    /// revision-two NativeValid head are admitted. The rev2 result proves the
    /// retained rev1 -> rev2 cut; the later Core challenge/capability join is
    /// still responsible for reconstructing the pruned tag-5 ancestry.
    /// Tag-5 commissioning,
    /// malformed/mixed history, or any later/other head is rejected directly;
    /// callers must not classify the namespace by fallback between the two
    /// specialized openers.
    pub fn open_existing_authenticated_genesis_application_h1_dispatch_v0(
        database_path: impl AsRef<Path>,
        profile: SafetyStateStoreProfileV0,
        verifier: V,
    ) -> Result<(Self, AuthenticatedGenesisApplicationH1ExistingCutV0), SafetyStoreErrorV0> {
        if profile
            .core_config()
            .authenticated_genesis_application_parent_v0()
            .is_none()
        {
            return Err(SafetyStoreErrorV0::InvalidProfile(
                "authenticated-genesis h1 dispatch requires its configured parent",
            ));
        }
        let store = Self::open_existing_internal_v0(database_path, profile, verifier)?;
        let cut = store.authenticated_genesis_application_h1_existing_cut_v0()?;
        Ok((store, cut))
    }

    /// Reopens only an already-completed authenticated-genesis h1 tag-2 head.
    /// Generic `open_existing` remains fenced for this Core configuration.
    pub fn open_existing_authenticated_genesis_application_h1_stable_native_valid_v0(
        database_path: impl AsRef<Path>,
        profile: SafetyStateStoreProfileV0,
        verifier: V,
    ) -> Result<Self, SafetyStoreErrorV0> {
        if profile
            .core_config()
            .authenticated_genesis_application_parent_v0()
            .is_none()
        {
            return Err(SafetyStoreErrorV0::InvalidProfile(
                "stable authenticated-genesis h1 reopen requires its configured parent",
            ));
        }
        let store = Self::open_existing_internal_v0(database_path, profile, verifier)?;
        let readback =
            store.authenticated_genesis_application_h1_stable_native_valid_lineage_readback_v0()?;
        drop(readback);
        Ok(store)
    }

    fn open_existing_internal_v0(
        database_path: impl AsRef<Path>,
        profile: SafetyStateStoreProfileV0,
        verifier: V,
    ) -> Result<Self, SafetyStoreErrorV0> {
        Self::open_existing_with_authenticated_genesis_mode_v0(database_path, profile, verifier)
    }

    pub fn path(&self) -> &Path {
        self.database_path.as_path()
    }

    /// Affines future writes to one host-designated Core instance.
    ///
    /// Opening and inspecting an inert obligation-bearing head does not require
    /// a live Core. Binding is therefore an explicit, one-way runtime step
    /// after the host has legitimately constructed or recovered its Core.
    pub fn bind_core_v0(
        &mut self,
        binding: SafetyStatePersistenceBindingV0,
    ) -> Result<(), SafetyStoreErrorV0> {
        if self
            .profile
            .core_config()
            .authenticated_genesis_application_parent_v0()
            .is_some()
        {
            return Err(SafetyStoreErrorV0::AuthenticatedGenesisApplicationActivationUnavailable);
        }
        if std::process::id() != self.owner_pid {
            return Err(SafetyStoreErrorV0::Conflict(
                SafetyStoreConflictV0::ProcessChanged,
            ));
        }
        if self.core_binding.is_some() {
            return Err(SafetyStoreErrorV0::CoreAlreadyBound);
        }
        self.core_binding = Some(SafetyStatePersistenceBindingModeV0::Ordinary(binding));
        Ok(())
    }

    /// Affines this exact live tag-5 owner to Core's narrow h1 offline owner.
    ///
    /// Both arguments are one-shot capabilities. The tag-5 capability proves
    /// that the journal still owns the exact revision-zero commissioning head;
    /// the Core capability binds the complete operator-pinned parent, record
    /// configuration, proposal, validation identity, and process-local
    /// persistence affinity. No generic Core binding is installed.
    ///
    /// ```compile_fail
    /// use trnm_consensus_core::SafetyStatePersistenceBindingV0;
    /// use trnm_consensus_safety_store::{
    ///     ConfirmedAuthenticatedGenesisApplicationBootstrapHeadV0,
    ///     SqliteSafetyStateStoreV0,
    /// };
    /// use trnm_consensus_types::SignatureVerifier;
    /// fn generic_binding_cannot_activate_h1<V: SignatureVerifier>(
    ///     store: &mut SqliteSafetyStateStoreV0<V>,
    ///     tag5: ConfirmedAuthenticatedGenesisApplicationBootstrapHeadV0,
    ///     generic: SafetyStatePersistenceBindingV0,
    /// ) {
    ///     store
    ///         .bind_authenticated_genesis_application_h1_offline_v0(tag5, generic)
    ///         .unwrap();
    /// }
    /// ```
    pub fn bind_authenticated_genesis_application_h1_offline_v0(
        &mut self,
        confirmed_tag5: ConfirmedAuthenticatedGenesisApplicationBootstrapHeadV0,
        binding: AuthenticatedGenesisApplicationH1OfflineSafetyPersistenceBindingV0,
    ) -> Result<(), SafetyStoreErrorV0> {
        if std::process::id() != self.owner_pid {
            return Err(SafetyStoreErrorV0::Conflict(
                SafetyStoreConflictV0::ProcessChanged,
            ));
        }
        if self.core_binding.is_some() {
            return Err(SafetyStoreErrorV0::CoreAlreadyBound);
        }
        self.ensure_file_identity()?;
        let configured_parent = self
            .profile
            .core_config()
            .authenticated_genesis_application_parent_v0()
            .copied()
            .ok_or(SafetyStoreErrorV0::AuthenticatedGenesisApplicationH1OfflineBindingMismatch)?;
        let proposal = binding.proposal_v0();
        let validation_id = binding.validation_id_v0();
        let proposal_header = proposal.block().header();
        if !confirmed_tag5.belongs_to_store_at_path_v0(self, self.path())
            || confirmed_tag5.revision_v0() != 0
            || confirmed_tag5.state_v0().revision() != 0
            || confirmed_tag5.transition_v0().transition_revision() != 0
            || confirmed_tag5.core_config_ref_v0() != self.profile.core_config_ref()?
            || confirmed_tag5.core_config_ref_v0() != binding.safety_state_record_config_ref_v0()
            || confirmed_tag5.transition_v0().carrier() != configured_parent
            || binding.authenticated_genesis_application_parent_v0() != configured_parent
            || confirmed_tag5.transition_v0().carrier_binding_ref()
                != configured_parent.binding_ref_v0()
            || confirmed_tag5.transition_v0().state_record_checksum()
                != confirmed_tag5.state_record_checksum_v0()
            || proposal_header.epoch().get() != 0
            || proposal_header.height().get() != 1
            || proposal_header.view().get() != 1
            || proposal_header.block_kind() != trnm_consensus_types::BlockKind::Regular
            || proposal_header.parent_id() != configured_parent.genesis_block_id()
            || proposal.witness().justify_qc() != confirmed_tag5.state_v0().high_qc()
            || proposal.witness().timeout_certificate().is_some()
            || proposal.witness().epoch_anchor_authorization().is_some()
            || validation_id.block_id() != proposal.block().id()
            || validation_id.view() != proposal_header.view()
            || validation_id.generation() != 1
            || binding.safety_state_record_config_ref_v0() != self.profile.core_config_ref()?
        {
            return Err(
                SafetyStoreErrorV0::AuthenticatedGenesisApplicationH1OfflineBindingMismatch,
            );
        }
        let fresh = self.confirmed_authenticated_genesis_application_bootstrap_head_v0()?;
        if fresh.state_v0() != confirmed_tag5.state_v0()
            || fresh.transition_context_v0() != confirmed_tag5.transition_context_v0()
            || fresh.state_record_checksum_v0() != confirmed_tag5.state_record_checksum_v0()
            || fresh.transition_context_checksum_v0()
                != confirmed_tag5.transition_context_checksum_v0()
            || fresh.chain_checksum_v0() != confirmed_tag5.chain_checksum_v0()
        {
            return Err(
                SafetyStoreErrorV0::AuthenticatedGenesisApplicationH1OfflineBindingMismatch,
            );
        }
        self.core_binding = Some(
            SafetyStatePersistenceBindingModeV0::AuthenticatedGenesisApplicationH1Offline(
                Box::new(AuthenticatedGenesisApplicationH1OfflineBindingV0 {
                    binding,
                    carrier_binding_ref: configured_parent.binding_ref_v0(),
                    safety_state_record_config_ref: fresh.core_config_ref_v0(),
                    tag5_state_record_checksum: fresh.state_record_checksum_v0(),
                    tag5_transition_context_checksum: fresh.transition_context_checksum_v0(),
                    tag5_chain_checksum: fresh.chain_checksum_v0(),
                }),
            ),
        );
        Ok(())
    }

    /// Rebinds an already-durable authenticated-genesis h1 obligation to the
    /// exact replay Core which will continue it to revision two.
    ///
    /// This is deliberately separate from the tag-5 bind above. It consumes a
    /// live, owner-affined rev1 capability, performs no SQLite write, and never
    /// rewrites the durable rev1 row. Only after this method returns can Core's
    /// post-rebind typestate acknowledge barrier one and release the validation
    /// request.
    pub fn rebind_authenticated_genesis_application_h1_obligation_takeover_exact_v0(
        &mut self,
        confirmed: ConfirmedAuthenticatedGenesisApplicationH1ObligationHeadV0,
        activation: AuthenticatedGenesisApplicationH1ObligationTakeoverActivationBundleV0,
    ) -> Result<
        AuthenticatedGenesisApplicationH1ObligationTakeoverReboundActivationV0,
        SafetyStoreErrorV0,
    > {
        activation.rebind_live_safety_v0(
            AuthenticatedGenesisApplicationH1ObligationTakeoverRebindRegistrarV0 {
                store: self,
                confirmed,
            },
        )
    }

    /// Production bridge for an already-durable authenticated-genesis h1
    /// obligation.
    ///
    /// The bridge consumes the entire replay Core takeover session, mints a
    /// fresh owner-affined rev1 capability, performs the private exact Safety
    /// reconciliation, activates the session, and installs its process-local
    /// persistence binding. No durable row, head, WAL, or lock watermark is
    /// rewritten. Only the rebound typestate can subsequently acknowledge
    /// barrier one and release the validation request.
    pub fn activate_and_rebind_authenticated_genesis_application_h1_obligation_takeover_exact_v0(
        &mut self,
        takeover: AuthenticatedGenesisApplicationH1ObligationTakeoverSessionV0,
    ) -> Result<
        AuthenticatedGenesisApplicationH1ObligationTakeoverReboundActivationV0,
        SafetyStoreErrorV0,
    > {
        let confirmed = self
            .confirmed_authenticated_genesis_application_h1_obligation_head_exact_v0(
                takeover.challenge_v0(),
            )?;
        let safety_head_facts = confirmed.safety_head_facts_v0().clone();
        let attestation = {
            let mut reconciler = AuthenticatedGenesisApplicationH1ObligationTakeoverReconcilerV0 {
                store: self,
                confirmed: &confirmed,
            };
            takeover
                .challenge_v0()
                .attest_authenticated_safety_head_v0(safety_head_facts, &mut reconciler)
                .map_err(|error| {
                    SafetyStoreErrorV0::core("reconcile h1 obligation takeover", error)
                })?
        };
        let activation = takeover
            .activate_after_authenticated_safety_v0(attestation)
            .map_err(|error| SafetyStoreErrorV0::core("activate h1 obligation takeover", error))?;
        self.rebind_authenticated_genesis_application_h1_obligation_takeover_exact_v0(
            confirmed, activation,
        )
    }

    fn install_authenticated_genesis_application_h1_obligation_takeover_binding_exact_v0(
        &mut self,
        confirmed: ConfirmedAuthenticatedGenesisApplicationH1ObligationHeadV0,
        safety_head_facts: &AuthenticatedGenesisApplicationH1ObligationTakeoverSafetyHeadFactsV0,
        persistence: &AuthenticatedGenesisApplicationH1ObligationPersistenceV0,
        binding: AuthenticatedGenesisApplicationH1OfflineSafetyPersistenceBindingV0,
    ) -> Result<(), SafetyStoreErrorV0> {
        if std::process::id() != self.owner_pid {
            return Err(SafetyStoreErrorV0::Conflict(
                SafetyStoreConflictV0::ProcessChanged,
            ));
        }
        self.ensure_file_identity()?;
        let profile_core_config_ref = self.profile.core_config_ref()?;
        let [durable_obligation] = persistence
            .persistence_v0()
            .state()
            .payload_validation_obligations()
        else {
            return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                "h1 takeover rebind requires one durable obligation",
            ));
        };
        let durable_parent_binding_ref = durable_obligation
            .parent_binding_ref_v0()
            .map_err(|error| SafetyStoreErrorV0::core("derive h1 takeover parent", error))?;
        if !confirmed.belongs_to_store_at_path_v0(self, self.path())
            || confirmed.safety_head_facts_v0() != safety_head_facts
            || confirmed.state_v0() != persistence.persistence_v0().state()
            || confirmed.transition_context_v0() != &SafetyTransitionContextV0::Ordinary
            || safety_head_facts.core_config_ref_v0() != profile_core_config_ref
            || safety_head_facts.journal_id_v0() != self.journal_id
            || safety_head_facts.verifier_profile_ref_v0() != self.profile.verifier_profile_ref()
            || safety_head_facts.barrier_v0() != persistence.barrier_v0()
            || safety_head_facts.validation_id_v0() != persistence.validation_id_v0()
            || safety_head_facts.authenticated_parent_binding_ref_v0() != durable_parent_binding_ref
            || binding.safety_state_record_config_ref_v0() != profile_core_config_ref
            || binding.validation_id_v0() != persistence.validation_id_v0()
            || !binding.accepts_persistence_v0(persistence.persistence_v0())
        {
            return Err(
                SafetyStoreErrorV0::AuthenticatedGenesisApplicationH1OfflineBindingMismatch,
            );
        }

        let (head, retained) = self.authenticated_head_with_retained_records_v0()?;
        let [revision_zero, revision_one] = retained.recovered_records.as_slice() else {
            return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                "h1 takeover rebind requires exactly retained tag-5 and rev1 records",
            ));
        };
        let [revision_zero_summary, revision_one_summary] = retained.records.as_slice() else {
            return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                "h1 takeover rebind requires exactly two retained checksum summaries",
            ));
        };
        if revision_zero.revision() != 0
            || !matches!(
                revision_zero.transition_context(),
                SafetyTransitionContextV0::AuthenticatedGenesisApplicationBootstrap(_)
            )
            || revision_zero.state_record_checksum()
                != safety_head_facts.tag5_state_record_checksum_v0()
            || revision_zero.transition_context_checksum()
                != safety_head_facts.tag5_transition_context_checksum_v0()
            || revision_zero.chain_checksum() != safety_head_facts.tag5_chain_checksum_v0()
            || revision_zero_summary.chain_checksum != safety_head_facts.tag5_chain_checksum_v0()
            || revision_one.revision() != 1
            || revision_one.transition_context() != &SafetyTransitionContextV0::Ordinary
            || revision_one.state() != persistence.persistence_v0().state()
            || revision_one.state_record_checksum()
                != safety_head_facts.revision_one_state_record_checksum_v0()
            || revision_one.transition_context_checksum()
                != safety_head_facts.revision_one_transition_context_checksum_v0()
            || revision_one.chain_checksum() != safety_head_facts.revision_one_chain_checksum_v0()
            || revision_one_summary.predecessor_revision != Some(0)
            || revision_one_summary.predecessor_chain_checksum
                != Some(safety_head_facts.tag5_chain_checksum_v0())
            || revision_one_summary.chain_checksum
                != safety_head_facts.revision_one_chain_checksum_v0()
            || head.revision() != 1
            || head.state() != persistence.persistence_v0().state()
            || head.state_record_checksum()
                != safety_head_facts.revision_one_state_record_checksum_v0()
            || head.transition_context_checksum()
                != safety_head_facts.revision_one_transition_context_checksum_v0()
            || head.chain_checksum() != safety_head_facts.revision_one_chain_checksum_v0()
            || head_checksum(
                self.journal_id,
                0,
                safety_head_facts.tag5_chain_checksum_v0(),
                0,
            ) != safety_head_facts.tag5_head_checksum_v0()
            || head_checksum(
                self.journal_id,
                1,
                safety_head_facts.revision_one_chain_checksum_v0(),
                0,
            ) != safety_head_facts.revision_one_head_checksum_v0()
        {
            return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                "h1 takeover rebind retained checksum lineage",
            ));
        }

        let configured_parent = self
            .profile
            .core_config()
            .authenticated_genesis_application_parent_v0()
            .copied()
            .ok_or(SafetyStoreErrorV0::AuthenticatedGenesisApplicationH1OfflineBindingMismatch)?;
        let replacement = AuthenticatedGenesisApplicationH1OfflineBindingV0 {
            binding,
            carrier_binding_ref: configured_parent.binding_ref_v0(),
            safety_state_record_config_ref: safety_head_facts.core_config_ref_v0(),
            tag5_state_record_checksum: safety_head_facts.tag5_state_record_checksum_v0(),
            tag5_transition_context_checksum: safety_head_facts
                .tag5_transition_context_checksum_v0(),
            tag5_chain_checksum: safety_head_facts.tag5_chain_checksum_v0(),
        };
        validate_authenticated_genesis_application_h1_obligation_v0(&replacement, persistence)?;
        let replacement_coordinates_match =
            |existing: &AuthenticatedGenesisApplicationH1OfflineBindingV0| {
                existing.carrier_binding_ref == configured_parent.binding_ref_v0()
                    && existing.safety_state_record_config_ref == profile_core_config_ref
                    && existing.tag5_state_record_checksum
                        == safety_head_facts.tag5_state_record_checksum_v0()
                    && existing.tag5_transition_context_checksum
                        == safety_head_facts.tag5_transition_context_checksum_v0()
                    && existing.tag5_chain_checksum == safety_head_facts.tag5_chain_checksum_v0()
                    && existing
                        .binding
                        .authenticated_genesis_application_parent_v0()
                        == configured_parent
                    && existing.binding.proposal_v0() == replacement.binding.proposal_v0()
                    && existing.binding.validation_id_v0() == replacement.binding.validation_id_v0()
            };
        match self.core_binding.as_ref() {
            None => {}
            Some(
                SafetyStatePersistenceBindingModeV0::AuthenticatedGenesisApplicationH1Offline(
                    existing,
                ),
            ) if replacement_coordinates_match(existing) => {}
            Some(_) => {
                return Err(
                    SafetyStoreErrorV0::AuthenticatedGenesisApplicationH1OfflineBindingMismatch,
                )
            }
        }

        self.ensure_file_identity()?;
        // The sole mutation is process-local. Durable rows, head, WAL and lock
        // watermark are untouched by the rebind.
        self.core_binding = Some(
            SafetyStatePersistenceBindingModeV0::AuthenticatedGenesisApplicationH1Offline(
                Box::new(replacement),
            ),
        );
        Ok(())
    }

    fn ordinary_core_binding_v0(
        &self,
    ) -> Result<&SafetyStatePersistenceBindingV0, SafetyStoreErrorV0> {
        match self.core_binding.as_ref() {
            Some(SafetyStatePersistenceBindingModeV0::Ordinary(binding)) => Ok(binding),
            Some(
                SafetyStatePersistenceBindingModeV0::AuthenticatedGenesisApplicationH1Offline(
                    binding,
                ),
            ) => {
                // Read the complete private mode facts here so a future field
                // addition cannot silently become unaudited while this generic
                // gate remains the only reachable consumer.
                let _ = binding;
                Err(
                    SafetyStoreErrorV0::AuthenticatedGenesisApplicationH1OfflineRequiresDedicatedPersistence,
                )
            }
            None => Err(SafetyStoreErrorV0::CoreNotBound),
        }
    }

    fn authenticated_genesis_application_h1_offline_binding_v0(
        &self,
    ) -> Result<&AuthenticatedGenesisApplicationH1OfflineBindingV0, SafetyStoreErrorV0> {
        match self.core_binding.as_ref() {
            Some(
                SafetyStatePersistenceBindingModeV0::AuthenticatedGenesisApplicationH1Offline(
                    binding,
                ),
            ) => Ok(binding.as_ref()),
            Some(SafetyStatePersistenceBindingModeV0::Ordinary(_)) => {
                Err(SafetyStoreErrorV0::AuthenticatedGenesisApplicationH1OfflineBindingMismatch)
            }
            None => Err(SafetyStoreErrorV0::CoreNotBound),
        }
    }

    /// Persists only Core's exact revision-one Synced h1 obligation above the
    /// bound tag-5 head. The transition context is fixed to Ordinary here and
    /// cannot be selected by a generic caller.
    pub fn persist_authenticated_genesis_application_h1_obligation_exact_v0(
        &mut self,
        carrier: &AuthenticatedGenesisApplicationH1ObligationPersistenceV0,
    ) -> Result<SafetyPersistDispositionV0, SafetyStoreErrorV0> {
        {
            let binding = self.authenticated_genesis_application_h1_offline_binding_v0()?;
            let request = carrier.persistence_v0();
            validate_authenticated_genesis_application_h1_obligation_v0(binding, carrier)?;
            self.validate_authenticated_genesis_application_h1_lineage_for_target_v0(1)?;
            if !binding.binding.accepts_persistence_v0(request) {
                return Err(SafetyStoreErrorV0::CoreAffinityMismatch);
            }
        }
        self.persist_bound_request_exact_v0(
            carrier.persistence_v0(),
            &SafetyTransitionContextV0::Ordinary,
        )
    }

    /// Persists and immediately authenticates Core/App's exact revision-two
    /// NativeValid completion for the same bound Synced h1 identity.
    ///
    /// The sole input is Core's opaque application-sealed `D` transition. This
    /// method internally constructs the canonical tag-2 transition context;
    /// callers cannot pair the carrier with a naked or substituted context.
    /// Inserted and exact-idempotent Existing writes both return the fresh
    /// fully authenticated head capability. Tag-1 invalid and every generic
    /// persistence/context surface remain unavailable in this slice.
    ///
    /// ```compile_fail
    /// use trnm_consensus_core::AuthenticatedGenesisApplicationH1ObligationPersistenceV0;
    /// use trnm_consensus_safety_store::SqliteSafetyStateStoreV0;
    /// use trnm_consensus_types::SignatureVerifier;
    /// fn rev1_cannot_enter_the_rev2_api<V: SignatureVerifier>(
    ///     store: &mut SqliteSafetyStateStoreV0<V>,
    ///     rev1: &AuthenticatedGenesisApplicationH1ObligationPersistenceV0,
    /// ) {
    ///     store
    ///         .persist_authenticated_genesis_application_h1_native_valid_exact_v0(rev1)
    ///         .unwrap();
    /// }
    /// ```
    ///
    /// A raw Core carrier and caller-constructed transition cannot enter this
    /// special API:
    ///
    /// ```compile_fail
    /// use trnm_consensus_core::AuthenticatedGenesisApplicationH1CompletionPersistenceV0;
    /// use trnm_consensus_safety_store::{NativeValidTransitionV0, SqliteSafetyStateStoreV0};
    /// use trnm_consensus_types::SignatureVerifier;
    /// fn naked_transition_is_rejected_by_type<V: SignatureVerifier>(
    ///     store: &mut SqliteSafetyStateStoreV0<V>,
    ///     carrier: &AuthenticatedGenesisApplicationH1CompletionPersistenceV0,
    ///     transition: &NativeValidTransitionV0,
    /// ) {
    ///     store
    ///         .persist_authenticated_genesis_application_h1_native_valid_exact_v0(
    ///             carrier,
    ///             transition,
    ///         )
    ///         .unwrap();
    /// }
    /// ```
    pub fn persist_authenticated_genesis_application_h1_native_valid_exact_v0(
        &mut self,
        sealed_transition: &ApplicationSealedNativeValidTransitionV0,
    ) -> Result<ConfirmedNativeValidHeadV0, SafetyStoreErrorV0> {
        let carrier = sealed_transition.completion_persistence_v0();
        let transition = native_valid_transition_from_application_seal_v0(sealed_transition)?;
        {
            let binding = self.authenticated_genesis_application_h1_offline_binding_v0()?;
            let request = carrier.persistence_v0();
            validate_authenticated_genesis_application_h1_native_valid_v0(
                binding,
                sealed_transition,
                &transition,
            )?;
            self.validate_authenticated_genesis_application_h1_lineage_for_target_v0(2)?;
            if !binding.binding.accepts_persistence_v0(request) {
                return Err(SafetyStoreErrorV0::CoreAffinityMismatch);
            }
        }
        let context = SafetyTransitionContextV0::native_valid(transition);
        let persist_error = self
            .persist_bound_request_exact_v0(carrier.persistence_v0(), &context)
            .err();
        match self.confirmed_native_valid_head_exact_v0(carrier.persistence_v0().state(), &context)
        {
            Ok(confirmed) => Ok(confirmed),
            Err(confirm_error) => Err(persist_error.unwrap_or(confirm_error)),
        }
    }

    /// Canonically projects Core's exact rev2 NativeValid request while the
    /// dedicated journal is still at its authenticated rev1 predecessor.
    ///
    /// This preflight is the only bridge exposed to the authenticated-genesis
    /// application owner. It returns inert comparison facts, performs no
    /// SQLite write, and cannot be called with a generic persistence request.
    /// The later persistence call still requires the App-owned exact tag-2
    /// transition and re-runs these binding, phase, and state checks.
    ///
    /// ```compile_fail
    /// use trnm_consensus_core::SafetyStatePersistenceV0;
    /// use trnm_consensus_safety_store::SqliteSafetyStateStoreV0;
    /// use trnm_consensus_types::SignatureVerifier;
    /// fn generic_request_cannot_enter_the_h1_preflight<V: SignatureVerifier>(
    ///     store: &SqliteSafetyStateStoreV0<V>,
    ///     generic: &SafetyStatePersistenceV0,
    /// ) {
    ///     store
    ///         .preflight_authenticated_genesis_application_h1_native_valid_exact_v0(generic)
    ///         .unwrap();
    /// }
    /// ```
    pub fn preflight_authenticated_genesis_application_h1_native_valid_exact_v0(
        &self,
        carrier: &AuthenticatedGenesisApplicationH1CompletionPersistenceV0,
    ) -> Result<NativeValidSafetyStatePreflightV0, SafetyStoreErrorV0> {
        {
            let binding = self.authenticated_genesis_application_h1_offline_binding_v0()?;
            let request = carrier.persistence_v0();
            validate_authenticated_genesis_application_h1_native_valid_completion_v0(
                binding, carrier,
            )?;
            self.validate_authenticated_genesis_application_h1_preflight_lineage_v0()?;
            if !binding.binding.accepts_persistence_v0(request) {
                return Err(SafetyStoreErrorV0::CoreAffinityMismatch);
            }
        }
        self.preflight_native_valid_request_v0(carrier.persistence_v0())
    }

    fn validate_authenticated_genesis_application_h1_preflight_lineage_v0(
        &self,
    ) -> Result<(), SafetyStoreErrorV0> {
        let binding = self.authenticated_genesis_application_h1_offline_binding_v0()?;
        let (head, retained) = self.authenticated_head_with_retained_records_v0()?;
        let lineage_matches = matches!(retained.records.as_slice(), [revision_zero, revision_one]
            if revision_zero.revision == 0
                && revision_zero.chain_checksum == binding.tag5_chain_checksum
                && revision_one.revision == 1
                && revision_one.predecessor_revision == Some(0)
                && revision_one.predecessor_chain_checksum == Some(binding.tag5_chain_checksum));
        if head.revision() != 1
            || head
                .state()
                .authenticated_genesis_application_parent_v0()
                .is_none_or(|parent| parent.binding_ref_v0() != binding.carrier_binding_ref)
            || self.profile.core_config_ref()? != binding.safety_state_record_config_ref
            || !matches!(
                head.transition_context(),
                SafetyTransitionContextV0::Ordinary
            )
            || !lineage_matches
        {
            return Err(
                SafetyStoreErrorV0::AuthenticatedGenesisApplicationH1OfflinePersistenceMismatch {
                    expected_revision: 1,
                    actual_revision: head.revision(),
                },
            );
        }
        Ok(())
    }

    fn validate_authenticated_genesis_application_h1_lineage_for_target_v0(
        &self,
        target_revision: u64,
    ) -> Result<(), SafetyStoreErrorV0> {
        let binding = self.authenticated_genesis_application_h1_offline_binding_v0()?;
        let (head, retained) = self.authenticated_head_with_retained_records_v0()?;
        let records = retained.records.as_slice();
        let lineage_matches = match (target_revision, head.revision()) {
            (1, 0) => {
                matches!(records, [revision_zero]
                if revision_zero.revision == 0
                    && revision_zero.predecessor_revision.is_none()
                    && revision_zero.predecessor_chain_checksum.is_none()
                    && revision_zero.chain_checksum == binding.tag5_chain_checksum)
                    && head
                        .transition_context()
                        .authenticated_genesis_application_bootstrap_transition()
                        .is_some()
            }
            (1, 1) | (2, 1) => {
                matches!(records, [revision_zero, revision_one]
                if revision_zero.revision == 0
                    && revision_zero.chain_checksum == binding.tag5_chain_checksum
                    && revision_one.revision == 1
                    && revision_one.predecessor_revision == Some(0)
                    && revision_one.predecessor_chain_checksum
                        == Some(binding.tag5_chain_checksum))
                    && matches!(
                        head.transition_context(),
                        SafetyTransitionContextV0::Ordinary
                    )
            }
            (2, 2) => {
                matches!(records, [revision_one, revision_two]
                if revision_one.revision == 1
                    && revision_one.predecessor_revision == Some(0)
                    && revision_one.predecessor_chain_checksum
                        == Some(binding.tag5_chain_checksum)
                    && revision_two.revision == 2
                    && revision_two.predecessor_revision == Some(1)
                    && revision_two.predecessor_chain_checksum
                        == Some(revision_one.chain_checksum))
                    && head
                        .transition_context()
                        .native_valid_transition()
                        .is_some()
            }
            _ => false,
        };
        let current_revision = head.revision();
        if (current_revision != target_revision
            && current_revision.checked_add(1) != Some(target_revision))
            || head
                .state()
                .authenticated_genesis_application_parent_v0()
                .is_none_or(|parent| parent.binding_ref_v0() != binding.carrier_binding_ref)
            || self.profile.core_config_ref()? != binding.safety_state_record_config_ref
            || !lineage_matches
        {
            return Err(
                SafetyStoreErrorV0::AuthenticatedGenesisApplicationH1OfflinePersistenceMismatch {
                    expected_revision: target_revision,
                    actual_revision: head.revision(),
                },
            );
        }
        if head.revision() == 0
            && (head.state_record_checksum() != binding.tag5_state_record_checksum
                || head.transition_context_checksum() != binding.tag5_transition_context_checksum)
        {
            return Err(
                SafetyStoreErrorV0::AuthenticatedGenesisApplicationH1OfflinePersistenceMismatch {
                    expected_revision: target_revision,
                    actual_revision: head.revision(),
                },
            );
        }
        Ok(())
    }

    /// Stable identifier of this journal namespace.
    ///
    /// An unrelated fresh store receives a different value. A complete
    /// namespace clone retains it, so callers must not treat this as an
    /// external anti-rollback watermark.
    pub const fn journal_id_v0(&self) -> [u8; 32] {
        self.journal_id
    }

    /// Verifier/profile identity bound into every record in this store.
    pub const fn verifier_profile_ref_v0(&self) -> [u8; 32] {
        self.profile.verifier_profile_ref()
    }

    fn authenticated_head_with_retained_records_v0(
        &self,
    ) -> Result<(RecoveredSafetyStateV0, ValidatedRetainedRecordsV0), SafetyStoreErrorV0> {
        self.ensure_file_identity()?;
        self.ensure_not_halted()?;
        validate_transaction_environment(&self.connection, &self.profile, self.journal_id)?;
        validate_storage_resource_bounds(&self.connection, &self.profile)?;
        let retained = validate_all_records(
            &self.connection,
            &self.profile,
            &self.verifier,
            self.journal_id,
        )?;
        let (active_revision, active_checksum, _) = read_head(&self.connection, self.journal_id)?;
        if active_revision != self.observed_head_revision
            || active_checksum != self.observed_head_chain_checksum
        {
            return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                "head differs from durable lock watermark",
            ));
        }
        let row = read_active_record(&self.connection)?;
        if row.chain_checksum != active_checksum {
            return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                "active head checksum does not identify active record",
            ));
        }
        let recovered = decode_and_validate_record(&row, &self.profile, &self.verifier)?;
        self.postcheck_primary_resources()?;
        Ok((recovered, retained))
    }

    pub fn head(&self) -> Result<RecoveredSafetyStateV0, SafetyStoreErrorV0> {
        self.authenticated_head_with_retained_records_v0()
            .map(|(head, _retained)| head)
    }

    /// Confirms the current authenticated head for a future external
    /// Safety/App/signer checkpoint join.
    ///
    /// Every call reruns the complete authenticated-head validation and exact
    /// durable readback. The caller-held state is comparison input only; a
    /// foreign or stale state cannot produce a capability. This operation is
    /// inert and does not bind Core or change the journal revision.
    pub fn confirm_node_checkpoint_head_exact_v0(
        &self,
        expected_state: &SafetyState,
    ) -> Result<ConfirmedSafetyNodeCheckpointFactsV0, SafetyStoreErrorV0> {
        let head = self.head()?;
        if head.state() != expected_state {
            return Err(SafetyStoreErrorV0::SafetyNodeCheckpointHeadMismatch {
                expected_revision: expected_state.revision(),
                actual_revision: head.revision(),
            });
        }
        Ok(
            ConfirmedSafetyNodeCheckpointFactsV0::from_authenticated_head(
                self.journal_id,
                self.profile.verifier_profile_ref(),
                self.profile.core_config_ref()?,
                head,
                Arc::clone(&self.owner_affinity),
            ),
        )
    }

    /// Returns a non-forgeable capability for the authenticated revision-zero
    /// tag-4 state-sync bootstrap head.
    pub fn confirmed_state_sync_checkpoint_bootstrap_head_v0(
        &self,
    ) -> Result<ConfirmedStateSyncCheckpointBootstrapHeadV0, SafetyStoreErrorV0> {
        ConfirmedStateSyncCheckpointBootstrapHeadV0::from_authenticated_head(
            self.journal_id,
            self.profile.verifier_profile_ref(),
            self.head()?,
        )
    }

    /// Returns the tag-4 capability only when its authenticated state exactly
    /// equals Core's caller-held prepared state. The context-to-record checksum
    /// join is independently revalidated by the complete `head()` path.
    pub fn confirmed_state_sync_checkpoint_bootstrap_head_exact_v0(
        &self,
        expected_state: &SafetyState,
    ) -> Result<ConfirmedStateSyncCheckpointBootstrapHeadV0, SafetyStoreErrorV0> {
        let confirmed = self.confirmed_state_sync_checkpoint_bootstrap_head_v0()?;
        if confirmed.state() != expected_state {
            return Err(
                SafetyStoreErrorV0::StateSyncCheckpointBootstrapHeadMismatch {
                    expected_revision: expected_state.revision(),
                    actual_revision: confirmed.revision(),
                },
            );
        }
        Ok(confirmed)
    }

    /// Returns a one-shot capability for this exact live tag-5 head.
    pub fn confirmed_authenticated_genesis_application_bootstrap_head_v0(
        &self,
    ) -> Result<ConfirmedAuthenticatedGenesisApplicationBootstrapHeadV0, SafetyStoreErrorV0> {
        ConfirmedAuthenticatedGenesisApplicationBootstrapHeadV0::from_authenticated_head(
            self.database_path.clone(),
            self.journal_id,
            self.profile.verifier_profile_ref(),
            self.profile.core_config_ref()?,
            self.head()?,
            Arc::clone(&self.owner_affinity),
        )
    }

    /// Mints the tag-5 capability only when the live journal head equals every
    /// Core-prepared comparison fact and exact canonical record configuration.
    pub fn confirmed_authenticated_genesis_application_bootstrap_head_exact_v0(
        &self,
        expected: &PreparedAuthenticatedGenesisApplicationBootstrapV0,
    ) -> Result<ConfirmedAuthenticatedGenesisApplicationBootstrapHeadV0, SafetyStoreErrorV0> {
        let confirmed = self.confirmed_authenticated_genesis_application_bootstrap_head_v0()?;
        if confirmed.state_v0() != expected.safety_state()
            || confirmed.core_config_ref_v0() != expected.safety_state_record_config_ref_v0()
            || confirmed.transition_v0().carrier()
                != expected.authenticated_genesis_application_parent_v0()
            || confirmed.transition_v0().carrier_binding_ref()
                != expected
                    .authenticated_genesis_application_parent_v0()
                    .binding_ref_v0()
            || confirmed.transition_v0().state_record_checksum()
                != confirmed.state_record_checksum_v0()
        {
            return Err(
                SafetyStoreErrorV0::AuthenticatedGenesisApplicationBootstrapHeadMismatch {
                    expected_revision: expected.safety_state().revision(),
                    actual_revision: confirmed.revision_v0(),
                },
            );
        }
        Ok(confirmed)
    }

    /// Returns a non-forgeable capability for the current authenticated native
    /// deterministic-invalid head.
    ///
    /// The full `head()` validation path runs on every call. An Ordinary head
    /// is a typed failure and never produces a capability.
    pub fn confirmed_native_deterministic_invalid_head_v0(
        &self,
    ) -> Result<ConfirmedNativeDeterministicInvalidHeadV0, SafetyStoreErrorV0> {
        ConfirmedNativeDeterministicInvalidHeadV0::from_authenticated_head(
            self.journal_id,
            self.profile.verifier_profile_ref(),
            self.head()?,
        )
    }

    /// Returns the same capability only when the authenticated readback is
    /// byte-semantically equal to the caller's exact expected state and
    /// transition context.
    ///
    /// This comparison does not trust the expected values: the authoritative
    /// side is still produced by the complete `head()` validation path.
    pub fn confirmed_native_deterministic_invalid_head_exact_v0(
        &self,
        expected_state: &SafetyState,
        expected_context: &SafetyTransitionContextV0,
    ) -> Result<ConfirmedNativeDeterministicInvalidHeadV0, SafetyStoreErrorV0> {
        let confirmed = self.confirmed_native_deterministic_invalid_head_v0()?;
        if confirmed.state() != expected_state || confirmed.transition_context() != expected_context
        {
            return Err(SafetyStoreErrorV0::NativeDeterministicInvalidHeadMismatch {
                expected_revision: expected_state.revision(),
                actual_revision: confirmed.revision(),
            });
        }
        Ok(confirmed)
    }

    /// Returns a non-forgeable capability for the current authenticated native
    /// Valid head.
    ///
    /// The full `head()` validation path runs on every call. Ordinary and
    /// deterministic-invalid heads are typed failures and never produce a
    /// capability.
    pub fn confirmed_native_valid_head_v0(
        &self,
    ) -> Result<ConfirmedNativeValidHeadV0, SafetyStoreErrorV0> {
        ConfirmedNativeValidHeadV0::from_authenticated_head(
            self.journal_id,
            self.profile.verifier_profile_ref(),
            self.head()?,
            Arc::clone(&self.owner_affinity),
        )
    }

    /// Returns the same capability only when the authenticated readback is
    /// byte-semantically equal to the caller's exact expected state and
    /// transition context.
    ///
    /// This comparison does not trust the expected values: the authoritative
    /// side is still produced by the complete `head()` validation path.
    pub fn confirmed_native_valid_head_exact_v0(
        &self,
        expected_state: &SafetyState,
        expected_context: &SafetyTransitionContextV0,
    ) -> Result<ConfirmedNativeValidHeadV0, SafetyStoreErrorV0> {
        let confirmed = self.confirmed_native_valid_head_v0()?;
        if confirmed.state() != expected_state || confirmed.transition_context() != expected_context
        {
            return Err(SafetyStoreErrorV0::NativeValidHeadMismatch {
                expected_revision: expected_state.revision(),
                actual_revision: confirmed.revision(),
            });
        }
        Ok(confirmed)
    }

    /// Returns the exact authenticated tag-5/rev1 states for Core's dedicated
    /// h1 obligation-takeover constructor. This is not a generic head
    /// readback: it admits only the configured authenticated parent, retained
    /// tag-5 revision zero, Ordinary revision one, and one still-uncompleted
    /// Synced h1 validation obligation.
    pub fn authenticated_genesis_application_h1_obligation_lineage_readback_v0(
        &self,
    ) -> Result<AuthenticatedGenesisApplicationH1ObligationLineageReadbackV0, SafetyStoreErrorV0>
    {
        let configured_parent = self
            .profile
            .core_config()
            .authenticated_genesis_application_parent_v0()
            .copied()
            .ok_or(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                "h1 obligation lineage lacks its configured authenticated parent",
            ))?;
        let (head, retained) = self.authenticated_head_with_retained_records_v0()?;
        let [revision_zero, revision_one] = retained.recovered_records.as_slice() else {
            return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                "authenticated-genesis h1 obligation requires retained rev0/rev1 records",
            ));
        };
        let Some(tag5) = revision_zero
            .transition_context()
            .authenticated_genesis_application_bootstrap_transition()
        else {
            return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                "authenticated-genesis h1 obligation retained revision zero is not tag-5",
            ));
        };
        let [obligation] = revision_one.state().payload_validation_obligations() else {
            return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                "authenticated-genesis h1 obligation head must contain one obligation",
            ));
        };
        if revision_zero.revision() != 0
            || revision_one.revision() != 1
            || revision_one != &head
            || !matches!(
                revision_one.transition_context(),
                SafetyTransitionContextV0::Ordinary
            )
            || tag5.transition_revision() != 0
            || tag5.carrier() != configured_parent
            || tag5.carrier_binding_ref() != configured_parent.binding_ref_v0()
            || revision_zero
                .state()
                .authenticated_genesis_application_parent_v0()
                .copied()
                != Some(configured_parent)
            || revision_one
                .state()
                .authenticated_genesis_application_parent_v0()
                .copied()
                != Some(configured_parent)
            || obligation.route() != PayloadValidationRouteV0::Synced
            || obligation.first_recorded_revision() != 1
            || !revision_one
                .state()
                .payload_validation_completions()
                .is_empty()
            || !revision_one.state().payload_terminal_facts().is_empty()
        {
            return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                "authenticated-genesis h1 obligation retained lineage is not exact",
            ));
        }
        Ok(
            AuthenticatedGenesisApplicationH1ObligationLineageReadbackV0 {
                revision_zero: revision_zero.state().clone(),
                revision_one: revision_one.state().clone(),
            },
        )
    }

    /// Classifies one already-open live owner without error-driven fallback.
    /// The head and retained records are authenticated once and the active
    /// revision selects one exact structural validator below.
    pub fn authenticated_genesis_application_h1_existing_cut_v0(
        &self,
    ) -> Result<AuthenticatedGenesisApplicationH1ExistingCutV0, SafetyStoreErrorV0> {
        let configured_parent = self
            .profile
            .core_config()
            .authenticated_genesis_application_parent_v0()
            .copied()
            .ok_or(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                "authenticated-genesis h1 dispatch lacks its configured parent",
            ))?;
        let (head, retained) = self.authenticated_head_with_retained_records_v0()?;
        match head.revision() {
            1 => {
                let [revision_zero, revision_one] = retained.recovered_records.as_slice() else {
                    return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                        "authenticated-genesis h1 obligation dispatch requires retained rev0/rev1 records",
                    ));
                };
                let Some(tag5) = revision_zero
                    .transition_context()
                    .authenticated_genesis_application_bootstrap_transition()
                else {
                    return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                        "authenticated-genesis h1 obligation dispatch retained revision zero is not tag-5",
                    ));
                };
                let [obligation] = revision_one.state().payload_validation_obligations() else {
                    return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                        "authenticated-genesis h1 obligation dispatch requires one obligation",
                    ));
                };
                if revision_zero.revision() != 0
                    || revision_one.revision() != 1
                    || revision_one != &head
                    || !matches!(
                        revision_one.transition_context(),
                        SafetyTransitionContextV0::Ordinary
                    )
                    || tag5.transition_revision() != 0
                    || tag5.carrier() != configured_parent
                    || tag5.carrier_binding_ref() != configured_parent.binding_ref_v0()
                    || revision_zero
                        .state()
                        .authenticated_genesis_application_parent_v0()
                        .copied()
                        != Some(configured_parent)
                    || revision_one
                        .state()
                        .authenticated_genesis_application_parent_v0()
                        .copied()
                        != Some(configured_parent)
                    || obligation.route() != PayloadValidationRouteV0::Synced
                    || obligation.first_recorded_revision() != 1
                    || !revision_one
                        .state()
                        .payload_validation_completions()
                        .is_empty()
                    || !revision_one.state().payload_terminal_facts().is_empty()
                {
                    return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                        "authenticated-genesis h1 obligation dispatch lineage is not exact",
                    ));
                }
                Ok(
                    AuthenticatedGenesisApplicationH1ExistingCutV0::ObligationRev1(
                        AuthenticatedGenesisApplicationH1ObligationLineageReadbackV0 {
                            revision_zero: revision_zero.state().clone(),
                            revision_one: revision_one.state().clone(),
                        },
                    ),
                )
            }
            2 => {
                let [revision_one, revision_two] = retained.recovered_records.as_slice() else {
                    return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                        "authenticated-genesis h1 stable dispatch requires retained rev1/rev2 records",
                    ));
                };
                if revision_one.revision() != 1
                    || revision_two.revision() != 2
                    || revision_two != &head
                    || !matches!(
                        revision_one.transition_context(),
                        SafetyTransitionContextV0::Ordinary
                    )
                    || revision_two
                        .transition_context()
                        .native_valid_transition()
                        .is_none()
                    || revision_one
                        .state()
                        .authenticated_genesis_application_parent_v0()
                        .copied()
                        != Some(configured_parent)
                    || revision_two
                        .state()
                        .authenticated_genesis_application_parent_v0()
                        .copied()
                        != Some(configured_parent)
                {
                    return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                        "authenticated-genesis h1 stable dispatch lineage is not exact",
                    ));
                }
                Ok(
                    AuthenticatedGenesisApplicationH1ExistingCutV0::StableNativeValidRev2(
                        AuthenticatedGenesisApplicationH1StableNativeValidLineageReadbackV0 {
                            revision_one: revision_one.state().clone(),
                            revision_two: revision_two.state().clone(),
                        },
                    ),
                )
            }
            _ => Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                "authenticated-genesis h1 dispatch supports only exact rev1 obligation or rev2 NativeValid",
            )),
        }
    }

    /// Mints a live-owner capability only after reconstructing and checking
    /// every checksum in the retained tag-5 -> rev1 Ordinary lineage against
    /// Core's exact replay challenge. This operation is read-only and neither
    /// binds Core nor acknowledges the revision-one barrier.
    pub fn confirmed_authenticated_genesis_application_h1_obligation_head_exact_v0(
        &self,
        challenge: &AuthenticatedGenesisApplicationH1ObligationTakeoverChallengeV0,
    ) -> Result<ConfirmedAuthenticatedGenesisApplicationH1ObligationHeadV0, SafetyStoreErrorV0>
    {
        self.ensure_file_identity()?;
        if self.profile.core_config_ref()? != challenge.safety_state_record_config_ref_v0()
            || challenge.revision_zero_state_v0().revision() != 0
            || challenge.revision_one_state_v0().revision() != 1
            || challenge.barrier_v0() != BarrierId::new(1)
        {
            return Err(
                SafetyStoreErrorV0::AuthenticatedGenesisApplicationH1OfflineBindingMismatch,
            );
        }
        let (head, retained) = self.authenticated_head_with_retained_records_v0()?;
        let [revision_zero, revision_one] = retained.recovered_records.as_slice() else {
            return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                "h1 obligation capability requires retained rev0/rev1 records",
            ));
        };
        let [revision_zero_summary, revision_one_summary] = retained.records.as_slice() else {
            return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                "h1 obligation capability lacks retained checksum lineage",
            ));
        };
        let [obligation] = revision_one.state().payload_validation_obligations() else {
            return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                "h1 obligation capability requires one durable obligation",
            ));
        };
        let parent_binding_ref = obligation
            .parent_binding_ref_v0()
            .map_err(|error| SafetyStoreErrorV0::core("derive h1 obligation parent", error))?;
        if revision_zero.state() != challenge.revision_zero_state_v0()
            || revision_one.state() != challenge.revision_one_state_v0()
            || revision_one != &head
            || !matches!(
                revision_one.transition_context(),
                SafetyTransitionContextV0::Ordinary
            )
            || obligation.proposal() != challenge.proposal_v0()
            || obligation.id() != challenge.validation_id_v0()
            || parent_binding_ref != challenge.authenticated_parent_binding_ref_v0()
        {
            return Err(
                SafetyStoreErrorV0::AuthenticatedGenesisApplicationH1OfflinePersistenceMismatch {
                    expected_revision: 1,
                    actual_revision: head.revision(),
                },
            );
        }

        let tag5_state_record_checksum =
            encoded_state_record_checksum_v0(&self.profile, challenge.revision_zero_state_v0())?;
        let tag5_transition =
            AuthenticatedGenesisApplicationBootstrapTransitionV0::from_state_record_v0(
                challenge.revision_zero_state_v0(),
                tag5_state_record_checksum,
            )?;
        let tag5_context =
            SafetyTransitionContextV0::authenticated_genesis_application_bootstrap(tag5_transition);
        let tag5_prepared = prepare_record(
            &self.profile,
            &self.verifier,
            BarrierId::new(0),
            challenge.revision_zero_state_v0(),
            &tag5_context,
        )?;
        let revision_one_prepared = prepare_record(
            &self.profile,
            &self.verifier,
            challenge.barrier_v0(),
            challenge.revision_one_state_v0(),
            &SafetyTransitionContextV0::Ordinary,
        )?;
        let tag5_chain_checksum = chain_checksum(
            self.journal_id,
            0,
            None,
            None,
            tag5_prepared.state_record_checksum,
            tag5_prepared.transition_context_checksum,
        );
        let revision_one_chain_checksum = chain_checksum(
            self.journal_id,
            1,
            Some(0),
            Some(tag5_chain_checksum),
            revision_one_prepared.state_record_checksum,
            revision_one_prepared.transition_context_checksum,
        );
        if revision_zero_summary.revision != 0
            || revision_zero_summary.predecessor_revision.is_some()
            || revision_zero_summary.predecessor_chain_checksum.is_some()
            || revision_zero_summary.chain_checksum != tag5_chain_checksum
            || revision_one_summary.revision != 1
            || revision_one_summary.predecessor_revision != Some(0)
            || revision_one_summary.predecessor_chain_checksum != Some(tag5_chain_checksum)
            || revision_one_summary.chain_checksum != revision_one_chain_checksum
            || head.state_record_checksum() != revision_one_prepared.state_record_checksum
            || head.transition_context_checksum()
                != revision_one_prepared.transition_context_checksum
            || head.chain_checksum() != revision_one_chain_checksum
        {
            return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                "h1 obligation checksum lineage differs from tag-5 ancestry",
            ));
        }
        let (live_revision, live_chain_checksum, live_floor) =
            read_head(&self.connection, self.journal_id)?;
        if live_revision != 1
            || live_chain_checksum != revision_one_chain_checksum
            || live_floor != 0
        {
            return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                "h1 obligation live head tuple differs from retained lineage",
            ));
        }
        let tag5_head_checksum = head_checksum(self.journal_id, 0, tag5_chain_checksum, 0);
        let revision_one_head_checksum = head_checksum(
            self.journal_id,
            live_revision,
            live_chain_checksum,
            live_floor,
        );
        let safety_head_facts =
            AuthenticatedGenesisApplicationH1ObligationTakeoverSafetyHeadFactsV0::from_authenticated_store_comparison_v0(
                self.journal_id,
                self.profile.verifier_profile_ref(),
                self.profile.core_config_ref()?,
                tag5_prepared.state_record_checksum,
                tag5_prepared.transition_context_checksum,
                tag5_chain_checksum,
                revision_one_prepared.state_record_checksum,
                revision_one_prepared.transition_context_checksum,
                revision_one_chain_checksum,
                tag5_head_checksum,
                revision_one_head_checksum,
                challenge.barrier_v0(),
                challenge.validation_id_v0(),
                challenge.authenticated_parent_binding_ref_v0(),
            )
            .map_err(|error| SafetyStoreErrorV0::core("construct h1 obligation Safety facts", error))?;
        self.ensure_file_identity()?;
        Ok(ConfirmedAuthenticatedGenesisApplicationH1ObligationHeadV0 {
            database_path: self.database_path.clone(),
            safety_head_facts,
            state: head.state().clone(),
            transition_context: head.transition_context().clone(),
            live_revision,
            live_chain_checksum,
            live_floor,
            lock_watermark: self.observed_lock_watermark,
            owner_affinity: Arc::clone(&self.owner_affinity),
        })
    }

    /// Returns the exact authenticated rev1/rev2 states for Core's dedicated
    /// stable h1 recovery constructor.  This is not a generic head readback:
    /// it admits only the configured authenticated parent, Ordinary rev1, and
    /// NativeValid rev2 retained pair.
    pub fn authenticated_genesis_application_h1_stable_native_valid_lineage_readback_v0(
        &self,
    ) -> Result<
        AuthenticatedGenesisApplicationH1StableNativeValidLineageReadbackV0,
        SafetyStoreErrorV0,
    > {
        let (head, retained) = self.authenticated_head_with_retained_records_v0()?;
        let [revision_one, revision_two] = retained.recovered_records.as_slice() else {
            return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                "stable authenticated-genesis h1 requires retained rev1/rev2 records",
            ));
        };
        if revision_one.revision() != 1
            || revision_two.revision() != 2
            || revision_two != &head
            || !matches!(
                revision_one.transition_context(),
                SafetyTransitionContextV0::Ordinary
            )
            || revision_two
                .transition_context()
                .native_valid_transition()
                .is_none()
            || revision_one
                .state()
                .authenticated_genesis_application_parent_v0()
                != self
                    .profile
                    .core_config()
                    .authenticated_genesis_application_parent_v0()
            || revision_two
                .state()
                .authenticated_genesis_application_parent_v0()
                != self
                    .profile
                    .core_config()
                    .authenticated_genesis_application_parent_v0()
        {
            return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                "stable authenticated-genesis h1 retained lineage is not exact",
            ));
        }
        Ok(
            AuthenticatedGenesisApplicationH1StableNativeValidLineageReadbackV0 {
                revision_one: revision_one.state().clone(),
                revision_two: revision_two.state().clone(),
            },
        )
    }

    /// Mints a live-owner capability only after reconstructing and checking
    /// every checksum in the pruned tag-5 -> rev1 Ordinary -> rev2 NativeValid
    /// lineage against Core's exact recovery challenge.
    pub fn confirmed_authenticated_genesis_application_h1_stable_native_valid_head_exact_v0(
        &self,
        challenge: &AuthenticatedGenesisApplicationH1StableNativeValidRecoveryChallengeV0,
    ) -> Result<ConfirmedAuthenticatedGenesisApplicationH1StableNativeValidHeadV0, SafetyStoreErrorV0>
    {
        self.ensure_file_identity()?;
        if self.profile.core_config_ref()? != challenge.safety_state_record_config_ref_v0()
            || challenge.revision_two_state_v0().revision() != 2
        {
            return Err(
                SafetyStoreErrorV0::AuthenticatedGenesisApplicationH1OfflineBindingMismatch,
            );
        }
        let (head, retained) = self.authenticated_head_with_retained_records_v0()?;
        let [revision_one, revision_two] = retained.recovered_records.as_slice() else {
            return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                "stable authenticated-genesis h1 capability requires retained rev1/rev2 records",
            ));
        };
        let [revision_one_summary, revision_two_summary] = retained.records.as_slice() else {
            return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                "stable authenticated-genesis h1 capability lacks retained checksum lineage",
            ));
        };
        if revision_one.state() != challenge.revision_one_state_v0()
            || revision_two.state() != challenge.revision_two_state_v0()
            || revision_two != &head
            || !matches!(
                revision_one.transition_context(),
                SafetyTransitionContextV0::Ordinary
            )
        {
            return Err(
                SafetyStoreErrorV0::AuthenticatedGenesisApplicationH1OfflinePersistenceMismatch {
                    expected_revision: 2,
                    actual_revision: head.revision(),
                },
            );
        }

        let tag5_state_checksum =
            encoded_state_record_checksum_v0(&self.profile, challenge.revision_zero_state_v0())?;
        let tag5_transition =
            AuthenticatedGenesisApplicationBootstrapTransitionV0::from_state_record_v0(
                challenge.revision_zero_state_v0(),
                tag5_state_checksum,
            )?;
        let tag5_context =
            SafetyTransitionContextV0::authenticated_genesis_application_bootstrap(tag5_transition);
        let tag5_prepared = prepare_record(
            &self.profile,
            &self.verifier,
            BarrierId::new(0),
            challenge.revision_zero_state_v0(),
            &tag5_context,
        )?;
        let revision_one_prepared = prepare_record(
            &self.profile,
            &self.verifier,
            BarrierId::new(1),
            challenge.revision_one_state_v0(),
            &SafetyTransitionContextV0::Ordinary,
        )?;
        let revision_two_prepared = prepare_record(
            &self.profile,
            &self.verifier,
            BarrierId::new(2),
            challenge.revision_two_state_v0(),
            head.transition_context(),
        )?;
        let tag5_chain_checksum = chain_checksum(
            self.journal_id,
            0,
            None,
            None,
            tag5_prepared.state_record_checksum,
            tag5_prepared.transition_context_checksum,
        );
        let revision_one_chain_checksum = chain_checksum(
            self.journal_id,
            1,
            Some(0),
            Some(tag5_chain_checksum),
            revision_one_prepared.state_record_checksum,
            revision_one_prepared.transition_context_checksum,
        );
        let revision_two_chain_checksum = chain_checksum(
            self.journal_id,
            2,
            Some(1),
            Some(revision_one_chain_checksum),
            revision_two_prepared.state_record_checksum,
            revision_two_prepared.transition_context_checksum,
        );
        if revision_one_summary.revision != 1
            || revision_one_summary.predecessor_revision != Some(0)
            || revision_one_summary.predecessor_chain_checksum != Some(tag5_chain_checksum)
            || revision_one_summary.chain_checksum != revision_one_chain_checksum
            || revision_two_summary.revision != 2
            || revision_two_summary.predecessor_revision != Some(1)
            || revision_two_summary.predecessor_chain_checksum != Some(revision_one_chain_checksum)
            || revision_two_summary.chain_checksum != revision_two_chain_checksum
            || head.state_record_checksum() != revision_two_prepared.state_record_checksum
            || head.transition_context_checksum()
                != revision_two_prepared.transition_context_checksum
            || head.chain_checksum() != revision_two_chain_checksum
        {
            return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                "stable authenticated-genesis h1 checksum lineage differs from tag-5 ancestry",
            ));
        }

        let transition = head
            .transition_context()
            .native_valid_transition()
            .ok_or(SafetyStoreErrorV0::MissingNativeValidTransition { revision: 2 })?;
        let delivery_facts = ApplicationNativeValidDeliveryFactsV0::new(
            transition.route(),
            transition.validation_id(),
            transition.request_fingerprint(),
            transition.job_immutable_checksum(),
            transition.application_host_config_ref(),
            transition.valid_result_checksum(),
            transition.callback_payload_checksum(),
            transition.idempotency_key(),
            transition.delivery_attempt(),
            transition.delivered_job_row_checksum(),
            transition.outbox_checksum(),
            NativeValidPostAckActionV0::from_code(transition.post_ack_action_code()).ok_or(
                SafetyStoreErrorV0::PersistedRepresentationMalformed(
                    "stable authenticated-genesis h1 has an unknown post-ack action",
                ),
            )?,
            transition.completion_revision(),
        )
        .map_err(|error| SafetyStoreErrorV0::core("reconstruct h1 delivery facts", error))?;
        let tag5_head_checksum = head_checksum(self.journal_id, 0, tag5_chain_checksum, 0);
        // `read_head` independently verifies the persisted head checksum over
        // its live revision/chain/floor tuple. Re-read it here so the current
        // rev2 checksum placed in the capability is that authenticated live
        // value, not merely a checksum self-reported from reconstructed rows.
        let (live_revision, live_chain_checksum, live_floor) =
            read_head(&self.connection, self.journal_id)?;
        if live_revision != 2
            || live_chain_checksum != revision_two_chain_checksum
            || live_floor != 1
        {
            return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                "stable authenticated-genesis h1 live head tuple differs from retained lineage",
            ));
        }
        let revision_two_head_checksum = head_checksum(
            self.journal_id,
            live_revision,
            live_chain_checksum,
            live_floor,
        );
        let safety_head_facts =
            AuthenticatedGenesisApplicationH1StableNativeValidSafetyHeadFactsV0::from_authenticated_store_comparison_v0(
                self.journal_id,
                self.profile.verifier_profile_ref(),
                self.profile.core_config_ref()?,
                tag5_prepared.state_record_checksum,
                tag5_prepared.transition_context_checksum,
                tag5_chain_checksum,
                revision_one_prepared.state_record_checksum,
                revision_one_prepared.transition_context_checksum,
                revision_one_chain_checksum,
                revision_two_prepared.state_record_checksum,
                revision_two_prepared.transition_context_checksum,
                revision_two_chain_checksum,
                tag5_head_checksum,
                revision_two_head_checksum,
                challenge.completion_carrier_checksum_v0(),
                delivery_facts,
            )
            .map_err(|error| SafetyStoreErrorV0::core("construct stable h1 Safety facts", error))?;
        self.ensure_file_identity()?;
        Ok(
            ConfirmedAuthenticatedGenesisApplicationH1StableNativeValidHeadV0 {
                database_path: self.database_path.clone(),
                safety_head_facts,
                state: head.state().clone(),
                transition_context: head.transition_context().clone(),
                owner_affinity: Arc::clone(&self.owner_affinity),
            },
        )
    }

    /// Reconstructs and authenticates the pruned h2 NativeValid transition
    /// committed beneath one current anchored rev4 head.
    ///
    /// The challenge supplies Core-authenticated h2/h3 bodies and the exact
    /// current SafetyState. `historical_transition` is only a preimage: every
    /// checksum and record in rev0→rev1→rev2 is recomputed under this store's
    /// profile and journal ID, then compared with the retained rev3 record's
    /// predecessor chain checksum. A stale, foreign, or field-tampered
    /// transition therefore cannot produce this capability.
    pub fn confirm_anchored_successor_h2_transition_from_rev4_v0(
        &self,
        challenge: &StateSyncAnchorSuccessorRecoveryChallengeV0,
        historical_transition: &NativeValidTransitionV0,
    ) -> Result<ConfirmedAnchoredSuccessorHistoricalValidV0, SafetyStoreErrorV0> {
        if challenge.phase() != StateSyncAnchorSuccessorPhaseV0::H3Valid {
            return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                "historical h2 transition proof requires anchored rev4",
            ));
        }
        let (head, retained) = self.authenticated_head_with_retained_records_v0()?;
        let [revision_three, revision_four] = retained.records.as_slice() else {
            return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                "anchored rev4 historical proof lacks the retained rev3 predecessor",
            ));
        };
        if head.state() != challenge.safety_state()
            || head.revision() != 4
            || revision_three.revision != 3
            || revision_four.revision != 4
            || historical_transition.completion_revision() != 2
        {
            return Err(SafetyStoreErrorV0::NativeValidHeadMismatch {
                expected_revision: challenge.safety_state().revision(),
                actual_revision: head.revision(),
            });
        }

        let states = reconstruct_h1_state_sync_anchor_successor_prefix_v0(
            self.profile.core_config(),
            challenge,
            &self.verifier,
        )
        .map_err(|error| {
            SafetyStoreErrorV0::core("reconstruct anchored successor prefix", error)
        })?;
        let [revision_zero, revision_one, revision_two] = states.as_slice() else {
            unreachable!("the private reconstruction always returns rev0, rev1, and rev2")
        };
        let reconstructed_bootstrap =
            PreparedH1StateSyncBootstrapV0::from_authenticated_anchor_state_v0(
                self.profile.core_config(),
                revision_zero.clone(),
                &self.verifier,
            )
            .map_err(|error| {
                SafetyStoreErrorV0::core("rewrap reconstructed h1 bootstrap", error)
            })?;
        let bootstrap = prepare_h1_state_sync_bootstrap_record_v0(
            &self.profile,
            &self.verifier,
            &reconstructed_bootstrap,
        )?;
        let stored_zero = stored_record_from_prepared(&bootstrap, None, None, self.journal_id);
        let ordinary = prepare_record(
            &self.profile,
            &self.verifier,
            BarrierId::new(1),
            revision_one,
            &SafetyTransitionContextV0::Ordinary,
        )?;
        let stored_one = stored_record_from_prepared(
            &ordinary,
            Some(0),
            Some(stored_zero.chain_checksum),
            self.journal_id,
        );
        let historical_context =
            SafetyTransitionContextV0::native_valid(historical_transition.clone());
        let native_valid = prepare_record(
            &self.profile,
            &self.verifier,
            BarrierId::new(2),
            revision_two,
            &historical_context,
        )?;
        let stored_two = stored_record_from_prepared(
            &native_valid,
            Some(1),
            Some(stored_one.chain_checksum),
            self.journal_id,
        );
        if revision_three.predecessor_revision != Some(2)
            || revision_three.predecessor_chain_checksum != Some(stored_two.chain_checksum)
        {
            return Err(SafetyStoreErrorV0::NativeValidHeadMismatch {
                expected_revision: 2,
                actual_revision: head.revision(),
            });
        }

        Ok(ConfirmedAnchoredSuccessorHistoricalValidV0 {
            journal_id: self.journal_id,
            verifier_profile_ref: self.profile.verifier_profile_ref(),
            current_state_record_checksum: head.state_record_checksum(),
            current_chain_checksum: head.chain_checksum(),
            reconstructed_state_record_checksum: native_valid.state_record_checksum,
            transition: historical_transition.clone(),
            transition_checksum: native_valid.transition_context_checksum,
            reconstructed_chain_checksum: stored_two.chain_checksum,
        })
    }

    /// Returns a non-cloneable exact-readback capability only when the
    /// authenticated current head carries tag-3 finalization-applied context.
    pub fn confirmed_native_finalization_applied_head_v0(
        &self,
    ) -> Result<ConfirmedNativeFinalizationAppliedHeadV0, SafetyStoreErrorV0> {
        let (head, retained) = self.authenticated_head_with_retained_records_v0()?;
        let consumed_finalization = retained.consumed_finalization.ok_or(
            SafetyStoreErrorV0::PersistedRepresentationMalformed(
                "tag-3 transition context has no authenticated consumed queue front",
            ),
        )?;
        ConfirmedNativeFinalizationAppliedHeadV0::from_authenticated_head(
            self.journal_id,
            self.profile.verifier_profile_ref(),
            head,
            consumed_finalization,
        )
    }

    pub fn confirmed_native_finalization_applied_head_exact_v0(
        &self,
        expected_state: &SafetyState,
        expected_context: &SafetyTransitionContextV0,
    ) -> Result<ConfirmedNativeFinalizationAppliedHeadV0, SafetyStoreErrorV0> {
        let confirmed = self.confirmed_native_finalization_applied_head_v0()?;
        if confirmed.state() != expected_state || confirmed.transition_context() != expected_context
        {
            return Err(SafetyStoreErrorV0::NativeFinalizationAppliedHeadMismatch {
                expected_revision: expected_state.revision(),
                actual_revision: confirmed.revision(),
            });
        }
        Ok(confirmed)
    }

    /// Preflights the exact Core-owned finalization transition, including the
    /// authenticated predecessor currently stored in this journal, without
    /// beginning a writer transaction.
    pub fn preflight_bound_native_finalization_applied_persistence_v0(
        &self,
        request: &SafetyStatePersistenceV0,
    ) -> Result<NativeFinalizationAppliedSafetyStatePreflightV0, SafetyStoreErrorV0> {
        let binding = self.ordinary_core_binding_v0()?;
        if !binding.accepts(request) {
            return Err(SafetyStoreErrorV0::CoreAffinityMismatch);
        }
        let revision = request.state().revision();
        if request.barrier().get() != revision {
            return Err(SafetyStoreErrorV0::InvalidProfile(
                "barrier does not equal SafetyState revision",
            ));
        }
        let manifest = request
            .native_finalization_applied_v0()
            .ok_or(SafetyStoreErrorV0::MissingNativeFinalizationAppliedManifest { revision })?;
        if request.native_valid_post_ack_action_v0().is_some() {
            return Err(SafetyStoreErrorV0::NativeFinalizationAppliedManifestMismatch { revision });
        }
        validate_native_finalization_applied_successor_v0(revision, manifest, request.state())?;
        let predecessor = self.head()?;
        validate_native_finalization_applied_predecessor_v0(
            revision,
            manifest,
            predecessor.state(),
            request.state(),
        )?;
        Core::validate_persisted_state_v0(
            self.profile.core_config(),
            request.state(),
            &self.verifier,
        )
        .map_err(|error| {
            SafetyStoreErrorV0::core(
                "validate state during native finalization-applied preflight",
                error,
            )
        })?;
        let context = self.profile.record_context()?;
        let encoded =
            encode_safety_state_record_v0(request.state(), &context).map_err(|error| {
                SafetyStoreErrorV0::record(
                    "encode state during native finalization-applied preflight",
                    error,
                )
            })?;
        let decoded = decode_safety_state_record_v0_exact(&encoded, &context).map_err(|error| {
            SafetyStoreErrorV0::record(
                "read back native finalization-applied preflight state",
                error,
            )
        })?;
        Ok(NativeFinalizationAppliedSafetyStatePreflightV0 {
            journal_id: self.journal_id,
            verifier_profile_ref: self.profile.verifier_profile_ref(),
            revision,
            state_record_checksum: decoded.record_checksum(),
            manifest: manifest.clone(),
        })
    }

    /// Canonically projects an exact, bound native Valid persistence request
    /// without changing the journal or opening another namespace.
    pub fn preflight_bound_native_valid_persistence_v0(
        &self,
        request: &SafetyStatePersistenceV0,
    ) -> Result<NativeValidSafetyStatePreflightV0, SafetyStoreErrorV0> {
        let binding = self.ordinary_core_binding_v0()?;
        if !binding.accepts(request) {
            return Err(SafetyStoreErrorV0::CoreAffinityMismatch);
        }
        self.preflight_native_valid_request_v0(request)
    }

    fn preflight_native_valid_request_v0(
        &self,
        request: &SafetyStatePersistenceV0,
    ) -> Result<NativeValidSafetyStatePreflightV0, SafetyStoreErrorV0> {
        let revision = request.state().revision();
        if request.barrier().get() != revision {
            return Err(SafetyStoreErrorV0::InvalidProfile(
                "barrier does not equal SafetyState revision",
            ));
        }
        let post_ack_action = request
            .native_valid_post_ack_action_v0()
            .ok_or(SafetyStoreErrorV0::MissingNativeValidPostAckAction { revision })?;
        Core::validate_persisted_state_v0(
            self.profile.core_config(),
            request.state(),
            &self.verifier,
        )
        .map_err(|error| {
            SafetyStoreErrorV0::core("validate state during native Valid preflight", error)
        })?;
        let context = self.profile.record_context()?;
        let encoded =
            encode_safety_state_record_v0(request.state(), &context).map_err(|error| {
                SafetyStoreErrorV0::record("encode state during native Valid preflight", error)
            })?;
        let decoded = decode_safety_state_record_v0_exact(&encoded, &context).map_err(|error| {
            SafetyStoreErrorV0::record("read back native Valid preflight state", error)
        })?;
        Ok(NativeValidSafetyStatePreflightV0 {
            journal_id: self.journal_id,
            verifier_profile_ref: self.profile.verifier_profile_ref(),
            revision,
            state_record_checksum: decoded.record_checksum(),
            post_ack_action,
        })
    }

    /// Derives the only typed SafetyStore context accepted for a Core-owned
    /// anchored-ordinary promotion request.
    ///
    /// The state-record checksum is computed under this exact store profile;
    /// callers cannot select any transition field. Persistence still redoes
    /// every check against the authenticated active revision-four head.
    pub fn state_sync_anchor_ordinary_promotion_context_v0(
        &self,
        request: &SafetyStatePersistenceV0,
    ) -> Result<SafetyTransitionContextV0, SafetyStoreErrorV0> {
        let binding = self.ordinary_core_binding_v0()?;
        if !binding.accepts(request) {
            return Err(SafetyStoreErrorV0::CoreAffinityMismatch);
        }
        let manifest = request.state_sync_anchor_ordinary_promotion_v0().ok_or(
            SafetyStoreErrorV0::PersistedRepresentationMalformed(
                "state-sync promotion request lacks its Core manifest",
            ),
        )?;
        if request.native_valid_post_ack_action_v0().is_some()
            || request.native_finalization_applied_v0().is_some()
            || request.barrier().get() != request.state().revision()
            || manifest.transition_revision() != request.state().revision()
            || request
                .state()
                .state_sync_anchor()
                .is_none_or(|anchor| anchor.proof_id() != manifest.anchor_proof_id())
        {
            return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                "state-sync promotion request manifest differs from its Core state",
            ));
        }
        Core::validate_persisted_state_v0(
            self.profile.core_config(),
            request.state(),
            &self.verifier,
        )
        .map_err(|error| SafetyStoreErrorV0::core("validate state-sync promotion state", error))?;
        let state_record_checksum =
            encoded_state_record_checksum_v0(&self.profile, request.state())?;
        let facts = StateSyncAnchorOrdinaryPromotionTransitionV0::from_state_record_v0(
            request.state(),
            state_record_checksum,
        )?;
        Ok(SafetyTransitionContextV0::state_sync_anchor_ordinary_promotion(facts))
    }

    pub fn persist_exact_v0(
        &mut self,
        request: &SafetyStatePersistenceV0,
        transition_context: &SafetyTransitionContextV0,
    ) -> Result<SafetyPersistDispositionV0, SafetyStoreErrorV0> {
        let binding = self.ordinary_core_binding_v0()?;
        if !binding.accepts(request) {
            return Err(SafetyStoreErrorV0::CoreAffinityMismatch);
        }
        self.persist_bound_request_exact_v0(request, transition_context)
    }

    fn persist_bound_request_exact_v0(
        &mut self,
        request: &SafetyStatePersistenceV0,
        transition_context: &SafetyTransitionContextV0,
    ) -> Result<SafetyPersistDispositionV0, SafetyStoreErrorV0> {
        let manifest_count = usize::from(request.native_valid_post_ack_action_v0().is_some())
            + usize::from(request.native_finalization_applied_v0().is_some())
            + usize::from(request.state_sync_anchor_ordinary_promotion_v0().is_some());
        if manifest_count > 1 {
            return Err(
                SafetyStoreErrorV0::NativeFinalizationAppliedManifestMismatch {
                    revision: request.state().revision(),
                },
            );
        }
        validate_native_valid_post_ack_manifest_v0(
            request.state().revision(),
            request
                .native_valid_post_ack_action_v0()
                .map(|action| action.code()),
            transition_context,
        )?;
        validate_native_finalization_applied_manifest_v0(
            request.state().revision(),
            request.native_finalization_applied_v0(),
            transition_context,
        )?;
        validate_state_sync_anchor_ordinary_promotion_manifest_v0(request, transition_context)?;
        if let Some(manifest) = request.native_finalization_applied_v0() {
            validate_native_finalization_applied_successor_v0(
                request.state().revision(),
                manifest,
                request.state(),
            )?;
        }
        self.ensure_file_identity()?;
        self.ensure_not_halted()?;
        let barrier = request.barrier();
        let state = request.state();
        let prepared = prepare_record(
            &self.profile,
            &self.verifier,
            barrier,
            state,
            transition_context,
        )?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| SafetyStoreErrorV0::sqlite("begin persistence transaction", error))?;
        validate_transaction_environment(&transaction, &self.profile, self.journal_id)?;
        ensure_not_halted_connection(&transaction)?;
        validate_storage_resource_bounds(&transaction, &self.profile)?;
        validate_all_records(&transaction, &self.profile, &self.verifier, self.journal_id)?;
        let (active_revision, active_chain_checksum, retention_floor) =
            read_head(&transaction, self.journal_id)?;
        let stable_sequence = match self.observed_lock_watermark {
            LockWatermarkV0::Stable {
                sequence,
                journal_id,
                revision,
                chain_checksum,
            } if journal_id == self.journal_id
                && revision == active_revision
                && chain_checksum == active_chain_checksum =>
            {
                sequence
            }
            _ => {
                self.sticky_halt.store(true, Ordering::Release);
                return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                    "persistence began without an exact stable watermark",
                ));
            }
        };
        if active_revision != self.observed_head_revision
            || active_chain_checksum != self.observed_head_chain_checksum
        {
            self.sticky_halt.store(true, Ordering::Release);
            return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                "live head differs from durable lock watermark",
            ));
        }
        let active = read_active_record(&transaction)?;
        if active.revision != active_revision || active.chain_checksum != active_chain_checksum {
            self.sticky_halt.store(true, Ordering::Release);
            return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                "active head changed inside persistence transaction",
            ));
        }

        if prepared.revision == active_revision {
            if prepared_matches_stored(&prepared, &active) {
                transaction
                    .rollback()
                    .map_err(|error| SafetyStoreErrorV0::sqlite("finish exact retry", error))?;
                self.postcheck_primary_resources()?;
                return Ok(SafetyPersistDispositionV0::Existing);
            }
            return Err(commit_conflict(
                transaction,
                &self.sticky_halt,
                &mut self.lock_file,
                ObservedDurabilityStateV0 {
                    head_watermark: &mut self.observed_lock_watermark,
                    halt_latch: &mut self.observed_halt_latch,
                },
                ConflictStableHeadV0 {
                    sequence: stable_sequence,
                    journal_id: self.journal_id,
                    revision: active_revision,
                    chain_checksum: active_chain_checksum,
                },
                SafetyStoreConflictV0::SameRevisionDifferentRecord {
                    revision: prepared.revision,
                },
            ));
        }
        if prepared.revision < active_revision {
            return Err(commit_conflict(
                transaction,
                &self.sticky_halt,
                &mut self.lock_file,
                ObservedDurabilityStateV0 {
                    head_watermark: &mut self.observed_lock_watermark,
                    halt_latch: &mut self.observed_halt_latch,
                },
                ConflictStableHeadV0 {
                    sequence: stable_sequence,
                    journal_id: self.journal_id,
                    revision: active_revision,
                    chain_checksum: active_chain_checksum,
                },
                SafetyStoreConflictV0::RevisionRegression {
                    active: active_revision,
                    incoming: prepared.revision,
                },
            ));
        }
        if active_revision.checked_add(1) != Some(prepared.revision) {
            return Err(commit_conflict(
                transaction,
                &self.sticky_halt,
                &mut self.lock_file,
                ObservedDurabilityStateV0 {
                    head_watermark: &mut self.observed_lock_watermark,
                    halt_latch: &mut self.observed_halt_latch,
                },
                ConflictStableHeadV0 {
                    sequence: stable_sequence,
                    journal_id: self.journal_id,
                    revision: active_revision,
                    chain_checksum: active_chain_checksum,
                },
                SafetyStoreConflictV0::RevisionGap {
                    active: active_revision,
                    incoming: prepared.revision,
                },
            ));
        }
        let active_state =
            decode_and_validate_record(&active, &self.profile, &self.verifier)?.state;
        let application_applied_changed =
            active_state.application_applied() != state.application_applied();
        if application_applied_changed != request.native_finalization_applied_v0().is_some() {
            return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                "application-applied watermark and tag-3 Core manifest disagree",
            ));
        }
        if let Some(manifest) = request.native_finalization_applied_v0() {
            validate_native_finalization_applied_predecessor_v0(
                state.revision(),
                manifest,
                &active_state,
                state,
            )?;
        }
        Core::validate_persisted_successor_v0(
            self.profile.core_config(),
            &active_state,
            state,
            &self.verifier,
        )
        .map_err(|error| SafetyStoreErrorV0::core("validate incoming successor", error))?;
        validate_state_sync_anchor_ordinary_promotion_context_pair_v0(
            &active_state,
            state,
            transition_context,
        )?;

        if retention_floor < active_revision {
            let deleted = transaction
                .execute(
                    "DELETE FROM safety_state_records_v0 WHERE revision_be=?1",
                    params![retention_floor.to_be_bytes().as_slice()],
                )
                .map_err(|error| {
                    SafetyStoreErrorV0::sqlite("release retained floor record", error)
                })?;
            if deleted != 1 {
                self.sticky_halt.store(true, Ordering::Release);
                return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                    "retention floor did not identify one record",
                ));
            }
        }

        let row = stored_record_from_prepared(
            &prepared,
            Some(active_revision),
            Some(active_chain_checksum),
            self.journal_id,
        );
        insert_record(&transaction, &row)?;
        let retention_floor = active_revision;
        let head_checksum = head_checksum(
            self.journal_id,
            row.revision,
            row.chain_checksum,
            retention_floor,
        );
        let updated = transaction
            .execute(
                "UPDATE safety_state_head_v0
                 SET active_revision_be=?1, active_chain_checksum=?2,
                     retention_floor_revision_be=?3, head_checksum=?4
                 WHERE singleton=1 AND active_revision_be=?5 AND active_chain_checksum=?6",
                params![
                    row.revision.to_be_bytes().as_slice(),
                    row.chain_checksum.as_slice(),
                    retention_floor.to_be_bytes().as_slice(),
                    head_checksum.as_slice(),
                    active_revision.to_be_bytes().as_slice(),
                    active_chain_checksum.as_slice(),
                ],
            )
            .map_err(|error| SafetyStoreErrorV0::sqlite("advance active head", error))?;
        if updated != 1 {
            return Err(commit_conflict(
                transaction,
                &self.sticky_halt,
                &mut self.lock_file,
                ObservedDurabilityStateV0 {
                    head_watermark: &mut self.observed_lock_watermark,
                    halt_latch: &mut self.observed_halt_latch,
                },
                ConflictStableHeadV0 {
                    sequence: stable_sequence,
                    journal_id: self.journal_id,
                    revision: active_revision,
                    chain_checksum: active_chain_checksum,
                },
                SafetyStoreConflictV0::HeadChanged,
            ));
        }
        transaction
            .execute(
                "DELETE FROM safety_state_records_v0 WHERE revision_be < ?1",
                params![retention_floor.to_be_bytes().as_slice()],
            )
            .map_err(|error| SafetyStoreErrorV0::sqlite("prune old safety records", error))?;
        rewrite_accounting(&transaction)?;
        validate_storage_resource_bounds(&transaction, &self.profile)?;
        validate_all_records(&transaction, &self.profile, &self.verifier, self.journal_id)?;

        let readback = read_active_record(&transaction)?;
        if readback != row {
            self.sticky_halt.store(true, Ordering::Release);
            return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                "transactional record readback differs",
            ));
        }
        let decoded = decode_and_validate_record(&readback, &self.profile, &self.verifier)?;
        if decoded.state() != state || decoded.transition_context() != transition_context {
            self.sticky_halt.store(true, Ordering::Release);
            return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                "transactional semantic readback differs",
            ));
        }

        let intent_sequence = preflight_intent_sequence(stable_sequence)?;
        let intent = LockWatermarkV0::HeadIntent {
            sequence: intent_sequence,
            journal_id: self.journal_id,
            source_revision: active_revision,
            source_chain_checksum: active_chain_checksum,
            target_revision: row.revision,
            target_chain_checksum: row.chain_checksum,
        };
        // The durable intent must precede SQLite's commit marker. Its write
        // targets the other slot, preserving the last Stable watermark.
        if let Err(source) = write_lock_watermark(&mut self.lock_file, intent) {
            self.sticky_halt.store(true, Ordering::Release);
            return Err(SafetyStoreErrorV0::HeadWatermarkUncertain {
                source: Box::new(source),
            });
        }
        self.observed_lock_watermark = intent;

        match transaction.commit() {
            Ok(()) => {
                if let Err(source) = self.sync_confirmed_sqlite_commit() {
                    self.sticky_halt.store(true, Ordering::Release);
                    return Err(SafetyStoreErrorV0::HeadWatermarkUncertain {
                        source: Box::new(source),
                    });
                }
                self.resolve_head_watermark(row.revision, row.chain_checksum)?;
                Ok(SafetyPersistDispositionV0::Inserted)
            }
            Err(commit_error) => match self.confirm_stored_exact(&row) {
                Ok(ExactSafetyStateConfirmationV0::Exact) => {
                    if let Err(confirmation) = self.sync_confirmed_sqlite_commit() {
                        self.sticky_halt.store(true, Ordering::Release);
                        return Err(SafetyStoreErrorV0::CommitUncertain {
                            commit: commit_error,
                            confirmation: Box::new(confirmation),
                        });
                    }
                    self.resolve_head_watermark(row.revision, row.chain_checksum)?;
                    Ok(SafetyPersistDispositionV0::ConfirmedAfterCommitError)
                }
                Ok(ExactSafetyStateConfirmationV0::Absent) => {
                    self.resolve_head_watermark(active_revision, active_chain_checksum)?;
                    Err(SafetyStoreErrorV0::CommitNotApplied {
                        commit: commit_error,
                    })
                }
                Ok(ExactSafetyStateConfirmationV0::Conflict) => {
                    self.sticky_halt.store(true, Ordering::Release);
                    let conflict = SafetyStoreConflictV0::CommitReadbackConflict;
                    self.terminalize_head_intent(conflict)?;
                    Err(SafetyStoreErrorV0::Conflict(conflict))
                }
                Err(confirmation) => {
                    self.sticky_halt.store(true, Ordering::Release);
                    Err(SafetyStoreErrorV0::CommitUncertain {
                        commit: commit_error,
                        confirmation: Box::new(confirmation),
                    })
                }
            },
        }
    }

    fn confirm_stored_exact(
        &self,
        expected: &StoredRecordV0,
    ) -> Result<ExactSafetyStateConfirmationV0, SafetyStoreErrorV0> {
        self.ensure_file_identity()?;
        self.ensure_not_halted()?;
        if !self.connection.is_autocommit() {
            self.sticky_halt.store(true, Ordering::Release);
            return Ok(ExactSafetyStateConfirmationV0::Conflict);
        }
        let connection = &*self.connection;
        validate_transaction_environment(connection, &self.profile, self.journal_id)?;
        validate_storage_resource_bounds(connection, &self.profile)?;
        if durable_halt_present(connection)? {
            self.ensure_file_identity()?;
            return Ok(ExactSafetyStateConfirmationV0::Conflict);
        }
        validate_all_records(connection, &self.profile, &self.verifier, self.journal_id)?;
        self.ensure_file_identity()?;
        let (active_revision, active_chain_checksum, _) = read_head(connection, self.journal_id)?;
        let active = read_active_record(connection)?;
        let outcome = if active_revision == expected.revision {
            if active.chain_checksum == active_chain_checksum && active == *expected {
                ExactSafetyStateConfirmationV0::Exact
            } else {
                ExactSafetyStateConfirmationV0::Conflict
            }
        } else if expected.predecessor_revision == Some(active_revision)
            && expected.predecessor_chain_checksum == Some(active_chain_checksum)
            && connection
                .query_row(
                    "SELECT 1 FROM safety_state_records_v0 WHERE revision_be=?1",
                    params![expected.revision.to_be_bytes().as_slice()],
                    |_| Ok(()),
                )
                .optional()
                .map_err(|error| {
                    SafetyStoreErrorV0::sqlite("confirm absent target revision", error)
                })?
                .is_none()
        {
            ExactSafetyStateConfirmationV0::Absent
        } else {
            ExactSafetyStateConfirmationV0::Conflict
        };
        validate_storage_resource_bounds(connection, &self.profile)?;
        self.ensure_file_identity()?;
        Ok(outcome)
    }

    fn ensure_file_identity(&self) -> Result<(), SafetyStoreErrorV0> {
        if std::process::id() != self.owner_pid {
            return Err(SafetyStoreErrorV0::Conflict(
                SafetyStoreConflictV0::ProcessChanged,
            ));
        }
        let matches = (|| {
            let wal_path = sqlite_auxiliary_path(&self.database_path, "-wal");
            let shm_path = sqlite_auxiliary_path(&self.database_path, "-shm");
            validate_sqlite_auxiliary_files(
                &self.database_path,
                self.profile.maximum_database_bytes(),
            )?;
            validate_private_directory(&self.directory_path)?;
            Ok::<_, SafetyStoreErrorV0>(
                canonical_path_is_stable(&self.database_path)?
                    && canonical_path_is_stable(&self.lock_path)?
                    && canonical_path_is_stable(&self.directory_path)?
                    && canonical_path_is_stable(&wal_path)?
                    && canonical_path_is_stable(&shm_path)?
                    && file_identity(&self.database_path)? == self.database_identity
                    && file_identity(&self.lock_path)? == self.lock_identity
                    && file_identity(&wal_path)? == self.wal_identity
                    && file_identity(&shm_path)? == self.shm_identity
                    && directory_identity(&self.directory_path)? == self.directory_identity
                    && file_handle_identity(&self.database_file, &self.database_path)?
                        == self.database_identity
                    && file_handle_identity(&self.lock_file, &self.lock_path)?
                        == self.lock_identity
                    && file_handle_identity(&self.wal_file, &wal_path)? == self.wal_identity
                    && file_handle_identity(&self.shm_file, &shm_path)? == self.shm_identity
                    && directory_handle_identity(&self.directory_file, &self.directory_path)?
                        == self.directory_identity
                    && read_lock_watermark(&self.lock_file)? == self.observed_lock_watermark
                    && read_halt_latch(&self.lock_file)? == self.observed_halt_latch,
            )
        })();
        if !matches.unwrap_or(false) {
            self.sticky_halt.store(true, Ordering::Release);
            return Err(SafetyStoreErrorV0::Conflict(
                SafetyStoreConflictV0::FileIdentityChanged,
            ));
        }
        Ok(())
    }

    fn postcheck_primary_resources(&self) -> Result<(), SafetyStoreErrorV0> {
        self.ensure_file_identity()?;
        validate_storage_resource_bounds(&self.connection, &self.profile)
    }

    fn resolve_head_watermark(
        &mut self,
        revision: u64,
        chain_checksum: [u8; 32],
    ) -> Result<(), SafetyStoreErrorV0> {
        let sequence = self
            .observed_lock_watermark
            .sequence()
            .checked_add(1)
            .ok_or(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                "lock watermark sequence overflow",
            ))?;
        let stable = LockWatermarkV0::Stable {
            sequence,
            journal_id: self.journal_id,
            revision,
            chain_checksum,
        };
        if let Err(source) = write_lock_watermark(&mut self.lock_file, stable) {
            self.sticky_halt.store(true, Ordering::Release);
            return Err(SafetyStoreErrorV0::HeadWatermarkUncertain {
                source: Box::new(source),
            });
        }
        self.observed_lock_watermark = stable;
        self.observed_head_revision = revision;
        self.observed_head_chain_checksum = chain_checksum;
        self.postcheck_primary_resources()
    }

    fn terminalize_head_intent(
        &mut self,
        conflict: SafetyStoreConflictV0,
    ) -> Result<(), SafetyStoreErrorV0> {
        if !matches!(
            self.observed_lock_watermark,
            LockWatermarkV0::HeadIntent { .. }
        ) {
            return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                "commit conflict did not retain its head intent",
            ));
        }
        let latch = DurableHaltLatchV0 {
            head_watermark: self.observed_lock_watermark,
            halt: halt_fact_for_conflict(self.journal_id, conflict),
        };
        write_halt_latch(&mut self.lock_file, latch)
            .map_err(|source| conflict_halt_uncertain(conflict, source))?;
        self.observed_halt_latch = Some(latch);
        Ok(())
    }

    fn sync_confirmed_sqlite_commit(&self) -> Result<(), SafetyStoreErrorV0> {
        self.database_file
            .sync_all()
            .map_err(|error| SafetyStoreErrorV0::io("sync confirmed SQLite database", error))?;
        self.wal_file
            .sync_all()
            .map_err(|error| SafetyStoreErrorV0::io("sync confirmed SQLite WAL", error))?;
        self.directory_file
            .sync_all()
            .map_err(|error| SafetyStoreErrorV0::io("sync confirmed SQLite namespace", error))?;
        self.ensure_file_identity()
    }

    fn ensure_not_halted(&self) -> Result<(), SafetyStoreErrorV0> {
        if self.observed_halt_latch.is_some()
            || self.sticky_halt.load(Ordering::Acquire)
            || durable_halt_present(&self.connection)?
        {
            self.sticky_halt.store(true, Ordering::Release);
            return Err(SafetyStoreErrorV0::DurableHalt);
        }
        Ok(())
    }

    fn resolve_open_watermark(&mut self) -> Result<(), SafetyStoreErrorV0> {
        // No sidecar state, including a terminal halt, is trusted until the
        // SQLite schema, bindings, resource accounting, record chain, and
        // Core semantics have all passed deep validation.
        let (active_revision, active_chain_checksum, durable_halt) =
            self.validate_database_contents()?;
        let validated = validate_open_watermark_closure_v0(
            active_revision,
            active_chain_checksum,
            durable_halt,
            self.observed_lock_watermark,
            self.observed_halt_latch,
            self.journal_id,
        );
        let validated = match validated {
            Ok(validated) => validated,
            Err(SafetyStoreErrorV0::DurableHalt) => {
                self.observed_head_revision = active_revision;
                self.observed_head_chain_checksum = active_chain_checksum;
                self.sticky_halt.store(true, Ordering::Release);
                return Err(SafetyStoreErrorV0::DurableHalt);
            }
            Err(error) => return Err(error),
        };
        if validated.needs_head_resolution {
            self.sync_confirmed_sqlite_commit()?;
            self.resolve_head_watermark(validated.revision, validated.chain_checksum)
        } else {
            self.observed_head_revision = validated.revision;
            self.observed_head_chain_checksum = validated.chain_checksum;
            Ok(())
        }
    }

    fn validate_database_contents(
        &self,
    ) -> Result<(u64, [u8; 32], Option<DurableHaltFactV0>), SafetyStoreErrorV0> {
        self.ensure_file_identity()?;
        let validated = validate_database_contents_snapshot_v0(
            &self.connection,
            &self.profile,
            &self.verifier,
            self.journal_id,
        )?;
        self.ensure_file_identity()?;
        Ok(validated)
    }

    fn validate_database(&self) -> Result<(), SafetyStoreErrorV0> {
        let (active_revision, active_chain_checksum, _) = self.validate_database_contents()?;
        if !matches!(
            self.observed_lock_watermark,
            LockWatermarkV0::Stable {
                journal_id,
                revision,
                chain_checksum,
                ..
            } if journal_id == self.journal_id
                && revision == self.observed_head_revision
                && chain_checksum == self.observed_head_chain_checksum
        ) || active_revision != self.observed_head_revision
            || active_chain_checksum != self.observed_head_chain_checksum
        {
            return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                "database head differs from stable lock watermark",
            ));
        }
        Ok(())
    }
}

impl<V> Drop for SqliteSafetyStateStoreV0<V> {
    fn drop(&mut self) {
        if std::process::id() != self.owner_pid {
            // A post-fork child must not run SQLite cleanup or unlock inherited
            // open-file descriptions. The kernel reclaims these descriptors
            // when the unsupported child exits or execs.
            return;
        }
        // SAFETY: each field is initialized exactly once, wrapped immediately,
        // and dropped exactly here. SQLite must close before its pinned main,
        // WAL, SHM, and lock handles.
        unsafe {
            ManuallyDrop::drop(&mut self.connection);
            ManuallyDrop::drop(&mut self.shm_file);
            ManuallyDrop::drop(&mut self.wal_file);
            ManuallyDrop::drop(&mut self.database_file);
            ManuallyDrop::drop(&mut self.lock_file);
            ManuallyDrop::drop(&mut self.directory_file);
        }
    }
}

fn validate_authenticated_genesis_application_h1_obligation_v0(
    binding: &AuthenticatedGenesisApplicationH1OfflineBindingV0,
    carrier: &AuthenticatedGenesisApplicationH1ObligationPersistenceV0,
) -> Result<(), SafetyStoreErrorV0> {
    let request = carrier.persistence_v0();
    let state = request.state();
    let obligations = state.payload_validation_obligations();
    let [obligation] = obligations else {
        return Err(
            SafetyStoreErrorV0::AuthenticatedGenesisApplicationH1OfflinePersistenceMismatch {
                expected_revision: 1,
                actual_revision: state.revision(),
            },
        );
    };
    let configured_parent = binding
        .binding
        .authenticated_genesis_application_parent_v0();
    if state.revision() != 1
        || request.barrier().get() != 1
        || carrier.barrier_v0().get() != 1
        || carrier.validation_id_v0() != binding.binding.validation_id_v0()
        || request.native_valid_post_ack_action_v0().is_some()
        || request.native_finalization_applied_v0().is_some()
        || state.authenticated_genesis_application_parent_v0().copied() != Some(configured_parent)
        || obligation.route() != PayloadValidationRouteV0::Synced
        || obligation.id() != binding.binding.validation_id_v0()
        || obligation.proposal() != binding.binding.proposal_v0()
        || obligation
            .parent()
            .authenticated_genesis_application_parent_v0()
            != Some(configured_parent)
        || obligation.parent().provenance() != PayloadValidationParentProvenanceV0::Finalized
        || obligation.parent().tip().height().get() != 0
        || obligation.parent().tip().view().get() != 0
        || obligation.parent().tip().block_id() != configured_parent.genesis_block_id()
        || obligation.parent().tip().timestamp_ms() != configured_parent.timestamp_ms()
        || obligation.parent_binding_ref_v0().is_err()
        || obligation.first_recorded_revision() != 1
        || !state.payload_validation_completions().is_empty()
        || !state.payload_terminal_facts().is_empty()
    {
        return Err(
            SafetyStoreErrorV0::AuthenticatedGenesisApplicationH1OfflinePersistenceMismatch {
                expected_revision: 1,
                actual_revision: state.revision(),
            },
        );
    }
    Ok(())
}

fn validate_authenticated_genesis_application_h1_native_valid_v0(
    binding: &AuthenticatedGenesisApplicationH1OfflineBindingV0,
    sealed_transition: &ApplicationSealedNativeValidTransitionV0,
    transition: &NativeValidTransitionV0,
) -> Result<(), SafetyStoreErrorV0> {
    let carrier = sealed_transition.completion_persistence_v0();
    validate_authenticated_genesis_application_h1_native_valid_completion_v0(binding, carrier)?;
    let facts = sealed_transition.delivery_facts_v0();
    let validation_id = binding.binding.validation_id_v0();
    let [completion] = carrier
        .persistence_v0()
        .state()
        .payload_validation_completions()
    else {
        return Err(
            SafetyStoreErrorV0::AuthenticatedGenesisApplicationH1OfflinePersistenceMismatch {
                expected_revision: 2,
                actual_revision: carrier.persistence_v0().state().revision(),
            },
        );
    };
    if sealed_transition.carrier_checksum_v0() == [0; 32]
        || facts.route() != PayloadValidationRouteV0::Synced
        || facts.validation_id() != validation_id
        || facts.valid_result_checksum()
            != trnm_consensus_core::native_valid_result_checksum_v0(completion.result()).ok_or(
                SafetyStoreErrorV0::AuthenticatedGenesisApplicationH1OfflinePersistenceMismatch {
                    expected_revision: 2,
                    actual_revision: carrier.persistence_v0().state().revision(),
                },
            )?
        || transition.route() != facts.route()
        || transition.validation_id() != validation_id
        || transition.request_fingerprint() != facts.request_fingerprint()
        || transition.job_immutable_checksum() != facts.job_immutable_checksum()
        || transition.application_host_config_ref() != facts.application_host_config_ref()
        || transition.valid_result_checksum() != facts.valid_result_checksum()
        || transition.callback_payload_checksum() != facts.callback_payload_checksum()
        || transition.idempotency_key() != facts.idempotency_key()
        || transition.delivery_attempt() != facts.delivery_attempt()
        || transition.delivered_job_row_checksum() != facts.delivered_job_row_checksum()
        || transition.outbox_checksum() != facts.outbox_checksum()
        || transition.completion_revision() != facts.completion_revision()
        || transition.post_ack_action_code() != facts.post_ack_action().code()
    {
        return Err(
            SafetyStoreErrorV0::AuthenticatedGenesisApplicationH1OfflinePersistenceMismatch {
                expected_revision: 2,
                actual_revision: carrier.persistence_v0().state().revision(),
            },
        );
    }
    Ok(())
}

fn native_valid_transition_from_application_seal_v0(
    sealed_transition: &ApplicationSealedNativeValidTransitionV0,
) -> Result<NativeValidTransitionV0, SafetyStoreErrorV0> {
    let facts = sealed_transition.delivery_facts_v0();
    NativeValidTransitionV0::new(
        facts.route(),
        facts.validation_id(),
        facts.request_fingerprint(),
        facts.job_immutable_checksum(),
        facts.application_host_config_ref(),
        facts.valid_result_checksum(),
        facts.callback_payload_checksum(),
        facts.idempotency_key(),
        facts.delivery_attempt(),
        facts.delivered_job_row_checksum(),
        facts.outbox_checksum(),
        facts.post_ack_action().code(),
        facts.completion_revision(),
    )
}

fn validate_authenticated_genesis_application_h1_native_valid_completion_v0(
    binding: &AuthenticatedGenesisApplicationH1OfflineBindingV0,
    carrier: &AuthenticatedGenesisApplicationH1CompletionPersistenceV0,
) -> Result<(), SafetyStoreErrorV0> {
    let request = carrier.persistence_v0();
    let state = request.state();
    let completions = state.payload_validation_completions();
    let [completion] = completions else {
        return Err(
            SafetyStoreErrorV0::AuthenticatedGenesisApplicationH1OfflinePersistenceMismatch {
                expected_revision: 2,
                actual_revision: state.revision(),
            },
        );
    };
    let terminals = state.payload_terminal_facts();
    let [terminal] = terminals else {
        return Err(
            SafetyStoreErrorV0::AuthenticatedGenesisApplicationH1OfflinePersistenceMismatch {
                expected_revision: 2,
                actual_revision: state.revision(),
            },
        );
    };
    let configured_parent = binding
        .binding
        .authenticated_genesis_application_parent_v0();
    let validation_id = binding.binding.validation_id_v0();
    if state.revision() != 2
        || request.barrier().get() != 2
        || carrier.barrier_v0().get() != 2
        || carrier.validation_id_v0() != validation_id
        || request.native_valid_post_ack_action_v0() != Some(NativeValidPostAckActionV0::None)
        || request.native_finalization_applied_v0().is_some()
        || state.authenticated_genesis_application_parent_v0().copied() != Some(configured_parent)
        || !state.payload_validation_obligations().is_empty()
        || completion.route() != PayloadValidationRouteV0::Synced
        || completion.id() != validation_id
        || !completion.result().is_valid()
        || completion.first_recorded_revision() != 2
        || terminal.block_id() != validation_id.block_id()
        || terminal.result() != PayloadTerminalResult::Valid
        || terminal.first_recorded_revision() != 2
    {
        return Err(
            SafetyStoreErrorV0::AuthenticatedGenesisApplicationH1OfflinePersistenceMismatch {
                expected_revision: 2,
                actual_revision: state.revision(),
            },
        );
    }
    Ok(())
}

fn validate_native_valid_post_ack_manifest_v0(
    revision: u64,
    core_action_code: Option<u32>,
    transition_context: &SafetyTransitionContextV0,
) -> Result<(), SafetyStoreErrorV0> {
    let Some(transition) = transition_context.native_valid_transition() else {
        // State/context congruence is checked canonically by `prepare_record`.
        // In particular, an Ordinary or deterministic-invalid context cannot
        // accompany a newly recorded Valid completion. Core may attach one of
        // the same deferred action shapes to an unrelated transition, so the
        // manifest alone does not select the context variant.
        return Ok(());
    };
    let core_action_code =
        core_action_code.ok_or(SafetyStoreErrorV0::MissingNativeValidPostAckAction { revision })?;
    let context_action_code = transition.post_ack_action_code();
    if core_action_code != context_action_code {
        return Err(SafetyStoreErrorV0::NativeValidPostAckActionMismatch {
            revision,
            core_action_code,
            context_action_code,
        });
    }
    Ok(())
}

fn validate_native_finalization_applied_manifest_v0(
    revision: u64,
    core_manifest: Option<&NativeFinalizationAppliedPersistenceV0>,
    transition_context: &SafetyTransitionContextV0,
) -> Result<(), SafetyStoreErrorV0> {
    let context = transition_context.native_finalization_applied_transition();
    match (core_manifest, context) {
        (None, None) => Ok(()),
        (None, Some(_)) => {
            Err(SafetyStoreErrorV0::MissingNativeFinalizationAppliedManifest { revision })
        }
        (Some(_), None) => {
            Err(SafetyStoreErrorV0::MissingNativeFinalizationAppliedTransition { revision })
        }
        (Some(manifest), Some(context)) => {
            let readback = manifest.application_store_readback_v0();
            if context.source_route() != readback.source_route()
                || context.source_validation_id() != readback.source_validation_id()
                || context.ordinal() != readback.ordinal()
                || context.application_host_config_ref() != readback.application_host_config_ref()
                || context.finalization_checksum() != readback.finalization_checksum()
                || context.prior_head_checksum() != readback.prior_head_checksum()
                || context.new_head_checksum() != readback.new_head_checksum()
                || context.source_artifact_checksum() != readback.source_artifact_checksum()
                || context.accepted_source_checksum() != readback.accepted_source_checksum()
                || context.applied_job_row_checksum() != readback.applied_job_row_checksum()
                || context.receipt_row_checksum() != readback.receipt_row_checksum()
                || context.post_ack_action_code() != manifest.post_ack_action_v0().code()
                || context.completion_revision() != revision
            {
                return Err(
                    SafetyStoreErrorV0::NativeFinalizationAppliedManifestMismatch { revision },
                );
            }
            Ok(())
        }
    }
}

fn validate_state_sync_anchor_ordinary_promotion_manifest_v0(
    request: &SafetyStatePersistenceV0,
    transition_context: &SafetyTransitionContextV0,
) -> Result<(), SafetyStoreErrorV0> {
    let manifest = request.state_sync_anchor_ordinary_promotion_v0();
    let context = transition_context.state_sync_anchor_ordinary_promotion_transition();
    match (manifest, context) {
        (None, None) => Ok(()),
        (None, Some(_)) => Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
            "state-sync promotion context lacks its Core manifest",
        )),
        (Some(_), None) => Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
            "state-sync promotion Core manifest lacks its typed context",
        )),
        (Some(manifest), Some(context)) => {
            let anchor = request.state().state_sync_anchor().ok_or(
                SafetyStoreErrorV0::PersistedRepresentationMalformed(
                    "state-sync promotion request has no permanent anchor",
                ),
            )?;
            if request.state().revision() != 5
                || request.barrier().get() != 5
                || manifest.transition_revision() != 5
                || context.transition_revision() != 5
                || manifest.anchor_proof_id() != anchor.proof_id()
                || context.proof_id() != anchor.proof_id()
                || context.anchor_checksum() != state_sync_anchor_checksum_v0(anchor)
            {
                return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                    "state-sync promotion manifest, context, or state differs",
                ));
            }
            Ok(())
        }
    }
}

fn validate_native_finalization_applied_successor_v0(
    revision: u64,
    manifest: &NativeFinalizationAppliedPersistenceV0,
    successor_state: &SafetyState,
) -> Result<(), SafetyStoreErrorV0> {
    let readback = manifest.application_store_readback_v0();
    let predecessor = manifest.predecessor();
    let successor = manifest.successor();
    if successor_state.revision() != revision
        || successor_state.application_applied() != successor
        || predecessor.height().checked_next().ok() != Some(successor.height())
        || readback.ordinal() != successor.height().get()
        || readback.source_validation_id().block_id() != successor.block_id()
        || readback.source_validation_id().view() != successor.view()
        || successor_state
            .pending_finalization()
            .is_some_and(|front| front.authenticated_parent() != successor)
        || successor_state.pending_finalize()
            != successor_state
                .pending_finalization()
                .map(trnm_consensus_core::DurableFinalizationV0::proof_id)
        || !native_finalization_applied_action_matches_state_v0(
            manifest.post_ack_action_v0(),
            successor_state,
        )
    {
        return Err(SafetyStoreErrorV0::NativeFinalizationAppliedManifestMismatch { revision });
    }
    Ok(())
}

fn validate_native_finalization_applied_predecessor_v0(
    revision: u64,
    manifest: &NativeFinalizationAppliedPersistenceV0,
    predecessor_state: &SafetyState,
    successor_state: &SafetyState,
) -> Result<(), SafetyStoreErrorV0> {
    validate_native_finalization_applied_successor_v0(revision, manifest, successor_state)?;
    let Some(front) = predecessor_state.pending_finalization() else {
        return Err(SafetyStoreErrorV0::NativeFinalizationAppliedPredecessorMismatch { revision });
    };
    let expected_successor_queue = predecessor_state
        .finalization_queue()
        .get(1..)
        .ok_or(SafetyStoreErrorV0::NativeFinalizationAppliedPredecessorMismatch { revision })?;
    let exact_source_overlay = successor_state
        .payload_validation_completions()
        .iter()
        .filter(|completion| {
            completion.route() == manifest.application_store_readback_v0().source_route()
                && completion.id()
                    == manifest
                        .application_store_readback_v0()
                        .source_validation_id()
        })
        .filter_map(|completion| completion.result().artifact_ref())
        .filter(|artifact| {
            artifact.source_artifact_checksum()
                == manifest
                    .application_store_readback_v0()
                    .source_artifact_checksum()
        })
        .map(|artifact| artifact.overlay())
        .collect::<Vec<_>>();
    if predecessor_state.revision().checked_add(1) != Some(revision)
        || predecessor_state.application_applied() != manifest.predecessor()
        || front.authenticated_parent() != manifest.predecessor()
        || native_finalization_applied_checksum_v0(front)
            != Ok(manifest
                .application_store_readback_v0()
                .finalization_checksum())
        || !successor_state
            .finalization_queue()
            .starts_with(expected_successor_queue)
        || exact_source_overlay.as_slice() != [front.target_overlay_ref()]
    {
        return Err(SafetyStoreErrorV0::NativeFinalizationAppliedPredecessorMismatch { revision });
    }
    Ok(())
}

fn native_finalization_applied_action_matches_state_v0(
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
                .map(trnm_consensus_core::DurableFinalizationV0::proof_id);

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

fn validate_persisted_native_finalization_applied_pair_v0(
    transition: &NativeFinalizationAppliedTransitionV0,
    predecessor_state: &SafetyState,
    successor_state: &SafetyState,
) -> Result<(), SafetyStoreErrorV0> {
    let revision = successor_state.revision();
    let Some(action) =
        NativeFinalizationAppliedPostAckActionV0::from_code(transition.post_ack_action_code())
    else {
        return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
            "native finalization-applied transition action",
        ));
    };
    let Some(front) = predecessor_state.pending_finalization() else {
        return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
            "native finalization-applied transition has no predecessor queue front",
        ));
    };
    let expected_successor_queue = predecessor_state.finalization_queue().get(1..).ok_or(
        SafetyStoreErrorV0::PersistedRepresentationMalformed(
            "native finalization-applied transition queue",
        ),
    )?;
    let target = front.proof().finalized_block().header();
    let exact_source_overlays = successor_state
        .payload_validation_completions()
        .iter()
        .filter(|completion| {
            completion.route() == transition.source_route()
                && completion.id() == transition.source_validation_id()
        })
        .filter_map(|completion| completion.result().artifact_ref())
        .filter(|artifact| {
            artifact.source_artifact_checksum() == transition.source_artifact_checksum()
        })
        .map(|artifact| artifact.overlay())
        .collect::<Vec<_>>();
    if predecessor_state.revision().checked_add(1) != Some(revision)
        || transition.completion_revision() != revision
        || predecessor_state.application_applied() != front.authenticated_parent()
        || successor_state.application_applied().height() != target.height()
        || successor_state.application_applied().view() != target.view()
        || successor_state.application_applied().block_id() != target.id()
        || successor_state.application_applied().timestamp_ms() != target.timestamp_ms()
        || transition.ordinal() != target.height().get()
        || transition.source_validation_id().block_id() != target.id()
        || transition.source_validation_id().view() != target.view()
        || native_finalization_applied_checksum_v0(front) != Ok(transition.finalization_checksum())
        || exact_source_overlays.as_slice() != [front.target_overlay_ref()]
        || !successor_state
            .finalization_queue()
            .starts_with(expected_successor_queue)
        || successor_state.pending_finalize()
            != successor_state
                .pending_finalization()
                .map(trnm_consensus_core::DurableFinalizationV0::proof_id)
        || !native_finalization_applied_action_matches_state_v0(action, successor_state)
    {
        return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
            "native finalization-applied retained predecessor relation",
        ));
    }
    Ok(())
}

fn validate_application_applied_context_pair_v0(
    predecessor: &RecoveredSafetyStateV0,
    successor: &RecoveredSafetyStateV0,
) -> Result<(), SafetyStoreErrorV0> {
    let watermark_changed =
        predecessor.state().application_applied() != successor.state().application_applied();
    match (
        watermark_changed,
        successor
            .transition_context()
            .native_finalization_applied_transition(),
    ) {
        (false, None) => Ok(()),
        (true, Some(transition)) => validate_persisted_native_finalization_applied_pair_v0(
            transition,
            predecessor.state(),
            successor.state(),
        ),
        (true, None) => Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
            "application-applied watermark advanced without tag-3 transition context",
        )),
        (false, Some(_)) => Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
            "tag-3 transition context did not advance application-applied watermark",
        )),
    }
}

fn validate_state_sync_anchor_ordinary_promotion_context_pair_v0(
    predecessor: &SafetyState,
    successor: &SafetyState,
    successor_context: &SafetyTransitionContextV0,
) -> Result<(), SafetyStoreErrorV0> {
    let crossing_promotion = predecessor.state_sync_anchor().is_some()
        && predecessor.revision() == 4
        && successor.state_sync_anchor().is_some()
        && successor.revision() == 5;
    let transition = successor_context.state_sync_anchor_ordinary_promotion_transition();
    match (crossing_promotion, transition) {
        (false, None) => Ok(()),
        (true, Some(transition)) => {
            let predecessor_anchor = predecessor.state_sync_anchor().ok_or(
                SafetyStoreErrorV0::PersistedRepresentationMalformed(
                    "state-sync promotion predecessor lost its anchor",
                ),
            )?;
            let successor_anchor = successor.state_sync_anchor().ok_or(
                SafetyStoreErrorV0::PersistedRepresentationMalformed(
                    "state-sync promotion successor lost its anchor",
                ),
            )?;
            if predecessor_anchor != successor_anchor
                || transition.transition_revision() != successor.revision()
                || transition.proof_id() != successor_anchor.proof_id()
                || transition.anchor_checksum() != state_sync_anchor_checksum_v0(successor_anchor)
            {
                return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                    "state-sync promotion transition differs from its retained predecessor pair",
                ));
            }
            Ok(())
        }
        (true, None) => Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
            "revision-four to revision-five anchor promotion lacks tag-6 context",
        )),
        (false, Some(_)) => Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
            "tag-6 context does not cross the sole revision-four promotion predecessor",
        )),
    }
}

fn prepare_record<V: SignatureVerifier>(
    profile: &SafetyStateStoreProfileV0,
    verifier: &V,
    barrier: BarrierId,
    state: &SafetyState,
    transition_context: &SafetyTransitionContextV0,
) -> Result<PreparedRecordV0, SafetyStoreErrorV0> {
    if barrier.get() != state.revision() {
        return Err(SafetyStoreErrorV0::InvalidProfile(
            "barrier does not equal SafetyState revision",
        ));
    }
    Core::validate_persisted_state_v0(profile.core_config(), state, verifier)
        .map_err(|error| SafetyStoreErrorV0::core("validate state before persistence", error))?;
    let context = profile.record_context()?;
    let state_record_bytes = encode_safety_state_record_v0(state, &context)
        .map_err(|error| SafetyStoreErrorV0::record("encode state for persistence", error))?;
    let decoded = decode_safety_state_record_v0_exact(&state_record_bytes, &context)
        .map_err(|error| SafetyStoreErrorV0::record("read back encoded state", error))?;
    validate_transition_context_against_state_v0(transition_context, state)?;
    validate_transition_context_record_identity_v0(transition_context, decoded.record_checksum())?;
    let transition_context_bytes = encode_transition_context_v0(transition_context)?;
    let transition_context_checksum = transition_context_checksum_v0(&transition_context_bytes)?;
    Ok(PreparedRecordV0 {
        revision: state.revision(),
        state_record_checksum: decoded.record_checksum(),
        state_record_bytes,
        transition_context_bytes,
        transition_context_checksum,
    })
}

fn encoded_state_record_checksum_v0(
    profile: &SafetyStateStoreProfileV0,
    state: &SafetyState,
) -> Result<[u8; 32], SafetyStoreErrorV0> {
    let context = profile.record_context()?;
    let bytes = encode_safety_state_record_v0(state, &context)
        .map_err(|error| SafetyStoreErrorV0::record("encode bootstrap state", error))?;
    decode_safety_state_record_v0_exact(&bytes, &context)
        .map(|record| record.record_checksum())
        .map_err(|error| SafetyStoreErrorV0::record("read back bootstrap state", error))
}

fn prepare_h1_state_sync_bootstrap_record_v0<V: SignatureVerifier>(
    profile: &SafetyStateStoreProfileV0,
    verifier: &V,
    bootstrap: &PreparedH1StateSyncBootstrapV0,
) -> Result<PreparedRecordV0, SafetyStoreErrorV0> {
    let state = bootstrap.safety_state();
    if state.revision() != 0 || state.state_sync_anchor().is_none() {
        return Err(SafetyStoreErrorV0::InvalidProfile(
            "h1 state-sync bootstrap is not an anchored revision-zero state",
        ));
    }
    Core::validate_persisted_state_v0(profile.core_config(), state, verifier)
        .map_err(|error| SafetyStoreErrorV0::core("validate h1 bootstrap state", error))?;
    let _recovery_session = Core::begin_state_sync_anchor_recovery_v0(
        profile.core_config().clone(),
        state.clone(),
        verifier,
    )
    .map_err(|error| SafetyStoreErrorV0::core("prove h1 bootstrap state recoverable", error))?;
    let state_record_checksum = encoded_state_record_checksum_v0(profile, state)?;
    let transition = StateSyncCheckpointBootstrapTransitionV0::from_state_record_v0(
        state,
        state_record_checksum,
    )?;
    prepare_record(
        profile,
        verifier,
        BarrierId::new(0),
        state,
        &SafetyTransitionContextV0::state_sync_checkpoint_bootstrap(transition),
    )
}

fn prepare_authenticated_genesis_application_bootstrap_record_v0<V: SignatureVerifier>(
    profile: &SafetyStateStoreProfileV0,
    verifier: &V,
    bootstrap: &PreparedAuthenticatedGenesisApplicationBootstrapV0,
) -> Result<PreparedRecordV0, SafetyStoreErrorV0> {
    let state = bootstrap.safety_state();
    let carrier = bootstrap.authenticated_genesis_application_parent_v0();
    if state.revision() != 0
        || state.state_sync_anchor().is_some()
        || state.authenticated_genesis_application_parent_v0().copied() != Some(carrier)
        || profile
            .core_config()
            .authenticated_genesis_application_parent_v0()
            .copied()
            != Some(carrier)
        || profile.core_config_ref()? != bootstrap.safety_state_record_config_ref_v0()
    {
        return Err(SafetyStoreErrorV0::InvalidProfile(
            "authenticated-genesis application bootstrap/profile mismatch",
        ));
    }
    Core::validate_persisted_state_v0(profile.core_config(), state, verifier).map_err(|error| {
        SafetyStoreErrorV0::core("validate authenticated-genesis bootstrap state", error)
    })?;
    let state_record_checksum = encoded_state_record_checksum_v0(profile, state)?;
    let transition = AuthenticatedGenesisApplicationBootstrapTransitionV0::from_state_record_v0(
        state,
        state_record_checksum,
    )?;
    prepare_record(
        profile,
        verifier,
        BarrierId::new(0),
        state,
        &SafetyTransitionContextV0::authenticated_genesis_application_bootstrap(transition),
    )
}

fn prepare_h1_state_sync_initialization_v0(
    profile: &SafetyStateStoreProfileV0,
    journal_id: [u8; 32],
    record: &PreparedRecordV0,
    kind: SafetyBootstrapInitializationKindV0,
) -> Result<PreparedH1StateSyncInitializationV0, SafetyStoreErrorV0> {
    if record.revision != 0 || journal_id == [0; 32] {
        return Err(SafetyStoreErrorV0::InvalidProfile(
            "h1 initialization revision or journal ID",
        ));
    }
    let context = decode_transition_context_v0_exact(&record.transition_context_bytes)?;
    let context_matches_kind = match kind {
        SafetyBootstrapInitializationKindV0::StateSyncCheckpoint => context
            .state_sync_checkpoint_bootstrap_transition()
            .is_some(),
        SafetyBootstrapInitializationKindV0::AuthenticatedGenesisApplication => context
            .authenticated_genesis_application_bootstrap_transition()
            .is_some(),
    };
    if !context_matches_kind {
        return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
            "bootstrap initialization kind differs from transition context",
        ));
    }
    let stored = stored_record_from_prepared(record, None, None, journal_id);
    let metadata_checksum = metadata_values(profile, journal_id)?.checksum;
    let intent = H1StateSyncInitializationIntentV0 {
        kind,
        journal_id,
        metadata_checksum,
        state_record_bytes: usize_to_u64(record.state_record_bytes.len(), "state record bytes")?,
        transition_context_bytes: usize_to_u64(
            record.transition_context_bytes.len(),
            "transition-context bytes",
        )?,
        state_record_checksum: record.state_record_checksum,
        transition_context_checksum: record.transition_context_checksum,
        chain_checksum: stored.chain_checksum,
        head_checksum: head_checksum(journal_id, 0, stored.chain_checksum, 0),
    };
    Ok(PreparedH1StateSyncInitializationV0 {
        record: record.clone(),
        stored,
        intent,
    })
}

fn prepared_matches_stored(prepared: &PreparedRecordV0, stored: &StoredRecordV0) -> bool {
    prepared.revision == stored.revision
        && prepared.state_record_bytes == stored.state_record_bytes
        && prepared.state_record_checksum == stored.state_record_checksum
        && prepared.transition_context_bytes == stored.transition_context_bytes
        && prepared.transition_context_checksum == stored.transition_context_checksum
}

fn stored_record_from_prepared(
    prepared: &PreparedRecordV0,
    predecessor_revision: Option<u64>,
    predecessor_chain_checksum: Option<[u8; 32]>,
    journal_id: [u8; 32],
) -> StoredRecordV0 {
    let chain_checksum = chain_checksum(
        journal_id,
        prepared.revision,
        predecessor_revision,
        predecessor_chain_checksum,
        prepared.state_record_checksum,
        prepared.transition_context_checksum,
    );
    StoredRecordV0 {
        revision: prepared.revision,
        predecessor_revision,
        predecessor_chain_checksum,
        state_record_bytes: prepared.state_record_bytes.clone(),
        state_record_checksum: prepared.state_record_checksum,
        transition_context_bytes: prepared.transition_context_bytes.clone(),
        transition_context_checksum: prepared.transition_context_checksum,
        chain_checksum,
    }
}

fn initialize_schema(
    connection: &mut Connection,
    profile: &SafetyStateStoreProfileV0,
    journal_id: [u8; 32],
    prepared: &PreparedRecordV0,
) -> Result<(), SafetyStoreErrorV0> {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| SafetyStoreErrorV0::sqlite("begin initialization", error))?;
    transaction
        .execute_batch(JOURNAL_SCHEMA_SQL_V6)
        .map_err(|error| SafetyStoreErrorV0::sqlite("install safety-store schema", error))?;
    let metadata = metadata_values(profile, journal_id)?;
    if transaction
        .execute(
            "INSERT INTO safety_store_metadata_v0(
                singleton, journal_schema, journal_id, core_record_codec,
                safety_schema, core_config_ref, verifier_profile_ref,
                maximum_record_bytes_be, maximum_blob_bytes_be,
                maximum_database_bytes_be, transition_codec, metadata_checksum
             ) VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                i64::from(JOURNAL_SCHEMA_VERSION_V6),
                journal_id.as_slice(),
                i64::from(SAFETY_STATE_RECORD_CODEC_VERSION_V0),
                i64::from(SAFETY_STATE_RECORD_SAFETY_SCHEMA_VERSION_V0),
                metadata.core_config_ref.as_slice(),
                profile.verifier_profile_ref().as_slice(),
                usize_to_u64(
                    profile.record_limits().maximum_record_bytes(),
                    "record limit"
                )?
                .to_be_bytes()
                .as_slice(),
                usize_to_u64(profile.record_limits().maximum_blob_bytes(), "blob limit")?
                    .to_be_bytes()
                    .as_slice(),
                usize_to_u64(profile.maximum_database_bytes(), "database limit")?
                    .to_be_bytes()
                    .as_slice(),
                i64::from(TRANSITION_CONTEXT_CODEC_V0),
                metadata.checksum.as_slice(),
            ],
        )
        .map_err(|error| SafetyStoreErrorV0::sqlite("insert safety-store metadata", error))?
        != 1
    {
        return Err(SafetyStoreErrorV0::MetadataMismatch);
    }
    let row = stored_record_from_prepared(prepared, None, None, journal_id);
    insert_record(&transaction, &row)?;
    let head = head_checksum(journal_id, 0, row.chain_checksum, 0);
    transaction
        .execute(
            "INSERT INTO safety_state_head_v0(
                singleton, active_revision_be, active_chain_checksum,
                retention_floor_revision_be, head_checksum
             ) VALUES (1, ?1, ?2, ?3, ?4)",
            params![
                0u64.to_be_bytes().as_slice(),
                row.chain_checksum.as_slice(),
                0u64.to_be_bytes().as_slice(),
                head.as_slice(),
            ],
        )
        .map_err(|error| SafetyStoreErrorV0::sqlite("insert initial head", error))?;
    rewrite_accounting(&transaction)?;
    validate_transaction_environment(&transaction, profile, journal_id)?;
    let readback = read_active_record(&transaction)?;
    if readback != row {
        return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
            "initial record readback differs",
        ));
    }
    transaction
        .commit()
        .map_err(|error| SafetyStoreErrorV0::sqlite("commit initialization", error))
}

fn insert_record(connection: &Connection, row: &StoredRecordV0) -> Result<(), SafetyStoreErrorV0> {
    let inserted = connection
        .execute(
            "INSERT INTO safety_state_records_v0(
                revision_be, predecessor_revision_be, predecessor_chain_checksum,
                state_record_bytes, state_record_checksum,
                transition_context_bytes, transition_context_checksum, chain_checksum
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                row.revision.to_be_bytes().as_slice(),
                row.predecessor_revision
                    .map(u64::to_be_bytes)
                    .as_ref()
                    .map(<[u8; 8]>::as_slice),
                row.predecessor_chain_checksum
                    .as_ref()
                    .map(<[u8; 32]>::as_slice),
                row.state_record_bytes,
                row.state_record_checksum.as_slice(),
                row.transition_context_bytes,
                row.transition_context_checksum.as_slice(),
                row.chain_checksum.as_slice(),
            ],
        )
        .map_err(|error| SafetyStoreErrorV0::sqlite("insert safety-state record", error))?;
    if inserted != 1 {
        return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
            "record insertion did not affect one row",
        ));
    }
    Ok(())
}

fn rewrite_accounting(connection: &Connection) -> Result<(), SafetyStoreErrorV0> {
    let accounting: (i64, i64, i64) = connection
        .query_row(
            "SELECT COUNT(*), COALESCE(SUM(length(state_record_bytes)),0),
                    COALESCE(SUM(length(transition_context_bytes)),0)
             FROM safety_state_records_v0",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .map_err(|error| SafetyStoreErrorV0::sqlite("derive safety-store accounting", error))?;
    if !(1..=2).contains(&accounting.0) || accounting.1 <= 0 || accounting.2 < 3 {
        return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
            "derived accounting is outside journal bounds",
        ));
    }
    let changed = connection
        .execute(
            "INSERT INTO safety_state_accounting_v0(
                singleton, record_count, state_bytes, transition_bytes
             ) VALUES (1, ?1, ?2, ?3)
             ON CONFLICT(singleton) DO UPDATE SET
                record_count=excluded.record_count,
                state_bytes=excluded.state_bytes,
                transition_bytes=excluded.transition_bytes",
            params![accounting.0, accounting.1, accounting.2],
        )
        .map_err(|error| SafetyStoreErrorV0::sqlite("write safety-store accounting", error))?;
    if changed != 1 {
        return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
            "accounting update did not affect one row",
        ));
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct MetadataValuesV0 {
    core_config_ref: [u8; 32],
    checksum: [u8; 32],
}

fn metadata_values(
    profile: &SafetyStateStoreProfileV0,
    journal_id: [u8; 32],
) -> Result<MetadataValuesV0, SafetyStoreErrorV0> {
    let core_config_ref = profile.core_config_ref()?;
    let journal_schema = JOURNAL_SCHEMA_VERSION_V6.to_be_bytes();
    let record_codec = SAFETY_STATE_RECORD_CODEC_VERSION_V0.to_be_bytes();
    let safety_schema = SAFETY_STATE_RECORD_SAFETY_SCHEMA_VERSION_V0.to_be_bytes();
    let record_limit = usize_to_u64(
        profile.record_limits().maximum_record_bytes(),
        "record limit",
    )?
    .to_be_bytes();
    let blob_limit =
        usize_to_u64(profile.record_limits().maximum_blob_bytes(), "blob limit")?.to_be_bytes();
    let database_limit =
        usize_to_u64(profile.maximum_database_bytes(), "database limit")?.to_be_bytes();
    let transition_codec = TRANSITION_CONTEXT_CODEC_V0.to_be_bytes();
    let checksum = hash_domain(
        METADATA_DOMAIN_V0,
        &[
            &journal_schema,
            &journal_id,
            &record_codec,
            &safety_schema,
            &core_config_ref,
            &profile.verifier_profile_ref,
            &record_limit,
            &blob_limit,
            &database_limit,
            &transition_codec,
        ],
    );
    Ok(MetadataValuesV0 {
        core_config_ref,
        checksum,
    })
}

fn validate_metadata(
    connection: &Connection,
    profile: &SafetyStateStoreProfileV0,
    journal_id: [u8; 32],
) -> Result<(), SafetyStoreErrorV0> {
    let row: StoredMetadataRowV0 = connection
        .query_row(
            "SELECT journal_schema, journal_id, core_record_codec, safety_schema,
                        core_config_ref, verifier_profile_ref, maximum_record_bytes_be,
                        maximum_blob_bytes_be, maximum_database_bytes_be,
                        transition_codec, metadata_checksum
                 FROM safety_store_metadata_v0 WHERE singleton=1",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                    row.get(8)?,
                    row.get(9)?,
                    row.get(10)?,
                ))
            },
        )
        .map_err(|error| SafetyStoreErrorV0::sqlite("read safety-store metadata", error))?;
    let expected = metadata_values(profile, journal_id)?;
    let metadata_count: i64 = connection
        .query_row("SELECT COUNT(*) FROM safety_store_metadata_v0", [], |row| {
            row.get(0)
        })
        .map_err(|error| SafetyStoreErrorV0::sqlite("count safety-store metadata", error))?;
    if metadata_count != 1
        || row.0 != i64::from(JOURNAL_SCHEMA_VERSION_V6)
        || row.1.as_slice() != journal_id.as_slice()
        || row.2 != i64::from(SAFETY_STATE_RECORD_CODEC_VERSION_V0)
        || row.3 != i64::from(SAFETY_STATE_RECORD_SAFETY_SCHEMA_VERSION_V0)
        || row.4.as_slice() != expected.core_config_ref.as_slice()
        || row.5.as_slice() != profile.verifier_profile_ref.as_slice()
        || decode_u64_blob(&row.6, "record limit")?
            != usize_to_u64(profile.record_limits.maximum_record_bytes(), "record limit")?
        || decode_u64_blob(&row.7, "blob limit")?
            != usize_to_u64(profile.record_limits.maximum_blob_bytes(), "blob limit")?
        || decode_u64_blob(&row.8, "database limit")?
            != usize_to_u64(profile.maximum_database_bytes, "database limit")?
        || row.9 != i64::from(TRANSITION_CONTEXT_CODEC_V0)
        || row.10.as_slice() != expected.checksum.as_slice()
    {
        return Err(SafetyStoreErrorV0::MetadataMismatch);
    }
    Ok(())
}

fn read_active_record(connection: &Connection) -> Result<StoredRecordV0, SafetyStoreErrorV0> {
    connection
        .query_row(
            "SELECT r.revision_be, r.predecessor_revision_be,
                    r.predecessor_chain_checksum, r.state_record_bytes,
                    r.state_record_checksum, r.transition_context_bytes,
                    r.transition_context_checksum, r.chain_checksum
             FROM safety_state_head_v0 h
             JOIN safety_state_records_v0 r
               ON r.revision_be=h.active_revision_be
              AND r.chain_checksum=h.active_chain_checksum
             WHERE h.singleton=1",
            [],
            decode_stored_record_row,
        )
        .map_err(|error| SafetyStoreErrorV0::sqlite("read active safety record", error))
}

fn decode_stored_record_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoredRecordV0> {
    let revision: Vec<u8> = row.get(0)?;
    let predecessor_revision: Option<Vec<u8>> = row.get(1)?;
    let predecessor_chain_checksum: Option<Vec<u8>> = row.get(2)?;
    let state_record_checksum: Vec<u8> = row.get(4)?;
    let transition_context_checksum: Vec<u8> = row.get(6)?;
    let chain_checksum: Vec<u8> = row.get(7)?;
    Ok(StoredRecordV0 {
        revision: u64_from_slice_sql(&revision, 0)?,
        predecessor_revision: predecessor_revision
            .as_deref()
            .map(|bytes| u64_from_slice_sql(bytes, 1))
            .transpose()?,
        predecessor_chain_checksum: predecessor_chain_checksum
            .as_deref()
            .map(|bytes| array32_sql(bytes, 2))
            .transpose()?,
        state_record_bytes: row.get(3)?,
        state_record_checksum: array32_sql(&state_record_checksum, 4)?,
        transition_context_bytes: row.get(5)?,
        transition_context_checksum: array32_sql(&transition_context_checksum, 6)?,
        chain_checksum: array32_sql(&chain_checksum, 7)?,
    })
}

fn read_head(
    connection: &Connection,
    journal_id: [u8; 32],
) -> Result<(u64, [u8; 32], u64), SafetyStoreErrorV0> {
    let (revision, chain, floor, stored_head): (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) = connection
        .query_row(
            "SELECT active_revision_be, active_chain_checksum,
                    retention_floor_revision_be, head_checksum
             FROM safety_state_head_v0 WHERE singleton=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .map_err(|error| SafetyStoreErrorV0::sqlite("read safety-state head", error))?;
    let revision = decode_u64_blob(&revision, "head revision")?;
    let chain = decode_array32(&chain, "head chain checksum")?;
    let floor = decode_u64_blob(&floor, "retention floor")?;
    let stored_head = decode_array32(&stored_head, "head checksum")?;
    if floor > revision || stored_head != head_checksum(journal_id, revision, chain, floor) {
        return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
            "head checksum or retention floor",
        ));
    }
    Ok((revision, chain, floor))
}

fn decode_and_validate_record<V: SignatureVerifier>(
    row: &StoredRecordV0,
    profile: &SafetyStateStoreProfileV0,
    verifier: &V,
) -> Result<RecoveredSafetyStateV0, SafetyStoreErrorV0> {
    let context = profile.record_context()?;
    let decoded = decode_safety_state_record_v0_exact(&row.state_record_bytes, &context)
        .map_err(|error| SafetyStoreErrorV0::record("decode stored state", error))?;
    if decoded.record_checksum() != row.state_record_checksum
        || decoded.state().revision() != row.revision
    {
        return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
            "state record checksum or revision",
        ));
    }
    Core::validate_persisted_state_v0(profile.core_config(), decoded.state(), verifier)
        .map_err(|error| SafetyStoreErrorV0::core("validate stored state", error))?;
    let transition_context = decode_transition_context_v0_exact(&row.transition_context_bytes)?;
    if transition_context_checksum_v0(&row.transition_context_bytes)?
        != row.transition_context_checksum
    {
        return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
            "transition-context checksum",
        ));
    }
    validate_transition_context_against_state_v0(&transition_context, decoded.state())?;
    validate_transition_context_record_identity_v0(&transition_context, decoded.record_checksum())?;
    Ok(RecoveredSafetyStateV0 {
        state: decoded.state().clone(),
        transition_context,
        state_record_checksum: row.state_record_checksum,
        transition_context_checksum: row.transition_context_checksum,
        chain_checksum: row.chain_checksum,
    })
}

fn validate_storage_resource_bounds(
    connection: &Connection,
    profile: &SafetyStateStoreProfileV0,
) -> Result<(), SafetyStoreErrorV0> {
    let page_size: i64 = connection
        .query_row("PRAGMA page_size", [], |row| row.get(0))
        .map_err(|error| SafetyStoreErrorV0::sqlite("audit SQLite page size", error))?;
    let page_count: i64 = connection
        .query_row("PRAGMA page_count", [], |row| row.get(0))
        .map_err(|error| SafetyStoreErrorV0::sqlite("audit SQLite page count", error))?;
    if page_size <= 0
        || page_count < 0
        || (page_size as u128) * (page_count as u128) > profile.maximum_database_bytes() as u128
    {
        return Err(SafetyStoreErrorV0::IntegrityFailure);
    }

    let (count, maximum_state, maximum_context, state_bytes, context_bytes): (
        i64,
        i64,
        i64,
        i64,
        i64,
    ) = connection
        .query_row(
            "SELECT COUNT(*), COALESCE(MAX(length(state_record_bytes)),0),
                    COALESCE(MAX(length(transition_context_bytes)),0),
                    COALESCE(SUM(length(state_record_bytes)),0),
                    COALESCE(SUM(length(transition_context_bytes)),0)
             FROM safety_state_records_v0",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )
        .map_err(|error| SafetyStoreErrorV0::sqlite("audit stored resource bounds", error))?;
    let maximum_record_bytes = i64::try_from(profile.record_limits().maximum_record_bytes())
        .map_err(|_| SafetyStoreErrorV0::InvalidProfile("record limit"))?;
    let maximum_retained_state_bytes =
        maximum_record_bytes
            .checked_mul(2)
            .ok_or(SafetyStoreErrorV0::InvalidProfile(
                "retained record limit overflow",
            ))?;
    let maximum_context_bytes = i64::try_from(MAXIMUM_TRANSITION_CONTEXT_BYTES_V0)
        .map_err(|_| SafetyStoreErrorV0::InvalidProfile("transition-context limit"))?;
    if !(1..=2).contains(&count)
        || maximum_state <= 0
        || maximum_state > maximum_record_bytes
        || maximum_context < 3
        || maximum_context > maximum_context_bytes
        || state_bytes <= 0
        || state_bytes > maximum_retained_state_bytes
        || context_bytes < 3
        || context_bytes > maximum_context_bytes.saturating_mul(2)
    {
        return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
            "stored resource bounds",
        ));
    }
    Ok(())
}

fn validate_all_records<V: SignatureVerifier>(
    connection: &Connection,
    profile: &SafetyStateStoreProfileV0,
    verifier: &V,
    journal_id: [u8; 32],
) -> Result<ValidatedRetainedRecordsV0, SafetyStoreErrorV0> {
    let mut statement = connection
        .prepare(
            "SELECT revision_be, predecessor_revision_be,
                    predecessor_chain_checksum, state_record_bytes,
                    state_record_checksum, transition_context_bytes,
                    transition_context_checksum, chain_checksum
             FROM safety_state_records_v0 ORDER BY revision_be",
        )
        .map_err(|error| SafetyStoreErrorV0::sqlite("prepare safety record scan", error))?;
    let rows = statement
        .query_map([], decode_stored_record_row)
        .map_err(|error| SafetyStoreErrorV0::sqlite("query safety record scan", error))?;
    let mut records = Vec::with_capacity(2);
    let mut recovered_records = Vec::new();
    for row in rows {
        let row =
            row.map_err(|error| SafetyStoreErrorV0::sqlite("read safety record scan", error))?;
        let expected_chain = chain_checksum(
            journal_id,
            row.revision,
            row.predecessor_revision,
            row.predecessor_chain_checksum,
            row.state_record_checksum,
            row.transition_context_checksum,
        );
        if expected_chain != row.chain_checksum {
            return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                "record-chain checksum",
            ));
        }
        let recovered = decode_and_validate_record(&row, profile, verifier)?;
        recovered_records.push(recovered);
        records.push(RetainedRecordSummaryV0 {
            revision: row.revision,
            predecessor_revision: row.predecessor_revision,
            predecessor_chain_checksum: row.predecessor_chain_checksum,
            chain_checksum: row.chain_checksum,
        });
    }
    if records.is_empty() || records.len() > 2 {
        return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
            "retained record count",
        ));
    }
    let (active_revision, active_chain, floor) = read_head(connection, journal_id)?;
    let first = records.first().expect("nonempty checked");
    let active = records.last().expect("nonempty checked");
    let floor_predecessor_is_canonical = if first.revision == 0 {
        first.predecessor_revision.is_none() && first.predecessor_chain_checksum.is_none()
    } else {
        first.predecessor_revision == first.revision.checked_sub(1)
            && first
                .predecessor_chain_checksum
                .is_some_and(|checksum| checksum != [0; 32])
    };
    if !floor_predecessor_is_canonical
        || first.revision != floor
        || active.revision != active_revision
        || active.chain_checksum != active_chain
        || (records.len() == 1 && active_revision != 0)
        || (records.len() == 2
            && (first.revision.checked_add(1) != Some(active.revision)
                || active.predecessor_revision != Some(first.revision)
                || active.predecessor_chain_checksum != Some(first.chain_checksum)))
    {
        return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
            "retained predecessor chain",
        ));
    }
    let consumed_finalization = if let [previous, current] = recovered_records.as_slice() {
        Core::validate_persisted_successor_v0(
            profile.core_config(),
            previous.state(),
            current.state(),
            verifier,
        )
        .map_err(|error| SafetyStoreErrorV0::core("validate retained successor", error))?;
        validate_application_applied_context_pair_v0(previous, current)?;
        validate_state_sync_anchor_ordinary_promotion_context_pair_v0(
            previous.state(),
            current.state(),
            current.transition_context(),
        )?;
        if current
            .transition_context()
            .native_finalization_applied_transition()
            .is_some()
        {
            Some(
                previous
                    .state()
                    .pending_finalization()
                    .ok_or(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                        "tag-3 transition context has no predecessor queue front",
                    ))?
                    .clone(),
            )
        } else {
            None
        }
    } else if recovered_records[0]
        .transition_context()
        .native_finalization_applied_transition()
        .is_some()
    {
        return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
            "tag-3 transition context has no retained predecessor",
        ));
    } else if recovered_records[0]
        .transition_context()
        .state_sync_anchor_ordinary_promotion_transition()
        .is_some()
    {
        return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
            "tag-6 transition context has no retained predecessor",
        ));
    } else {
        None
    };
    let actual: (i64, i64, i64) = connection
        .query_row(
            "SELECT COUNT(*), COALESCE(SUM(length(state_record_bytes)),0),
                    COALESCE(SUM(length(transition_context_bytes)),0)
             FROM safety_state_records_v0",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .map_err(|error| SafetyStoreErrorV0::sqlite("audit record accounting", error))?;
    let stored: (i64, i64, i64) = connection
        .query_row(
            "SELECT record_count, state_bytes, transition_bytes
             FROM safety_state_accounting_v0 WHERE singleton=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .map_err(|error| SafetyStoreErrorV0::sqlite("read record accounting", error))?;
    if actual != stored || stored.0 != records.len() as i64 {
        return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
            "safety-store accounting mismatch",
        ));
    }
    Ok(ValidatedRetainedRecordsV0 {
        consumed_finalization,
        records,
        recovered_records,
    })
}

fn classify_marker_bound_h1_initialization_database_v0<V: SignatureVerifier>(
    database_path: &Path,
    database_file: &File,
    profile: &SafetyStateStoreProfileV0,
    verifier: &V,
    prepared: &PreparedH1StateSyncInitializationV0,
) -> Result<InitializationDatabaseStateV0, SafetyStoreErrorV0> {
    let auxiliary =
        inspect_initialization_auxiliary_state_v0(database_path, profile.maximum_database_bytes())?;
    let main_state =
        classify_immutable_h1_initialization_main_v0(database_path, profile, verifier, prepared)?;
    match main_state {
        ImmutableInitializationMainStateV0::ExactPostCommit => {
            if auxiliary.wal_bytes.is_some_and(|bytes| bytes != 0) {
                let shadow_state = classify_h1_state_sync_initialization_wal_shadow_v0(
                    database_path,
                    database_file,
                    profile,
                    verifier,
                    prepared,
                    main_state,
                )?;
                if shadow_state != InitializationWalShadowStateV0::ExactPostCommit {
                    return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                        "h1 initialization WAL shadow regresses an exact main database",
                    ));
                }
            }
            Ok(InitializationDatabaseStateV0::ExactPostCommit)
        }
        ImmutableInitializationMainStateV0::PreCommit => match auxiliary.wal_bytes {
            None => {
                if auxiliary.shm_bytes.is_some() {
                    return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                        "h1 initialization prestate has SHM without WAL",
                    ));
                }
                Ok(InitializationDatabaseStateV0::PreCommit)
            }
            Some(0) => Ok(InitializationDatabaseStateV0::PreCommit),
            Some(_) => match classify_h1_state_sync_initialization_wal_shadow_v0(
                database_path,
                database_file,
                profile,
                verifier,
                prepared,
                main_state,
            )? {
                InitializationWalShadowStateV0::PreCommit => {
                    Ok(InitializationDatabaseStateV0::PreCommit)
                }
                InitializationWalShadowStateV0::ExactPostCommit => {
                    Ok(InitializationDatabaseStateV0::ExactPostCommit)
                }
            },
        },
    }
}

fn classify_immutable_h1_initialization_main_v0<V: SignatureVerifier>(
    database_path: &Path,
    profile: &SafetyStateStoreProfileV0,
    verifier: &V,
    prepared: &PreparedH1StateSyncInitializationV0,
) -> Result<ImmutableInitializationMainStateV0, SafetyStoreErrorV0> {
    let metadata = fs::symlink_metadata(database_path)
        .map_err(|error| SafetyStoreErrorV0::io("stat h1 initialization main database", error))?;
    if !metadata.file_type().is_file()
        || u128::from(metadata.len()) > profile.maximum_database_bytes() as u128
    {
        return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
            "h1 initialization main database shape or size",
        ));
    }
    if metadata.len() == 0 {
        return Ok(ImmutableInitializationMainStateV0::PreCommit);
    }
    let uri = immutable_sqlite_uri(database_path);
    let connection = Connection::open_with_flags(
        uri,
        OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_URI
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .map_err(|error| SafetyStoreErrorV0::sqlite("open immutable h1 main classifier", error))?;
    if sqlite_schema_object_count_v0(&connection)? == 0 {
        validate_immutable_initialization_precommit_v0(&connection)?;
        Ok(ImmutableInitializationMainStateV0::PreCommit)
    } else {
        validate_exact_h1_state_sync_initialization_connection_v0(
            &connection,
            profile,
            verifier,
            prepared,
            false,
        )?;
        Ok(ImmutableInitializationMainStateV0::ExactPostCommit)
    }
}

fn sqlite_schema_object_count_v0(connection: &Connection) -> Result<u64, SafetyStoreErrorV0> {
    let count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'",
            [],
            |row| row.get(0),
        )
        .map_err(|error| SafetyStoreErrorV0::sqlite("classify SQLite schema objects", error))?;
    u64::try_from(count).map_err(|_| {
        SafetyStoreErrorV0::PersistedRepresentationMalformed("negative SQLite schema object count")
    })
}

fn validate_immutable_initialization_precommit_v0(
    connection: &Connection,
) -> Result<(), SafetyStoreErrorV0> {
    let page_size: i64 = connection
        .query_row("PRAGMA page_size", [], |row| row.get(0))
        .map_err(|error| SafetyStoreErrorV0::sqlite("read precommit page size", error))?;
    let page_count: i64 = connection
        .query_row("PRAGMA page_count", [], |row| row.get(0))
        .map_err(|error| SafetyStoreErrorV0::sqlite("read precommit page count", error))?;
    let freelist_count: i64 = connection
        .query_row("PRAGMA freelist_count", [], |row| row.get(0))
        .map_err(|error| SafetyStoreErrorV0::sqlite("read precommit freelist", error))?;
    let application_id: i64 = connection
        .query_row("PRAGMA application_id", [], |row| row.get(0))
        .map_err(|error| SafetyStoreErrorV0::sqlite("read precommit application ID", error))?;
    let user_version: i64 = connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(|error| SafetyStoreErrorV0::sqlite("read precommit user version", error))?;
    if page_size != 4096
        || page_count != 1
        || freelist_count != 0
        || application_id != 0
        || user_version != 0
    {
        return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
            "h1 initialization main database is not canonical empty precommit state",
        ));
    }
    Ok(())
}

fn classify_h1_state_sync_initialization_wal_shadow_v0<V: SignatureVerifier>(
    database_path: &Path,
    database_file: &File,
    profile: &SafetyStateStoreProfileV0,
    verifier: &V,
    prepared: &PreparedH1StateSyncInitializationV0,
    main_state: ImmutableInitializationMainStateV0,
) -> Result<InitializationWalShadowStateV0, SafetyStoreErrorV0> {
    let wal_path = sqlite_auxiliary_path(database_path, "-wal");
    let wal_file = open_existing_private_file(&wal_path, "pin h1 initialization WAL snapshot")?;
    acquire_lifetime_lock(&wal_file)?;
    let database_identity = file_handle_identity(database_file, database_path)?;
    let wal_identity = file_handle_identity(&wal_file, &wal_path)?;
    let directory_path = database_path
        .parent()
        .ok_or(SafetyStoreErrorV0::InvalidProfile("database parent"))?;
    let directory_identity_before = directory_identity(directory_path)?;
    let audit_directory = create_initialization_audit_directory_v0(database_path)?;
    let audit_database = audit_directory.database_path_v0();
    let audit_wal = sqlite_auxiliary_path(&audit_database, "-wal");
    let audit_result = (|| {
        copy_pinned_initialization_file_v0(
            database_file,
            &audit_database,
            profile.maximum_database_bytes(),
        )?;
        copy_pinned_initialization_file_v0(
            &wal_file,
            &audit_wal,
            profile.maximum_database_bytes(),
        )?;
        let validated_wal =
            validate_initialization_wal_snapshot_v0(&audit_wal, profile.maximum_database_bytes())?;
        with_pinned_audit_connection_v0(
            &audit_database,
            &audit_wal,
            profile.maximum_database_bytes(),
            "open h1 WAL audit snapshot",
            |connection| {
                let schema_objects = sqlite_schema_object_count_v0(connection)?;
                let shadow_state = if schema_objects == 0 {
                    validate_immutable_initialization_precommit_v0(connection)?;
                    if validated_wal.contains_commit {
                        return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                            "h1 initialization WAL has a commit marker but resolves to precommit",
                        ));
                    }
                    InitializationWalShadowStateV0::PreCommit
                } else {
                    validate_exact_h1_state_sync_initialization_connection_v0(
                        connection, profile, verifier, prepared, true,
                    )?;
                    if main_state == ImmutableInitializationMainStateV0::PreCommit
                        && !validated_wal.contains_commit
                    {
                        return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                            "h1 initialization WAL has no commit marker but resolves to postcommit",
                        ));
                    }
                    InitializationWalShadowStateV0::ExactPostCommit
                };
                if main_state == ImmutableInitializationMainStateV0::ExactPostCommit
                    && shadow_state != InitializationWalShadowStateV0::ExactPostCommit
                {
                    return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                        "h1 initialization WAL shadow regresses an exact main database",
                    ));
                }
                Ok(shadow_state)
            },
        )
    })();
    let cleanup_result = cleanup_initialization_audit_directory_v0(&audit_directory);
    cleanup_result?;
    if file_handle_identity(database_file, database_path)? != database_identity
        || file_identity(database_path)? != database_identity
        || file_handle_identity(&wal_file, &wal_path)? != wal_identity
        || file_identity(&wal_path)? != wal_identity
        || directory_identity(directory_path)? != directory_identity_before
    {
        return Err(SafetyStoreErrorV0::Conflict(
            SafetyStoreConflictV0::FileIdentityChanged,
        ));
    }
    audit_result
}

fn validate_initialization_wal_snapshot_v0(
    wal_path: &Path,
    maximum_bytes: usize,
) -> Result<ValidatedInitializationWalV0, SafetyStoreErrorV0> {
    const WAL_HEADER_BYTES: usize = 32;
    const WAL_FRAME_HEADER_BYTES: usize = 24;
    const WAL_MAGIC_BIG_CHECKSUMS: u32 = 0x377f_0683;
    const WAL_MAGIC_LITTLE_CHECKSUMS: u32 = 0x377f_0682;
    const WAL_FORMAT_VERSION: u32 = 3_007_000;

    let bytes = fs::read(wal_path)
        .map_err(|error| SafetyStoreErrorV0::io("read h1 initialization WAL snapshot", error))?;
    if bytes.len() > maximum_bytes || bytes.len() < WAL_HEADER_BYTES {
        return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
            "h1 initialization WAL snapshot length",
        ));
    }
    let magic = u32::from_be_bytes(
        bytes[0..4]
            .try_into()
            .expect("fixed WAL magic slice length"),
    );
    let checksum_big_endian = match magic {
        WAL_MAGIC_BIG_CHECKSUMS => true,
        WAL_MAGIC_LITTLE_CHECKSUMS => false,
        _ => {
            return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                "h1 initialization WAL snapshot magic",
            ));
        }
    };
    if u32::from_be_bytes(
        bytes[4..8]
            .try_into()
            .expect("fixed WAL version slice length"),
    ) != WAL_FORMAT_VERSION
    {
        return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
            "h1 initialization WAL snapshot format version",
        ));
    }
    let page_size = usize::try_from(u32::from_be_bytes(
        bytes[8..12]
            .try_into()
            .expect("fixed WAL page-size slice length"),
    ))
    .map_err(|_| {
        SafetyStoreErrorV0::PersistedRepresentationMalformed(
            "h1 initialization WAL snapshot page size",
        )
    })?;
    if page_size != 4096 {
        return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
            "h1 initialization WAL snapshot page size",
        ));
    }
    let frame_bytes = WAL_FRAME_HEADER_BYTES.checked_add(page_size).ok_or(
        SafetyStoreErrorV0::PersistedRepresentationMalformed(
            "h1 initialization WAL snapshot frame size",
        ),
    )?;
    let frame_region_bytes = bytes.len() - WAL_HEADER_BYTES;
    if frame_region_bytes == 0 || !frame_region_bytes.is_multiple_of(frame_bytes) {
        return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
            "h1 initialization WAL snapshot has a partial frame",
        ));
    }
    let mut checksum = wal_checksum_v0(checksum_big_endian, (0, 0), &bytes[..24])?;
    if checksum
        != (
            u32::from_be_bytes(
                bytes[24..28]
                    .try_into()
                    .expect("fixed WAL checksum-1 slice length"),
            ),
            u32::from_be_bytes(
                bytes[28..32]
                    .try_into()
                    .expect("fixed WAL checksum-2 slice length"),
            ),
        )
    {
        return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
            "h1 initialization WAL snapshot header checksum",
        ));
    }
    let salts = &bytes[16..24];
    let mut contains_commit = false;
    for frame in bytes[WAL_HEADER_BYTES..].chunks_exact(frame_bytes) {
        if frame[8..16] != salts[..] {
            return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                "h1 initialization WAL snapshot frame salt",
            ));
        }
        let page_number = u32::from_be_bytes(
            frame[0..4]
                .try_into()
                .expect("fixed WAL page-number slice length"),
        );
        if page_number == 0 {
            return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                "h1 initialization WAL snapshot zero page number",
            ));
        }
        let database_pages_after_commit = u32::from_be_bytes(
            frame[4..8]
                .try_into()
                .expect("fixed WAL database-size slice length"),
        );
        checksum = wal_checksum_v0(checksum_big_endian, checksum, &frame[..8])?;
        checksum = wal_checksum_v0(
            checksum_big_endian,
            checksum,
            &frame[WAL_FRAME_HEADER_BYTES..],
        )?;
        if checksum
            != (
                u32::from_be_bytes(
                    frame[16..20]
                        .try_into()
                        .expect("fixed WAL checksum-1 slice length"),
                ),
                u32::from_be_bytes(
                    frame[20..24]
                        .try_into()
                        .expect("fixed WAL checksum-2 slice length"),
                ),
            )
        {
            return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                "h1 initialization WAL snapshot frame checksum",
            ));
        }
        contains_commit |= database_pages_after_commit != 0;
    }
    Ok(ValidatedInitializationWalV0 { contains_commit })
}

fn recoverable_current_journal_wal_prefix_v0(
    wal_file: &File,
    maximum_bytes: usize,
) -> Result<RecoverableCurrentJournalWalV0, SafetyStoreErrorV0> {
    const WAL_HEADER_BYTES: usize = 32;
    const WAL_FRAME_HEADER_BYTES: usize = 24;
    const WAL_MAGIC_BIG_CHECKSUMS: u32 = 0x377f_0683;
    const WAL_MAGIC_LITTLE_CHECKSUMS: u32 = 0x377f_0682;
    const WAL_FORMAT_VERSION: u32 = 3_007_000;

    // Ordinary SQLite recovery treats a WAL without one checksum-valid commit
    // as non-authoritative. Preserve that distinction from commissioning, but
    // do not conflate a checksum-valid header for an unsupported WAL format
    // with an absent transaction: SQLite would inspect that header and fail
    // only after opening the live namespace and resetting SHM.
    let bytes =
        pinned_file_bytes_bounded_v0(wal_file, maximum_bytes, "read ordinary-open WAL preflight")?;
    if bytes.len() < WAL_HEADER_BYTES {
        return Ok(RecoverableCurrentJournalWalV0::NoCommit);
    }
    let magic = u32::from_be_bytes(
        bytes[0..4]
            .try_into()
            .expect("fixed ordinary WAL magic slice length"),
    );
    let checksum_big_endian = match magic {
        WAL_MAGIC_BIG_CHECKSUMS => true,
        WAL_MAGIC_LITTLE_CHECKSUMS => false,
        _ => return Ok(RecoverableCurrentJournalWalV0::NoCommit),
    };
    let mut checksum = wal_checksum_v0(checksum_big_endian, (0, 0), &bytes[..24])?;
    if checksum
        != (
            u32::from_be_bytes(
                bytes[24..28]
                    .try_into()
                    .expect("fixed ordinary WAL checksum-1 slice length"),
            ),
            u32::from_be_bytes(
                bytes[28..32]
                    .try_into()
                    .expect("fixed ordinary WAL checksum-2 slice length"),
            ),
        )
    {
        return Ok(RecoverableCurrentJournalWalV0::NoCommit);
    }
    if u32::from_be_bytes(
        bytes[4..8]
            .try_into()
            .expect("fixed ordinary WAL version slice length"),
    ) != WAL_FORMAT_VERSION
    {
        return Ok(RecoverableCurrentJournalWalV0::Invalid(
            "ordinary-open WAL snapshot format version",
        ));
    }
    let page_size = usize::try_from(u32::from_be_bytes(
        bytes[8..12]
            .try_into()
            .expect("fixed ordinary WAL page-size slice length"),
    ))
    .map_err(|_| {
        SafetyStoreErrorV0::PersistedRepresentationMalformed("ordinary-open WAL snapshot page size")
    })?;
    if page_size != 4096 {
        return Ok(RecoverableCurrentJournalWalV0::Invalid(
            "ordinary-open WAL snapshot page size",
        ));
    }
    let frame_bytes = WAL_FRAME_HEADER_BYTES.checked_add(page_size).ok_or(
        SafetyStoreErrorV0::PersistedRepresentationMalformed(
            "ordinary-open WAL snapshot frame size",
        ),
    )?;
    if bytes.len() == WAL_HEADER_BYTES {
        return Ok(RecoverableCurrentJournalWalV0::NoCommit);
    }

    let salts = &bytes[16..24];
    let complete_frame_bytes = ((bytes.len() - WAL_HEADER_BYTES) / frame_bytes) * frame_bytes;
    let mut last_commit_end = None;
    for (index, frame) in bytes[WAL_HEADER_BYTES..WAL_HEADER_BYTES + complete_frame_bytes]
        .chunks_exact(frame_bytes)
        .enumerate()
    {
        if frame[8..16] != salts[..] {
            break;
        }
        let page_number = u32::from_be_bytes(
            frame[0..4]
                .try_into()
                .expect("fixed ordinary WAL page-number slice length"),
        );
        if page_number == 0 {
            break;
        }
        let database_pages_after_commit = u32::from_be_bytes(
            frame[4..8]
                .try_into()
                .expect("fixed ordinary WAL database-size slice length"),
        );
        let mut candidate = wal_checksum_v0(checksum_big_endian, checksum, &frame[..8])?;
        candidate = wal_checksum_v0(
            checksum_big_endian,
            candidate,
            &frame[WAL_FRAME_HEADER_BYTES..],
        )?;
        if candidate
            != (
                u32::from_be_bytes(
                    frame[16..20]
                        .try_into()
                        .expect("fixed ordinary WAL frame checksum-1 slice length"),
                ),
                u32::from_be_bytes(
                    frame[20..24]
                        .try_into()
                        .expect("fixed ordinary WAL frame checksum-2 slice length"),
                ),
            )
        {
            break;
        }
        checksum = candidate;
        if database_pages_after_commit != 0 {
            if u128::from(database_pages_after_commit)
                * u128::try_from(page_size).expect("WAL page size fits u128")
                > maximum_bytes as u128
            {
                return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                    "ordinary-open WAL committed database exceeds bound",
                ));
            }
            last_commit_end = Some(
                WAL_HEADER_BYTES
                    .checked_add((index + 1).checked_mul(frame_bytes).ok_or(
                        SafetyStoreErrorV0::PersistedRepresentationMalformed(
                            "ordinary-open WAL committed prefix overflow",
                        ),
                    )?)
                    .ok_or(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                        "ordinary-open WAL committed prefix overflow",
                    ))?,
            );
        }
    }

    let Some(last_commit_end) = last_commit_end else {
        return Ok(RecoverableCurrentJournalWalV0::NoCommit);
    };
    u64::try_from(last_commit_end)
        .map(|prefix_bytes| RecoverableCurrentJournalWalV0::Committed { prefix_bytes })
        .map_err(|_| {
            SafetyStoreErrorV0::PersistedRepresentationMalformed(
                "ordinary-open WAL committed prefix length",
            )
        })
}

fn wal_checksum_v0(
    big_endian_words: bool,
    mut checksum: (u32, u32),
    bytes: &[u8],
) -> Result<(u32, u32), SafetyStoreErrorV0> {
    if !bytes.len().is_multiple_of(8) {
        return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
            "h1 initialization WAL checksum input length",
        ));
    }
    for pair in bytes.chunks_exact(8) {
        let first = if big_endian_words {
            u32::from_be_bytes(pair[0..4].try_into().expect("fixed WAL checksum word"))
        } else {
            u32::from_le_bytes(pair[0..4].try_into().expect("fixed WAL checksum word"))
        };
        let second = if big_endian_words {
            u32::from_be_bytes(pair[4..8].try_into().expect("fixed WAL checksum word"))
        } else {
            u32::from_le_bytes(pair[4..8].try_into().expect("fixed WAL checksum word"))
        };
        checksum.0 = checksum.0.wrapping_add(first).wrapping_add(checksum.1);
        checksum.1 = checksum.1.wrapping_add(second).wrapping_add(checksum.0);
    }
    Ok(checksum)
}

fn create_initialization_audit_directory_v0(
    journal_database_path: &Path,
) -> Result<InitializationAuditDirectoryV0, SafetyStoreErrorV0> {
    ensure_supported_file_identity()?;
    let parent_path = fs::canonicalize(env::temp_dir())
        .map_err(|error| SafetyStoreErrorV0::io("canonicalize audit temp root", error))?;
    let journal_parent = fs::canonicalize(
        journal_database_path
            .parent()
            .ok_or(SafetyStoreErrorV0::InvalidProfile("database parent"))?,
    )
    .map_err(|error| SafetyStoreErrorV0::io("canonicalize journal parent for audit", error))?;
    if parent_path.starts_with(&journal_parent) {
        return Err(SafetyStoreErrorV0::InvalidProfile(
            "audit temp root must be outside journal parent",
        ));
    }
    let parent_metadata = fs::metadata(&parent_path)
        .map_err(|error| SafetyStoreErrorV0::io("stat audit temp root", error))?;
    if !parent_metadata.is_dir() {
        return Err(SafetyStoreErrorV0::InvalidProfile(
            "audit temp root is not a directory",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        // SAFETY: `geteuid` has no pointer arguments and no caller obligations.
        let effective_uid = unsafe { libc::geteuid() };
        let owner_private =
            parent_metadata.uid() == effective_uid && parent_metadata.mode() & 0o022 == 0;
        let trusted_sticky_root = parent_metadata.uid() == 0
            && parent_metadata.mode() & 0o1000 != 0
            && parent_metadata.mode() & 0o002 != 0;
        if !owner_private && !trusted_sticky_root {
            return Err(SafetyStoreErrorV0::InvalidProfile(
                "audit temp root is not owner-private or trusted sticky root",
            ));
        }
    }
    let parent_file = File::open(&parent_path)
        .map_err(|error| SafetyStoreErrorV0::io("pin audit temp root", error))?;
    let parent_identity = directory_handle_identity(&parent_file, &parent_path)?;
    if directory_identity(&journal_parent)? == parent_identity {
        return Err(SafetyStoreErrorV0::InvalidProfile(
            "audit temp root aliases journal parent",
        ));
    }

    for _ in 0..8 {
        let mut random = [0u8; 16];
        getrandom::getrandom(&mut random).map_err(|error| {
            SafetyStoreErrorV0::io(
                "generate h1 initialization audit namespace",
                io::Error::other(error.to_string()),
            )
        })?;
        let mut suffix = String::with_capacity(32);
        for byte in random {
            use std::fmt::Write as _;
            write!(&mut suffix, "{byte:02x}").map_err(|_| {
                SafetyStoreErrorV0::InvalidProfile("format initialization audit namespace")
            })?;
        }
        let directory_name = OsString::from(format!("trnm-safety-audit-{suffix}"));
        #[cfg(not(target_os = "linux"))]
        let _ = &directory_name;
        #[cfg(target_os = "linux")]
        {
            use std::{os::fd::AsRawFd, os::unix::ffi::OsStrExt};

            let name = CString::new(directory_name.as_os_str().as_bytes()).map_err(|_| {
                SafetyStoreErrorV0::InvalidProfile("audit directory name contains NUL")
            })?;
            // SAFETY: both directory descriptors stay live for the calls and
            // `name` is NUL-terminated. The random entry is created beneath
            // the pinned temp-root fd, never by resolving a mutable path.
            let created = unsafe { libc::mkdirat(parent_file.as_raw_fd(), name.as_ptr(), 0o700) };
            if created != 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::AlreadyExists {
                    continue;
                }
                return Err(SafetyStoreErrorV0::io(
                    "create independent audit namespace",
                    error,
                ));
            }
            // SAFETY: the pinned parent fd and NUL-terminated name remain
            // valid. O_NOFOLLOW/O_DIRECTORY rule out a substituted symlink.
            let directory_fd = unsafe {
                libc::openat(
                    parent_file.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if directory_fd < 0 {
                let error = io::Error::last_os_error();
                // SAFETY: same pinned parent/name pair used for mkdirat.
                if unsafe {
                    libc::unlinkat(parent_file.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR)
                } != 0
                {
                    return Err(SafetyStoreErrorV0::io(
                        "remove unpinned audit namespace",
                        io::Error::last_os_error(),
                    ));
                }
                return Err(SafetyStoreErrorV0::io("pin audit namespace", error));
            }
            // SAFETY: openat returned one owned descriptor on success.
            let directory_file =
                unsafe { <File as std::os::fd::FromRawFd>::from_raw_fd(directory_fd) };
            let child_identity_result = (|| {
                let metadata = directory_file
                    .metadata()
                    .map_err(|error| SafetyStoreErrorV0::io("stat audit namespace", error))?;
                use std::os::unix::fs::MetadataExt;
                // SAFETY: `geteuid` has no pointer arguments and no caller obligations.
                let effective_uid = unsafe { libc::geteuid() };
                if !metadata.is_dir()
                    || metadata.uid() != effective_uid
                    || metadata.mode() & 0o777 != 0o700
                {
                    return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                        "audit namespace identity or permissions",
                    ));
                }
                let child_identity =
                    directory_handle_identity(&directory_file, &parent_path.join(&directory_name))?;
                if directory_identity(&parent_path.join(&directory_name))? != child_identity
                    || directory_handle_identity(&parent_file, &parent_path)? != parent_identity
                {
                    return Err(SafetyStoreErrorV0::Conflict(
                        SafetyStoreConflictV0::FileIdentityChanged,
                    ));
                }
                Ok(child_identity)
            })();
            let child_identity = match child_identity_result {
                Ok(identity) => identity,
                Err(error) => {
                    drop(directory_file);
                    // SAFETY: same pinned parent/name pair used for mkdirat.
                    if unsafe {
                        libc::unlinkat(parent_file.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR)
                    } != 0
                    {
                        return Err(SafetyStoreErrorV0::io(
                            "remove rejected audit namespace",
                            io::Error::last_os_error(),
                        ));
                    }
                    return Err(error);
                }
            };
            return Ok(InitializationAuditDirectoryV0 {
                parent_path,
                parent_file,
                parent_identity,
                directory_name,
                directory_file,
                directory_identity: child_identity,
            });
        }
    }
    Err(SafetyStoreErrorV0::AlreadyExists(
        "independent audit namespace",
    ))
}

fn copy_pinned_initialization_file_v0(
    source: &File,
    target: &Path,
    maximum_bytes: usize,
) -> Result<(), SafetyStoreErrorV0> {
    let length = source
        .metadata()
        .map_err(|error| SafetyStoreErrorV0::io("stat h1 initialization audit source", error))?
        .len();
    if u128::from(length) > maximum_bytes as u128 {
        return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
            "h1 initialization audit source exceeds bound",
        ));
    }
    let mut source = source
        .try_clone()
        .map_err(|error| SafetyStoreErrorV0::io("clone h1 initialization audit source", error))?;
    source
        .seek(SeekFrom::Start(0))
        .map_err(|error| SafetyStoreErrorV0::io("seek h1 initialization audit source", error))?;
    let mut target = create_new_private_file(target, "create h1 initialization audit copy")?;
    let copied = io::copy(&mut source, &mut target)
        .map_err(|error| SafetyStoreErrorV0::io("copy h1 initialization audit source", error))?;
    if copied != length {
        return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
            "h1 initialization audit copy length",
        ));
    }
    target
        .sync_all()
        .map_err(|error| SafetyStoreErrorV0::io("sync h1 initialization audit copy", error))
}

fn pinned_file_bytes_bounded_v0(
    source: &File,
    maximum_bytes: usize,
    stage: &'static str,
) -> Result<Vec<u8>, SafetyStoreErrorV0> {
    let length = source
        .metadata()
        .map_err(|error| SafetyStoreErrorV0::io(stage, error))?
        .len();
    if u128::from(length) > maximum_bytes as u128 {
        return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
            "pinned audit source exceeds bound",
        ));
    }
    let capacity = usize::try_from(length).map_err(|_| {
        SafetyStoreErrorV0::PersistedRepresentationMalformed("pinned audit source length")
    })?;
    let mut source = source
        .try_clone()
        .map_err(|error| SafetyStoreErrorV0::io(stage, error))?;
    source
        .seek(SeekFrom::Start(0))
        .map_err(|error| SafetyStoreErrorV0::io(stage, error))?;
    let mut bytes = Vec::with_capacity(capacity);
    source
        .take(length)
        .read_to_end(&mut bytes)
        .map_err(|error| SafetyStoreErrorV0::io(stage, error))?;
    if bytes.len() != capacity {
        return Err(SafetyStoreErrorV0::Conflict(
            SafetyStoreConflictV0::FileIdentityChanged,
        ));
    }
    Ok(bytes)
}

fn pinned_file_image_commitment_v0(
    source: &File,
    maximum_bytes: usize,
    stage: &'static str,
) -> Result<FileImageCommitmentV0, SafetyStoreErrorV0> {
    let length = source
        .metadata()
        .map_err(|error| SafetyStoreErrorV0::io(stage, error))?
        .len();
    if u128::from(length) > maximum_bytes as u128 {
        return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
            "pinned commitment source exceeds bound",
        ));
    }
    let mut source = source
        .try_clone()
        .map_err(|error| SafetyStoreErrorV0::io(stage, error))?;
    source
        .seek(SeekFrom::Start(0))
        .map_err(|error| SafetyStoreErrorV0::io(stage, error))?;
    let mut remaining = length;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    while remaining != 0 {
        let requested = usize::try_from(remaining.min(buffer.len() as u64))
            .expect("bounded commitment read length fits usize");
        let read = source
            .read(&mut buffer[..requested])
            .map_err(|error| SafetyStoreErrorV0::io(stage, error))?;
        if read == 0 {
            return Err(SafetyStoreErrorV0::Conflict(
                SafetyStoreConflictV0::FileIdentityChanged,
            ));
        }
        hasher.update(&buffer[..read]);
        remaining -= u64::try_from(read).expect("buffer read length fits u64");
    }
    let checksum: [u8; 32] = hasher.finalize().into();
    Ok(FileImageCommitmentV0 { length, checksum })
}

#[cfg(target_os = "linux")]
fn pinned_file_image_commitment_preserving_locks_v0(
    source: &File,
    maximum_bytes: usize,
    stage: &'static str,
) -> Result<FileImageCommitmentV0, SafetyStoreErrorV0> {
    use std::os::unix::fs::FileExt as _;

    let length = source
        .metadata()
        .map_err(|error| SafetyStoreErrorV0::io(stage, error))?
        .len();
    if u128::from(length) > maximum_bytes as u128 {
        return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
            "pinned commitment source exceeds bound",
        ));
    }
    let mut offset = 0u64;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    while offset != length {
        let requested = usize::try_from((length - offset).min(buffer.len() as u64))
            .expect("bounded lock-preserving commitment read length fits usize");
        let read = source
            .read_at(&mut buffer[..requested], offset)
            .map_err(|error| SafetyStoreErrorV0::io(stage, error))?;
        if read == 0 {
            return Err(SafetyStoreErrorV0::Conflict(
                SafetyStoreConflictV0::FileIdentityChanged,
            ));
        }
        hasher.update(&buffer[..read]);
        offset = offset
            .checked_add(u64::try_from(read).expect("buffer read length fits u64"))
            .ok_or(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                "pinned commitment source length overflow",
            ))?;
    }
    let checksum: [u8; 32] = hasher.finalize().into();
    Ok(FileImageCommitmentV0 { length, checksum })
}

#[cfg(not(target_os = "linux"))]
fn pinned_file_image_commitment_preserving_locks_v0(
    _source: &File,
    _maximum_bytes: usize,
    _stage: &'static str,
) -> Result<FileImageCommitmentV0, SafetyStoreErrorV0> {
    Err(SafetyStoreErrorV0::UnsupportedPlatform)
}

fn with_pinned_audit_connection_v0<T>(
    database_path: &Path,
    wal_path: &Path,
    maximum_bytes: usize,
    open_stage: &'static str,
    validate: impl FnOnce(&Connection) -> Result<T, SafetyStoreErrorV0>,
) -> Result<T, SafetyStoreErrorV0> {
    let database_file = open_existing_private_file(database_path, "pin audit main copy")?;
    let wal_file = open_existing_private_file(wal_path, "pin audit WAL copy")?;
    let database_identity = file_handle_identity(&database_file, database_path)?;
    let wal_identity = file_handle_identity(&wal_file, wal_path)?;
    let database_image = pinned_file_image_commitment_v0(
        &database_file,
        maximum_bytes,
        "commit audit main before SQLite open",
    )?;
    let wal_image = pinned_file_image_commitment_v0(
        &wal_file,
        maximum_bytes,
        "commit audit WAL before SQLite open",
    )?;
    let verify_pinned_copies = || -> Result<(), SafetyStoreErrorV0> {
        if file_handle_identity(&database_file, database_path)? != database_identity
            || file_identity(database_path)? != database_identity
            || file_handle_identity(&wal_file, wal_path)? != wal_identity
            || file_identity(wal_path)? != wal_identity
            || pinned_file_image_commitment_v0(
                &database_file,
                maximum_bytes,
                "commit audit main after SQLite validation",
            )? != database_image
            || pinned_file_image_commitment_v0(
                &wal_file,
                maximum_bytes,
                "commit audit WAL after SQLite validation",
            )? != wal_image
        {
            return Err(SafetyStoreErrorV0::Conflict(
                SafetyStoreConflictV0::FileIdentityChanged,
            ));
        }
        Ok(())
    };
    verify_pinned_copies()?;

    // `/proc/self/fd/<pinned-dirfd>/audit.sqlite` intentionally contains one
    // procfs symlink component. SQLite's NOFOLLOW rejects that indirection even
    // though the directory resolution is already fixed by the live dirfd. The
    // audit copy alone therefore omits SQLITE_OPEN_NOFOLLOW; both files remain
    // pinned and are re-committed before cleanup. Live journal opens retain
    // SQLITE_OPEN_NOFOLLOW.
    let connection = match Connection::open_with_flags(
        database_path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    ) {
        Ok(connection) => connection,
        Err(error) => {
            verify_pinned_copies()?;
            return Err(SafetyStoreErrorV0::sqlite(open_stage, error));
        }
    };
    let validation_result = validate(&connection);
    let verification_result = verify_pinned_copies();
    drop(connection);
    verification_result?;
    validation_result
}

fn cleanup_initialization_audit_directory_v0(
    directory: &InitializationAuditDirectoryV0,
) -> Result<(), SafetyStoreErrorV0> {
    if directory_handle_identity(&directory.parent_file, &directory.parent_path)?
        != directory.parent_identity
        || directory_handle_identity(
            &directory.directory_file,
            &directory.parent_path.join(&directory.directory_name),
        )? != directory.directory_identity
        || directory_identity(&directory.parent_path.join(&directory.directory_name))?
            != directory.directory_identity
    {
        return Err(SafetyStoreErrorV0::Conflict(
            SafetyStoreConflictV0::FileIdentityChanged,
        ));
    }

    #[cfg(target_os = "linux")]
    {
        use std::{os::fd::AsRawFd, os::unix::ffi::OsStrExt};

        for name in [
            "audit.sqlite-journal",
            "audit.sqlite-shm",
            "audit.sqlite-wal",
            "audit.sqlite",
        ] {
            let name = CString::new(name).expect("static audit file name has no NUL");
            // SAFETY: the directory fd remains pinned and `name` is a static,
            // NUL-free single component. unlinkat cannot traverse a replaced
            // intermediate path or follow a final symlink.
            let result =
                unsafe { libc::unlinkat(directory.directory_file.as_raw_fd(), name.as_ptr(), 0) };
            if result != 0 {
                let error = io::Error::last_os_error();
                if error.kind() != io::ErrorKind::NotFound {
                    return Err(SafetyStoreErrorV0::io(
                        "remove audit namespace file by dirfd",
                        error,
                    ));
                }
            }
        }
        directory
            .directory_file
            .sync_all()
            .map_err(|error| SafetyStoreErrorV0::io("sync cleaned audit namespace", error))?;
        if directory_handle_identity(&directory.parent_file, &directory.parent_path)?
            != directory.parent_identity
            || directory_handle_identity(
                &directory.directory_file,
                &directory.parent_path.join(&directory.directory_name),
            )? != directory.directory_identity
            || directory_identity(&directory.parent_path.join(&directory.directory_name))?
                != directory.directory_identity
        {
            return Err(SafetyStoreErrorV0::Conflict(
                SafetyStoreConflictV0::FileIdentityChanged,
            ));
        }
        let directory_name = CString::new(directory.directory_name.as_os_str().as_bytes())
            .map_err(|_| SafetyStoreErrorV0::InvalidProfile("audit directory name contains NUL"))?;
        // SAFETY: the parent fd is pinned and `directory_name` is one
        // NUL-terminated component. AT_REMOVEDIR cannot follow a replacement.
        if unsafe {
            libc::unlinkat(
                directory.parent_file.as_raw_fd(),
                directory_name.as_ptr(),
                libc::AT_REMOVEDIR,
            )
        } != 0
        {
            return Err(SafetyStoreErrorV0::io(
                "remove audit namespace by parent dirfd",
                io::Error::last_os_error(),
            ));
        }
        if directory_handle_identity(&directory.parent_file, &directory.parent_path)?
            != directory.parent_identity
        {
            return Err(SafetyStoreErrorV0::Conflict(
                SafetyStoreConflictV0::FileIdentityChanged,
            ));
        }
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err(SafetyStoreErrorV0::UnsupportedPlatform)
    }
}

fn validate_exact_h1_state_sync_initialization_connection_v0<V: SignatureVerifier>(
    connection: &Connection,
    profile: &SafetyStateStoreProfileV0,
    verifier: &V,
    prepared: &PreparedH1StateSyncInitializationV0,
    require_wal_mode: bool,
) -> Result<(), SafetyStoreErrorV0> {
    let journal_id = prepared.intent.journal_id;
    validate_canonical_schema(connection)?;
    validate_metadata(connection, profile, journal_id)?;
    validate_storage_resource_bounds(connection, profile)?;
    if require_wal_mode {
        let journal_mode: String = connection
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))
            .map_err(|error| {
                SafetyStoreErrorV0::sqlite("audit initialization journal mode", error)
            })?;
        if !journal_mode.eq_ignore_ascii_case("wal") {
            return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                "h1 initialization database is not WAL",
            ));
        }
    }
    let integrity: String = connection
        .query_row("PRAGMA integrity_check", [], |row| row.get(0))
        .map_err(|error| SafetyStoreErrorV0::sqlite("audit initialization integrity", error))?;
    if integrity != "ok" {
        return Err(SafetyStoreErrorV0::IntegrityFailure);
    }
    let mut foreign_keys = connection
        .prepare("PRAGMA foreign_key_check")
        .map_err(|error| SafetyStoreErrorV0::sqlite("prepare initialization FK audit", error))?;
    if foreign_keys
        .query([])
        .map_err(|error| SafetyStoreErrorV0::sqlite("run initialization FK audit", error))?
        .next()
        .map_err(|error| SafetyStoreErrorV0::sqlite("read initialization FK audit", error))?
        .is_some()
    {
        return Err(SafetyStoreErrorV0::ForeignKeyFailure);
    }
    drop(foreign_keys);
    let validated = validate_all_records(connection, profile, verifier, journal_id)?;
    if validated.consumed_finalization.is_some()
        || read_active_record(connection)? != prepared.stored
        || read_head(connection, journal_id)? != (0, prepared.stored.chain_checksum, 0)
        || read_validated_durable_halt(connection, journal_id)?.is_some()
    {
        return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
            "committed h1 initialization differs from its exact intent",
        ));
    }
    Ok(())
}

fn chain_checksum(
    journal_id: [u8; 32],
    revision: u64,
    predecessor_revision: Option<u64>,
    predecessor_checksum: Option<[u8; 32]>,
    state_record_checksum: [u8; 32],
    transition_context_checksum: [u8; 32],
) -> [u8; 32] {
    let revision = revision.to_be_bytes();
    let predecessor_tag = [u8::from(predecessor_revision.is_some())];
    let predecessor_revision = predecessor_revision.unwrap_or(0).to_be_bytes();
    let predecessor_checksum = predecessor_checksum.unwrap_or([0; 32]);
    hash_domain(
        CHAIN_DOMAIN_V0,
        &[
            &journal_id,
            &revision,
            &predecessor_tag,
            &predecessor_revision,
            &predecessor_checksum,
            &state_record_checksum,
            &transition_context_checksum,
        ],
    )
}

fn head_checksum(
    journal_id: [u8; 32],
    revision: u64,
    chain_checksum: [u8; 32],
    floor: u64,
) -> [u8; 32] {
    hash_domain(
        HEAD_DOMAIN_V0,
        &[
            &journal_id,
            &revision.to_be_bytes(),
            &chain_checksum,
            &floor.to_be_bytes(),
        ],
    )
}

fn validate_transaction_environment(
    connection: &Connection,
    profile: &SafetyStateStoreProfileV0,
    journal_id: [u8; 32],
) -> Result<(), SafetyStoreErrorV0> {
    validate_canonical_schema(connection)?;
    validate_metadata(connection, profile, journal_id)
}

struct ObservedDurabilityStateV0<'a> {
    head_watermark: &'a mut LockWatermarkV0,
    halt_latch: &'a mut Option<DurableHaltLatchV0>,
}

#[derive(Clone, Copy)]
struct ConflictStableHeadV0 {
    sequence: u64,
    journal_id: [u8; 32],
    revision: u64,
    chain_checksum: [u8; 32],
}

fn commit_conflict(
    transaction: rusqlite::Transaction<'_>,
    sticky_halt: &AtomicBool,
    lock_file: &mut File,
    observed: ObservedDurabilityStateV0<'_>,
    stable_head: ConflictStableHeadV0,
    conflict: SafetyStoreConflictV0,
) -> SafetyStoreErrorV0 {
    sticky_halt.store(true, Ordering::Release);
    let halt = halt_fact_for_conflict(stable_head.journal_id, conflict);
    let stable = LockWatermarkV0::Stable {
        sequence: stable_head.sequence,
        journal_id: stable_head.journal_id,
        revision: stable_head.revision,
        chain_checksum: stable_head.chain_checksum,
    };
    if *observed.head_watermark != stable {
        return SafetyStoreErrorV0::PersistedRepresentationMalformed(
            "conflict did not begin from its exact stable watermark",
        );
    }
    let halt_latch = DurableHaltLatchV0 {
        head_watermark: stable,
        halt,
    };
    // The terminal latch must reach stable storage before SQLite can commit
    // the redundant halt row. It occupies a third region and never overwrites
    // either recoverable head slot.
    if let Err(source) = write_halt_latch(lock_file, halt_latch) {
        return conflict_halt_uncertain(conflict, source);
    }
    let readback_latch = match read_halt_latch(lock_file) {
        Ok(Some(latch)) => latch,
        Ok(None) => {
            return conflict_halt_uncertain(
                conflict,
                SafetyStoreErrorV0::PersistedRepresentationMalformed(
                    "terminal halt latch disappeared after write",
                ),
            );
        }
        Err(source) => {
            return conflict_halt_uncertain(conflict, source);
        }
    };
    if readback_latch != halt_latch {
        return conflict_halt_uncertain(
            conflict,
            SafetyStoreErrorV0::PersistedRepresentationMalformed(
                "terminal halt latch readback differs",
            ),
        );
    }
    *observed.halt_latch = Some(halt_latch);

    let _storage_result = if conflict == SafetyStoreConflictV0::HeadChanged {
        // This defensive CAS branch is reached only after candidate record
        // writes were staged. Keep the exact durable latch, but roll those
        // writes back so a reopen can validate the unchanged source database
        // before honoring the latch.
        transaction.rollback()
    } else {
        let revision_blob = halt.revision.map(u64::to_be_bytes);
        let halt_checksum = durable_halt_checksum(stable_head.journal_id, halt);
        transaction
            .execute(
                "INSERT OR IGNORE INTO safety_store_halt_v0(
                    singleton, reason_code, revision_be, evidence_checksum, halt_checksum
                 ) VALUES (1, ?1, ?2, ?3, ?4)",
                params![
                    halt.reason_code,
                    revision_blob.as_ref().map(<[u8; 8]>::as_slice),
                    halt.evidence_checksum.as_slice(),
                    halt_checksum.as_slice(),
                ],
            )
            .and_then(|_| transaction.commit())
    };
    // The sidecar is already a terminal, fsynced halt capability. The SQLite
    // row is only a redundant, deeply validated copy, so a SQLite error cannot
    // make this conflict retryable or uncertain.
    SafetyStoreErrorV0::Conflict(conflict)
}

fn conflict_halt_uncertain(
    conflict: SafetyStoreConflictV0,
    source: SafetyStoreErrorV0,
) -> SafetyStoreErrorV0 {
    SafetyStoreErrorV0::ConflictHaltUncertain {
        conflict,
        source: Box::new(source),
    }
}

fn halt_fact_for_conflict(
    journal_id: [u8; 32],
    conflict: SafetyStoreConflictV0,
) -> DurableHaltFactV0 {
    let (reason_code, revision) = match conflict {
        SafetyStoreConflictV0::RevisionRegression { incoming, .. } => (1i64, Some(incoming)),
        SafetyStoreConflictV0::RevisionGap { incoming, .. } => (2, Some(incoming)),
        SafetyStoreConflictV0::SameRevisionDifferentRecord { revision } => (3, Some(revision)),
        SafetyStoreConflictV0::HeadChanged => (4, None),
        SafetyStoreConflictV0::CommitReadbackConflict => (5, None),
        SafetyStoreConflictV0::FileIdentityChanged => (6, None),
        SafetyStoreConflictV0::ProcessChanged => (7, None),
    };
    let evidence = format!("{conflict:?}");
    let revision_bytes = revision.unwrap_or(0).to_be_bytes();
    let evidence_checksum = hash_domain(
        HALT_DOMAIN_V0,
        &[
            &journal_id,
            &reason_code.to_be_bytes(),
            &revision_bytes,
            evidence.as_bytes(),
        ],
    );
    DurableHaltFactV0 {
        reason_code,
        revision,
        evidence_checksum,
    }
}

fn durable_halt_checksum(journal_id: [u8; 32], halt: DurableHaltFactV0) -> [u8; 32] {
    hash_domain(
        HALT_DOMAIN_V0,
        &[
            &journal_id,
            &halt.reason_code.to_be_bytes(),
            &halt.revision.unwrap_or(0).to_be_bytes(),
            &halt.evidence_checksum,
        ],
    )
}

fn durable_halt_present(connection: &Connection) -> Result<bool, SafetyStoreErrorV0> {
    connection
        .query_row(
            "SELECT 1 FROM safety_store_halt_v0 WHERE singleton=1",
            [],
            |_| Ok(()),
        )
        .optional()
        .map(|value| value.is_some())
        .map_err(|error| SafetyStoreErrorV0::sqlite("read durable halt", error))
}

fn ensure_not_halted_connection(connection: &Connection) -> Result<(), SafetyStoreErrorV0> {
    if durable_halt_present(connection)? {
        return Err(SafetyStoreErrorV0::DurableHalt);
    }
    Ok(())
}

fn read_validated_durable_halt(
    connection: &Connection,
    journal_id: [u8; 32],
) -> Result<Option<DurableHaltFactV0>, SafetyStoreErrorV0> {
    let row: Option<StoredHaltRowV0> = connection
        .query_row(
            "SELECT reason_code, revision_be, evidence_checksum, halt_checksum
             FROM safety_store_halt_v0 WHERE singleton=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()
        .map_err(|error| SafetyStoreErrorV0::sqlite("validate durable halt", error))?;
    let Some((reason, revision, evidence, stored)) = row else {
        return Ok(None);
    };
    let revision = revision
        .as_deref()
        .map(|bytes| decode_u64_blob(bytes, "halt revision"))
        .transpose()?;
    let evidence = decode_array32(&evidence, "halt evidence checksum")?;
    let halt = DurableHaltFactV0 {
        reason_code: reason,
        revision,
        evidence_checksum: evidence,
    };
    if !durable_halt_fact_is_well_formed(halt) {
        return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
            "durable halt fields",
        ));
    }
    let expected = durable_halt_checksum(journal_id, halt);
    if stored.as_slice() != expected.as_slice() {
        return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
            "durable halt checksum",
        ));
    }
    Ok(Some(halt))
}

fn validate_database_contents_snapshot_v0<V: SignatureVerifier>(
    connection: &Connection,
    profile: &SafetyStateStoreProfileV0,
    verifier: &V,
    journal_id: [u8; 32],
) -> Result<(u64, [u8; 32], Option<DurableHaltFactV0>), SafetyStoreErrorV0> {
    validate_canonical_schema(connection)?;
    validate_metadata(connection, profile, journal_id)?;
    validate_storage_resource_bounds(connection, profile)?;
    let integrity: String = connection
        .query_row("PRAGMA integrity_check", [], |row| row.get(0))
        .map_err(|error| SafetyStoreErrorV0::sqlite("run integrity check", error))?;
    if integrity != "ok" {
        return Err(SafetyStoreErrorV0::IntegrityFailure);
    }
    let mut foreign_keys = connection
        .prepare("PRAGMA foreign_key_check")
        .map_err(|error| SafetyStoreErrorV0::sqlite("prepare foreign-key check", error))?;
    if foreign_keys
        .query([])
        .map_err(|error| SafetyStoreErrorV0::sqlite("run foreign-key check", error))?
        .next()
        .map_err(|error| SafetyStoreErrorV0::sqlite("read foreign-key check", error))?
        .is_some()
    {
        return Err(SafetyStoreErrorV0::ForeignKeyFailure);
    }
    drop(foreign_keys);
    validate_all_records(connection, profile, verifier, journal_id)?;
    let (active_revision, active_chain_checksum, _) = read_head(connection, journal_id)?;
    let durable_halt = read_validated_durable_halt(connection, journal_id)?;
    Ok((active_revision, active_chain_checksum, durable_halt))
}

fn validate_open_watermark_closure_v0(
    active_revision: u64,
    active_chain_checksum: [u8; 32],
    durable_halt: Option<DurableHaltFactV0>,
    lock_watermark: LockWatermarkV0,
    halt_latch: Option<DurableHaltLatchV0>,
    journal_id: [u8; 32],
) -> Result<ValidatedOpenWatermarkV0, SafetyStoreErrorV0> {
    let validated = match lock_watermark {
        LockWatermarkV0::Stable {
            journal_id: stored_journal_id,
            revision,
            chain_checksum,
            ..
        } if stored_journal_id == journal_id
            && revision == active_revision
            && chain_checksum == active_chain_checksum =>
        {
            ValidatedOpenWatermarkV0 {
                revision,
                chain_checksum,
                needs_head_resolution: false,
            }
        }
        LockWatermarkV0::HeadIntent {
            journal_id: stored_journal_id,
            source_revision,
            source_chain_checksum,
            target_revision,
            target_chain_checksum,
            ..
        } if stored_journal_id == journal_id => {
            if active_revision == source_revision && active_chain_checksum == source_chain_checksum
            {
                ValidatedOpenWatermarkV0 {
                    revision: source_revision,
                    chain_checksum: source_chain_checksum,
                    needs_head_resolution: true,
                }
            } else if active_revision == target_revision
                && active_chain_checksum == target_chain_checksum
            {
                ValidatedOpenWatermarkV0 {
                    revision: target_revision,
                    chain_checksum: target_chain_checksum,
                    needs_head_resolution: true,
                }
            } else {
                return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                    "intent watermark matches neither exact source nor exact target",
                ));
            }
        }
        _ => {
            return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                "database head differs from durable lock watermark",
            ));
        }
    };

    if let Some(latch) = halt_latch {
        if latch.head_watermark != lock_watermark {
            return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                "terminal halt latch differs from selected head watermark",
            ));
        }
        if durable_halt.is_some_and(|stored| stored != latch.halt) {
            return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                "durable halt row differs from terminal halt latch",
            ));
        }
        return Err(SafetyStoreErrorV0::DurableHalt);
    }
    if durable_halt.is_some() {
        return Err(SafetyStoreErrorV0::DurableHalt);
    }
    Ok(validated)
}

fn preflight_current_journal_schema(database_path: &Path) -> Result<(), SafetyStoreErrorV0> {
    let uri = immutable_sqlite_uri(database_path);
    let connection = Connection::open_with_flags(
        uri,
        OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_URI
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .map_err(|error| SafetyStoreErrorV0::sqlite("open immutable schema preflight", error))?;
    validate_canonical_schema(&connection)
}

fn preflight_current_journal_namespace_v0<V: SignatureVerifier>(
    database_path: &Path,
    database_file: &File,
    wal_file: &File,
    shm_file: &File,
    facts: OrdinaryOpenPreflightFactsV0<'_, V>,
) -> Result<(), SafetyStoreErrorV0> {
    let OrdinaryOpenPreflightFactsV0 {
        profile,
        verifier,
        journal_id,
        lock_watermark,
        halt_latch,
    } = facts;
    let wal_path = sqlite_auxiliary_path(database_path, "-wal");
    let shm_path = sqlite_auxiliary_path(database_path, "-shm");
    let database_identity = file_handle_identity(database_file, database_path)?;
    let wal_identity = file_handle_identity(wal_file, &wal_path)?;
    let shm_identity = file_handle_identity(shm_file, &shm_path)?;
    // SQLite's Unix VFS only trusts a persisted wal-index while another
    // process retains the SHM deadman-switch lock. Claim that byte before
    // classifying any WAL bytes. The same-process live open below inherits
    // the process-scoped lock, truncates the old wal-index, and rebuilds it
    // from the already audited WAL rather than trusting persisted SHM bytes.
    acquire_sqlite_shm_reset_guard_v0(shm_file)?;
    let database_image_before = pinned_file_image_commitment_v0(
        database_file,
        profile.maximum_database_bytes(),
        "commit main before schema preflight",
    )?;
    let wal_image_before = pinned_file_image_commitment_v0(
        wal_file,
        profile.maximum_database_bytes(),
        "commit WAL before schema preflight",
    )?;
    let shm_image_before = pinned_file_image_commitment_preserving_locks_v0(
        shm_file,
        profile.maximum_database_bytes(),
        "commit SHM before schema preflight",
    )?;
    let directory_path = database_path
        .parent()
        .ok_or(SafetyStoreErrorV0::InvalidProfile("database parent"))?;
    let directory_identity_before = directory_identity(directory_path)?;

    let preflight_result = (|| {
        // The checkpointed main database must itself be the current journal
        // schema. A newer WAL cannot serve as an implicit migration from an
        // historical main image.
        preflight_current_journal_schema(database_path)?;
        let wal =
            recoverable_current_journal_wal_prefix_v0(wal_file, profile.maximum_database_bytes())?;
        if let RecoverableCurrentJournalWalV0::Invalid(reason) = wal {
            return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(reason));
        }

        let audit_directory = create_initialization_audit_directory_v0(database_path)?;
        let audit_database = audit_directory.database_path_v0();
        let audit_wal = sqlite_auxiliary_path(&audit_database, "-wal");
        let audit_result = (|| {
            copy_pinned_initialization_file_v0(
                database_file,
                &audit_database,
                profile.maximum_database_bytes(),
            )?;
            let audit_wal_file = match wal {
                RecoverableCurrentJournalWalV0::NoCommit => {
                    // Do not copy a header-only, torn, or wholly uncommitted
                    // live WAL into the audit projection. SQLite recovery
                    // selects the checkpointed main image in every such case.
                    create_new_private_file(&audit_wal, "create empty ordinary WAL audit copy")?
                }
                RecoverableCurrentJournalWalV0::Committed { prefix_bytes } => {
                    copy_pinned_initialization_file_v0(
                        wal_file,
                        &audit_wal,
                        profile.maximum_database_bytes(),
                    )?;
                    // Never copy the persisted live wal-index. The independent
                    // audit namespace has no SHM entry, so SQLite derives its
                    // index from only the checksum-valid committed prefix.
                    let file =
                        open_existing_private_file(&audit_wal, "open recoverable WAL audit copy")?;
                    file.set_len(prefix_bytes).map_err(|error| {
                        SafetyStoreErrorV0::io("truncate recoverable WAL audit copy", error)
                    })?;
                    file
                }
                RecoverableCurrentJournalWalV0::Invalid(_) => {
                    return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                        "invalid ordinary WAL reached snapshot audit",
                    ));
                }
            };
            audit_wal_file.sync_all().map_err(|error| {
                SafetyStoreErrorV0::io("sync recoverable WAL audit copy", error)
            })?;
            drop(audit_wal_file);
            with_pinned_audit_connection_v0(
                &audit_database,
                &audit_wal,
                profile.maximum_database_bytes(),
                "open WAL schema audit snapshot",
                |connection| {
                    configure_connection(connection, false, profile.maximum_database_bytes())?;
                    let (revision, chain_checksum, durable_halt) =
                        validate_database_contents_snapshot_v0(
                            connection, profile, verifier, journal_id,
                        )?;
                    validate_open_watermark_closure_v0(
                        revision,
                        chain_checksum,
                        durable_halt,
                        lock_watermark,
                        halt_latch,
                        journal_id,
                    )?;
                    Ok(())
                },
            )
        })();
        let cleanup_result = cleanup_initialization_audit_directory_v0(&audit_directory);
        cleanup_result?;
        audit_result
    })();

    let database_image_after = pinned_file_image_commitment_v0(
        database_file,
        profile.maximum_database_bytes(),
        "commit main after schema preflight",
    )?;
    let wal_image_after = pinned_file_image_commitment_v0(
        wal_file,
        profile.maximum_database_bytes(),
        "commit WAL after schema preflight",
    )?;
    let shm_image_after = pinned_file_image_commitment_preserving_locks_v0(
        shm_file,
        profile.maximum_database_bytes(),
        "commit SHM after schema preflight",
    )?;
    if file_handle_identity(database_file, database_path)? != database_identity
        || file_identity(database_path)? != database_identity
        || file_handle_identity(wal_file, &wal_path)? != wal_identity
        || file_identity(&wal_path)? != wal_identity
        || file_handle_identity(shm_file, &shm_path)? != shm_identity
        || file_identity(&shm_path)? != shm_identity
        || directory_identity(directory_path)? != directory_identity_before
        || database_image_after != database_image_before
        || wal_image_after != wal_image_before
        || shm_image_after != shm_image_before
    {
        return Err(SafetyStoreErrorV0::Conflict(
            SafetyStoreConflictV0::FileIdentityChanged,
        ));
    }
    preflight_result
}

#[cfg(target_os = "linux")]
fn acquire_sqlite_shm_reset_guard_v0(shm_file: &File) -> Result<(), SafetyStoreErrorV0> {
    use std::os::fd::AsRawFd;

    // Bundled SQLite's Unix WAL layout fixes the deadman switch at byte 128:
    // (22 + SQLITE_SHM_NLOCK) * 4 + SQLITE_SHM_NLOCK, with
    // SQLITE_SHM_NLOCK=8. Taking the process-scoped write lock proves that no
    // other process can currently make the persisted wal-index authoritative.
    // Do not unlock it here: the subsequent SQLite open in this process takes
    // over the byte, resets SHM, and downgrades it to SQLite's shared DMS lock.
    const SQLITE_SHM_DEADMAN_SWITCH_OFFSET_V0: libc::off_t = 128;
    // SAFETY: all-zero is a valid initial `flock`; every field consumed by
    // F_SETLK is assigned below before the syscall.
    let mut lock: libc::flock = unsafe { std::mem::zeroed() };
    lock.l_type = libc::F_WRLCK as _;
    lock.l_whence = libc::SEEK_SET as _;
    lock.l_start = SQLITE_SHM_DEADMAN_SWITCH_OFFSET_V0;
    lock.l_len = 1;
    // SAFETY: `shm_file` owns a live descriptor and `lock` remains writable
    // for the duration of this nonblocking F_SETLK call.
    if unsafe { libc::fcntl(shm_file.as_raw_fd(), libc::F_SETLK, &lock) } == 0 {
        return Ok(());
    }
    let error = io::Error::last_os_error();
    if matches!(
        error.raw_os_error(),
        Some(libc::EACCES) | Some(libc::EAGAIN)
    ) {
        Err(SafetyStoreErrorV0::Locked)
    } else {
        Err(SafetyStoreErrorV0::io(
            "acquire SQLite SHM reset guard",
            error,
        ))
    }
}

#[cfg(not(target_os = "linux"))]
fn acquire_sqlite_shm_reset_guard_v0(_shm_file: &File) -> Result<(), SafetyStoreErrorV0> {
    Err(SafetyStoreErrorV0::UnsupportedPlatform)
}

#[cfg(target_os = "linux")]
fn immutable_sqlite_uri(database_path: &Path) -> String {
    use std::os::unix::ffi::OsStrExt;

    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut uri = String::with_capacity(database_path.as_os_str().len().saturating_mul(3) + 17);
    uri.push_str("file:");
    for byte in database_path.as_os_str().as_bytes() {
        if byte.is_ascii_alphanumeric() || matches!(*byte, b'/' | b'-' | b'.' | b'_' | b'~') {
            uri.push(char::from(*byte));
        } else {
            uri.push('%');
            uri.push(char::from(HEX[usize::from(*byte >> 4)]));
            uri.push(char::from(HEX[usize::from(*byte & 0x0f)]));
        }
    }
    uri.push_str("?immutable=1");
    uri
}

#[cfg(not(target_os = "linux"))]
fn immutable_sqlite_uri(_database_path: &Path) -> String {
    String::new()
}

fn configure_connection(
    connection: &Connection,
    initialize: bool,
    maximum_database_bytes: usize,
) -> Result<(), SafetyStoreErrorV0> {
    connection
        .busy_timeout(DEFAULT_BUSY_TIMEOUT)
        .map_err(|error| SafetyStoreErrorV0::sqlite("configure busy timeout", error))?;
    if initialize {
        connection
            .execute_batch("PRAGMA page_size=4096; PRAGMA journal_mode=WAL;")
            .map_err(|error| SafetyStoreErrorV0::sqlite("enable SQLite WAL", error))?;
    }
    connection
        .execute_batch(
            "PRAGMA synchronous=FULL;
             PRAGMA foreign_keys=ON;
             PRAGMA trusted_schema=OFF;
             PRAGMA recursive_triggers=OFF;",
        )
        .map_err(|error| SafetyStoreErrorV0::sqlite("configure SQLite safety", error))?;
    let page_size: i64 = connection
        .query_row("PRAGMA page_size", [], |row| row.get(0))
        .map_err(|error| SafetyStoreErrorV0::sqlite("read SQLite page size", error))?;
    if page_size <= 0 {
        return Err(SafetyStoreErrorV0::InvalidProfile("SQLite page size"));
    }
    let max_pages = (maximum_database_bytes as u64) / (page_size as u64);
    if max_pages == 0 || max_pages > i64::MAX as u64 {
        return Err(SafetyStoreErrorV0::InvalidProfile(
            "SQLite maximum page count",
        ));
    }
    connection
        .pragma_update(None, "max_page_count", max_pages as i64)
        .map_err(|error| SafetyStoreErrorV0::sqlite("set SQLite page bound", error))?;
    connection
        .pragma_update(None, "journal_size_limit", maximum_database_bytes as i64)
        .map_err(|error| SafetyStoreErrorV0::sqlite("set SQLite WAL bound", error))?;
    let journal_mode: String = connection
        .query_row("PRAGMA journal_mode", [], |row| row.get(0))
        .map_err(|error| SafetyStoreErrorV0::sqlite("read journal mode", error))?;
    if !journal_mode.eq_ignore_ascii_case("wal") {
        return Err(SafetyStoreErrorV0::InvalidProfile(
            "SQLite journal is not WAL",
        ));
    }
    enable_persistent_wal(connection)?;
    let synchronous: i64 = connection
        .query_row("PRAGMA synchronous", [], |row| row.get(0))
        .map_err(|error| SafetyStoreErrorV0::sqlite("read synchronous mode", error))?;
    let foreign_keys: i64 = connection
        .query_row("PRAGMA foreign_keys", [], |row| row.get(0))
        .map_err(|error| SafetyStoreErrorV0::sqlite("read foreign-key mode", error))?;
    let trusted_schema: i64 = connection
        .query_row("PRAGMA trusted_schema", [], |row| row.get(0))
        .map_err(|error| SafetyStoreErrorV0::sqlite("read trusted-schema mode", error))?;
    let configured_max_pages: i64 = connection
        .query_row("PRAGMA max_page_count", [], |row| row.get(0))
        .map_err(|error| SafetyStoreErrorV0::sqlite("read SQLite page bound", error))?;
    let current_pages: i64 = connection
        .query_row("PRAGMA page_count", [], |row| row.get(0))
        .map_err(|error| SafetyStoreErrorV0::sqlite("read SQLite page count", error))?;
    if synchronous != 2
        || foreign_keys != 1
        || trusted_schema != 0
        || configured_max_pages <= 0
        || configured_max_pages > max_pages as i64
        || current_pages < 0
        || current_pages > configured_max_pages
    {
        return Err(SafetyStoreErrorV0::InvalidProfile(
            "SQLite durability PRAGMAs",
        ));
    }
    Ok(())
}

fn enable_persistent_wal(connection: &Connection) -> Result<(), SafetyStoreErrorV0> {
    let mut enabled = 1i32;
    // SAFETY: the connection remains alive for the call, `main` is a static
    // NUL-terminated database name, and SQLite expects an `int *` for this
    // file-control opcode.
    let result = unsafe {
        rusqlite::ffi::sqlite3_file_control(
            connection.handle(),
            c"main".as_ptr(),
            rusqlite::ffi::SQLITE_FCNTL_PERSIST_WAL,
            (&mut enabled as *mut i32).cast(),
        )
    };
    if result != rusqlite::ffi::SQLITE_OK || enabled != 1 {
        return Err(SafetyStoreErrorV0::sqlite(
            "enable persistent SQLite WAL",
            rusqlite::Error::SqliteFailure(
                rusqlite::ffi::Error::new(result),
                Some("SQLITE_FCNTL_PERSIST_WAL was not accepted".to_owned()),
            ),
        ));
    }
    Ok(())
}

fn checkpoint_and_sync_initialization(
    connection: &Connection,
    database_file: &File,
    directory_file: &File,
) -> Result<(), SafetyStoreErrorV0> {
    connection
        .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
        .map_err(|error| SafetyStoreErrorV0::sqlite("checkpoint initialized journal", error))?;
    database_file
        .sync_all()
        .map_err(|error| SafetyStoreErrorV0::io("sync initialized database", error))?;
    sync_directory_handle(directory_file)
}

fn validate_private_directory(path: &Path) -> Result<(), SafetyStoreErrorV0> {
    let metadata = fs::metadata(path)
        .map_err(|error| SafetyStoreErrorV0::io("stat safety-store directory", error))?;
    if !metadata.is_dir() {
        return Err(SafetyStoreErrorV0::InvalidProfile(
            "safety-store parent is not a directory",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        // SAFETY: `geteuid` has no pointer arguments and no caller obligations.
        let effective_uid = unsafe { libc::geteuid() };
        if metadata.uid() != effective_uid || metadata.mode() & 0o022 != 0 {
            return Err(SafetyStoreErrorV0::InvalidProfile(
                "safety-store parent must be owner-controlled and non-writable by peers",
            ));
        }
        let mut ancestor = path.parent();
        while let Some(directory) = ancestor {
            let metadata = fs::metadata(directory).map_err(|error| {
                SafetyStoreErrorV0::io("stat safety-store ancestor directory", error)
            })?;
            if !metadata.is_dir() {
                return Err(SafetyStoreErrorV0::InvalidProfile(
                    "safety-store ancestor is not a directory",
                ));
            }
            let peer_writable = metadata.mode() & 0o022 != 0;
            let trusted_sticky_root = metadata.mode() & 0o1000 != 0 && metadata.uid() == 0;
            if peer_writable && !trusted_sticky_root {
                return Err(SafetyStoreErrorV0::InvalidProfile(
                    "safety-store ancestor namespace is peer-writable",
                ));
            }
            ancestor = directory.parent();
        }
    }
    Ok(())
}

fn sqlite_auxiliary_path(database_path: &Path, suffix: &str) -> PathBuf {
    let mut name = database_path.as_os_str().to_os_string();
    name.push(suffix);
    PathBuf::from(name)
}

fn ensure_sqlite_auxiliary_files_absent(database_path: &Path) -> Result<(), SafetyStoreErrorV0> {
    for suffix in ["-wal", "-shm", "-journal"] {
        let path = sqlite_auxiliary_path(database_path, suffix);
        match fs::symlink_metadata(&path) {
            Ok(_) => return Err(SafetyStoreErrorV0::AlreadyExists("SQLite auxiliary file")),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(SafetyStoreErrorV0::io(
                    "inspect SQLite auxiliary file",
                    error,
                ));
            }
        }
    }
    Ok(())
}

fn inspect_initialization_auxiliary_state_v0(
    database_path: &Path,
    maximum_database_bytes: usize,
) -> Result<InitializationAuxiliaryStateV0, SafetyStoreErrorV0> {
    validate_sqlite_auxiliary_files(database_path, maximum_database_bytes)?;
    let bytes = |suffix: &str, stage: &'static str| -> Result<Option<u64>, SafetyStoreErrorV0> {
        let path = sqlite_auxiliary_path(database_path, suffix);
        match fs::symlink_metadata(&path) {
            Ok(metadata) => Ok(Some(metadata.len())),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(SafetyStoreErrorV0::io(stage, error)),
        }
    };
    Ok(InitializationAuxiliaryStateV0 {
        wal_bytes: bytes("-wal", "inspect h1 initialization WAL")?,
        shm_bytes: bytes("-shm", "inspect h1 initialization SHM")?,
    })
}

fn preflight_unowned_initialization_namespace_v0(
    database_path: &Path,
    database_exists: bool,
    lock_exists: bool,
    auxiliary: InitializationAuxiliaryStateV0,
    maximum_database_bytes: usize,
) -> Result<(), SafetyStoreErrorV0> {
    if database_exists {
        let database_file =
            open_existing_private_file(database_path, "preflight unowned initialization database")?;
        let database_identity = file_handle_identity(&database_file, database_path)?;
        let metadata = database_file.metadata().map_err(|error| {
            SafetyStoreErrorV0::io("stat unowned initialization database", error)
        })?;
        if u128::from(metadata.len()) > maximum_database_bytes as u128 {
            return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                "unowned initialization database exceeds bound",
            ));
        }
        if metadata.len() != 0 {
            preflight_current_journal_schema(database_path)?;
        }
        if file_identity(database_path)? != database_identity {
            return Err(SafetyStoreErrorV0::Conflict(
                SafetyStoreConflictV0::FileIdentityChanged,
            ));
        }
    }
    if lock_exists {
        let lock_path = lock_path_for(database_path)?;
        let lock_file = open_existing_private_file(&lock_path, "preflight unowned lock sidecar")?;
        file_handle_identity(&lock_file, &lock_path)?;
    }
    if auxiliary.wal_bytes.is_some() || auxiliary.shm_bytes.is_some() {
        validate_sqlite_auxiliary_files(database_path, maximum_database_bytes)?;
    }
    Ok(())
}

fn require_persistent_sqlite_auxiliary_files(
    database_path: &Path,
) -> Result<(), SafetyStoreErrorV0> {
    for (suffix, target) in [("-wal", "persistent WAL"), ("-shm", "persistent SHM")] {
        let path = sqlite_auxiliary_path(database_path, suffix);
        match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_file() => {}
            Ok(_) => {
                return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                    "persistent SQLite auxiliary path is not a regular file",
                ));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(SafetyStoreErrorV0::Missing(target));
            }
            Err(error) => {
                return Err(SafetyStoreErrorV0::io(
                    "inspect persistent SQLite auxiliary file",
                    error,
                ));
            }
        }
    }
    Ok(())
}

fn materialize_sqlite_auxiliary_files(connection: &Connection) -> Result<(), SafetyStoreErrorV0> {
    connection
        .execute_batch("BEGIN IMMEDIATE; ROLLBACK;")
        .map_err(|error| SafetyStoreErrorV0::sqlite("materialize SQLite WAL namespace", error))
}

fn pin_sqlite_auxiliary_files(
    database_path: &Path,
    maximum_database_bytes: usize,
) -> Result<(File, FileIdentityV0, File, FileIdentityV0), SafetyStoreErrorV0> {
    validate_sqlite_auxiliary_files(database_path, maximum_database_bytes)?;
    let wal_path = sqlite_auxiliary_path(database_path, "-wal");
    let shm_path = sqlite_auxiliary_path(database_path, "-shm");
    let wal_file = pin_sqlite_auxiliary_file(&wal_path, "pin SQLite WAL")?;
    let shm_file = pin_sqlite_auxiliary_file(&shm_path, "pin SQLite shared memory")?;
    let wal_identity = file_handle_identity(&wal_file, &wal_path)?;
    let shm_identity = file_handle_identity(&shm_file, &shm_path)?;
    if !canonical_path_is_stable(&wal_path)?
        || !canonical_path_is_stable(&shm_path)?
        || file_identity(&wal_path)? != wal_identity
        || file_identity(&shm_path)? != shm_identity
    {
        return Err(SafetyStoreErrorV0::Conflict(
            SafetyStoreConflictV0::FileIdentityChanged,
        ));
    }
    Ok((wal_file, wal_identity, shm_file, shm_identity))
}

fn pin_sqlite_auxiliary_file(path: &Path, stage: &'static str) -> Result<File, SafetyStoreErrorV0> {
    let file = open_existing_private_file(path, stage)?;
    acquire_lifetime_lock(&file)?;
    Ok(file)
}

fn validate_sqlite_auxiliary_files(
    database_path: &Path,
    maximum_database_bytes: usize,
) -> Result<(), SafetyStoreErrorV0> {
    let rollback_journal = sqlite_auxiliary_path(database_path, "-journal");
    match fs::symlink_metadata(&rollback_journal) {
        Ok(_) => {
            return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                "rollback journal is forbidden for WAL safety store",
            ));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(SafetyStoreErrorV0::io(
                "inspect SQLite rollback journal",
                error,
            ));
        }
    }
    for suffix in ["-wal", "-shm"] {
        let path = sqlite_auxiliary_path(database_path, suffix);
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(SafetyStoreErrorV0::io(
                    "inspect SQLite auxiliary file",
                    error,
                ));
            }
        };
        if !metadata.file_type().is_file()
            || u128::from(metadata.len()) > maximum_database_bytes as u128
        {
            return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                "SQLite auxiliary file shape or size",
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            // SAFETY: `geteuid` has no pointer arguments and no caller obligations.
            let effective_uid = unsafe { libc::geteuid() };
            if metadata.nlink() != 1
                || metadata.uid() != effective_uid
                || metadata.mode() & 0o777 != 0o600
            {
                return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                    "SQLite auxiliary file identity or permissions",
                ));
            }
        }
    }
    Ok(())
}

fn canonical_new_path(path: &Path) -> Result<PathBuf, SafetyStoreErrorV0> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        env::current_dir()
            .map_err(|error| SafetyStoreErrorV0::io("resolve current directory", error))?
            .join(path)
    };
    let file_name = absolute
        .file_name()
        .ok_or(SafetyStoreErrorV0::InvalidProfile("database file name"))?;
    validate_database_file_name(file_name)?;
    let parent = absolute
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let parent = match fs::canonicalize(parent) {
        Ok(parent) => parent,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(SafetyStoreErrorV0::Missing(
                "pre-existing safety-store parent directory",
            ));
        }
        Err(error) => {
            return Err(SafetyStoreErrorV0::io(
                "canonicalize safety-store directory",
                error,
            ));
        }
    };
    validate_private_directory(&parent)?;
    Ok(parent.join(file_name))
}

fn canonical_path_is_stable(path: &Path) -> Result<bool, SafetyStoreErrorV0> {
    fs::canonicalize(path)
        .map(|canonical| canonical == path)
        .map_err(|error| SafetyStoreErrorV0::io("verify canonical safety-store path", error))
}

fn ensure_supported_file_identity() -> Result<(), SafetyStoreErrorV0> {
    #[cfg(target_os = "linux")]
    {
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err(SafetyStoreErrorV0::UnsupportedPlatform)
    }
}

fn canonical_existing_database_path(path: &Path) -> Result<PathBuf, SafetyStoreErrorV0> {
    match fs::canonicalize(path) {
        Ok(path) => {
            let file_name = path
                .file_name()
                .ok_or(SafetyStoreErrorV0::InvalidProfile("database file name"))?;
            validate_database_file_name(file_name)?;
            let parent = path
                .parent()
                .ok_or(SafetyStoreErrorV0::InvalidProfile("database parent"))?;
            validate_private_directory(parent)?;
            file_identity(&path)?;
            Ok(path)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            Err(SafetyStoreErrorV0::Missing("database"))
        }
        Err(error) => Err(SafetyStoreErrorV0::io(
            "canonicalize existing database",
            error,
        )),
    }
}

fn validate_database_file_name(file_name: &std::ffi::OsStr) -> Result<(), SafetyStoreErrorV0> {
    let name = file_name.to_string_lossy().to_ascii_lowercase();
    if ["-wal", "-shm", "-journal"]
        .iter()
        .any(|suffix| name.ends_with(suffix))
    {
        return Err(SafetyStoreErrorV0::InvalidProfile(
            "database name collides with SQLite auxiliary namespace",
        ));
    }
    Ok(())
}

fn lock_path_for(database_path: &Path) -> Result<PathBuf, SafetyStoreErrorV0> {
    let file_name = database_path
        .file_name()
        .ok_or(SafetyStoreErrorV0::InvalidProfile("database file name"))?;
    let mut lock_name = OsString::from(file_name);
    lock_name.push(".safety.lock");
    Ok(database_path.with_file_name(lock_name))
}

fn initialization_intent_path_for(database_path: &Path) -> Result<PathBuf, SafetyStoreErrorV0> {
    let file_name = database_path
        .file_name()
        .ok_or(SafetyStoreErrorV0::InvalidProfile("database file name"))?;
    let mut initialization_name = OsString::from(file_name);
    initialization_name.push(".safety.init.v0");
    Ok(database_path.with_file_name(initialization_name))
}

fn initialization_intent_temporary_path_for(
    database_path: &Path,
) -> Result<PathBuf, SafetyStoreErrorV0> {
    let file_name = database_path
        .file_name()
        .ok_or(SafetyStoreErrorV0::InvalidProfile("database file name"))?;
    let mut initialization_name = OsString::from(file_name);
    initialization_name.push(".safety.init.v0.tmp");
    Ok(database_path.with_file_name(initialization_name))
}

fn secure_private_file_exists_v0(
    path: &Path,
    stage: &'static str,
) -> Result<bool, SafetyStoreErrorV0> {
    if !path_exists_v0(path, stage)? {
        return Ok(false);
    }
    let file = open_existing_private_file(path, stage)?;
    let identity = file_handle_identity(&file, path)?;
    if !canonical_path_is_stable(path)? || file_identity(path)? != identity {
        return Err(SafetyStoreErrorV0::Conflict(
            SafetyStoreConflictV0::FileIdentityChanged,
        ));
    }
    Ok(true)
}

fn path_exists_v0(path: &Path, stage: &'static str) -> Result<bool, SafetyStoreErrorV0> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(SafetyStoreErrorV0::io(stage, error)),
    }
}

fn create_new_private_file(path: &Path, stage: &'static str) -> Result<File, SafetyStoreErrorV0> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    options
        .open(path)
        .map_err(|error| SafetyStoreErrorV0::io(stage, error))
}

fn open_existing_private_file(
    path: &Path,
    stage: &'static str,
) -> Result<File, SafetyStoreErrorV0> {
    let mut options = OpenOptions::new();
    options.read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    options
        .open(path)
        .map_err(|error| SafetyStoreErrorV0::io(stage, error))
}

fn publish_h1_state_sync_initialization_intent_v0(
    temporary_file: &File,
    temporary_identity: FileIdentityV0,
    temporary_path: &Path,
    published_path: &Path,
    directory_file: &File,
) -> Result<(), SafetyStoreErrorV0> {
    if file_handle_identity(temporary_file, temporary_path)? != temporary_identity
        || !canonical_path_is_stable(temporary_path)?
        || file_identity(temporary_path)? != temporary_identity
    {
        return Err(SafetyStoreErrorV0::Conflict(
            SafetyStoreConflictV0::FileIdentityChanged,
        ));
    }
    rename_no_replace_v0(temporary_path, published_path)?;
    sync_directory_handle(directory_file)?;
    if path_exists_v0(
        temporary_path,
        "verify retired initialization intent temporary",
    )? || !canonical_path_is_stable(published_path)?
        || file_identity(published_path)? != temporary_identity
        || file_handle_identity(temporary_file, published_path)? != temporary_identity
    {
        return Err(SafetyStoreErrorV0::Conflict(
            SafetyStoreConflictV0::FileIdentityChanged,
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn rename_no_replace_v0(source: &Path, target: &Path) -> Result<(), SafetyStoreErrorV0> {
    use std::os::unix::ffi::OsStrExt;

    let source = CString::new(source.as_os_str().as_bytes()).map_err(|_| {
        SafetyStoreErrorV0::InvalidProfile("initialization temporary path contains NUL")
    })?;
    let target = CString::new(target.as_os_str().as_bytes()).map_err(|_| {
        SafetyStoreErrorV0::InvalidProfile("initialization published path contains NUL")
    })?;
    // SAFETY: both C strings are NUL terminated and remain alive for the
    // syscall. `RENAME_NOREPLACE` provides the required atomic publish without
    // replacing a concurrently created marker.
    let result = unsafe {
        libc::renameat2(
            libc::AT_FDCWD,
            source.as_ptr(),
            libc::AT_FDCWD,
            target.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(SafetyStoreErrorV0::io(
            "atomically publish h1 initialization intent without replacement",
            io::Error::last_os_error(),
        ))
    }
}

#[cfg(not(target_os = "linux"))]
fn rename_no_replace_v0(_source: &Path, _target: &Path) -> Result<(), SafetyStoreErrorV0> {
    Err(SafetyStoreErrorV0::UnsupportedPlatform)
}

fn acquire_lifetime_lock(file: &File) -> Result<(), SafetyStoreErrorV0> {
    match FileExt::try_lock_exclusive(file) {
        Ok(()) => Ok(()),
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::PermissionDenied
            ) =>
        {
            Err(SafetyStoreErrorV0::Locked)
        }
        Err(error) => Err(SafetyStoreErrorV0::io(
            "acquire safety-store lifetime lock",
            error,
        )),
    }
}

fn initialize_lock_file(file: &mut File) -> Result<(), SafetyStoreErrorV0> {
    if file
        .metadata()
        .map_err(|error| SafetyStoreErrorV0::io("stat new lock sidecar", error))?
        .len()
        != 0
    {
        return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
            "new lock sidecar is not empty",
        ));
    }
    file.set_len(LOCK_FILE_BYTES_V0 as u64)
        .map_err(|error| SafetyStoreErrorV0::io("allocate lock watermark slots", error))?;
    file.sync_all()
        .map_err(|error| SafetyStoreErrorV0::io("sync empty lock watermark slots", error))
}

fn complete_owned_initialization_prestate_lock_v0(
    file: &mut File,
) -> Result<(), SafetyStoreErrorV0> {
    let length = file
        .metadata()
        .map_err(|error| SafetyStoreErrorV0::io("stat incomplete initialization lock", error))?
        .len();
    if length > LOCK_FILE_BYTES_V0 as u64 {
        return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
            "incomplete initialization lock is oversized",
        ));
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|error| SafetyStoreErrorV0::io("seek incomplete initialization lock", error))?;
    let mut remaining = length;
    let mut buffer = [0u8; 4096];
    while remaining != 0 {
        let wanted = usize::try_from(remaining.min(buffer.len() as u64)).map_err(|_| {
            SafetyStoreErrorV0::PersistedRepresentationMalformed(
                "incomplete initialization lock size conversion",
            )
        })?;
        file.read_exact(&mut buffer[..wanted]).map_err(|error| {
            SafetyStoreErrorV0::io("read incomplete initialization lock", error)
        })?;
        if buffer[..wanted].iter().any(|byte| *byte != 0) {
            return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                "incomplete initialization lock contains non-prestate bytes",
            ));
        }
        remaining -= wanted as u64;
    }
    file.set_len(LOCK_FILE_BYTES_V0 as u64)
        .map_err(|error| SafetyStoreErrorV0::io("complete initialization lock size", error))?;
    file.sync_all()
        .map_err(|error| SafetyStoreErrorV0::io("sync completed initialization lock", error))?;
    if read_exact_initialization_lock_state_v0(file)? != InitializationLockStateV0::Empty {
        return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
            "completed initialization lock is not exact empty prestate",
        ));
    }
    Ok(())
}

fn read_marker_bound_initialization_lock_state_v0(
    file: &File,
    expected_stable: LockWatermarkV0,
) -> Result<InitializationLockStateV0, SafetyStoreErrorV0> {
    if file
        .metadata()
        .map_err(|error| SafetyStoreErrorV0::io("stat marker-bound initialization lock", error))?
        .len()
        != LOCK_FILE_BYTES_V0 as u64
    {
        return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
            "marker-bound initialization lock size",
        ));
    }
    let mut file = file;
    file.seek(SeekFrom::Start(0))
        .map_err(|error| SafetyStoreErrorV0::io("seek marker-bound initialization lock", error))?;
    let mut bytes = [0u8; LOCK_FILE_BYTES_V0];
    file.read_exact(&mut bytes)
        .map_err(|error| SafetyStoreErrorV0::io("read marker-bound initialization lock", error))?;
    if bytes.iter().all(|byte| *byte == 0) {
        return Ok(InitializationLockStateV0::Empty);
    }
    let expected = encode_lock_slot(expected_stable)?;
    if bytes[..LOCK_SLOT_BYTES_V0] == expected
        && bytes[LOCK_SLOT_BYTES_V0..].iter().all(|byte| *byte == 0)
    {
        return Ok(InitializationLockStateV0::Stable(expected_stable));
    }
    if bytes[LOCK_SLOT_BYTES_V0..].iter().all(|byte| *byte == 0)
        && (1..LOCK_SLOT_BYTES_V0).any(|prefix| {
            bytes[..prefix] == expected[..prefix]
                && bytes[prefix..LOCK_SLOT_BYTES_V0]
                    .iter()
                    .all(|byte| *byte == 0)
        })
    {
        return Ok(InitializationLockStateV0::RecoverableTornStable);
    }
    Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
        "marker-bound initialization lock is mixed, foreign, or tampered",
    ))
}

fn read_exact_initialization_lock_state_v0(
    file: &File,
) -> Result<InitializationLockStateV0, SafetyStoreErrorV0> {
    if file
        .metadata()
        .map_err(|error| SafetyStoreErrorV0::io("stat initialization lock sidecar", error))?
        .len()
        != LOCK_FILE_BYTES_V0 as u64
    {
        return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
            "initialization lock sidecar size",
        ));
    }
    let mut file = file;
    file.seek(SeekFrom::Start(0))
        .map_err(|error| SafetyStoreErrorV0::io("seek initialization lock sidecar", error))?;
    let mut bytes = [0u8; LOCK_FILE_BYTES_V0];
    file.read_exact(&mut bytes)
        .map_err(|error| SafetyStoreErrorV0::io("read initialization lock sidecar", error))?;
    if bytes.iter().all(|byte| *byte == 0) {
        return Ok(InitializationLockStateV0::Empty);
    }
    let watermark = decode_lock_slot(&bytes[..LOCK_SLOT_BYTES_V0], 0).ok_or(
        SafetyStoreErrorV0::PersistedRepresentationMalformed(
            "initialization lock sidecar has no exact Stable slot",
        ),
    )?;
    if !matches!(
        watermark,
        LockWatermarkV0::Stable {
            sequence: 0,
            revision: 0,
            ..
        }
    ) {
        return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
            "initialization lock sidecar is not revision-zero Stable",
        ));
    }
    let encoded = encode_lock_slot(watermark)?;
    if bytes[..LOCK_SLOT_BYTES_V0] != encoded
        || bytes[LOCK_SLOT_BYTES_V0..].iter().any(|byte| *byte != 0)
    {
        return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
            "initialization lock sidecar has mixed or extra state",
        ));
    }
    Ok(InitializationLockStateV0::Stable(watermark))
}

fn write_h1_state_sync_initialization_intent_v0(
    file: &mut File,
    path: &Path,
    intent: H1StateSyncInitializationIntentV0,
) -> Result<(), SafetyStoreErrorV0> {
    if file
        .metadata()
        .map_err(|error| SafetyStoreErrorV0::io("stat new h1 initialization intent", error))?
        .len()
        != 0
    {
        return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
            "new h1 initialization intent is not empty",
        ));
    }
    let bytes = encode_h1_state_sync_initialization_intent_v0(path, intent)?;
    file.write_all(&bytes)
        .map_err(|error| SafetyStoreErrorV0::io("write h1 initialization intent", error))?;
    file.sync_all()
        .map_err(|error| SafetyStoreErrorV0::io("sync h1 initialization intent", error))?;
    if read_h1_state_sync_initialization_intent_v0(file, path)? != intent {
        return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
            "h1 initialization intent readback differs",
        ));
    }
    Ok(())
}

fn rewrite_unpublished_h1_state_sync_initialization_intent_v0(
    file: &mut File,
    identity: FileIdentityV0,
    temporary_path: &Path,
    published_path: &Path,
    intent: H1StateSyncInitializationIntentV0,
) -> Result<(), SafetyStoreErrorV0> {
    if file_handle_identity(file, temporary_path)? != identity
        || !canonical_path_is_stable(temporary_path)?
        || file_identity(temporary_path)? != identity
        || path_exists_v0(
            published_path,
            "verify h1 initialization marker remains unpublished",
        )?
    {
        return Err(SafetyStoreErrorV0::Conflict(
            SafetyStoreConflictV0::FileIdentityChanged,
        ));
    }
    file.set_len(0).map_err(|error| {
        SafetyStoreErrorV0::io("truncate unpublished h1 initialization intent", error)
    })?;
    file.seek(SeekFrom::Start(0)).map_err(|error| {
        SafetyStoreErrorV0::io("seek unpublished h1 initialization intent", error)
    })?;
    write_h1_state_sync_initialization_intent_v0(file, published_path, intent)?;
    if file_handle_identity(file, temporary_path)? != identity
        || file_identity(temporary_path)? != identity
    {
        return Err(SafetyStoreErrorV0::Conflict(
            SafetyStoreConflictV0::FileIdentityChanged,
        ));
    }
    Ok(())
}

fn read_h1_state_sync_initialization_intent_v0(
    file: &File,
    path: &Path,
) -> Result<H1StateSyncInitializationIntentV0, SafetyStoreErrorV0> {
    if file
        .metadata()
        .map_err(|error| SafetyStoreErrorV0::io("stat h1 initialization intent", error))?
        .len()
        != INITIALIZATION_INTENT_BYTES_V0 as u64
    {
        return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
            "h1 initialization intent size",
        ));
    }
    let mut file = file;
    file.seek(SeekFrom::Start(0))
        .map_err(|error| SafetyStoreErrorV0::io("seek h1 initialization intent", error))?;
    let mut bytes = [0u8; INITIALIZATION_INTENT_BYTES_V0];
    file.read_exact(&mut bytes)
        .map_err(|error| SafetyStoreErrorV0::io("read h1 initialization intent", error))?;
    decode_h1_state_sync_initialization_intent_v0(path, &bytes).ok_or(
        SafetyStoreErrorV0::PersistedRepresentationMalformed("h1 initialization intent encoding"),
    )
}

fn encode_h1_state_sync_initialization_intent_v0(
    path: &Path,
    intent: H1StateSyncInitializationIntentV0,
) -> Result<[u8; INITIALIZATION_INTENT_BYTES_V0], SafetyStoreErrorV0> {
    if intent.journal_id == [0; 32]
        || intent.metadata_checksum == [0; 32]
        || intent.state_record_bytes == 0
        || intent.transition_context_bytes == 0
        || intent.state_record_checksum == [0; 32]
        || intent.transition_context_checksum == [0; 32]
        || intent.chain_checksum
            != chain_checksum(
                intent.journal_id,
                0,
                None,
                None,
                intent.state_record_checksum,
                intent.transition_context_checksum,
            )
        || intent.head_checksum != head_checksum(intent.journal_id, 0, intent.chain_checksum, 0)
    {
        return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
            "h1 initialization intent fields",
        ));
    }
    let mut bytes = [0u8; INITIALIZATION_INTENT_BYTES_V0];
    bytes[..8].copy_from_slice(INITIALIZATION_INTENT_MAGIC_V0);
    bytes[8..10].copy_from_slice(&INITIALIZATION_INTENT_VERSION_V0.to_be_bytes());
    bytes[10] = intent.kind.tag_v0();
    bytes[16..48].copy_from_slice(&intent.journal_id);
    bytes[48..80].copy_from_slice(&intent.metadata_checksum);
    bytes[80..88].copy_from_slice(&intent.state_record_bytes.to_be_bytes());
    bytes[88..96].copy_from_slice(&intent.transition_context_bytes.to_be_bytes());
    bytes[96..128].copy_from_slice(&intent.state_record_checksum);
    bytes[128..160].copy_from_slice(&intent.transition_context_checksum);
    bytes[160..192].copy_from_slice(&intent.chain_checksum);
    bytes[192..224].copy_from_slice(&intent.head_checksum);
    let checksum = h1_state_sync_initialization_intent_checksum_v0(
        path,
        &bytes[..INITIALIZATION_INTENT_CHECKSUM_OFFSET_V0],
    )?;
    bytes[INITIALIZATION_INTENT_CHECKSUM_OFFSET_V0..].copy_from_slice(&checksum);
    Ok(bytes)
}

fn decode_h1_state_sync_initialization_intent_v0(
    path: &Path,
    bytes: &[u8],
) -> Option<H1StateSyncInitializationIntentV0> {
    if bytes.len() != INITIALIZATION_INTENT_BYTES_V0
        || &bytes[..8] != INITIALIZATION_INTENT_MAGIC_V0
        || u16::from_be_bytes(bytes[8..10].try_into().ok()?) != INITIALIZATION_INTENT_VERSION_V0
        || SafetyBootstrapInitializationKindV0::from_byte_v0(bytes[10]).is_none()
        || bytes[11..16].iter().any(|byte| *byte != 0)
        || h1_state_sync_initialization_intent_checksum_v0(
            path,
            &bytes[..INITIALIZATION_INTENT_CHECKSUM_OFFSET_V0],
        )
        .ok()?
            != bytes[INITIALIZATION_INTENT_CHECKSUM_OFFSET_V0..]
    {
        return None;
    }
    let intent = H1StateSyncInitializationIntentV0 {
        kind: SafetyBootstrapInitializationKindV0::from_byte_v0(bytes[10])?,
        journal_id: bytes[16..48].try_into().ok()?,
        metadata_checksum: bytes[48..80].try_into().ok()?,
        state_record_bytes: u64::from_be_bytes(bytes[80..88].try_into().ok()?),
        transition_context_bytes: u64::from_be_bytes(bytes[88..96].try_into().ok()?),
        state_record_checksum: bytes[96..128].try_into().ok()?,
        transition_context_checksum: bytes[128..160].try_into().ok()?,
        chain_checksum: bytes[160..192].try_into().ok()?,
        head_checksum: bytes[192..224].try_into().ok()?,
    };
    encode_h1_state_sync_initialization_intent_v0(path, intent).ok()?;
    Some(intent)
}

fn h1_state_sync_initialization_intent_checksum_v0(
    path: &Path,
    bytes: &[u8],
) -> Result<[u8; 32], SafetyStoreErrorV0> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        Ok(hash_domain(
            INITIALIZATION_INTENT_CHECKSUM_DOMAIN_V0,
            &[bytes, path.as_os_str().as_bytes()],
        ))
    }
    #[cfg(not(unix))]
    {
        let _ = (path, bytes);
        Err(SafetyStoreErrorV0::UnsupportedPlatform)
    }
}

fn retire_h1_state_sync_initialization_intent_v0(
    file: &mut File,
    identity: FileIdentityV0,
    path: &Path,
    directory_file: &File,
    expected: H1StateSyncInitializationIntentV0,
) -> Result<(), SafetyStoreErrorV0> {
    if read_h1_state_sync_initialization_intent_v0(file, path)? != expected
        || !canonical_path_is_stable(path)?
        || file_handle_identity(file, path)? != identity
        || file_identity(path)? != identity
        || path_exists_v0(
            &initialization_intent_temporary_path_from_published_v0(path)?,
            "verify initialization temporary absent before marker retirement",
        )?
    {
        return Err(SafetyStoreErrorV0::Conflict(
            SafetyStoreConflictV0::FileIdentityChanged,
        ));
    }
    fs::remove_file(path)
        .map_err(|error| SafetyStoreErrorV0::io("retire h1 initialization intent", error))?;
    sync_directory_handle(directory_file)
}

fn initialization_intent_temporary_path_from_published_v0(
    published_path: &Path,
) -> Result<PathBuf, SafetyStoreErrorV0> {
    let file_name = published_path
        .file_name()
        .ok_or(SafetyStoreErrorV0::InvalidProfile(
            "published initialization file name",
        ))?;
    let name = file_name.to_string_lossy();
    let Some(database_name) = name.strip_suffix(".safety.init.v0") else {
        return Err(SafetyStoreErrorV0::InvalidProfile(
            "published initialization suffix",
        ));
    };
    Ok(published_path.with_file_name(format!("{database_name}.safety.init.v0.tmp")))
}

fn write_lock_watermark(
    file: &mut File,
    watermark: LockWatermarkV0,
) -> Result<(), SafetyStoreErrorV0> {
    if file
        .metadata()
        .map_err(|error| SafetyStoreErrorV0::io("stat lock watermark slots", error))?
        .len()
        != LOCK_FILE_BYTES_V0 as u64
    {
        return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
            "lock watermark file size",
        ));
    }
    let bytes = encode_lock_slot(watermark)?;
    let slot = (watermark.sequence() & 1) as usize;
    file.seek(SeekFrom::Start((slot * LOCK_SLOT_REGION_BYTES_V0) as u64))
        .map_err(|error| SafetyStoreErrorV0::io("seek lock watermark slot", error))?;
    file.write_all(&bytes)
        .map_err(|error| SafetyStoreErrorV0::io("write lock watermark slot", error))?;
    file.sync_all()
        .map_err(|error| SafetyStoreErrorV0::io("sync lock watermark slot", error))?;
    if read_lock_watermark(file)? != watermark {
        return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
            "lock watermark readback differs",
        ));
    }
    Ok(())
}

fn write_halt_latch(file: &mut File, latch: DurableHaltLatchV0) -> Result<(), SafetyStoreErrorV0> {
    if file
        .metadata()
        .map_err(|error| SafetyStoreErrorV0::io("stat terminal halt latch", error))?
        .len()
        != LOCK_FILE_BYTES_V0 as u64
    {
        return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
            "lock watermark file size",
        ));
    }
    match read_halt_latch(file)? {
        Some(existing) if existing == latch => return Ok(()),
        Some(_) => {
            return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                "terminal halt latch is already occupied",
            ));
        }
        None => {}
    }
    let bytes = encode_halt_latch(latch)?;
    file.seek(SeekFrom::Start(
        (LOCK_HALT_LATCH_REGION_V0 * LOCK_SLOT_REGION_BYTES_V0) as u64,
    ))
    .map_err(|error| SafetyStoreErrorV0::io("seek terminal halt latch", error))?;
    file.write_all(&bytes)
        .map_err(|error| SafetyStoreErrorV0::io("write terminal halt latch", error))?;
    file.sync_all()
        .map_err(|error| SafetyStoreErrorV0::io("sync terminal halt latch", error))?;
    if read_halt_latch(file)? != Some(latch) {
        return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
            "terminal halt latch readback differs",
        ));
    }
    Ok(())
}

fn encode_halt_latch(
    latch: DurableHaltLatchV0,
) -> Result<[u8; HALT_LATCH_BYTES_V0], SafetyStoreErrorV0> {
    encode_lock_slot(latch.head_watermark)?;
    if !durable_halt_fact_is_well_formed(latch.halt) {
        return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
            "invalid terminal halt latch fields",
        ));
    }
    let mut bytes = [0u8; HALT_LATCH_BYTES_V0];
    bytes[..8].copy_from_slice(HALT_LATCH_MAGIC_V0);
    bytes[8..10].copy_from_slice(&HALT_LATCH_VERSION_V0.to_be_bytes());
    let (kind, sequence, journal_id, source_revision, source_chain, target_revision, target_chain) =
        match latch.head_watermark {
            LockWatermarkV0::Stable {
                sequence,
                journal_id,
                revision,
                chain_checksum,
            } => (
                LOCK_KIND_STABLE_V0,
                sequence,
                journal_id,
                revision,
                chain_checksum,
                revision,
                chain_checksum,
            ),
            LockWatermarkV0::HeadIntent {
                sequence,
                journal_id,
                source_revision,
                source_chain_checksum,
                target_revision,
                target_chain_checksum,
            } => (
                LOCK_KIND_HEAD_INTENT_V0,
                sequence,
                journal_id,
                source_revision,
                source_chain_checksum,
                target_revision,
                target_chain_checksum,
            ),
        };
    bytes[10] = kind;
    bytes[16..24].copy_from_slice(&sequence.to_be_bytes());
    bytes[24..56].copy_from_slice(&journal_id);
    bytes[56..64].copy_from_slice(&source_revision.to_be_bytes());
    bytes[64..96].copy_from_slice(&source_chain);
    bytes[96..104].copy_from_slice(&target_revision.to_be_bytes());
    bytes[104..136].copy_from_slice(&target_chain);
    bytes[136..144].copy_from_slice(&latch.halt.reason_code.to_be_bytes());
    if let Some(revision) = latch.halt.revision {
        bytes[144] = 1;
        bytes[152..160].copy_from_slice(&revision.to_be_bytes());
    }
    bytes[160..192].copy_from_slice(&latch.halt.evidence_checksum);
    let checksum = hash_domain(
        LOCK_CHECKSUM_DOMAIN_V0,
        &[&bytes[..HALT_LATCH_CHECKSUM_OFFSET_V0]],
    );
    bytes[HALT_LATCH_CHECKSUM_OFFSET_V0..].copy_from_slice(&checksum);
    Ok(bytes)
}

fn read_halt_latch(file: &File) -> Result<Option<DurableHaltLatchV0>, SafetyStoreErrorV0> {
    if file
        .metadata()
        .map_err(|error| SafetyStoreErrorV0::io("stat terminal halt latch", error))?
        .len()
        != LOCK_FILE_BYTES_V0 as u64
    {
        return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
            "lock watermark file size",
        ));
    }
    let mut file = file;
    file.seek(SeekFrom::Start(
        (LOCK_HALT_LATCH_REGION_V0 * LOCK_SLOT_REGION_BYTES_V0) as u64,
    ))
    .map_err(|error| SafetyStoreErrorV0::io("seek terminal halt latch", error))?;
    let mut region = [0u8; LOCK_SLOT_REGION_BYTES_V0];
    file.read_exact(&mut region)
        .map_err(|error| SafetyStoreErrorV0::io("read terminal halt latch", error))?;
    if region.iter().all(|byte| *byte == 0) {
        return Ok(None);
    }
    if region[HALT_LATCH_BYTES_V0..].iter().any(|byte| *byte != 0) {
        return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
            "terminal halt latch padding",
        ));
    }
    decode_halt_latch(&region[..HALT_LATCH_BYTES_V0])
        .map(Some)
        .ok_or(SafetyStoreErrorV0::PersistedRepresentationMalformed(
            "terminal halt latch",
        ))
}

fn decode_halt_latch(bytes: &[u8]) -> Option<DurableHaltLatchV0> {
    if bytes.len() != HALT_LATCH_BYTES_V0
        || &bytes[..8] != HALT_LATCH_MAGIC_V0
        || u16::from_be_bytes(bytes[8..10].try_into().ok()?) != HALT_LATCH_VERSION_V0
        || !matches!(bytes[10], LOCK_KIND_STABLE_V0 | LOCK_KIND_HEAD_INTENT_V0)
        || bytes[11..16].iter().any(|byte| *byte != 0)
        || hash_domain(
            LOCK_CHECKSUM_DOMAIN_V0,
            &[&bytes[..HALT_LATCH_CHECKSUM_OFFSET_V0]],
        ) != bytes[HALT_LATCH_CHECKSUM_OFFSET_V0..]
    {
        return None;
    }
    let sequence = u64::from_be_bytes(bytes[16..24].try_into().ok()?);
    let journal_id: [u8; 32] = bytes[24..56].try_into().ok()?;
    let source_revision = u64::from_be_bytes(bytes[56..64].try_into().ok()?);
    let source_chain_checksum: [u8; 32] = bytes[64..96].try_into().ok()?;
    let target_revision = u64::from_be_bytes(bytes[96..104].try_into().ok()?);
    let target_chain_checksum: [u8; 32] = bytes[104..136].try_into().ok()?;
    let head_watermark = match bytes[10] {
        LOCK_KIND_STABLE_V0
            if source_revision == target_revision
                && source_chain_checksum == target_chain_checksum =>
        {
            LockWatermarkV0::Stable {
                sequence,
                journal_id,
                revision: source_revision,
                chain_checksum: source_chain_checksum,
            }
        }
        LOCK_KIND_HEAD_INTENT_V0 if source_revision.checked_add(1) == Some(target_revision) => {
            LockWatermarkV0::HeadIntent {
                sequence,
                journal_id,
                source_revision,
                source_chain_checksum,
                target_revision,
                target_chain_checksum,
            }
        }
        _ => return None,
    };
    encode_lock_slot(head_watermark).ok()?;
    let revision = match bytes[144] {
        0 if bytes[152..160].iter().all(|byte| *byte == 0) => None,
        1 => Some(u64::from_be_bytes(bytes[152..160].try_into().ok()?)),
        _ => return None,
    };
    if bytes[145..152].iter().any(|byte| *byte != 0) {
        return None;
    }
    let halt = DurableHaltFactV0 {
        reason_code: i64::from_be_bytes(bytes[136..144].try_into().ok()?),
        revision,
        evidence_checksum: bytes[160..192].try_into().ok()?,
    };
    if !durable_halt_fact_is_well_formed(halt) {
        return None;
    }
    Some(DurableHaltLatchV0 {
        head_watermark,
        halt,
    })
}

fn preflight_intent_sequence(stable_sequence: u64) -> Result<u64, SafetyStoreErrorV0> {
    // Both the intent and its potential Stable resolution must be representable
    // before the intent is written or the associated SQLite transaction can
    // commit. This rejects MAX-1 before it can strand a resolvable transition.
    stable_sequence
        .checked_add(2)
        .ok_or(SafetyStoreErrorV0::PersistedRepresentationMalformed(
            "lock watermark sequence overflow",
        ))?;
    Ok(stable_sequence + 1)
}

fn durable_halt_fact_is_well_formed(halt: DurableHaltFactV0) -> bool {
    let revision_shape_matches_reason = match halt.reason_code {
        1..=3 => halt.revision.is_some(),
        4..=7 => halt.revision.is_none(),
        _ => false,
    };
    revision_shape_matches_reason && halt.evidence_checksum != [0; 32]
}

fn encode_lock_slot(
    watermark: LockWatermarkV0,
) -> Result<[u8; LOCK_SLOT_BYTES_V0], SafetyStoreErrorV0> {
    let mut bytes = [0u8; LOCK_SLOT_BYTES_V0];
    bytes[..8].copy_from_slice(LOCK_MAGIC_V0);
    bytes[8..10].copy_from_slice(&LOCK_VERSION_V0.to_be_bytes());
    let (kind, sequence, journal_id) = match watermark {
        LockWatermarkV0::Stable {
            sequence,
            journal_id,
            revision,
            chain_checksum,
        } if journal_id != [0; 32] && chain_checksum != [0; 32] => {
            bytes[56..64].copy_from_slice(&revision.to_be_bytes());
            bytes[64..96].copy_from_slice(&chain_checksum);
            (LOCK_KIND_STABLE_V0, sequence, journal_id)
        }
        LockWatermarkV0::HeadIntent {
            sequence,
            journal_id,
            source_revision,
            source_chain_checksum,
            target_revision,
            target_chain_checksum,
        } if journal_id != [0; 32]
            && source_chain_checksum != [0; 32]
            && target_chain_checksum != [0; 32]
            && source_revision.checked_add(1) == Some(target_revision) =>
        {
            bytes[56..64].copy_from_slice(&source_revision.to_be_bytes());
            bytes[64..96].copy_from_slice(&source_chain_checksum);
            bytes[96..104].copy_from_slice(&target_revision.to_be_bytes());
            bytes[104..136].copy_from_slice(&target_chain_checksum);
            (LOCK_KIND_HEAD_INTENT_V0, sequence, journal_id)
        }
        _ => {
            return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                "invalid lock watermark fields",
            ));
        }
    };
    bytes[10] = kind;
    bytes[16..24].copy_from_slice(&sequence.to_be_bytes());
    bytes[24..56].copy_from_slice(&journal_id);
    let checksum = hash_domain(
        LOCK_CHECKSUM_DOMAIN_V0,
        &[&bytes[..LOCK_SLOT_CHECKSUM_OFFSET_V0]],
    );
    bytes[LOCK_SLOT_CHECKSUM_OFFSET_V0..].copy_from_slice(&checksum);
    Ok(bytes)
}

fn read_lock_watermark(file: &File) -> Result<LockWatermarkV0, SafetyStoreErrorV0> {
    if file
        .metadata()
        .map_err(|error| SafetyStoreErrorV0::io("stat lock watermark slots", error))?
        .len()
        != LOCK_FILE_BYTES_V0 as u64
    {
        return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
            "lock watermark file size",
        ));
    }
    let mut file = file;
    file.seek(SeekFrom::Start(0))
        .map_err(|error| SafetyStoreErrorV0::io("seek lock watermark slots", error))?;
    let mut bytes = [0u8; LOCK_FILE_BYTES_V0];
    file.read_exact(&mut bytes)
        .map_err(|error| SafetyStoreErrorV0::io("read lock watermark slots", error))?;

    let mut valid = [None, None];
    for (slot, target) in valid.iter_mut().enumerate() {
        let start = slot * LOCK_SLOT_REGION_BYTES_V0;
        let payload_end = start + LOCK_SLOT_BYTES_V0;
        let region_end = start + LOCK_SLOT_REGION_BYTES_V0;
        *target = if bytes[payload_end..region_end].iter().all(|byte| *byte == 0) {
            decode_lock_slot(&bytes[start..payload_end], slot)
        } else {
            None
        };
    }
    match (valid[0], valid[1]) {
        (None, None) => Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
            "no valid lock watermark slot",
        )),
        (Some(watermark), None) | (None, Some(watermark)) => Ok(watermark),
        (Some(left), Some(right)) => {
            let (older, newer) = if left.sequence() < right.sequence() {
                (left, right)
            } else {
                (right, left)
            };
            if older.journal_id() != newer.journal_id()
                || older.sequence().checked_add(1) != Some(newer.sequence())
                || !lock_watermarks_are_adjacent(older, newer)
            {
                return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                    "lock watermark slot sequence or transition",
                ));
            }
            Ok(newer)
        }
    }
}

fn decode_lock_slot(bytes: &[u8], slot: usize) -> Option<LockWatermarkV0> {
    if bytes.len() != LOCK_SLOT_BYTES_V0 || bytes.iter().all(|byte| *byte == 0) {
        return None;
    }
    if &bytes[..8] != LOCK_MAGIC_V0
        || u16::from_be_bytes(bytes[8..10].try_into().ok()?) != LOCK_VERSION_V0
        || !matches!(bytes[10], LOCK_KIND_STABLE_V0 | LOCK_KIND_HEAD_INTENT_V0)
        || bytes[11..16].iter().any(|byte| *byte != 0)
        || hash_domain(
            LOCK_CHECKSUM_DOMAIN_V0,
            &[&bytes[..LOCK_SLOT_CHECKSUM_OFFSET_V0]],
        ) != bytes[LOCK_SLOT_CHECKSUM_OFFSET_V0..]
    {
        return None;
    }
    let sequence = u64::from_be_bytes(bytes[16..24].try_into().ok()?);
    if (sequence & 1) as usize != slot {
        return None;
    }
    let journal_id: [u8; 32] = bytes[24..56].try_into().ok()?;
    let source_revision = u64::from_be_bytes(bytes[56..64].try_into().ok()?);
    let source_chain_checksum: [u8; 32] = bytes[64..96].try_into().ok()?;
    if journal_id == [0; 32] || source_chain_checksum == [0; 32] {
        return None;
    }
    match bytes[10] {
        LOCK_KIND_STABLE_V0
            if bytes[96..LOCK_SLOT_CHECKSUM_OFFSET_V0]
                .iter()
                .all(|byte| *byte == 0) =>
        {
            Some(LockWatermarkV0::Stable {
                sequence,
                journal_id,
                revision: source_revision,
                chain_checksum: source_chain_checksum,
            })
        }
        LOCK_KIND_HEAD_INTENT_V0 => {
            let target_revision = u64::from_be_bytes(bytes[96..104].try_into().ok()?);
            let target_chain_checksum: [u8; 32] = bytes[104..136].try_into().ok()?;
            if source_revision.checked_add(1) != Some(target_revision)
                || target_chain_checksum == [0; 32]
                || bytes[136..LOCK_SLOT_CHECKSUM_OFFSET_V0]
                    .iter()
                    .any(|byte| *byte != 0)
            {
                return None;
            }
            Some(LockWatermarkV0::HeadIntent {
                sequence,
                journal_id,
                source_revision,
                source_chain_checksum,
                target_revision,
                target_chain_checksum,
            })
        }
        _ => None,
    }
}

fn lock_watermarks_are_adjacent(older: LockWatermarkV0, newer: LockWatermarkV0) -> bool {
    match (older, newer) {
        (
            LockWatermarkV0::Stable {
                revision,
                chain_checksum,
                ..
            },
            LockWatermarkV0::HeadIntent {
                source_revision,
                source_chain_checksum,
                ..
            },
        ) => revision == source_revision && chain_checksum == source_chain_checksum,
        (
            LockWatermarkV0::HeadIntent {
                source_revision,
                source_chain_checksum,
                target_revision,
                target_chain_checksum,
                ..
            },
            LockWatermarkV0::Stable {
                revision,
                chain_checksum,
                ..
            },
        ) => {
            (revision == source_revision && chain_checksum == source_chain_checksum)
                || (revision == target_revision && chain_checksum == target_chain_checksum)
        }
        _ => false,
    }
}

fn new_journal_id(_path: &Path) -> Result<[u8; 32], SafetyStoreErrorV0> {
    let mut id = [0u8; 32];
    getrandom::getrandom(&mut id).map_err(|error| {
        SafetyStoreErrorV0::io(
            "generate journal identity",
            std::io::Error::other(error.to_string()),
        )
    })?;
    if id == [0; 32] {
        return Err(SafetyStoreErrorV0::InvalidProfile("zero journal ID"));
    }
    Ok(id)
}

fn sync_directory_handle(directory_file: &File) -> Result<(), SafetyStoreErrorV0> {
    directory_file
        .sync_all()
        .map_err(|error| SafetyStoreErrorV0::io("sync safety-store parent directory", error))
}

fn file_identity(path: &Path) -> Result<FileIdentityV0, SafetyStoreErrorV0> {
    let metadata = fs::metadata(path)
        .map_err(|error| SafetyStoreErrorV0::io("stat safety-store file", error))?;
    file_identity_from_metadata(path, &metadata)
}

fn directory_identity(path: &Path) -> Result<FileIdentityV0, SafetyStoreErrorV0> {
    let metadata = fs::metadata(path)
        .map_err(|error| SafetyStoreErrorV0::io("stat pinned directory path", error))?;
    directory_identity_from_metadata(path, &metadata)
}

fn directory_handle_identity(
    file: &File,
    canonical_path: &Path,
) -> Result<FileIdentityV0, SafetyStoreErrorV0> {
    let metadata = file
        .metadata()
        .map_err(|error| SafetyStoreErrorV0::io("stat pinned directory handle", error))?;
    directory_identity_from_metadata(canonical_path, &metadata)
}

fn directory_identity_from_metadata(
    path: &Path,
    metadata: &fs::Metadata,
) -> Result<FileIdentityV0, SafetyStoreErrorV0> {
    if !metadata.is_dir() {
        return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
            "safety-store directory path is not a directory",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let _ = path;
        Ok(FileIdentityV0 {
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }
    #[cfg(not(unix))]
    {
        Ok(FileIdentityV0 {
            canonical_path: fs::canonicalize(path)
                .map_err(|error| SafetyStoreErrorV0::io("canonicalize directory", error))?,
        })
    }
}

fn file_handle_identity(
    file: &File,
    canonical_path: &Path,
) -> Result<FileIdentityV0, SafetyStoreErrorV0> {
    let metadata = file
        .metadata()
        .map_err(|error| SafetyStoreErrorV0::io("stat pinned safety-store file", error))?;
    file_identity_from_metadata(canonical_path, &metadata)
}

fn file_identity_from_metadata(
    path: &Path,
    metadata: &fs::Metadata,
) -> Result<FileIdentityV0, SafetyStoreErrorV0> {
    if !metadata.is_file() {
        return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
            "safety-store path is not a regular file",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let _ = path;
        // SAFETY: `geteuid` has no pointer arguments and no caller obligations.
        let effective_uid = unsafe { libc::geteuid() };
        if metadata.nlink() != 1
            || metadata.uid() != effective_uid
            || metadata.mode() & 0o777 != 0o600
        {
            return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                "safety-store file identity or permissions",
            ));
        }
        Ok(FileIdentityV0 {
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }
    #[cfg(not(unix))]
    {
        Ok(FileIdentityV0 {
            canonical_path: fs::canonicalize(path)
                .map_err(|error| SafetyStoreErrorV0::io("canonicalize file identity", error))?,
        })
    }
}

fn usize_to_u64(value: usize, field: &'static str) -> Result<u64, SafetyStoreErrorV0> {
    u64::try_from(value).map_err(|_| SafetyStoreErrorV0::InvalidProfile(field))
}

fn decode_u64_blob(bytes: &[u8], field: &'static str) -> Result<u64, SafetyStoreErrorV0> {
    let bytes: [u8; 8] = bytes
        .try_into()
        .map_err(|_| SafetyStoreErrorV0::PersistedRepresentationMalformed(field))?;
    Ok(u64::from_be_bytes(bytes))
}

fn decode_array32(bytes: &[u8], field: &'static str) -> Result<[u8; 32], SafetyStoreErrorV0> {
    bytes
        .try_into()
        .map_err(|_| SafetyStoreErrorV0::PersistedRepresentationMalformed(field))
}

fn u64_from_slice_sql(bytes: &[u8], column: usize) -> rusqlite::Result<u64> {
    let bytes: [u8; 8] = bytes.try_into().map_err(|_| {
        rusqlite::Error::FromSqlConversionFailure(
            column,
            rusqlite::types::Type::Blob,
            "expected 8-byte big-endian integer".into(),
        )
    })?;
    Ok(u64::from_be_bytes(bytes))
}

fn array32_sql(bytes: &[u8], column: usize) -> rusqlite::Result<[u8; 32]> {
    bytes.try_into().map_err(|_| {
        rusqlite::Error::FromSqlConversionFailure(
            column,
            rusqlite::types::Type::Blob,
            "expected 32-byte checksum".into(),
        )
    })
}

#[cfg(test)]
mod lock_watermark_tests {
    use super::*;

    const JOURNAL_ID: [u8; 32] = [0x11; 32];
    const SOURCE_CHAIN: [u8; 32] = [0x22; 32];
    const TARGET_CHAIN: [u8; 32] = [0x33; 32];
    const HALT_EVIDENCE: [u8; 32] = [0x44; 32];

    fn new_lock_file() -> File {
        let mut file = tempfile::tempfile().expect("create temporary lock sidecar");
        initialize_lock_file(&mut file).expect("initialize lock slots");
        file
    }

    fn stable(sequence: u64, revision: u64, chain_checksum: [u8; 32]) -> LockWatermarkV0 {
        LockWatermarkV0::Stable {
            sequence,
            journal_id: JOURNAL_ID,
            revision,
            chain_checksum,
        }
    }

    fn intent(sequence: u64) -> LockWatermarkV0 {
        LockWatermarkV0::HeadIntent {
            sequence,
            journal_id: JOURNAL_ID,
            source_revision: 7,
            source_chain_checksum: SOURCE_CHAIN,
            target_revision: 8,
            target_chain_checksum: TARGET_CHAIN,
        }
    }

    fn halt_latch(head_watermark: LockWatermarkV0) -> DurableHaltLatchV0 {
        DurableHaltLatchV0 {
            head_watermark,
            halt: DurableHaltFactV0 {
                reason_code: 2,
                revision: Some(9),
                evidence_checksum: HALT_EVIDENCE,
            },
        }
    }

    fn overwrite_slot(file: &mut File, slot: usize, bytes: &[u8; LOCK_SLOT_BYTES_V0]) {
        file.seek(SeekFrom::Start((slot * LOCK_SLOT_REGION_BYTES_V0) as u64))
            .expect("seek raw lock slot");
        file.write_all(bytes).expect("write raw lock slot");
        file.sync_all().expect("sync raw lock slot");
    }

    #[test]
    fn one_torn_slot_falls_back_to_the_other_valid_slot() {
        let mut file = new_lock_file();
        let source = stable(0, 7, SOURCE_CHAIN);
        write_lock_watermark(&mut file, source).expect("write source Stable");
        overwrite_slot(&mut file, 1, &[0xa5; LOCK_SLOT_BYTES_V0]);

        assert_eq!(read_lock_watermark(&file).expect("read valid slot"), source);
    }

    #[test]
    fn slot_payloads_occupy_disjoint_four_kib_regions() {
        let mut file = new_lock_file();
        write_lock_watermark(&mut file, stable(0, 7, SOURCE_CHAIN)).expect("write first region");
        write_lock_watermark(&mut file, intent(1)).expect("write second region");
        let mut bytes = Vec::new();
        file.seek(SeekFrom::Start(0)).expect("rewind lock file");
        file.read_to_end(&mut bytes).expect("read lock file");

        assert_eq!(bytes.len(), 3 * LOCK_SLOT_REGION_BYTES_V0);
        assert_eq!(&bytes[..8], LOCK_MAGIC_V0);
        assert_eq!(
            &bytes[LOCK_SLOT_REGION_BYTES_V0..LOCK_SLOT_REGION_BYTES_V0 + 8],
            LOCK_MAGIC_V0
        );
        assert!(bytes[LOCK_SLOT_BYTES_V0..LOCK_SLOT_REGION_BYTES_V0]
            .iter()
            .all(|byte| *byte == 0));
        assert!(bytes
            [LOCK_SLOT_REGION_BYTES_V0 + LOCK_SLOT_BYTES_V0..2 * LOCK_SLOT_REGION_BYTES_V0]
            .iter()
            .all(|byte| *byte == 0));
        assert!(bytes[2 * LOCK_SLOT_REGION_BYTES_V0..]
            .iter()
            .all(|byte| *byte == 0));
    }

    #[test]
    fn stable_to_intent_and_intent_to_either_stable_are_adjacent() {
        let mut target_file = new_lock_file();
        write_lock_watermark(&mut target_file, stable(0, 7, SOURCE_CHAIN))
            .expect("write source Stable");
        write_lock_watermark(&mut target_file, intent(1)).expect("write Intent");
        assert_eq!(
            read_lock_watermark(&target_file).expect("select Intent"),
            intent(1)
        );
        let target = stable(2, 8, TARGET_CHAIN);
        write_lock_watermark(&mut target_file, target).expect("resolve target Stable");
        assert_eq!(
            read_lock_watermark(&target_file).expect("select target Stable"),
            target
        );

        let mut source_file = new_lock_file();
        write_lock_watermark(&mut source_file, stable(0, 7, SOURCE_CHAIN))
            .expect("write source Stable");
        write_lock_watermark(&mut source_file, intent(1)).expect("write Intent");
        let source = stable(2, 7, SOURCE_CHAIN);
        write_lock_watermark(&mut source_file, source).expect("resolve source Stable");
        assert_eq!(
            read_lock_watermark(&source_file).expect("select source Stable"),
            source
        );
    }

    #[test]
    fn terminal_halt_latch_roundtrips_without_changing_stable_head() {
        let mut file = new_lock_file();
        let source = stable(0, 7, SOURCE_CHAIN);
        let latch = halt_latch(source);
        write_lock_watermark(&mut file, source).expect("write source Stable");
        write_halt_latch(&mut file, latch).expect("write terminal halt latch");

        assert_eq!(read_lock_watermark(&file).expect("retain Stable"), source);
        assert_eq!(read_halt_latch(&file).expect("read latch"), Some(latch));
        assert_eq!(
            decode_halt_latch(&encode_halt_latch(latch).expect("encode halt latch")),
            Some(latch)
        );
    }

    #[test]
    fn commit_readback_conflict_latch_binds_the_full_head_intent() {
        let mut file = new_lock_file();
        write_lock_watermark(&mut file, stable(0, 7, SOURCE_CHAIN)).expect("write source Stable");
        let head_intent = intent(1);
        write_lock_watermark(&mut file, head_intent).expect("write HeadIntent");
        let latch = DurableHaltLatchV0 {
            head_watermark: head_intent,
            halt: halt_fact_for_conflict(JOURNAL_ID, SafetyStoreConflictV0::CommitReadbackConflict),
        };
        write_halt_latch(&mut file, latch).expect("write terminal halt latch");

        assert_eq!(
            read_lock_watermark(&file).expect("retain HeadIntent"),
            head_intent
        );
        assert_eq!(read_halt_latch(&file).expect("read latch"), Some(latch));
    }

    #[test]
    fn torn_halt_latch_is_fail_closed_without_damaging_the_head_slots() {
        let mut file = new_lock_file();
        let source = stable(0, 7, SOURCE_CHAIN);
        write_lock_watermark(&mut file, source).expect("write source Stable");
        file.seek(SeekFrom::Start(
            (LOCK_HALT_LATCH_REGION_V0 * LOCK_SLOT_REGION_BYTES_V0) as u64,
        ))
        .expect("seek raw halt latch");
        file.write_all(&[0xa5; HALT_LATCH_BYTES_V0])
            .expect("write torn halt latch");
        file.sync_all().expect("sync torn halt latch");

        assert_eq!(
            read_lock_watermark(&file).expect("head remains readable"),
            source
        );
        assert!(matches!(
            read_halt_latch(&file),
            Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                "terminal halt latch"
            ))
        ));
        let conflict = SafetyStoreConflictV0::RevisionGap {
            active: 7,
            incoming: 9,
        };
        let failure = write_halt_latch(&mut file, halt_latch(source))
            .map_err(|source| conflict_halt_uncertain(conflict, source))
            .expect_err("a torn latch cannot be reported durable");
        assert!(matches!(
            failure,
            SafetyStoreErrorV0::ConflictHaltUncertain {
                conflict: SafetyStoreConflictV0::RevisionGap {
                    active: 7,
                    incoming: 9
                },
                ..
            }
        ));
    }

    #[test]
    fn intent_sequence_preflight_reserves_the_following_stable_sequence() {
        assert_eq!(
            preflight_intent_sequence(u64::MAX - 2)
                .expect("final intent sequence is representable"),
            u64::MAX - 1
        );
        assert!(matches!(
            preflight_intent_sequence(u64::MAX - 1),
            Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                "lock watermark sequence overflow"
            ))
        ));
    }

    #[test]
    fn two_valid_nonadjacent_slots_are_rejected() {
        let mut file = new_lock_file();
        overwrite_slot(
            &mut file,
            0,
            &encode_lock_slot(stable(0, 7, SOURCE_CHAIN)).expect("encode Stable"),
        );
        overwrite_slot(
            &mut file,
            1,
            &encode_lock_slot(intent(3)).expect("encode nonadjacent Intent"),
        );

        assert!(matches!(
            read_lock_watermark(&file),
            Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                "lock watermark slot sequence or transition"
            ))
        ));
    }

    #[test]
    fn torn_newest_rewrite_preserves_the_prior_intent_or_stable() {
        let mut after_intent = new_lock_file();
        write_lock_watermark(&mut after_intent, stable(0, 7, SOURCE_CHAIN))
            .expect("write source Stable");
        write_lock_watermark(&mut after_intent, intent(1)).expect("write Intent");
        overwrite_slot(&mut after_intent, 0, &[0x5a; LOCK_SLOT_BYTES_V0]);
        assert_eq!(
            read_lock_watermark(&after_intent).expect("recover prior Intent"),
            intent(1)
        );

        let mut after_stable = new_lock_file();
        write_lock_watermark(&mut after_stable, stable(0, 7, SOURCE_CHAIN))
            .expect("write source Stable");
        write_lock_watermark(&mut after_stable, intent(1)).expect("write Intent");
        let target = stable(2, 8, TARGET_CHAIN);
        write_lock_watermark(&mut after_stable, target).expect("write target Stable");
        overwrite_slot(&mut after_stable, 1, &[0x96; LOCK_SLOT_BYTES_V0]);
        assert_eq!(
            read_lock_watermark(&after_stable).expect("recover prior Stable"),
            target
        );
    }
}

#[cfg(test)]
mod native_valid_post_ack_manifest_tests {
    use super::*;
    use trnm_consensus_core::{PayloadValidationRouteV0, ValidationId};
    use trnm_consensus_types::{BlockId, View};

    const REVISION: u64 = 10;
    const ACTION_CODE: u32 = 3;

    fn native_valid_context(action_code: u32) -> SafetyTransitionContextV0 {
        SafetyTransitionContextV0::native_valid(
            NativeValidTransitionV0::new(
                PayloadValidationRouteV0::Proposal,
                ValidationId::new(BlockId::new([0x11; 32]), View::new(7), 9),
                [0x21; 32],
                [0x22; 32],
                [0x23; 32],
                [0x24; 32],
                [0x25; 32],
                [0x26; 32],
                1,
                [0x27; 32],
                [0x28; 32],
                action_code,
                REVISION,
            )
            .expect("valid native Valid transition facts"),
        )
    }

    #[test]
    fn native_valid_context_requires_the_exact_core_owned_post_ack_manifest() {
        let context = native_valid_context(ACTION_CODE);
        assert!(
            validate_native_valid_post_ack_manifest_v0(REVISION, Some(ACTION_CODE), &context,)
                .is_ok()
        );
        assert!(matches!(
            validate_native_valid_post_ack_manifest_v0(REVISION, None, &context),
            Err(SafetyStoreErrorV0::MissingNativeValidPostAckAction { revision: REVISION })
        ));
        assert!(matches!(
            validate_native_valid_post_ack_manifest_v0(
                REVISION,
                Some(ACTION_CODE + 1),
                &context,
            ),
            Err(SafetyStoreErrorV0::NativeValidPostAckActionMismatch {
                revision: REVISION,
                core_action_code,
                context_action_code: ACTION_CODE,
            }) if core_action_code == ACTION_CODE + 1
        ));
        assert!(validate_native_valid_post_ack_manifest_v0(
            REVISION,
            None,
            &SafetyTransitionContextV0::Ordinary,
        )
        .is_ok());
    }
}

#[cfg(test)]
mod native_finalization_applied_pair_tests {
    use super::*;
    use trnm_consensus_core::{CoreConfig, FinalizedTip, PayloadValidationRouteV0, ValidationId};
    use trnm_consensus_types::{
        BlockId, ChainId, ConsensusParametersV0, ConsensusPublicKey, Epoch, GenesisHash,
        GenesisQcV0, ProtocolVersion, SignatureBytes, SignatureVerifier, SigningRoot, Validator,
        ValidatorId, ValidatorSet, View, VotingPower,
    };

    #[derive(Debug, Clone, Copy)]
    struct AcceptSignatures;

    impl SignatureVerifier for AcceptSignatures {
        fn verify(
            &self,
            _validator: &Validator,
            _signing_root: &SigningRoot,
            _signature: &SignatureBytes,
        ) -> bool {
            true
        }
    }

    fn genesis_state() -> SafetyState {
        let parameters = ConsensusParametersV0::reference_shadow_v0();
        let validators = (1u8..=4)
            .map(|index| {
                Validator::new(
                    ValidatorId::new([index; 32]),
                    ConsensusPublicKey::new([index.saturating_add(100); 32]),
                    VotingPower::new(1).expect("positive voting power"),
                )
                .expect("valid validator")
            })
            .collect();
        let validator_set = ValidatorSet::new(
            GenesisHash::new([0xa5; 32]),
            ChainId::from_static("trnm-finalization-context-test"),
            ProtocolVersion::V0,
            Epoch::new(0),
            parameters.hash(),
            validators,
        )
        .expect("valid validator set");
        let config = CoreConfig::new(
            ValidatorId::new([1; 32]),
            validator_set.clone(),
            parameters,
            17,
            64,
            64,
        )
        .expect("valid Core config");
        let genesis_qc = GenesisQcV0::new(
            validator_set.genesis_hash(),
            validator_set.chain_id(),
            &validator_set,
        )
        .expect("valid GenesisQC");
        Core::new(config, genesis_qc, &AcceptSignatures)
            .expect("valid genesis Core")
            .safety_state()
            .clone()
    }

    fn with_revision_and_applied(
        state: &SafetyState,
        revision: u64,
        application_applied: FinalizedTip,
    ) -> SafetyState {
        SafetyState::from_persisted_parts_v11(
            state.schema_version(),
            state.chain_id(),
            state.protocol_version(),
            state.epoch(),
            state.validator_set_id(),
            state.genesis_block_id(),
            state.current_view(),
            state.last_voted_view(),
            state.last_timeout_view(),
            state.high_qc().clone(),
            state.locked_qc().clone(),
            state.finalized(),
            revision,
            state.payload_terminal_facts().to_vec(),
            state.payload_validation_obligations().to_vec(),
            state.payload_validation_completions().to_vec(),
            state.pending_tc_high_qc_sync().cloned(),
            state.pending_standalone_qc_sync().cloned(),
            state.pending_sign().cloned(),
            state.last_finalization().cloned(),
            state.state_sync_anchor().cloned(),
            application_applied,
            state.finalization_queue().to_vec(),
            state.pending_finalize(),
            state.safety_halt().cloned(),
        )
    }

    fn recovered(
        state: SafetyState,
        transition_context: SafetyTransitionContextV0,
    ) -> RecoveredSafetyStateV0 {
        RecoveredSafetyStateV0 {
            state,
            transition_context,
            state_record_checksum: [0x91; 32],
            transition_context_checksum: [0x93; 32],
            chain_checksum: [0x92; 32],
        }
    }

    #[test]
    fn ordinary_context_cannot_advance_application_applied_watermark() {
        let previous_state = genesis_state();
        let successor_tip = FinalizedTip::new(
            trnm_consensus_types::Height::new(1),
            View::new(1),
            BlockId::new([0x41; 32]),
            18,
        );
        let successor_state = with_revision_and_applied(&previous_state, 1, successor_tip);
        let previous = recovered(previous_state, SafetyTransitionContextV0::Ordinary);
        let successor = recovered(successor_state, SafetyTransitionContextV0::Ordinary);

        assert!(matches!(
            validate_application_applied_context_pair_v0(&previous, &successor),
            Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                "application-applied watermark advanced without tag-3 transition context"
            ))
        ));
    }

    #[test]
    fn tag_three_context_cannot_be_spliced_without_the_retained_queue_front() {
        let previous_state = genesis_state();
        let successor_tip = FinalizedTip::new(
            trnm_consensus_types::Height::new(1),
            View::new(1),
            BlockId::new([0x41; 32]),
            18,
        );
        let successor_state = with_revision_and_applied(&previous_state, 1, successor_tip);
        let transition = NativeFinalizationAppliedTransitionV0::new(
            PayloadValidationRouteV0::Proposal,
            ValidationId::new(successor_tip.block_id(), successor_tip.view(), 1),
            successor_tip.height().get(),
            [0x51; 32],
            [0x52; 32],
            [0x53; 32],
            [0x54; 32],
            [0x55; 32],
            [0x56; 32],
            [0x57; 32],
            [0x58; 32],
            NativeFinalizationAppliedPostAckActionV0::None.code(),
            1,
        )
        .expect("canonical tag-3 context");
        let previous = recovered(previous_state, SafetyTransitionContextV0::Ordinary);
        let successor = recovered(
            successor_state,
            SafetyTransitionContextV0::native_finalization_applied(transition),
        );

        assert!(matches!(
            validate_application_applied_context_pair_v0(&previous, &successor),
            Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                "native finalization-applied transition has no predecessor queue front"
            ))
        ));
    }
}

#[cfg(test)]
mod state_sync_checkpoint_store_tests {
    use super::*;
    use trnm_consensus_core::{
        leader_for, ApplicationNativeValidDeliveryFactsV0, ApplicationSealedValidV0,
        AuthenticatedGenesisApplicationH1OfflineActivationBundleV0,
        AuthenticatedGenesisApplicationH1OfflineApplicationOwnerV0,
        AuthenticatedGenesisApplicationH1OfflineApplicationRegistrarV0,
        AuthenticatedGenesisApplicationH1StableNativeValidRecoveryChallengeV0,
        AuthenticatedGenesisApplicationH1StableNativeValidRecoveryReconcilerV0,
        AuthenticatedGenesisApplicationH1StableNativeValidSafetyHeadFactsV0,
        AuthenticatedGenesisApplicationParentV0, CoreError, CoreIssuedApplicationSealAuthorityV0,
        Effect, H1StateSyncAnchorSuccessorBundleV0, PayloadValidationRequest,
        SafetyStateRecordLimitsV0, StateSyncAnchorSuccessorPhaseV0,
        StateSyncAnchorSuccessorRecoveryChallengeV0, StateSyncAnchorSuccessorRecoveryReconcilerV0,
        StateSyncAnchorSuccessorReplayV0, ValidatedPayloadArtifactRefV0,
    };
    use trnm_consensus_types::{
        decode_application_payload_v0_exact, ApplicationPayloadV0, Block, BlockBodyV0, BlockHeader,
        BlockId, BlockKind, CertifiedHeaderV0, ChainId, ConsensusParametersV0, ConsensusPublicKey,
        Epoch, ExecutionReceiptCommitmentV0, ExecutionReceiptsV0, FinalityProofV0, GenesisHash,
        GenesisQcV0, Height, ProposalWitnessV0, ProtocolVersion, QcReferenceV0, QuorumCertificate,
        SignatureBytes, SignedProposalV0, SigningRoot, StateRoot, ValidatedBlockCommitmentsV0,
        Validator, ValidatorId, ValidatorSet, View, Vote, VotingPower, SIGNATURE_BYTES,
    };

    const GENESIS_TIMESTAMP_MS: u64 = 17;

    struct TestAuthenticatedGenesisH1RegistrarV0;

    impl AuthenticatedGenesisApplicationH1OfflineApplicationRegistrarV0
        for TestAuthenticatedGenesisH1RegistrarV0
    {
        type Output = AuthenticatedGenesisApplicationH1OfflineApplicationOwnerV0;
        type Error = std::convert::Infallible;

        fn register_authenticated_genesis_application_h1_offline_v0(
            self,
            owner: AuthenticatedGenesisApplicationH1OfflineApplicationOwnerV0,
        ) -> std::result::Result<Self::Output, Self::Error> {
            Ok(owner)
        }
    }

    fn activate_authenticated_genesis_h1_for_test_v0(
        bundle: AuthenticatedGenesisApplicationH1OfflineActivationBundleV0,
    ) -> AuthenticatedGenesisApplicationH1OfflineApplicationOwnerV0 {
        bundle
            .activate_application_v0(TestAuthenticatedGenesisH1RegistrarV0)
            .unwrap_or_else(|never| match never {})
    }
    const HISTORICAL_JOURNAL_V5_METADATA_DDL: &str = "
        CREATE TABLE safety_store_metadata_v0 (
            singleton INTEGER PRIMARY KEY NOT NULL CHECK(singleton=1),
            journal_schema INTEGER NOT NULL CHECK(journal_schema=5),
            journal_id BLOB NOT NULL CHECK(length(journal_id)=32),
            core_record_codec INTEGER NOT NULL CHECK(core_record_codec=0),
            safety_schema INTEGER NOT NULL CHECK(safety_schema=11),
            core_config_ref BLOB NOT NULL CHECK(length(core_config_ref)=32),
            verifier_profile_ref BLOB NOT NULL CHECK(length(verifier_profile_ref)=32),
            maximum_record_bytes_be BLOB NOT NULL CHECK(length(maximum_record_bytes_be)=8),
            maximum_blob_bytes_be BLOB NOT NULL CHECK(length(maximum_blob_bytes_be)=8),
            maximum_database_bytes_be BLOB NOT NULL CHECK(length(maximum_database_bytes_be)=8),
            transition_codec INTEGER NOT NULL CHECK(transition_codec=0),
            metadata_checksum BLOB NOT NULL CHECK(length(metadata_checksum)=32)
        ) STRICT;
    ";

    const HISTORICAL_JOURNAL_V4_METADATA_DDL: &str = "
        CREATE TABLE safety_store_metadata_v0 (
            singleton INTEGER PRIMARY KEY NOT NULL CHECK(singleton=1),
            journal_schema INTEGER NOT NULL CHECK(journal_schema=4),
            journal_id BLOB NOT NULL CHECK(length(journal_id)=32),
            core_record_codec INTEGER NOT NULL CHECK(core_record_codec=0),
            safety_schema INTEGER NOT NULL CHECK(safety_schema=10),
            core_config_ref BLOB NOT NULL CHECK(length(core_config_ref)=32),
            verifier_profile_ref BLOB NOT NULL CHECK(length(verifier_profile_ref)=32),
            maximum_record_bytes_be BLOB NOT NULL CHECK(length(maximum_record_bytes_be)=8),
            maximum_blob_bytes_be BLOB NOT NULL CHECK(length(maximum_blob_bytes_be)=8),
            maximum_database_bytes_be BLOB NOT NULL CHECK(length(maximum_database_bytes_be)=8),
            transition_codec INTEGER NOT NULL CHECK(transition_codec=0),
            metadata_checksum BLOB NOT NULL CHECK(length(metadata_checksum)=32)
        ) STRICT;
    ";

    #[cfg(unix)]
    #[derive(Debug, Clone, PartialEq, Eq)]
    struct NamespaceFileSnapshotV0 {
        bytes: Vec<u8>,
        device: u64,
        inode: u64,
        mode: u32,
        links: u64,
    }

    #[derive(Debug, Clone, Copy)]
    struct RootSignatures;

    impl SignatureVerifier for RootSignatures {
        fn verify(
            &self,
            _validator: &Validator,
            signing_root: &SigningRoot,
            signature: &SignatureBytes,
        ) -> bool {
            signature.as_bytes()[..32] == signing_root.as_bytes()[..]
                && signature.as_bytes()[32..] == signing_root.as_bytes()[..]
        }
    }

    fn signature(root: SigningRoot) -> SignatureBytes {
        let mut bytes = [0u8; SIGNATURE_BYTES];
        bytes[..32].copy_from_slice(root.as_bytes());
        bytes[32..].copy_from_slice(root.as_bytes());
        SignatureBytes::from_array(bytes)
    }

    fn validator_id(index: u8) -> ValidatorId {
        ValidatorId::new([index; 32])
    }

    fn validator_set(parameters: &ConsensusParametersV0) -> ValidatorSet {
        let validators = (1u8..=4)
            .map(|index| {
                Validator::new(
                    validator_id(index),
                    ConsensusPublicKey::new([index.saturating_add(100); 32]),
                    VotingPower::new(1).expect("positive voting power"),
                )
                .expect("valid validator")
            })
            .collect();
        ValidatorSet::new(
            GenesisHash::new([0xa5; 32]),
            ChainId::from_static("trnm-safety-store-h1-sync"),
            ProtocolVersion::V0,
            Epoch::new(0),
            parameters.hash(),
            validators,
        )
        .expect("valid validator set")
    }

    fn signed_vote(
        set: &ValidatorSet,
        view: u64,
        height: u64,
        block_id: BlockId,
        author: ValidatorId,
    ) -> Vote {
        let root = Vote::signing_root_for_set(set, View::new(view), Height::new(height), block_id)
            .expect("valid vote signing root");
        Vote::new(
            set.chain_id(),
            set.protocol_version(),
            set.epoch(),
            View::new(view),
            Height::new(height),
            block_id,
            set.id(),
            author,
            signature(root),
            set,
        )
        .expect("valid vote")
    }

    fn qc(set: &ValidatorSet, view: u64, height: u64, block_id: BlockId) -> QuorumCertificate {
        QuorumCertificate::new(
            set.chain_id(),
            set.protocol_version(),
            set.epoch(),
            View::new(view),
            Height::new(height),
            block_id,
            set.id(),
            [1u8, 2, 3]
                .into_iter()
                .map(|author| signed_vote(set, view, height, block_id, validator_id(author)))
                .collect(),
            set,
        )
        .expect("valid QC")
    }

    fn proposal(
        set: &ValidatorSet,
        parameters: &ConsensusParametersV0,
        justify: QcReferenceV0,
        view: u64,
        payload: &[u8],
    ) -> SignedProposalV0 {
        let justify_ref = justify.qc_ref();
        let application_payload =
            ApplicationPayloadV0::new(vec![payload.to_vec()]).expect("canonical payload");
        let receipt = ExecutionReceiptCommitmentV0::for_transaction(
            &application_payload,
            0,
            0,
            0,
            Vec::new(),
        )
        .expect("canonical receipt");
        let receipts = ExecutionReceiptsV0::new(&application_payload, vec![receipt])
            .expect("canonical receipt list");
        let body = BlockBodyV0::new(application_payload, Vec::new()).expect("canonical body");
        let height = justify_ref.height().get() + 1;
        let header = BlockHeader::new(
            set.genesis_hash(),
            set.chain_id(),
            set.protocol_version(),
            set.epoch(),
            View::new(view),
            Height::new(height),
            BlockKind::Regular,
            justify_ref.block_id(),
            leader_for(set, View::new(view)),
            set.id(),
            set.consensus_parameters_hash(),
            body.payload_root().expect("payload root"),
            StateRoot::new([height as u8; 32]),
            receipts.receipts_root().expect("receipts root"),
            body.evidence_root().expect("evidence root"),
            height.saturating_mul(100),
            None,
        )
        .expect("valid header");
        let block = Block::new(
            header,
            body.application_payload()
                .try_cev0_bytes()
                .expect("canonical application payload"),
            Vec::new(),
        )
        .expect("valid block");
        let parent_timestamp = if height == 1 {
            GENESIS_TIMESTAMP_MS
        } else {
            height.saturating_sub(1).saturating_mul(100)
        };
        let signing_root =
            ProposalWitnessV0::signing_root_for(block.header(), &justify, None, None)
                .expect("proposal signing root");
        let witness = ProposalWitnessV0::new(
            block.header(),
            justify,
            None,
            None,
            signature(signing_root),
            set,
            None,
            parameters,
            parent_timestamp,
        )
        .expect("valid proposal witness");
        SignedProposalV0::new(block, witness, set, None, parameters, parent_timestamp)
            .expect("valid signed proposal")
    }

    fn try_bootstrap_successor_fixture_with_genesis_parent_v0(
        authenticate_genesis_application_parent: bool,
    ) -> trnm_consensus_core::Result<(
        CoreConfig,
        PreparedH1StateSyncBootstrapV0,
        BlockHeader,
        SignedProposalV0,
        SignedProposalV0,
    )> {
        let parameters = ConsensusParametersV0::reference_shadow_v0();
        let set = validator_set(&parameters);
        let genesis =
            GenesisQcV0::new(set.genesis_hash(), set.chain_id(), &set).expect("valid genesis QC");
        let config = if authenticate_genesis_application_parent {
            let parent = AuthenticatedGenesisApplicationParentV0::new(
                genesis.block_id(),
                GENESIS_TIMESTAMP_MS,
                0,
                StateRoot::new([0x91; 32]),
                [0x92; 32],
                [0x93; 32],
            )
            .expect("valid authenticated genesis application parent");
            CoreConfig::new_with_authenticated_genesis_application_parent_v0(
                validator_id(1),
                set.clone(),
                parameters,
                GENESIS_TIMESTAMP_MS,
                parent,
                64,
                64,
            )
            .expect("valid Core config with authenticated genesis application parent")
        } else {
            CoreConfig::new(
                validator_id(1),
                set.clone(),
                parameters,
                GENESIS_TIMESTAMP_MS,
                64,
                64,
            )
            .expect("valid Core config")
        };
        let h1 = proposal(
            &set,
            &parameters,
            QcReferenceV0::genesis_anchor(genesis),
            1,
            b"h1",
        );
        let q1 = qc(&set, 1, 1, h1.block().id());
        let h2 = proposal(
            &set,
            &parameters,
            QcReferenceV0::ordinary(q1.clone()),
            2,
            b"h2",
        );
        let q2 = qc(&set, 2, 2, h2.block().id());
        let h3 = proposal(
            &set,
            &parameters,
            QcReferenceV0::ordinary(q2.clone()),
            3,
            b"h3",
        );
        let q3 = qc(&set, 3, 3, h3.block().id());
        let certified_h1 = CertifiedHeaderV0::from_signed_proposal(
            h1.clone(),
            q1,
            &set,
            None,
            &parameters,
            GENESIS_TIMESTAMP_MS,
        )
        .expect("certified h1");
        let certified_h2 = CertifiedHeaderV0::from_signed_proposal(
            h2.clone(),
            q2,
            &set,
            None,
            &parameters,
            h1.block().header().timestamp_ms(),
        )
        .expect("certified h2");
        let certified_h3 = CertifiedHeaderV0::from_signed_proposal(
            h3.clone(),
            q3,
            &set,
            None,
            &parameters,
            h2.block().header().timestamp_ms(),
        )
        .expect("certified h3");
        let proof = FinalityProofV0::new(
            certified_h1,
            certified_h2,
            certified_h3,
            &set,
            None,
            &parameters,
            GENESIS_TIMESTAMP_MS,
        )
        .expect("valid h1 finality proof");
        let h1_header = h1.block().header().clone();
        let prepared =
            Core::prepare_h1_state_sync_bootstrap_v0(config.clone(), proof, &RootSignatures)?;
        Ok((config, prepared, h1_header, h2, h3))
    }

    fn bootstrap_successor_fixture() -> (
        CoreConfig,
        PreparedH1StateSyncBootstrapV0,
        BlockHeader,
        SignedProposalV0,
        SignedProposalV0,
    ) {
        try_bootstrap_successor_fixture_with_genesis_parent_v0(false)
            .expect("prepared h1 state-sync bootstrap")
    }

    fn bootstrap_fixture() -> (CoreConfig, PreparedH1StateSyncBootstrapV0, BlockHeader) {
        let (config, prepared, h1_header, _h2, _h3) = bootstrap_successor_fixture();
        (config, prepared, h1_header)
    }

    fn authenticated_genesis_bootstrap_fixture() -> (
        CoreConfig,
        PreparedAuthenticatedGenesisApplicationBootstrapV0,
    ) {
        let parameters = ConsensusParametersV0::reference_shadow_v0();
        let set = validator_set(&parameters);
        let genesis =
            GenesisQcV0::new(set.genesis_hash(), set.chain_id(), &set).expect("valid genesis QC");
        let parent = AuthenticatedGenesisApplicationParentV0::new(
            genesis.block_id(),
            GENESIS_TIMESTAMP_MS,
            0,
            StateRoot::new([0xa1; 32]),
            [0xa2; 32],
            [0xa3; 32],
        )
        .expect("valid authenticated-genesis application parent");
        let config = CoreConfig::new_with_authenticated_genesis_application_parent_v0(
            validator_id(1),
            set,
            parameters,
            GENESIS_TIMESTAMP_MS,
            parent,
            64,
            64,
        )
        .expect("valid authenticated-genesis Core config");
        let selected_profile = profile(&config);
        let prepared = Core::prepare_authenticated_genesis_application_bootstrap_v0(
            config.clone(),
            genesis,
            selected_profile.verifier_profile_ref(),
            selected_profile.record_limits(),
            &RootSignatures,
        )
        .expect("prepare inert authenticated-genesis facts");
        (config, prepared)
    }

    fn authenticated_genesis_h1_offline_fixture() -> (
        CoreConfig,
        PreparedAuthenticatedGenesisApplicationBootstrapV0,
        SignedProposalV0,
    ) {
        let (config, prepared) = authenticated_genesis_bootstrap_fixture();
        let genesis = GenesisQcV0::new(
            config.validator_set().genesis_hash(),
            config.validator_set().chain_id(),
            config.validator_set(),
        )
        .expect("rebuild exact genesis QC");
        let h1 = proposal(
            config.validator_set(),
            config.consensus_parameters(),
            QcReferenceV0::genesis_anchor(genesis),
            1,
            b"authenticated-genesis-h1",
        );
        (config, prepared, h1)
    }

    fn authenticated_genesis_empty_h1_proposal_v0(config: &CoreConfig) -> SignedProposalV0 {
        let payload = ApplicationPayloadV0::new(Vec::new()).expect("empty application payload");
        let receipts = ExecutionReceiptsV0::new(&payload, Vec::new()).expect("empty receipts");
        let body = BlockBodyV0::new(payload, Vec::new()).expect("empty regular body");
        let header = BlockHeader::new(
            config.validator_set().genesis_hash(),
            config.validator_set().chain_id(),
            config.validator_set().protocol_version(),
            Epoch::new(0),
            View::new(1),
            Height::new(1),
            BlockKind::Regular,
            config
                .authenticated_genesis_application_parent_v0()
                .expect("authenticated application parent")
                .genesis_block_id(),
            leader_for(config.validator_set(), View::new(1)),
            config.validator_set().id(),
            config.consensus_parameters().hash(),
            body.payload_root().expect("empty payload root"),
            StateRoot::new([1; 32]),
            receipts.receipts_root().expect("empty receipts root"),
            body.evidence_root().expect("empty evidence root"),
            100,
            None,
        )
        .expect("canonical empty h1 header");
        let block = Block::new(
            header,
            body.application_payload()
                .try_cev0_bytes()
                .expect("encode empty payload"),
            Vec::new(),
        )
        .expect("canonical empty h1 block");
        let genesis = GenesisQcV0::new(
            config.validator_set().genesis_hash(),
            config.validator_set().chain_id(),
            config.validator_set(),
        )
        .expect("exact genesis QC");
        let justify = QcReferenceV0::genesis_anchor(genesis);
        let signing_root =
            ProposalWitnessV0::signing_root_for(block.header(), &justify, None, None)
                .expect("empty h1 signing root");
        let witness = ProposalWitnessV0::new(
            block.header(),
            justify,
            None,
            None,
            signature(signing_root),
            config.validator_set(),
            None,
            config.consensus_parameters(),
            config.trusted_genesis_timestamp_ms(),
        )
        .expect("canonical empty h1 witness");
        SignedProposalV0::new(
            block,
            witness,
            config.validator_set(),
            None,
            config.consensus_parameters(),
            config.trusted_genesis_timestamp_ms(),
        )
        .expect("canonical empty h1 proposal")
    }

    fn authenticated_genesis_h1_stable_fixture_v0() -> (
        CoreConfig,
        PreparedAuthenticatedGenesisApplicationBootstrapV0,
        PreparedAuthenticatedGenesisApplicationBootstrapV0,
        SignedProposalV0,
    ) {
        let (config, prepared_live) = authenticated_genesis_bootstrap_fixture();
        let selected_profile = profile(&config);
        let genesis = GenesisQcV0::new(
            config.validator_set().genesis_hash(),
            config.validator_set().chain_id(),
            config.validator_set(),
        )
        .expect("rebuild exact genesis QC");
        let prepared_recovery = Core::prepare_authenticated_genesis_application_bootstrap_v0(
            config.clone(),
            genesis,
            selected_profile.verifier_profile_ref(),
            selected_profile.record_limits(),
            &RootSignatures,
        )
        .expect("prepare independent stable recovery facts");
        let h1 = authenticated_genesis_empty_h1_proposal_v0(&config);
        (config, prepared_live, prepared_recovery, h1)
    }

    fn authenticated_genesis_h1_offline_completion_without_store_v0(
        config: &CoreConfig,
        prepared: PreparedAuthenticatedGenesisApplicationBootstrapV0,
        h1: SignedProposalV0,
    ) -> ApplicationSealedNativeValidTransitionV0 {
        let bundle = Core::begin_authenticated_genesis_application_h1_offline_validation_v0(
            config.clone(),
            prepared,
            &RootSignatures,
        )
        .expect("begin foreign bounded h1 activation");
        let mut owner = activate_authenticated_genesis_h1_for_test_v0(bundle);
        let obligation = owner
            .submit_exact_h1_synced_proposal_v0(h1, &RootSignatures)
            .expect("produce foreign rev1 obligation");
        let _binding = owner
            .issue_safety_persistence_binding_v0()
            .expect("issue foreign Safety binding");
        let validation = owner
            .acknowledge_obligation_persisted_v0(
                &obligation,
                obligation.barrier_v0(),
                &RootSignatures,
            )
            .expect("advance foreign owner to validation");
        let claimed = validation
            .try_claim_v0()
            .unwrap_or_else(|_| panic!("foreign h1 validation request was unexpectedly claimed"));
        let (_route, _id, block, _parent, permit) = claimed.into_parts();
        let sealed = owner.seal_after_application_store_commit_v0(
            permit,
            valid_commitments_v0(config, &block),
            artifact_ref_v0(&block),
        );
        let completion = owner
            .accept_application_sealed_valid_v0(&sealed, &RootSignatures)
            .expect("produce foreign rev2 completion");
        let [durable_completion] = completion
            .persistence_v0()
            .state()
            .payload_validation_completions()
        else {
            panic!("foreign rev2 state contains one completion")
        };
        let facts = ApplicationNativeValidDeliveryFactsV0::new(
            PayloadValidationRouteV0::Synced,
            completion.validation_id_v0(),
            [0x61; 32],
            [0x62; 32],
            [0x63; 32],
            trnm_consensus_core::native_valid_result_checksum_v0(durable_completion.result())
                .expect("canonical foreign Valid result checksum"),
            [0x64; 32],
            [0x65; 32],
            1,
            [0x66; 32],
            [0x67; 32],
            NativeValidPostAckActionV0::None,
            2,
        )
        .expect("foreign exact D facts");
        owner
            .seal_authenticated_genesis_h1_native_valid_transition_v0(completion, facts)
            .expect("seal foreign exact D transition")
    }

    #[test]
    fn authenticated_genesis_application_tag5_initializes_reopens_and_mints_exact_capability_v0() {
        let (config, prepared) = authenticated_genesis_bootstrap_fixture();
        let directory = protected_temp_dir();
        let database = directory.path().join("authenticated-genesis.sqlite");
        let selected_profile = profile(&config);

        let (store, disposition) =
            SqliteSafetyStateStoreV0::initialize_or_resume_authenticated_genesis_application_exact_v0(
                &database,
                selected_profile.clone(),
                RootSignatures,
                &prepared,
            )
            .expect("initialize exact authenticated-genesis tag-5 journal");
        assert_eq!(
            disposition,
            AuthenticatedGenesisApplicationInitializationDispositionV0::Initialized
        );
        let capability = store
            .confirmed_authenticated_genesis_application_bootstrap_head_exact_v0(&prepared)
            .expect("confirm exact live tag-5 head");
        assert!(capability.belongs_to_store_at_path_v0(&store, store.path()));
        assert_eq!(capability.database_path_v0(), store.path());
        assert_eq!(capability.revision_v0(), 0);
        assert_eq!(capability.state_v0(), prepared.safety_state());
        assert_eq!(
            capability.core_config_ref_v0(),
            prepared.safety_state_record_config_ref_v0()
        );
        assert_eq!(
            capability.transition_v0().carrier(),
            prepared.authenticated_genesis_application_parent_v0()
        );
        assert_eq!(
            capability.transition_v0().carrier_binding_ref(),
            prepared
                .authenticated_genesis_application_parent_v0()
                .binding_ref_v0()
        );
        assert_eq!(
            capability.transition_v0().state_record_checksum(),
            capability.state_record_checksum_v0()
        );
        assert_ne!(capability.transition_context_checksum_v0(), [0; 32]);
        assert_ne!(capability.chain_checksum_v0(), [0; 32]);
        assert_ne!(capability.head_checksum_v0(), [0; 32]);
        drop(capability);
        drop(store);

        assert!(matches!(
            SqliteSafetyStateStoreV0::open_existing(
                &database,
                selected_profile.clone(),
                RootSignatures,
            ),
            Err(SafetyStoreErrorV0::AuthenticatedGenesisApplicationActivationUnavailable)
        ));
        assert!(matches!(
            SqliteSafetyStateStoreV0::open_existing_authenticated_genesis_application_h1_dispatch_v0(
                &database,
                selected_profile.clone(),
                RootSignatures,
            ),
            Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(_))
        ));
        let reopened =
            SqliteSafetyStateStoreV0::open_existing_authenticated_genesis_application_exact_v0(
                &database,
                selected_profile,
                RootSignatures,
                &prepared,
            )
            .expect("reopen exact authenticated-genesis tag-5 journal");
        let capability = reopened
            .confirmed_authenticated_genesis_application_bootstrap_head_exact_v0(&prepared)
            .expect("confirm reopened tag-5 head");
        assert!(capability.belongs_to_store_at_path_v0(&reopened, reopened.path()));
    }

    fn exercise_authenticated_genesis_h1_stable_native_valid_recovery_v0() {
        let (config, prepared, prepared_recovery, h1) =
            authenticated_genesis_h1_stable_fixture_v0();
        let selected_profile = profile(&config);
        let directory = protected_temp_dir();
        let database = directory.path().join("authenticated-genesis-h1.sqlite");
        let (mut store, disposition) =
            SqliteSafetyStateStoreV0::initialize_or_resume_authenticated_genesis_application_exact_v0(
                &database,
                selected_profile.clone(),
                RootSignatures,
                &prepared,
            )
            .expect("initialize exact tag-5 journal");
        assert_eq!(
            disposition,
            AuthenticatedGenesisApplicationInitializationDispositionV0::Initialized
        );
        let tag5 = store
            .confirmed_authenticated_genesis_application_bootstrap_head_exact_v0(&prepared)
            .expect("confirm fresh tag-5 head");
        let bundle = Core::begin_authenticated_genesis_application_h1_offline_validation_v0(
            config.clone(),
            prepared,
            &RootSignatures,
        )
        .expect("begin bounded authenticated-genesis h1 activation");
        let mut owner = activate_authenticated_genesis_h1_for_test_v0(bundle);
        let obligation = owner
            .submit_exact_h1_synced_proposal_v0(h1, &RootSignatures)
            .expect("admit exact h1 and produce rev1 persistence");
        let revision_one = obligation.persistence_v0().state().clone();
        let binding = owner
            .issue_safety_persistence_binding_v0()
            .expect("issue one dedicated Safety binding");
        store
            .bind_authenticated_genesis_application_h1_offline_v0(tag5, binding)
            .expect("bind exact tag-5 journal to bounded h1 owner");

        assert!(matches!(
            store.persist_exact_v0(
                obligation.persistence_v0(),
                &SafetyTransitionContextV0::Ordinary,
            ),
            Err(
                SafetyStoreErrorV0::AuthenticatedGenesisApplicationH1OfflineRequiresDedicatedPersistence
            )
        ));
        assert!(matches!(
            store.preflight_bound_native_valid_persistence_v0(obligation.persistence_v0()),
            Err(
                SafetyStoreErrorV0::AuthenticatedGenesisApplicationH1OfflineRequiresDedicatedPersistence
            )
        ));
        assert_eq!(
            store
                .persist_authenticated_genesis_application_h1_obligation_exact_v0(&obligation)
                .expect("persist exact rev1 Synced obligation"),
            SafetyPersistDispositionV0::Inserted
        );
        assert_eq!(
            store
                .persist_authenticated_genesis_application_h1_obligation_exact_v0(&obligation)
                .expect("retry exact rev1 Synced obligation"),
            SafetyPersistDispositionV0::Existing
        );
        let validation = owner
            .acknowledge_obligation_persisted_v0(
                &obligation,
                obligation.barrier_v0(),
                &RootSignatures,
            )
            .expect("release exact h1 validation request after rev1");
        let validation_id = validation.validation_id_v0();
        let claimed = validation
            .try_claim_v0()
            .unwrap_or_else(|_| panic!("h1 validation request was unexpectedly claimed"));
        let (route, id, block, _parent, permit) = claimed.into_parts();
        assert_eq!(route, PayloadValidationRouteV0::Synced);
        assert_eq!(id, validation_id);
        let sealed = owner.seal_after_application_store_commit_v0(
            permit,
            valid_commitments_v0(&config, &block),
            artifact_ref_v0(&block),
        );
        let completion = owner
            .accept_application_sealed_valid_v0(&sealed, &RootSignatures)
            .expect("accept exact App-sealed h1 Valid");
        let revision_two = completion.persistence_v0().state().clone();
        assert!(matches!(
            store.preflight_bound_native_valid_persistence_v0(completion.persistence_v0()),
            Err(
                SafetyStoreErrorV0::AuthenticatedGenesisApplicationH1OfflineRequiresDedicatedPersistence
            )
        ));
        let preflight = store
            .preflight_authenticated_genesis_application_h1_native_valid_exact_v0(&completion)
            .expect("preflight exact rev2 completion above the live rev1 head");
        assert_eq!(preflight.journal_id_v0(), store.journal_id_v0());
        assert_eq!(
            preflight.verifier_profile_ref_v0(),
            store.verifier_profile_ref_v0()
        );
        assert_eq!(preflight.revision_v0(), 2);
        assert_ne!(preflight.state_record_checksum_v0(), [0; 32]);
        assert_eq!(
            preflight.post_ack_action_v0(),
            NativeValidPostAckActionV0::None
        );
        assert_eq!(
            store
                .head()
                .expect("preflight leaves the exact rev1 head unchanged")
                .revision(),
            1
        );
        let context = successor_native_valid_context_v0(
            completion.persistence_v0(),
            PayloadValidationRouteV0::Synced,
            validation_id,
        );
        assert!(matches!(
            store.persist_exact_v0(completion.persistence_v0(), &context),
            Err(
                SafetyStoreErrorV0::AuthenticatedGenesisApplicationH1OfflineRequiresDedicatedPersistence
            )
        ));
        let [durable_completion] = completion
            .persistence_v0()
            .state()
            .payload_validation_completions()
        else {
            panic!("exact rev2 state contains one completion")
        };
        let delivery_facts = ApplicationNativeValidDeliveryFactsV0::new(
            PayloadValidationRouteV0::Synced,
            validation_id,
            [0x31; 32],
            [0x32; 32],
            [0x33; 32],
            trnm_consensus_core::native_valid_result_checksum_v0(durable_completion.result())
                .expect("canonical rev2 Valid result checksum"),
            [0x35; 32],
            [0x36; 32],
            1,
            [0x37; 32],
            [0x38; 32],
            NativeValidPostAckActionV0::None,
            2,
        )
        .expect("exact App D delivery facts");
        let sealed_transition = owner
            .seal_authenticated_genesis_h1_native_valid_transition_v0(completion, delivery_facts)
            .expect("seal exact App D transition");
        let confirmed = store
            .persist_authenticated_genesis_application_h1_native_valid_exact_v0(&sealed_transition)
            .expect("persist and confirm exact rev2 NativeValid");
        assert_eq!(confirmed.revision(), 2);
        assert_eq!(confirmed.transition_context(), &context);
        let retried = store
            .persist_authenticated_genesis_application_h1_native_valid_exact_v0(&sealed_transition)
            .expect("retry and confirm exact rev2 NativeValid");
        assert_eq!(retried.revision(), 2);
        assert_eq!(retried.transition_context(), &context);
        assert!(matches!(
            store.preflight_authenticated_genesis_application_h1_native_valid_exact_v0(
                sealed_transition.completion_persistence_v0(),
            ),
            Err(
                SafetyStoreErrorV0::AuthenticatedGenesisApplicationH1OfflinePersistenceMismatch {
                    expected_revision: 1,
                    actual_revision: 2,
                }
            )
        ));
        let completed = owner
            .acknowledge_completion_persisted_v0(
                &sealed_transition,
                sealed_transition.completion_persistence_v0().barrier_v0(),
                &RootSignatures,
            )
            .expect("close bounded h1 owner after rev2");
        assert_eq!(completed.safety_revision_v0(), 2);
        assert_eq!(completed.validation_id_v0(), validation_id);
        let head = store.head().expect("authenticate exact rev2 head");
        assert_eq!(head.revision(), 2);
        assert_eq!(head.transition_context(), &context);
        drop(head);
        drop(store);

        assert!(matches!(
            SqliteSafetyStateStoreV0::open_existing(
                &database,
                selected_profile.clone(),
                RootSignatures,
            ),
            Err(SafetyStoreErrorV0::AuthenticatedGenesisApplicationActivationUnavailable)
        ));
        let (reopened, cut) =
            SqliteSafetyStateStoreV0::open_existing_authenticated_genesis_application_h1_dispatch_v0(
                &database,
                selected_profile.clone(),
                RootSignatures,
            )
            .expect("typed dispatch authenticates the stable rev1/rev2 lineage");
        let AuthenticatedGenesisApplicationH1ExistingCutV0::StableNativeValidRev2(readback) = cut
        else {
            panic!("stable rev2 journal was misclassified as a rev1 obligation")
        };
        let (read_revision_one, read_revision_two) = readback.into_core_states_v0();
        assert_eq!(read_revision_one, revision_one);
        assert_eq!(read_revision_two, revision_two);
        let recovery =
            Core::begin_authenticated_genesis_application_h1_stable_native_valid_recovery_v0(
                config,
                prepared_recovery,
                read_revision_one,
                read_revision_two,
                &RootSignatures,
            )
            .expect("Core accepts only the exact empty-h1 stable lineage");
        let confirmed = reopened
            .confirmed_authenticated_genesis_application_h1_stable_native_valid_head_exact_v0(
                recovery.challenge_v0(),
            )
            .expect("fresh live Safety owner confirms the complete tag5/rev1/rev2 lineage");
        assert!(confirmed.belongs_to_store_at_path_v0(&reopened, reopened.path()));
        assert_eq!(
            confirmed.state_v0(),
            recovery.challenge_v0().revision_two_state_v0()
        );
        assert_eq!(confirmed.transition_context_v0(), &context);
        assert_eq!(confirmed.application_delivery_facts_v0(), delivery_facts);
        assert_ne!(confirmed.state_record_checksum_v0(), [0; 32]);
        assert_ne!(confirmed.chain_checksum_v0(), [0; 32]);
        assert_ne!(
            confirmed.safety_head_facts_v0().tag5_head_checksum_v0(),
            confirmed
                .safety_head_facts_v0()
                .revision_two_head_checksum_v0()
        );
        let wrong_path = directory.path().join("foreign-stable-owner.sqlite");
        assert!(!confirmed.belongs_to_store_at_path_v0(&reopened, &wrong_path));
        drop(reopened);
        let reopened = SqliteSafetyStateStoreV0::open_existing_authenticated_genesis_application_h1_stable_native_valid_v0(
            &database,
            selected_profile,
            RootSignatures,
        )
        .expect("reopen a second dedicated stable owner");
        assert!(
            !confirmed.belongs_to_store_at_path_v0(&reopened, reopened.path()),
            "an old capability cannot transfer to a replacement owner"
        );
        let confirmed = reopened
            .confirmed_authenticated_genesis_application_h1_stable_native_valid_head_exact_v0(
                recovery.challenge_v0(),
            )
            .expect("mint fresh capability from the replacement owner");

        struct ExactStableJoin;
        impl AuthenticatedGenesisApplicationH1StableNativeValidRecoveryReconcilerV0 for ExactStableJoin {
            fn reconcile_authenticated_genesis_application_h1_stable_native_valid_v0(
                &mut self,
                challenge: &AuthenticatedGenesisApplicationH1StableNativeValidRecoveryChallengeV0,
                safety_head_facts: &AuthenticatedGenesisApplicationH1StableNativeValidSafetyHeadFactsV0,
            ) -> bool {
                challenge.revision_two_state_v0().revision() == 2
                    && safety_head_facts.revision_two_state_record_checksum_v0() != [0; 32]
                    && safety_head_facts
                        .application_delivery_facts_v0()
                        .completion_revision()
                        == 2
            }
        }
        let attestation = recovery
            .challenge_v0()
            .attest_authenticated_reconciliation_v0(
                confirmed.safety_head_facts_v0().clone(),
                &mut ExactStableJoin,
            )
            .expect("trusted exact join attests the live store capability");
        let mut replay = recovery
            .reconcile_and_complete_v0(attestation)
            .expect("the owning recovery session consumes its attestation");
        let recovered = replay
            .release_inert_completed_facts_v0()
            .expect("release inert completed facts once");
        assert_eq!(
            recovered.proposal_v0().block().id(),
            confirmed
                .application_delivery_facts_v0()
                .validation_id()
                .block_id()
        );
        assert_eq!(
            recovered.completion_carrier_checksum_v0(),
            confirmed
                .safety_head_facts_v0()
                .completion_carrier_checksum_v0()
        );
        let displaced_database = directory.path().join("displaced-stable.sqlite");
        fs::rename(&database, &displaced_database).expect("displace the pinned main DB inode");
        fs::copy(&displaced_database, &database).expect("install byte-identical replacement inode");
        assert!(
            !confirmed.belongs_to_store_at_path_v0(&reopened, reopened.path()),
            "a same-path byte-identical inode replacement invalidates the live capability"
        );
    }

    #[test]
    fn authenticated_genesis_h1_obligation_reopens_existing_only_with_exact_rev0_rev1_lineage_v0() {
        let worker = std::thread::Builder::new()
            .name("safety-store-authenticated-genesis-h1-obligation-reopen".to_string())
            .stack_size(32 * 1024 * 1024)
            .spawn(run_authenticated_genesis_h1_obligation_reopen_exact_lineage_v0)
            .expect("spawn the bounded large-stack h1 obligation-reopen test");
        match worker.join() {
            Ok(()) => {}
            Err(payload) => std::panic::resume_unwind(payload),
        }
    }

    fn run_authenticated_genesis_h1_obligation_reopen_exact_lineage_v0() {
        let (config, prepared, prepared_takeover, h1) =
            authenticated_genesis_h1_stable_fixture_v0();
        let revision_zero = prepared.safety_state().clone();
        let selected_profile = profile(&config);
        let directory = protected_temp_dir();
        let database = directory
            .path()
            .join("authenticated-genesis-h1-obligation.sqlite");
        let (mut store, disposition) =
            SqliteSafetyStateStoreV0::initialize_or_resume_authenticated_genesis_application_exact_v0(
                &database,
                selected_profile.clone(),
                RootSignatures,
                &prepared,
            )
            .expect("initialize exact tag-5 journal");
        assert_eq!(
            disposition,
            AuthenticatedGenesisApplicationInitializationDispositionV0::Initialized
        );
        let tag5 = store
            .confirmed_authenticated_genesis_application_bootstrap_head_exact_v0(&prepared)
            .expect("confirm exact tag-5 head");
        let bundle = Core::begin_authenticated_genesis_application_h1_offline_validation_v0(
            config.clone(),
            prepared,
            &RootSignatures,
        )
        .expect("begin exact h1 owner");
        let mut owner = activate_authenticated_genesis_h1_for_test_v0(bundle);
        let obligation = owner
            .submit_exact_h1_synced_proposal_v0(h1, &RootSignatures)
            .expect("derive exact rev1 obligation");
        let revision_one = obligation.persistence_v0().state().clone();
        let binding = owner
            .issue_safety_persistence_binding_v0()
            .expect("issue exact h1 Safety binding");
        store
            .bind_authenticated_genesis_application_h1_offline_v0(tag5, binding)
            .expect("bind tag-5 owner");
        assert_eq!(
            store
                .persist_authenticated_genesis_application_h1_obligation_exact_v0(&obligation)
                .expect("persist exact rev1 obligation"),
            SafetyPersistDispositionV0::Inserted
        );
        drop(store);

        assert!(matches!(
            SqliteSafetyStateStoreV0::open_existing(
                &database,
                selected_profile.clone(),
                RootSignatures,
            ),
            Err(SafetyStoreErrorV0::AuthenticatedGenesisApplicationActivationUnavailable)
        ));
        let (mut reopened, cut) =
            SqliteSafetyStateStoreV0::open_existing_authenticated_genesis_application_h1_dispatch_v0(
                &database,
                selected_profile.clone(),
                RootSignatures,
            )
            .expect("typed dispatch authenticates the retained rev0/rev1 obligation lineage");
        let AuthenticatedGenesisApplicationH1ExistingCutV0::ObligationRev1(readback) = cut else {
            panic!("rev1 obligation journal was misclassified as stable rev2")
        };
        let (read_revision_zero, read_revision_one) = readback.into_core_states_v0();
        assert_eq!(read_revision_zero, revision_zero);
        assert_eq!(read_revision_one, revision_one);
        assert_eq!(
            reopened.head().expect("authenticate rev1 head").revision(),
            1
        );

        let takeover = Core::begin_authenticated_genesis_application_h1_obligation_takeover_v0(
            config,
            prepared_takeover,
            read_revision_one,
            &RootSignatures,
        )
        .expect("Core truly replays the durable h1 obligation from tag-5");
        let confirmed = reopened
            .confirmed_authenticated_genesis_application_h1_obligation_head_exact_v0(
                takeover.challenge_v0(),
            )
            .expect("live Safety owner confirms the exact tag-5/rev1 lineage");
        assert!(confirmed.belongs_to_store_at_path_v0(&reopened, reopened.path()));
        assert_eq!(
            confirmed.state_v0(),
            takeover.challenge_v0().revision_one_state_v0()
        );
        assert_eq!(
            confirmed.transition_context_v0(),
            &SafetyTransitionContextV0::Ordinary
        );
        assert_eq!(
            confirmed.state_record_checksum_v0(),
            confirmed
                .safety_head_facts_v0()
                .revision_one_state_record_checksum_v0()
        );
        assert_ne!(confirmed.chain_checksum_v0(), [0; 32]);
        assert_ne!(
            confirmed.safety_head_facts_v0().tag5_head_checksum_v0(),
            confirmed
                .safety_head_facts_v0()
                .revision_one_head_checksum_v0()
        );
        let expected_validation_id = confirmed.safety_head_facts_v0().validation_id_v0();
        let wrong_path = directory.path().join("foreign-h1-obligation.sqlite");
        assert!(!confirmed.belongs_to_store_at_path_v0(&reopened, &wrong_path));
        let stale_confirmed = reopened
            .confirmed_authenticated_genesis_application_h1_obligation_head_exact_v0(
                takeover.challenge_v0(),
            )
            .expect("mint a second one-shot capability for replacement-owner rejection");
        let observed_revision = reopened.observed_head_revision;
        reopened.observed_head_revision = observed_revision + 1;
        assert!(
            !stale_confirmed.belongs_to_store_at_path_v0(&reopened, reopened.path()),
            "a capability is stale as soon as its live owner head tuple advances"
        );
        reopened.observed_head_revision = observed_revision;

        let before_rebind_head = reopened.head().expect("authenticate pre-rebind rev1 head");
        let before_rebind_watermark = reopened.observed_lock_watermark;
        let rebound = reopened
            .activate_and_rebind_authenticated_genesis_application_h1_obligation_takeover_exact_v0(
                takeover,
            )
            .expect(
                "production bridge privately reconciles and rebinds the replay Core without rewriting rev1",
            );
        let after_rebind_head = reopened.head().expect("authenticate post-rebind rev1 head");
        assert_eq!(after_rebind_head, before_rebind_head);
        assert_eq!(reopened.observed_lock_watermark, before_rebind_watermark);
        let (_bundle, request) = rebound
            .acknowledge_and_release_validation_request_v0(&RootSignatures)
            .expect("real Core StorageAck releases one fresh validation request");
        assert_eq!(request.validation_id_v0(), expected_validation_id);
        drop(reopened);
        let replacement = SqliteSafetyStateStoreV0::open_existing_authenticated_genesis_application_h1_obligation_v0(
            &database,
            selected_profile,
            RootSignatures,
        )
        .expect("open a replacement obligation owner");
        assert!(
            !stale_confirmed.belongs_to_store_at_path_v0(&replacement, replacement.path()),
            "an old capability cannot transfer to a replacement Safety owner"
        );
    }

    fn run_authenticated_genesis_h1_stable_native_valid_recovery_on_large_stack_v0() {
        let worker = std::thread::Builder::new()
            .name("safety-store-authenticated-genesis-h1-stable-native-valid".to_string())
            .stack_size(32 * 1024 * 1024)
            .spawn(exercise_authenticated_genesis_h1_stable_native_valid_recovery_v0)
            .expect("spawn the bounded large-stack h1 stable NativeValid recovery test");
        match worker.join() {
            Ok(()) => {}
            Err(payload) => std::panic::resume_unwind(payload),
        }
    }

    #[test]
    fn authenticated_genesis_h1_offline_tag5_ordinary_native_valid_sequence_is_dedicated_v0() {
        run_authenticated_genesis_h1_stable_native_valid_recovery_on_large_stack_v0();
    }

    #[test]
    fn authenticated_genesis_h1_stable_native_valid_reopens_and_mints_exact_capability_v0() {
        run_authenticated_genesis_h1_stable_native_valid_recovery_on_large_stack_v0();
    }

    #[test]
    fn authenticated_genesis_h1_offline_rejects_foreign_tag5_owner_before_binding_v0() {
        let (config_a, prepared_a, _h1_a) = authenticated_genesis_h1_offline_fixture();
        let (config_b, prepared_b, h1_b) = authenticated_genesis_h1_offline_fixture();
        let directory = protected_temp_dir();
        let database_a = directory.path().join("tag5-owner-a.sqlite");
        let database_b = directory.path().join("tag5-owner-b.sqlite");
        let (store_a, _) =
            SqliteSafetyStateStoreV0::initialize_or_resume_authenticated_genesis_application_exact_v0(
                &database_a,
                profile(&config_a),
                RootSignatures,
                &prepared_a,
            )
            .expect("initialize first exact tag-5 owner");
        let foreign_tag5 = store_a
            .confirmed_authenticated_genesis_application_bootstrap_head_exact_v0(&prepared_a)
            .expect("mint first owner capability");
        let (mut store_b, _) =
            SqliteSafetyStateStoreV0::initialize_or_resume_authenticated_genesis_application_exact_v0(
                &database_b,
                profile(&config_b),
                RootSignatures,
                &prepared_b,
            )
            .expect("initialize second exact tag-5 owner");
        let bundle_b = Core::begin_authenticated_genesis_application_h1_offline_validation_v0(
            config_b,
            prepared_b,
            &RootSignatures,
        )
        .expect("begin second bounded h1 activation");
        let mut owner_b = activate_authenticated_genesis_h1_for_test_v0(bundle_b);
        let obligation_b = owner_b
            .submit_exact_h1_synced_proposal_v0(h1_b, &RootSignatures)
            .expect("produce second owner rev1 request");
        let binding_b = owner_b
            .issue_safety_persistence_binding_v0()
            .expect("issue second owner binding");

        assert!(matches!(
            store_b.bind_authenticated_genesis_application_h1_offline_v0(foreign_tag5, binding_b,),
            Err(SafetyStoreErrorV0::AuthenticatedGenesisApplicationH1OfflineBindingMismatch)
        ));
        assert_eq!(
            store_b
                .head()
                .expect("second owner remains tag 5")
                .revision(),
            0
        );
        assert!(matches!(
            store_b
                .persist_authenticated_genesis_application_h1_obligation_exact_v0(&obligation_b,),
            Err(SafetyStoreErrorV0::CoreNotBound)
        ));
    }

    #[test]
    fn authenticated_genesis_h1_offline_preflight_rejects_foreign_core_completion_v0() {
        let (config, prepared, h1) = authenticated_genesis_h1_offline_fixture();
        let directory = protected_temp_dir();
        let database = directory.path().join("tag5-preflight-owner.sqlite");
        let (mut store, _) =
            SqliteSafetyStateStoreV0::initialize_or_resume_authenticated_genesis_application_exact_v0(
                &database,
                profile(&config),
                RootSignatures,
                &prepared,
            )
            .expect("initialize exact tag-5 preflight owner");
        let tag5 = store
            .confirmed_authenticated_genesis_application_bootstrap_head_exact_v0(&prepared)
            .expect("mint exact preflight owner capability");
        let bundle = Core::begin_authenticated_genesis_application_h1_offline_validation_v0(
            config,
            prepared,
            &RootSignatures,
        )
        .expect("begin exact preflight activation");
        let mut owner = activate_authenticated_genesis_h1_for_test_v0(bundle);
        let obligation = owner
            .submit_exact_h1_synced_proposal_v0(h1, &RootSignatures)
            .expect("produce exact owner rev1 obligation");
        let binding = owner
            .issue_safety_persistence_binding_v0()
            .expect("issue exact preflight owner binding");
        store
            .bind_authenticated_genesis_application_h1_offline_v0(tag5, binding)
            .expect("bind exact preflight owner");
        assert_eq!(
            store
                .persist_authenticated_genesis_application_h1_obligation_exact_v0(&obligation)
                .expect("persist exact preflight owner rev1"),
            SafetyPersistDispositionV0::Inserted
        );

        let (foreign_config, foreign_prepared, foreign_h1) =
            authenticated_genesis_h1_offline_fixture();
        let foreign_sealed = authenticated_genesis_h1_offline_completion_without_store_v0(
            &foreign_config,
            foreign_prepared,
            foreign_h1,
        );
        assert!(matches!(
            store.preflight_authenticated_genesis_application_h1_native_valid_exact_v0(
                foreign_sealed.completion_persistence_v0(),
            ),
            Err(SafetyStoreErrorV0::CoreAffinityMismatch)
        ));
        assert!(matches!(
            store.persist_authenticated_genesis_application_h1_native_valid_exact_v0(
                &foreign_sealed,
            ),
            Err(SafetyStoreErrorV0::CoreAffinityMismatch)
        ));
        assert_eq!(
            store
                .head()
                .expect("foreign preflight leaves exact rev1 head unchanged")
                .revision(),
            1
        );
    }

    #[test]
    fn authenticated_genesis_application_tag5_resumes_all_initialization_commit_cuts_v0() {
        let (config, bootstrap) = authenticated_genesis_bootstrap_fixture();
        let selected_profile = profile(&config);
        let directory = protected_temp_dir();

        let intent_only_database = directory.path().join("tag5-intent-only.sqlite");
        let (intent_only_marker, _) = seed_authenticated_genesis_initialization_intent(
            &intent_only_database,
            &selected_profile,
            &bootstrap,
            [0xd1; 32],
        );
        let (store, disposition) = SqliteSafetyStateStoreV0::
            initialize_or_resume_authenticated_genesis_application_exact_v0(
                &intent_only_database,
                selected_profile.clone(),
                RootSignatures,
                &bootstrap,
            )
            .expect("resume tag-5 after published intent");
        assert_eq!(
            disposition,
            AuthenticatedGenesisApplicationInitializationDispositionV0::ResumedBeforeDatabaseCommit
        );
        assert!(!intent_only_marker.exists());
        let capability = store
            .confirmed_authenticated_genesis_application_bootstrap_head_exact_v0(&bootstrap)
            .expect("confirm tag-5 head resumed after intent");
        drop(capability);
        drop(store);

        let precommit_database = directory.path().join("tag5-precommit.sqlite");
        let (precommit_marker, _) = seed_authenticated_genesis_initialization_intent(
            &precommit_database,
            &selected_profile,
            &bootstrap,
            [0xd2; 32],
        );
        seed_empty_initialization_lock(&precommit_database);
        let precommit_file =
            create_new_private_file(&precommit_database, "test create tag-5 precommit database")
                .expect("create tag-5 precommit database");
        precommit_file
            .sync_all()
            .expect("sync tag-5 precommit database");
        drop(precommit_file);
        let (store, disposition) = SqliteSafetyStateStoreV0::
            initialize_or_resume_authenticated_genesis_application_exact_v0(
                &precommit_database,
                selected_profile.clone(),
                RootSignatures,
                &bootstrap,
            )
            .expect("resume tag-5 after main creation before commit");
        assert_eq!(
            disposition,
            AuthenticatedGenesisApplicationInitializationDispositionV0::ResumedBeforeDatabaseCommit
        );
        assert!(!precommit_marker.exists());
        let capability = store
            .confirmed_authenticated_genesis_application_bootstrap_head_exact_v0(&bootstrap)
            .expect("confirm tag-5 head resumed after precommit");
        drop(capability);
        drop(store);

        let committed_database = directory.path().join("tag5-committed-prestable.sqlite");
        let (committed_marker, committed_prepared) =
            seed_authenticated_genesis_initialization_intent(
                &committed_database,
                &selected_profile,
                &bootstrap,
                [0xd3; 32],
            );
        seed_empty_initialization_lock(&committed_database);
        seed_exact_checkpointed_h1_database(
            &committed_database,
            &selected_profile,
            &committed_prepared,
        );
        let (store, disposition) = SqliteSafetyStateStoreV0::
            initialize_or_resume_authenticated_genesis_application_exact_v0(
                &committed_database,
                selected_profile.clone(),
                RootSignatures,
                &bootstrap,
            )
            .expect("resume tag-5 after database commit before Stable");
        assert_eq!(
            disposition,
            AuthenticatedGenesisApplicationInitializationDispositionV0::ResumedAfterDatabaseCommit
        );
        assert!(!committed_marker.exists());
        let capability = store
            .confirmed_authenticated_genesis_application_bootstrap_head_exact_v0(&bootstrap)
            .expect("confirm tag-5 head resumed after commit");
        drop(capability);
        drop(store);

        let stable_database = directory.path().join("tag5-stable-before-retire.sqlite");
        let (stable_marker, stable_prepared) = seed_authenticated_genesis_initialization_intent(
            &stable_database,
            &selected_profile,
            &bootstrap,
            [0xd4; 32],
        );
        let stable_lock_path = seed_empty_initialization_lock(&stable_database);
        seed_exact_checkpointed_h1_database(&stable_database, &selected_profile, &stable_prepared);
        let mut stable_lock =
            open_existing_private_file(&stable_lock_path, "test open tag-5 Stable lock")
                .expect("open tag-5 Stable lock");
        write_lock_watermark(
            &mut stable_lock,
            LockWatermarkV0::Stable {
                sequence: 0,
                journal_id: stable_prepared.intent.journal_id,
                revision: 0,
                chain_checksum: stable_prepared.stored.chain_checksum,
            },
        )
        .expect("write tag-5 Stable before marker retirement");
        drop(stable_lock);
        let (store, disposition) = SqliteSafetyStateStoreV0::
            initialize_or_resume_authenticated_genesis_application_exact_v0(
                &stable_database,
                selected_profile,
                RootSignatures,
                &bootstrap,
            )
            .expect("resume tag-5 after Stable before marker retirement");
        assert_eq!(
            disposition,
            AuthenticatedGenesisApplicationInitializationDispositionV0::ResumedAfterDatabaseCommit
        );
        assert!(!stable_marker.exists());
        let capability = store
            .confirmed_authenticated_genesis_application_bootstrap_head_exact_v0(&bootstrap)
            .expect("confirm tag-5 head resumed after Stable");
        drop(capability);
    }

    #[test]
    fn authenticated_genesis_application_bootstrap_rejects_tag4_and_foreign_profile_v0() {
        let (config, prepared) = authenticated_genesis_bootstrap_fixture();
        let selected_profile = profile(&config);
        let record = prepare_authenticated_genesis_application_bootstrap_record_v0(
            &selected_profile,
            &RootSignatures,
            &prepared,
        )
        .expect("prepare tag-5 record");
        assert!(matches!(
            prepare_h1_state_sync_initialization_v0(
                &selected_profile,
                [0xc1; 32],
                &record,
                SafetyBootstrapInitializationKindV0::StateSyncCheckpoint,
            ),
            Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                "bootstrap initialization kind differs from transition context"
            ))
        ));

        let foreign_profile = SafetyStateStoreProfileV0::new(
            config,
            [0x98; 32],
            selected_profile.record_limits(),
            selected_profile.maximum_database_bytes(),
        )
        .expect("foreign verifier profile");
        let directory = protected_temp_dir();
        assert!(matches!(
            SqliteSafetyStateStoreV0::initialize_authenticated_genesis_application_v0(
                directory.path().join("foreign.sqlite"),
                foreign_profile,
                RootSignatures,
                &prepared,
            ),
            Err(SafetyStoreErrorV0::InvalidProfile(
                "authenticated-genesis application bootstrap/profile mismatch"
            ))
        ));
    }

    #[test]
    fn authenticated_genesis_application_initialization_intent_kind5_vector_is_frozen_v0() {
        use std::fmt::Write as _;

        let path = Path::new("/var/lib/trnm/safety.sqlite");
        let journal_id = [0x31; 32];
        let state_record_checksum = [0x33; 32];
        let transition_context_checksum = [0x34; 32];
        let chain_checksum = chain_checksum(
            journal_id,
            0,
            None,
            None,
            state_record_checksum,
            transition_context_checksum,
        );
        let intent = H1StateSyncInitializationIntentV0 {
            kind: SafetyBootstrapInitializationKindV0::AuthenticatedGenesisApplication,
            journal_id,
            metadata_checksum: [0x32; 32],
            state_record_bytes: 123,
            // Frozen tag-5 transition-context width.
            transition_context_bytes: 219,
            state_record_checksum,
            transition_context_checksum,
            chain_checksum,
            head_checksum: head_checksum(journal_id, 0, chain_checksum, 0),
        };
        let encoded = encode_h1_state_sync_initialization_intent_v0(path, intent)
            .expect("encode authenticated-genesis initialization intent");
        let mut vector = String::with_capacity(encoded.len().saturating_mul(2));
        for byte in encoded {
            write!(&mut vector, "{byte:02x}").expect("write vector");
        }
        assert_eq!(
            vector,
            concat!(
                "54524e4d53494e00",
                "0000",
                "05",
                "0000000000",
                "3131313131313131313131313131313131313131313131313131313131313131",
                "3232323232323232323232323232323232323232323232323232323232323232",
                "000000000000007b",
                "00000000000000db",
                "3333333333333333333333333333333333333333333333333333333333333333",
                "3434343434343434343434343434343434343434343434343434343434343434",
                "a2a58305f11668594ebc81ffefa5e4ff64cdfe0d2d26bbceb720d55133482481",
                "d77dfa18bd556bbb230d720eba84071c873d5935d31d27c4acbc3882d72cd038",
                "e80f4cf5b162b45b005398c68debedfab8434a7c5748dfbff80bfcef7f55c911",
            )
        );
        assert_eq!(
            decode_h1_state_sync_initialization_intent_v0(path, &encoded),
            Some(intent)
        );
    }

    #[derive(Debug)]
    struct ExactSuccessorReconcilerV0 {
        expected_state: SafetyState,
        expected_phase: StateSyncAnchorSuccessorPhaseV0,
        expected_child: SignedProposalV0,
        expected_grandchild: SignedProposalV0,
    }

    impl StateSyncAnchorSuccessorRecoveryReconcilerV0 for ExactSuccessorReconcilerV0 {
        fn reconcile_state_sync_anchor_successors_v0(
            &mut self,
            challenge: &StateSyncAnchorSuccessorRecoveryChallengeV0,
        ) -> bool {
            challenge.safety_state() == &self.expected_state
                && challenge.phase() == self.expected_phase
                && challenge.child() == &self.expected_child
                && challenge.grandchild() == &self.expected_grandchild
        }
    }

    fn activate_successor_replay_v0(
        config: &CoreConfig,
        state: SafetyState,
        child: SignedProposalV0,
        grandchild: SignedProposalV0,
        expected_phase: StateSyncAnchorSuccessorPhaseV0,
    ) -> StateSyncAnchorSuccessorReplayV0 {
        let bundle: H1StateSyncAnchorSuccessorBundleV0 =
            Core::prepare_h1_state_sync_anchor_successor_bundle_v0(
                config,
                &state,
                child.clone(),
                grandchild.clone(),
                &RootSignatures,
            )
            .expect("prepare exact anchored-successor carrier");
        let session = Core::begin_state_sync_anchor_successor_recovery_v0(
            config.clone(),
            state.clone(),
            bundle,
            &RootSignatures,
        )
        .expect("begin stable anchored-successor recovery");
        session
            .reconcile_and_activate_v0(&mut ExactSuccessorReconcilerV0 {
                expected_state: state,
                expected_phase,
                expected_child: child,
                expected_grandchild: grandchild,
            })
            .expect("activate exact anchored-successor owner")
    }

    fn persistence_request_v0(effects: &[Effect]) -> &SafetyStatePersistenceV0 {
        match effects {
            [Effect::PersistSafetyState(request)] => request,
            _ => panic!("expected exactly one Safety persistence effect: {effects:?}"),
        }
    }

    fn validation_request_v0(effects: Vec<Effect>) -> PayloadValidationRequest {
        match effects.as_slice() {
            [Effect::ValidateSyncedPayload(_)] => {}
            _ => panic!("expected exactly one synced validation request: {effects:?}"),
        }
        match effects.into_iter().next() {
            Some(Effect::ValidateSyncedPayload(request)) => request,
            _ => unreachable!(),
        }
    }

    fn valid_commitments_v0(config: &CoreConfig, block: &Block) -> ValidatedBlockCommitmentsV0 {
        let payload = decode_application_payload_v0_exact(
            block.application_payload(),
            config.consensus_parameters(),
        )
        .expect("successor fixture has one exact payload");
        let receipts = ExecutionReceiptsV0::new(
            &payload,
            (0..payload.transaction_count())
                .map(|index| {
                    ExecutionReceiptCommitmentV0::for_transaction(&payload, index, 0, 0, Vec::new())
                        .expect("canonical successor receipt")
                })
                .collect(),
        )
        .expect("canonical successor receipts");
        BlockBodyV0::new(payload, Vec::new())
            .expect("canonical successor body")
            .validate_ordinary_commitments(
                block.header(),
                &receipts,
                config.consensus_parameters(),
                config.validator_set(),
                &RootSignatures,
            )
            .expect("successor fixture commitments")
    }

    fn artifact_ref_v0(block: &Block) -> ValidatedPayloadArtifactRefV0 {
        let mut overlay_checksum = *block.id().as_bytes();
        overlay_checksum[0] ^= 0x5a;
        let mut source_checksum = *block.id().as_bytes();
        source_checksum[0] ^= 0xa5;
        ValidatedPayloadArtifactRefV0::new(
            trnm_consensus_core::BlockIdOverlayRefV0::new(
                block.id(),
                block.header().parent_id(),
                overlay_checksum,
            ),
            source_checksum,
        )
    }

    fn seal_successor_valid_v0(
        config: &CoreConfig,
        authority: &CoreIssuedApplicationSealAuthorityV0,
        request: PayloadValidationRequest,
    ) -> (
        trnm_consensus_core::PayloadValidationRouteV0,
        trnm_consensus_core::ValidationId,
        ApplicationSealedValidV0,
    ) {
        let claimed = request
            .try_claim()
            .unwrap_or_else(|_| panic!("successor request was unexpectedly claimed"));
        let (route, id, block, _parent, permit) = claimed.into_parts();
        let sealed = authority.seal_after_application_store_commit_v0(
            permit,
            valid_commitments_v0(config, &block),
            artifact_ref_v0(&block),
        );
        (route, id, sealed)
    }

    fn successor_native_valid_context_v0(
        request: &SafetyStatePersistenceV0,
        route: trnm_consensus_core::PayloadValidationRouteV0,
        id: trnm_consensus_core::ValidationId,
    ) -> SafetyTransitionContextV0 {
        let state = request.state();
        let completion = state
            .payload_validation_completions()
            .iter()
            .find(|completion| completion.route() == route && completion.id() == id)
            .expect("successor completion is present at the new head");
        let post_ack_action_code = request
            .native_valid_post_ack_action_v0()
            .expect("successor completion binds its inert post-ack action")
            .code();
        SafetyTransitionContextV0::native_valid(
            NativeValidTransitionV0::new(
                route,
                id,
                [0x31; 32],
                [0x32; 32],
                [0x33; 32],
                crate::native_valid_result_checksum_v0(completion.result())
                    .expect("canonical successor Valid result checksum"),
                [0x35; 32],
                [0x36; 32],
                1,
                [0x37; 32],
                [0x38; 32],
                post_ack_action_code,
                state.revision(),
            )
            .expect("canonical successor NativeValid transition"),
        )
    }

    fn profile(config: &CoreConfig) -> SafetyStateStoreProfileV0 {
        SafetyStateStoreProfileV0::new(
            config.clone(),
            [0x71; 32],
            SafetyStateRecordLimitsV0::new(64 * 1024 * 1024, 16 * 1024 * 1024)
                .expect("valid record limits"),
            192 * 1024 * 1024,
        )
        .expect("valid store profile")
    }

    fn protected_temp_dir() -> tempfile::TempDir {
        let directory = tempfile::TempDir::new().expect("temporary directory");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
                .expect("protect temporary directory");
        }
        directory
    }

    fn seed_h1_initialization_intent(
        database_path: &Path,
        selected_profile: &SafetyStateStoreProfileV0,
        bootstrap: &PreparedH1StateSyncBootstrapV0,
        journal_id: [u8; 32],
    ) -> (PathBuf, PreparedH1StateSyncInitializationV0) {
        let database_path = canonical_new_path(database_path).expect("canonical database path");
        let prepared_record =
            prepare_h1_state_sync_bootstrap_record_v0(selected_profile, &RootSignatures, bootstrap)
                .expect("prepare h1 record");
        let prepared = prepare_h1_state_sync_initialization_v0(
            selected_profile,
            journal_id,
            &prepared_record,
            SafetyBootstrapInitializationKindV0::StateSyncCheckpoint,
        )
        .expect("prepare h1 initialization");
        let initialization_path =
            initialization_intent_path_for(&database_path).expect("initialization path");
        let mut initialization_file =
            create_new_private_file(&initialization_path, "test create initialization intent")
                .expect("create initialization intent");
        write_h1_state_sync_initialization_intent_v0(
            &mut initialization_file,
            &initialization_path,
            prepared.intent,
        )
        .expect("persist initialization intent");
        let directory_file = File::open(database_path.parent().expect("database parent"))
            .expect("open database parent");
        sync_directory_handle(&directory_file).expect("sync initialization namespace");
        drop(initialization_file);
        (initialization_path, prepared)
    }

    fn seed_authenticated_genesis_initialization_intent(
        database_path: &Path,
        selected_profile: &SafetyStateStoreProfileV0,
        bootstrap: &PreparedAuthenticatedGenesisApplicationBootstrapV0,
        journal_id: [u8; 32],
    ) -> (PathBuf, PreparedH1StateSyncInitializationV0) {
        let database_path = canonical_new_path(database_path).expect("canonical database path");
        let prepared_record = prepare_authenticated_genesis_application_bootstrap_record_v0(
            selected_profile,
            &RootSignatures,
            bootstrap,
        )
        .expect("prepare authenticated-genesis record");
        let prepared = prepare_h1_state_sync_initialization_v0(
            selected_profile,
            journal_id,
            &prepared_record,
            SafetyBootstrapInitializationKindV0::AuthenticatedGenesisApplication,
        )
        .expect("prepare authenticated-genesis initialization");
        let initialization_path =
            initialization_intent_path_for(&database_path).expect("initialization path");
        let mut initialization_file =
            create_new_private_file(&initialization_path, "test create initialization intent")
                .expect("create initialization intent");
        write_h1_state_sync_initialization_intent_v0(
            &mut initialization_file,
            &initialization_path,
            prepared.intent,
        )
        .expect("persist initialization intent");
        let directory_file = File::open(database_path.parent().expect("database parent"))
            .expect("open database parent");
        sync_directory_handle(&directory_file).expect("sync initialization namespace");
        drop(initialization_file);
        (initialization_path, prepared)
    }

    fn seed_h1_initialization_temporary(
        database_path: &Path,
        selected_profile: &SafetyStateStoreProfileV0,
        bootstrap: &PreparedH1StateSyncBootstrapV0,
        journal_id: [u8; 32],
    ) -> (PathBuf, PathBuf, PreparedH1StateSyncInitializationV0) {
        let database_path = canonical_new_path(database_path).expect("canonical database path");
        let prepared_record =
            prepare_h1_state_sync_bootstrap_record_v0(selected_profile, &RootSignatures, bootstrap)
                .expect("prepare h1 record");
        let prepared = prepare_h1_state_sync_initialization_v0(
            selected_profile,
            journal_id,
            &prepared_record,
            SafetyBootstrapInitializationKindV0::StateSyncCheckpoint,
        )
        .expect("prepare h1 initialization");
        let initialization_path =
            initialization_intent_path_for(&database_path).expect("initialization path");
        let temporary_path = initialization_intent_temporary_path_for(&database_path)
            .expect("temporary initialization path");
        let mut temporary_file =
            create_new_private_file(&temporary_path, "test create initialization temporary")
                .expect("create initialization temporary");
        write_h1_state_sync_initialization_intent_v0(
            &mut temporary_file,
            &initialization_path,
            prepared.intent,
        )
        .expect("persist initialization temporary");
        drop(temporary_file);
        (initialization_path, temporary_path, prepared)
    }

    fn seed_empty_initialization_lock(database_path: &Path) -> PathBuf {
        let lock_path = lock_path_for(database_path).expect("lock path");
        let mut lock_file = create_new_private_file(&lock_path, "test create initialization lock")
            .expect("create initialization lock");
        initialize_lock_file(&mut lock_file).expect("initialize empty lock sidecar");
        drop(lock_file);
        lock_path
    }

    fn install_private_initialization_cut(
        database_path: &Path,
        main_bytes: &[u8],
        wal_bytes: &[u8],
    ) {
        let mut database_file =
            create_new_private_file(database_path, "test install initialization main cut")
                .expect("create initialization main cut");
        database_file
            .write_all(main_bytes)
            .expect("write initialization main cut");
        database_file
            .sync_all()
            .expect("sync initialization main cut");
        drop(database_file);

        let wal_path = sqlite_auxiliary_path(database_path, "-wal");
        let mut wal_file =
            create_new_private_file(&wal_path, "test install initialization WAL cut")
                .expect("create initialization WAL cut");
        wal_file
            .write_all(wal_bytes)
            .expect("write initialization WAL cut");
        wal_file.sync_all().expect("sync initialization WAL cut");
        drop(wal_file);

        let directory_file = File::open(database_path.parent().expect("database parent"))
            .expect("open initialization cut parent");
        sync_directory_handle(&directory_file).expect("sync initialization cut namespace");
    }

    fn capture_real_uncommitted_wal_cut(
        source_database: &Path,
        selected_profile: &SafetyStateStoreProfileV0,
    ) -> (Vec<u8>, Vec<u8>) {
        let source_file =
            create_new_private_file(source_database, "test create uncommitted WAL source")
                .expect("create uncommitted WAL source");
        let connection = Connection::open_with_flags(
            source_database,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .expect("open uncommitted WAL source");
        configure_connection(&connection, true, selected_profile.maximum_database_bytes())
            .expect("configure uncommitted WAL source");
        connection
            .execute_batch(
                "PRAGMA cache_size=1;
                 BEGIN IMMEDIATE;
                 CREATE TABLE uncommitted_initialization_spill_v0(value BLOB NOT NULL);
                 WITH RECURSIVE ordinal(value) AS (
                    VALUES(1) UNION ALL SELECT value + 1 FROM ordinal WHERE value < 128
                 )
                 INSERT INTO uncommitted_initialization_spill_v0(value)
                 SELECT randomblob(4096) FROM ordinal;",
            )
            .expect("spill a real uncommitted WAL transaction");
        assert!(!connection.is_autocommit());
        source_file
            .sync_all()
            .expect("sync uncommitted source main visibility");
        let source_wal = sqlite_auxiliary_path(source_database, "-wal");
        let wal_file = open_existing_private_file(&source_wal, "test pin uncommitted source WAL")
            .expect("pin uncommitted source WAL");
        wal_file
            .sync_all()
            .expect("sync uncommitted source WAL visibility");
        drop(wal_file);
        let main_bytes = fs::read(source_database).expect("capture uncommitted source main");
        let wal_bytes = fs::read(&source_wal).expect("capture uncommitted source WAL");
        assert!(
            wal_bytes.len() > 32,
            "real transaction must spill WAL frames"
        );
        assert_eq!(
            validate_initialization_wal_snapshot_v0(
                &source_wal,
                selected_profile.maximum_database_bytes(),
            )
            .expect("validate real uncommitted WAL"),
            ValidatedInitializationWalV0 {
                contains_commit: false,
            }
        );
        connection
            .execute_batch("ROLLBACK;")
            .expect("rollback source transaction after capturing cut");
        drop(connection);
        drop(source_file);
        (main_bytes, wal_bytes)
    }

    fn replace_wal_header_word_and_checksum_v0(
        header: &[u8],
        offset: usize,
        value: u32,
    ) -> Vec<u8> {
        const WAL_MAGIC_BIG_CHECKSUMS: u32 = 0x377f_0683;
        const WAL_MAGIC_LITTLE_CHECKSUMS: u32 = 0x377f_0682;

        assert_eq!(header.len(), 32, "fixture is one complete WAL header");
        assert!(matches!(offset, 4 | 8), "only version/page size varies");
        let mut rewritten = header.to_vec();
        rewritten[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
        let magic = u32::from_be_bytes(rewritten[0..4].try_into().expect("fixed WAL magic slice"));
        let checksum_big_endian = match magic {
            WAL_MAGIC_BIG_CHECKSUMS => true,
            WAL_MAGIC_LITTLE_CHECKSUMS => false,
            other => panic!("fixture has unsupported WAL magic {other:#x}"),
        };
        let checksum = wal_checksum_v0(checksum_big_endian, (0, 0), &rewritten[..24])
            .expect("recompute rewritten WAL header checksum");
        rewritten[24..28].copy_from_slice(&checksum.0.to_be_bytes());
        rewritten[28..32].copy_from_slice(&checksum.1.to_be_bytes());
        rewritten
    }

    fn capture_live_committed_wal_index_v0(
        source_database: &Path,
        selected_profile: &SafetyStateStoreProfileV0,
    ) -> Vec<u8> {
        let source_file =
            create_new_private_file(source_database, "test create committed SHM source")
                .expect("create committed SHM source");
        let connection = Connection::open_with_flags(
            source_database,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .expect("open committed SHM source");
        configure_connection(&connection, true, selected_profile.maximum_database_bytes())
            .expect("configure committed SHM source");
        connection
            .execute_batch(
                "PRAGMA wal_autocheckpoint=0;
                 BEGIN IMMEDIATE;
                 CREATE TABLE committed_shm_probe_v0(value INTEGER PRIMARY KEY NOT NULL) STRICT;
                 DROP TABLE committed_shm_probe_v0;
                 COMMIT;",
            )
            .expect("commit source transaction represented by SHM");
        let shm_path = sqlite_auxiliary_path(source_database, "-shm");
        let shm_bytes = fs::read(&shm_path).expect("capture live committed wal-index");
        assert!(
            shm_bytes.len() >= 96,
            "live committed wal-index contains both header copies"
        );
        assert_eq!(
            shm_bytes[0..48],
            shm_bytes[48..96],
            "live committed wal-index header copies agree"
        );
        assert_eq!(
            shm_bytes[12], 1,
            "live wal-index first header is initialized"
        );
        assert_eq!(
            shm_bytes[60], 1,
            "live wal-index second header is initialized"
        );
        assert!(
            shm_bytes[16..20].iter().any(|byte| *byte != 0),
            "live committed wal-index advertises at least one frame"
        );
        drop(connection);
        drop(source_file);
        shm_bytes
    }

    fn capture_exact_committed_wal_cut(
        source_database: &Path,
        selected_profile: &SafetyStateStoreProfileV0,
        prepared: &PreparedH1StateSyncInitializationV0,
    ) -> (Vec<u8>, Vec<u8>) {
        let source_file =
            create_new_private_file(source_database, "test create committed WAL source")
                .expect("create committed WAL source");
        let mut connection = Connection::open_with_flags(
            source_database,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .expect("open committed WAL source");
        configure_connection(&connection, true, selected_profile.maximum_database_bytes())
            .expect("configure committed WAL source");
        initialize_schema(
            &mut connection,
            selected_profile,
            prepared.intent.journal_id,
            &prepared.record,
        )
        .expect("commit foreign exact tag-4 WAL source");
        assert!(connection.is_autocommit());
        let source_wal = sqlite_auxiliary_path(source_database, "-wal");
        let wal_file = open_existing_private_file(&source_wal, "test pin committed source WAL")
            .expect("pin committed source WAL");
        wal_file
            .sync_all()
            .expect("sync committed source WAL visibility");
        source_file
            .sync_all()
            .expect("sync committed source main visibility");
        let main_bytes = fs::read(source_database).expect("capture committed source main");
        let wal_bytes = fs::read(&source_wal).expect("capture committed source WAL");
        assert!(wal_bytes.len() > 32, "commit must retain WAL frames");
        assert!(
            validate_initialization_wal_snapshot_v0(
                &source_wal,
                selected_profile.maximum_database_bytes(),
            )
            .expect("validate exact committed WAL")
            .contains_commit
        );
        drop(wal_file);
        drop(connection);
        drop(source_file);
        (main_bytes, wal_bytes)
    }

    fn seed_exact_checkpointed_h1_database(
        database_path: &Path,
        selected_profile: &SafetyStateStoreProfileV0,
        prepared: &PreparedH1StateSyncInitializationV0,
    ) {
        let database_file = create_new_private_file(database_path, "test create h1 database")
            .expect("create h1 database");
        let mut connection = Connection::open_with_flags(
            database_path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .expect("open h1 database");
        configure_connection(&connection, true, selected_profile.maximum_database_bytes())
            .expect("configure h1 database");
        initialize_schema(
            &mut connection,
            selected_profile,
            prepared.intent.journal_id,
            &prepared.record,
        )
        .expect("initialize exact h1 database");
        let directory_file = File::open(database_path.parent().expect("database parent"))
            .expect("open database parent");
        checkpoint_and_sync_initialization(&connection, &database_file, &directory_file)
            .expect("checkpoint exact h1 database");
        drop(connection);
        drop(database_file);
    }

    #[cfg(unix)]
    fn initialization_namespace_snapshot(
        database_path: &Path,
    ) -> Vec<(PathBuf, Option<NamespaceFileSnapshotV0>)> {
        use std::os::unix::fs::MetadataExt;

        let paths = [
            database_path.to_path_buf(),
            sqlite_auxiliary_path(database_path, "-wal"),
            sqlite_auxiliary_path(database_path, "-shm"),
            sqlite_auxiliary_path(database_path, "-journal"),
            lock_path_for(database_path).expect("lock path"),
            initialization_intent_path_for(database_path).expect("published intent path"),
            initialization_intent_temporary_path_for(database_path).expect("temporary intent path"),
        ];
        paths
            .into_iter()
            .map(|path| {
                let snapshot = match fs::symlink_metadata(&path) {
                    Ok(metadata) => Some(NamespaceFileSnapshotV0 {
                        bytes: fs::read(&path).expect("read namespace snapshot component"),
                        device: metadata.dev(),
                        inode: metadata.ino(),
                        mode: metadata.mode(),
                        links: metadata.nlink(),
                    }),
                    Err(error) if error.kind() == io::ErrorKind::NotFound => None,
                    Err(error) => panic!("snapshot {}: {error}", path.display()),
                };
                (path, snapshot)
            })
            .collect()
    }

    fn write_foreign_initialization_auxiliary(database_path: &Path, suffix: &str) {
        let path = sqlite_auxiliary_path(database_path, suffix);
        let mut file =
            create_new_private_file(&path, "test create foreign initialization auxiliary")
                .expect("create foreign initialization auxiliary");
        file.write_all(format!("foreign{suffix}").as_bytes())
            .expect("write foreign initialization auxiliary");
        file.sync_all()
            .expect("sync foreign initialization auxiliary");
    }

    fn rewrite_h1_database_as_historical_v0(
        database_path: &Path,
        metadata_ddl: &str,
        journal_schema: u16,
        safety_schema: u16,
    ) {
        let connection = Connection::open_with_flags(
            database_path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .expect("open h1 database for historical rewrite");
        connection
            .execute_batch(&format!(
                "PRAGMA foreign_keys=OFF;
                 BEGIN IMMEDIATE;
                 ALTER TABLE safety_store_metadata_v0 RENAME TO safety_store_metadata_v6_source;
                 {metadata_ddl}
                 INSERT INTO safety_store_metadata_v0(
                    singleton, journal_schema, journal_id, core_record_codec,
                    safety_schema, core_config_ref, verifier_profile_ref,
                    maximum_record_bytes_be, maximum_blob_bytes_be,
                    maximum_database_bytes_be, transition_codec, metadata_checksum
                 )
                 SELECT singleton, {journal_schema}, journal_id, core_record_codec, {safety_schema},
                    core_config_ref, verifier_profile_ref, maximum_record_bytes_be,
                    maximum_blob_bytes_be, maximum_database_bytes_be,
                    transition_codec, metadata_checksum
                 FROM safety_store_metadata_v6_source;
                 DROP TABLE safety_store_metadata_v6_source;
                 COMMIT;
                 PRAGMA wal_checkpoint(TRUNCATE);"
            ))
            .expect("rewrite h1 database to frozen historical metadata");
        drop(connection);
    }

    #[test]
    fn h1_anchor_successor_tag4_and_tag6_anchor_promotion_sequence_reopens_v0() {
        let (config, bootstrap, _h1, h2, h3) = bootstrap_successor_fixture();
        let directory = protected_temp_dir();
        let database_path = directory.path().join("anchor-successors.sqlite");
        let selected_profile = profile(&config);
        let mut store = SqliteSafetyStateStoreV0::initialize_h1_state_sync_v0(
            &database_path,
            selected_profile.clone(),
            RootSignatures,
            &bootstrap,
        )
        .expect("initialize exact tag-4 anchor");
        let initial = bootstrap.safety_state().clone();
        let mut replay = activate_successor_replay_v0(
            &config,
            initial.clone(),
            h2.clone(),
            h3.clone(),
            StateSyncAnchorSuccessorPhaseV0::H1Bootstrap,
        );
        store
            .bind_core_v0(replay.safety_state_persistence_binding_v0())
            .expect("bind the exact successor replay owner");
        let authority = replay
            .issue_application_seal_authority_v0()
            .expect("issue one private successor seal authority");

        let h2_obligation = replay
            .step_next_proposal_v0(&RootSignatures)
            .expect("register exact h2");
        let h2_obligation_request = persistence_request_v0(&h2_obligation);
        assert_eq!(h2_obligation_request.state().revision(), 1);
        assert_eq!(
            store
                .persist_exact_v0(h2_obligation_request, &SafetyTransitionContextV0::Ordinary)
                .expect("persist h2 obligation"),
            SafetyPersistDispositionV0::Inserted
        );
        let h2_request = validation_request_v0(
            replay
                .step_storage_ack_v0(h2_obligation_request.barrier(), &RootSignatures)
                .expect("ack h2 obligation"),
        );
        let (h2_route, h2_id, h2_sealed) = seal_successor_valid_v0(&config, &authority, h2_request);
        let h2_completion = replay
            .step_application_sealed_valid_v0(&h2_sealed, &RootSignatures)
            .expect("accept h2 Valid");
        let h2_completion_request = persistence_request_v0(&h2_completion);
        assert_eq!(h2_completion_request.state().revision(), 2);
        let h2_context = successor_native_valid_context_v0(h2_completion_request, h2_route, h2_id);
        assert_eq!(
            store
                .persist_exact_v0(h2_completion_request, &h2_context)
                .expect("persist h2 NativeValid"),
            SafetyPersistDispositionV0::Inserted
        );
        assert!(replay
            .step_storage_ack_v0(h2_completion_request.barrier(), &RootSignatures)
            .expect("ack h2 completion")
            .is_empty());

        let h3_obligation = replay
            .step_next_proposal_v0(&RootSignatures)
            .expect("register exact h3");
        let h3_obligation_request = persistence_request_v0(&h3_obligation);
        assert_eq!(h3_obligation_request.state().revision(), 3);
        assert_eq!(
            store
                .persist_exact_v0(h3_obligation_request, &SafetyTransitionContextV0::Ordinary)
                .expect("persist h3 obligation"),
            SafetyPersistDispositionV0::Inserted
        );
        let h3_request = validation_request_v0(
            replay
                .step_storage_ack_v0(h3_obligation_request.barrier(), &RootSignatures)
                .expect("ack h3 obligation"),
        );
        let (h3_route, h3_id, h3_sealed) = seal_successor_valid_v0(&config, &authority, h3_request);
        let h3_completion = replay
            .step_application_sealed_valid_v0(&h3_sealed, &RootSignatures)
            .expect("accept h3 Valid");
        let h3_completion_request = persistence_request_v0(&h3_completion);
        assert_eq!(h3_completion_request.state().revision(), 4);
        let h3_context = successor_native_valid_context_v0(h3_completion_request, h3_route, h3_id);
        assert_eq!(
            store
                .persist_exact_v0(h3_completion_request, &h3_context)
                .expect("persist h3 NativeValid"),
            SafetyPersistDispositionV0::Inserted
        );
        assert!(replay
            .step_storage_ack_v0(h3_completion_request.barrier(), &RootSignatures)
            .expect("ack h3 completion")
            .is_empty());
        let revision_four = replay.safety_state().clone();
        assert_eq!(
            replay.phase().expect("closed successor phase"),
            StateSyncAnchorSuccessorPhaseV0::H3Valid
        );
        let exact_head = store
            .confirmed_native_valid_head_exact_v0(&revision_four, &h3_context)
            .expect("confirm exact h3 NativeValid head");
        assert_eq!(exact_head.revision(), 4);
        drop(exact_head);
        let historical_h2_context = h2_context
            .native_valid_transition()
            .expect("h2 context is NativeValid")
            .clone();
        drop(authority);
        drop(replay);
        drop(store);

        let mut reopened = SqliteSafetyStateStoreV0::open_existing(
            &database_path,
            selected_profile.clone(),
            RootSignatures,
        )
        .expect("reopen rev4 successor journal");
        let reopened_head = reopened
            .confirmed_native_valid_head_exact_v0(&revision_four, &h3_context)
            .expect("authenticate reopened rev4 NativeValid head");
        assert_eq!(reopened_head.revision(), 4);
        let mut recovered = activate_successor_replay_v0(
            &config,
            revision_four.clone(),
            h2.clone(),
            h3.clone(),
            StateSyncAnchorSuccessorPhaseV0::H3Valid,
        );
        let reconstructed_bundle = Core::prepare_h1_state_sync_anchor_successor_bundle_v0(
            &config,
            &revision_four,
            h2,
            h3,
            &RootSignatures,
        )
        .expect("prepare rev4 reconstruction carrier");
        let reconstruction_session = Core::begin_state_sync_anchor_successor_recovery_v0(
            config.clone(),
            revision_four.clone(),
            reconstructed_bundle,
            &RootSignatures,
        )
        .expect("begin rev4 reconstruction challenge");
        let historical = reopened
            .confirm_anchored_successor_h2_transition_from_rev4_v0(
                reconstruction_session.challenge(),
                &historical_h2_context,
            )
            .expect("authenticate pruned h2 NativeValid transition from rev3 predecessor chain");
        assert_eq!(historical.transition_v0(), &historical_h2_context);
        assert_eq!(
            historical.current_state_record_checksum_v0(),
            reopened_head.state_record_checksum()
        );
        assert_ne!(historical.reconstructed_chain_checksum_v0(), [0; 32]);
        assert_ne!(
            historical.reconstructed_state_record_checksum_v0(),
            historical.current_state_record_checksum_v0()
        );
        drop(reopened_head);

        let mut tampered_h2_transition = historical_h2_context.clone();
        tampered_h2_transition.tamper_request_fingerprint_for_test_v0();
        assert!(reopened
            .confirm_anchored_successor_h2_transition_from_rev4_v0(
                reconstruction_session.challenge(),
                &tampered_h2_transition,
            )
            .is_err());
        drop(historical);
        assert_eq!(
            recovered.phase().expect("recovered successor phase"),
            StateSyncAnchorSuccessorPhaseV0::H3Valid
        );
        assert_eq!(recovered.safety_state().finalized(), initial.finalized());
        assert_eq!(
            recovered.safety_state().application_applied(),
            initial.application_applied()
        );

        reopened
            .bind_core_v0(recovered.safety_state_persistence_binding_v0())
            .expect("bind recovered H3Valid owner before promotion");
        let promotion = recovered
            .step_ordinary_promotion_v0(&RootSignatures)
            .expect("prepare exact durable anchored-ordinary promotion");
        let promotion_request = persistence_request_v0(&promotion);
        assert_eq!(promotion_request.state().revision(), 5);
        assert!(promotion_request
            .state_sync_anchor_ordinary_promotion_v0()
            .is_some());
        let promotion_context = reopened
            .state_sync_anchor_ordinary_promotion_context_v0(promotion_request)
            .expect("derive caller-invariant tag-6 context");
        let encoded_promotion = encode_transition_context_v0(&promotion_context)
            .expect("encode canonical tag-6 transition");
        assert_eq!(encoded_promotion.len(), 171);
        assert_eq!(
            decode_transition_context_v0_exact(&encoded_promotion)
                .expect("decode canonical tag-6 transition"),
            promotion_context
        );
        assert!(reopened
            .persist_exact_v0(promotion_request, &SafetyTransitionContextV0::Ordinary)
            .is_err());

        let mut tampered_proof = encoded_promotion.clone();
        tampered_proof[67] ^= 1;
        let tampered_proof = decode_transition_context_v0_exact(&tampered_proof)
            .expect("proof-id tamper remains shape-decodable");
        assert!(reopened
            .persist_exact_v0(promotion_request, &tampered_proof)
            .is_err());

        let mut tampered_revision = encoded_promotion.clone();
        let final_byte = tampered_revision
            .last_mut()
            .expect("tag-6 context is nonempty");
        *final_byte = 4;
        assert!(decode_transition_context_v0_exact(&tampered_revision).is_err());
        assert_eq!(
            reopened
                .persist_exact_v0(promotion_request, &promotion_context)
                .expect("persist exact tag-6 promotion after all rejected probes"),
            SafetyPersistDispositionV0::Inserted
        );
        let promotion_head = reopened.head().expect("authenticate tag-6 head");
        assert_eq!(promotion_head.revision(), 5);
        assert_eq!(promotion_head.state(), promotion_request.state());
        assert_eq!(promotion_head.transition_context(), &promotion_context);
        let activation = recovered
            .acknowledge_ordinary_promotion_v0(promotion_request.barrier(), &RootSignatures)
            .expect("only the durable tag-6 barrier releases ordinary Core");
        assert!(matches!(
            activation.effects(),
            [Effect::ArmViewTimer { .. }]
        ));
        drop(activation);
        drop(reopened);

        let reopened_promoted = SqliteSafetyStateStoreV0::open_existing(
            &database_path,
            selected_profile,
            RootSignatures,
        )
        .expect("reopen exact retained rev4 -> tag-6 rev5 lineage");
        let reopened_head = reopened_promoted
            .head()
            .expect("authenticate promoted head");
        assert_eq!(reopened_head.revision(), 5);
        assert_eq!(reopened_head.transition_context(), &promotion_context);
    }

    #[test]
    fn h1_tag4_cannot_be_prepared_with_authenticated_genesis_application_parent_v0() {
        assert!(matches!(
            try_bootstrap_successor_fixture_with_genesis_parent_v0(true),
            Err(CoreError::InvalidConfig(
                "authenticated genesis application bootstrap and h1 state-sync bootstrap are mutually exclusive"
            ))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn ordinary_preflight_accepts_real_committed_wal_with_torn_tail_without_journal_namespace_mutation_v0(
    ) {
        use std::os::unix::fs::PermissionsExt;

        let (config, bootstrap, _) = bootstrap_fixture();
        let directory = protected_temp_dir();
        let database_path = directory.path().join("ordinary-torn-wal.sqlite");
        let selected_profile = profile(&config);
        let store = SqliteSafetyStateStoreV0::initialize_h1_state_sync_v0(
            &database_path,
            selected_profile.clone(),
            RootSignatures,
            &bootstrap,
        )
        .expect("initialize current journal for ordinary WAL recovery");
        let journal_id = store.journal_id_v0();
        let lock_watermark = store.observed_lock_watermark;
        let halt_latch = store.observed_halt_latch;
        let expected_head = store.head().expect("authenticate expected current head");
        drop(store);

        let checkpointed_main =
            fs::read(&database_path).expect("snapshot checkpointed current main database");
        let shm_path = sqlite_auxiliary_path(&database_path, "-shm");

        let connection = Connection::open_with_flags(
            &database_path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .expect("open ordinary committed-WAL source");
        configure_connection(&connection, true, selected_profile.maximum_database_bytes())
            .expect("configure ordinary committed-WAL source");
        connection
            .execute_batch(
                "PRAGMA wal_autocheckpoint=0;
                 BEGIN IMMEDIATE;
                 CREATE TABLE ordinary_open_torn_tail_probe_v0(
                    value INTEGER PRIMARY KEY NOT NULL
                 ) STRICT;
                 DROP TABLE ordinary_open_torn_tail_probe_v0;
                 COMMIT;",
            )
            .expect("commit semantically inert ordinary WAL transaction");
        assert_eq!(
            fs::read(&database_path).expect("read main after ordinary WAL commit"),
            checkpointed_main,
            "ordinary fixture commit must remain solely in the WAL"
        );
        let wal_path = sqlite_auxiliary_path(&database_path, "-wal");
        let wal_file = open_existing_private_file(&wal_path, "pin ordinary committed-WAL source")
            .expect("pin ordinary committed-WAL source");
        wal_file
            .sync_all()
            .expect("sync ordinary committed-WAL source");
        let committed_prefix_bytes = match recoverable_current_journal_wal_prefix_v0(
            &wal_file,
            selected_profile.maximum_database_bytes(),
        )
        .expect("classify real ordinary committed WAL")
        {
            RecoverableCurrentJournalWalV0::Committed { prefix_bytes } => prefix_bytes,
            other => panic!("real ordinary WAL must contain a commit, got {other:?}"),
        };
        let mut committed_wal = fs::read(&wal_path).expect("capture real ordinary committed WAL");
        let committed_shm = fs::read(&shm_path).expect("capture live committed ordinary wal-index");
        assert!(
            committed_shm.len() >= 96,
            "live ordinary wal-index contains both header copies"
        );
        assert_eq!(committed_shm[0..48], committed_shm[48..96]);
        assert_eq!(committed_shm[12], 1);
        assert_eq!(committed_shm[60], 1);
        assert_eq!(
            usize::try_from(committed_prefix_bytes).expect("committed prefix fits usize"),
            committed_wal.len(),
            "source WAL ends at its checksum-valid commit"
        );
        drop(wal_file);
        drop(connection);

        committed_wal.extend_from_slice(&[0xa5; 17]);
        fs::write(&database_path, &checkpointed_main)
            .expect("restore checkpointed ordinary main database");
        fs::write(&wal_path, &committed_wal).expect("install real committed WAL plus torn tail");
        fs::write(&shm_path, &committed_shm)
            .expect("restore coherent committed ordinary wal-index");
        fs::set_permissions(&wal_path, fs::Permissions::from_mode(0o600))
            .expect("protect restored ordinary WAL");
        fs::set_permissions(&shm_path, fs::Permissions::from_mode(0o600))
            .expect("protect restored ordinary SHM");

        let database_file =
            open_existing_private_file(&database_path, "pin ordinary main for preflight test")
                .expect("pin ordinary main for preflight test");
        let wal_file =
            open_existing_private_file(&wal_path, "pin torn ordinary WAL for preflight test")
                .expect("pin torn ordinary WAL for preflight test");
        let shm_file =
            open_existing_private_file(&shm_path, "pin coherent committed SHM for preflight test")
                .expect("pin coherent committed SHM for preflight test");
        assert_eq!(
            recoverable_current_journal_wal_prefix_v0(
                &wal_file,
                selected_profile.maximum_database_bytes(),
            )
            .expect("classify ordinary WAL with torn tail"),
            RecoverableCurrentJournalWalV0::Committed {
                prefix_bytes: committed_prefix_bytes,
            }
        );
        let namespace_before = initialization_namespace_snapshot(&database_path);
        preflight_current_journal_namespace_v0(
            &database_path,
            &database_file,
            &wal_file,
            &shm_file,
            OrdinaryOpenPreflightFactsV0 {
                profile: &selected_profile,
                verifier: &RootSignatures,
                journal_id,
                lock_watermark,
                halt_latch,
            },
        )
        .expect("preflight real committed WAL through its last commit");
        assert_eq!(
            initialization_namespace_snapshot(&database_path),
            namespace_before,
            "successful preflight changed fixed journal namespace presence, bytes, dev/inode, mode, or nlink"
        );
        drop(shm_file);
        drop(wal_file);
        drop(database_file);

        let reopened = SqliteSafetyStateStoreV0::open_existing(
            &database_path,
            selected_profile,
            RootSignatures,
        )
        .expect("ordinary reopen recovers through committed WAL before torn tail");
        assert_eq!(
            reopened
                .head()
                .expect("authenticate ordinary reopened head through torn WAL"),
            expected_head
        );
    }

    #[cfg(unix)]
    #[test]
    fn ordinary_preflight_ignores_wal_without_authoritative_commit_without_journal_namespace_mutation_v0(
    ) {
        use std::os::unix::fs::PermissionsExt;

        let (config, bootstrap, _) = bootstrap_fixture();
        let directory = protected_temp_dir();
        let selected_profile = profile(&config);
        let source_database = directory.path().join("uncommitted-wal-source.sqlite");
        let (_main, uncommitted_wal) =
            capture_real_uncommitted_wal_cut(&source_database, &selected_profile);
        let coherent_shm = capture_live_committed_wal_index_v0(
            &directory.path().join("foreign-committed-shm-source.sqlite"),
            &selected_profile,
        );
        assert!(
            uncommitted_wal.len() > 32,
            "valid uncommitted source contains a WAL header and frames"
        );
        let valid_header = uncommitted_wal[..32].to_vec();

        let mut invalid_magic = valid_header.clone();
        invalid_magic[0] ^= 0xff;
        let mut invalid_version = valid_header.clone();
        invalid_version[7] ^= 0x01;
        let mut invalid_checksum = valid_header.clone();
        invalid_checksum[31] ^= 0x01;
        let mut torn_first_frame = valid_header.clone();
        torn_first_frame.extend_from_slice(&[0x5a; 17]);
        for (case, wal_bytes) in [
            ("empty", Vec::new()),
            ("partial-header", valid_header[..17].to_vec()),
            ("invalid-magic", invalid_magic),
            ("invalid-version", invalid_version),
            ("invalid-checksum", invalid_checksum),
            ("header-only", valid_header.clone()),
            ("torn-first-frame", torn_first_frame),
            ("valid-uncommitted", uncommitted_wal),
        ] {
            let database_path = directory
                .path()
                .join(format!("ordinary-ignored-wal-{case}.sqlite"));
            let store = SqliteSafetyStateStoreV0::initialize_h1_state_sync_v0(
                &database_path,
                selected_profile.clone(),
                RootSignatures,
                &bootstrap,
            )
            .unwrap_or_else(|error| panic!("initialize current main for {case} WAL: {error}"));
            let journal_id = store.journal_id_v0();
            let lock_watermark = store.observed_lock_watermark;
            let halt_latch = store.observed_halt_latch;
            let expected_head = store
                .head()
                .unwrap_or_else(|error| panic!("authenticate {case} expected head: {error}"));
            drop(store);

            let wal_path = sqlite_auxiliary_path(&database_path, "-wal");
            let shm_path = sqlite_auxiliary_path(&database_path, "-shm");
            fs::write(&wal_path, &wal_bytes).expect("install non-authoritative WAL case");
            fs::write(&shm_path, &coherent_shm)
                .expect("install foreign coherent committed wal-index case");
            fs::set_permissions(&wal_path, fs::Permissions::from_mode(0o600))
                .expect("protect non-authoritative WAL case");
            fs::set_permissions(&shm_path, fs::Permissions::from_mode(0o600))
                .expect("protect foreign coherent committed wal-index case");
            let database_file =
                open_existing_private_file(&database_path, "pin ignored-WAL current main")
                    .expect("pin ignored-WAL current main");
            let wal_file = open_existing_private_file(&wal_path, "pin ignored-WAL case")
                .expect("pin ignored-WAL case");
            let shm_file = open_existing_private_file(
                &shm_path,
                "pin foreign coherent SHM for ignored-WAL case",
            )
            .expect("pin foreign coherent SHM for ignored-WAL case");
            assert_eq!(
                recoverable_current_journal_wal_prefix_v0(
                    &wal_file,
                    selected_profile.maximum_database_bytes(),
                )
                .unwrap_or_else(|error| panic!("classify {case} WAL: {error}")),
                RecoverableCurrentJournalWalV0::NoCommit,
                "{case} WAL has no authoritative committed prefix"
            );
            let namespace_before = initialization_namespace_snapshot(&database_path);
            preflight_current_journal_namespace_v0(
                &database_path,
                &database_file,
                &wal_file,
                &shm_file,
                OrdinaryOpenPreflightFactsV0 {
                    profile: &selected_profile,
                    verifier: &RootSignatures,
                    journal_id,
                    lock_watermark,
                    halt_latch,
                },
            )
            .unwrap_or_else(|error| panic!("preflight {case} WAL against immutable main: {error}"));
            assert_eq!(
                initialization_namespace_snapshot(&database_path),
                namespace_before,
                "successful {case} ignored-WAL preflight changed fixed journal namespace"
            );
            drop(shm_file);
            drop(wal_file);
            drop(database_file);

            let reopened = SqliteSafetyStateStoreV0::open_existing(
                &database_path,
                selected_profile.clone(),
                RootSignatures,
            )
            .unwrap_or_else(|error| panic!("ordinary reopen with ignored {case} WAL: {error}"));
            assert_eq!(
                reopened
                    .head()
                    .unwrap_or_else(|error| panic!("authenticate {case} reopened head: {error}")),
                expected_head,
                "ordinary reopen with ignored {case} WAL changed the authenticated main head"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn ordinary_preflight_rejects_checksum_valid_unsupported_wal_headers_without_namespace_mutation_v0(
    ) {
        use std::os::unix::fs::PermissionsExt;

        let (config, bootstrap, _) = bootstrap_fixture();
        let directory = protected_temp_dir();
        let selected_profile = profile(&config);
        let source_database = directory
            .path()
            .join("unsupported-wal-header-source.sqlite");
        let (_main, uncommitted_wal) =
            capture_real_uncommitted_wal_cut(&source_database, &selected_profile);
        let valid_header = &uncommitted_wal[..32];
        let unsupported_version =
            replace_wal_header_word_and_checksum_v0(valid_header, 4, 3_007_001);
        let unsupported_page_size = replace_wal_header_word_and_checksum_v0(valid_header, 8, 8192);
        let coherent_shm = capture_live_committed_wal_index_v0(
            &directory
                .path()
                .join("unsupported-header-shm-source.sqlite"),
            &selected_profile,
        );

        for (case, wal_bytes, reason) in [
            (
                "version",
                unsupported_version,
                "ordinary-open WAL snapshot format version",
            ),
            (
                "page-size",
                unsupported_page_size,
                "ordinary-open WAL snapshot page size",
            ),
        ] {
            let database_path = directory
                .path()
                .join(format!("ordinary-unsupported-wal-{case}.sqlite"));
            let store = SqliteSafetyStateStoreV0::initialize_h1_state_sync_v0(
                &database_path,
                selected_profile.clone(),
                RootSignatures,
                &bootstrap,
            )
            .unwrap_or_else(|error| panic!("initialize {case} fixture: {error}"));
            drop(store);
            let wal_path = sqlite_auxiliary_path(&database_path, "-wal");
            let shm_path = sqlite_auxiliary_path(&database_path, "-shm");
            fs::write(&wal_path, &wal_bytes)
                .unwrap_or_else(|error| panic!("install {case} WAL header: {error}"));
            fs::write(&shm_path, &coherent_shm)
                .unwrap_or_else(|error| panic!("install {case} coherent SHM: {error}"));
            fs::set_permissions(&wal_path, fs::Permissions::from_mode(0o600))
                .expect("protect unsupported WAL header");
            fs::set_permissions(&shm_path, fs::Permissions::from_mode(0o600))
                .expect("protect unsupported-header SHM");

            let wal_file = open_existing_private_file(&wal_path, "pin unsupported WAL header")
                .expect("pin unsupported WAL header");
            assert_eq!(
                recoverable_current_journal_wal_prefix_v0(
                    &wal_file,
                    selected_profile.maximum_database_bytes(),
                )
                .unwrap_or_else(|error| panic!("classify {case} WAL header: {error}")),
                RecoverableCurrentJournalWalV0::Invalid(reason)
            );
            drop(wal_file);

            let namespace_before = initialization_namespace_snapshot(&database_path);
            let result = SqliteSafetyStateStoreV0::open_existing(
                &database_path,
                selected_profile.clone(),
                RootSignatures,
            );
            let namespace_after = initialization_namespace_snapshot(&database_path);
            assert_eq!(
                namespace_after, namespace_before,
                "rejected checksum-valid unsupported {case} WAL changed fixed namespace"
            );
            let error = match result {
                Ok(_) => panic!("checksum-valid unsupported {case} WAL unexpectedly opened"),
                Err(error) => error,
            };
            assert!(matches!(
                error,
                SafetyStoreErrorV0::PersistedRepresentationMalformed(stored) if stored == reason
            ));
        }
    }

    #[cfg(unix)]
    #[test]
    fn ordinary_preflight_deeply_rejects_tampered_main_across_no_commit_wal_shapes_v0() {
        use std::os::unix::fs::PermissionsExt;

        let (config, bootstrap, _) = bootstrap_fixture();
        let directory = protected_temp_dir();
        let selected_profile = profile(&config);
        let source_database = directory.path().join("deep-no-commit-source.sqlite");
        let (_main, uncommitted_wal) =
            capture_real_uncommitted_wal_cut(&source_database, &selected_profile);
        let valid_header = uncommitted_wal[..32].to_vec();
        let coherent_shm = capture_live_committed_wal_index_v0(
            &directory.path().join("deep-no-commit-shm-source.sqlite"),
            &selected_profile,
        );
        let no_commit_cases = [
            ("empty", Vec::new()),
            ("header-only", valid_header),
            ("valid-uncommitted", uncommitted_wal),
        ];
        let tampers = [
            (
                "metadata",
                "UPDATE safety_store_metadata_v0 SET metadata_checksum=zeroblob(32) WHERE singleton=1",
            ),
            (
                "record",
                "UPDATE safety_state_records_v0 SET transition_context_checksum=zeroblob(32)",
            ),
            (
                "accounting",
                "UPDATE safety_state_accounting_v0 SET state_bytes=state_bytes+1 WHERE singleton=1",
            ),
        ];

        for (tamper, sql) in tampers {
            for (wal_case, wal_bytes) in &no_commit_cases {
                let database_path = directory
                    .path()
                    .join(format!("deep-{tamper}-{wal_case}.sqlite"));
                let store = SqliteSafetyStateStoreV0::initialize_h1_state_sync_v0(
                    &database_path,
                    selected_profile.clone(),
                    RootSignatures,
                    &bootstrap,
                )
                .unwrap_or_else(|error| {
                    panic!("initialize {tamper}/{wal_case} deep-audit fixture: {error}")
                });
                drop(store);

                let connection = Connection::open_with_flags(
                    &database_path,
                    OpenFlags::SQLITE_OPEN_READ_WRITE
                        | OpenFlags::SQLITE_OPEN_NO_MUTEX
                        | OpenFlags::SQLITE_OPEN_NOFOLLOW,
                )
                .expect("open deep-audit main tamper connection");
                enable_persistent_wal(&connection).expect("retain deep-audit auxiliary files");
                assert_eq!(
                    connection.execute(sql, []).unwrap_or_else(|error| {
                        panic!("apply {tamper}/{wal_case} main tamper: {error}")
                    }),
                    1
                );
                connection
                    .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
                    .expect("checkpoint deep-audit main tamper");
                drop(connection);

                let wal_path = sqlite_auxiliary_path(&database_path, "-wal");
                let shm_path = sqlite_auxiliary_path(&database_path, "-shm");
                fs::write(&wal_path, wal_bytes).expect("install no-commit WAL shape");
                fs::write(&shm_path, &coherent_shm)
                    .expect("install coherent foreign SHM for deep rejection");
                fs::set_permissions(&wal_path, fs::Permissions::from_mode(0o600))
                    .expect("protect deep-audit WAL");
                fs::set_permissions(&shm_path, fs::Permissions::from_mode(0o600))
                    .expect("protect deep-audit SHM");

                let wal_file = open_existing_private_file(&wal_path, "pin no-commit WAL shape")
                    .expect("pin no-commit WAL shape");
                assert_eq!(
                    recoverable_current_journal_wal_prefix_v0(
                        &wal_file,
                        selected_profile.maximum_database_bytes(),
                    )
                    .unwrap_or_else(|error| {
                        panic!("classify {tamper}/{wal_case} WAL: {error}")
                    }),
                    RecoverableCurrentJournalWalV0::NoCommit
                );
                drop(wal_file);

                let namespace_before = initialization_namespace_snapshot(&database_path);
                let result = SqliteSafetyStateStoreV0::open_existing(
                    &database_path,
                    selected_profile.clone(),
                    RootSignatures,
                );
                let namespace_after = initialization_namespace_snapshot(&database_path);
                assert_eq!(
                    namespace_after, namespace_before,
                    "rejected {tamper}/{wal_case} journal changed fixed namespace"
                );
                let error = match result {
                    Ok(_) => panic!("tampered {tamper}/{wal_case} journal unexpectedly opened"),
                    Err(error) => error,
                };
                match tamper {
                    "metadata" => assert!(matches!(error, SafetyStoreErrorV0::MetadataMismatch)),
                    "record" => assert!(matches!(
                        error,
                        SafetyStoreErrorV0::PersistedRepresentationMalformed(
                            "record-chain checksum"
                        )
                    )),
                    "accounting" => assert!(matches!(
                        error,
                        SafetyStoreErrorV0::PersistedRepresentationMalformed(
                            "safety-store accounting mismatch"
                        )
                    )),
                    _ => unreachable!("fixed tamper matrix"),
                }
            }
        }
    }

    #[test]
    fn h1_state_sync_bootstrap_initializes_reopens_and_detects_context_tamper() {
        let (config, bootstrap, h1) = bootstrap_fixture();
        let directory = protected_temp_dir();
        let database_path = directory.path().join("safety.sqlite");
        let generic_path = directory.path().join("generic.sqlite");

        assert!(SqliteSafetyStateStoreV0::initialize_new(
            &generic_path,
            profile(&config),
            RootSignatures,
            bootstrap.safety_state(),
        )
        .is_err());
        assert!(!generic_path.exists());

        let store = SqliteSafetyStateStoreV0::initialize_h1_state_sync_v0(
            &database_path,
            profile(&config),
            RootSignatures,
            &bootstrap,
        )
        .expect("initialize anchored journal v6");
        let confirmed = store
            .confirmed_state_sync_checkpoint_bootstrap_head_exact_v0(bootstrap.safety_state())
            .expect("exact tag-4 readback");
        assert_eq!(confirmed.revision(), 0);
        assert_eq!(confirmed.transition().target_block_id(), h1.id());
        assert_eq!(confirmed.transition().target_state_root(), h1.state_root());
        assert_eq!(
            confirmed.transition().state_record_checksum(),
            confirmed.state_record_checksum()
        );
        let node_checkpoint_facts = store
            .confirm_node_checkpoint_head_exact_v0(bootstrap.safety_state())
            .expect("project exact h1 Safety node-checkpoint facts");
        assert_eq!(node_checkpoint_facts.journal_id_v0(), store.journal_id_v0());
        assert_eq!(
            node_checkpoint_facts.verifier_profile_ref_v0(),
            store.verifier_profile_ref_v0()
        );
        assert_eq!(node_checkpoint_facts.revision_v0(), confirmed.revision());
        assert_eq!(
            node_checkpoint_facts.state_record_checksum_v0(),
            confirmed.state_record_checksum()
        );
        assert_eq!(
            node_checkpoint_facts.chain_checksum_v0(),
            confirmed.chain_checksum()
        );
        drop(node_checkpoint_facts);
        drop(confirmed);
        drop(store);

        let reopened = SqliteSafetyStateStoreV0::open_existing(
            &database_path,
            profile(&config),
            RootSignatures,
        )
        .expect("reopen anchored journal v6");
        let reopened_confirmation = reopened
            .confirmed_state_sync_checkpoint_bootstrap_head_exact_v0(bootstrap.safety_state())
            .expect("exact reopened tag-4 readback");
        drop(reopened_confirmation);
        drop(reopened);

        let connection = Connection::open(&database_path).expect("open tamper connection");
        connection
            .execute(
                "UPDATE safety_state_records_v0
                 SET transition_context_bytes=zeroblob(length(transition_context_bytes))
                 WHERE revision_be=?1",
                [0u64.to_be_bytes().as_slice()],
            )
            .expect("tamper tag-4 bytes");
        drop(connection);
        assert!(SqliteSafetyStateStoreV0::open_existing(
            &database_path,
            profile(&config),
            RootSignatures,
        )
        .is_err());
    }

    #[test]
    fn h1_initialization_resumes_exactly_after_durable_intent_before_database() {
        let (config, bootstrap, _) = bootstrap_fixture();
        let directory = protected_temp_dir();
        let database_path = directory.path().join("after-intent.sqlite");
        let selected_profile = profile(&config);
        let (initialization_path, _) = seed_h1_initialization_intent(
            &database_path,
            &selected_profile,
            &bootstrap,
            [0x91; 32],
        );

        let (store, disposition) =
            SqliteSafetyStateStoreV0::initialize_or_resume_h1_state_sync_exact_v0(
                &database_path,
                selected_profile,
                RootSignatures,
                &bootstrap,
            )
            .expect("resume exact durable intent");
        assert_eq!(
            disposition,
            StateSyncCheckpointInitializationDispositionV0::ResumedBeforeDatabaseCommit
        );
        assert!(!initialization_path.exists());
        let confirmation = store
            .confirmed_state_sync_checkpoint_bootstrap_head_exact_v0(bootstrap.safety_state())
            .expect("exact resumed tag-4 head");
        drop(confirmation);
    }

    #[test]
    fn h1_initialization_atomically_publishes_exact_and_rewrites_partial_temporary() {
        let (config, bootstrap, _) = bootstrap_fixture();
        let directory = protected_temp_dir();
        let selected_profile = profile(&config);
        let database_path = directory.path().join("temporary-publish.sqlite");
        let (initialization_path, temporary_path, _) = seed_h1_initialization_temporary(
            &database_path,
            &selected_profile,
            &bootstrap,
            [0x95; 32],
        );
        let (store, disposition) =
            SqliteSafetyStateStoreV0::initialize_or_resume_h1_state_sync_exact_v0(
                &database_path,
                selected_profile.clone(),
                RootSignatures,
                &bootstrap,
            )
            .expect("publish and resume exact temporary intent");
        assert_eq!(
            disposition,
            StateSyncCheckpointInitializationDispositionV0::ResumedBeforeDatabaseCommit
        );
        assert!(!temporary_path.exists());
        assert!(!initialization_path.exists());
        drop(store);

        let partial_database = directory.path().join("partial-temporary.sqlite");
        let partial_temporary =
            initialization_intent_temporary_path_for(&partial_database).expect("temporary path");
        let mut partial =
            create_new_private_file(&partial_temporary, "test create partial temporary")
                .expect("create partial temporary");
        partial.write_all(b"partial").expect("write partial intent");
        partial.sync_all().expect("sync partial intent");
        drop(partial);
        let (store, disposition) =
            SqliteSafetyStateStoreV0::initialize_or_resume_h1_state_sync_exact_v0(
                &partial_database,
                selected_profile,
                RootSignatures,
                &bootstrap,
            )
            .expect("rewrite and publish partial unpublished temporary");
        assert_eq!(
            disposition,
            StateSyncCheckpointInitializationDispositionV0::ResumedBeforeDatabaseCommit
        );
        assert!(!partial_temporary.exists());
        assert!(!initialization_intent_path_for(&partial_database)
            .expect("partial published path")
            .exists());
        drop(store);
    }

    #[test]
    fn h1_initialization_recovers_owned_partial_lock_and_database_created_precommit() {
        let (config, bootstrap, _) = bootstrap_fixture();
        let directory = protected_temp_dir();
        let selected_profile = profile(&config);

        let partial_lock_database = directory.path().join("partial-lock.sqlite");
        seed_h1_initialization_intent(
            &partial_lock_database,
            &selected_profile,
            &bootstrap,
            [0x96; 32],
        );
        let partial_lock_path = lock_path_for(&partial_lock_database).expect("partial lock path");
        let partial_lock = create_new_private_file(&partial_lock_path, "test create partial lock")
            .expect("create partial lock");
        partial_lock.set_len(4096).expect("allocate partial lock");
        partial_lock.sync_all().expect("sync partial lock");
        drop(partial_lock);
        let (store, disposition) =
            SqliteSafetyStateStoreV0::initialize_or_resume_h1_state_sync_exact_v0(
                &partial_lock_database,
                selected_profile.clone(),
                RootSignatures,
                &bootstrap,
            )
            .expect("recover exact owned partial lock");
        assert_eq!(
            disposition,
            StateSyncCheckpointInitializationDispositionV0::ResumedBeforeDatabaseCommit
        );
        drop(store);

        let precommit_database = directory.path().join("database-precommit.sqlite");
        seed_h1_initialization_intent(
            &precommit_database,
            &selected_profile,
            &bootstrap,
            [0x97; 32],
        );
        seed_empty_initialization_lock(&precommit_database);
        let database_file =
            create_new_private_file(&precommit_database, "test create precommit database")
                .expect("create precommit database");
        database_file.sync_all().expect("sync precommit database");
        drop(database_file);
        let (store, disposition) =
            SqliteSafetyStateStoreV0::initialize_or_resume_h1_state_sync_exact_v0(
                &precommit_database,
                selected_profile,
                RootSignatures,
                &bootstrap,
            )
            .expect("resume database-created precommit");
        assert_eq!(
            disposition,
            StateSyncCheckpointInitializationDispositionV0::ResumedBeforeDatabaseCommit
        );
        drop(store);
    }

    #[test]
    fn h1_initialization_resumes_real_nonzero_uncommitted_wal_as_precommit() {
        let (config, bootstrap, _) = bootstrap_fixture();
        let directory = protected_temp_dir();
        let selected_profile = profile(&config);
        let source_database = directory.path().join("uncommitted-source.sqlite");
        let (main_bytes, wal_bytes) =
            capture_real_uncommitted_wal_cut(&source_database, &selected_profile);

        let database_path = directory.path().join("uncommitted-cut.sqlite");
        let (initialization_path, _) = seed_h1_initialization_intent(
            &database_path,
            &selected_profile,
            &bootstrap,
            [0x9b; 32],
        );
        seed_empty_initialization_lock(&database_path);
        install_private_initialization_cut(&database_path, &main_bytes, &wal_bytes);
        assert!(
            fs::metadata(sqlite_auxiliary_path(&database_path, "-wal"))
                .expect("stat installed uncommitted WAL")
                .len()
                > 32
        );

        let (store, disposition) =
            SqliteSafetyStateStoreV0::initialize_or_resume_h1_state_sync_exact_v0(
                &database_path,
                selected_profile,
                RootSignatures,
                &bootstrap,
            )
            .expect("resume a canonical precommit with ignored uncommitted WAL frames");
        assert_eq!(
            disposition,
            StateSyncCheckpointInitializationDispositionV0::ResumedBeforeDatabaseCommit
        );
        assert!(!initialization_path.exists());
        let confirmation = store
            .confirmed_state_sync_checkpoint_bootstrap_head_exact_v0(bootstrap.safety_state())
            .expect("exact tag-4 head after resuming uncommitted WAL cut");
        drop(confirmation);
        drop(store);
    }

    #[test]
    #[cfg(unix)]
    fn h1_initialization_rejects_foreign_garbage_and_truncated_wal_without_namespace_mutation() {
        let (config, bootstrap, _) = bootstrap_fixture();
        let directory = protected_temp_dir();
        let selected_profile = profile(&config);
        let uncommitted_source = directory.path().join("negative-uncommitted-source.sqlite");
        let (canonical_main, uncommitted_wal) =
            capture_real_uncommitted_wal_cut(&uncommitted_source, &selected_profile);

        let foreign_source = directory.path().join("negative-foreign-source.sqlite");
        let prepared_record = prepare_h1_state_sync_bootstrap_record_v0(
            &selected_profile,
            &RootSignatures,
            &bootstrap,
        )
        .expect("prepare foreign committed WAL record");
        let foreign_prepared = prepare_h1_state_sync_initialization_v0(
            &selected_profile,
            [0xee; 32],
            &prepared_record,
            SafetyBootstrapInitializationKindV0::StateSyncCheckpoint,
        )
        .expect("prepare foreign committed WAL bundle");
        let (foreign_main, foreign_wal) =
            capture_exact_committed_wal_cut(&foreign_source, &selected_profile, &foreign_prepared);
        assert_eq!(
            foreign_main, canonical_main,
            "both WAL cuts must share the same canonical empty main prestate"
        );

        let mut truncated_wal = uncommitted_wal.clone();
        truncated_wal
            .pop()
            .expect("real WAL has a byte to truncate");
        let cases: [(&str, &[u8]); 3] = [
            ("foreign", &foreign_wal),
            ("garbage", b"not-a-sqlite-wal-snapshot"),
            ("truncated", &truncated_wal),
        ];
        for (ordinal, (name, wal_bytes)) in cases.into_iter().enumerate() {
            let database_path = directory.path().join(format!("{name}-wal.sqlite"));
            seed_h1_initialization_intent(
                &database_path,
                &selected_profile,
                &bootstrap,
                [0xb0 + u8::try_from(ordinal).expect("small ordinal"); 32],
            );
            seed_empty_initialization_lock(&database_path);
            install_private_initialization_cut(&database_path, &canonical_main, wal_bytes);
            let before = initialization_namespace_snapshot(&database_path);

            assert!(
                SqliteSafetyStateStoreV0::initialize_or_resume_h1_state_sync_exact_v0(
                    &database_path,
                    selected_profile.clone(),
                    RootSignatures,
                    &bootstrap,
                )
                .is_err(),
                "{name} WAL must fail closed"
            );
            assert_eq!(
                initialization_namespace_snapshot(&database_path),
                before,
                "{name} WAL rejection changed bytes, dev/inode, mode, nlink, or presence"
            );
        }
    }

    #[test]
    fn h1_initialization_reconstructs_missing_auxiliaries_and_torn_initial_stable() {
        let (config, bootstrap, _) = bootstrap_fixture();
        let directory = protected_temp_dir();
        let database_path = directory.path().join("torn-stable.sqlite");
        let selected_profile = profile(&config);
        let (_, prepared) = seed_h1_initialization_intent(
            &database_path,
            &selected_profile,
            &bootstrap,
            [0x98; 32],
        );
        let lock_path = seed_empty_initialization_lock(&database_path);
        seed_exact_checkpointed_h1_database(&database_path, &selected_profile, &prepared);
        for suffix in ["-wal", "-shm"] {
            let path = sqlite_auxiliary_path(&database_path, suffix);
            if path.exists() {
                fs::remove_file(path).expect("remove reconstructible auxiliary");
            }
        }
        let expected_stable = LockWatermarkV0::Stable {
            sequence: 0,
            journal_id: prepared.intent.journal_id,
            revision: 0,
            chain_checksum: prepared.stored.chain_checksum,
        };
        let encoded = encode_lock_slot(expected_stable).expect("encode expected Stable");
        let mut lock_file = open_existing_private_file(&lock_path, "test open torn Stable")
            .expect("open torn Stable");
        lock_file
            .write_all(&encoded[..97])
            .expect("write torn Stable prefix");
        lock_file.sync_all().expect("sync torn Stable");
        drop(lock_file);

        let (store, disposition) =
            SqliteSafetyStateStoreV0::initialize_or_resume_h1_state_sync_exact_v0(
                &database_path,
                selected_profile,
                RootSignatures,
                &bootstrap,
            )
            .expect("reconstruct auxiliaries and exact Stable");
        assert_eq!(
            disposition,
            StateSyncCheckpointInitializationDispositionV0::ResumedAfterDatabaseCommit
        );
        assert_eq!(
            read_exact_initialization_lock_state_v0(&store.lock_file)
                .expect("read repaired Stable"),
            InitializationLockStateV0::Stable(expected_stable)
        );
        drop(store);
    }

    #[test]
    fn h1_initialization_resumes_exact_committed_database_before_stable() {
        let (config, bootstrap, _) = bootstrap_fixture();
        let directory = protected_temp_dir();
        let database_path = directory.path().join("postcommit-prestable.sqlite");
        let selected_profile = profile(&config);
        let (initialization_path, prepared) = seed_h1_initialization_intent(
            &database_path,
            &selected_profile,
            &bootstrap,
            [0x92; 32],
        );
        let lock_path = lock_path_for(&database_path).expect("lock path");
        let mut lock_file = create_new_private_file(&lock_path, "test create initialization lock")
            .expect("create initialization lock");
        initialize_lock_file(&mut lock_file).expect("initialize empty lock sidecar");
        let database_file = create_new_private_file(&database_path, "test create database")
            .expect("create initialization database");
        let mut connection = Connection::open_with_flags(
            &database_path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .expect("open initialization database");
        configure_connection(&connection, true, selected_profile.maximum_database_bytes())
            .expect("configure initialization database");
        initialize_schema(
            &mut connection,
            &selected_profile,
            prepared.intent.journal_id,
            &prepared.record,
        )
        .expect("commit exact revision-zero tag-4 database");
        materialize_sqlite_auxiliary_files(&connection).expect("retain WAL/SHM namespace");
        let directory_file = File::open(directory.path()).expect("open test parent");
        sync_directory_handle(&directory_file).expect("sync committed database namespace");
        drop(connection);
        drop(database_file);
        drop(lock_file);

        let (store, disposition) =
            SqliteSafetyStateStoreV0::initialize_or_resume_h1_state_sync_exact_v0(
                &database_path,
                selected_profile,
                RootSignatures,
                &bootstrap,
            )
            .expect("resolve committed database to exact Stable");
        assert_eq!(
            disposition,
            StateSyncCheckpointInitializationDispositionV0::ResumedAfterDatabaseCommit
        );
        assert!(!initialization_path.exists());
        let confirmation = store
            .confirmed_state_sync_checkpoint_bootstrap_head_exact_v0(bootstrap.safety_state())
            .expect("exact postcommit tag-4 head");
        drop(confirmation);
    }

    #[test]
    #[cfg(unix)]
    fn h1_initialization_rejects_auxiliaries_without_main_before_any_namespace_change() {
        let (config, bootstrap, _) = bootstrap_fixture();
        let directory = protected_temp_dir();
        let selected_profile = profile(&config);
        let combinations: [(&str, &[&str]); 3] = [
            ("wal-only", &["-wal"]),
            ("shm-only", &["-shm"]),
            ("wal-and-shm", &["-wal", "-shm"]),
        ];

        for (ordinal, (name, suffixes)) in combinations.into_iter().enumerate() {
            let database_path = directory.path().join(format!("{name}.sqlite"));
            seed_h1_initialization_intent(
                &database_path,
                &selected_profile,
                &bootstrap,
                [0xa0 + u8::try_from(ordinal).expect("small ordinal"); 32],
            );
            seed_empty_initialization_lock(&database_path);
            for suffix in suffixes {
                write_foreign_initialization_auxiliary(&database_path, suffix);
            }
            let directory_file = File::open(directory.path()).expect("open test parent");
            sync_directory_handle(&directory_file).expect("sync foreign auxiliary namespace");
            let before = initialization_namespace_snapshot(&database_path);

            assert!(matches!(
                SqliteSafetyStateStoreV0::initialize_or_resume_h1_state_sync_exact_v0(
                    &database_path,
                    selected_profile.clone(),
                    RootSignatures,
                    &bootstrap,
                ),
                Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                    "h1 initialization has SQLite auxiliary state without main database"
                ))
            ));
            assert_eq!(
                initialization_namespace_snapshot(&database_path),
                before,
                "{name} rejection changed bytes, dev/inode, mode, nlink, or presence"
            );
            assert!(
                !database_path.exists(),
                "{name} rejection must occur before SQLite can create the main database"
            );

            for suffix in suffixes {
                fs::remove_file(sqlite_auxiliary_path(&database_path, suffix))
                    .expect("remove test-owned foreign auxiliary");
            }
            sync_directory_handle(&directory_file).expect("sync cleaned test namespace");
            let (store, disposition) =
                SqliteSafetyStateStoreV0::initialize_or_resume_h1_state_sync_exact_v0(
                    &database_path,
                    selected_profile.clone(),
                    RootSignatures,
                    &bootstrap,
                )
                .expect("exact marker resumes after operator removes foreign auxiliaries");
            assert_eq!(
                disposition,
                StateSyncCheckpointInitializationDispositionV0::ResumedBeforeDatabaseCommit
            );
            drop(store);
        }
    }

    #[test]
    #[cfg(unix)]
    fn h1_initialization_resume_rejects_marker_bound_historical_journals_without_mutation() {
        let (config, bootstrap, _) = bootstrap_fixture();
        let directory = protected_temp_dir();
        let selected_profile = profile(&config);
        for (name, metadata_ddl, journal_schema, safety_schema) in [
            ("v5-schema11", HISTORICAL_JOURNAL_V5_METADATA_DDL, 5, 11),
            ("v4-schema10", HISTORICAL_JOURNAL_V4_METADATA_DDL, 4, 10),
        ] {
            let database_path = directory.path().join(format!("marker-bound-{name}.sqlite"));
            let store = SqliteSafetyStateStoreV0::initialize_h1_state_sync_v0(
                &database_path,
                selected_profile.clone(),
                RootSignatures,
                &bootstrap,
            )
            .expect("initialize source journal v6");
            let journal_id = store.journal_id_v0();
            drop(store);
            rewrite_h1_database_as_historical_v0(
                &database_path,
                metadata_ddl,
                journal_schema,
                safety_schema,
            );
            seed_h1_initialization_intent(
                &database_path,
                &selected_profile,
                &bootstrap,
                journal_id,
            );
            let before = initialization_namespace_snapshot(&database_path);

            assert!(matches!(
                SqliteSafetyStateStoreV0::initialize_or_resume_h1_state_sync_exact_v0(
                    &database_path,
                    selected_profile.clone(),
                    RootSignatures,
                    &bootstrap,
                ),
                Err(SafetyStoreErrorV0::SchemaMismatch)
            ));
            assert_eq!(
                initialization_namespace_snapshot(&database_path),
                before,
                "marker-bound {name} rejection changed bytes, dev/inode, mode, nlink, or presence"
            );
        }
    }

    #[test]
    fn h1_initialization_tamper_and_foreign_profile_fail_without_namespace_mutation() {
        let (config, bootstrap, _) = bootstrap_fixture();
        let directory = protected_temp_dir();
        let tampered_database = directory.path().join("tampered-intent.sqlite");
        let selected_profile = profile(&config);
        let (tampered_intent, _) = seed_h1_initialization_intent(
            &tampered_database,
            &selected_profile,
            &bootstrap,
            [0x93; 32],
        );
        let mut tampered_bytes = fs::read(&tampered_intent).expect("read initialization intent");
        tampered_bytes[100] ^= 1;
        fs::write(&tampered_intent, &tampered_bytes).expect("tamper initialization intent");
        File::open(&tampered_intent)
            .expect("open tampered intent")
            .sync_all()
            .expect("sync tampered intent");
        let before_tamper = fs::read(&tampered_intent).expect("snapshot tampered intent");
        assert!(
            SqliteSafetyStateStoreV0::initialize_or_resume_h1_state_sync_exact_v0(
                &tampered_database,
                selected_profile,
                RootSignatures,
                &bootstrap,
            )
            .is_err()
        );
        assert_eq!(
            fs::read(&tampered_intent).expect("read unchanged tampered intent"),
            before_tamper
        );
        assert!(!tampered_database.exists());
        assert!(!lock_path_for(&tampered_database)
            .expect("tampered lock path")
            .exists());

        let foreign_database = directory.path().join("foreign-profile.sqlite");
        let original_profile = profile(&config);
        let (foreign_intent, _) = seed_h1_initialization_intent(
            &foreign_database,
            &original_profile,
            &bootstrap,
            [0x94; 32],
        );
        let foreign_before = fs::read(&foreign_intent).expect("snapshot foreign intent");
        let foreign_profile = SafetyStateStoreProfileV0::new(
            config,
            [0x72; 32],
            original_profile.record_limits(),
            original_profile.maximum_database_bytes(),
        )
        .expect("foreign profile");
        assert!(matches!(
            SqliteSafetyStateStoreV0::initialize_or_resume_h1_state_sync_exact_v0(
                &foreign_database,
                foreign_profile,
                RootSignatures,
                &bootstrap,
            ),
            Err(SafetyStoreErrorV0::StateSyncInitializationIntentMismatch)
        ));
        assert_eq!(
            fs::read(&foreign_intent).expect("read unchanged foreign intent"),
            foreign_before
        );
        assert!(!foreign_database.exists());
        assert!(!lock_path_for(&foreign_database)
            .expect("foreign lock path")
            .exists());
    }

    #[test]
    fn h1_initialization_marker_gates_ordinary_open_and_foreign_main_is_immutable() {
        let (config, bootstrap, _) = bootstrap_fixture();
        let directory = protected_temp_dir();
        let selected_profile = profile(&config);
        let database_path = directory.path().join("foreign-main.sqlite");
        let (initialization_path, _) = seed_h1_initialization_intent(
            &database_path,
            &selected_profile,
            &bootstrap,
            [0x99; 32],
        );
        let lock_path = seed_empty_initialization_lock(&database_path);
        let database_file = create_new_private_file(&database_path, "test create foreign main")
            .expect("create foreign main");
        let connection = Connection::open_with_flags(
            &database_path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .expect("open foreign main");
        connection
            .execute_batch("PRAGMA page_size=4096; CREATE TABLE foreign_v4_shape(value BLOB);")
            .expect("install foreign schema");
        drop(connection);
        database_file.sync_all().expect("sync foreign main");
        drop(database_file);
        let before_database = fs::read(&database_path).expect("snapshot foreign main");
        let before_marker = fs::read(&initialization_path).expect("snapshot marker");
        let before_lock = fs::read(&lock_path).expect("snapshot lock");

        assert!(matches!(
            SqliteSafetyStateStoreV0::open_existing(
                &database_path,
                selected_profile.clone(),
                RootSignatures,
            ),
            Err(SafetyStoreErrorV0::StateSyncInitializationPending)
        ));
        assert!(
            SqliteSafetyStateStoreV0::initialize_or_resume_h1_state_sync_exact_v0(
                &database_path,
                selected_profile,
                RootSignatures,
                &bootstrap,
            )
            .is_err()
        );
        assert_eq!(
            fs::read(&database_path).expect("read unchanged foreign main"),
            before_database
        );
        assert_eq!(
            fs::read(&initialization_path).expect("read unchanged marker"),
            before_marker
        );
        assert_eq!(
            fs::read(&lock_path).expect("read unchanged lock"),
            before_lock
        );
        assert!(!sqlite_auxiliary_path(&database_path, "-shm").exists());
    }

    #[test]
    #[cfg(unix)]
    fn h1_initialization_rejects_marker_symlink_mode_and_inode_swap_without_deletion() {
        use std::os::unix::fs::PermissionsExt;

        let (config, bootstrap, _) = bootstrap_fixture();
        let directory = protected_temp_dir();
        let selected_profile = profile(&config);

        let mode_database = directory.path().join("marker-mode.sqlite");
        let (mode_marker, _) = seed_h1_initialization_intent(
            &mode_database,
            &selected_profile,
            &bootstrap,
            [0x9a; 32],
        );
        fs::set_permissions(&mode_marker, fs::Permissions::from_mode(0o640))
            .expect("make marker mode noncanonical");
        let mode_before = fs::read(&mode_marker).expect("snapshot mode marker");
        assert!(
            SqliteSafetyStateStoreV0::initialize_or_resume_h1_state_sync_exact_v0(
                &mode_database,
                selected_profile.clone(),
                RootSignatures,
                &bootstrap,
            )
            .is_err()
        );
        assert_eq!(
            fs::read(&mode_marker).expect("read unchanged mode marker"),
            mode_before
        );
        assert!(!mode_database.exists());

        let symlink_database = directory.path().join("marker-symlink.sqlite");
        let symlink_marker =
            initialization_intent_path_for(&symlink_database).expect("symlink marker path");
        std::os::unix::fs::symlink(&mode_marker, &symlink_marker).expect("create marker symlink");
        assert!(
            SqliteSafetyStateStoreV0::initialize_or_resume_h1_state_sync_exact_v0(
                &symlink_database,
                selected_profile.clone(),
                RootSignatures,
                &bootstrap,
            )
            .is_err()
        );
        assert!(fs::symlink_metadata(&symlink_marker)
            .expect("marker symlink remains")
            .file_type()
            .is_symlink());
        assert!(!symlink_database.exists());

        fs::set_permissions(&mode_marker, fs::Permissions::from_mode(0o600))
            .expect("restore exact marker mode");
        let marker_file =
            open_existing_private_file(&mode_marker, "test pin marker before inode swap")
                .expect("pin marker before inode swap");
        let old_identity = file_handle_identity(&marker_file, &mode_marker).expect("old identity");
        let old_path = directory.path().join("old-marker-inode");
        fs::rename(&mode_marker, &old_path).expect("move pinned marker inode");
        fs::copy(&old_path, &mode_marker).expect("install replacement marker inode");
        fs::set_permissions(&mode_marker, fs::Permissions::from_mode(0o600))
            .expect("protect replacement marker");
        let replacement_before = fs::read(&mode_marker).expect("snapshot replacement marker");
        let directory_file = File::open(directory.path()).expect("open marker parent");
        let prepared_record = prepare_h1_state_sync_bootstrap_record_v0(
            &selected_profile,
            &RootSignatures,
            &bootstrap,
        )
        .expect("prepare marker replacement record");
        let prepared = prepare_h1_state_sync_initialization_v0(
            &selected_profile,
            [0x9a; 32],
            &prepared_record,
            SafetyBootstrapInitializationKindV0::StateSyncCheckpoint,
        )
        .expect("prepare marker replacement intent");
        let mut marker_file = marker_file;
        assert!(matches!(
            retire_h1_state_sync_initialization_intent_v0(
                &mut marker_file,
                old_identity,
                &mode_marker,
                &directory_file,
                prepared.intent,
            ),
            Err(SafetyStoreErrorV0::Conflict(
                SafetyStoreConflictV0::FileIdentityChanged
            ))
        ));
        assert_eq!(
            fs::read(&mode_marker).expect("replacement marker remains"),
            replacement_before
        );
    }
}
