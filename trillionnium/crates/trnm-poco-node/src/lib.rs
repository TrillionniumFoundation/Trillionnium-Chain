#![forbid(unsafe_code)]
//! Fail-closed lifecycle scaffold for the future PoCO-BFT node.
//!
//! This package is deliberately separate from the frozen legacy `trnm-node`
//! harness. It is the first process-ownership boundary for one [`Core`] and
//! one [`SqliteSafetyStateStoreV0`] plus one independent signer journal:
//! construction or recovery keeps all three under one process-local owner,
//! and none can be detached from the host through this API.
//!
//! This is not an effect driver or a production node. In particular, this
//! crate does not call `Core::step`, sign, broadcast, execute application
//! payloads, finalize blocks, run a pacemaker, serve a network, or install
//! state sync. The binary always exits non-zero. These omissions keep the
//! scaffold inert until the frozen production contracts have real adapters;
//! they must not be bypassed with the private CometBFT application fixture.
//!
//! The safety store and signer journal must live in distinct, already-existing
//! canonical parent directories. This limits one directory replacement from
//! replacing both local histories, but does not create an atomic transaction
//! across either store or the external signer watermark. New initialization
//! writes the safety store first and the signer journal second. A crash between
//! those operations can therefore leave a safety-only namespace; any partial
//! namespace fails closed on recovery and requires explicit operator
//! quarantine or recovery. This scaffold deliberately does not reconcile the
//! Core lock state, safety revision, and signer watermark across those stores.

use std::{
    error::Error,
    fmt, fs, io,
    path::{Path, PathBuf},
};

use sha2::{Digest, Sha256};
use trnm_consensus_core::{Core, CoreConfig, SafetyState, SafetyStateRecordLimitsV0};
use trnm_consensus_crypto::StrictEd25519Verifier;
use trnm_consensus_safety_store::{
    RecoveredSafetyStateV0, SafetyStateStoreProfileV0, SafetyStoreErrorV0, SqliteSafetyStateStoreV0,
};
use trnm_consensus_signer_journal::{
    ExternalMonotonicWatermarkV0, JournalCapacityV0, SignerJournalErrorV0, SignerJournalProfileV0,
    SignerWatermarkV0, SqliteSignerJournalV0,
};
use trnm_consensus_types::{GenesisQcV0, RolloutPhase};

/// This package must not be interpreted as a deployable consensus candidate.
pub const PRODUCTION_CANDIDATE_V0: bool = false;

/// This package deliberately has no effect-driving/running state.
pub const HOST_IMPLEMENTATION_COMPLETE_V0: bool = false;

/// SHA-256 of `trnm.poco-node.strict-ed25519-verifier-profile.v0`.
///
/// The safety journal binds this exact verification implementation profile;
/// callers cannot substitute a caller-selected profile reference.
pub const STRICT_ED25519_VERIFIER_PROFILE_REF_V0: [u8; 32] = [
    0x21, 0xc6, 0x12, 0x2a, 0xbb, 0xc2, 0xae, 0x7c, 0x72, 0xf0, 0x22, 0x72, 0xc1, 0xdc, 0x24, 0x1b,
    0xb0, 0x3a, 0x52, 0x67, 0x7d, 0xc4, 0x1f, 0xd2, 0x53, 0x63, 0x3f, 0x17, 0x89, 0xcc, 0x41, 0x1a,
];

/// SHA-256 of `trnm.poco-node.signer-journal-profile.v0`.
///
/// This binds the inert host's frozen strict-Ed25519 signer-journal profile;
/// it is not a key identifier or a claim that a producer is wired.
pub const SIGNER_JOURNAL_PROFILE_REF_V0: [u8; 32] = [
    0xe4, 0xff, 0xb8, 0x35, 0x52, 0x4b, 0xfd, 0x25, 0x4a, 0xb3, 0x11, 0x0c, 0xa6, 0xad, 0xcf, 0x13,
    0xc4, 0x85, 0x57, 0x4c, 0xdf, 0xdf, 0xc0, 0x0d, 0x1e, 0x84, 0x42, 0x2d, 0x42, 0xb9, 0x36, 0x69,
];

const SIGNER_WATERMARK_SCOPE_DOMAIN_V0: &[u8] = b"trnm.poco-node.signer-watermark-scope.v0";

/// A frozen production contract which this scaffold intentionally does not
/// implement or claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnwiredProductionContractV0 {
    CanonicalSignIntentSignerAdapter,
    IndependentSignerWatermark,
    CompleteHotstuffSafetyRules,
    SafetyStateSignerLockReconciliation,
    ApplicationStoreAdapter,
    ApplicationValidationRecovery,
    BlockIdSpeculativeOverlay,
    OrderedFinalizationQueue,
    EffectDriver,
    AuthenticatedPacemakerTransport,
    StateSync,
}

impl UnwiredProductionContractV0 {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CanonicalSignIntentSignerAdapter => "canonical_sign_intent_signer_adapter_v0",
            Self::IndependentSignerWatermark => "independent_signer_watermark",
            Self::CompleteHotstuffSafetyRules => "complete_hotstuff_safety_rules",
            Self::SafetyStateSignerLockReconciliation => "safety_state_signer_lock_reconciliation",
            Self::ApplicationStoreAdapter => "application_store_adapter",
            Self::ApplicationValidationRecovery => "application_validation_recovery",
            Self::BlockIdSpeculativeOverlay => "block_id_speculative_overlay",
            Self::OrderedFinalizationQueue => "ordered_finalization_queue",
            Self::EffectDriver => "core_effect_driver",
            Self::AuthenticatedPacemakerTransport => "authenticated_pacemaker_transport",
            Self::StateSync => "state_sync",
        }
    }
}

/// Exact activation blockers at this host boundary.
pub const UNWIRED_PRODUCTION_CONTRACTS_V0: &[UnwiredProductionContractV0] = &[
    UnwiredProductionContractV0::CanonicalSignIntentSignerAdapter,
    UnwiredProductionContractV0::IndependentSignerWatermark,
    UnwiredProductionContractV0::CompleteHotstuffSafetyRules,
    UnwiredProductionContractV0::SafetyStateSignerLockReconciliation,
    UnwiredProductionContractV0::ApplicationStoreAdapter,
    UnwiredProductionContractV0::ApplicationValidationRecovery,
    UnwiredProductionContractV0::BlockIdSpeculativeOverlay,
    UnwiredProductionContractV0::OrderedFinalizationQueue,
    UnwiredProductionContractV0::EffectDriver,
    UnwiredProductionContractV0::AuthenticatedPacemakerTransport,
    UnwiredProductionContractV0::StateSync,
];

/// Typed, local-only startup configuration for an inert host.
///
/// Consensus parameters remain inside [`CoreConfig`]. Record and database
/// capacities are node-local resource bounds and never become block-validity
/// inputs.
#[derive(Debug, Clone)]
pub struct PocoNodeStartConfigV0 {
    safety_store_path: PathBuf,
    safety_store_profile: SafetyStateStoreProfileV0,
    signer_journal_path: PathBuf,
    signer_journal_profile: SignerJournalProfileV0,
}

impl PocoNodeStartConfigV0 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        safety_store_path: impl AsRef<Path>,
        signer_journal_path: impl AsRef<Path>,
        core_config: CoreConfig,
        record_limits: SafetyStateRecordLimitsV0,
        maximum_safety_database_bytes: usize,
        maximum_signer_intents: u64,
        maximum_signer_intent_bytes: usize,
        maximum_signer_database_bytes: usize,
    ) -> Result<Self, PocoNodeHostErrorV0> {
        let safety_store_path = safety_store_path.as_ref();
        if !safety_store_path.is_absolute() {
            return Err(PocoNodeHostErrorV0::RelativeSafetyStorePath);
        }
        if safety_store_path.file_name().is_none() {
            return Err(PocoNodeHostErrorV0::InvalidSafetyStorePath);
        }
        let signer_journal_path = signer_journal_path.as_ref();
        if !signer_journal_path.is_absolute() {
            return Err(PocoNodeHostErrorV0::RelativeSignerJournalPath);
        }
        if signer_journal_path.file_name().is_none() {
            return Err(PocoNodeHostErrorV0::InvalidSignerJournalPath);
        }
        if core_config.consensus_parameters().production_activation() {
            return Err(PocoNodeHostErrorV0::ProductionActivationRequested);
        }
        let rollout_phase = core_config.consensus_parameters().rollout_phase();
        if rollout_phase != RolloutPhase::Shadow {
            return Err(PocoNodeHostErrorV0::NonShadowRolloutRequested { rollout_phase });
        }
        let epoch = core_config.validator_set().epoch().get();
        if epoch != 0 {
            return Err(PocoNodeHostErrorV0::UnsupportedEpoch { epoch });
        }
        let safety_store_file_name = safety_store_path
            .file_name()
            .expect("validated safety-store file name");
        let safety_store_parent = fs::canonicalize(
            safety_store_path
                .parent()
                .ok_or(PocoNodeHostErrorV0::InvalidSafetyStorePath)?,
        )
        .map_err(PocoNodeHostErrorV0::safety_store_parent)?;
        if !safety_store_parent.is_dir() {
            return Err(PocoNodeHostErrorV0::InvalidSafetyStoreParent);
        }
        let signer_journal_file_name = signer_journal_path
            .file_name()
            .expect("validated signer-journal file name");
        let signer_journal_parent = fs::canonicalize(
            signer_journal_path
                .parent()
                .ok_or(PocoNodeHostErrorV0::InvalidSignerJournalPath)?,
        )
        .map_err(PocoNodeHostErrorV0::signer_journal_parent)?;
        if !signer_journal_parent.is_dir() {
            return Err(PocoNodeHostErrorV0::InvalidSignerJournalParent);
        }
        if safety_store_parent == signer_journal_parent {
            return Err(PocoNodeHostErrorV0::SharedStoreParentNamespace);
        }
        let safety_store_path = safety_store_parent.join(safety_store_file_name);
        let signer_journal_path = signer_journal_parent.join(signer_journal_file_name);
        let signer_journal_profile = SignerJournalProfileV0::new(
            core_config.validator_set().clone(),
            core_config.local_validator(),
            SIGNER_JOURNAL_PROFILE_REF_V0,
            derive_signer_watermark_scope_v0(&core_config),
            maximum_signer_intents,
            maximum_signer_intent_bytes,
            maximum_signer_database_bytes,
        )
        .map_err(PocoNodeHostErrorV0::signer_journal)?;
        let safety_store_profile = SafetyStateStoreProfileV0::new(
            core_config,
            STRICT_ED25519_VERIFIER_PROFILE_REF_V0,
            record_limits,
            maximum_safety_database_bytes,
        )
        .map_err(PocoNodeHostErrorV0::safety_store)?;
        Ok(Self {
            safety_store_path,
            safety_store_profile,
            signer_journal_path,
            signer_journal_profile,
        })
    }

    pub fn safety_store_path(&self) -> &Path {
        self.safety_store_path.as_path()
    }

    pub const fn core_config(&self) -> &CoreConfig {
        self.safety_store_profile.core_config()
    }

    pub const fn record_limits(&self) -> SafetyStateRecordLimitsV0 {
        self.safety_store_profile.record_limits()
    }

    pub const fn maximum_database_bytes(&self) -> usize {
        self.safety_store_profile.maximum_database_bytes()
    }

    pub fn signer_journal_path(&self) -> &Path {
        self.signer_journal_path.as_path()
    }

    pub const fn maximum_signer_intents(&self) -> u64 {
        self.signer_journal_profile.maximum_intents()
    }

    pub const fn maximum_signer_intent_bytes(&self) -> usize {
        self.signer_journal_profile.maximum_intent_bytes()
    }

    pub const fn maximum_signer_database_bytes(&self) -> usize {
        self.signer_journal_profile.maximum_database_bytes()
    }
}

fn derive_signer_watermark_scope_v0(core_config: &CoreConfig) -> [u8; 32] {
    let validator_set = core_config.validator_set();
    let author = core_config.local_validator();
    let mut hasher = Sha256::new();
    hasher.update(SIGNER_WATERMARK_SCOPE_DOMAIN_V0);
    hasher.update((validator_set.chain_id().as_bytes().len() as u64).to_be_bytes());
    hasher.update(validator_set.chain_id().as_bytes());
    hasher.update(validator_set.protocol_version().get().to_be_bytes());
    hasher.update(validator_set.epoch().get().to_be_bytes());
    hasher.update(validator_set.id().as_bytes());
    hasher.update((author.as_bytes().len() as u64).to_be_bytes());
    hasher.update(author.as_bytes());
    hasher.finalize().into()
}

/// How the inert owner acquired its exact safety state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostBootstrapModeV0 {
    InitializedGenesis,
    RecoveredExisting,
}

/// The only lifecycle phase currently expressible by this package.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostLifecyclePhaseV0 {
    BootstrappedInert,
}

/// Non-cloneable owner of one Core, its safety store, and signer journal.
///
/// There is intentionally no mutable Core accessor, `step`, `run`, signer,
/// application adapter, or escape hatch returning the two owned parts.
pub struct PocoNodeHostV0<W> {
    core: Core,
    safety_store: SqliteSafetyStateStoreV0<StrictEd25519Verifier>,
    signer_journal: SqliteSignerJournalV0<W>,
    signer_journal_head: SignerWatermarkV0,
    bootstrap_mode: HostBootstrapModeV0,
}

impl<W: ExternalMonotonicWatermarkV0> PocoNodeHostV0<W> {
    /// Creates the epoch-zero Core, initializes its journal at revision zero,
    /// and binds future persistence to this exact Core instance.
    ///
    /// The safety store is initialized before the signer journal. There is no
    /// atomic transaction across the two SQLite stores or the external
    /// watermark. An interrupted partial initialization is intentionally not
    /// repaired here: subsequent recovery fails closed and requires explicit
    /// operator quarantine or recovery.
    pub fn initialize_new(
        config: PocoNodeStartConfigV0,
        genesis_qc: GenesisQcV0,
        external_watermark: W,
    ) -> Result<Self, PocoNodeHostErrorV0> {
        reject_activation_request(&config)?;
        let core_config = config.core_config().clone();
        let PocoNodeStartConfigV0 {
            safety_store_path,
            safety_store_profile,
            signer_journal_path,
            signer_journal_profile,
        } = config;
        let verifier = StrictEd25519Verifier;
        let core =
            Core::new(core_config, genesis_qc, &verifier).map_err(PocoNodeHostErrorV0::core)?;
        let mut safety_store = SqliteSafetyStateStoreV0::initialize_new(
            safety_store_path,
            safety_store_profile,
            verifier,
            core.safety_state(),
        )
        .map_err(PocoNodeHostErrorV0::safety_store)?;
        let mut signer_journal = SqliteSignerJournalV0::initialize_new(
            signer_journal_path,
            signer_journal_profile,
            external_watermark,
        )
        .map_err(PocoNodeHostErrorV0::signer_journal)?;
        let signer_journal_head = signer_journal
            .external_head()
            .map_err(PocoNodeHostErrorV0::signer_journal)?;
        safety_store
            .bind_core_v0(core.safety_state_persistence_binding_v0())
            .map_err(PocoNodeHostErrorV0::safety_store)?;
        Ok(Self {
            core,
            safety_store,
            signer_journal,
            signer_journal_head,
            bootstrap_mode: HostBootstrapModeV0::InitializedGenesis,
        })
    }

    /// Opens and authenticates the exact journal head, recovers Core, and
    /// binds the journal to that recovered instance.
    ///
    /// Obligation-bearing heads fail before Core construction because the
    /// authenticated validation replay/takeover contract does not yet exist.
    pub fn open_existing(
        config: PocoNodeStartConfigV0,
        external_watermark: W,
    ) -> Result<Self, PocoNodeHostErrorV0> {
        reject_activation_request(&config)?;
        let core_config = config.core_config().clone();
        let PocoNodeStartConfigV0 {
            safety_store_path,
            safety_store_profile,
            signer_journal_path,
            signer_journal_profile,
        } = config;
        let verifier = StrictEd25519Verifier;
        let mut safety_store = SqliteSafetyStateStoreV0::open_existing(
            safety_store_path,
            safety_store_profile,
            verifier,
        )
        .map_err(PocoNodeHostErrorV0::safety_store)?;
        let head = safety_store
            .head()
            .map_err(PocoNodeHostErrorV0::safety_store)?;
        let obligation_count = head.state().payload_validation_obligations().len();
        if obligation_count != 0 {
            return Err(
                PocoNodeHostErrorV0::AuthenticatedObligationReplayUnavailable {
                    revision: head.revision(),
                    obligation_count,
                },
            );
        }
        let mut signer_journal = SqliteSignerJournalV0::open_existing(
            signer_journal_path,
            signer_journal_profile,
            external_watermark,
        )
        .map_err(PocoNodeHostErrorV0::signer_journal)?;
        let signer_journal_head = signer_journal
            .external_head()
            .map_err(PocoNodeHostErrorV0::signer_journal)?;
        let core = Core::recover(core_config, head.state().clone(), &verifier)
            .map_err(PocoNodeHostErrorV0::core)?;
        if core.safety_state() != head.state() {
            return Err(PocoNodeHostErrorV0::RecoveredHeadMismatch);
        }
        safety_store
            .bind_core_v0(core.safety_state_persistence_binding_v0())
            .map_err(PocoNodeHostErrorV0::safety_store)?;
        Ok(Self {
            core,
            safety_store,
            signer_journal,
            signer_journal_head,
            bootstrap_mode: HostBootstrapModeV0::RecoveredExisting,
        })
    }

    pub const fn bootstrap_mode(&self) -> HostBootstrapModeV0 {
        self.bootstrap_mode
    }

    pub const fn lifecycle_phase(&self) -> HostLifecyclePhaseV0 {
        HostLifecyclePhaseV0::BootstrappedInert
    }

    pub const fn core_config(&self) -> &CoreConfig {
        self.core.config()
    }

    /// Exposes inert state facts, not the live Core or a persistence binding.
    pub const fn safety_state(&self) -> &SafetyState {
        self.core.safety_state()
    }

    pub fn safety_store_path(&self) -> &Path {
        self.safety_store.path()
    }

    pub fn signer_journal_path(&self) -> &Path {
        self.signer_journal.path()
    }

    /// Captured exact external/local signer head at successful bootstrap.
    /// The inert host has no API capable of advancing it.
    pub const fn signer_journal_head(&self) -> SignerWatermarkV0 {
        self.signer_journal_head
    }

    pub fn signer_journal_capacity(&self) -> Result<JournalCapacityV0, PocoNodeHostErrorV0> {
        self.signer_journal
            .capacity()
            .map_err(PocoNodeHostErrorV0::signer_journal)
    }

    pub fn safety_head(&self) -> Result<RecoveredSafetyStateV0, PocoNodeHostErrorV0> {
        self.safety_store
            .head()
            .map_err(PocoNodeHostErrorV0::safety_store)
    }

    /// No running/effect-driving state is constructible in this slice.
    pub fn production_activation_check(&self) -> Result<(), ProductionActivationBlockedV0> {
        Err(ProductionActivationBlockedV0::new())
    }
}

fn reject_activation_request(config: &PocoNodeStartConfigV0) -> Result<(), PocoNodeHostErrorV0> {
    let parameters = config.core_config().consensus_parameters();
    if parameters.production_activation() {
        return Err(PocoNodeHostErrorV0::ProductionActivationRequested);
    }
    let rollout_phase = parameters.rollout_phase();
    if rollout_phase != RolloutPhase::Shadow {
        return Err(PocoNodeHostErrorV0::NonShadowRolloutRequested { rollout_phase });
    }
    Ok(())
}

/// The static production gate used by the inert binary and live owner alike.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProductionActivationBlockedV0 {
    _private: (),
}

impl ProductionActivationBlockedV0 {
    const fn new() -> Self {
        Self { _private: () }
    }

    pub const fn blockers(self) -> &'static [UnwiredProductionContractV0] {
        UNWIRED_PRODUCTION_CONTRACTS_V0
    }
}

impl fmt::Display for ProductionActivationBlockedV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("production activation is blocked; unwired contracts: ")?;
        for (index, contract) in UNWIRED_PRODUCTION_CONTRACTS_V0.iter().enumerate() {
            if index != 0 {
                formatter.write_str(",")?;
            }
            formatter.write_str(contract.as_str())?;
        }
        Ok(())
    }
}

impl Error for ProductionActivationBlockedV0 {}

pub const fn production_activation_gate_v0() -> Result<(), ProductionActivationBlockedV0> {
    Err(ProductionActivationBlockedV0::new())
}

/// Startup failures are fail-closed and never converted into consensus
/// invalidity.
#[derive(Debug)]
pub enum PocoNodeHostErrorV0 {
    RelativeSafetyStorePath,
    InvalidSafetyStorePath,
    SafetyStoreParentIo(Box<io::Error>),
    InvalidSafetyStoreParent,
    RelativeSignerJournalPath,
    InvalidSignerJournalPath,
    SignerJournalParentIo(Box<io::Error>),
    InvalidSignerJournalParent,
    SharedStoreParentNamespace,
    ProductionActivationRequested,
    NonShadowRolloutRequested {
        rollout_phase: RolloutPhase,
    },
    UnsupportedEpoch {
        epoch: u64,
    },
    AuthenticatedObligationReplayUnavailable {
        revision: u64,
        obligation_count: usize,
    },
    RecoveredHeadMismatch,
    Core(Box<trnm_consensus_core::CoreError>),
    SafetyStore(Box<SafetyStoreErrorV0>),
    SignerJournal(Box<SignerJournalErrorV0>),
}

impl PocoNodeHostErrorV0 {
    fn core(error: trnm_consensus_core::CoreError) -> Self {
        Self::Core(Box::new(error))
    }

    fn safety_store(error: SafetyStoreErrorV0) -> Self {
        Self::SafetyStore(Box::new(error))
    }

    fn signer_journal(error: SignerJournalErrorV0) -> Self {
        Self::SignerJournal(Box::new(error))
    }

    fn safety_store_parent(error: io::Error) -> Self {
        Self::SafetyStoreParentIo(Box::new(error))
    }

    fn signer_journal_parent(error: io::Error) -> Self {
        Self::SignerJournalParentIo(Box::new(error))
    }
}

impl fmt::Display for PocoNodeHostErrorV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RelativeSafetyStorePath => {
                formatter.write_str("safety-store path must be absolute")
            }
            Self::InvalidSafetyStorePath => {
                formatter.write_str("safety-store path must name a database file")
            }
            Self::SafetyStoreParentIo(error) => {
                write!(formatter, "safety-store parent must already exist: {error}")
            }
            Self::InvalidSafetyStoreParent => {
                formatter.write_str("safety-store parent must be a directory")
            }
            Self::RelativeSignerJournalPath => {
                formatter.write_str("signer-journal path must be absolute")
            }
            Self::InvalidSignerJournalPath => {
                formatter.write_str("signer-journal path must name a database file")
            }
            Self::SignerJournalParentIo(error) => {
                write!(formatter, "signer-journal parent must already exist: {error}")
            }
            Self::InvalidSignerJournalParent => {
                formatter.write_str("signer-journal parent must be a directory")
            }
            Self::SharedStoreParentNamespace => {
                formatter.write_str(
                    "safety-store and signer-journal must use distinct canonical parent directories",
                )
            }
            Self::ProductionActivationRequested => formatter.write_str(
                "incomplete PoCO host refuses production-activated consensus parameters",
            ),
            Self::NonShadowRolloutRequested { rollout_phase } => write!(
                formatter,
                "incomplete PoCO host supports only shadow rollout, got {rollout_phase:?}",
            ),
            Self::UnsupportedEpoch { epoch } => {
                write!(formatter, "incomplete PoCO host supports only epoch zero, got {epoch}")
            }
            Self::AuthenticatedObligationReplayUnavailable {
                revision,
                obligation_count,
            } => write!(
                formatter,
                "safety revision {revision} retains {obligation_count} validation obligation(s), but authenticated replay/takeover is not implemented",
            ),
            Self::RecoveredHeadMismatch => {
                formatter.write_str("recovered Core state differs from the authenticated journal head")
            }
            Self::Core(error) => write!(formatter, "PoCO Core startup failed: {error}"),
            Self::SafetyStore(error) => write!(formatter, "PoCO safety-store startup failed: {error}"),
            Self::SignerJournal(error) => {
                write!(formatter, "PoCO signer-journal startup failed: {error}")
            }
        }
    }
}

impl Error for PocoNodeHostErrorV0 {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::SafetyStoreParentIo(error) => Some(error.as_ref()),
            Self::SignerJournalParentIo(error) => Some(error.as_ref()),
            Self::SafetyStore(error) => Some(error.as_ref()),
            Self::SignerJournal(error) => Some(error.as_ref()),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    #[cfg(target_os = "linux")]
    use std::{
        fs,
        sync::{Arc, Mutex},
    };

    #[cfg(target_os = "linux")]
    use tempfile::TempDir;
    use trnm_consensus_core::SafetyStateRecordLimitsV0;
    use trnm_consensus_types::{
        ChainId, ConsensusParametersV0, ConsensusPublicKey, Epoch, GenesisHash, GenesisQcV0,
        ProtocolVersion, Validator, ValidatorId, ValidatorSet, VotingPower,
    };

    use super::*;

    const _: () = {
        assert!(!PRODUCTION_CANDIDATE_V0);
        assert!(!HOST_IMPLEMENTATION_COMPLETE_V0);
    };

    const MAXIMUM_RECORD_BYTES: usize = 64 * 1024 * 1024;
    const MAXIMUM_BLOB_BYTES: usize = 16 * 1024 * 1024;
    const MAXIMUM_DATABASE_BYTES: usize = 192 * 1024 * 1024;
    const MAXIMUM_SIGNER_INTENTS: u64 = 64;
    const MAXIMUM_SIGNER_INTENT_BYTES: usize = 4096;
    const MAXIMUM_SIGNER_DATABASE_BYTES: usize = 32 * 1024 * 1024;

    #[cfg(target_os = "linux")]
    #[derive(Debug, Clone, Default)]
    struct MemoryWatermark(Arc<Mutex<Option<SignerWatermarkV0>>>);

    #[cfg(target_os = "linux")]
    impl ExternalMonotonicWatermarkV0 for MemoryWatermark {
        fn load(
            &mut self,
            scope: [u8; 32],
        ) -> Result<
            Option<SignerWatermarkV0>,
            trnm_consensus_signer_journal::ExternalWatermarkErrorV0,
        > {
            let value = *self.0.lock().expect("test watermark lock");
            if value.is_some_and(|watermark| watermark.scope() != scope) {
                return Err(
                    trnm_consensus_signer_journal::ExternalWatermarkErrorV0::InvalidPersistedState,
                );
            }
            Ok(value)
        }

        fn compare_and_advance(
            &mut self,
            expected: Option<SignerWatermarkV0>,
            target: SignerWatermarkV0,
        ) -> Result<(), trnm_consensus_signer_journal::ExternalWatermarkErrorV0> {
            use trnm_consensus_signer_journal::ExternalWatermarkErrorV0;

            let mut value = self.0.lock().expect("test watermark lock");
            if *value != expected {
                return Err(ExternalWatermarkErrorV0::CompareFailed);
            }
            match expected {
                None if target.sequence() == 0 => {}
                Some(source)
                    if source.scope() == target.scope()
                        && source.journal_id() == target.journal_id()
                        && source.sequence().checked_add(1) == Some(target.sequence()) => {}
                _ => return Err(ExternalWatermarkErrorV0::InvalidPersistedState),
            }
            *value = Some(target);
            Ok(())
        }
    }

    fn validator_id(index: u8) -> ValidatorId {
        ValidatorId::new([index; 32])
    }

    fn core_config(parameters: ConsensusParametersV0) -> CoreConfig {
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
        let validator_set = ValidatorSet::new(
            GenesisHash::new([0xa5; 32]),
            ChainId::from_static("trnm-poco-node-test"),
            ProtocolVersion::V0,
            Epoch::new(0),
            parameters.hash(),
            validators,
        )
        .expect("valid validator set");
        CoreConfig::new(validator_id(1), validator_set, parameters, 17, 64, 64)
            .expect("valid Core config")
    }

    fn record_limits() -> SafetyStateRecordLimitsV0 {
        SafetyStateRecordLimitsV0::new(MAXIMUM_RECORD_BYTES, MAXIMUM_BLOB_BYTES)
            .expect("valid local record limits")
    }

    fn start_config(
        safety_store_path: impl AsRef<Path>,
        signer_journal_path: impl AsRef<Path>,
        core_config: CoreConfig,
    ) -> Result<PocoNodeStartConfigV0, PocoNodeHostErrorV0> {
        PocoNodeStartConfigV0::new(
            safety_store_path,
            signer_journal_path,
            core_config,
            record_limits(),
            MAXIMUM_DATABASE_BYTES,
            MAXIMUM_SIGNER_INTENTS,
            MAXIMUM_SIGNER_INTENT_BYTES,
            MAXIMUM_SIGNER_DATABASE_BYTES,
        )
    }

    fn genesis_qc(core_config: &CoreConfig) -> GenesisQcV0 {
        GenesisQcV0::new(
            core_config.validator_set().genesis_hash(),
            core_config.validator_set().chain_id(),
            core_config.validator_set(),
        )
        .expect("valid genesis anchor")
    }

    #[cfg(target_os = "linux")]
    fn protected_temp_dir() -> TempDir {
        let directory = TempDir::new().expect("temporary directory");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
                .expect("protect temporary safety-store directory");
        }
        directory
    }

    #[cfg(target_os = "linux")]
    fn protected_store_namespace(root: &TempDir, name: &str) -> PathBuf {
        let namespace = root.path().join(name);
        fs::create_dir(&namespace).expect("create isolated store namespace");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&namespace, fs::Permissions::from_mode(0o700))
                .expect("protect isolated store namespace");
        }
        namespace
    }

    #[cfg(target_os = "linux")]
    fn dual_store_paths(root: &TempDir) -> (PathBuf, PathBuf) {
        (
            protected_store_namespace(root, "safety").join("safety.sqlite3"),
            protected_store_namespace(root, "signer").join("signer.sqlite3"),
        )
    }

    #[test]
    fn static_activation_gate_names_real_unwired_contracts() {
        let error = production_activation_gate_v0().expect_err("activation must remain blocked");
        assert_eq!(error.blockers(), UNWIRED_PRODUCTION_CONTRACTS_V0);
        assert!(error.to_string().contains("independent_signer_watermark"));
        assert!(error.to_string().contains("complete_hotstuff_safety_rules"));
        assert!(!error.to_string().contains("append_only_sign_journal"));
        assert!(error.to_string().contains("block_id_speculative_overlay"));
    }

    #[test]
    fn startup_config_rejects_relative_store_path() {
        let error = PocoNodeStartConfigV0::new(
            "relative/safety.sqlite3",
            "/tmp/trnm-poco-node-relative-safety-signer.sqlite3",
            core_config(ConsensusParametersV0::reference_shadow_v0()),
            record_limits(),
            MAXIMUM_DATABASE_BYTES,
            MAXIMUM_SIGNER_INTENTS,
            MAXIMUM_SIGNER_INTENT_BYTES,
            MAXIMUM_SIGNER_DATABASE_BYTES,
        )
        .expect_err("relative startup state must be refused");
        assert!(matches!(
            error,
            PocoNodeHostErrorV0::RelativeSafetyStorePath
        ));
    }

    #[test]
    fn startup_config_rejects_relative_signer_journal_path() {
        let error = start_config(
            "/tmp/trnm-poco-node-relative-signer-safety.sqlite3",
            "relative/signer.sqlite3",
            core_config(ConsensusParametersV0::reference_shadow_v0()),
        )
        .expect_err("relative signer state must be refused");
        assert!(matches!(
            error,
            PocoNodeHostErrorV0::RelativeSignerJournalPath
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn startup_config_rejects_shared_canonical_parent_namespace() {
        let directory = protected_temp_dir();
        let error = start_config(
            directory.path().join("safety.sqlite3"),
            directory.path().join("signer.sqlite3"),
            core_config(ConsensusParametersV0::reference_shadow_v0()),
        )
        .expect_err("two histories in one canonical parent must be refused");
        assert!(matches!(
            error,
            PocoNodeHostErrorV0::SharedStoreParentNamespace
        ));
    }

    #[test]
    fn startup_config_rejects_production_activation() {
        let mut fields = ConsensusParametersV0::reference_shadow_v0().fields();
        fields.production_activation = true;
        let activated = ConsensusParametersV0::new(fields)
            .expect("production flag is a future policy value, not a shape error");
        let error = PocoNodeStartConfigV0::new(
            "/tmp/trnm-poco-node-production-refusal.sqlite3",
            "/tmp/trnm-poco-node-production-refusal-signer.sqlite3",
            core_config(activated),
            record_limits(),
            MAXIMUM_DATABASE_BYTES,
            MAXIMUM_SIGNER_INTENTS,
            MAXIMUM_SIGNER_INTENT_BYTES,
            MAXIMUM_SIGNER_DATABASE_BYTES,
        )
        .expect_err("incomplete host must refuse production activation");
        assert!(matches!(
            error,
            PocoNodeHostErrorV0::ProductionActivationRequested
        ));
    }

    #[test]
    fn startup_config_rejects_non_shadow_rollout() {
        let mut fields = ConsensusParametersV0::reference_shadow_v0().fields();
        fields.rollout_phase = RolloutPhase::EligibilityOnly;
        let non_shadow = ConsensusParametersV0::new(fields)
            .expect("eligibility-only is a future policy value, not a shape error");
        let error = PocoNodeStartConfigV0::new(
            "/tmp/trnm-poco-node-rollout-refusal.sqlite3",
            "/tmp/trnm-poco-node-rollout-refusal-signer.sqlite3",
            core_config(non_shadow),
            record_limits(),
            MAXIMUM_DATABASE_BYTES,
            MAXIMUM_SIGNER_INTENTS,
            MAXIMUM_SIGNER_INTENT_BYTES,
            MAXIMUM_SIGNER_DATABASE_BYTES,
        )
        .expect_err("incomplete host must refuse non-shadow rollout");
        assert!(matches!(
            error,
            PocoNodeHostErrorV0::NonShadowRolloutRequested {
                rollout_phase: RolloutPhase::EligibilityOnly
            }
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn one_host_initializes_and_recovers_exact_dual_store_ownership() {
        let directory = protected_temp_dir();
        let (safety_path, signer_path) = dual_store_paths(&directory);
        let core_config = core_config(ConsensusParametersV0::reference_shadow_v0());
        let genesis_qc = genesis_qc(&core_config);
        let config =
            start_config(&safety_path, &signer_path, core_config).expect("valid inert host config");
        let watermark = MemoryWatermark::default();

        let host = PocoNodeHostV0::initialize_new(config.clone(), genesis_qc, watermark.clone())
            .expect("initialize exact dual-store owner");
        assert_eq!(
            host.bootstrap_mode(),
            HostBootstrapModeV0::InitializedGenesis
        );
        assert_eq!(
            host.lifecycle_phase(),
            HostLifecyclePhaseV0::BootstrappedInert
        );
        assert_eq!(host.safety_state().revision(), 0);
        assert_eq!(host.safety_head().expect("journal head").revision(), 0);
        assert_eq!(host.safety_store_path(), safety_path.as_path());
        assert_eq!(host.signer_journal_path(), signer_path.as_path());
        assert_eq!(host.signer_journal_head().sequence(), 0);
        assert_eq!(
            host.signer_journal_capacity()
                .expect("signer capacity")
                .intent_count(),
            0
        );
        assert!(host.production_activation_check().is_err());

        let duplicate_open = match PocoNodeHostV0::open_existing(config.clone(), watermark.clone())
        {
            Ok(_) => panic!("a second live owner must not open the same journal"),
            Err(error) => error,
        };
        assert!(matches!(
            duplicate_open,
            PocoNodeHostErrorV0::SafetyStore(error)
                if matches!(error.as_ref(), SafetyStoreErrorV0::Locked)
        ));
        drop(host);

        let recovered = PocoNodeHostV0::open_existing(config, watermark)
            .expect("recover exact dual-store owner");
        assert_eq!(
            recovered.bootstrap_mode(),
            HostBootstrapModeV0::RecoveredExisting
        );
        assert_eq!(recovered.safety_state().revision(), 0);
        assert_eq!(recovered.safety_store_path(), safety_path.as_path());
        assert_eq!(recovered.signer_journal_path(), signer_path.as_path());
        assert_eq!(recovered.signer_journal_head().sequence(), 0);
        assert!(recovered.production_activation_check().is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn signer_profile_mismatch_fails_after_safety_store_authentication() {
        let directory = protected_temp_dir();
        let (safety_path, signer_path) = dual_store_paths(&directory);
        let core_config = core_config(ConsensusParametersV0::reference_shadow_v0());
        let genesis_qc = genesis_qc(&core_config);
        let config = start_config(&safety_path, &signer_path, core_config.clone())
            .expect("valid initial config");
        let watermark = MemoryWatermark::default();
        let host = PocoNodeHostV0::initialize_new(config, genesis_qc, watermark.clone())
            .expect("initialize dual stores");
        drop(host);

        let mismatched = PocoNodeStartConfigV0::new(
            &safety_path,
            &signer_path,
            core_config,
            record_limits(),
            MAXIMUM_DATABASE_BYTES,
            MAXIMUM_SIGNER_INTENTS + 1,
            MAXIMUM_SIGNER_INTENT_BYTES,
            MAXIMUM_SIGNER_DATABASE_BYTES,
        )
        .expect("shape-valid alternate local capacity profile");
        let error = match PocoNodeHostV0::open_existing(mismatched, watermark) {
            Ok(_) => panic!("different signer profile must not open"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            PocoNodeHostErrorV0::SignerJournal(error)
                if matches!(error.as_ref(), SignerJournalErrorV0::MetadataMismatch)
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn either_partial_dual_store_namespace_fails_closed() {
        let missing_signer_directory = protected_temp_dir();
        let (safety_path, signer_path) = dual_store_paths(&missing_signer_directory);
        let safety_only_core_config = core_config(ConsensusParametersV0::reference_shadow_v0());
        let config = start_config(&safety_path, &signer_path, safety_only_core_config.clone())
            .expect("valid missing-signer config");
        let watermark = MemoryWatermark::default();
        let host = PocoNodeHostV0::initialize_new(
            config.clone(),
            genesis_qc(&safety_only_core_config),
            watermark.clone(),
        )
        .expect("initialize missing-signer fixture");
        drop(host);
        fs::remove_file(&signer_path).expect("remove signer database only");
        let error = match PocoNodeHostV0::open_existing(config, watermark) {
            Ok(_) => panic!("safety-only namespace must fail closed"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            PocoNodeHostErrorV0::SignerJournal(error)
                if matches!(error.as_ref(), SignerJournalErrorV0::Missing("database"))
        ));

        let missing_safety_directory = protected_temp_dir();
        let (safety_path, signer_path) = dual_store_paths(&missing_safety_directory);
        let signer_only_core_config = core_config(ConsensusParametersV0::reference_shadow_v0());
        let config = start_config(&safety_path, &signer_path, signer_only_core_config.clone())
            .expect("valid missing-safety config");
        let watermark = MemoryWatermark::default();
        let host = PocoNodeHostV0::initialize_new(
            config.clone(),
            genesis_qc(&signer_only_core_config),
            watermark.clone(),
        )
        .expect("initialize missing-safety fixture");
        drop(host);
        fs::remove_file(&safety_path).expect("remove safety database only");
        let error = match PocoNodeHostV0::open_existing(config, watermark) {
            Ok(_) => panic!("signer-only namespace must fail closed"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            PocoNodeHostErrorV0::SafetyStore(error)
                if matches!(error.as_ref(), SafetyStoreErrorV0::Missing("database"))
        ));
    }
}
