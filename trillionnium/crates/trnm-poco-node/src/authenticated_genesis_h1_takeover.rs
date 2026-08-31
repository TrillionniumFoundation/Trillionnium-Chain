//! Existing-only whole-node recovery for authenticated-genesis empty-h1.
//!
//! This owner is deliberately separate from commissioning, the one-shot live
//! h1 driver, stable recovery, and the ordinary process host.  It pins the
//! virgin signer before opening either durable consensus namespace, opens the
//! Safety journal exactly once, and dispatches that one authenticated owner to
//! either the revision-one obligation takeover or the revision-two stable
//! recovery protocol.  The returned owner is inert and retains all three
//! lifetime locks; it exposes no Core, callback, persistence carrier, signer
//! activation, network, timer, finalization, or production surface.

use std::{fmt, path::Path};

use trnm_consensus_app::{
    ConsensusAppConfig, NativeAuthenticatedGenesisH1CompletedAppConfirmationV0,
    NativeAuthenticatedGenesisH1ObligationTakeoverCompletedHostV0,
    NativeAuthenticatedGenesisH1ObligationTakeoverConfigV0,
    NativeAuthenticatedGenesisH1ObligationTakeoverErrorV0,
    NativeAuthenticatedGenesisH1ObligationTakeoverHostV0,
    NativeAuthenticatedGenesisH1ObligationTakeoverSourceV0,
    NativeAuthenticatedGenesisH1StableApplicationHostV0,
    NativeAuthenticatedGenesisH1StableApplicationSourceV0,
    NativeAuthenticatedGenesisH1StableRecoveryConfigV0,
    NativeAuthenticatedGenesisH1StableRecoveryErrorV0,
    PreparedNativeAuthenticatedGenesisH1InactiveExpectationV0,
};
use trnm_consensus_core::{
    AuthenticatedGenesisApplicationH1CompletedV0,
    AuthenticatedGenesisApplicationH1StableNativeValidRecoveredFactsV0, Core, CoreConfig,
    CoreError, PreparedAuthenticatedGenesisApplicationBootstrapV0, SafetyStateRecordLimitsV0,
    ValidationId,
};
use trnm_consensus_crypto::StrictEd25519Verifier;
use trnm_consensus_safety_store::{
    AuthenticatedGenesisApplicationH1ExistingCutV0, ConfirmedNativeValidHeadV0, SafetyStoreErrorV0,
    SqliteSafetyStateStoreV0,
};
use trnm_consensus_signer_journal::{
    ExternalMonotonicWatermarkV0, PinnedSqliteSignerJournalV0, SignerJournalErrorV0,
    SignerWatermarkV0,
};
use trnm_consensus_types::BlockId;

use crate::{
    authenticated_genesis_commissioning::{
        same_stable_application_poststate_v0, validate_confirmed_virgin_signer_v0,
        validate_initial_virgin_signer_v0, validate_prepared_bootstrap_v0,
        validate_stable_application_capability_v0, validate_stable_recovered_closure_v0,
        validate_stable_safety_capability_v0, PocoNodeAuthenticatedGenesisCommissioningConfigV0,
        PocoNodeAuthenticatedGenesisCommissioningErrorV0,
        PocoNodeAuthenticatedGenesisH1StableRecoveryErrorV0,
    },
    process_host::{revalidate_process_store_paths_v0, ProcessStoreParentIdentitiesV0},
};

// Exact SafetyState and App closure authentication uses deliberately deep,
// bounded decoders. Keep that stack requirement inside this public owner
// instead of inheriting the caller's (often much smaller) debug-build stack.
// The scoped worker is joined before any owner is returned.
const TAKEOVER_STARTUP_AUDIT_STACK_BYTES_V0: usize = 32 * 1024 * 1024;

/// Fixed terminal mode of the unified existing-only recovery owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PocoNodeAuthenticatedGenesisH1TakeoverModeV0 {
    AuthenticatedGenesisApplicationEmptyH1RecoveredInert,
}

/// Durable source consumed by one unified recovery call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PocoNodeAuthenticatedGenesisH1TakeoverSourceV0 {
    ObligationAbsent,
    ObligationReserved,
    ObligationCallbackPending,
    ObligationDelivered,
    StableDeliveredToAcked,
    StableAcked,
}

/// Existing-only configuration for obligation takeover or stable recovery.
///
/// Construction reuses the exact commissioning profile derivation and the
/// same three canonical, non-overlapping parent identities.  The runtime entry
/// below never initializes a missing Safety, App, or signer namespace.
#[derive(Debug)]
pub struct PocoNodeAuthenticatedGenesisH1TakeoverConfigV0 {
    inner: PocoNodeAuthenticatedGenesisCommissioningConfigV0,
}

impl PocoNodeAuthenticatedGenesisH1TakeoverConfigV0 {
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
        application: ConsensusAppConfig,
    ) -> Result<Self, PocoNodeAuthenticatedGenesisH1TakeoverErrorV0> {
        let inner = PocoNodeAuthenticatedGenesisCommissioningConfigV0::new(
            safety_store_path,
            signer_journal_path,
            core_config,
            record_limits,
            maximum_safety_database_bytes,
            maximum_signer_intents,
            maximum_signer_intent_bytes,
            maximum_signer_database_bytes,
            application,
        )
        .map_err(PocoNodeAuthenticatedGenesisH1TakeoverErrorV0::InvalidConfiguration)?;
        Ok(Self { inner })
    }
}

/// Typed failure from the unified existing-only owner. No variant carries a
/// partially opened owner, Core activation, request, callback, or transition.
#[derive(Debug)]
pub enum PocoNodeAuthenticatedGenesisH1TakeoverErrorV0 {
    InvalidConfiguration(PocoNodeAuthenticatedGenesisCommissioningErrorV0),
    PreparedBootstrapMismatch,
    SignerJournal(SignerJournalErrorV0),
    SignerCapabilityMismatch,
    SafetyStore(SafetyStoreErrorV0),
    SafetyCapabilityMismatch,
    ApplicationTakeover(NativeAuthenticatedGenesisH1ObligationTakeoverErrorV0),
    ApplicationStable(NativeAuthenticatedGenesisH1StableRecoveryErrorV0),
    ApplicationCapabilityMismatch,
    Core(CoreError),
    CompletedClosureMismatch,
    StoreParentIdentityChanged,
    StartupAuditWorkerUnavailable,
}

impl fmt::Display for PocoNodeAuthenticatedGenesisH1TakeoverErrorV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfiguration(error) => {
                write!(
                    formatter,
                    "authenticated-genesis h1 takeover configuration: {error}"
                )
            }
            Self::PreparedBootstrapMismatch => {
                formatter.write_str("authenticated-genesis h1 takeover prepared bootstrap differs")
            }
            Self::SignerJournal(error) => write!(formatter, "signer journal: {error}"),
            Self::SignerCapabilityMismatch => formatter.write_str(
                "authenticated-genesis h1 takeover signer capability is foreign or stale",
            ),
            Self::SafetyStore(error) => write!(formatter, "safety store: {error}"),
            Self::SafetyCapabilityMismatch => formatter.write_str(
                "authenticated-genesis h1 takeover Safety capability is foreign or stale",
            ),
            Self::ApplicationTakeover(error) => {
                write!(formatter, "application obligation takeover: {error}")
            }
            Self::ApplicationStable(error) => {
                write!(formatter, "application stable recovery: {error}")
            }
            Self::ApplicationCapabilityMismatch => formatter
                .write_str("authenticated-genesis h1 takeover App capability is foreign or stale"),
            Self::Core(error) => write!(formatter, "Core h1 takeover: {error}"),
            Self::CompletedClosureMismatch => {
                formatter.write_str("authenticated-genesis h1 takeover completed closure differs")
            }
            Self::StoreParentIdentityChanged => formatter
                .write_str("authenticated-genesis h1 takeover store parent identity changed"),
            Self::StartupAuditWorkerUnavailable => formatter
                .write_str("authenticated-genesis h1 takeover startup audit worker is unavailable"),
        }
    }
}

impl std::error::Error for PocoNodeAuthenticatedGenesisH1TakeoverErrorV0 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidConfiguration(error) => Some(error),
            Self::SignerJournal(error) => Some(error),
            Self::SafetyStore(error) => Some(error),
            Self::ApplicationTakeover(error) => Some(error),
            Self::ApplicationStable(error) => Some(error),
            Self::Core(_) => None,
            Self::PreparedBootstrapMismatch
            | Self::SignerCapabilityMismatch
            | Self::SafetyCapabilityMismatch
            | Self::ApplicationCapabilityMismatch
            | Self::CompletedClosureMismatch
            | Self::StoreParentIdentityChanged
            | Self::StartupAuditWorkerUnavailable => None,
        }
    }
}

impl From<SignerJournalErrorV0> for PocoNodeAuthenticatedGenesisH1TakeoverErrorV0 {
    fn from(error: SignerJournalErrorV0) -> Self {
        Self::SignerJournal(error)
    }
}

impl From<SafetyStoreErrorV0> for PocoNodeAuthenticatedGenesisH1TakeoverErrorV0 {
    fn from(error: SafetyStoreErrorV0) -> Self {
        Self::SafetyStore(error)
    }
}

impl From<NativeAuthenticatedGenesisH1ObligationTakeoverErrorV0>
    for PocoNodeAuthenticatedGenesisH1TakeoverErrorV0
{
    fn from(error: NativeAuthenticatedGenesisH1ObligationTakeoverErrorV0) -> Self {
        Self::ApplicationTakeover(error)
    }
}

impl From<NativeAuthenticatedGenesisH1StableRecoveryErrorV0>
    for PocoNodeAuthenticatedGenesisH1TakeoverErrorV0
{
    fn from(error: NativeAuthenticatedGenesisH1StableRecoveryErrorV0) -> Self {
        Self::ApplicationStable(error)
    }
}

impl From<CoreError> for PocoNodeAuthenticatedGenesisH1TakeoverErrorV0 {
    fn from(error: CoreError) -> Self {
        Self::Core(error)
    }
}

/// Copy-only point-in-time facts from the final Safety/App/Safety plus signer
/// join. They grant no authority and are not a continuously fresh lease.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PocoNodeAuthenticatedGenesisH1TakeoverFactsV0 {
    mode: PocoNodeAuthenticatedGenesisH1TakeoverModeV0,
    source: PocoNodeAuthenticatedGenesisH1TakeoverSourceV0,
    carrier_binding_ref: [u8; 32],
    block_id: BlockId,
    validation_id: ValidationId,
    valid_result_checksum: [u8; 32],
    safety_revision: u64,
    safety_journal_id: [u8; 32],
    safety_core_config_ref: [u8; 32],
    safety_state_record_checksum: [u8; 32],
    safety_chain_checksum: [u8; 32],
    application_host_config_ref: [u8; 32],
    application_delivered_job_row_checksum: [u8; 32],
    application_acked_job_row_checksum: [u8; 32],
    application_outbox_checksum: [u8; 32],
    application_artifact_checksum: [u8; 32],
    application_overlay_checksum: [u8; 32],
    application_completion_carrier_checksum: [u8; 32],
    signer_journal_id: [u8; 32],
    signer_profile_checksum: [u8; 32],
    signer_exact_watermark: SignerWatermarkV0,
}

impl PocoNodeAuthenticatedGenesisH1TakeoverFactsV0 {
    pub const fn mode(self) -> PocoNodeAuthenticatedGenesisH1TakeoverModeV0 {
        self.mode
    }
    pub const fn source(self) -> PocoNodeAuthenticatedGenesisH1TakeoverSourceV0 {
        self.source
    }
    pub const fn carrier_binding_ref(self) -> [u8; 32] {
        self.carrier_binding_ref
    }
    pub const fn block_id(self) -> BlockId {
        self.block_id
    }
    pub const fn validation_id(self) -> ValidationId {
        self.validation_id
    }
    pub const fn valid_result_checksum(self) -> [u8; 32] {
        self.valid_result_checksum
    }
    pub const fn safety_revision(self) -> u64 {
        self.safety_revision
    }
    pub const fn safety_journal_id(self) -> [u8; 32] {
        self.safety_journal_id
    }
    pub const fn safety_core_config_ref(self) -> [u8; 32] {
        self.safety_core_config_ref
    }
    pub const fn safety_state_record_checksum(self) -> [u8; 32] {
        self.safety_state_record_checksum
    }
    pub const fn safety_chain_checksum(self) -> [u8; 32] {
        self.safety_chain_checksum
    }
    pub const fn application_host_config_ref(self) -> [u8; 32] {
        self.application_host_config_ref
    }
    pub const fn application_delivered_job_row_checksum(self) -> [u8; 32] {
        self.application_delivered_job_row_checksum
    }
    pub const fn application_acked_job_row_checksum(self) -> [u8; 32] {
        self.application_acked_job_row_checksum
    }
    pub const fn application_outbox_checksum(self) -> [u8; 32] {
        self.application_outbox_checksum
    }
    pub const fn application_artifact_checksum(self) -> [u8; 32] {
        self.application_artifact_checksum
    }
    pub const fn application_overlay_checksum(self) -> [u8; 32] {
        self.application_overlay_checksum
    }
    pub const fn application_completion_carrier_checksum(self) -> [u8; 32] {
        self.application_completion_carrier_checksum
    }
    pub const fn signer_journal_id(self) -> [u8; 32] {
        self.signer_journal_id
    }
    pub const fn signer_profile_checksum(self) -> [u8; 32] {
        self.signer_profile_checksum
    }
    pub const fn signer_exact_watermark(self) -> SignerWatermarkV0 {
        self.signer_exact_watermark
    }
    pub const fn signer_activated(self) -> bool {
        false
    }
    pub const fn application_authorities_installed(self) -> bool {
        false
    }
    pub const fn network_started(self) -> bool {
        false
    }
    pub const fn timer_started(self) -> bool {
        false
    }
    pub const fn finalization_started(self) -> bool {
        false
    }
    pub const fn production_activation_enabled(self) -> bool {
        false
    }
}

enum PocoNodeAuthenticatedGenesisH1TakeoverApplicationOwnerV0 {
    Obligation(Box<NativeAuthenticatedGenesisH1ObligationTakeoverCompletedHostV0>),
    Stable(Box<NativeAuthenticatedGenesisH1StableApplicationHostV0>),
}

/// Inert three-owner result of unified existing-only h1 recovery.
///
/// ```compile_fail
/// use trnm_poco_node::PocoNodeAuthenticatedGenesisH1TakeoverHostV0;
/// fn require_clone<T: Clone>() {}
/// require_clone::<PocoNodeAuthenticatedGenesisH1TakeoverHostV0<()>>();
/// ```
///
/// ```compile_fail
/// use trnm_poco_node::PocoNodeAuthenticatedGenesisH1TakeoverHostV0;
/// fn escape<W>(host: &mut PocoNodeAuthenticatedGenesisH1TakeoverHostV0<W>) {
///     let _ = host.core();
///     let _ = host.step();
///     let _ = host.activate_v0();
///     let _ = host.sign();
///     let _ = host.finalize();
///     let _ = host.into_parts();
/// }
/// ```
#[must_use = "the inert takeover owner must remain live while its facts are trusted"]
pub struct PocoNodeAuthenticatedGenesisH1TakeoverHostV0<W> {
    safety_store: SqliteSafetyStateStoreV0<StrictEd25519Verifier>,
    application_owner: PocoNodeAuthenticatedGenesisH1TakeoverApplicationOwnerV0,
    pinned_signer: PinnedSqliteSignerJournalV0<W>,
    facts: PocoNodeAuthenticatedGenesisH1TakeoverFactsV0,
}

impl<W> PocoNodeAuthenticatedGenesisH1TakeoverHostV0<W> {
    pub const fn facts(&self) -> PocoNodeAuthenticatedGenesisH1TakeoverFactsV0 {
        self.facts
    }
}

impl<W> fmt::Debug for PocoNodeAuthenticatedGenesisH1TakeoverHostV0<W> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = (&self.safety_store, &self.pinned_signer);
        match &self.application_owner {
            PocoNodeAuthenticatedGenesisH1TakeoverApplicationOwnerV0::Obligation(owner) => {
                let _ = owner;
            }
            PocoNodeAuthenticatedGenesisH1TakeoverApplicationOwnerV0::Stable(owner) => {
                let _ = owner;
            }
        }
        formatter
            .debug_struct("PocoNodeAuthenticatedGenesisH1TakeoverHostV0")
            .field("facts", &self.facts)
            .finish_non_exhaustive()
    }
}

impl<W: ExternalMonotonicWatermarkV0> PocoNodeAuthenticatedGenesisH1TakeoverHostV0<W> {
    /// Opens only existing owners and closes either exact rev1 O+A/R/P/D or
    /// exact rev2 C+D/C+K to one inert C+K result. The signer is pinned and
    /// confirmed Exact before Safety/App are opened. No external CAS is made.
    #[allow(clippy::result_large_err)]
    pub fn open_existing_and_complete_exact_v0(
        config: PocoNodeAuthenticatedGenesisH1TakeoverConfigV0,
        prepared: PreparedAuthenticatedGenesisApplicationBootstrapV0,
        external_watermark: W,
    ) -> Result<Self, PocoNodeAuthenticatedGenesisH1TakeoverErrorV0>
    where
        W: Send,
    {
        std::thread::scope(|scope| {
            let worker = std::thread::Builder::new()
                .name("poco-node-authenticated-genesis-h1-takeover-audit-v0".to_string())
                .stack_size(TAKEOVER_STARTUP_AUDIT_STACK_BYTES_V0)
                .spawn_scoped(scope, move || {
                    Self::open_existing_on_startup_audit_stack_v0(
                        config,
                        prepared,
                        external_watermark,
                    )
                })
                .map_err(|_| {
                    PocoNodeAuthenticatedGenesisH1TakeoverErrorV0::StartupAuditWorkerUnavailable
                })?;
            worker.join().map_err(|_| {
                PocoNodeAuthenticatedGenesisH1TakeoverErrorV0::StartupAuditWorkerUnavailable
            })?
        })
    }

    fn open_existing_on_startup_audit_stack_v0(
        config: PocoNodeAuthenticatedGenesisH1TakeoverConfigV0,
        prepared: PreparedAuthenticatedGenesisApplicationBootstrapV0,
        external_watermark: W,
    ) -> Result<Self, PocoNodeAuthenticatedGenesisH1TakeoverErrorV0> {
        let PocoNodeAuthenticatedGenesisCommissioningConfigV0 {
            safety_store_path,
            safety_store_profile,
            signer_journal_path,
            signer_journal_profile,
            application,
            store_parents,
        } = config.inner;
        let core_config = safety_store_profile.core_config().clone();
        validate_prepared_bootstrap_v0(
            &core_config,
            safety_store_profile.record_limits(),
            &prepared,
        )
        .map_err(|_| Self::prepared_mismatch_v0())?;
        let safety_core_config_ref = prepared.safety_state_record_config_ref_v0();
        let application_path = application
            .state_path
            .as_deref()
            .ok_or_else(Self::prepared_mismatch_v0)?
            .to_path_buf();
        let inactive_expectation =
            PreparedNativeAuthenticatedGenesisH1InactiveExpectationV0::new_v0(
                &core_config,
                &prepared,
                &application,
            )
            .map_err(|_| Self::prepared_mismatch_v0())?;

        revalidate_takeover_paths_v0(
            &safety_store_path,
            &signer_journal_path,
            &application_path,
            store_parents,
        )?;

        // Strict signer-first ordering. This pinned owner has no signing or
        // CAS method and remains live across the complete Safety/App flow.
        let mut pinned_signer = PinnedSqliteSignerJournalV0::open_existing_v0(
            &signer_journal_path,
            signer_journal_profile,
            external_watermark,
        )?;
        let initial_signer = pinned_signer.reconciliation_facts();
        validate_initial_virgin_signer_v0(&pinned_signer, initial_signer, &core_config)
            .map_err(map_commissioning_validation_v0)?;
        let confirmed_start_signer = pinned_signer.confirm_node_checkpoint_head_exact_v0()?;
        validate_confirmed_virgin_signer_v0(
            &pinned_signer,
            &signer_journal_path,
            initial_signer,
            &confirmed_start_signer,
            &core_config,
        )
        .map_err(map_commissioning_validation_v0)?;
        drop(confirmed_start_signer);

        revalidate_takeover_paths_v0(
            &safety_store_path,
            &signer_journal_path,
            &application_path,
            store_parents,
        )?;
        let (mut safety_store, cut) =
            SqliteSafetyStateStoreV0::open_existing_authenticated_genesis_application_h1_dispatch_v0(
                &safety_store_path,
                safety_store_profile,
                StrictEd25519Verifier,
            )?;

        let (application_owner, facts_without_signer) = match cut {
            AuthenticatedGenesisApplicationH1ExistingCutV0::ObligationRev1(lineage) => {
                let (revision_zero, revision_one) = lineage.into_core_states_v0();
                let expected_revision_zero = revision_zero.clone();
                let expected_revision_one = revision_one.clone();
                let takeover =
                    Core::begin_authenticated_genesis_application_h1_obligation_takeover_v0(
                        core_config.clone(),
                        prepared,
                        revision_one,
                        &StrictEd25519Verifier,
                    )?;
                let rebound = safety_store
                    .activate_and_rebind_authenticated_genesis_application_h1_obligation_takeover_exact_v0(
                        takeover,
                    )?;
                let (activation, request) = rebound
                    .acknowledge_and_release_validation_request_v0(&StrictEd25519Verifier)?;

                let before_app = safety_store
                    .authenticated_genesis_application_h1_obligation_lineage_readback_v0()?;
                let (before_zero, before_one) = before_app.into_core_states_v0();
                if before_zero != expected_revision_zero || before_one != expected_revision_one {
                    return Err(Self::safety_mismatch_v0());
                }

                let app_config = NativeAuthenticatedGenesisH1ObligationTakeoverConfigV0::new(
                    application,
                    inactive_expectation,
                )?;
                let app_host =
                    NativeAuthenticatedGenesisH1ObligationTakeoverHostV0::open_existing_v0(
                        app_config,
                    )?;
                let app_cut = app_host.inspect_exact_cut_v0(&request)?;
                let source = takeover_source_v0(app_cut.source_v0());

                let after_app = safety_store
                    .authenticated_genesis_application_h1_obligation_lineage_readback_v0()?;
                let (after_zero, after_one) = after_app.into_core_states_v0();
                if after_zero != expected_revision_zero || after_one != expected_revision_one {
                    return Err(Self::safety_mismatch_v0());
                }

                let completed_owner = app_host.take_over_and_complete_v0(
                    app_cut,
                    activation,
                    request,
                    &mut safety_store,
                    &safety_store_path,
                    &StrictEd25519Verifier,
                )?;
                if !completed_owner.belongs_to_host_at_path_v0(&application_path) {
                    return Err(Self::application_mismatch_v0());
                }

                let safety_before_app = safety_store.confirmed_native_valid_head_v0()?;
                validate_live_native_valid_capability_v0(
                    &safety_store,
                    &safety_store_path,
                    &safety_before_app,
                )?;
                let application_before = completed_owner.application_facts_v0();
                let application_final = completed_owner.fresh_confirm_capability_exact_v0()?;
                if !application_final
                    .belongs_to_host_at_path_v0(&completed_owner, &application_path)
                    || application_final.validation_id_v0()
                        != completed_owner.core_facts_v0().validation_id_v0()
                    || application_final.safety_revision_v0() != 2
                    || application_final.authenticated_parent_binding_ref_v0()
                        != completed_owner
                            .core_facts_v0()
                            .authenticated_parent_binding_ref_v0()
                    || application_before != application_final.application_facts_v0()
                {
                    return Err(Self::application_mismatch_v0());
                }
                let safety_final = safety_store.confirmed_native_valid_head_v0()?;
                validate_live_native_valid_capability_v0(
                    &safety_store,
                    &safety_store_path,
                    &safety_final,
                )?;
                if !same_native_valid_head_v0(&safety_before_app, &safety_final) {
                    return Err(Self::safety_mismatch_v0());
                }
                validate_takeover_completed_closure_v0(
                    completed_owner.core_facts_v0(),
                    application_final.application_facts_v0(),
                    &safety_final,
                )?;

                let facts = CommonCompletedFactsV0::from_takeover_v0(
                    source,
                    completed_owner.core_facts_v0(),
                    application_final.application_facts_v0(),
                    &safety_final,
                    safety_store.journal_id_v0(),
                    safety_core_config_ref,
                );
                drop((application_final, safety_before_app, safety_final));
                (
                    PocoNodeAuthenticatedGenesisH1TakeoverApplicationOwnerV0::Obligation(Box::new(
                        completed_owner,
                    )),
                    facts,
                )
            }
            AuthenticatedGenesisApplicationH1ExistingCutV0::StableNativeValidRev2(lineage) => {
                let (revision_one, revision_two) = lineage.into_core_states_v0();
                let session =
                    Core::begin_authenticated_genesis_application_h1_stable_native_valid_recovery_v0(
                        core_config.clone(),
                        prepared,
                        revision_one,
                        revision_two,
                        &StrictEd25519Verifier,
                    )?;
                let challenge = session.challenge_v0();
                let initial_safety = safety_store
                    .confirmed_authenticated_genesis_application_h1_stable_native_valid_head_exact_v0(
                        challenge,
                    )?;
                validate_stable_safety_capability_v0(
                    challenge,
                    &safety_store,
                    &safety_store_path,
                    &initial_safety,
                )
                .map_err(map_stable_validation_v0)?;

                let app_config = NativeAuthenticatedGenesisH1StableRecoveryConfigV0::new(
                    application,
                    inactive_expectation,
                )?;
                let mut app_host =
                    NativeAuthenticatedGenesisH1StableApplicationHostV0::open_existing_v0(
                        app_config,
                    )?;
                let application_capability = app_host.recover_or_confirm_exact_v0(
                    challenge,
                    &safety_store,
                    &safety_store_path,
                    initial_safety,
                )?;
                validate_stable_application_capability_v0(
                    challenge,
                    &app_host,
                    &application_path,
                    &application_capability,
                )
                .map_err(map_stable_validation_v0)?;
                let source = match application_capability.source_v0() {
                    NativeAuthenticatedGenesisH1StableApplicationSourceV0::Delivered => {
                        PocoNodeAuthenticatedGenesisH1TakeoverSourceV0::StableDeliveredToAcked
                    }
                    NativeAuthenticatedGenesisH1StableApplicationSourceV0::Acked => {
                        PocoNodeAuthenticatedGenesisH1TakeoverSourceV0::StableAcked
                    }
                };

                let safety_before_app = safety_store
                    .confirmed_authenticated_genesis_application_h1_stable_native_valid_head_exact_v0(
                        challenge,
                    )?;
                validate_stable_safety_capability_v0(
                    challenge,
                    &safety_store,
                    &safety_store_path,
                    &safety_before_app,
                )
                .map_err(map_stable_validation_v0)?;
                let mut final_application = app_host.fresh_confirm_exact_v0(
                    challenge,
                    &safety_store,
                    &safety_store_path,
                )?;
                validate_stable_application_capability_v0(
                    challenge,
                    &app_host,
                    &application_path,
                    &final_application,
                )
                .map_err(map_stable_validation_v0)?;
                if !same_stable_application_poststate_v0(
                    &application_capability,
                    &final_application,
                ) {
                    return Err(Self::application_mismatch_v0());
                }
                let final_safety = safety_store
                    .confirmed_authenticated_genesis_application_h1_stable_native_valid_head_exact_v0(
                        challenge,
                    )?;
                validate_stable_safety_capability_v0(
                    challenge,
                    &safety_store,
                    &safety_store_path,
                    &final_safety,
                )
                .map_err(map_stable_validation_v0)?;
                if final_application.safety_head_facts_v0() != final_safety.safety_head_facts_v0() {
                    return Err(Self::safety_mismatch_v0());
                }

                let attestation = challenge.attest_authenticated_reconciliation_v0(
                    final_safety.safety_head_facts_v0().clone(),
                    &mut final_application,
                )?;
                let mut replay = session.reconcile_and_complete_v0(attestation)?;
                let recovered = replay.release_inert_completed_facts_v0()?;
                validate_stable_recovered_closure_v0(&recovered, &final_application, &final_safety)
                    .map_err(map_stable_validation_v0)?;

                let facts = CommonCompletedFactsV0::from_stable_v0(
                    source,
                    &recovered,
                    &final_application,
                    &final_safety,
                    safety_core_config_ref,
                );
                drop((
                    application_capability,
                    safety_before_app,
                    final_application,
                    final_safety,
                    recovered,
                ));
                (
                    PocoNodeAuthenticatedGenesisH1TakeoverApplicationOwnerV0::Stable(Box::new(
                        app_host,
                    )),
                    facts,
                )
            }
        };

        // No durable operation occurs after the final Safety/App/Safety join.
        // The external watermark load below is the return linearization point
        // and never performs compare-and-advance.
        revalidate_takeover_paths_v0(
            &safety_store_path,
            &signer_journal_path,
            &application_path,
            store_parents,
        )?;
        let final_signer = pinned_signer.confirm_node_checkpoint_head_exact_v0()?;
        validate_confirmed_virgin_signer_v0(
            &pinned_signer,
            &signer_journal_path,
            initial_signer,
            &final_signer,
            &core_config,
        )
        .map_err(map_commissioning_validation_v0)?;

        let facts = facts_without_signer.with_signer_v0(
            final_signer.journal_id(),
            final_signer.profile_checksum(),
            final_signer.exact_watermark(),
        );
        drop(final_signer);
        Ok(Self {
            safety_store,
            application_owner,
            pinned_signer,
            facts,
        })
    }

    const fn prepared_mismatch_v0() -> PocoNodeAuthenticatedGenesisH1TakeoverErrorV0 {
        PocoNodeAuthenticatedGenesisH1TakeoverErrorV0::PreparedBootstrapMismatch
    }

    const fn safety_mismatch_v0() -> PocoNodeAuthenticatedGenesisH1TakeoverErrorV0 {
        PocoNodeAuthenticatedGenesisH1TakeoverErrorV0::SafetyCapabilityMismatch
    }

    const fn application_mismatch_v0() -> PocoNodeAuthenticatedGenesisH1TakeoverErrorV0 {
        PocoNodeAuthenticatedGenesisH1TakeoverErrorV0::ApplicationCapabilityMismatch
    }
}

#[derive(Debug, Clone, Copy)]
struct CommonCompletedFactsV0 {
    source: PocoNodeAuthenticatedGenesisH1TakeoverSourceV0,
    carrier_binding_ref: [u8; 32],
    block_id: BlockId,
    validation_id: ValidationId,
    valid_result_checksum: [u8; 32],
    safety_revision: u64,
    safety_journal_id: [u8; 32],
    safety_core_config_ref: [u8; 32],
    safety_state_record_checksum: [u8; 32],
    safety_chain_checksum: [u8; 32],
    application_host_config_ref: [u8; 32],
    application_delivered_job_row_checksum: [u8; 32],
    application_acked_job_row_checksum: [u8; 32],
    application_outbox_checksum: [u8; 32],
    application_artifact_checksum: [u8; 32],
    application_overlay_checksum: [u8; 32],
    application_completion_carrier_checksum: [u8; 32],
}

impl CommonCompletedFactsV0 {
    fn from_takeover_v0(
        source: PocoNodeAuthenticatedGenesisH1TakeoverSourceV0,
        core: &AuthenticatedGenesisApplicationH1CompletedV0,
        application: NativeAuthenticatedGenesisH1CompletedAppConfirmationV0,
        safety: &ConfirmedNativeValidHeadV0,
        safety_journal_id: [u8; 32],
        safety_core_config_ref: [u8; 32],
    ) -> Self {
        Self {
            source,
            carrier_binding_ref: core.authenticated_parent_binding_ref_v0(),
            block_id: core.proposal_v0().block().id(),
            validation_id: core.validation_id_v0(),
            valid_result_checksum: application.valid_result_checksum_v0(),
            safety_revision: safety.revision(),
            safety_journal_id,
            safety_core_config_ref,
            safety_state_record_checksum: safety.state_record_checksum(),
            safety_chain_checksum: safety.chain_checksum(),
            application_host_config_ref: application.application_host_config_ref_v0(),
            application_delivered_job_row_checksum: application.delivered_job_row_checksum_v0(),
            application_acked_job_row_checksum: application.acked_job_row_checksum_v0(),
            application_outbox_checksum: application.outbox_checksum_v0(),
            application_artifact_checksum: application.artifact_checksum_v0(),
            application_overlay_checksum: application.overlay_checksum_v0(),
            application_completion_carrier_checksum: application.completion_carrier_checksum_v0(),
        }
    }

    fn from_stable_v0(
        source: PocoNodeAuthenticatedGenesisH1TakeoverSourceV0,
        recovered: &AuthenticatedGenesisApplicationH1StableNativeValidRecoveredFactsV0,
        application: &trnm_consensus_app::ConfirmedNativeAuthenticatedGenesisH1StableApplicationV0,
        safety: &trnm_consensus_safety_store::ConfirmedAuthenticatedGenesisApplicationH1StableNativeValidHeadV0,
        safety_core_config_ref: [u8; 32],
    ) -> Self {
        Self {
            source,
            carrier_binding_ref: recovered.authenticated_parent_binding_ref_v0(),
            block_id: recovered.proposal_v0().block().id(),
            validation_id: application.validation_id_v0(),
            valid_result_checksum: application.valid_result_checksum_v0(),
            safety_revision: safety.state_v0().revision(),
            safety_journal_id: safety.journal_id_v0(),
            safety_core_config_ref,
            safety_state_record_checksum: safety.state_record_checksum_v0(),
            safety_chain_checksum: safety.chain_checksum_v0(),
            application_host_config_ref: application.application_host_config_ref_v0(),
            application_delivered_job_row_checksum: application.delivered_job_row_checksum_v0(),
            application_acked_job_row_checksum: application.acked_job_row_checksum_v0(),
            application_outbox_checksum: application.outbox_checksum_v0(),
            application_artifact_checksum: application.artifact_checksum_v0(),
            application_overlay_checksum: application.overlay_checksum_v0(),
            application_completion_carrier_checksum: application.completion_carrier_checksum_v0(),
        }
    }

    const fn with_signer_v0(
        self,
        signer_journal_id: [u8; 32],
        signer_profile_checksum: [u8; 32],
        signer_exact_watermark: SignerWatermarkV0,
    ) -> PocoNodeAuthenticatedGenesisH1TakeoverFactsV0 {
        PocoNodeAuthenticatedGenesisH1TakeoverFactsV0 {
            mode: PocoNodeAuthenticatedGenesisH1TakeoverModeV0::AuthenticatedGenesisApplicationEmptyH1RecoveredInert,
            source: self.source,
            carrier_binding_ref: self.carrier_binding_ref,
            block_id: self.block_id,
            validation_id: self.validation_id,
            valid_result_checksum: self.valid_result_checksum,
            safety_revision: self.safety_revision,
            safety_journal_id: self.safety_journal_id,
            safety_core_config_ref: self.safety_core_config_ref,
            safety_state_record_checksum: self.safety_state_record_checksum,
            safety_chain_checksum: self.safety_chain_checksum,
            application_host_config_ref: self.application_host_config_ref,
            application_delivered_job_row_checksum: self.application_delivered_job_row_checksum,
            application_acked_job_row_checksum: self.application_acked_job_row_checksum,
            application_outbox_checksum: self.application_outbox_checksum,
            application_artifact_checksum: self.application_artifact_checksum,
            application_overlay_checksum: self.application_overlay_checksum,
            application_completion_carrier_checksum: self.application_completion_carrier_checksum,
            signer_journal_id,
            signer_profile_checksum,
            signer_exact_watermark,
        }
    }
}

fn takeover_source_v0(
    source: NativeAuthenticatedGenesisH1ObligationTakeoverSourceV0,
) -> PocoNodeAuthenticatedGenesisH1TakeoverSourceV0 {
    match source {
        NativeAuthenticatedGenesisH1ObligationTakeoverSourceV0::Absent => {
            PocoNodeAuthenticatedGenesisH1TakeoverSourceV0::ObligationAbsent
        }
        NativeAuthenticatedGenesisH1ObligationTakeoverSourceV0::Reserved => {
            PocoNodeAuthenticatedGenesisH1TakeoverSourceV0::ObligationReserved
        }
        NativeAuthenticatedGenesisH1ObligationTakeoverSourceV0::CallbackPending => {
            PocoNodeAuthenticatedGenesisH1TakeoverSourceV0::ObligationCallbackPending
        }
        NativeAuthenticatedGenesisH1ObligationTakeoverSourceV0::Delivered => {
            PocoNodeAuthenticatedGenesisH1TakeoverSourceV0::ObligationDelivered
        }
    }
}

fn revalidate_takeover_paths_v0(
    safety_path: &Path,
    signer_path: &Path,
    application_path: &Path,
    expected: ProcessStoreParentIdentitiesV0,
) -> Result<(), PocoNodeAuthenticatedGenesisH1TakeoverErrorV0> {
    revalidate_process_store_paths_v0(safety_path, signer_path, application_path, expected)
        .map_err(|_| PocoNodeAuthenticatedGenesisH1TakeoverErrorV0::StoreParentIdentityChanged)
}

fn map_commissioning_validation_v0(
    error: PocoNodeAuthenticatedGenesisCommissioningErrorV0,
) -> PocoNodeAuthenticatedGenesisH1TakeoverErrorV0 {
    match error {
        PocoNodeAuthenticatedGenesisCommissioningErrorV0::SignerJournal(error) => {
            PocoNodeAuthenticatedGenesisH1TakeoverErrorV0::SignerJournal(error)
        }
        PocoNodeAuthenticatedGenesisCommissioningErrorV0::SignerNotVirgin
        | PocoNodeAuthenticatedGenesisCommissioningErrorV0::SignerCapabilityMismatch => {
            PocoNodeAuthenticatedGenesisH1TakeoverErrorV0::SignerCapabilityMismatch
        }
        other => PocoNodeAuthenticatedGenesisH1TakeoverErrorV0::InvalidConfiguration(other),
    }
}

fn map_stable_validation_v0(
    error: PocoNodeAuthenticatedGenesisH1StableRecoveryErrorV0,
) -> PocoNodeAuthenticatedGenesisH1TakeoverErrorV0 {
    match error {
        PocoNodeAuthenticatedGenesisH1StableRecoveryErrorV0::SignerJournal(error) => {
            PocoNodeAuthenticatedGenesisH1TakeoverErrorV0::SignerJournal(error)
        }
        PocoNodeAuthenticatedGenesisH1StableRecoveryErrorV0::SignerCapabilityMismatch => {
            PocoNodeAuthenticatedGenesisH1TakeoverErrorV0::SignerCapabilityMismatch
        }
        PocoNodeAuthenticatedGenesisH1StableRecoveryErrorV0::SafetyStore(error) => {
            PocoNodeAuthenticatedGenesisH1TakeoverErrorV0::SafetyStore(error)
        }
        PocoNodeAuthenticatedGenesisH1StableRecoveryErrorV0::SafetyCapabilityMismatch => {
            PocoNodeAuthenticatedGenesisH1TakeoverErrorV0::SafetyCapabilityMismatch
        }
        PocoNodeAuthenticatedGenesisH1StableRecoveryErrorV0::Application(error) => {
            PocoNodeAuthenticatedGenesisH1TakeoverErrorV0::ApplicationStable(error)
        }
        PocoNodeAuthenticatedGenesisH1StableRecoveryErrorV0::ApplicationCapabilityMismatch => {
            PocoNodeAuthenticatedGenesisH1TakeoverErrorV0::ApplicationCapabilityMismatch
        }
        PocoNodeAuthenticatedGenesisH1StableRecoveryErrorV0::Core(error) => {
            PocoNodeAuthenticatedGenesisH1TakeoverErrorV0::Core(error)
        }
        PocoNodeAuthenticatedGenesisH1StableRecoveryErrorV0::RecoveredClosureMismatch => {
            PocoNodeAuthenticatedGenesisH1TakeoverErrorV0::CompletedClosureMismatch
        }
        PocoNodeAuthenticatedGenesisH1StableRecoveryErrorV0::StoreParentIdentityChanged => {
            PocoNodeAuthenticatedGenesisH1TakeoverErrorV0::StoreParentIdentityChanged
        }
        PocoNodeAuthenticatedGenesisH1StableRecoveryErrorV0::InvalidConfiguration
        | PocoNodeAuthenticatedGenesisH1StableRecoveryErrorV0::PreparedBootstrapMismatch => {
            PocoNodeAuthenticatedGenesisH1TakeoverErrorV0::PreparedBootstrapMismatch
        }
    }
}

fn validate_live_native_valid_capability_v0(
    store: &SqliteSafetyStateStoreV0<StrictEd25519Verifier>,
    expected_path: &Path,
    confirmed: &ConfirmedNativeValidHeadV0,
) -> Result<(), PocoNodeAuthenticatedGenesisH1TakeoverErrorV0> {
    if !confirmed.belongs_to_store_at_path_v0(store, expected_path)
        || confirmed.journal_id_v0() != store.journal_id_v0()
        || confirmed.verifier_profile_ref_v0() != store.verifier_profile_ref_v0()
        || confirmed.revision() != 2
        || confirmed.state_record_checksum() == [0; 32]
        || confirmed.chain_checksum() == [0; 32]
    {
        return Err(PocoNodeAuthenticatedGenesisH1TakeoverErrorV0::SafetyCapabilityMismatch);
    }
    Ok(())
}

fn same_native_valid_head_v0(
    left: &ConfirmedNativeValidHeadV0,
    right: &ConfirmedNativeValidHeadV0,
) -> bool {
    left.journal_id_v0() == right.journal_id_v0()
        && left.verifier_profile_ref_v0() == right.verifier_profile_ref_v0()
        && left.state() == right.state()
        && left.transition_context() == right.transition_context()
        && left.state_record_checksum() == right.state_record_checksum()
        && left.chain_checksum() == right.chain_checksum()
}

fn validate_takeover_completed_closure_v0(
    core: &AuthenticatedGenesisApplicationH1CompletedV0,
    application: NativeAuthenticatedGenesisH1CompletedAppConfirmationV0,
    safety: &ConfirmedNativeValidHeadV0,
) -> Result<(), PocoNodeAuthenticatedGenesisH1TakeoverErrorV0> {
    let completion = core.completion_v0();
    let terminal = core.terminal_fact_v0();
    let transition = safety.transition();
    let validation_id = core.validation_id_v0();
    if core.authenticated_parent_binding_ref_v0() == [0; 32]
        || core.safety_revision_v0() != 2
        || completion.first_recorded_revision() != 2
        || terminal.first_recorded_revision() != 2
        || completion.id() != validation_id
        || terminal.block_id() != validation_id.block_id()
        || terminal.valid_overlay().is_none()
        || core.proposal_v0().block().id() != validation_id.block_id()
        || application.validation_id_v0() != validation_id
        || application.valid_result_checksum_v0() != transition.valid_result_checksum()
        || application.application_host_config_ref_v0() != transition.application_host_config_ref()
        || application.delivered_job_row_checksum_v0() != transition.delivered_job_row_checksum()
        || application.outbox_checksum_v0() != transition.outbox_checksum()
        || application.acked_job_row_checksum_v0() == [0; 32]
        || application.artifact_checksum_v0() == [0; 32]
        || application.overlay_checksum_v0() == [0; 32]
        || application.completion_carrier_checksum_v0() == [0; 32]
        || transition.validation_id() != validation_id
        || transition.delivery_attempt() != 1
        || transition.completion_revision() != 2
        || safety.post_ack_action_v0() != trnm_consensus_core::NativeValidPostAckActionV0::None
        || safety.state().payload_validation_completions() != [completion.clone()]
        || safety.state().payload_terminal_facts() != [terminal]
    {
        return Err(PocoNodeAuthenticatedGenesisH1TakeoverErrorV0::CompletedClosureMismatch);
    }
    Ok(())
}
