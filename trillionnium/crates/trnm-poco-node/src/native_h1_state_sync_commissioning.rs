//! One-way fresh-genesis h1 promotion into the zero-Comet native stores.
//!
//! The join consumes Core's proof-carrying retirement product together with
//! the still-live source SafetyStore and virgin signer journal.  It installs
//! the exact proof-derived tag-4 Safety head, independently executes and
//! installs the same h1 as the native ApplicationStore trusted base, activates
//! only Core's replay-fenced h1 recovery owner, and commits generation zero in
//! the independent whole-node checkpoint CAS.  No signer activation, signing,
//! SignatureReady, broadcast, timer, ingress, or successor proposal is exposed.

use std::{
    error::Error,
    fmt, fs,
    path::{Path, PathBuf},
};

use sha2::{Digest, Sha256};
use trnm_consensus_core::{
    AuthenticatedGenesisApplicationH1StateSyncPromotionCandidateV0, Core, CoreConfig, CoreError,
    StateSyncAnchorRecoveryChallengeV0, StateSyncAnchorRecoveryReconcilerV0,
};
use trnm_consensus_crypto::StrictEd25519Verifier;
use trnm_consensus_safety_store::{
    ConfirmedSafetyNodeCheckpointFactsV0, SafetyStateStoreProfileV0, SafetyStoreErrorV0,
    SqliteSafetyStateStoreV0,
};
use trnm_consensus_signer_journal::{
    ConfirmedSignerNodeCheckpointFactsV0, ExternalMonotonicWatermarkV0,
    PinnedSqliteSignerJournalV0, SignerJournalErrorV0,
};
use trnm_consensus_types::{
    decode_application_payload_v0_exact, BlockId, CertificateId, StateRoot,
};
use trnm_native_application::{
    BlockIdV0, ChainIdV0, GenesisHashV0, Hash32V0, HeightV0, NativeBlockExecutionRequestV0,
    NativeExpectedBlockCommitmentsV0, ReceiptsRootV0, StateRootV0, ValidatorSetIdV0,
};
use trnm_native_execution_v0::{
    ConfirmedNativeH1StateSyncTrustedBaseV0, DurableNativeApplicationV0,
    NativeApplicationExecutionErrorV0, NativeH1StateSyncTrustedBaseRequestV0,
};

use crate::{
    derive_signer_watermark_scope_v0, ExternalNodeCheckpointDecodeErrorV0,
    ExternalNodeCheckpointFieldsV0, ExternalNodeCheckpointStoreErrorV0,
    ExternalNodeCheckpointStoreV0, ExternalNodeCheckpointV0, SqliteExternalNodeCheckpointStoreV0,
    STRICT_ED25519_VERIFIER_PROFILE_REF_V0,
};

const NATIVE_H1_HOST_CONFIG_DOMAIN_V0: &[u8] =
    b"trnm.poco-node.native-h1-state-sync.host-config.v0";
const NATIVE_H1_PROJECTION_DOMAIN_V0: &[u8] =
    b"trnm.poco-node.native-h1-state-sync.projection.schema-3.v0";
const NATIVE_H1_SAFETY_BINDING_DOMAIN_V0: &[u8] =
    b"trnm.poco-node.native-h1-state-sync.safety-binding.v0";
const NATIVE_H1_HEAD_ROW_DOMAIN_V0: &[u8] = b"trnm.poco-node.native-h1-state-sync.head-row.v0";
const NATIVE_H1_RECOVERY_CLOSURE_DOMAIN_V0: &[u8] =
    b"trnm.poco-node.native-h1-state-sync.recovery-closure.v0";

/// Linear, non-forgeable authority input for the native h1 promotion join.
///
/// Construction remains private to the Node crate.  The candidate itself has
/// no public constructor and can only be minted by consuming Core's exact
/// completed authenticated-genesis h1 owner.  Commissioning reauthenticates
/// the supplied source SafetyStore and signer rather than trusting this
/// wrapper's shape.
#[must_use = "the proof-carrying source authorities must be commissioned or discarded"]
pub struct PocoNodeNativeH1StateSyncPromotionSourceV0<W: ExternalMonotonicWatermarkV0> {
    candidate: AuthenticatedGenesisApplicationH1StateSyncPromotionCandidateV0,
    source_safety_store: SqliteSafetyStateStoreV0<StrictEd25519Verifier>,
    pinned_signer: PinnedSqliteSignerJournalV0<W>,
}

impl<W: ExternalMonotonicWatermarkV0> PocoNodeNativeH1StateSyncPromotionSourceV0<W> {
    #[allow(dead_code)]
    pub(crate) fn from_completed_authorities_v0(
        candidate: AuthenticatedGenesisApplicationH1StateSyncPromotionCandidateV0,
        source_safety_store: SqliteSafetyStateStoreV0<StrictEd25519Verifier>,
        pinned_signer: PinnedSqliteSignerJournalV0<W>,
    ) -> Self {
        Self {
            candidate,
            source_safety_store,
            pinned_signer,
        }
    }

    /// Consumes every source owner into one exact replay-fenced native host.
    pub fn commission_native_h1_state_sync_v0(
        self,
        config: PocoNodeNativeH1StateSyncCommissioningConfigV0,
    ) -> Result<
        PocoNodeNativeH1StateSyncCommissionedHostV0<W>,
        PocoNodeNativeH1StateSyncCommissioningErrorV0,
    > {
        commission_native_h1_state_sync_v0(self, config)
    }
}

impl<W: ExternalMonotonicWatermarkV0> fmt::Debug for PocoNodeNativeH1StateSyncPromotionSourceV0<W> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PocoNodeNativeH1StateSyncPromotionSourceV0")
            .field("proof_id", &self.candidate.proof_id_v0())
            .field("source_safety_path", &self.source_safety_store.path())
            .field("signer_path", &self.pinned_signer.path())
            .finish_non_exhaustive()
    }
}

/// Owned target namespaces and resource limits for one native h1 join.
pub struct PocoNodeNativeH1StateSyncCommissioningConfigV0 {
    target_safety_path: PathBuf,
    target_safety_record_limits: trnm_consensus_core::SafetyStateRecordLimitsV0,
    target_safety_maximum_database_bytes: usize,
    application: DurableNativeApplicationV0,
    checkpoint_store: SqliteExternalNodeCheckpointStoreV0,
}

impl PocoNodeNativeH1StateSyncCommissioningConfigV0 {
    pub fn new(
        target_safety_path: impl AsRef<Path>,
        target_safety_record_limits: trnm_consensus_core::SafetyStateRecordLimitsV0,
        target_safety_maximum_database_bytes: usize,
        application: DurableNativeApplicationV0,
        checkpoint_store: SqliteExternalNodeCheckpointStoreV0,
    ) -> Result<Self, PocoNodeNativeH1StateSyncCommissioningErrorV0> {
        let target_safety_path = target_safety_path.as_ref().to_path_buf();
        require_absolute_file_path_v0(&target_safety_path, "target safety path")?;
        require_disjoint_store_parents_v0(&[
            target_safety_path.as_path(),
            application.path(),
            checkpoint_store.database_path(),
        ])?;
        Ok(Self {
            target_safety_path,
            target_safety_record_limits,
            target_safety_maximum_database_bytes,
            application,
            checkpoint_store,
        })
    }
}

impl fmt::Debug for PocoNodeNativeH1StateSyncCommissioningConfigV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PocoNodeNativeH1StateSyncCommissioningConfigV0")
            .field("target_safety_path", &self.target_safety_path)
            .field("application_path", &self.application.path())
            .field("checkpoint_path", &self.checkpoint_store.database_path())
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PocoNodeNativeH1StateSyncCommissionedFactsV0 {
    proof_id: CertificateId,
    block_id: BlockId,
    height: u64,
    state_root: StateRoot,
    target_safety_journal_id: [u8; 32],
    native_application_store_id: [u8; 32],
    checkpoint_checksum: [u8; 32],
    replay_fenced: bool,
    signer_activated: bool,
}

impl PocoNodeNativeH1StateSyncCommissionedFactsV0 {
    pub const fn proof_id(self) -> CertificateId {
        self.proof_id
    }
    pub const fn block_id(self) -> BlockId {
        self.block_id
    }
    pub const fn height(self) -> u64 {
        self.height
    }
    pub const fn state_root(self) -> StateRoot {
        self.state_root
    }
    pub const fn target_safety_journal_id(self) -> [u8; 32] {
        self.target_safety_journal_id
    }
    pub const fn native_application_store_id(self) -> [u8; 32] {
        self.native_application_store_id
    }
    pub const fn checkpoint_checksum(self) -> [u8; 32] {
        self.checkpoint_checksum
    }
    pub const fn replay_fenced(self) -> bool {
        self.replay_fenced
    }
    pub const fn signer_activated(self) -> bool {
        self.signer_activated
    }
}

/// Live, replay-fenced owner produced by the complete native h1 join.
///
/// No owner or mutable subsystem escapes through the public API.  A later
/// in-crate successor protocol must consume this value through
/// `into_next_owner_v0`; it cannot reconstruct authority from `facts()`.
#[must_use = "the commissioned h1 owner keeps Core and every durable namespace live"]
#[allow(dead_code)]
pub struct PocoNodeNativeH1StateSyncCommissionedHostV0<W: ExternalMonotonicWatermarkV0> {
    core: Core,
    retired_source_safety_store: SqliteSafetyStateStoreV0<StrictEd25519Verifier>,
    target_safety_store: SqliteSafetyStateStoreV0<StrictEd25519Verifier>,
    application: DurableNativeApplicationV0,
    pinned_signer: PinnedSqliteSignerJournalV0<W>,
    checkpoint_store: SqliteExternalNodeCheckpointStoreV0,
    checkpoint: ExternalNodeCheckpointV0,
    h1_request: NativeH1StateSyncTrustedBaseRequestV0,
    facts: PocoNodeNativeH1StateSyncCommissionedFactsV0,
}

impl<W: ExternalMonotonicWatermarkV0> PocoNodeNativeH1StateSyncCommissionedHostV0<W> {
    pub const fn facts(&self) -> PocoNodeNativeH1StateSyncCommissionedFactsV0 {
        self.facts
    }

    #[allow(dead_code)]
    pub(crate) fn into_next_owner_v0(self) -> PocoNodeNativeH1StateSyncNextOwnerV0<W> {
        PocoNodeNativeH1StateSyncNextOwnerV0 {
            core: self.core,
            retired_source_safety_store: self.retired_source_safety_store,
            target_safety_store: self.target_safety_store,
            application: self.application,
            pinned_signer: self.pinned_signer,
            checkpoint_store: self.checkpoint_store,
            checkpoint: self.checkpoint,
            h1_request: self.h1_request,
        }
    }
}

impl<W: ExternalMonotonicWatermarkV0> fmt::Debug
    for PocoNodeNativeH1StateSyncCommissionedHostV0<W>
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PocoNodeNativeH1StateSyncCommissionedHostV0")
            .field("facts", &self.facts)
            .finish_non_exhaustive()
    }
}

/// Node-private, non-forgeable continuation owner above the h1 checkpoint.
///
/// This API intentionally retains all live owners, including the independent
/// checkpoint CAS.  It does not yet expose proposal admission because the h1
/// recovery Core is replay-only; h2/h3 successor authentication must consume
/// this owner before the signer may be activated.
#[allow(dead_code)]
pub(crate) struct PocoNodeNativeH1StateSyncNextOwnerV0<W: ExternalMonotonicWatermarkV0> {
    pub(super) core: Core,
    pub(super) retired_source_safety_store: SqliteSafetyStateStoreV0<StrictEd25519Verifier>,
    pub(super) target_safety_store: SqliteSafetyStateStoreV0<StrictEd25519Verifier>,
    pub(super) application: DurableNativeApplicationV0,
    pub(super) pinned_signer: PinnedSqliteSignerJournalV0<W>,
    pub(super) checkpoint_store: SqliteExternalNodeCheckpointStoreV0,
    pub(super) checkpoint: ExternalNodeCheckpointV0,
    pub(super) h1_request: NativeH1StateSyncTrustedBaseRequestV0,
}

#[derive(Debug)]
pub enum PocoNodeNativeH1StateSyncCommissioningErrorV0 {
    InvalidConfiguration(&'static str),
    SourceMismatch(&'static str),
    Core(CoreError),
    Safety(SafetyStoreErrorV0),
    Signer(SignerJournalErrorV0),
    Application(NativeApplicationExecutionErrorV0),
    Checkpoint(ExternalNodeCheckpointStoreErrorV0),
    CheckpointRecord(ExternalNodeCheckpointDecodeErrorV0),
}

impl fmt::Display for PocoNodeNativeH1StateSyncCommissioningErrorV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfiguration(field) => {
                write!(formatter, "invalid commissioning configuration: {field}")
            }
            Self::SourceMismatch(field) => write!(formatter, "native h1 source mismatch: {field}"),
            Self::Core(error) => {
                write!(formatter, "Core rejected native h1 commissioning: {error}")
            }
            Self::Safety(error) => write!(
                formatter,
                "SafetyStore rejected native h1 commissioning: {error}"
            ),
            Self::Signer(error) => write!(
                formatter,
                "signer journal rejected native h1 commissioning: {error}"
            ),
            Self::Application(error) => write!(
                formatter,
                "native application rejected h1 commissioning: {error}"
            ),
            Self::Checkpoint(error) => write!(
                formatter,
                "whole-node checkpoint rejected h1 commissioning: {error}"
            ),
            Self::CheckpointRecord(error) => {
                write!(formatter, "invalid h1 checkpoint record: {error}")
            }
        }
    }
}

impl Error for PocoNodeNativeH1StateSyncCommissioningErrorV0 {}

impl From<CoreError> for PocoNodeNativeH1StateSyncCommissioningErrorV0 {
    fn from(value: CoreError) -> Self {
        Self::Core(value)
    }
}
impl From<SafetyStoreErrorV0> for PocoNodeNativeH1StateSyncCommissioningErrorV0 {
    fn from(value: SafetyStoreErrorV0) -> Self {
        Self::Safety(value)
    }
}
impl From<SignerJournalErrorV0> for PocoNodeNativeH1StateSyncCommissioningErrorV0 {
    fn from(value: SignerJournalErrorV0) -> Self {
        Self::Signer(value)
    }
}
impl From<NativeApplicationExecutionErrorV0> for PocoNodeNativeH1StateSyncCommissioningErrorV0 {
    fn from(value: NativeApplicationExecutionErrorV0) -> Self {
        Self::Application(value)
    }
}
impl From<ExternalNodeCheckpointStoreErrorV0> for PocoNodeNativeH1StateSyncCommissioningErrorV0 {
    fn from(value: ExternalNodeCheckpointStoreErrorV0) -> Self {
        Self::Checkpoint(value)
    }
}
impl From<ExternalNodeCheckpointDecodeErrorV0> for PocoNodeNativeH1StateSyncCommissioningErrorV0 {
    fn from(value: ExternalNodeCheckpointDecodeErrorV0) -> Self {
        Self::CheckpointRecord(value)
    }
}

fn commission_native_h1_state_sync_v0<W: ExternalMonotonicWatermarkV0>(
    source: PocoNodeNativeH1StateSyncPromotionSourceV0<W>,
    config: PocoNodeNativeH1StateSyncCommissioningConfigV0,
) -> Result<
    PocoNodeNativeH1StateSyncCommissionedHostV0<W>,
    PocoNodeNativeH1StateSyncCommissioningErrorV0,
> {
    let PocoNodeNativeH1StateSyncPromotionSourceV0 {
        candidate,
        source_safety_store,
        mut pinned_signer,
    } = source;
    let PocoNodeNativeH1StateSyncCommissioningConfigV0 {
        target_safety_path,
        target_safety_record_limits,
        target_safety_maximum_database_bytes,
        application,
        mut checkpoint_store,
    } = config;

    require_disjoint_store_parents_v0(&[
        source_safety_store.path(),
        pinned_signer.path(),
        target_safety_path.as_path(),
        application.path(),
        checkpoint_store.database_path(),
    ])?;

    let source_safety = source_safety_store
        .confirm_node_checkpoint_head_exact_v0(candidate.source_safety_state_v0())?;
    if !source_safety.belongs_to_store_at_path_v0(&source_safety_store, source_safety_store.path())
    {
        return Err(
            PocoNodeNativeH1StateSyncCommissioningErrorV0::SourceMismatch(
                "source SafetyStore affinity",
            ),
        );
    }

    let signer = pinned_signer.confirm_node_checkpoint_head_exact_v0()?;
    validate_virgin_signer_v0(candidate.plain_core_config_v0(), &pinned_signer, &signer)?;
    validate_native_application_genesis_v0(&candidate, &application)?;
    let request = native_h1_request_v0(&candidate, &application)?;

    let target_profile = SafetyStateStoreProfileV0::new(
        candidate.plain_core_config_v0().clone(),
        STRICT_ED25519_VERIFIER_PROFILE_REF_V0,
        target_safety_record_limits,
        target_safety_maximum_database_bytes,
    )?;
    let (target_safety_store, _) =
        SqliteSafetyStateStoreV0::initialize_or_resume_h1_state_sync_exact_v0(
            &target_safety_path,
            target_profile,
            StrictEd25519Verifier,
            candidate.prepared_bootstrap_v0(),
        )?;
    let target_bootstrap = target_safety_store
        .confirmed_state_sync_checkpoint_bootstrap_head_exact_v0(
            candidate.prepared_bootstrap_v0().safety_state(),
        )?;
    drop(target_bootstrap);

    let installed = application.install_h1_state_sync_trusted_base_v0(&request)?;
    let fresh_installed = application.confirm_h1_state_sync_trusted_base_exact_v0(&request)?;
    if fresh_installed.import_digest_v0() != installed.import_digest_v0() {
        return Err(
            PocoNodeNativeH1StateSyncCommissioningErrorV0::SourceMismatch(
                "native h1 fresh import readback",
            ),
        );
    }
    let installed = fresh_installed;

    let proof_id = candidate.proof_id_v0();
    let source_parent = candidate.source_authenticated_parent_v0();
    let h1_header = candidate.h1_proposal_v0().block().header().clone();
    let (plain_config, prepared, retained_h1) = candidate.into_h1_state_sync_bootstrap_parts_v0();
    if retained_h1.block().header() != &h1_header {
        return Err(
            PocoNodeNativeH1StateSyncCommissioningErrorV0::SourceMismatch(
                "retained h1 changed during candidate consumption",
            ),
        );
    }
    let session = Core::begin_state_sync_anchor_recovery_v0(
        plain_config.clone(),
        prepared.into_safety_state(),
        &StrictEd25519Verifier,
    )?;
    let target_safety = target_safety_store
        .confirm_node_checkpoint_head_exact_v0(session.challenge().safety_state())?;
    let mut reconciler = NativeH1ExactJoinReconcilerV0 {
        safety_store: &target_safety_store,
        safety: &target_safety,
        application: &application,
        installed: &installed,
        pinned_signer: &pinned_signer,
        signer: &signer,
        proof_id,
    };
    let core = session.reconcile_and_activate_v0(&mut reconciler)?;

    let checkpoint = build_generation_zero_checkpoint_v0(
        &plain_config,
        source_parent,
        &h1_header,
        &target_safety,
        &application,
        &installed,
        &signer,
    )?;
    commit_generation_zero_checkpoint_v0(&mut checkpoint_store, checkpoint)?;

    let facts = PocoNodeNativeH1StateSyncCommissionedFactsV0 {
        proof_id,
        block_id: h1_header.id(),
        height: h1_header.height().get(),
        state_root: h1_header.state_root(),
        target_safety_journal_id: target_safety.journal_id_v0(),
        native_application_store_id: installed.store_id_v0(),
        checkpoint_checksum: checkpoint.checkpoint_checksum(),
        replay_fenced: true,
        signer_activated: false,
    };
    Ok(PocoNodeNativeH1StateSyncCommissionedHostV0 {
        core,
        retired_source_safety_store: source_safety_store,
        target_safety_store,
        application,
        pinned_signer,
        checkpoint_store,
        checkpoint,
        h1_request: request,
        facts,
    })
}

struct NativeH1ExactJoinReconcilerV0<'a, W: ExternalMonotonicWatermarkV0> {
    safety_store: &'a SqliteSafetyStateStoreV0<StrictEd25519Verifier>,
    safety: &'a ConfirmedSafetyNodeCheckpointFactsV0,
    application: &'a DurableNativeApplicationV0,
    installed: &'a ConfirmedNativeH1StateSyncTrustedBaseV0,
    pinned_signer: &'a PinnedSqliteSignerJournalV0<W>,
    signer: &'a ConfirmedSignerNodeCheckpointFactsV0,
    proof_id: CertificateId,
}

impl<W: ExternalMonotonicWatermarkV0> StateSyncAnchorRecoveryReconcilerV0
    for NativeH1ExactJoinReconcilerV0<'_, W>
{
    fn reconcile_state_sync_anchor_v0(
        &mut self,
        challenge: &StateSyncAnchorRecoveryChallengeV0,
    ) -> bool {
        let header = challenge.trusted_base_header();
        self.safety
            .belongs_to_store_at_path_v0(self.safety_store, self.safety_store.path())
            && self.safety.state_v0() == challenge.safety_state()
            && self
                .installed
                .belongs_to_application_at_path_v0(self.application, self.application.path())
            && self.installed.proof_id_v0() == *self.proof_id.as_bytes()
            && self.installed.head_v0().height().get() == header.height().get()
            && self.installed.head_v0().block_id().as_bytes() == header.id().as_bytes()
            && self.installed.head_v0().state_root().as_bytes() == header.state_root().as_bytes()
            && self
                .signer
                .belongs_to_pinned_journal_at_path_v0(self.pinned_signer, self.pinned_signer.path())
            && signer_shape_is_virgin_v0(self.signer)
    }
}

fn validate_native_application_genesis_v0(
    candidate: &AuthenticatedGenesisApplicationH1StateSyncPromotionCandidateV0,
    application: &DurableNativeApplicationV0,
) -> Result<(), PocoNodeNativeH1StateSyncCommissioningErrorV0> {
    let core = candidate.plain_core_config_v0();
    let parent = candidate.source_authenticated_parent_v0();
    let app = application.config_v0();
    let head = application.confirmed_committed_head_v0()?;
    if app.chain_id_v0() != core.validator_set().chain_id().as_str()
        || app.genesis_hash_v0() != *core.validator_set().genesis_hash().as_bytes()
        || app.chain_descriptor_hash_v0() != parent.descriptor_ref()
        || app.validator_set_v0() != core.validator_set()
        || app.consensus_parameters_v0() != core.consensus_parameters()
        || app.initial_block_id_v0() != *parent.genesis_block_id().as_bytes()
        || app.initial_state_root() != *parent.state_root().as_bytes()
        || head.height().get() != 0
        || head.block_id().as_bytes() != parent.genesis_block_id().as_bytes()
        || head.state_root().as_bytes() != parent.state_root().as_bytes()
    {
        return Err(
            PocoNodeNativeH1StateSyncCommissioningErrorV0::SourceMismatch(
                "native application genesis trust inputs",
            ),
        );
    }
    Ok(())
}

fn native_h1_request_v0(
    candidate: &AuthenticatedGenesisApplicationH1StateSyncPromotionCandidateV0,
    application: &DurableNativeApplicationV0,
) -> Result<NativeH1StateSyncTrustedBaseRequestV0, PocoNodeNativeH1StateSyncCommissioningErrorV0> {
    let core = candidate.plain_core_config_v0();
    let block = candidate.h1_proposal_v0().block();
    let header = block.header();
    let payload = decode_application_payload_v0_exact(
        block.application_payload(),
        core.consensus_parameters(),
    )
    .map_err(|_| {
        PocoNodeNativeH1StateSyncCommissioningErrorV0::SourceMismatch(
            "canonical h1 application payload",
        )
    })?;
    let expected = NativeExpectedBlockCommitmentsV0::new(
        Hash32V0::new(*header.payload_root().as_bytes()),
        StateRootV0::new(*header.state_root().as_bytes()).map_err(|_| {
            PocoNodeNativeH1StateSyncCommissioningErrorV0::SourceMismatch("h1 state root")
        })?,
        ReceiptsRootV0::new(*header.receipts_root().as_bytes()).map_err(|_| {
            PocoNodeNativeH1StateSyncCommissioningErrorV0::SourceMismatch("h1 receipts root")
        })?,
        Hash32V0::new(*header.evidence_root().as_bytes()),
    )
    .map_err(|_| {
        PocoNodeNativeH1StateSyncCommissioningErrorV0::SourceMismatch("h1 commitment shape")
    })?;
    let execution = NativeBlockExecutionRequestV0::new(
        ChainIdV0::new(core.validator_set().chain_id().as_str()).map_err(|_| {
            PocoNodeNativeH1StateSyncCommissioningErrorV0::SourceMismatch("chain id")
        })?,
        GenesisHashV0::new(*core.validator_set().genesis_hash().as_bytes()).map_err(|_| {
            PocoNodeNativeH1StateSyncCommissioningErrorV0::SourceMismatch("genesis hash")
        })?,
        application.confirmed_committed_head_v0()?,
        BlockIdV0::new(*block.id().as_bytes()).map_err(|_| {
            PocoNodeNativeH1StateSyncCommissioningErrorV0::SourceMismatch("h1 block id")
        })?,
        HeightV0::new(header.height().get()),
        header.timestamp_ms(),
        ValidatorSetIdV0::new(*header.validator_set_id().as_bytes()).map_err(|_| {
            PocoNodeNativeH1StateSyncCommissioningErrorV0::SourceMismatch("validator set id")
        })?,
        payload.transactions().to_vec(),
        expected,
    )
    .map_err(|_| {
        PocoNodeNativeH1StateSyncCommissioningErrorV0::SourceMismatch("native h1 execution request")
    })?;
    NativeH1StateSyncTrustedBaseRequestV0::new(*candidate.proof_id_v0().as_bytes(), execution)
        .map_err(|_| {
            PocoNodeNativeH1StateSyncCommissioningErrorV0::SourceMismatch("native h1 proof request")
        })
}

fn validate_virgin_signer_v0<W: ExternalMonotonicWatermarkV0>(
    core: &CoreConfig,
    pinned: &PinnedSqliteSignerJournalV0<W>,
    signer: &ConfirmedSignerNodeCheckpointFactsV0,
) -> Result<(), PocoNodeNativeH1StateSyncCommissioningErrorV0> {
    let identity = signer.identity();
    let validator_set = core.validator_set();
    if !signer.belongs_to_pinned_journal_at_path_v0(pinned, pinned.path())
        || identity.chain_id() != validator_set.chain_id()
        || identity.protocol_version() != validator_set.protocol_version()
        || identity.epoch() != validator_set.epoch()
        || identity.validator_set_id() != validator_set.id()
        || identity.author() != core.local_validator()
        || identity.external_watermark_scope() != derive_signer_watermark_scope_v0(core)
        || signer.exact_watermark().scope() != identity.external_watermark_scope()
        || signer.exact_watermark().journal_id() != signer.journal_id()
        || !signer_shape_is_virgin_v0(signer)
    {
        return Err(
            PocoNodeNativeH1StateSyncCommissioningErrorV0::SourceMismatch(
                "virgin signer identity or state",
            ),
        );
    }
    Ok(())
}

fn signer_shape_is_virgin_v0(signer: &ConfirmedSignerNodeCheckpointFactsV0) -> bool {
    let capacity = signer.capacity();
    capacity.intent_count() == 0
        && capacity.event_count() == 0
        && capacity.intent_bytes() == 0
        && capacity.maximum_safety_revision().is_none()
        && capacity.maximum_vote_view().is_none()
        && capacity.maximum_timeout_view().is_none()
        && signer.tail().is_none()
        && signer.pending_intent().is_none()
}

fn build_generation_zero_checkpoint_v0(
    core: &CoreConfig,
    source_parent: trnm_consensus_core::AuthenticatedGenesisApplicationParentV0,
    h1: &trnm_consensus_types::BlockHeader,
    safety: &ConfirmedSafetyNodeCheckpointFactsV0,
    application: &DurableNativeApplicationV0,
    installed: &ConfirmedNativeH1StateSyncTrustedBaseV0,
    signer: &ConfirmedSignerNodeCheckpointFactsV0,
) -> Result<ExternalNodeCheckpointV0, PocoNodeNativeH1StateSyncCommissioningErrorV0> {
    let scope = signer.exact_watermark().scope();
    let app_config = application.config_v0();
    let host_config = native_h1_hash_v0(
        NATIVE_H1_HOST_CONFIG_DOMAIN_V0,
        &[
            core.validator_set().chain_id().as_bytes(),
            core.validator_set().genesis_hash().as_bytes(),
            core.validator_set().id().as_bytes(),
            &app_config.store_id(),
            &app_config.initial_commit_id_v0(),
        ],
    );
    let projection = native_h1_hash_v0(
        NATIVE_H1_PROJECTION_DOMAIN_V0,
        &[
            b"native-execution-schema-3",
            b"proof-derived-h1-trusted-base",
        ],
    );
    let safety_binding = native_h1_hash_v0(
        NATIVE_H1_SAFETY_BINDING_DOMAIN_V0,
        &[
            source_parent.binding_ref_v0().as_slice(),
            &safety.journal_id_v0(),
            &safety.state_record_checksum_v0(),
            &safety.chain_checksum_v0(),
            &installed.proof_id_v0(),
            &installed.import_digest_v0(),
        ],
    );
    let head_row = native_h1_hash_v0(
        NATIVE_H1_HEAD_ROW_DOMAIN_V0,
        &[
            installed.head_v0().block_id().as_bytes(),
            installed.head_v0().state_root().as_bytes(),
            installed.head_v0().commit_id().as_bytes(),
            &installed.import_digest_v0(),
        ],
    );
    let recovery = native_h1_hash_v0(
        NATIVE_H1_RECOVERY_CLOSURE_DOMAIN_V0,
        &[
            &installed.store_id_v0(),
            &installed.install_sequence_v0().to_be_bytes(),
            &installed.proof_id_v0(),
            &installed.artifact_digest_v0(),
            &installed.snapshot_digest_v0(),
            &installed.import_digest_v0(),
        ],
    );
    ExternalNodeCheckpointV0::new(ExternalNodeCheckpointFieldsV0 {
        scope,
        generation: 0,
        predecessor_checksum: [0; 32],
        safety_journal_id: safety.journal_id_v0(),
        safety_verifier_profile_ref: safety.verifier_profile_ref_v0(),
        safety_revision: safety.revision_v0(),
        safety_state_record_checksum: safety.state_record_checksum_v0(),
        safety_record_chain_checksum: safety.chain_checksum_v0(),
        application_host_config_ref: host_config,
        application_projection_profile_ref: projection,
        application_safety_binding_manifest_checksum: safety_binding,
        application_committed_head_row_checksum: head_row,
        application_recovery_closure_checksum: recovery,
        application_block_id: h1.id(),
        application_height: h1.height().get(),
        application_state_root: h1.state_root(),
        application_view: h1.view().get(),
        application_timestamp_ms: h1.timestamp_ms(),
        signer_journal_id: signer.journal_id(),
        signer_profile_checksum: signer.profile_checksum(),
        signer_exact_watermark: signer.exact_watermark(),
    })
    .map_err(Into::into)
}

fn commit_generation_zero_checkpoint_v0(
    store: &mut SqliteExternalNodeCheckpointStoreV0,
    target: ExternalNodeCheckpointV0,
) -> Result<(), PocoNodeNativeH1StateSyncCommissioningErrorV0> {
    match store.compare_and_advance(None, target) {
        Ok(()) => {}
        Err(ExternalNodeCheckpointStoreErrorV0::Unavailable) => match store.load(target.scope())? {
            Some(observed) if observed == target => return Ok(()),
            None => store.compare_and_advance(None, target)?,
            Some(_) => {
                return Err(PocoNodeNativeH1StateSyncCommissioningErrorV0::Checkpoint(
                    ExternalNodeCheckpointStoreErrorV0::InvalidPersistedState,
                ))
            }
        },
        Err(error) => return Err(error.into()),
    }
    if store.load(target.scope())? != Some(target) {
        return Err(PocoNodeNativeH1StateSyncCommissioningErrorV0::Checkpoint(
            ExternalNodeCheckpointStoreErrorV0::InvalidPersistedState,
        ));
    }
    Ok(())
}

fn native_h1_hash_v0(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"trnm.domain.hash.v1");
    hasher.update((domain.len() as u64).to_be_bytes());
    hasher.update(domain);
    for part in parts {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part);
    }
    hasher.finalize().into()
}

fn require_absolute_file_path_v0(
    path: &Path,
    field: &'static str,
) -> Result<(), PocoNodeNativeH1StateSyncCommissioningErrorV0> {
    if !path.is_absolute() || path.file_name().is_none() || path.parent().is_none() {
        return Err(PocoNodeNativeH1StateSyncCommissioningErrorV0::InvalidConfiguration(field));
    }
    Ok(())
}

fn require_disjoint_store_parents_v0(
    paths: &[&Path],
) -> Result<(), PocoNodeNativeH1StateSyncCommissioningErrorV0> {
    let mut parents = Vec::with_capacity(paths.len());
    for path in paths {
        require_absolute_file_path_v0(path, "store path")?;
        let parent = fs::canonicalize(path.parent().ok_or(
            PocoNodeNativeH1StateSyncCommissioningErrorV0::InvalidConfiguration("store parent"),
        )?)
        .map_err(|_| {
            PocoNodeNativeH1StateSyncCommissioningErrorV0::InvalidConfiguration(
                "canonical store parent",
            )
        })?;
        parents.push(parent);
    }
    for left in 0..parents.len() {
        for right in left + 1..parents.len() {
            if parents[left].starts_with(&parents[right])
                || parents[right].starts_with(&parents[left])
            {
                return Err(
                    PocoNodeNativeH1StateSyncCommissioningErrorV0::InvalidConfiguration(
                        "overlapping store parent namespaces",
                    ),
                );
            }
        }
    }
    Ok(())
}
