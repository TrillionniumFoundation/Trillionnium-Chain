//! One-way h1-anchor successor takeover into an ordinary native validator.
//!
//! This module is crate-private by design.  It consumes the commissioned h1
//! owner, drives the proof-named h2/h3 through real durable native P/D/C/K,
//! advances an independent whole-node CAS after each stable cut, persists the
//! exact revision-five promotion, and activates the pinned signer only after
//! every other authority has been freshly read back.

use std::{error::Error, fmt};

use sha2::{Digest, Sha256};
use trnm_consensus_core::{
    BlockIdOverlayRefV0, Core, CoreConfig, CoreError, CoreIssuedApplicationSealAuthorityV0,
    DurablePayloadValidationCompletionV0, Effect, SafetyStatePersistenceV0,
    StateSyncAnchorSuccessorPhaseV0, StateSyncAnchorSuccessorRecoveryChallengeV0,
    StateSyncAnchorSuccessorRecoveryReconcilerV0, StateSyncAnchorSuccessorReplayV0, ValidationId,
};
use trnm_consensus_crypto::StrictEd25519Verifier;
use trnm_consensus_safety_store::{
    SafetyStoreErrorV0, SafetyTransitionContextV0, SqliteSafetyStateStoreV0,
};
use trnm_consensus_signer_journal::{
    ExternalMonotonicWatermarkV0, PinnedSqliteSignerJournalV0, SignerJournalActivationFailureV0,
    SignerJournalErrorV0, SqliteSignerJournalV0,
};
use trnm_consensus_types::{
    decode_application_payload_v0_exact, BlockId, BlockKind, SignatureVerifier, SignedProposalV0,
    StateRoot,
};
use trnm_native_application::{
    ApplicationHeadV0, BlockIdV0, ChainIdV0, GenesisHashV0, Hash32V0, HeightV0,
    NativeBlockExecutionRequestV0, NativeExpectedBlockCommitmentsV0, ReceiptsRootV0, StateRootV0,
    ValidatorSetIdV0,
};
use trnm_native_application_sqlite::{
    ConfirmedProposalValidationCheckpointFactsV0, DurableValidationStageV0, ProposalRouteV0,
    ProposalValidationBindingV0, ProposalValidationOwnerIdV0, SqliteProposalValidationStoreV0,
    ValidationStoreErrorV0,
};
use trnm_native_execution_v0::{
    DurableNativeApplicationV0, NativeApplicationExecutionErrorV0,
    NativeH1StateSyncTrustedBaseRequestV0,
};

#[cfg(feature = "lab-validator-runtime")]
use crate::lab_authority::{
    PocoNodeLabAuthorityErrorV0, PocoNodeLabOrdinaryProposalRuntimeV0,
    PocoNodeLabProposalJournalConfigV0,
};
use crate::{
    cross_store_lock::{common_authority_root_v0, CrossStoreLockErrorV0},
    native_h1_state_sync_commissioning::{
        PocoNodeNativeH1StateSyncCommissionedHostV0, PocoNodeNativeH1StateSyncNextOwnerV0,
    },
    native_proposal_p_host::{
        PocoNodeNativeAnchoredSuccessorCompletedV0, PocoNodeNativeApplicationAckedKV0,
        PocoNodeNativeCoreDOutcomeV0, PocoNodeNativeKOutcomeV0, PocoNodeNativeProposalPHostErrorV0,
        PocoNodeNativeProposalPHostV0,
    },
    ExternalNodeCheckpointDecodeErrorV0, ExternalNodeCheckpointFieldsV0,
    ExternalNodeCheckpointStoreErrorV0, ExternalNodeCheckpointStoreV0, ExternalNodeCheckpointV0,
    SqliteExternalNodeCheckpointStoreV0,
};

type NativeHostErrorV0 = PocoNodeNativeProposalPHostErrorV0<NativeApplicationExecutionErrorV0>;

const TAKEOVER_CHECKPOINT_OWNER_DOMAIN_V0: &[u8] =
    b"trnm.poco-node.anchor-successor.checkpoint.owner.v0";
const TAKEOVER_CHECKPOINT_PROFILE_DOMAIN_V0: &[u8] =
    b"trnm.poco-node.anchor-successor.checkpoint.profile.v0";
const TAKEOVER_CHECKPOINT_SAFETY_DOMAIN_V0: &[u8] =
    b"trnm.poco-node.anchor-successor.checkpoint.safety.v0";
const TAKEOVER_CHECKPOINT_RECOVERY_DOMAIN_V0: &[u8] =
    b"trnm.poco-node.anchor-successor.checkpoint.recovery.v0";

pub(crate) struct PocoNodeNativeH1OrdinaryTakeoverConfigV0 {
    validation_store: SqliteProposalValidationStoreV0,
    validation_owner: ProposalValidationOwnerIdV0,
}

impl PocoNodeNativeH1OrdinaryTakeoverConfigV0 {
    pub(crate) fn new(
        validation_store: SqliteProposalValidationStoreV0,
        validation_owner: ProposalValidationOwnerIdV0,
    ) -> Self {
        Self {
            validation_store,
            validation_owner,
        }
    }
}

/// Already-open, uniquely owned namespaces for a crash restart anywhere in
/// the bounded rev0..rev4 anchored-successor protocol. Construction does not
/// activate the signer or bind Safety to a Core; the consuming recovery entry
/// performs both only after the complete cross-store cut is reconciled.
pub struct PocoNodeNativeH1OrdinaryRecoveryConfigV0<W: ExternalMonotonicWatermarkV0> {
    core_config: CoreConfig,
    safety_store: SqliteSafetyStateStoreV0<StrictEd25519Verifier>,
    application: DurableNativeApplicationV0,
    validation_store: SqliteProposalValidationStoreV0,
    validation_owner: ProposalValidationOwnerIdV0,
    h1_request: NativeH1StateSyncTrustedBaseRequestV0,
    pinned_signer: PinnedSqliteSignerJournalV0<W>,
    checkpoint_store: SqliteExternalNodeCheckpointStoreV0,
}

impl<W: ExternalMonotonicWatermarkV0> PocoNodeNativeH1OrdinaryRecoveryConfigV0<W> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        core_config: CoreConfig,
        safety_store: SqliteSafetyStateStoreV0<StrictEd25519Verifier>,
        application: DurableNativeApplicationV0,
        validation_store: SqliteProposalValidationStoreV0,
        validation_owner: ProposalValidationOwnerIdV0,
        h1_request: NativeH1StateSyncTrustedBaseRequestV0,
        pinned_signer: PinnedSqliteSignerJournalV0<W>,
        checkpoint_store: SqliteExternalNodeCheckpointStoreV0,
    ) -> Self {
        Self {
            core_config,
            safety_store,
            application,
            validation_store,
            validation_owner,
            h1_request,
            pinned_signer,
            checkpoint_store,
        }
    }

    pub(crate) fn recover_v0(
        self,
        child: SignedProposalV0,
        grandchild: SignedProposalV0,
    ) -> Result<PocoNodeNativeH1OrdinaryHostV0<W>, PocoNodeNativeH1OrdinaryTakeoverErrorV0<W>> {
        recover_native_h1_ordinary_takeover_v0(self, child, grandchild)
    }

    /// Reconciles an exact rev0..rev4 native h1 successor cut and consumes it
    /// directly into the public laboratory runtime owner. The proof-derived
    /// h1 request supplied to [`Self::new`] is mandatory: recovery never
    /// reconstructs the trusted-base body from checkpoint scalars or facts.
    #[cfg(feature = "lab-validator-runtime")]
    pub fn recover_lab_ordinary_takeover_v0(
        self,
        child: SignedProposalV0,
        grandchild: SignedProposalV0,
        proposal_journal: PocoNodeLabProposalJournalConfigV0,
    ) -> Result<PocoNodeLabOrdinaryProposalRuntimeV0<W>, PocoNodeLabAuthorityErrorV0> {
        let host = self
            .recover_v0(child, grandchild)
            .map_err(lab_takeover_error_v0)?;
        let parts = host
            .into_runtime_parts_v0()
            .map_err(lab_takeover_error_v0)?;
        PocoNodeLabOrdinaryProposalRuntimeV0::from_native_h1_ordinary_runtime_parts_v0(
            parts,
            proposal_journal,
        )
    }
}

/// Crate-private, non-cloneable ordinary owner.  No constituent authority has
/// a public escape hatch; the continuous runtime must consume this value in a
/// later in-crate integration step.
#[must_use = "the ordinary native owner must remain joined"]
pub(crate) struct PocoNodeNativeH1OrdinaryHostV0<W: ExternalMonotonicWatermarkV0> {
    core: Core,
    seal_authority: CoreIssuedApplicationSealAuthorityV0,
    startup_effects: Vec<Effect>,
    retired_source_safety_store: Option<SqliteSafetyStateStoreV0<StrictEd25519Verifier>>,
    safety_store: SqliteSafetyStateStoreV0<StrictEd25519Verifier>,
    application: DurableNativeApplicationV0,
    validation_store: SqliteProposalValidationStoreV0,
    validation_owner: ProposalValidationOwnerIdV0,
    signer: SqliteSignerJournalV0<W>,
    checkpoint_store: SqliteExternalNodeCheckpointStoreV0,
    checkpoint: ExternalNodeCheckpointV0,
    h2: PocoNodeNativeAnchoredSuccessorCompletedV0,
    h3: PocoNodeNativeAnchoredSuccessorCompletedV0,
}

/// Linear handoff consumed by the feature-gated continuous runtime. The
/// validation-store owner remains live so the consumer can read back h2/h3,
/// compare the exact journal path/scope/owner/sequence, and only then release
/// that lock into the same proposal-journal configuration.
#[must_use = "ordinary runtime parts must be consumed without reconstructing authority"]
pub(crate) struct PocoNodeNativeH1OrdinaryRuntimePartsV0<W: ExternalMonotonicWatermarkV0> {
    pub(crate) core: Core,
    pub(crate) seal_authority: CoreIssuedApplicationSealAuthorityV0,
    pub(crate) startup_effects: Vec<Effect>,
    pub(crate) retired_source_safety_store: Option<SqliteSafetyStateStoreV0<StrictEd25519Verifier>>,
    pub(crate) safety_store: SqliteSafetyStateStoreV0<StrictEd25519Verifier>,
    pub(crate) application: DurableNativeApplicationV0,
    pub(crate) validation_store: SqliteProposalValidationStoreV0,
    pub(crate) validation_owner: ProposalValidationOwnerIdV0,
    pub(crate) signer: SqliteSignerJournalV0<W>,
    pub(crate) checkpoint_store: SqliteExternalNodeCheckpointStoreV0,
    pub(crate) checkpoint: ExternalNodeCheckpointV0,
    pub(crate) h2: PocoNodeNativeAnchoredSuccessorCompletedV0,
    pub(crate) h3: PocoNodeNativeAnchoredSuccessorCompletedV0,
}

impl<W: ExternalMonotonicWatermarkV0> PocoNodeNativeH1OrdinaryHostV0<W> {
    pub(crate) fn into_runtime_parts_v0(
        self,
    ) -> Result<PocoNodeNativeH1OrdinaryRuntimePartsV0<W>, PocoNodeNativeH1OrdinaryTakeoverErrorV0<W>>
    {
        if self.core.safety_state().revision() != 5
            || self.h2.safety_revision_v0() != 2
            || self.h3.safety_revision_v0() != 4
            || self
                .startup_effects
                .iter()
                .any(|effect| !matches!(effect, Effect::ArmViewTimer { .. }))
        {
            return Err(PocoNodeNativeH1OrdinaryTakeoverErrorV0::Rejected(
                "ordinary runtime handoff is not the exact rev5 cut",
            ));
        }
        Ok(PocoNodeNativeH1OrdinaryRuntimePartsV0 {
            core: self.core,
            seal_authority: self.seal_authority,
            startup_effects: self.startup_effects,
            retired_source_safety_store: self.retired_source_safety_store,
            safety_store: self.safety_store,
            application: self.application,
            validation_store: self.validation_store,
            validation_owner: self.validation_owner,
            signer: self.signer,
            checkpoint_store: self.checkpoint_store,
            checkpoint: self.checkpoint,
            h2: self.h2,
            h3: self.h3,
        })
    }
}

impl<W: ExternalMonotonicWatermarkV0> fmt::Debug for PocoNodeNativeH1OrdinaryHostV0<W> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PocoNodeNativeH1OrdinaryHostV0")
            .field("safety_revision", &self.core.safety_state().revision())
            .field("checkpoint", &self.checkpoint.checkpoint_checksum())
            .field("h2", &self.h2.binding_v0().block_id())
            .field("h3", &self.h3.binding_v0().block_id())
            .field("startup_effect_count", &self.startup_effects.len())
            .finish_non_exhaustive()
    }
}

pub(crate) enum PocoNodeNativeH1OrdinaryTakeoverErrorV0<W> {
    Core(CoreError),
    Safety(SafetyStoreErrorV0),
    Application(NativeApplicationExecutionErrorV0),
    Validation(ValidationStoreErrorV0),
    Host(NativeHostErrorV0),
    Signer(SignerJournalErrorV0),
    SignerActivation(SignerJournalActivationFailureV0<W>),
    Checkpoint(ExternalNodeCheckpointStoreErrorV0),
    CheckpointRecord(ExternalNodeCheckpointDecodeErrorV0),
    CrossStoreLock(String),
    Rejected(&'static str),
}

impl<W> fmt::Debug for PocoNodeNativeH1OrdinaryTakeoverErrorV0<W> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Core(error) => formatter.debug_tuple("Core").field(error).finish(),
            Self::Safety(error) => formatter.debug_tuple("Safety").field(error).finish(),
            Self::Application(error) => formatter.debug_tuple("Application").field(error).finish(),
            Self::Validation(error) => formatter.debug_tuple("Validation").field(error).finish(),
            Self::Host(error) => formatter.debug_tuple("Host").field(error).finish(),
            Self::Signer(error) => formatter.debug_tuple("Signer").field(error).finish(),
            Self::SignerActivation(error) => formatter
                .debug_tuple("SignerActivation")
                .field(error.error())
                .finish(),
            Self::Checkpoint(error) => formatter.debug_tuple("Checkpoint").field(error).finish(),
            Self::CheckpointRecord(error) => formatter
                .debug_tuple("CheckpointRecord")
                .field(error)
                .finish(),
            Self::CrossStoreLock(error) => formatter
                .debug_tuple("CrossStoreLock")
                .field(error)
                .finish(),
            Self::Rejected(reason) => formatter.debug_tuple("Rejected").field(reason).finish(),
        }
    }
}

impl<W> fmt::Display for PocoNodeNativeH1OrdinaryTakeoverErrorV0<W> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Core(error) => write!(formatter, "Core rejected h1 ordinary takeover: {error}"),
            Self::Safety(error) => write!(formatter, "SafetyStore rejected takeover: {error}"),
            Self::Application(error) => {
                write!(formatter, "native application rejected takeover: {error}")
            }
            Self::Validation(error) => write!(
                formatter,
                "native validation journal rejected takeover: {error}"
            ),
            Self::Host(error) => {
                write!(formatter, "native P/D/C/K host rejected takeover: {error}")
            }
            Self::Signer(error) => write!(formatter, "signer journal rejected takeover: {error}"),
            Self::SignerActivation(error) => write!(
                formatter,
                "signer activation rejected takeover: {}",
                error.error()
            ),
            Self::Checkpoint(error) => write!(
                formatter,
                "whole-node checkpoint rejected takeover: {error}"
            ),
            Self::CheckpointRecord(error) => {
                write!(formatter, "invalid whole-node checkpoint: {error}")
            }
            Self::CrossStoreLock(error) => write!(
                formatter,
                "cross-store authority lock rejected takeover: {error}"
            ),
            Self::Rejected(reason) => write!(formatter, "h1 ordinary takeover rejected: {reason}"),
        }
    }
}

impl<W: ExternalMonotonicWatermarkV0 + fmt::Debug> Error
    for PocoNodeNativeH1OrdinaryTakeoverErrorV0<W>
{
}

impl<W> From<CoreError> for PocoNodeNativeH1OrdinaryTakeoverErrorV0<W> {
    fn from(value: CoreError) -> Self {
        Self::Core(value)
    }
}
impl<W> From<SafetyStoreErrorV0> for PocoNodeNativeH1OrdinaryTakeoverErrorV0<W> {
    fn from(value: SafetyStoreErrorV0) -> Self {
        Self::Safety(value)
    }
}
impl<W> From<NativeApplicationExecutionErrorV0> for PocoNodeNativeH1OrdinaryTakeoverErrorV0<W> {
    fn from(value: NativeApplicationExecutionErrorV0) -> Self {
        Self::Application(value)
    }
}
impl<W> From<ValidationStoreErrorV0> for PocoNodeNativeH1OrdinaryTakeoverErrorV0<W> {
    fn from(value: ValidationStoreErrorV0) -> Self {
        Self::Validation(value)
    }
}
impl<W> From<NativeHostErrorV0> for PocoNodeNativeH1OrdinaryTakeoverErrorV0<W> {
    fn from(value: NativeHostErrorV0) -> Self {
        Self::Host(value)
    }
}
impl<W> From<SignerJournalErrorV0> for PocoNodeNativeH1OrdinaryTakeoverErrorV0<W> {
    fn from(value: SignerJournalErrorV0) -> Self {
        Self::Signer(value)
    }
}
impl<W> From<ExternalNodeCheckpointStoreErrorV0> for PocoNodeNativeH1OrdinaryTakeoverErrorV0<W> {
    fn from(value: ExternalNodeCheckpointStoreErrorV0) -> Self {
        Self::Checkpoint(value)
    }
}
impl<W> From<ExternalNodeCheckpointDecodeErrorV0> for PocoNodeNativeH1OrdinaryTakeoverErrorV0<W> {
    fn from(value: ExternalNodeCheckpointDecodeErrorV0) -> Self {
        Self::CheckpointRecord(value)
    }
}
impl<W> From<CrossStoreLockErrorV0> for PocoNodeNativeH1OrdinaryTakeoverErrorV0<W> {
    fn from(value: CrossStoreLockErrorV0) -> Self {
        Self::CrossStoreLock(value.to_string())
    }
}

impl<W: ExternalMonotonicWatermarkV0> PocoNodeNativeH1StateSyncCommissionedHostV0<W> {
    pub(crate) fn complete_native_h1_ordinary_takeover_v0(
        self,
        child: SignedProposalV0,
        grandchild: SignedProposalV0,
        config: PocoNodeNativeH1OrdinaryTakeoverConfigV0,
    ) -> Result<PocoNodeNativeH1OrdinaryHostV0<W>, PocoNodeNativeH1OrdinaryTakeoverErrorV0<W>> {
        complete_native_h1_ordinary_takeover_v0(
            self.into_next_owner_v0(),
            child,
            grandchild,
            config,
        )
    }

    /// Consumes a freshly commissioned h1 owner through the exact h2/h3
    /// native P/D/C/K takeover and directly into the public laboratory
    /// runtime. No Core, store, signer, checkpoint, or derived capability is
    /// exported between those two linear transitions.
    #[cfg(feature = "lab-validator-runtime")]
    pub fn complete_lab_ordinary_takeover_v0(
        self,
        child: SignedProposalV0,
        grandchild: SignedProposalV0,
        validation_store: SqliteProposalValidationStoreV0,
        validation_owner: ProposalValidationOwnerIdV0,
        proposal_journal: PocoNodeLabProposalJournalConfigV0,
    ) -> Result<PocoNodeLabOrdinaryProposalRuntimeV0<W>, PocoNodeLabAuthorityErrorV0> {
        let host = self
            .complete_native_h1_ordinary_takeover_v0(
                child,
                grandchild,
                PocoNodeNativeH1OrdinaryTakeoverConfigV0::new(validation_store, validation_owner),
            )
            .map_err(lab_takeover_error_v0)?;
        let parts = host
            .into_runtime_parts_v0()
            .map_err(lab_takeover_error_v0)?;
        PocoNodeLabOrdinaryProposalRuntimeV0::from_native_h1_ordinary_runtime_parts_v0(
            parts,
            proposal_journal,
        )
    }
}

#[cfg(feature = "lab-validator-runtime")]
fn lab_takeover_error_v0<W>(
    error: PocoNodeNativeH1OrdinaryTakeoverErrorV0<W>,
) -> PocoNodeLabAuthorityErrorV0 {
    PocoNodeLabAuthorityErrorV0::AuthorityChain(error.to_string())
}

fn complete_native_h1_ordinary_takeover_v0<W: ExternalMonotonicWatermarkV0>(
    owner: PocoNodeNativeH1StateSyncNextOwnerV0<W>,
    child: SignedProposalV0,
    grandchild: SignedProposalV0,
    config: PocoNodeNativeH1OrdinaryTakeoverConfigV0,
) -> Result<PocoNodeNativeH1OrdinaryHostV0<W>, PocoNodeNativeH1OrdinaryTakeoverErrorV0<W>> {
    let PocoNodeNativeH1StateSyncNextOwnerV0 {
        core,
        retired_source_safety_store,
        mut target_safety_store,
        application,
        mut pinned_signer,
        mut checkpoint_store,
        mut checkpoint,
        h1_request,
    } = owner;
    let PocoNodeNativeH1OrdinaryTakeoverConfigV0 {
        mut validation_store,
        validation_owner,
    } = config;

    let bundle = Core::prepare_h1_state_sync_anchor_successor_bundle_v0(
        core.config(),
        core.safety_state(),
        child,
        grandchild,
        &StrictEd25519Verifier,
    )?;
    let session =
        core.begin_live_state_sync_anchor_successor_transfer_v0(bundle, &StrictEd25519Verifier)?;
    let safety = target_safety_store
        .confirm_node_checkpoint_head_exact_v0(session.challenge().safety_state())?;
    let installed = application.confirm_h1_state_sync_trusted_base_exact_v0(&h1_request)?;
    let signer = pinned_signer.confirm_node_checkpoint_head_exact_v0()?;
    let mut replay = {
        let mut reconciler = CommissionedSuccessorReconcilerV0 {
            safety_store: &target_safety_store,
            safety: &safety,
            application: &application,
            installed_head: installed.head_v0(),
            pinned_signer: &pinned_signer,
            signer: &signer,
            validation_store: &mut validation_store,
            checkpoint_store: &mut checkpoint_store,
            checkpoint,
        };
        session.reconcile_and_activate_v0(&mut reconciler)?
    };
    target_safety_store.bind_core_v0(replay.safety_state_persistence_binding_v0())?;

    let application_head = application.confirmed_committed_head_v0()?;
    // H1 takeover is a deployed writer path, not an isolated host fixture.
    // Derive the authenticated common root from the exact P and K paths before
    // moving either store into the host; `from_open_store_v0` requires this
    // capability and therefore cannot silently opt out of the K/P fence.
    let cross_store_root = common_authority_root_v0(application.path(), validation_store.path())?;
    let consensus_parameters = *replay.config().consensus_parameters();
    let validator_set = replay.config().validator_set().clone();
    let seal_authority = replay.issue_application_seal_authority_v0()?;
    let mut host = PocoNodeNativeProposalPHostV0::from_open_store_v0(
        application,
        validation_store,
        validation_owner,
        application_head,
        None,
        cross_store_root,
        consensus_parameters,
        validator_set,
    );

    let (_h2_marker, h2_acked) = drive_fresh_successor_v0::<W, _>(
        &mut replay,
        &mut host,
        &mut target_safety_store,
        &seal_authority,
        &StrictEd25519Verifier,
    )?;
    checkpoint = checkpoint_anchored_k_v0(
        CheckpointAdvanceKindV0::Successor,
        checkpoint,
        &mut checkpoint_store,
        &target_safety_store,
        &mut pinned_signer,
        &mut host,
        &h2_acked,
    )?;
    let h2 = host.acknowledge_anchor_successor_checkpointed_k_v0(
        h2_acked,
        &mut replay,
        &StrictEd25519Verifier,
    )?;
    if h2.safety_revision_v0() != 2 {
        return Err(PocoNodeNativeH1OrdinaryTakeoverErrorV0::Rejected(
            "h2 did not close at revision two",
        ));
    }

    let (_h3_marker, h3_acked) = drive_fresh_successor_v0::<W, _>(
        &mut replay,
        &mut host,
        &mut target_safety_store,
        &seal_authority,
        &StrictEd25519Verifier,
    )?;
    checkpoint = checkpoint_anchored_k_v0(
        CheckpointAdvanceKindV0::Successor,
        checkpoint,
        &mut checkpoint_store,
        &target_safety_store,
        &mut pinned_signer,
        &mut host,
        &h3_acked,
    )?;
    let h3 = host.acknowledge_anchor_successor_checkpointed_k_v0(
        h3_acked,
        &mut replay,
        &StrictEd25519Verifier,
    )?;
    if h3.safety_revision_v0() != 4 {
        return Err(PocoNodeNativeH1OrdinaryTakeoverErrorV0::Rejected(
            "h3 did not close at revision four",
        ));
    }

    let promotion =
        exact_persistence_v0(replay.step_ordinary_promotion_v0(&StrictEd25519Verifier)?)?;
    let promotion_context =
        target_safety_store.state_sync_anchor_ordinary_promotion_context_v0(&promotion)?;
    target_safety_store.persist_exact_v0(&promotion, &promotion_context)?;
    let h3_application = host.reconfirm_anchor_successor_k_checkpoint_facts_v0(h3.binding_v0())?;
    checkpoint = checkpoint_confirmed_application_v0(
        CheckpointAdvanceKindV0::Promotion,
        checkpoint,
        &mut checkpoint_store,
        &target_safety_store,
        &mut pinned_signer,
        &host,
        h3_application,
    )?;
    let activation =
        replay.acknowledge_ordinary_promotion_v0(promotion.barrier(), &StrictEd25519Verifier)?;
    if activation.core().safety_state().revision() != 5
        || activation
            .effects()
            .iter()
            .any(|effect| !matches!(effect, Effect::ArmViewTimer { .. }))
    {
        return Err(PocoNodeNativeH1OrdinaryTakeoverErrorV0::Rejected(
            "revision-five activation exposed a non-timer effect",
        ));
    }

    let final_safety = target_safety_store
        .confirm_node_checkpoint_head_exact_v0(activation.core().safety_state())?;
    let final_application =
        host.reconfirm_anchor_successor_k_checkpoint_facts_v0(h3.binding_v0())?;
    let final_signer = pinned_signer.confirm_node_checkpoint_head_exact_v0()?;
    validate_final_join_v0(
        &checkpoint,
        &final_safety,
        &final_application,
        &final_signer,
        &pinned_signer,
        &mut checkpoint_store,
    )?;
    let (application, validation_store, validation_owner) = host.into_anchor_ordinary_parts_v0()?;
    let (core, startup_effects) = activation.into_parts_v0();

    // This is intentionally the final mutable authority transition.  All
    // Safety, App, checkpoint, ancestry, and Core checks above are complete.
    let signer = pinned_signer
        .activate_v0()
        .map_err(PocoNodeNativeH1OrdinaryTakeoverErrorV0::SignerActivation)?;

    Ok(PocoNodeNativeH1OrdinaryHostV0 {
        core,
        seal_authority,
        startup_effects,
        retired_source_safety_store: Some(retired_source_safety_store),
        safety_store: target_safety_store,
        application,
        validation_store,
        validation_owner,
        signer,
        checkpoint_store,
        checkpoint,
        h2,
        h3,
    })
}

fn recover_native_h1_ordinary_takeover_v0<W: ExternalMonotonicWatermarkV0>(
    config: PocoNodeNativeH1OrdinaryRecoveryConfigV0<W>,
    child: SignedProposalV0,
    grandchild: SignedProposalV0,
) -> Result<PocoNodeNativeH1OrdinaryHostV0<W>, PocoNodeNativeH1OrdinaryTakeoverErrorV0<W>> {
    let PocoNodeNativeH1OrdinaryRecoveryConfigV0 {
        core_config,
        mut safety_store,
        application,
        mut validation_store,
        validation_owner,
        h1_request,
        mut pinned_signer,
        mut checkpoint_store,
    } = config;
    let safety_head = safety_store.head()?;
    let bundle = Core::prepare_h1_state_sync_anchor_successor_bundle_v0(
        &core_config,
        safety_head.state(),
        child,
        grandchild,
        &StrictEd25519Verifier,
    )?;
    let session = Core::begin_state_sync_anchor_successor_recovery_v0(
        core_config.clone(),
        safety_head.state().clone(),
        bundle,
        &StrictEd25519Verifier,
    )?;
    let phase = session.challenge().phase();
    let safety =
        safety_store.confirm_node_checkpoint_head_exact_v0(session.challenge().safety_state())?;
    let anchor = session
        .challenge()
        .safety_state()
        .state_sync_anchor()
        .ok_or(PocoNodeNativeH1OrdinaryTakeoverErrorV0::Rejected(
            "restart h1 request lost its anchor",
        ))?;
    let h1 = anchor.proof().finalized_block().header();
    let h1_execution = h1_request.execution_v0();
    if h1_request.proof_id_v0() != *anchor.proof().id().as_bytes()
        || h1_execution.block_id().as_bytes() != h1.id().as_bytes()
        || h1_execution.height().get() != h1.height().get()
        || h1_execution.timestamp_ms() != h1.timestamp_ms()
        || h1_execution.expected().payload_root().as_bytes() != h1.payload_root().as_bytes()
        || h1_execution.expected().post_state_root().as_bytes() != h1.state_root().as_bytes()
        || h1_execution.expected().receipts_root().as_bytes() != h1.receipts_root().as_bytes()
        || h1_execution.expected().evidence_root().as_bytes() != h1.evidence_root().as_bytes()
    {
        return Err(PocoNodeNativeH1OrdinaryTakeoverErrorV0::Rejected(
            "restart h1 request differs from the durable proof",
        ));
    }
    let installed = application.confirm_h1_state_sync_trusted_base_exact_v0(&h1_request)?;
    let signer = pinned_signer.confirm_node_checkpoint_head_exact_v0()?;
    let mut reconciler = RestartSuccessorReconcilerV0 {
        core_config: &core_config,
        safety_store: &safety_store,
        safety: &safety,
        application: &application,
        installed_head: installed.head_v0(),
        pinned_signer: &pinned_signer,
        signer: &signer,
        validation_store: &mut validation_store,
        checkpoint_store: &mut checkpoint_store,
        recovered: None,
    };
    let mut replay = session.reconcile_and_activate_v0(&mut reconciler)?;
    let recovered =
        reconciler
            .recovered
            .take()
            .ok_or(PocoNodeNativeH1OrdinaryTakeoverErrorV0::Rejected(
                "restart reconciler did not retain the authenticated cut",
            ))?;
    drop(reconciler);
    if recovered.phase != phase || replay.phase()? != phase {
        return Err(PocoNodeNativeH1OrdinaryTakeoverErrorV0::Rejected(
            "restart phase changed during activation",
        ));
    }
    safety_store.bind_core_v0(replay.safety_state_persistence_binding_v0())?;

    let RecoveredSuccessorCutV0 {
        phase,
        mut checkpoint,
        application_head,
        application_overlay,
        mut pending_binding,
        h2: recovered_h2,
        h3: recovered_h3,
    } = recovered;
    let consensus_parameters = *replay.config().consensus_parameters();
    let validator_set = replay.config().validator_set().clone();
    let cross_store_root = common_authority_root_v0(application.path(), validation_store.path())?;
    let seal_authority = replay.issue_application_seal_authority_v0()?;
    let mut host = PocoNodeNativeProposalPHostV0::from_open_store_v0(
        application,
        validation_store,
        validation_owner,
        application_head,
        application_overlay,
        cross_store_root,
        consensus_parameters,
        validator_set,
    );
    let mut h2 = recovered_h2
        .map(|row| reconciled_completed_v0::<W>(row, 2))
        .transpose()?;
    let mut h3 = recovered_h3
        .map(|row| reconciled_completed_v0::<W>(row, 4))
        .transpose()?;

    match phase {
        StateSyncAnchorSuccessorPhaseV0::H1Bootstrap => {
            let (_, h2_acked) = drive_fresh_successor_v0::<W, _>(
                &mut replay,
                &mut host,
                &mut safety_store,
                &seal_authority,
                &StrictEd25519Verifier,
            )?;
            checkpoint = checkpoint_anchored_k_v0(
                CheckpointAdvanceKindV0::Successor,
                checkpoint,
                &mut checkpoint_store,
                &safety_store,
                &mut pinned_signer,
                &mut host,
                &h2_acked,
            )?;
            h2 = Some(host.acknowledge_anchor_successor_checkpointed_k_v0(
                h2_acked,
                &mut replay,
                &StrictEd25519Verifier,
            )?);
        }
        StateSyncAnchorSuccessorPhaseV0::H2ValidationPending => {
            let h2_acked = drive_recovered_successor_v0::<W, _>(
                &mut replay,
                &mut host,
                &mut safety_store,
                &seal_authority,
                pending_binding
                    .take()
                    .ok_or(PocoNodeNativeH1OrdinaryTakeoverErrorV0::Rejected(
                        "rev1 restart lost its durable P binding",
                    ))?,
                &StrictEd25519Verifier,
            )?;
            checkpoint = checkpoint_anchored_k_v0(
                CheckpointAdvanceKindV0::Successor,
                checkpoint,
                &mut checkpoint_store,
                &safety_store,
                &mut pinned_signer,
                &mut host,
                &h2_acked,
            )?;
            h2 = Some(host.acknowledge_anchor_successor_checkpointed_k_v0(
                h2_acked,
                &mut replay,
                &StrictEd25519Verifier,
            )?);
        }
        StateSyncAnchorSuccessorPhaseV0::H2Valid
        | StateSyncAnchorSuccessorPhaseV0::H3ValidationPending
        | StateSyncAnchorSuccessorPhaseV0::H3Valid => {}
    }

    match replay.phase()? {
        StateSyncAnchorSuccessorPhaseV0::H2Valid => {
            let (_, h3_acked) = drive_fresh_successor_v0::<W, _>(
                &mut replay,
                &mut host,
                &mut safety_store,
                &seal_authority,
                &StrictEd25519Verifier,
            )?;
            checkpoint = checkpoint_anchored_k_v0(
                CheckpointAdvanceKindV0::Successor,
                checkpoint,
                &mut checkpoint_store,
                &safety_store,
                &mut pinned_signer,
                &mut host,
                &h3_acked,
            )?;
            h3 = Some(host.acknowledge_anchor_successor_checkpointed_k_v0(
                h3_acked,
                &mut replay,
                &StrictEd25519Verifier,
            )?);
        }
        StateSyncAnchorSuccessorPhaseV0::H3ValidationPending => {
            let h3_acked = drive_recovered_successor_v0::<W, _>(
                &mut replay,
                &mut host,
                &mut safety_store,
                &seal_authority,
                pending_binding
                    .take()
                    .ok_or(PocoNodeNativeH1OrdinaryTakeoverErrorV0::Rejected(
                        "rev3 restart lost its durable P binding",
                    ))?,
                &StrictEd25519Verifier,
            )?;
            checkpoint = checkpoint_anchored_k_v0(
                CheckpointAdvanceKindV0::Successor,
                checkpoint,
                &mut checkpoint_store,
                &safety_store,
                &mut pinned_signer,
                &mut host,
                &h3_acked,
            )?;
            h3 = Some(host.acknowledge_anchor_successor_checkpointed_k_v0(
                h3_acked,
                &mut replay,
                &StrictEd25519Verifier,
            )?);
        }
        StateSyncAnchorSuccessorPhaseV0::H3Valid => {}
        StateSyncAnchorSuccessorPhaseV0::H1Bootstrap
        | StateSyncAnchorSuccessorPhaseV0::H2ValidationPending => {
            return Err(PocoNodeNativeH1OrdinaryTakeoverErrorV0::Rejected(
                "restart failed to close h2",
            ));
        }
    }

    let h2 = h2.ok_or(PocoNodeNativeH1OrdinaryTakeoverErrorV0::Rejected(
        "ordinary takeover lacks terminal h2",
    ))?;
    let h3 = h3.ok_or(PocoNodeNativeH1OrdinaryTakeoverErrorV0::Rejected(
        "ordinary takeover lacks terminal h3",
    ))?;
    if h2.safety_revision_v0() != 2 || h3.safety_revision_v0() != 4 {
        return Err(PocoNodeNativeH1OrdinaryTakeoverErrorV0::Rejected(
            "ordinary takeover terminal revisions differ",
        ));
    }

    let promotion =
        exact_persistence_v0(replay.step_ordinary_promotion_v0(&StrictEd25519Verifier)?)?;
    let promotion_context =
        safety_store.state_sync_anchor_ordinary_promotion_context_v0(&promotion)?;
    safety_store.persist_exact_v0(&promotion, &promotion_context)?;
    let h3_application = host.reconfirm_anchor_successor_k_checkpoint_facts_v0(h3.binding_v0())?;
    checkpoint = checkpoint_confirmed_application_v0(
        CheckpointAdvanceKindV0::Promotion,
        checkpoint,
        &mut checkpoint_store,
        &safety_store,
        &mut pinned_signer,
        &host,
        h3_application,
    )?;
    let activation =
        replay.acknowledge_ordinary_promotion_v0(promotion.barrier(), &StrictEd25519Verifier)?;
    if activation.core().safety_state().revision() != 5
        || activation
            .effects()
            .iter()
            .any(|effect| !matches!(effect, Effect::ArmViewTimer { .. }))
    {
        return Err(PocoNodeNativeH1OrdinaryTakeoverErrorV0::Rejected(
            "restart revision-five activation exposed a non-timer effect",
        ));
    }
    let final_safety =
        safety_store.confirm_node_checkpoint_head_exact_v0(activation.core().safety_state())?;
    let final_application =
        host.reconfirm_anchor_successor_k_checkpoint_facts_v0(h3.binding_v0())?;
    let final_signer = pinned_signer.confirm_node_checkpoint_head_exact_v0()?;
    validate_final_join_v0(
        &checkpoint,
        &final_safety,
        &final_application,
        &final_signer,
        &pinned_signer,
        &mut checkpoint_store,
    )?;
    let (application, validation_store, validation_owner) = host.into_anchor_ordinary_parts_v0()?;
    let (core, startup_effects) = activation.into_parts_v0();
    let signer = pinned_signer
        .activate_v0()
        .map_err(PocoNodeNativeH1OrdinaryTakeoverErrorV0::SignerActivation)?;
    Ok(PocoNodeNativeH1OrdinaryHostV0 {
        core,
        seal_authority,
        startup_effects,
        retired_source_safety_store: None,
        safety_store,
        application,
        validation_store,
        validation_owner,
        signer,
        checkpoint_store,
        checkpoint,
        h2,
        h3,
    })
}

struct CommissionedSuccessorReconcilerV0<'a, W: ExternalMonotonicWatermarkV0> {
    safety_store: &'a SqliteSafetyStateStoreV0<StrictEd25519Verifier>,
    safety: &'a trnm_consensus_safety_store::ConfirmedSafetyNodeCheckpointFactsV0,
    application: &'a DurableNativeApplicationV0,
    installed_head: &'a ApplicationHeadV0,
    pinned_signer: &'a PinnedSqliteSignerJournalV0<W>,
    signer: &'a trnm_consensus_signer_journal::ConfirmedSignerNodeCheckpointFactsV0,
    validation_store: &'a mut SqliteProposalValidationStoreV0,
    checkpoint_store: &'a mut SqliteExternalNodeCheckpointStoreV0,
    checkpoint: ExternalNodeCheckpointV0,
}

impl<W: ExternalMonotonicWatermarkV0> StateSyncAnchorSuccessorRecoveryReconcilerV0
    for CommissionedSuccessorReconcilerV0<'_, W>
{
    fn reconcile_state_sync_anchor_successors_v0(
        &mut self,
        challenge: &StateSyncAnchorSuccessorRecoveryChallengeV0,
    ) -> bool {
        (|| {
            let anchor = challenge.safety_state().state_sync_anchor()?;
            let h1 = anchor.proof().finalized_block().header();
            let observed = self.checkpoint_store.load(self.checkpoint.scope()).ok()??;
            let sequence = self.validation_store.durable_sequence_v0().ok()?;
            (self
                .safety
                .belongs_to_store_at_path_v0(self.safety_store, self.safety_store.path())
                && self.safety.state_v0() == challenge.safety_state()
                && self.installed_head.height().get() == h1.height().get()
                && self.installed_head.block_id().as_bytes() == h1.id().as_bytes()
                && self.installed_head.state_root().as_bytes() == h1.state_root().as_bytes()
                && self
                    .application
                    .confirmed_committed_head_v0()
                    .is_ok_and(|head| head == *self.installed_head)
                && self.signer.belongs_to_pinned_journal_at_path_v0(
                    self.pinned_signer,
                    self.pinned_signer.path(),
                )
                && self.signer.capacity().intent_count() == 0
                && self.signer.capacity().event_count() == 0
                && self.signer.pending_intent().is_none()
                && sequence == 0
                && observed == self.checkpoint)
                .then_some(())
        })()
        .is_some()
    }
}

struct RecoveredSuccessorCutV0 {
    phase: StateSyncAnchorSuccessorPhaseV0,
    checkpoint: ExternalNodeCheckpointV0,
    application_head: ApplicationHeadV0,
    application_overlay: Option<BlockIdOverlayRefV0>,
    pending_binding: Option<ProposalValidationBindingV0>,
    h2: Option<ReconciledSuccessorRowV0>,
    h3: Option<ReconciledSuccessorRowV0>,
}

struct RestartSuccessorReconcilerV0<'a, W: ExternalMonotonicWatermarkV0> {
    core_config: &'a CoreConfig,
    safety_store: &'a SqliteSafetyStateStoreV0<StrictEd25519Verifier>,
    safety: &'a trnm_consensus_safety_store::ConfirmedSafetyNodeCheckpointFactsV0,
    application: &'a DurableNativeApplicationV0,
    installed_head: &'a ApplicationHeadV0,
    pinned_signer: &'a PinnedSqliteSignerJournalV0<W>,
    signer: &'a trnm_consensus_signer_journal::ConfirmedSignerNodeCheckpointFactsV0,
    validation_store: &'a mut SqliteProposalValidationStoreV0,
    checkpoint_store: &'a mut SqliteExternalNodeCheckpointStoreV0,
    recovered: Option<RecoveredSuccessorCutV0>,
}

impl<W: ExternalMonotonicWatermarkV0> StateSyncAnchorSuccessorRecoveryReconcilerV0
    for RestartSuccessorReconcilerV0<'_, W>
{
    fn reconcile_state_sync_anchor_successors_v0(
        &mut self,
        challenge: &StateSyncAnchorSuccessorRecoveryChallengeV0,
    ) -> bool {
        match reconcile_restarted_successor_cut_v0::<W>(
            self.core_config,
            challenge,
            self.safety_store,
            self.safety,
            self.application,
            self.installed_head,
            self.pinned_signer,
            self.signer,
            self.validation_store,
            self.checkpoint_store,
        ) {
            Ok(recovered) => {
                self.recovered = Some(recovered);
                true
            }
            Err(_) => false,
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn reconcile_restarted_successor_cut_v0<W: ExternalMonotonicWatermarkV0>(
    core_config: &CoreConfig,
    challenge: &StateSyncAnchorSuccessorRecoveryChallengeV0,
    safety_store: &SqliteSafetyStateStoreV0<StrictEd25519Verifier>,
    safety: &trnm_consensus_safety_store::ConfirmedSafetyNodeCheckpointFactsV0,
    application: &DurableNativeApplicationV0,
    installed_head: &ApplicationHeadV0,
    pinned_signer: &PinnedSqliteSignerJournalV0<W>,
    signer: &trnm_consensus_signer_journal::ConfirmedSignerNodeCheckpointFactsV0,
    validation_store: &mut SqliteProposalValidationStoreV0,
    checkpoint_store: &mut SqliteExternalNodeCheckpointStoreV0,
) -> Result<RecoveredSuccessorCutV0, PocoNodeNativeH1OrdinaryTakeoverErrorV0<W>> {
    let phase = challenge.phase();
    let anchor = challenge.safety_state().state_sync_anchor().ok_or(
        PocoNodeNativeH1OrdinaryTakeoverErrorV0::Rejected(
            "anchored successor recovery lost its h1 anchor",
        ),
    )?;
    let h1 = anchor.proof().finalized_block().header();
    if !safety.belongs_to_store_at_path_v0(safety_store, safety_store.path())
        || safety.state_v0() != challenge.safety_state()
        || installed_head.height().get() != h1.height().get()
        || installed_head.block_id().as_bytes() != h1.id().as_bytes()
        || installed_head.state_root().as_bytes() != h1.state_root().as_bytes()
        || application.confirmed_committed_head_v0()? != *installed_head
        || !signer.belongs_to_pinned_journal_at_path_v0(pinned_signer, pinned_signer.path())
        || signer.capacity().intent_count() != 0
        || signer.capacity().event_count() != 0
        || signer.pending_intent().is_some()
    {
        return Err(PocoNodeNativeH1OrdinaryTakeoverErrorV0::Rejected(
            "restart Safety/App/signer join differs",
        ));
    }

    let expected_sequence = match phase {
        StateSyncAnchorSuccessorPhaseV0::H1Bootstrap => 0,
        StateSyncAnchorSuccessorPhaseV0::H2ValidationPending => 1,
        StateSyncAnchorSuccessorPhaseV0::H2Valid => 3,
        StateSyncAnchorSuccessorPhaseV0::H3ValidationPending => 4,
        StateSyncAnchorSuccessorPhaseV0::H3Valid => 6,
    };
    if validation_store.durable_sequence_v0()? != expected_sequence {
        return Err(PocoNodeNativeH1OrdinaryTakeoverErrorV0::Rejected(
            "restart validation sequence differs",
        ));
    }

    let h2_completion = challenge
        .safety_state()
        .payload_validation_completions()
        .iter()
        .find(|completion| {
            completion.route() == trnm_consensus_core::PayloadValidationRouteV0::Synced
                && completion.id().block_id() == challenge.child().block().id()
                && completion.first_recorded_revision() == 2
        });
    let h2 = if matches!(
        phase,
        StateSyncAnchorSuccessorPhaseV0::H2Valid
            | StateSyncAnchorSuccessorPhaseV0::H3ValidationPending
            | StateSyncAnchorSuccessorPhaseV0::H3Valid
    ) {
        let completion = h2_completion.ok_or(PocoNodeNativeH1OrdinaryTakeoverErrorV0::Rejected(
            "restart cut lacks the h2 completion",
        ))?;
        Some(reconcile_successor_row_v0::<W>(
            validation_store,
            application,
            challenge.child(),
            installed_head.clone(),
            completion.id(),
            DurableValidationStageV0::Acked,
            Some(completion),
            core_config,
        )?)
    } else {
        None
    };
    let h3_completion = challenge
        .safety_state()
        .payload_validation_completions()
        .iter()
        .find(|completion| {
            completion.route() == trnm_consensus_core::PayloadValidationRouteV0::Synced
                && completion.id().block_id() == challenge.grandchild().block().id()
                && completion.first_recorded_revision() == 4
        });
    let h3 = if phase == StateSyncAnchorSuccessorPhaseV0::H3Valid {
        let completion = h3_completion.ok_or(PocoNodeNativeH1OrdinaryTakeoverErrorV0::Rejected(
            "restart cut lacks the h3 completion",
        ))?;
        Some(reconcile_successor_row_v0::<W>(
            validation_store,
            application,
            challenge.grandchild(),
            h2.as_ref()
                .ok_or(PocoNodeNativeH1OrdinaryTakeoverErrorV0::Rejected(
                    "h3 restart lacks h2 parent",
                ))?
                .application_head
                .clone(),
            completion.id(),
            DurableValidationStageV0::Acked,
            Some(completion),
            core_config,
        )?)
    } else {
        None
    };

    let pending_binding = match phase {
        StateSyncAnchorSuccessorPhaseV0::H2ValidationPending
        | StateSyncAnchorSuccessorPhaseV0::H3ValidationPending => {
            let [obligation] = challenge.safety_state().payload_validation_obligations() else {
                return Err(PocoNodeNativeH1OrdinaryTakeoverErrorV0::Rejected(
                    "restart pending cut lacks one obligation",
                ));
            };
            let (proposal, parent) =
                if phase == StateSyncAnchorSuccessorPhaseV0::H2ValidationPending {
                    (challenge.child(), installed_head.clone())
                } else {
                    (
                        challenge.grandchild(),
                        h2.as_ref()
                            .ok_or(PocoNodeNativeH1OrdinaryTakeoverErrorV0::Rejected(
                                "h3 pending restart lacks h2 parent",
                            ))?
                            .application_head
                            .clone(),
                    )
                };
            let row = reconcile_successor_row_v0::<W>(
                validation_store,
                application,
                proposal,
                parent,
                obligation.id(),
                DurableValidationStageV0::Reserved,
                None,
                core_config,
            )?;
            Some(row.binding)
        }
        StateSyncAnchorSuccessorPhaseV0::H1Bootstrap
        | StateSyncAnchorSuccessorPhaseV0::H2Valid
        | StateSyncAnchorSuccessorPhaseV0::H3Valid => None,
    };

    let h2_context = h2
        .as_ref()
        .map(|row| {
            validation_store
                .reconstruct_anchor_successor_native_valid_context_from_k_v0(&row.binding)
        })
        .transpose()?;
    let h3_context = h3
        .as_ref()
        .map(|row| {
            validation_store
                .reconstruct_anchor_successor_native_valid_context_from_k_v0(&row.binding)
        })
        .transpose()?;
    match phase {
        StateSyncAnchorSuccessorPhaseV0::H2Valid => {
            let current = safety_store.confirmed_native_valid_head_exact_v0(
                challenge.safety_state(),
                h2_context
                    .as_ref()
                    .ok_or(PocoNodeNativeH1OrdinaryTakeoverErrorV0::Rejected(
                        "rev2 restart lacks h2 context",
                    ))?,
            )?;
            if current.revision() != 2
                || !current.belongs_to_store_at_path_v0(safety_store, safety_store.path())
            {
                return Err(PocoNodeNativeH1OrdinaryTakeoverErrorV0::Rejected(
                    "rev2 current Safety capability is foreign",
                ));
            }
        }
        StateSyncAnchorSuccessorPhaseV0::H3Valid => {
            let current = safety_store.confirmed_native_valid_head_exact_v0(
                challenge.safety_state(),
                h3_context
                    .as_ref()
                    .ok_or(PocoNodeNativeH1OrdinaryTakeoverErrorV0::Rejected(
                        "rev4 restart lacks h3 context",
                    ))?,
            )?;
            if current.revision() != 4
                || !current.belongs_to_store_at_path_v0(safety_store, safety_store.path())
            {
                return Err(PocoNodeNativeH1OrdinaryTakeoverErrorV0::Rejected(
                    "rev4 current Safety capability is foreign",
                ));
            }
            let historical = safety_store.confirm_anchored_successor_h2_transition_from_rev4_v0(
                challenge,
                h2_context
                    .as_ref()
                    .and_then(|context| context.native_valid_transition())
                    .ok_or(PocoNodeNativeH1OrdinaryTakeoverErrorV0::Rejected(
                        "rev4 restart lacks historical h2 context",
                    ))?,
            )?;
            if historical.journal_id_v0() != safety.journal_id_v0()
                || historical.verifier_profile_ref_v0() != safety.verifier_profile_ref_v0()
                || Some(historical.transition_v0())
                    != h2_context
                        .as_ref()
                        .and_then(|context| context.native_valid_transition())
            {
                return Err(PocoNodeNativeH1OrdinaryTakeoverErrorV0::Rejected(
                    "rev4 historical h2 Safety capability differs",
                ));
            }
        }
        StateSyncAnchorSuccessorPhaseV0::H1Bootstrap
        | StateSyncAnchorSuccessorPhaseV0::H2ValidationPending
        | StateSyncAnchorSuccessorPhaseV0::H3ValidationPending => {}
    }

    let checkpoint = checkpoint_store
        .load(signer.exact_watermark().scope())?
        .ok_or(PocoNodeNativeH1OrdinaryTakeoverErrorV0::Rejected(
            "restart whole-node checkpoint is absent",
        ))?;
    let (stable_head, stable_overlay, stable_binding, stable_header, stable_revision, generation) =
        match phase {
            StateSyncAnchorSuccessorPhaseV0::H1Bootstrap
            | StateSyncAnchorSuccessorPhaseV0::H2ValidationPending => {
                (installed_head.clone(), None, None, h1, 0, 0)
            }
            StateSyncAnchorSuccessorPhaseV0::H2Valid
            | StateSyncAnchorSuccessorPhaseV0::H3ValidationPending => {
                let row = h2
                    .as_ref()
                    .ok_or(PocoNodeNativeH1OrdinaryTakeoverErrorV0::Rejected(
                        "restart checkpoint lacks h2",
                    ))?;
                (
                    row.application_head.clone(),
                    Some(row.overlay),
                    Some(&row.binding),
                    challenge.child().block().header(),
                    2,
                    1,
                )
            }
            StateSyncAnchorSuccessorPhaseV0::H3Valid => {
                let row = h3
                    .as_ref()
                    .ok_or(PocoNodeNativeH1OrdinaryTakeoverErrorV0::Rejected(
                        "restart checkpoint lacks h3",
                    ))?;
                (
                    row.application_head.clone(),
                    Some(row.overlay),
                    Some(&row.binding),
                    challenge.grandchild().block().header(),
                    4,
                    2,
                )
            }
        };
    let fields = checkpoint.fields();
    if checkpoint.generation() != generation
        || checkpoint.scope() != signer.exact_watermark().scope()
        || fields.safety_journal_id != safety.journal_id_v0()
        || fields.safety_verifier_profile_ref != safety.verifier_profile_ref_v0()
        || fields.safety_revision != stable_revision
        || fields.application_block_id.as_bytes() != stable_head.block_id().as_bytes()
        || fields.application_height != stable_head.height().get()
        || fields.application_state_root.as_bytes() != stable_head.state_root().as_bytes()
        || fields.application_view != stable_header.view().get()
        || fields.application_timestamp_ms != stable_header.timestamp_ms()
        || fields.signer_journal_id != signer.journal_id()
        || fields.signer_profile_checksum != signer.profile_checksum()
        || fields.signer_exact_watermark != signer.exact_watermark()
    {
        return Err(PocoNodeNativeH1OrdinaryTakeoverErrorV0::Rejected(
            "restart whole-node checkpoint differs",
        ));
    }
    if let Some(binding) = stable_binding {
        let closure = validation_store.inspect_request_bound_safety_closure_exact_v0(binding)?;
        if closure.safety_revision() != stable_revision
            || closure.safety_record_digest().as_bytes() != &fields.safety_state_record_checksum
        {
            return Err(PocoNodeNativeH1OrdinaryTakeoverErrorV0::Rejected(
                "restart checkpoint differs from terminal K",
            ));
        }
    } else if phase == StateSyncAnchorSuccessorPhaseV0::H1Bootstrap
        && fields.safety_state_record_checksum != safety.state_record_checksum_v0()
    {
        return Err(PocoNodeNativeH1OrdinaryTakeoverErrorV0::Rejected(
            "rev0 restart checkpoint differs from Safety",
        ));
    }

    Ok(RecoveredSuccessorCutV0 {
        phase,
        checkpoint,
        application_head: stable_head,
        application_overlay: stable_overlay,
        pending_binding,
        h2,
        h3,
    })
}

fn drive_fresh_successor_v0<W: ExternalMonotonicWatermarkV0, V: SignatureVerifier>(
    replay: &mut StateSyncAnchorSuccessorReplayV0,
    host: &mut PocoNodeNativeProposalPHostV0<DurableNativeApplicationV0>,
    safety_store: &mut SqliteSafetyStateStoreV0<V>,
    seal_authority: &trnm_consensus_core::CoreIssuedApplicationSealAuthorityV0,
    verifier: &V,
) -> Result<(u64, PocoNodeNativeApplicationAckedKV0), PocoNodeNativeH1OrdinaryTakeoverErrorV0<W>> {
    let obligation = exact_persistence_v0(replay.step_next_proposal_v0(verifier)?)?;
    safety_store.persist_exact_v0(&obligation, &SafetyTransitionContextV0::Ordinary)?;
    let request =
        exact_synced_request_v0(replay.step_storage_ack_v0(obligation.barrier(), verifier)?)?;
    let claimed = request.try_claim().map_err(|_| {
        PocoNodeNativeH1OrdinaryTakeoverErrorV0::Rejected(
            "the anchored successor request was already claimed",
        )
    })?;
    let persisted = host.execute_and_persist_p_v0(claimed)?;
    let delivered = match host.seal_anchor_successor_valid_and_deliver_core_d_v0(
        persisted,
        replay,
        seal_authority,
        verifier,
    )? {
        PocoNodeNativeCoreDOutcomeV0::Applied(value) => *value,
        PocoNodeNativeCoreDOutcomeV0::NotApplied(value) => match host.retry_core_d_v0(*value)? {
            PocoNodeNativeCoreDOutcomeV0::Applied(value) => *value,
            PocoNodeNativeCoreDOutcomeV0::NotApplied(_) => {
                return Err(PocoNodeNativeH1OrdinaryTakeoverErrorV0::Rejected(
                    "Core D remained unapplied after exact retry",
                ));
            }
        },
    };
    let safety_path = safety_store.path().to_path_buf();
    let acked = match host.persist_anchor_successor_safety_c_and_ack_k_v0(
        delivered,
        safety_store,
        &safety_path,
    )? {
        PocoNodeNativeKOutcomeV0::Applied(value) => *value,
        PocoNodeNativeKOutcomeV0::NotApplied(value) => {
            match host.retry_anchor_successor_ack_k_v0(*value, safety_store, &safety_path)? {
                PocoNodeNativeKOutcomeV0::Applied(value) => *value,
                PocoNodeNativeKOutcomeV0::NotApplied(_) => {
                    return Err(PocoNodeNativeH1OrdinaryTakeoverErrorV0::Rejected(
                        "application K remained unapplied after exact retry",
                    ));
                }
            }
        }
    };
    Ok((obligation.state().revision(), acked))
}

fn reconciled_completed_v0<W>(
    row: ReconciledSuccessorRowV0,
    safety_revision: u64,
) -> Result<PocoNodeNativeAnchoredSuccessorCompletedV0, PocoNodeNativeH1OrdinaryTakeoverErrorV0<W>>
{
    PocoNodeNativeAnchoredSuccessorCompletedV0::from_reconciled_terminal_k_v0(
        row.binding,
        row.application_head,
        row.overlay,
        safety_revision,
    )
    .ok_or(PocoNodeNativeH1OrdinaryTakeoverErrorV0::Rejected(
        "reconciled terminal K facts differ",
    ))
}

fn drive_recovered_successor_v0<W: ExternalMonotonicWatermarkV0, V: SignatureVerifier>(
    replay: &mut StateSyncAnchorSuccessorReplayV0,
    host: &mut PocoNodeNativeProposalPHostV0<DurableNativeApplicationV0>,
    safety_store: &mut SqliteSafetyStateStoreV0<V>,
    seal_authority: &trnm_consensus_core::CoreIssuedApplicationSealAuthorityV0,
    binding: ProposalValidationBindingV0,
    verifier: &V,
) -> Result<PocoNodeNativeApplicationAckedKV0, PocoNodeNativeH1OrdinaryTakeoverErrorV0<W>> {
    let obligation = replay.pending_obligation_persistence_v0()?;
    safety_store.persist_exact_v0(&obligation, &SafetyTransitionContextV0::Ordinary)?;
    let request =
        exact_synced_request_v0(replay.step_storage_ack_v0(obligation.barrier(), verifier)?)?;
    let claimed = request.try_claim().map_err(|_| {
        PocoNodeNativeH1OrdinaryTakeoverErrorV0::Rejected(
            "the recovered anchored successor request was already claimed",
        )
    })?;
    let persisted = host.recover_anchor_successor_p_v0(claimed, binding)?;
    let delivered = match host.seal_anchor_successor_valid_and_deliver_core_d_v0(
        persisted,
        replay,
        seal_authority,
        verifier,
    )? {
        PocoNodeNativeCoreDOutcomeV0::Applied(value) => *value,
        PocoNodeNativeCoreDOutcomeV0::NotApplied(value) => match host.retry_core_d_v0(*value)? {
            PocoNodeNativeCoreDOutcomeV0::Applied(value) => *value,
            PocoNodeNativeCoreDOutcomeV0::NotApplied(_) => {
                return Err(PocoNodeNativeH1OrdinaryTakeoverErrorV0::Rejected(
                    "recovered Core D remained unapplied after exact retry",
                ));
            }
        },
    };
    let safety_path = safety_store.path().to_path_buf();
    match host.persist_anchor_successor_safety_c_and_ack_k_v0(
        delivered,
        safety_store,
        &safety_path,
    )? {
        PocoNodeNativeKOutcomeV0::Applied(value) => Ok(*value),
        PocoNodeNativeKOutcomeV0::NotApplied(value) => {
            match host.retry_anchor_successor_ack_k_v0(*value, safety_store, &safety_path)? {
                PocoNodeNativeKOutcomeV0::Applied(value) => Ok(*value),
                PocoNodeNativeKOutcomeV0::NotApplied(_) => {
                    Err(PocoNodeNativeH1OrdinaryTakeoverErrorV0::Rejected(
                        "recovered application K remained unapplied after exact retry",
                    ))
                }
            }
        }
    }
}

fn exact_persistence_v0<W>(
    effects: Vec<Effect>,
) -> Result<SafetyStatePersistenceV0, PocoNodeNativeH1OrdinaryTakeoverErrorV0<W>> {
    if !matches!(effects.as_slice(), [Effect::PersistSafetyState(_)]) {
        return Err(PocoNodeNativeH1OrdinaryTakeoverErrorV0::Rejected(
            "Core did not emit one exact Safety persistence request",
        ));
    }
    match effects.into_iter().next() {
        Some(Effect::PersistSafetyState(request)) => Ok(request),
        _ => unreachable!("the exact effect shape was checked"),
    }
}

fn exact_synced_request_v0<W>(
    effects: Vec<Effect>,
) -> Result<trnm_consensus_core::PayloadValidationRequest, PocoNodeNativeH1OrdinaryTakeoverErrorV0<W>>
{
    if !matches!(effects.as_slice(), [Effect::ValidateSyncedPayload(_)]) {
        return Err(PocoNodeNativeH1OrdinaryTakeoverErrorV0::Rejected(
            "Core did not release one exact Synced validation request",
        ));
    }
    match effects.into_iter().next() {
        Some(Effect::ValidateSyncedPayload(request))
            if request.route() == trnm_consensus_core::PayloadValidationRouteV0::Synced =>
        {
            Ok(request)
        }
        _ => Err(PocoNodeNativeH1OrdinaryTakeoverErrorV0::Rejected(
            "Core did not release one exact Synced validation request",
        )),
    }
}

#[derive(Clone, Copy)]
enum CheckpointAdvanceKindV0 {
    Successor,
    Promotion,
}

fn checkpoint_anchored_k_v0<W: ExternalMonotonicWatermarkV0>(
    kind: CheckpointAdvanceKindV0,
    predecessor: ExternalNodeCheckpointV0,
    checkpoint_store: &mut SqliteExternalNodeCheckpointStoreV0,
    safety_store: &SqliteSafetyStateStoreV0<StrictEd25519Verifier>,
    pinned_signer: &mut PinnedSqliteSignerJournalV0<W>,
    host: &mut PocoNodeNativeProposalPHostV0<DurableNativeApplicationV0>,
    acked: &PocoNodeNativeApplicationAckedKV0,
) -> Result<ExternalNodeCheckpointV0, PocoNodeNativeH1OrdinaryTakeoverErrorV0<W>> {
    let application = host.confirm_anchor_successor_k_checkpoint_facts_v0(acked)?;
    checkpoint_confirmed_application_v0(
        kind,
        predecessor,
        checkpoint_store,
        safety_store,
        pinned_signer,
        host,
        application,
    )
}

fn checkpoint_confirmed_application_v0<W: ExternalMonotonicWatermarkV0>(
    kind: CheckpointAdvanceKindV0,
    predecessor: ExternalNodeCheckpointV0,
    checkpoint_store: &mut SqliteExternalNodeCheckpointStoreV0,
    safety_store: &SqliteSafetyStateStoreV0<StrictEd25519Verifier>,
    pinned_signer: &mut PinnedSqliteSignerJournalV0<W>,
    host: &PocoNodeNativeProposalPHostV0<DurableNativeApplicationV0>,
    application: ConfirmedProposalValidationCheckpointFactsV0,
) -> Result<ExternalNodeCheckpointV0, PocoNodeNativeH1OrdinaryTakeoverErrorV0<W>> {
    let safety_head = safety_store.head()?;
    let safety = safety_store.confirm_node_checkpoint_head_exact_v0(safety_head.state())?;
    let signer = pinned_signer.confirm_node_checkpoint_head_exact_v0()?;
    if !safety.belongs_to_store_at_path_v0(safety_store, safety_store.path())
        || !application.belongs_to_store_at_path_v0(
            host.validation_store_v0(),
            host.application_store_path_v0(),
        )
        || !signer.belongs_to_pinned_journal_at_path_v0(pinned_signer, pinned_signer.path())
    {
        return Err(PocoNodeNativeH1OrdinaryTakeoverErrorV0::Rejected(
            "checkpoint facts lost their live owner affinity",
        ));
    }
    let binding = application.binding_v0();
    let closure = application.safety_closure_v0();
    let state = safety.state_v0();
    let predecessor_fields = predecessor.fields();
    let successor_edge = predecessor_fields.application_block_id.as_bytes()
        == binding.parent().block_id().as_bytes()
        && predecessor_fields.application_height + 1 == binding.height().get()
        && predecessor_fields.application_state_root.as_bytes()
            == binding.parent().state_root().as_bytes();
    let promotion_edge = predecessor_fields.application_block_id.as_bytes()
        == binding.block_id().as_bytes()
        && predecessor_fields.application_height == binding.height().get();
    if predecessor.scope() != signer.exact_watermark().scope()
        || predecessor_fields.safety_journal_id != safety.journal_id_v0()
        || predecessor_fields.safety_verifier_profile_ref != safety.verifier_profile_ref_v0()
        || predecessor_fields.safety_revision >= safety.revision_v0()
        || predecessor_fields.signer_journal_id != signer.journal_id()
        || predecessor_fields.signer_profile_checksum != signer.profile_checksum()
        || predecessor_fields.signer_exact_watermark != signer.exact_watermark()
        || signer.capacity().intent_count() != 0
        || signer.capacity().event_count() != 0
        || signer.pending_intent().is_some()
        || state.state_sync_anchor().is_none()
        || state.pending_sign().is_some()
        || closure.validation_id() != binding.validation_id()
        || closure.core_delivery_digest() != application.core_delivery_digest_v0()
        || closure.safety_record_digest().as_bytes() != &safety.state_record_checksum_v0()
            && matches!(kind, CheckpointAdvanceKindV0::Successor)
        || closure.safety_revision() != safety.revision_v0()
            && matches!(kind, CheckpointAdvanceKindV0::Successor)
        || !match kind {
            CheckpointAdvanceKindV0::Successor => successor_edge,
            CheckpointAdvanceKindV0::Promotion => {
                promotion_edge && safety.revision_v0() == 5 && closure.safety_revision() == 4
            }
        }
    {
        return Err(PocoNodeNativeH1OrdinaryTakeoverErrorV0::Rejected(
            "checkpoint Safety/App/signer join differs",
        ));
    }

    let generation = predecessor.generation().checked_add(1).ok_or(
        PocoNodeNativeH1OrdinaryTakeoverErrorV0::Rejected("checkpoint generation overflow"),
    )?;
    let safety_revision = safety.revision_v0().to_be_bytes();
    let row_revision = application.row_revision_v0().to_be_bytes();
    let sequence = application.store_sequence_v0().to_be_bytes();
    let application_host_config_ref = checkpoint_hash_v0(
        TAKEOVER_CHECKPOINT_OWNER_DOMAIN_V0,
        &[
            application.scope_v0().as_bytes(),
            &application.store_id_v0(),
            binding.chain_id().as_str().as_bytes(),
            binding.genesis_hash().as_bytes(),
        ],
    );
    let application_projection_profile_ref = checkpoint_hash_v0(
        TAKEOVER_CHECKPOINT_PROFILE_DOMAIN_V0,
        &[
            b"proposal-validation-schema-3",
            b"anchored-synced-terminal-k",
        ],
    );
    let application_safety_binding_manifest_checksum = checkpoint_hash_v0(
        TAKEOVER_CHECKPOINT_SAFETY_DOMAIN_V0,
        &[
            &safety.journal_id_v0(),
            &safety.verifier_profile_ref_v0(),
            &safety.core_config_ref_v0(),
            &safety_revision,
            &safety.state_record_checksum_v0(),
            &safety.chain_checksum_v0(),
            closure.core_delivery_digest().as_bytes(),
            closure.safety_record_digest().as_bytes(),
            closure.vote_intent_digest().as_bytes(),
        ],
    );
    let application_recovery_closure_checksum = checkpoint_hash_v0(
        TAKEOVER_CHECKPOINT_RECOVERY_DOMAIN_V0,
        &[
            binding.validation_id().as_bytes(),
            application.artifact_digest_v0().as_bytes(),
            application.core_delivery_digest_v0().as_bytes(),
            closure.safety_record_digest().as_bytes(),
            &row_revision,
            &sequence,
        ],
    );
    let target = ExternalNodeCheckpointV0::new(ExternalNodeCheckpointFieldsV0 {
        scope: predecessor.scope(),
        generation,
        predecessor_checksum: predecessor.checkpoint_checksum(),
        safety_journal_id: safety.journal_id_v0(),
        safety_verifier_profile_ref: safety.verifier_profile_ref_v0(),
        safety_revision: safety.revision_v0(),
        safety_state_record_checksum: safety.state_record_checksum_v0(),
        safety_record_chain_checksum: safety.chain_checksum_v0(),
        application_host_config_ref,
        application_projection_profile_ref,
        application_safety_binding_manifest_checksum,
        application_committed_head_row_checksum: *application.row_checksum_v0().as_bytes(),
        application_recovery_closure_checksum,
        application_block_id: BlockId::new(*binding.block_id().as_bytes()),
        application_height: binding.height().get(),
        application_state_root: StateRoot::new(*binding.commitments().post_state_root().as_bytes()),
        application_view: binding.view(),
        application_timestamp_ms: binding.timestamp_ms(),
        signer_journal_id: signer.journal_id(),
        signer_profile_checksum: signer.profile_checksum(),
        signer_exact_watermark: signer.exact_watermark(),
    })?;
    target.validate_successor_of(&predecessor)?;
    let compare = checkpoint_store.compare_and_advance(Some(predecessor), target);
    let observed = checkpoint_store.load(target.scope())?;
    match observed {
        Some(value) if value == target => Ok(value),
        Some(value) if value == predecessor => {
            let _ = compare;
            Err(PocoNodeNativeH1OrdinaryTakeoverErrorV0::Rejected(
                "checkpoint compare was not applied",
            ))
        }
        _ => Err(PocoNodeNativeH1OrdinaryTakeoverErrorV0::Rejected(
            "checkpoint CAS observed a third state",
        )),
    }
}

fn validate_final_join_v0<W: ExternalMonotonicWatermarkV0>(
    checkpoint: &ExternalNodeCheckpointV0,
    safety: &trnm_consensus_safety_store::ConfirmedSafetyNodeCheckpointFactsV0,
    application: &ConfirmedProposalValidationCheckpointFactsV0,
    signer: &trnm_consensus_signer_journal::ConfirmedSignerNodeCheckpointFactsV0,
    pinned_signer: &PinnedSqliteSignerJournalV0<W>,
    checkpoint_store: &mut SqliteExternalNodeCheckpointStoreV0,
) -> Result<(), PocoNodeNativeH1OrdinaryTakeoverErrorV0<W>> {
    let fields = checkpoint.fields();
    let observed = checkpoint_store.load(checkpoint.scope())?;
    if safety.revision_v0() != 5
        || fields.safety_revision != 5
        || fields.safety_state_record_checksum != safety.state_record_checksum_v0()
        || fields.application_block_id.as_bytes() != application.binding_v0().block_id().as_bytes()
        || fields.application_height != application.binding_v0().height().get()
        || fields.signer_journal_id != signer.journal_id()
        || fields.signer_profile_checksum != signer.profile_checksum()
        || fields.signer_exact_watermark != signer.exact_watermark()
        || !signer.belongs_to_pinned_journal_at_path_v0(pinned_signer, pinned_signer.path())
        || signer.capacity().intent_count() != 0
        || signer.capacity().event_count() != 0
        || signer.pending_intent().is_some()
        || observed != Some(*checkpoint)
    {
        return Err(PocoNodeNativeH1OrdinaryTakeoverErrorV0::Rejected(
            "final rev5 App/Safety/checkpoint/signer join differs",
        ));
    }
    Ok(())
}

struct ReconciledSuccessorRowV0 {
    binding: ProposalValidationBindingV0,
    application_head: ApplicationHeadV0,
    overlay: BlockIdOverlayRefV0,
}

fn native_successor_request_v0<W>(
    block: &trnm_consensus_types::Block,
    parent: ApplicationHeadV0,
    parameters: &trnm_consensus_types::ConsensusParametersV0,
) -> Result<NativeBlockExecutionRequestV0, PocoNodeNativeH1OrdinaryTakeoverErrorV0<W>> {
    let header = block.header();
    if header.block_kind() != BlockKind::Regular
        || header.height().get() != parent.height().get().saturating_add(1)
        || header.parent_id().as_bytes() != parent.block_id().as_bytes()
    {
        return Err(PocoNodeNativeH1OrdinaryTakeoverErrorV0::Rejected(
            "native successor geometry differs",
        ));
    }
    let payload = decode_application_payload_v0_exact(block.application_payload(), parameters)
        .map_err(|_| {
            PocoNodeNativeH1OrdinaryTakeoverErrorV0::Rejected(
                "native successor payload is not canonical",
            )
        })?;
    let expected = NativeExpectedBlockCommitmentsV0::new(
        Hash32V0::new(*header.payload_root().as_bytes()),
        StateRootV0::new(*header.state_root().as_bytes()).map_err(|_| {
            PocoNodeNativeH1OrdinaryTakeoverErrorV0::Rejected("native successor state root is zero")
        })?,
        ReceiptsRootV0::new(*header.receipts_root().as_bytes()).map_err(|_| {
            PocoNodeNativeH1OrdinaryTakeoverErrorV0::Rejected(
                "native successor receipts root is zero",
            )
        })?,
        Hash32V0::new(*header.evidence_root().as_bytes()),
    )
    .map_err(|_| {
        PocoNodeNativeH1OrdinaryTakeoverErrorV0::Rejected("native successor commitments differ")
    })?;
    NativeBlockExecutionRequestV0::new(
        ChainIdV0::new(header.chain_id().as_str()).map_err(|_| {
            PocoNodeNativeH1OrdinaryTakeoverErrorV0::Rejected("invalid native chain id")
        })?,
        GenesisHashV0::new(*header.genesis_hash().as_bytes()).map_err(|_| {
            PocoNodeNativeH1OrdinaryTakeoverErrorV0::Rejected("invalid native genesis hash")
        })?,
        parent,
        BlockIdV0::new(*block.id().as_bytes()).map_err(|_| {
            PocoNodeNativeH1OrdinaryTakeoverErrorV0::Rejected("invalid native block id")
        })?,
        HeightV0::new(header.height().get()),
        header.timestamp_ms(),
        ValidatorSetIdV0::new(*header.validator_set_id().as_bytes()).map_err(|_| {
            PocoNodeNativeH1OrdinaryTakeoverErrorV0::Rejected("invalid native validator-set id")
        })?,
        payload.transactions().to_vec(),
        expected,
    )
    .map_err(|_| {
        PocoNodeNativeH1OrdinaryTakeoverErrorV0::Rejected(
            "native successor execution request differs",
        )
    })
}

fn successor_binding_v0<W>(
    proposal: &SignedProposalV0,
    parent: ApplicationHeadV0,
    id: ValidationId,
    config: &CoreConfig,
) -> Result<ProposalValidationBindingV0, PocoNodeNativeH1OrdinaryTakeoverErrorV0<W>> {
    let block = proposal.block();
    let request = native_successor_request_v0::<W>(block, parent, config.consensus_parameters())?;
    if id.block_id() != block.id() || id.view() != block.header().view() || id.generation() == 0 {
        return Err(PocoNodeNativeH1OrdinaryTakeoverErrorV0::Rejected(
            "Core successor validation id differs",
        ));
    }
    ProposalValidationBindingV0::new(
        request.chain_id().clone(),
        request.genesis_hash(),
        request.parent().clone(),
        request.block_id(),
        request.height(),
        request.timestamp_ms(),
        request.active_validator_set_id(),
        id.view().get(),
        id.generation(),
        ProposalRouteV0::Synced,
        request.expected(),
    )
    .map_err(PocoNodeNativeH1OrdinaryTakeoverErrorV0::Validation)
}

#[allow(clippy::too_many_arguments)]
fn reconcile_successor_row_v0<W: ExternalMonotonicWatermarkV0>(
    store: &mut SqliteProposalValidationStoreV0,
    application: &DurableNativeApplicationV0,
    proposal: &SignedProposalV0,
    parent: ApplicationHeadV0,
    id: ValidationId,
    expected_stage: DurableValidationStageV0,
    completion: Option<&DurablePayloadValidationCompletionV0>,
    config: &CoreConfig,
) -> Result<ReconciledSuccessorRowV0, PocoNodeNativeH1OrdinaryTakeoverErrorV0<W>> {
    let binding = successor_binding_v0::<W>(proposal, parent.clone(), id, config)?;
    let fact = store.inspect_exact_v0(&binding)?;
    if fact.stage() != expected_stage || fact.outbox_present() {
        return Err(PocoNodeNativeH1OrdinaryTakeoverErrorV0::Rejected(
            "native successor validation row is at the wrong stage",
        ));
    }
    let executed = store.read_artifact_exact_v0(&binding)?;
    let expected =
        native_successor_request_v0::<W>(proposal.block(), parent, config.consensus_parameters())?;
    if executed.request() != &expected {
        return Err(PocoNodeNativeH1OrdinaryTakeoverErrorV0::Rejected(
            "native successor artifact differs from its proof body",
        ));
    }
    let confirmed = application.confirm_durable_p_v0(&executed)?;
    let application_head = confirmed.overlay_parent_head_v0()?;
    let overlay = BlockIdOverlayRefV0::new(
        BlockId::new(confirmed.block_id_v0()),
        BlockId::new(confirmed.parent_block_id_v0()),
        confirmed.overlay_checksum_v0(),
    );
    if let Some(completion) = completion {
        let artifact = completion.result().artifact_ref().ok_or(
            PocoNodeNativeH1OrdinaryTakeoverErrorV0::Rejected(
                "anchored successor completion is not Valid",
            ),
        )?;
        if completion.route() != trnm_consensus_core::PayloadValidationRouteV0::Synced
            || completion.id() != id
            || artifact.overlay() != overlay
            || artifact.source_artifact_checksum() != confirmed.source_artifact_checksum_v0()
        {
            return Err(PocoNodeNativeH1OrdinaryTakeoverErrorV0::Rejected(
                "anchored successor completion differs from durable P",
            ));
        }
    }
    Ok(ReconciledSuccessorRowV0 {
        binding,
        application_head,
        overlay,
    })
}

fn checkpoint_hash_v0(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
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

#[cfg(all(test, feature = "lab-validator-runtime", unix))]
mod tests {
    use std::{
        convert::Infallible,
        fs,
        os::unix::fs::PermissionsExt,
        path::{Path, PathBuf},
        sync::{Arc, Mutex},
    };

    use ed25519_dalek::{Signer, SigningKey};
    use tempfile::TempDir;
    use trnm_consensus_core::{
        leader_for, native_valid_result_checksum_v0, ApplicationNativeValidDeliveryFactsV0,
        AuthenticatedGenesisApplicationH1OfflineApplicationOwnerV0,
        AuthenticatedGenesisApplicationH1OfflineApplicationRegistrarV0,
        AuthenticatedGenesisApplicationParentV0, NativeValidPostAckActionV0,
        PayloadValidationRouteV0, SafetyStateRecordLimitsV0, ValidatedPayloadArtifactRefV0,
    };
    use trnm_consensus_safety_store::SafetyStateStoreProfileV0;
    use trnm_consensus_signer_journal::{
        ExternalWatermarkErrorV0, SignatureProducerErrorV0, SignatureProducerV0,
        SignatureRequestV0, SignerJournalProfileV0, SignerWatermarkV0,
    };
    use trnm_consensus_types::{
        ApplicationPayloadV0, Block, BlockBodyV0, BlockHeader, CertifiedHeaderV0, ChainId,
        ConsensusParametersV0, ConsensusPublicKey, Epoch, EvidenceRoot, ExecutionReceiptsV0,
        FinalityProofV0, GenesisHash, GenesisQcV0, Height, PayloadDigest, ProposalWitnessV0,
        ProtocolVersion, QcReferenceV0, QuorumCertificate, ReceiptsRoot, SignatureBytes,
        SignedProposalV0, StateRoot, Validator, ValidatorId, ValidatorSet, View, Vote, VotingPower,
    };
    use trnm_finality_types::SignedCommandEnvelopeV1;
    use trnm_native_application::{
        Hash32V0, NativeApplicationGenesisRequestV0, NativeApplicationV0, StateRootV0,
    };
    use trnm_native_application_sqlite::ProposalValidationStoreScopeV0;
    use trnm_native_execution_v0::{
        AuthorizedSignerV0, CanonicalLabNativeApplicationConfigInputsV0,
        CanonicalLabNativeChainGenesisInputsV0, CanonicalLabNativeEmptyBootstrapPrefixV0,
        NativeApplicationConfigV0,
    };
    use trnm_protocol::{
        CanonicalCommandV1, CanonicalTxV1, CANONICAL_TX_PAYLOAD_TYPE_V1, CANONICAL_TX_SCHEMA_V1,
    };

    use super::*;
    use crate::{
        derive_signer_watermark_scope_v0, PocoNodeNativeH1StateSyncCommissioningConfigV0,
        PocoNodeNativeH1StateSyncPromotionSourceV0, STRICT_ED25519_VERIFIER_PROFILE_REF_V0,
    };

    const TEST_CHAIN: ChainId = ChainId::from_static("trnm-native-anchor-takeover-test");
    const MAXIMUM_RECORD_BYTES: usize = 64 * 1024 * 1024;
    const MAXIMUM_BLOB_BYTES: usize = 16 * 1024 * 1024;
    const MAXIMUM_SAFETY_DATABASE_BYTES: usize = 192 * 1024 * 1024;
    const MAXIMUM_SIGNER_INTENTS: u64 = 64;
    const MAXIMUM_SIGNER_INTENT_BYTES: usize = 4096;
    const MAXIMUM_SIGNER_DATABASE_BYTES: usize = 32 * 1024 * 1024;

    #[derive(Debug, Clone, Default)]
    struct MemoryWatermarkV0 {
        value: Arc<Mutex<Option<SignerWatermarkV0>>>,
    }

    impl ExternalMonotonicWatermarkV0 for MemoryWatermarkV0 {
        fn load(
            &mut self,
            scope: [u8; 32],
        ) -> Result<Option<SignerWatermarkV0>, ExternalWatermarkErrorV0> {
            let value = *self.value.lock().expect("watermark lock");
            if value.is_some_and(|watermark| watermark.scope() != scope) {
                return Err(ExternalWatermarkErrorV0::InvalidPersistedState);
            }
            Ok(value)
        }

        fn compare_and_advance(
            &mut self,
            expected: Option<SignerWatermarkV0>,
            target: SignerWatermarkV0,
        ) -> Result<(), ExternalWatermarkErrorV0> {
            let mut value = self.value.lock().expect("watermark lock");
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

    struct ExactProducerV0(SigningKey);

    impl SignatureProducerV0 for ExactProducerV0 {
        fn sign(
            &mut self,
            request: SignatureRequestV0<'_>,
        ) -> Result<SignatureBytes, SignatureProducerErrorV0> {
            Ok(SignatureBytes::from_array(
                self.0.sign(request.signing_root().as_bytes()).to_bytes(),
            ))
        }
    }

    struct ExactRegistrarV0;

    impl AuthenticatedGenesisApplicationH1OfflineApplicationRegistrarV0 for ExactRegistrarV0 {
        type Output = AuthenticatedGenesisApplicationH1OfflineApplicationOwnerV0;
        type Error = Infallible;

        fn register_authenticated_genesis_application_h1_offline_v0(
            self,
            owner: AuthenticatedGenesisApplicationH1OfflineApplicationOwnerV0,
        ) -> Result<Self::Output, Self::Error> {
            Ok(owner)
        }
    }

    fn record_limits_v0() -> SafetyStateRecordLimitsV0 {
        SafetyStateRecordLimitsV0::new(MAXIMUM_RECORD_BYTES, MAXIMUM_BLOB_BYTES)
            .expect("valid Safety record limits")
    }

    fn protected_root_v0() -> TempDir {
        let root = TempDir::new().expect("temporary authority root");
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700))
            .expect("protect authority root");
        root
    }

    fn protected_file_v0(root: &TempDir, namespace: &str, filename: &str) -> PathBuf {
        let parent = root.path().join(namespace);
        fs::create_dir(&parent).expect("create authority namespace");
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o700))
            .expect("protect authority namespace");
        parent.join(filename)
    }

    fn hex_v0(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut value = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            value.push(char::from(HEX[usize::from(byte >> 4)]));
            value.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        value
    }

    fn consensus_fixture_v0() -> (
        Vec<(ValidatorId, SigningKey)>,
        ConsensusParametersV0,
        ValidatorSet,
    ) {
        let parameters = ConsensusParametersV0::reference_shadow_v0();
        let keys = (1_u8..=4)
            .map(|index| {
                (
                    ValidatorId::new([index; 32]),
                    SigningKey::from_bytes(&[index.saturating_add(40); 32]),
                )
            })
            .collect::<Vec<_>>();
        let validators = keys
            .iter()
            .map(|(id, key)| {
                Validator::new(
                    *id,
                    ConsensusPublicKey::new(key.verifying_key().to_bytes()),
                    VotingPower::new(1).expect("positive voting power"),
                )
                .expect("valid validator")
            })
            .collect();
        let validator_set = ValidatorSet::new(
            GenesisHash::new([0xa5; 32]),
            TEST_CHAIN,
            ProtocolVersion::V0,
            Epoch::new(0),
            parameters.hash(),
            validators,
        )
        .expect("valid validator set");
        (keys, parameters, validator_set)
    }

    fn application_signers_v0() -> Vec<AuthorizedSignerV0> {
        let operator = SigningKey::from_bytes(&[0x51; 32]);
        vec![AuthorizedSignerV0::new(
            "did:operator:anchor-test",
            "operator",
            hex_v0(&operator.verifying_key().to_bytes()),
        )
        .expect("valid independent application signer")]
    }

    fn native_application_config_v0(
        validator_set: ValidatorSet,
        parameters: ConsensusParametersV0,
        local_validator: ValidatorId,
    ) -> NativeApplicationConfigV0 {
        NativeApplicationConfigV0::from_canonical_lab_inputs_v0(
            CanonicalLabNativeApplicationConfigInputsV0::new(
                "anchor-takeover-test-001",
                [0x91; 32],
                [0x92; 32],
                [0x93; 32],
                [0x94; 32],
                local_validator,
                validator_set,
                parameters,
                application_signers_v0(),
                "did:operator:anchor-test",
            )
            .expect("canonical native application inputs"),
        )
        .expect("canonical native application config")
    }

    fn sign_v0(
        keys: &[(ValidatorId, SigningKey)],
        author: ValidatorId,
        root: trnm_consensus_types::SigningRoot,
    ) -> SignatureBytes {
        let key = keys
            .iter()
            .find_map(|(id, key)| (*id == author).then_some(key))
            .expect("validator signing key");
        SignatureBytes::from_array(key.sign(root.as_bytes()).to_bytes())
    }

    fn canonical_empty_prefix_v0(
        keys: &[(ValidatorId, SigningKey)],
        parameters: ConsensusParametersV0,
        validator_set: &ValidatorSet,
    ) -> (FinalityProofV0, [SignedProposalV0; 3]) {
        let chain_inputs = CanonicalLabNativeChainGenesisInputsV0::new(
            validator_set.clone(),
            parameters,
            application_signers_v0(),
            "did:operator:anchor-test",
        )
        .expect("canonical empty-prefix inputs");
        let mut prefix = CanonicalLabNativeEmptyBootstrapPrefixV0::new(chain_inputs)
            .expect("canonical empty-prefix owner");
        let genesis_qc = GenesisQcV0::new(
            validator_set.genesis_hash(),
            validator_set.chain_id(),
            validator_set,
        )
        .expect("genesis QC");
        let mut justify = QcReferenceV0::genesis_anchor(genesis_qc);
        let mut parent_timestamp_ms = 0;
        let mut proposals = Vec::with_capacity(3);
        let mut certificates = Vec::with_capacity(3);

        for height in 1_u64..=3 {
            let timestamp_ms = height * 100;
            let prepared = prefix
                .prepare_next_empty_block_v0(timestamp_ms)
                .expect("prepare exact empty prefix block");
            let facts = prepared.facts_v0();
            let view = View::new(height);
            let proposer = leader_for(validator_set, view);
            let header = BlockHeader::new(
                validator_set.genesis_hash(),
                validator_set.chain_id(),
                validator_set.protocol_version(),
                validator_set.epoch(),
                view,
                Height::new(height),
                BlockKind::Regular,
                facts.parent_block_id_v0(),
                proposer,
                validator_set.id(),
                parameters.hash(),
                facts.payload_root_v0(),
                facts.post_state_root_v0(),
                facts.receipts_root_v0(),
                facts.evidence_root_v0(),
                timestamp_ms,
                None,
            )
            .expect("canonical empty prefix header");
            let payload = ApplicationPayloadV0::new(Vec::new())
                .expect("empty payload")
                .try_cev0_bytes()
                .expect("encode empty payload");
            let block = Block::new(header, payload, Vec::new()).expect("canonical empty block");
            let proposal_root =
                ProposalWitnessV0::signing_root_for(block.header(), &justify, None, None)
                    .expect("proposal signing root");
            let witness = ProposalWitnessV0::new(
                block.header(),
                justify,
                None,
                None,
                sign_v0(keys, proposer, proposal_root),
                validator_set,
                None,
                &parameters,
                parent_timestamp_ms,
            )
            .expect("canonical proposal witness");
            let proposal = SignedProposalV0::new(
                block,
                witness,
                validator_set,
                None,
                &parameters,
                parent_timestamp_ms,
            )
            .expect("canonical signed proposal");
            prefix = prefix
                .commit_exact_block_v0(prepared, proposal.block())
                .expect("commit exact prefix block");

            let vote_root = Vote::signing_root_for_set(
                validator_set,
                view,
                Height::new(height),
                proposal.block().id(),
            )
            .expect("vote signing root");
            let votes = validator_set
                .validators()
                .iter()
                .map(|validator| {
                    Vote::new(
                        validator_set.chain_id(),
                        validator_set.protocol_version(),
                        validator_set.epoch(),
                        view,
                        Height::new(height),
                        proposal.block().id(),
                        validator_set.id(),
                        validator.id(),
                        sign_v0(keys, validator.id(), vote_root),
                        validator_set,
                    )
                    .expect("strict vote")
                })
                .collect();
            let qc = QuorumCertificate::new(
                validator_set.chain_id(),
                validator_set.protocol_version(),
                validator_set.epoch(),
                view,
                Height::new(height),
                proposal.block().id(),
                validator_set.id(),
                votes,
                validator_set,
            )
            .expect("strict all-signer QC");
            parent_timestamp_ms = timestamp_ms;
            justify = QcReferenceV0::ordinary(qc.clone());
            proposals.push(proposal);
            certificates.push(qc);
        }
        assert!(prefix.is_complete_v0());

        let certified_h1 = CertifiedHeaderV0::from_signed_proposal(
            proposals[0].clone(),
            certificates[0].clone(),
            validator_set,
            None,
            &parameters,
            0,
        )
        .expect("certified h1");
        let certified_h2 = CertifiedHeaderV0::from_signed_proposal(
            proposals[1].clone(),
            certificates[1].clone(),
            validator_set,
            None,
            &parameters,
            100,
        )
        .expect("certified h2");
        let certified_h3 = CertifiedHeaderV0::from_signed_proposal(
            proposals[2].clone(),
            certificates[2].clone(),
            validator_set,
            None,
            &parameters,
            200,
        )
        .expect("certified h3");
        let proof = FinalityProofV0::new(
            certified_h1,
            certified_h2,
            certified_h3,
            validator_set,
            None,
            &parameters,
            0,
        )
        .expect("strict h1 finality proof");
        (
            proof,
            [
                proposals[0].clone(),
                proposals[1].clone(),
                proposals[2].clone(),
            ],
        )
    }

    fn h1_valid_commitments_v0(
        block: &Block,
        validator_set: &ValidatorSet,
        parameters: &ConsensusParametersV0,
    ) -> trnm_consensus_types::ValidatedBlockCommitmentsV0 {
        let payload = ApplicationPayloadV0::new(Vec::new()).expect("empty h1 payload");
        let receipts = ExecutionReceiptsV0::new(&payload, Vec::new()).expect("empty h1 receipts");
        let body = BlockBodyV0::new(payload, Vec::new()).expect("empty h1 body");
        body.validate_ordinary_commitments(
            block.header(),
            &receipts,
            parameters,
            validator_set,
            &StrictEd25519Verifier,
        )
        .expect("h1 body commitments")
    }

    fn h1_artifact_ref_v0(block: &Block) -> ValidatedPayloadArtifactRefV0 {
        let mut overlay_checksum = *block.id().as_bytes();
        overlay_checksum[0] ^= 0x5a;
        let mut source_checksum = *block.id().as_bytes();
        source_checksum[0] ^= 0xa5;
        ValidatedPayloadArtifactRefV0::new(
            BlockIdOverlayRefV0::new(block.id(), block.header().parent_id(), overlay_checksum),
            source_checksum,
        )
    }

    fn initialize_native_application_v0(
        path: &Path,
        config: NativeApplicationConfigV0,
    ) -> DurableNativeApplicationV0 {
        let genesis_request = NativeApplicationGenesisRequestV0::new(
            ChainIdV0::new(config.chain_id_v0()).expect("native chain id"),
            GenesisHashV0::new(config.genesis_hash_v0()).expect("native genesis hash"),
            Hash32V0::new(config.chain_descriptor_hash_v0()),
            Hash32V0::new(config.signer_policy_commitment_v0()),
            StateRootV0::new(config.initial_state_root()).expect("native initial state root"),
            config.initial_validator_set().clone(),
        )
        .expect("native genesis request");
        let application =
            DurableNativeApplicationV0::open(path, config).expect("open native application owner");
        application
            .initialize(genesis_request)
            .expect("initialize native genesis");
        application
    }

    fn h4_transaction_v0(timestamp_ms: u64) -> Vec<u8> {
        let operator = SigningKey::from_bytes(&[0x51; 32]);
        let transaction = CanonicalTxV1 {
            schema: CANONICAL_TX_SCHEMA_V1.to_string(),
            sender: "did:operator:anchor-test".to_string(),
            nonce: 1,
            max_gas: 100_000,
            fee_limit: 100_000,
            command: CanonicalCommandV1::CreditAccount {
                account: "did:client:anchor-test".to_string(),
                amount: 10_000,
            },
        };
        let payload = serde_json::to_vec(&transaction).expect("canonical h4 transaction");
        let envelope = SignedCommandEnvelopeV1::sign(
            TEST_CHAIN.as_str(),
            "anchor-h4-credit-1",
            "did:operator:anchor-test",
            "operator",
            1,
            timestamp_ms,
            timestamp_ms + 10_000,
            CANONICAL_TX_PAYLOAD_TYPE_V1,
            &payload,
            &operator,
        )
        .expect("signed h4 command envelope");
        serde_json::to_vec(&envelope).expect("encode h4 command envelope")
    }

    #[test]
    fn native_anchor_fresh_commissioned_facade_reaches_h4_p_d_c_k_and_vote_v0() {
        std::thread::Builder::new()
            .name("native-anchor-facade-h4".to_string())
            .stack_size(32 * 1024 * 1024)
            .spawn(run_native_anchor_fresh_commissioned_facade_h4_v0)
            .expect("spawn native anchor facade fixture")
            .join()
            .expect("native anchor facade fixture must not panic");
    }

    fn run_native_anchor_fresh_commissioned_facade_h4_v0() {
        let root = protected_root_v0();
        let source_safety_path = protected_file_v0(&root, "source-safety", "safety.sqlite3");
        let target_safety_path = protected_file_v0(&root, "target-safety", "safety.sqlite3");
        let signer_path = protected_file_v0(&root, "signer", "signer.sqlite3");
        let application_path = protected_file_v0(&root, "application", "application.sqlite3");
        let checkpoint_path = protected_file_v0(&root, "checkpoint", "checkpoint.sqlite3");
        let validation_path = protected_file_v0(&root, "validation", "validation.sqlite3");

        let (keys, parameters, validator_set) = consensus_fixture_v0();
        let local_validator = keys[0].0;
        let application_config =
            native_application_config_v0(validator_set.clone(), parameters, local_validator);
        let chain_facts = application_config.chain_genesis_facts_v0();
        let application = initialize_native_application_v0(&application_path, application_config);
        let (proof, [h1, h2, h3]) = canonical_empty_prefix_v0(&keys, parameters, &validator_set);

        let authenticated_parent = AuthenticatedGenesisApplicationParentV0::new(
            BlockId::new(chain_facts.initial_block_id_v0()),
            0,
            0,
            StateRoot::new(chain_facts.initial_state_root_v0()),
            chain_facts.chain_descriptor_hash_v0(),
            [0x55; 32],
        )
        .expect("authenticated native genesis parent");
        let source_core_config = CoreConfig::new_with_authenticated_genesis_application_parent_v0(
            local_validator,
            validator_set.clone(),
            parameters,
            0,
            authenticated_parent,
            32,
            64,
        )
        .expect("authenticated-genesis source Core config");
        let genesis_qc = GenesisQcV0::new(
            validator_set.genesis_hash(),
            validator_set.chain_id(),
            &validator_set,
        )
        .expect("source genesis QC");
        let prepared = Core::prepare_authenticated_genesis_application_bootstrap_v0(
            source_core_config.clone(),
            genesis_qc,
            STRICT_ED25519_VERIFIER_PROFILE_REF_V0,
            record_limits_v0(),
            &StrictEd25519Verifier,
        )
        .expect("prepare authenticated-genesis source");
        let source_profile = SafetyStateStoreProfileV0::new(
            source_core_config.clone(),
            STRICT_ED25519_VERIFIER_PROFILE_REF_V0,
            record_limits_v0(),
            MAXIMUM_SAFETY_DATABASE_BYTES,
        )
        .expect("source Safety profile");
        let (mut source_safety_store, _) =
            SqliteSafetyStateStoreV0::initialize_or_resume_authenticated_genesis_application_exact_v0(
                &source_safety_path,
                source_profile,
                StrictEd25519Verifier,
                &prepared,
            )
            .expect("initialize authenticated-genesis source Safety");
        let confirmed_source = source_safety_store
            .confirmed_authenticated_genesis_application_bootstrap_head_exact_v0(&prepared)
            .expect("confirm source tag-5 head");
        let activation = Core::begin_authenticated_genesis_application_h1_offline_validation_v0(
            source_core_config.clone(),
            prepared,
            &StrictEd25519Verifier,
        )
        .expect("begin source h1 validation");
        let mut source_owner = activation
            .activate_application_v0(ExactRegistrarV0)
            .unwrap_or_else(|never| match never {});
        let obligation = source_owner
            .submit_exact_h1_synced_proposal_v0(h1.clone(), &StrictEd25519Verifier)
            .expect("source h1 obligation");
        let binding = source_owner
            .issue_safety_persistence_binding_v0()
            .expect("source h1 Safety binding");
        source_safety_store
            .bind_authenticated_genesis_application_h1_offline_v0(confirmed_source, binding)
            .expect("bind source Safety to h1 owner");
        source_safety_store
            .persist_authenticated_genesis_application_h1_obligation_exact_v0(&obligation)
            .expect("persist source h1 obligation");
        let request = source_owner
            .acknowledge_obligation_persisted_v0(
                &obligation,
                obligation.barrier_v0(),
                &StrictEd25519Verifier,
            )
            .expect("release source h1 validation request");
        let validation_id = request.validation_id_v0();
        let claimed = request
            .try_claim_v0()
            .unwrap_or_else(|_| panic!("source h1 request must be claimable"));
        let (_route, _id, block, _parent, permit) = claimed.into_parts();
        let sealed = source_owner.seal_after_application_store_commit_v0(
            permit,
            h1_valid_commitments_v0(&block, &validator_set, &parameters),
            h1_artifact_ref_v0(&block),
        );
        let completion = source_owner
            .accept_application_sealed_valid_v0(&sealed, &StrictEd25519Verifier)
            .expect("accept source h1 Valid");
        let [durable_completion] = completion
            .persistence_v0()
            .state()
            .payload_validation_completions()
        else {
            panic!("source h1 completion is not unique")
        };
        let delivery = ApplicationNativeValidDeliveryFactsV0::new(
            PayloadValidationRouteV0::Synced,
            validation_id,
            [0x61; 32],
            [0x62; 32],
            [0x63; 32],
            native_valid_result_checksum_v0(durable_completion.result())
                .expect("canonical source h1 valid-result checksum"),
            [0x64; 32],
            [0x65; 32],
            1,
            [0x66; 32],
            [0x67; 32],
            NativeValidPostAckActionV0::None,
            2,
        )
        .expect("source h1 delivery facts");
        let sealed_transition = source_owner
            .seal_authenticated_genesis_h1_native_valid_transition_v0(completion, delivery)
            .expect("seal source h1 D transition");
        let confirmed_source_native_valid = source_safety_store
            .persist_authenticated_genesis_application_h1_native_valid_exact_v0(&sealed_transition)
            .expect("persist source h1 NativeValid");
        assert_eq!(confirmed_source_native_valid.revision(), 2);
        drop(confirmed_source_native_valid);
        let completed = source_owner
            .acknowledge_completion_persisted_v0(
                &sealed_transition,
                sealed_transition.completion_persistence_v0().barrier_v0(),
                &StrictEd25519Verifier,
            )
            .expect("ack source h1 completion");
        assert_eq!(completed.validation_id_v0(), validation_id);
        let candidate = source_owner
            .retire_completed_into_h1_state_sync_promotion_v0(proof, &StrictEd25519Verifier)
            .expect("retire exact h1 into state-sync candidate");

        let watermark = MemoryWatermarkV0::default();
        let signer_profile = SignerJournalProfileV0::new(
            validator_set.clone(),
            local_validator,
            crate::SIGNER_JOURNAL_PROFILE_REF_V0,
            derive_signer_watermark_scope_v0(&source_core_config),
            MAXIMUM_SIGNER_INTENTS,
            MAXIMUM_SIGNER_INTENT_BYTES,
            MAXIMUM_SIGNER_DATABASE_BYTES,
        )
        .expect("signer profile");
        let pinned_signer =
            SqliteSignerJournalV0::initialize_new(&signer_path, signer_profile, watermark)
                .expect("initialize virgin signer")
                .into_pinned_v0()
                .expect("pin virgin signer");
        let checkpoint_store =
            SqliteExternalNodeCheckpointStoreV0::initialize_new(&checkpoint_path)
                .expect("initialize whole-node checkpoint store");
        let source = PocoNodeNativeH1StateSyncPromotionSourceV0::from_completed_authorities_v0(
            candidate,
            source_safety_store,
            pinned_signer,
        );
        let commissioned = source
            .commission_native_h1_state_sync_v0(
                PocoNodeNativeH1StateSyncCommissioningConfigV0::new(
                    &target_safety_path,
                    record_limits_v0(),
                    MAXIMUM_SAFETY_DATABASE_BYTES,
                    application,
                    checkpoint_store,
                )
                .expect("native h1 commissioning config"),
            )
            .expect("commission exact native h1");
        let commissioned_facts = commissioned.facts();

        let scope_bytes = [0x81; 32];
        let owner_bytes = [0x82; 32];
        let validation_scope =
            ProposalValidationStoreScopeV0::new(scope_bytes).expect("validation scope");
        let validation_owner =
            ProposalValidationOwnerIdV0::new(owner_bytes).expect("validation owner");
        let validation_store =
            SqliteProposalValidationStoreV0::open(&validation_path, validation_scope, 0)
                .expect("open empty validation journal");
        let proposal_journal =
            PocoNodeLabProposalJournalConfigV0::new(validation_path, scope_bytes, owner_bytes, 6)
                .expect("exact post-h3 proposal journal config");
        let runtime = commissioned
            .complete_lab_ordinary_takeover_v0(
                h2.clone(),
                h3.clone(),
                validation_store,
                validation_owner,
                proposal_journal,
            )
            .expect("fresh h1 owner reaches ordinary Lab runtime");
        let binding = runtime
            .proposal_binding_v0()
            .expect("exact post-takeover proposal binding");
        assert_eq!(binding.high_qc_v0().qc_ref().block_id(), h3.block().id());
        assert_eq!(
            binding
                .parent_v0()
                .application_head_v0()
                .block_id()
                .as_bytes(),
            h3.block().id().as_bytes()
        );
        assert_eq!(runtime.facts_v0().proposal_parent_height_v0(), 3);
        assert_eq!(runtime.facts_v0().application_applied_height_v0(), 1);
        assert_eq!(
            runtime.checkpoint_v0().fields().safety_journal_id,
            commissioned_facts.target_safety_journal_id()
        );

        let h4_timestamp_ms = 400;
        let transactions = vec![h4_transaction_v0(h4_timestamp_ms)];
        let (parent, preview) = runtime
            .preview_next_nonempty_v0(transactions.clone(), h4_timestamp_ms)
            .expect("preview exact nonempty h4");
        let payload = ApplicationPayloadV0::new(transactions).expect("h4 payload");
        let payload_root = payload.payload_root().expect("h4 payload root");
        assert_eq!(payload_root.as_bytes(), preview.payload_root().as_bytes());
        let h4_view = binding.current_view_v0();
        let h4_proposer = leader_for(&validator_set, h4_view);
        let h4_header = BlockHeader::new(
            validator_set.genesis_hash(),
            validator_set.chain_id(),
            validator_set.protocol_version(),
            validator_set.epoch(),
            h4_view,
            Height::new(4),
            BlockKind::Regular,
            BlockId::new(*parent.application_head_v0().block_id().as_bytes()),
            h4_proposer,
            validator_set.id(),
            parameters.hash(),
            PayloadDigest::new(*preview.payload_root().as_bytes()),
            StateRoot::new(*preview.post_state_root().as_bytes()),
            ReceiptsRoot::new(*preview.receipts_root().as_bytes()),
            EvidenceRoot::new(*preview.evidence_root().as_bytes()),
            h4_timestamp_ms,
            None,
        )
        .expect("exact h4 header");
        let h4_block = Block::new(
            h4_header,
            payload.try_cev0_bytes().expect("encode h4 payload"),
            Vec::new(),
        )
        .expect("exact h4 block");
        let h4_root = ProposalWitnessV0::signing_root_for(
            h4_block.header(),
            binding.high_qc_v0(),
            None,
            None,
        )
        .expect("h4 proposal signing root");
        let h4_witness = ProposalWitnessV0::new(
            h4_block.header(),
            binding.high_qc_v0().clone(),
            None,
            None,
            sign_v0(&keys, h4_proposer, h4_root),
            &validator_set,
            None,
            &parameters,
            parent.authenticated_parent_timestamp_ms_v0(),
        )
        .expect("exact h4 witness");
        let h4 = SignedProposalV0::new(
            h4_block,
            h4_witness,
            &validator_set,
            None,
            &parameters,
            parent.authenticated_parent_timestamp_ms_v0(),
        )
        .expect("exact h4 proposal");
        let h4_id = h4.block().id();
        let inert = runtime
            .drive_one_to_inert_request_v0(h4)
            .expect("h4 reaches durable P/D/C/K and inert Vote request");
        assert_eq!(inert.facts_v0().block_id(), h4_id);
        assert_eq!(inert.facts_v0().height(), 4);
        let mut producer = ExactProducerV0(keys[0].1.clone());
        let signed = inert
            .sign_exact_vote_v0(&mut producer)
            .expect("journal and release exact h4 Vote");
        assert_eq!(signed.outbound_v0().vote_v0().block_id(), h4_id);
        assert_eq!(signed.outbound_v0().vote_v0().height(), Height::new(4));
    }
}
