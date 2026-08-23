//! One-shot, feature-gated laboratory owner for the first real ordinary
//! proposal authority chain.
//!
//! This module is deliberately absent from the default Node API.  It exists
//! only for the G3 single-LAN laboratory binary.  It can either consume an
//! already authenticated positive-height checkpoint, or commission a plain
//! ordinary fresh-genesis cut with no authenticated application parent and no
//! state-sync anchor.  Fresh commissioning keeps the signer pinned until an
//! independently durable generation-zero whole-node checkpoint has exact
//! readback. The proposal and signing entry points then drive exactly
//!
//! `Proposal -> obligation C -> P -> Core-D -> Safety-C -> K -> whole-node CAS
//!  -> Core StorageAck -> inert RequestSignature -> signer journal
//!  -> whole-node CAS -> SignatureReady -> one verified Vote`.
//!
//! Every returned owner is non-cloneable and retains Core, application,
//! SafetyStore, signer journal, checkpoint store, and the exact authority
//! carrier together. The caller supplies only a bounded `SignatureProducerV0`;
//! raw Core/store/key owners and canonical intents are never exposed. Network
//! transport remains outside this module and production activation remains
//! false.

use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt,
    path::PathBuf,
    time::Instant,
};

use sha2::{Digest, Sha256};

use trnm_consensus_core::{
    ClaimedPayloadValidationRequestV0, Core, CoreError,
    CoreIssuedApplicationFinalizationApplyAuthorityV0, CoreIssuedApplicationSealAuthorityV0,
    DurableFinalizationV0, Effect, Input, OutboundMessage, SignId,
};
use trnm_consensus_crypto::StrictEd25519Verifier;
use trnm_consensus_safety_store::{
    ConfirmedSafetyNodeCheckpointFactsV0, SafetyPersistDispositionV0, SafetyStoreErrorV0,
    SafetyTransitionContextV0, SqliteSafetyStateStoreV0,
};
use trnm_consensus_signer_journal::{
    ConfirmedSignerNodeCheckpointFactsV0, ExternalMonotonicWatermarkInjectionV0,
    ExternalMonotonicWatermarkV0, SignatureProducerV0, SignerJournalErrorV0,
    SignerJournalLifetimeInventoryV1, SqliteSignerJournalV0,
};
use trnm_consensus_types::{
    BlockId, CanonicalSignIntentV0, CanonicalSignPreimageV0, CanonicalSignable, CertificateId,
    Epoch, FinalityProofV0, QcRef, QcReferenceV0, QuorumCertificate, ReceiptsRoot,
    SignedProposalV0, StateRoot, TimeoutCertificateV0, TimeoutVote, ValidatorSetId, View, Vote,
};
use trnm_native_application::{
    ApplicationHeadV0, BlockIdV0, ChainIdV0, GenesisHashV0, Hash32V0, HeightV0,
    NativeApplicationCommitRequestV0, NativeApplicationGenesisRequestV0,
    NativeApplicationRecoveryRequestV0, NativeApplicationV0, NativeExecutedBlockV0,
    NativeRecoveryDispositionV0, NativeRecoveryWatermarksV0, StateRootV0, ValidatorSetIdV0,
};
use trnm_native_application_sqlite::{
    DurableValidationStageV0, ProposalRouteV0, ProposalValidationBindingV0,
    ProposalValidationOwnerIdV0, ProposalValidationStoreScopeV0, SqliteProposalValidationStoreV0,
};
use trnm_native_execution_v0::{
    DurableNativeApplicationV0, FinalizedNativeApplicationReadV0,
    NativeApplicationExecutionErrorV0, NativeBlockPreviewRequestV0, NativeBlockPreviewV0,
};

use crate::{
    external_node_checkpoint::{
        ExternalNodeCheckpointStoreErrorV0, ExternalNodeCheckpointStoreV0,
        ExternalNodeCheckpointV0, SqliteExternalNodeCheckpointStoreV0,
    },
    native_h1_ordinary_takeover::PocoNodeNativeH1OrdinaryRuntimePartsV0,
    native_proposal_p_host::{
        PocoNodeNativeAnchoredSuccessorCompletedV0, PocoNodeNativeCoreDOutcomeV0,
        PocoNodeNativeInertRequestSignatureV0, PocoNodeNativeKOutcomeV0,
        PocoNodeNativeProposalPHostConfigV0, PocoNodeNativeProposalPHostErrorV0,
        PocoNodeNativeProposalPHostV0, PocoNodeNativeWholeNodeCheckpointOutcomeV0,
    },
};

/// The anchored-successor takeover closes exactly three durable validation
/// transitions for h2 and three for h3 before releasing the journal lock.
const NATIVE_H1_ORDINARY_TAKEOVER_VALIDATION_SEQUENCE_V0: u64 = 6;
const NATIVE_H1_ORDINARY_TAKEOVER_CHECKPOINT_OWNER_DOMAIN_V0: &[u8] =
    b"trnm.poco-node.anchor-successor.checkpoint.owner.v0";
const NATIVE_H1_ORDINARY_TAKEOVER_CHECKPOINT_PROFILE_DOMAIN_V0: &[u8] =
    b"trnm.poco-node.anchor-successor.checkpoint.profile.v0";
const NATIVE_K_CHECKPOINT_OWNER_DOMAIN_V0: &[u8] = b"trnm.native-k-checkpoint.application-owner.v0";
const NATIVE_K_CHECKPOINT_PROFILE_DOMAIN_V0: &[u8] =
    b"trnm.native-k-checkpoint.projection-profile.v0";
const LAB_FINALIZATION_CHECKPOINT_PROFILE_DOMAIN_V0: &[u8] =
    b"trnm.poco-node.lab-finalization.application-profile.v0";
const LAB_TIMEOUT_REBASE_CHECKPOINT_PROFILE_DOMAIN_V0: &[u8] =
    b"trnm.poco-node.lab-timeout-rebase.application-profile.v0";

/// Returns the signer crate's freshly audited lifetime inventory only when a
/// terminal owner has no unsigned tail and each Vote/TimeoutVote lifecycle is
/// individually closed.  Counts are never accepted from a caller.
pub(super) fn clean_signer_lifetime_inventory_v1(
    signer: &ConfirmedSignerNodeCheckpointFactsV0,
) -> Option<SignerJournalLifetimeInventoryV1> {
    let inventory = signer.lifetime_inventory();
    let durable_vote = inventory.durable_vote_intent_count();
    let durable_timeout = inventory.durable_timeout_intent_count();
    let signed_vote = inventory.signed_vote_intent_count();
    let signed_timeout = inventory.signed_timeout_intent_count();
    let durable_total = durable_vote.checked_add(durable_timeout)?;
    let signed_total = signed_vote.checked_add(signed_timeout)?;
    let event_total = durable_total.checked_add(signed_total)?;
    if signer.pending_intent().is_some()
        || inventory.inventory_digest() == [0; 32]
        || durable_vote != signed_vote
        || durable_timeout != signed_timeout
        || durable_total != signer.capacity().intent_count()
        || signed_total != signer.capacity().intent_count()
        || event_total != signer.capacity().event_count()
        || signer.exact_watermark().sequence() != signer.capacity().event_count()
    {
        return None;
    }
    Some(inventory)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct PocoNodeLabRetainedExecutionV0 {
    pub(super) binding: ProposalValidationBindingV0,
    pub(super) executed: NativeExecutedBlockV0,
    pub(super) view: View,
    pub(super) source_artifact_checksum: [u8; 32],
    pub(super) validation_row_checksum: [u8; 32],
    pub(super) overlay_ref: trnm_consensus_core::BlockIdOverlayRefV0,
    pub(super) speculative_head: ApplicationHeadV0,
}

enum PocoNodeLabProposalStorageAckEffectV0<T> {
    ValidatePayload(T),
    ArmViewTimer { epoch: Epoch, view: View },
    Unsupported,
}

fn exact_proposal_validation_effect_v0<T>(
    effects: impl IntoIterator<Item = PocoNodeLabProposalStorageAckEffectV0<T>>,
    expected_epoch: Epoch,
    expected_view: View,
) -> Result<T, PocoNodeLabAuthorityErrorV0> {
    let mut effects = effects.into_iter();
    let request = match effects.next() {
        Some(PocoNodeLabProposalStorageAckEffectV0::ValidatePayload(request)) => request,
        Some(PocoNodeLabProposalStorageAckEffectV0::ArmViewTimer { epoch, view })
            if epoch == expected_epoch && view == expected_view =>
        {
            match effects.next() {
                Some(PocoNodeLabProposalStorageAckEffectV0::ValidatePayload(request)) => request,
                _ => {
                    return Err(PocoNodeLabAuthorityErrorV0::UnexpectedEffect(
                        "obligation StorageAck did not release one Proposal validation request",
                    ));
                }
            }
        }
        None => {
            return Err(PocoNodeLabAuthorityErrorV0::UnexpectedEffect(
                "obligation StorageAck did not release one Proposal validation request",
            ));
        }
        _ => {
            return Err(PocoNodeLabAuthorityErrorV0::UnexpectedEffect(
                "obligation StorageAck released an unsupported Proposal effect",
            ));
        }
    };
    if effects.next().is_some() {
        return Err(PocoNodeLabAuthorityErrorV0::UnexpectedEffect(
            "obligation StorageAck released an unsupported Proposal effect",
        ));
    }
    Ok(request)
}

fn sqlite_namespace_exists_v0(path: &std::path::Path) -> bool {
    [
        "",
        "-wal",
        "-shm",
        "-journal",
        ".safety.lock",
        ".signer.lock",
    ]
    .into_iter()
    .any(|suffix| {
        let candidate = if suffix.is_empty() {
            path.to_path_buf()
        } else {
            let mut value = path.as_os_str().to_os_string();
            value.push(suffix);
            PathBuf::from(value)
        };
        match std::fs::symlink_metadata(candidate) {
            Ok(_) => true,
            Err(error) => error.kind() != std::io::ErrorKind::NotFound,
        }
    })
}

/// Fresh, plain-genesis owners for the feature-gated laboratory runtime.
///
/// This configuration contains no authenticated-genesis application parent
/// and no state-sync anchor.  It consumes each new namespace exactly once;
/// callers cannot assemble a live runtime from copied checkpoint facts.
pub struct PocoNodeLabFreshOrdinaryGenesisConfigV0<W: ExternalMonotonicWatermarkV0> {
    core_config: trnm_consensus_core::CoreConfig,
    genesis_qc: trnm_consensus_types::GenesisQcV0,
    safety_store_path: PathBuf,
    safety_record_limits: trnm_consensus_core::SafetyStateRecordLimitsV0,
    safety_maximum_database_bytes: usize,
    application: DurableNativeApplicationV0,
    expected_chain_descriptor_hash: [u8; 32],
    expected_signer_policy_commitment: [u8; 32],
    expected_initial_commit_id: [u8; 32],
    signer_journal_path: PathBuf,
    signer_maximum_intents: u64,
    signer_maximum_intent_bytes: usize,
    signer_maximum_database_bytes: usize,
    external_watermark: W,
    checkpoint_store: SqliteExternalNodeCheckpointStoreV0,
    proposal_journal: PocoNodeLabProposalJournalConfigV0,
}

impl<W: ExternalMonotonicWatermarkV0> PocoNodeLabFreshOrdinaryGenesisConfigV0<W> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        core_config: trnm_consensus_core::CoreConfig,
        genesis_qc: trnm_consensus_types::GenesisQcV0,
        safety_store_path: PathBuf,
        safety_record_limits: trnm_consensus_core::SafetyStateRecordLimitsV0,
        safety_maximum_database_bytes: usize,
        application: DurableNativeApplicationV0,
        expected_chain_descriptor_hash: [u8; 32],
        expected_signer_policy_commitment: [u8; 32],
        expected_initial_commit_id: [u8; 32],
        signer_journal_path: PathBuf,
        signer_maximum_intents: u64,
        signer_maximum_intent_bytes: usize,
        signer_maximum_database_bytes: usize,
        external_watermark: W,
        checkpoint_store: SqliteExternalNodeCheckpointStoreV0,
        proposal_journal: PocoNodeLabProposalJournalConfigV0,
    ) -> Result<Self, PocoNodeLabAuthorityErrorV0> {
        if core_config
            .authenticated_genesis_application_parent_v0()
            .is_some()
        {
            return Err(PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
                "fresh ordinary runtime forbids an authenticated-genesis application parent",
            ));
        }
        if expected_chain_descriptor_hash == [0; 32]
            || expected_signer_policy_commitment == [0; 32]
            || expected_initial_commit_id == [0; 32]
        {
            return Err(PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
                "fresh ordinary application trust inputs must be nonzero",
            ));
        }
        let paths = [
            safety_store_path.as_path(),
            application.path(),
            signer_journal_path.as_path(),
            checkpoint_store.database_path(),
            proposal_journal.store_path.as_path(),
        ];
        let mut parents = Vec::with_capacity(paths.len());
        for (index, path) in paths.into_iter().enumerate() {
            if !path.is_absolute() || path.file_name().is_none() {
                return Err(PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
                    "fresh ordinary runtime requires absolute store paths",
                ));
            }
            // The native application and independent whole-node checkpoint
            // are already-open, non-cloneable owners. Safety, signer, and P
            // journal namespaces must still be absent so commissioning cannot
            // silently attach to historical authority.
            if matches!(index, 0 | 2 | 4) && sqlite_namespace_exists_v0(path) {
                return Err(PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
                    "fresh ordinary mutable namespace already exists",
                ));
            }
            if matches!(index, 1 | 3) && std::fs::symlink_metadata(path).is_err() {
                return Err(PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
                    "fresh ordinary pre-opened owner namespace disappeared",
                ));
            }
            let parent = std::fs::canonicalize(path.parent().ok_or(
                PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
                    "fresh ordinary store lacks a parent namespace",
                ),
            )?)
            .map_err(|_| {
                PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
                    "fresh ordinary store parent is not canonical",
                )
            })?;
            parents.push(parent);
        }
        for left in 0..paths.len() {
            for right in left + 1..paths.len() {
                if paths[left] == paths[right]
                    || parents[left].starts_with(&parents[right])
                    || parents[right].starts_with(&parents[left])
                {
                    return Err(PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
                        "fresh ordinary store namespaces overlap",
                    ));
                }
            }
        }
        Ok(Self {
            core_config,
            genesis_qc,
            safety_store_path,
            safety_record_limits,
            safety_maximum_database_bytes,
            application,
            expected_chain_descriptor_hash,
            expected_signer_policy_commitment,
            expected_initial_commit_id,
            signer_journal_path,
            signer_maximum_intents,
            signer_maximum_intent_bytes,
            signer_maximum_database_bytes,
            external_watermark,
            checkpoint_store,
            proposal_journal,
        })
    }
}

/// Paths and stable identities for one laboratory proposal-validation owner.
#[derive(Debug, Clone)]
pub struct PocoNodeLabProposalJournalConfigV0 {
    store_path: PathBuf,
    scope: ProposalValidationStoreScopeV0,
    owner_id: ProposalValidationOwnerIdV0,
    minimum_durable_sequence: u64,
}

impl PocoNodeLabProposalJournalConfigV0 {
    pub fn new(
        store_path: PathBuf,
        scope: [u8; 32],
        owner_id: [u8; 32],
        minimum_durable_sequence: u64,
    ) -> Result<Self, PocoNodeLabAuthorityErrorV0> {
        if !store_path.is_absolute() || store_path.file_name().is_none() {
            return Err(PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
                "proposal journal path is not an absolute file path",
            ));
        }
        let scope = ProposalValidationStoreScopeV0::new(scope)
            .map_err(|error| PocoNodeLabAuthorityErrorV0::AuthorityChain(error.to_string()))?;
        let owner_id = ProposalValidationOwnerIdV0::new(owner_id)
            .map_err(|error| PocoNodeLabAuthorityErrorV0::AuthorityChain(error.to_string()))?;
        Ok(Self {
            store_path,
            scope,
            owner_id,
            minimum_durable_sequence,
        })
    }
}

/// Stable classification for a read-only external-checkpoint comparison.
///
/// This hook deliberately authenticates only the local whole-node CAS record.
/// It is not a snapshot, state-sync, or peer-trust verifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PocoNodeLabCheckpointComparisonClassV0 {
    Malformed = 1,
    Stale = 2,
    Mismatch = 3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PocoNodeLabCheckpointComparisonErrorV0 {
    class: PocoNodeLabCheckpointComparisonClassV0,
}

impl PocoNodeLabCheckpointComparisonErrorV0 {
    pub const fn class_v0(self) -> PocoNodeLabCheckpointComparisonClassV0 {
        self.class
    }
}

impl fmt::Display for PocoNodeLabCheckpointComparisonErrorV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "lab checkpoint comparison failed: {:?}",
            self.class
        )
    }
}

impl Error for PocoNodeLabCheckpointComparisonErrorV0 {}

#[cfg(test)]
mod checkpoint_comparison_tests_v0 {
    use super::*;
    use trnm_consensus_signer_journal::SignerWatermarkV0;

    fn checkpoint_v0(generation: u64, predecessor_checksum: [u8; 32]) -> ExternalNodeCheckpointV0 {
        ExternalNodeCheckpointV0::new(crate::ExternalNodeCheckpointFieldsV0 {
            scope: [1; 32],
            generation,
            predecessor_checksum,
            safety_journal_id: [2; 32],
            safety_verifier_profile_ref: [3; 32],
            safety_revision: generation,
            safety_state_record_checksum: [4; 32],
            safety_record_chain_checksum: [5; 32],
            application_host_config_ref: [6; 32],
            application_projection_profile_ref: [7; 32],
            application_safety_binding_manifest_checksum: [8; 32],
            application_committed_head_row_checksum: [9; 32],
            application_recovery_closure_checksum: [10; 32],
            application_block_id: BlockId::new([11; 32]),
            application_height: 0,
            application_state_root: trnm_consensus_types::StateRoot::new([12; 32]),
            application_view: 0,
            application_timestamp_ms: 1,
            signer_journal_id: [13; 32],
            signer_profile_checksum: [14; 32],
            signer_exact_watermark: SignerWatermarkV0::from_persisted_parts(
                [1; 32], [13; 32], generation, [15; 32],
            )
            .expect("shape-valid watermark"),
        })
        .expect("shape-valid checkpoint")
    }

    #[test]
    fn exact_checkpoint_compare_is_read_only_and_classifies_stale_malformed_mismatch_v0() {
        let stale = checkpoint_v0(0, [0; 32]);
        let live = checkpoint_v0(1, stale.checkpoint_checksum());
        assert_eq!(
            verify_checkpoint_bytes_exact_v0(live, &live.encode_canonical()),
            Ok(live)
        );
        assert_eq!(
            verify_checkpoint_bytes_exact_v0(live, &stale.encode_canonical())
                .expect_err("stale checkpoint rejected")
                .class_v0(),
            PocoNodeLabCheckpointComparisonClassV0::Stale
        );
        let mut malformed = live.encode_canonical();
        malformed[0] ^= 1;
        assert_eq!(
            verify_checkpoint_bytes_exact_v0(live, &malformed)
                .expect_err("malformed checkpoint rejected")
                .class_v0(),
            PocoNodeLabCheckpointComparisonClassV0::Malformed
        );
        let foreign_scope = [22; 32];
        let foreign = ExternalNodeCheckpointV0::new(crate::ExternalNodeCheckpointFieldsV0 {
            scope: foreign_scope,
            signer_exact_watermark: SignerWatermarkV0::from_persisted_parts(
                foreign_scope,
                live.fields().signer_journal_id,
                live.fields().signer_exact_watermark.sequence(),
                live.fields().signer_exact_watermark.chain_checksum(),
            )
            .expect("shape-valid foreign watermark"),
            ..*live.fields()
        })
        .expect("shape-valid foreign checkpoint");
        assert_eq!(
            verify_checkpoint_bytes_exact_v0(live, &foreign.encode_canonical())
                .expect_err("foreign checkpoint rejected")
                .class_v0(),
            PocoNodeLabCheckpointComparisonClassV0::Mismatch
        );
    }
}

#[cfg(test)]
mod proposal_storage_ack_effect_tests_v0 {
    use super::*;

    fn assert_unexpected_v0(result: Result<u8, PocoNodeLabAuthorityErrorV0>, context: &str) {
        assert!(
            matches!(
                result,
                Err(PocoNodeLabAuthorityErrorV0::UnexpectedEffect(_))
            ),
            "{context}"
        );
    }

    #[test]
    fn exact_core_order_and_timerless_validation_are_accepted_v0() {
        let epoch = Epoch::new(0);
        let view = View::new(7);
        let with_timer = exact_proposal_validation_effect_v0(
            [
                PocoNodeLabProposalStorageAckEffectV0::ArmViewTimer { epoch, view },
                PocoNodeLabProposalStorageAckEffectV0::ValidatePayload(11u8),
            ],
            epoch,
            view,
        )
        .expect("canonical Core timer-before-validation order");
        assert_eq!(with_timer, 11);

        let timerless = exact_proposal_validation_effect_v0(
            [PocoNodeLabProposalStorageAckEffectV0::ValidatePayload(12u8)],
            epoch,
            view,
        )
        .expect("validation-only release");
        assert_eq!(timerless, 12);
    }

    #[test]
    fn reordered_or_duplicate_effects_fail_closed_v0() {
        let epoch = Epoch::new(0);
        let view = View::new(7);
        assert_unexpected_v0(
            exact_proposal_validation_effect_v0(
                [
                    PocoNodeLabProposalStorageAckEffectV0::ValidatePayload(1u8),
                    PocoNodeLabProposalStorageAckEffectV0::ArmViewTimer { epoch, view },
                ],
                epoch,
                view,
            ),
            "timer after validation must fail",
        );
        assert_unexpected_v0(
            exact_proposal_validation_effect_v0(
                [
                    PocoNodeLabProposalStorageAckEffectV0::ArmViewTimer { epoch, view },
                    PocoNodeLabProposalStorageAckEffectV0::ArmViewTimer { epoch, view },
                    PocoNodeLabProposalStorageAckEffectV0::ValidatePayload(2u8),
                ],
                epoch,
                view,
            ),
            "duplicate timer must fail",
        );
        assert_unexpected_v0(
            exact_proposal_validation_effect_v0(
                [
                    PocoNodeLabProposalStorageAckEffectV0::ValidatePayload(3u8),
                    PocoNodeLabProposalStorageAckEffectV0::ValidatePayload(4u8),
                ],
                epoch,
                view,
            ),
            "duplicate validation must fail",
        );
    }

    #[test]
    fn mismatched_timer_or_unexpected_effect_fails_closed_v0() {
        let epoch = Epoch::new(0);
        let view = View::new(7);
        assert_unexpected_v0(
            exact_proposal_validation_effect_v0(
                [
                    PocoNodeLabProposalStorageAckEffectV0::ArmViewTimer {
                        epoch,
                        view: View::new(8),
                    },
                    PocoNodeLabProposalStorageAckEffectV0::ValidatePayload(5u8),
                ],
                epoch,
                view,
            ),
            "mismatched timer must fail",
        );
        assert_unexpected_v0(
            exact_proposal_validation_effect_v0(
                [PocoNodeLabProposalStorageAckEffectV0::<u8>::Unsupported],
                epoch,
                view,
            ),
            "unsupported effect must fail",
        );
    }
}

/// Read-only scalar projection of one live laboratory runtime cut.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PocoNodeLabRuntimeFactsV0 {
    checkpoint: ExternalNodeCheckpointV0,
    current_view: View,
    finalized_block_id: BlockId,
    finalized_height: u64,
    finalized_view: View,
    application_applied_block_id: BlockId,
    application_applied_height: u64,
    proposal_parent_block_id: BlockId,
    proposal_parent_height: u64,
}

impl PocoNodeLabRuntimeFactsV0 {
    pub const fn checkpoint_v0(self) -> ExternalNodeCheckpointV0 {
        self.checkpoint
    }

    pub const fn current_view_v0(self) -> View {
        self.current_view
    }

    pub const fn finalized_block_id_v0(self) -> BlockId {
        self.finalized_block_id
    }

    pub const fn finalized_height_v0(self) -> u64 {
        self.finalized_height
    }

    pub const fn finalized_view_v0(self) -> View {
        self.finalized_view
    }

    pub const fn application_applied_block_id_v0(self) -> BlockId {
        self.application_applied_block_id
    }

    pub const fn application_applied_height_v0(self) -> u64 {
        self.application_applied_height
    }

    pub const fn proposal_parent_block_id_v0(self) -> BlockId {
        self.proposal_parent_block_id
    }

    pub const fn proposal_parent_height_v0(self) -> u64 {
        self.proposal_parent_height
    }
}

/// Linear authority phase retained by one live laboratory validator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PocoNodeLabAuthorityPhaseV0 {
    Ready,
    VoteSigned,
    TimeoutSigned,
}

/// Phase-neutral terminal projection of the last exact durable readbacks.
///
/// The checkpoint is the independently persisted join of the Safety and
/// signer heads plus the committed application head. `proposal_parent_*` may
/// name a retained speculative execution above that committed application
/// cut. A pending TC identifier is exposed only when Core has durably retained
/// an unresolved high-QC sync target; a successful phase-complete certificate
/// advance refuses to return such an owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PocoNodeLabPhaseFactsV0 {
    phase: PocoNodeLabAuthorityPhaseV0,
    checkpoint: ExternalNodeCheckpointV0,
    current_view: View,
    high_qc: QcRef,
    pending_timeout_certificate_id: Option<CertificateId>,
    finalized_block_id: BlockId,
    finalized_height: u64,
    finalized_chain_root: [u8; 32],
    application_applied_block_id: BlockId,
    application_applied_height: u64,
    proposal_parent_block_id: BlockId,
    proposal_parent_height: u64,
    safety_revision: u64,
    safety_record_checksum: [u8; 32],
    safety_chain_checksum: [u8; 32],
    signer_exact_watermark: trnm_consensus_signer_journal::SignerWatermarkV0,
}

/// Authenticated finalized proof exposed by a Ready laboratory runtime.
///
/// The proof is copied only after the live Core revalidates its complete
/// three-chain against the configured validator set/parameter preimage and
/// the exact durable parent timestamp.  The scalar coordinates and roots are
/// retained alongside the proof so an RPC adapter cannot accidentally return
/// an unbound proof or a phase-facts-only claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PocoNodeLabFinalizedProofV0 {
    proof: FinalityProofV0,
    proof_id: CertificateId,
    finalized_block_id: BlockId,
    finalized_height: u64,
    validator_set_id: ValidatorSetId,
    state_root: StateRoot,
    receipts_root: ReceiptsRoot,
    authenticated_parent_timestamp_ms: u64,
    finalized_chain_root: [u8; 32],
}

impl PocoNodeLabFinalizedProofV0 {
    pub const fn proof_v0(&self) -> &FinalityProofV0 {
        &self.proof
    }

    pub const fn proof_id_v0(&self) -> CertificateId {
        self.proof_id
    }

    pub const fn finalized_block_id_v0(&self) -> BlockId {
        self.finalized_block_id
    }

    pub const fn finalized_height_v0(&self) -> u64 {
        self.finalized_height
    }

    pub const fn validator_set_id_v0(&self) -> ValidatorSetId {
        self.validator_set_id
    }

    pub const fn state_root_v0(&self) -> StateRoot {
        self.state_root
    }

    pub const fn receipts_root_v0(&self) -> ReceiptsRoot {
        self.receipts_root
    }

    pub const fn authenticated_parent_timestamp_ms_v0(&self) -> u64 {
        self.authenticated_parent_timestamp_ms
    }

    pub const fn finalized_chain_root_v0(&self) -> [u8; 32] {
        self.finalized_chain_root
    }
}

/// Proof-carrying readback of the current finalized application block.
///
/// The native application read is returned only after its immutable durable
/// row, state root, and receipt root are joined to the Ready Core proof above.
/// It is intentionally a local query adapter, not an HTTP/RPC activation.
#[derive(Debug)]
pub struct PocoNodeLabFinalizedQueryV0 {
    proof: PocoNodeLabFinalizedProofV0,
    read: FinalizedNativeApplicationReadV0,
}

impl PocoNodeLabFinalizedQueryV0 {
    pub const fn proof_v0(&self) -> &PocoNodeLabFinalizedProofV0 {
        &self.proof
    }

    pub const fn read_v0(&self) -> &FinalizedNativeApplicationReadV0 {
        &self.read
    }

    pub fn into_parts_v0(
        self,
    ) -> (
        PocoNodeLabFinalizedProofV0,
        FinalizedNativeApplicationReadV0,
    ) {
        (self.proof, self.read)
    }
}

#[derive(Debug)]
pub enum PocoNodeLabFinalizedQueryErrorV0 {
    Proof(PocoNodeLabAuthorityErrorV0),
    Application(String),
    QueryMismatch(&'static str),
}

impl fmt::Display for PocoNodeLabFinalizedQueryErrorV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Proof(error) => write!(formatter, "finalized proof: {error}"),
            Self::Application(error) => write!(formatter, "finalized application read: {error}"),
            Self::QueryMismatch(reason) => write!(formatter, "finalized query mismatch: {reason}"),
        }
    }
}

impl Error for PocoNodeLabFinalizedQueryErrorV0 {}

impl PocoNodeLabPhaseFactsV0 {
    pub const fn phase_v0(self) -> PocoNodeLabAuthorityPhaseV0 {
        self.phase
    }

    pub const fn checkpoint_v0(self) -> ExternalNodeCheckpointV0 {
        self.checkpoint
    }

    pub const fn current_view_v0(self) -> View {
        self.current_view
    }

    pub const fn high_qc_v0(self) -> QcRef {
        self.high_qc
    }

    pub const fn pending_timeout_certificate_id_v0(self) -> Option<CertificateId> {
        self.pending_timeout_certificate_id
    }

    pub const fn finalized_block_id_v0(self) -> BlockId {
        self.finalized_block_id
    }

    pub const fn finalized_height_v0(self) -> u64 {
        self.finalized_height
    }

    /// Domain-separated Core commitment to the exact hash-linked finalized
    /// prefix. This is projected directly from the live Core owner, not from
    /// the whole-node checkpoint or any network claim.
    pub const fn finalized_chain_root_v0(self) -> [u8; 32] {
        self.finalized_chain_root
    }

    pub const fn application_applied_block_id_v0(self) -> BlockId {
        self.application_applied_block_id
    }

    pub const fn application_applied_height_v0(self) -> u64 {
        self.application_applied_height
    }

    pub const fn proposal_parent_block_id_v0(self) -> BlockId {
        self.proposal_parent_block_id
    }

    pub const fn proposal_parent_height_v0(self) -> u64 {
        self.proposal_parent_height
    }

    pub const fn safety_revision_v0(self) -> u64 {
        self.safety_revision
    }

    pub const fn safety_record_checksum_v0(self) -> [u8; 32] {
        self.safety_record_checksum
    }

    pub const fn safety_chain_checksum_v0(self) -> [u8; 32] {
        self.safety_chain_checksum
    }

    pub const fn signer_exact_watermark_v0(
        self,
    ) -> trnm_consensus_signer_journal::SignerWatermarkV0 {
        self.signer_exact_watermark
    }
}

/// Inert, owner-authenticated projection of one clean operational signer cut.
///
/// This value has no public constructor. It is minted only after the live
/// Ready runtime freshly revalidates its operational signer database and
/// external watermark, proves owner affinity, and rejoins that exact signer
/// head to the independently durable whole-node checkpoint. The four
/// per-kind counters therefore cannot be supplied by a continuous-runtime
/// caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PocoNodeLabCleanSignerInventoryV1 {
    exact_watermark: trnm_consensus_signer_journal::SignerWatermarkV0,
    durable_vote_intent_count: u64,
    durable_timeout_intent_count: u64,
    signed_vote_intent_count: u64,
    signed_timeout_intent_count: u64,
    inventory_digest: [u8; 32],
    checkpoint_canonical_sha256: [u8; 32],
}

impl PocoNodeLabCleanSignerInventoryV1 {
    pub const fn exact_watermark_v1(self) -> trnm_consensus_signer_journal::SignerWatermarkV0 {
        self.exact_watermark
    }

    pub const fn durable_vote_intent_count_v1(self) -> u64 {
        self.durable_vote_intent_count
    }

    pub const fn durable_timeout_intent_count_v1(self) -> u64 {
        self.durable_timeout_intent_count
    }

    pub const fn signed_vote_intent_count_v1(self) -> u64 {
        self.signed_vote_intent_count
    }

    pub const fn signed_timeout_intent_count_v1(self) -> u64 {
        self.signed_timeout_intent_count
    }

    pub const fn inventory_digest_v1(self) -> [u8; 32] {
        self.inventory_digest
    }

    pub const fn checkpoint_canonical_sha256_v1(self) -> [u8; 32] {
        self.checkpoint_canonical_sha256
    }
}

/// Exact application record named by the independently persisted checkpoint
/// at a clean terminal cut.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PocoNodeLabTerminalCheckpointApplicationV0 {
    /// The checkpoint was advanced by the exact native finalization commit.
    CommittedFinalization,
    /// A TC moved the checkpoint back to the committed application anchor
    /// while retained P/K rows authenticate Core's selected high-QC path.
    CommittedTimeoutRebase,
    /// The checkpoint names one freshly revalidated terminal proposal `K` row.
    PreparedProposalValidation,
}

/// Authority-free, copyable projection of a consuming clean-stop join.
///
/// This value is minted only while the live Core, SafetyStore, native
/// application, signer journal, proposal-validation journal, and independent
/// checkpoint are all held by one non-cloneable terminal owner. It is inert
/// evidence input: it cannot reopen a namespace, sign, execute, finalize, or
/// advance consensus.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PocoNodeLabTerminalCutV0 {
    checkpoint: ExternalNodeCheckpointV0,
    checkpoint_canonical_sha256: [u8; 32],
    checkpoint_application: PocoNodeLabTerminalCheckpointApplicationV0,
    current_view: View,
    high_qc: QcRef,
    finalized_block_id: BlockId,
    finalized_height: u64,
    finalized_view: View,
    finalized_timestamp_ms: u64,
    finalized_chain_root: [u8; 32],
    submitted_height: u64,
    application_state_root: [u8; 32],
    application_commit_id: [u8; 32],
    application_store_id: [u8; 32],
    application_durable_sequence: u64,
    application_committed_head_row_checksum: [u8; 32],
    safety_journal_id: [u8; 32],
    safety_revision: u64,
    safety_state_record_checksum: [u8; 32],
    safety_record_chain_checksum: [u8; 32],
    signer_journal_id: [u8; 32],
    signer_profile_checksum: [u8; 32],
    signer_exact_watermark: trnm_consensus_signer_journal::SignerWatermarkV0,
    signer_intent_count: u64,
    signer_event_count: u64,
    signer_durable_vote_intent_count: u64,
    signer_durable_timeout_intent_count: u64,
    signer_signed_vote_intent_count: u64,
    signer_signed_timeout_intent_count: u64,
    signer_inventory_digest: [u8; 32],
    proposal_validation_scope: [u8; 32],
    proposal_validation_store_id: [u8; 32],
    proposal_validation_owner_id: [u8; 32],
    proposal_validation_durable_sequence: u64,
    proposal_validation_terminal_row_count: u64,
    prepared_application_record_count: u64,
}

impl PocoNodeLabTerminalCutV0 {
    pub const fn checkpoint_v0(self) -> ExternalNodeCheckpointV0 {
        self.checkpoint
    }

    pub const fn checkpoint_canonical_sha256_v0(self) -> [u8; 32] {
        self.checkpoint_canonical_sha256
    }

    pub const fn checkpoint_application_v0(self) -> PocoNodeLabTerminalCheckpointApplicationV0 {
        self.checkpoint_application
    }

    pub const fn current_view_v0(self) -> View {
        self.current_view
    }

    pub const fn high_qc_v0(self) -> QcRef {
        self.high_qc
    }

    pub const fn finalized_block_id_v0(self) -> BlockId {
        self.finalized_block_id
    }

    pub const fn finalized_height_v0(self) -> u64 {
        self.finalized_height
    }

    pub const fn finalized_view_v0(self) -> View {
        self.finalized_view
    }

    pub const fn finalized_timestamp_ms_v0(self) -> u64 {
        self.finalized_timestamp_ms
    }

    /// Domain-separated Core commitment to the exact hash-linked finalized
    /// prefix. This is never derived from the whole-node checkpoint.
    pub const fn finalized_chain_root_v0(self) -> [u8; 32] {
        self.finalized_chain_root
    }

    /// Maximum height in the freshly audited all-terminal proposal `K` store.
    pub const fn submitted_height_v0(self) -> u64 {
        self.submitted_height
    }

    pub const fn application_state_root_v0(self) -> [u8; 32] {
        self.application_state_root
    }

    pub const fn application_commit_id_v0(self) -> [u8; 32] {
        self.application_commit_id
    }

    pub const fn application_store_id_v0(self) -> [u8; 32] {
        self.application_store_id
    }

    pub const fn application_durable_sequence_v0(self) -> u64 {
        self.application_durable_sequence
    }

    pub const fn application_committed_head_row_checksum_v0(self) -> [u8; 32] {
        self.application_committed_head_row_checksum
    }

    pub const fn safety_journal_id_v0(self) -> [u8; 32] {
        self.safety_journal_id
    }

    pub const fn safety_revision_v0(self) -> u64 {
        self.safety_revision
    }

    pub const fn safety_state_record_checksum_v0(self) -> [u8; 32] {
        self.safety_state_record_checksum
    }

    pub const fn safety_record_chain_checksum_v0(self) -> [u8; 32] {
        self.safety_record_chain_checksum
    }

    pub const fn signer_journal_id_v0(self) -> [u8; 32] {
        self.signer_journal_id
    }

    pub const fn signer_profile_checksum_v0(self) -> [u8; 32] {
        self.signer_profile_checksum
    }

    pub const fn signer_exact_watermark_v0(
        self,
    ) -> trnm_consensus_signer_journal::SignerWatermarkV0 {
        self.signer_exact_watermark
    }

    pub const fn signer_intent_count_v0(self) -> u64 {
        self.signer_intent_count
    }

    pub const fn signer_event_count_v0(self) -> u64 {
        self.signer_event_count
    }

    pub const fn signer_durable_vote_intent_count_v1(self) -> u64 {
        self.signer_durable_vote_intent_count
    }

    pub const fn signer_durable_timeout_intent_count_v1(self) -> u64 {
        self.signer_durable_timeout_intent_count
    }

    pub const fn signer_signed_vote_intent_count_v1(self) -> u64 {
        self.signer_signed_vote_intent_count
    }

    pub const fn signer_signed_timeout_intent_count_v1(self) -> u64 {
        self.signer_signed_timeout_intent_count
    }

    pub const fn signer_inventory_digest_v1(self) -> [u8; 32] {
        self.signer_inventory_digest
    }

    pub const fn proposal_validation_scope_v0(self) -> [u8; 32] {
        self.proposal_validation_scope
    }

    pub const fn proposal_validation_store_id_v0(self) -> [u8; 32] {
        self.proposal_validation_store_id
    }

    pub const fn proposal_validation_owner_id_v0(self) -> [u8; 32] {
        self.proposal_validation_owner_id
    }

    pub const fn proposal_validation_durable_sequence_v0(self) -> u64 {
        self.proposal_validation_durable_sequence
    }

    pub const fn proposal_validation_terminal_row_count_v0(self) -> u64 {
        self.proposal_validation_terminal_row_count
    }

    pub const fn prepared_application_record_count_v0(self) -> u64 {
        self.prepared_application_record_count
    }
}

/// Authoritative typed input for binding one untrusted proposal carrier.
///
/// The Node owns certificate application and parent selection. The network
/// layer owns the unbound proposal and may turn it into `SignedProposalV0`
/// only after all four values below agree with the embedded witness/header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PocoNodeLabProposalBindingV0 {
    current_view: View,
    high_qc: QcReferenceV0,
    parent: PocoNodeLabProposalParentV0,
}

impl PocoNodeLabProposalBindingV0 {
    pub const fn current_view_v0(&self) -> View {
        self.current_view
    }

    pub const fn high_qc_v0(&self) -> &QcReferenceV0 {
        &self.high_qc
    }

    pub const fn parent_v0(&self) -> &PocoNodeLabProposalParentV0 {
        &self.parent
    }
}

/// Exact application parent selected by the live ordinary runtime.
///
/// This is inert proposal-construction input. It carries neither a Core
/// validation permit nor application read/apply authority. The timestamp is
/// authenticated either by the exact retained speculative execution or by
/// Core's fully applied durable tip; caller-supplied timestamps are never used
/// to reconstruct the parent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PocoNodeLabProposalParentV0 {
    application_head: ApplicationHeadV0,
    authenticated_parent_timestamp_ms: u64,
}

/// Read-only facts for one durable, inert local-timeout authorization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PocoNodeLabInertTimeoutFactsV0 {
    view: View,
    high_qc: QcRef,
    authorizing_safety_revision: u64,
    signing_root: [u8; 32],
    checkpoint: ExternalNodeCheckpointV0,
    signer_exact_watermark: trnm_consensus_signer_journal::SignerWatermarkV0,
}

impl PocoNodeLabInertTimeoutFactsV0 {
    pub const fn view_v0(&self) -> View {
        self.view
    }

    pub const fn high_qc_v0(&self) -> QcRef {
        self.high_qc
    }

    pub const fn authorizing_safety_revision_v0(&self) -> u64 {
        self.authorizing_safety_revision
    }

    pub const fn signing_root_v0(&self) -> [u8; 32] {
        self.signing_root
    }

    pub const fn checkpoint_v0(&self) -> ExternalNodeCheckpointV0 {
        self.checkpoint
    }

    pub const fn signer_exact_watermark_v0(
        &self,
    ) -> trnm_consensus_signer_journal::SignerWatermarkV0 {
        self.signer_exact_watermark
    }
}

/// Linear owner of one persisted-but-unsigned timeout intent.
pub struct PocoNodeLabInertTimeoutOwnerV0<W: ExternalMonotonicWatermarkV0> {
    core: Core,
    seal_authority: CoreIssuedApplicationSealAuthorityV0,
    finalization_authority: CoreIssuedApplicationFinalizationApplyAuthorityV0,
    safety_store: SqliteSafetyStateStoreV0<StrictEd25519Verifier>,
    application: DurableNativeApplicationV0,
    signer_journal: SqliteSignerJournalV0<W>,
    checkpoint_store: SqliteExternalNodeCheckpointStoreV0,
    application_head: ApplicationHeadV0,
    application_overlay: Option<trnm_consensus_core::BlockIdOverlayRefV0>,
    pending_executions: BTreeMap<BlockId, PocoNodeLabRetainedExecutionV0>,
    proposal_journal: PocoNodeLabProposalJournalConfigV0,
    intent: CanonicalSignIntentV0,
    facts: PocoNodeLabInertTimeoutFactsV0,
}

impl<W: ExternalMonotonicWatermarkV0> PocoNodeLabInertTimeoutOwnerV0<W> {
    pub const fn facts_v0(&self) -> &PocoNodeLabInertTimeoutFactsV0 {
        &self.facts
    }

    /// Journals the exact timeout signature, commits the resulting signer
    /// watermark through whole-node CAS, and only then feeds SignatureReady
    /// to Core. No raw signer or Core owner escapes this linear carrier.
    pub fn sign_exact_timeout_v0<P: SignatureProducerV0>(
        mut self,
        producer: &mut P,
    ) -> Result<PocoNodeLabSignedTimeoutOwnerV0<W>, PocoNodeLabAuthorityErrorV0> {
        let source_checkpoint = self.facts.checkpoint;
        if self
            .checkpoint_store
            .load(source_checkpoint.scope())
            .map_err(PocoNodeLabAuthorityErrorV0::Checkpoint)?
            != Some(source_checkpoint)
        {
            return Err(PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
                "inert timeout checkpoint is not the exact external head",
            ));
        }
        let safety_before =
            confirm_live_or_signature_released_safety_head_v0(&self.core, &self.safety_store)?;
        let signer_before = self
            .signer_journal
            .confirm_node_checkpoint_head_exact_v0()
            .map_err(PocoNodeLabAuthorityErrorV0::Signer)?;
        require_checkpoint_heads_v0(source_checkpoint, &safety_before, &signer_before)?;
        self.intent
            .validate(self.core.config().validator_set())
            .map_err(|error| PocoNodeLabAuthorityErrorV0::AuthorityChain(error.to_string()))?;
        let CanonicalSignPreimageV0::TimeoutVote(preimage) = self.intent.preimage() else {
            return Err(PocoNodeLabAuthorityErrorV0::UnexpectedEffect(
                "inert timeout owner retained a non-timeout intent",
            ));
        };
        if preimage.view() != self.facts.view
            || preimage.high_qc() != self.facts.high_qc
            || self.intent.authorizing_safety_revision() != self.facts.authorizing_safety_revision
            || self.intent.signing_root().as_bytes() != &self.facts.signing_root
        {
            return Err(PocoNodeLabAuthorityErrorV0::UnexpectedEffect(
                "inert timeout intent differs from its authority facts",
            ));
        }
        let signature = self
            .signer_journal
            .sign_exact_v0(&self.intent, producer)
            .map_err(PocoNodeLabAuthorityErrorV0::Signer)?;
        let signer_after = self
            .signer_journal
            .confirm_node_checkpoint_head_exact_v0()
            .map_err(PocoNodeLabAuthorityErrorV0::Signer)?;
        require_one_exact_signer_pair_v0(&signer_before, &signer_after)?;
        let safety_after = self
            .safety_store
            .confirm_node_checkpoint_head_exact_v0(self.core.safety_state())
            .map_err(PocoNodeLabAuthorityErrorV0::Safety)?;
        require_same_safety_head_v0(&safety_before, &safety_after)?;
        let signed_checkpoint =
            signer_checkpoint_successor_v0(source_checkpoint, &safety_after, &signer_after)?;
        compare_and_confirm_checkpoint_v0(
            &mut self.checkpoint_store,
            Some(source_checkpoint),
            signed_checkpoint,
        )?;
        let effects = self
            .core
            .step(
                Input::SignatureReady {
                    id: SignId::new(self.intent.signing_root()),
                    signature,
                },
                &StrictEd25519Verifier,
            )
            .map_err(PocoNodeLabAuthorityErrorV0::Core)?;
        let [Effect::Broadcast(OutboundMessage::TimeoutVote(vote))] = effects.as_slice() else {
            return Err(PocoNodeLabAuthorityErrorV0::UnexpectedEffect(
                "timeout SignatureReady did not release exactly one timeout vote",
            ));
        };
        vote.verify(self.core.config().validator_set(), &StrictEd25519Verifier)
            .map_err(|error| PocoNodeLabAuthorityErrorV0::AuthorityChain(error.to_string()))?;
        if vote.view() != preimage.view()
            || vote.high_qc() != preimage.high_qc()
            || vote.author() != self.intent.author()
            || vote.signature() != &signature
            || vote.signing_root() != self.intent.signing_root()
            || self.core.safety_state().pending_sign().is_some()
        {
            return Err(PocoNodeLabAuthorityErrorV0::UnexpectedEffect(
                "released timeout vote differs from the journaled intent",
            ));
        }
        let facts = PocoNodeLabSignedTimeoutFactsV0 {
            view: vote.view(),
            high_qc: vote.high_qc(),
            signing_root: *vote.signing_root().as_bytes(),
            checkpoint: signed_checkpoint,
            signer_exact_watermark: signer_after.exact_watermark(),
        };
        Ok(PocoNodeLabSignedTimeoutOwnerV0 {
            core: self.core,
            seal_authority: self.seal_authority,
            finalization_authority: self.finalization_authority,
            safety_store: self.safety_store,
            application: self.application,
            signer_journal: self.signer_journal,
            checkpoint_store: self.checkpoint_store,
            application_head: self.application_head,
            application_overlay: self.application_overlay,
            pending_executions: self.pending_executions,
            proposal_journal: self.proposal_journal,
            outbound: PocoNodeLabSignedTimeoutOutboundV0 { vote: vote.clone() },
            facts,
        })
    }
}

impl<W: ExternalMonotonicWatermarkV0> fmt::Debug for PocoNodeLabInertTimeoutOwnerV0<W> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PocoNodeLabInertTimeoutOwnerV0")
            .field("facts", &self.facts)
            .finish_non_exhaustive()
    }
}

/// Scalar readback of one released, journal-authenticated timeout vote.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PocoNodeLabSignedTimeoutFactsV0 {
    view: View,
    high_qc: QcRef,
    signing_root: [u8; 32],
    checkpoint: ExternalNodeCheckpointV0,
    signer_exact_watermark: trnm_consensus_signer_journal::SignerWatermarkV0,
}

impl PocoNodeLabSignedTimeoutFactsV0 {
    pub const fn view_v0(&self) -> View {
        self.view
    }

    pub const fn high_qc_v0(&self) -> QcRef {
        self.high_qc
    }

    pub const fn signing_root_v0(&self) -> [u8; 32] {
        self.signing_root
    }

    pub const fn checkpoint_v0(&self) -> ExternalNodeCheckpointV0 {
        self.checkpoint
    }

    pub const fn signer_exact_watermark_v0(
        &self,
    ) -> trnm_consensus_signer_journal::SignerWatermarkV0 {
        self.signer_exact_watermark
    }
}

/// Non-forgeable carrier for the sole timeout vote released from Core.
pub struct PocoNodeLabSignedTimeoutOutboundV0 {
    vote: TimeoutVote,
}

impl PocoNodeLabSignedTimeoutOutboundV0 {
    pub const fn timeout_vote_v0(&self) -> &TimeoutVote {
        &self.vote
    }
}

impl fmt::Debug for PocoNodeLabSignedTimeoutOutboundV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PocoNodeLabSignedTimeoutOutboundV0")
            .field("view", &self.vote.view())
            .field("high_qc", &self.vote.high_qc())
            .field("author", &self.vote.author())
            .finish_non_exhaustive()
    }
}

/// Live authority owner after exact timeout signing and SignatureReady.
pub struct PocoNodeLabSignedTimeoutOwnerV0<W: ExternalMonotonicWatermarkV0> {
    core: Core,
    seal_authority: CoreIssuedApplicationSealAuthorityV0,
    finalization_authority: CoreIssuedApplicationFinalizationApplyAuthorityV0,
    safety_store: SqliteSafetyStateStoreV0<StrictEd25519Verifier>,
    application: DurableNativeApplicationV0,
    signer_journal: SqliteSignerJournalV0<W>,
    checkpoint_store: SqliteExternalNodeCheckpointStoreV0,
    application_head: ApplicationHeadV0,
    application_overlay: Option<trnm_consensus_core::BlockIdOverlayRefV0>,
    pending_executions: BTreeMap<BlockId, PocoNodeLabRetainedExecutionV0>,
    proposal_journal: PocoNodeLabProposalJournalConfigV0,
    outbound: PocoNodeLabSignedTimeoutOutboundV0,
    facts: PocoNodeLabSignedTimeoutFactsV0,
}

impl<W: ExternalMonotonicWatermarkV0> PocoNodeLabSignedTimeoutOwnerV0<W> {
    pub const fn facts_v0(&self) -> &PocoNodeLabSignedTimeoutFactsV0 {
        &self.facts
    }

    pub fn phase_facts_v0(&self) -> PocoNodeLabPhaseFactsV0 {
        phase_facts_from_parts_v0(
            PocoNodeLabAuthorityPhaseV0::TimeoutSigned,
            &self.core,
            self.facts.checkpoint,
            &self.application_head,
        )
    }

    pub const fn outbound_v0(&self) -> &PocoNodeLabSignedTimeoutOutboundV0 {
        &self.outbound
    }

    pub fn reconfirm_phase_neutral_exact_high_qc_v0(
        &mut self,
        certificate: &QuorumCertificate,
    ) -> Result<PocoNodeLabPhaseFactsV0, PocoNodeLabAuthorityErrorV0> {
        reconfirm_phase_neutral_exact_high_qc_v0(
            certificate,
            &self.core,
            &self.safety_store,
            &self.application,
            &mut self.signer_journal,
            &mut self.checkpoint_store,
            self.facts.checkpoint,
            &self.application_head,
            &self.pending_executions,
            &self.proposal_journal,
            None,
        )?;
        Ok(self.phase_facts_v0())
    }

    /// A late QC remains admissible after the local timeout vote was released.
    pub fn advance_quorum_certificate_v0(
        self,
        certificate: QuorumCertificate,
    ) -> Result<PocoNodeLabCertificateAdvanceV0<W>, PocoNodeLabAuthorityErrorV0> {
        self.into_ready_v0()?
            .advance_quorum_certificate_v0(certificate)
    }

    /// Consumes one fully verified TC against the same Core owner. A TC can
    /// advance view/highQC but remains incapable of finalizing by itself.
    pub fn advance_timeout_certificate_v0(
        self,
        certificate: TimeoutCertificateV0,
    ) -> Result<PocoNodeLabCertificateAdvanceV0<W>, PocoNodeLabAuthorityErrorV0> {
        self.into_ready_v0()?
            .advance_timeout_certificate_v0(certificate)
    }

    fn into_ready_v0(
        self,
    ) -> Result<PocoNodeLabOrdinaryProposalRuntimeV0<W>, PocoNodeLabAuthorityErrorV0> {
        Ok(PocoNodeLabOrdinaryProposalRuntimeV0 {
            core: self.core,
            seal_authority: self.seal_authority,
            finalization_authority: self.finalization_authority,
            safety_store: self.safety_store,
            application: self.application,
            signer_journal: self.signer_journal,
            checkpoint_store: self.checkpoint_store,
            checkpoint: self.facts.checkpoint,
            application_head: self.application_head,
            application_overlay: self.application_overlay,
            pending_executions: self.pending_executions,
            proposal_journal: self.proposal_journal,
        })
    }
}

impl<W: ExternalMonotonicWatermarkV0> fmt::Debug for PocoNodeLabSignedTimeoutOwnerV0<W> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PocoNodeLabSignedTimeoutOwnerV0")
            .field("facts", &self.facts)
            .field("outbound", &self.outbound)
            .finish_non_exhaustive()
    }
}

impl PocoNodeLabProposalParentV0 {
    pub const fn application_head_v0(&self) -> &ApplicationHeadV0 {
        &self.application_head
    }

    pub const fn authenticated_parent_timestamp_ms_v0(&self) -> u64 {
        self.authenticated_parent_timestamp_ms
    }
}

/// Consuming terminal owner for one exact clean laboratory validator cut.
///
/// All mutable namespaces and the live Core remain privately pinned until this
/// value is dropped, while the proposal-seal and finalization-apply
/// capabilities have been consumed out of the live runtime and destroyed.
/// There is deliberately no method which can recover a Ready runtime or expose
/// any underlying owner.
#[must_use = "the terminal owner pins every namespace behind its inert cut"]
pub struct PocoNodeLabTerminalOwnerV0<W: ExternalMonotonicWatermarkV0> {
    _core: Core,
    _safety_store: SqliteSafetyStateStoreV0<StrictEd25519Verifier>,
    _application: DurableNativeApplicationV0,
    _signer_journal: SqliteSignerJournalV0<W>,
    _checkpoint_store: SqliteExternalNodeCheckpointStoreV0,
    _proposal_validation_store: SqliteProposalValidationStoreV0,
    facts: PocoNodeLabTerminalCutV0,
}

impl<W: ExternalMonotonicWatermarkV0> PocoNodeLabTerminalOwnerV0<W> {
    pub const fn facts_v0(&self) -> &PocoNodeLabTerminalCutV0 {
        &self.facts
    }
}

impl<W: ExternalMonotonicWatermarkV0> fmt::Debug for PocoNodeLabTerminalOwnerV0<W> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PocoNodeLabTerminalOwnerV0")
            .field("facts", &self.facts)
            .finish_non_exhaustive()
    }
}

/// One recovered, positive-height laboratory authority cut.
///
/// Construction consumes every live owner and binds the SafetyStore to this
/// exact Core.  A failure returns no partially usable authority bundle.
pub struct PocoNodeLabOrdinaryProposalRuntimeV0<W: ExternalMonotonicWatermarkV0> {
    pub(super) core: Core,
    pub(super) seal_authority: CoreIssuedApplicationSealAuthorityV0,
    pub(super) finalization_authority: CoreIssuedApplicationFinalizationApplyAuthorityV0,
    pub(super) safety_store: SqliteSafetyStateStoreV0<StrictEd25519Verifier>,
    pub(super) application: DurableNativeApplicationV0,
    pub(super) signer_journal: SqliteSignerJournalV0<W>,
    pub(super) checkpoint_store: SqliteExternalNodeCheckpointStoreV0,
    pub(super) checkpoint: ExternalNodeCheckpointV0,
    pub(super) application_head: ApplicationHeadV0,
    pub(super) application_overlay: Option<trnm_consensus_core::BlockIdOverlayRefV0>,
    pub(super) pending_executions: BTreeMap<BlockId, PocoNodeLabRetainedExecutionV0>,
    pub(super) proposal_journal: PocoNodeLabProposalJournalConfigV0,
}

impl<W: ExternalMonotonicWatermarkV0> fmt::Debug for PocoNodeLabOrdinaryProposalRuntimeV0<W> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PocoNodeLabOrdinaryProposalRuntimeV0")
            .field(
                "finalized_height",
                &self.core.safety_state().finalized().height(),
            )
            .field("application_head", &self.application_head)
            .field("checkpoint_generation", &self.checkpoint.generation())
            .finish_non_exhaustive()
    }
}

impl<W: ExternalMonotonicWatermarkV0> PocoNodeLabOrdinaryProposalRuntimeV0<W> {
    pub fn facts_v0(&self) -> PocoNodeLabRuntimeFactsV0 {
        let finalized = self.core.safety_state().finalized();
        let applied = self.core.safety_state().application_applied();
        PocoNodeLabRuntimeFactsV0 {
            checkpoint: self.checkpoint,
            current_view: self.core.safety_state().current_view(),
            finalized_block_id: finalized.block_id(),
            finalized_height: finalized.height().get(),
            finalized_view: finalized.view(),
            application_applied_block_id: applied.block_id(),
            application_applied_height: applied.height().get(),
            proposal_parent_block_id: BlockId::new(*self.application_head.block_id().as_bytes()),
            proposal_parent_height: self.application_head.height().get(),
        }
    }

    pub fn phase_facts_v0(&self) -> PocoNodeLabPhaseFactsV0 {
        phase_facts_from_parts_v0(
            PocoNodeLabAuthorityPhaseV0::Ready,
            &self.core,
            self.checkpoint,
            &self.application_head,
        )
    }

    /// Returns the exact authenticated proof for the current finalized tip.
    ///
    /// This is deliberately Ready-only and performs a fresh strict
    /// verification on every call.  A caller cannot turn the scalar phase
    /// projection into a proof: the proof must still be present in Core's
    /// durable finalization/state-sync provenance and must bind to the live
    /// validator set, parameter preimage, parent timestamp, finalized
    /// coordinates, and chain-root projection.
    pub fn finalized_proof_v0(
        &self,
    ) -> Result<PocoNodeLabFinalizedProofV0, PocoNodeLabAuthorityErrorV0> {
        finalized_proof_from_core_v0(&self.core)
    }

    /// Reads the exact current finalized application row by BlockId and
    /// returns it only when the native store revalidates the same proof.
    /// Historical/future keys are rejected instead of being answered with a
    /// proof for a different tip.
    pub fn read_finalized_by_block_id_v0(
        &self,
        block_id: BlockId,
    ) -> Result<PocoNodeLabFinalizedQueryV0, PocoNodeLabFinalizedQueryErrorV0> {
        let proof = self
            .finalized_proof_v0()
            .map_err(PocoNodeLabFinalizedQueryErrorV0::Proof)?;
        if block_id != proof.finalized_block_id_v0() {
            return Err(PocoNodeLabFinalizedQueryErrorV0::QueryMismatch(
                "BlockId is not the current Core finalized tip",
            ));
        }
        let application_block_id = BlockIdV0::new(*block_id.as_bytes()).map_err(|_| {
            PocoNodeLabFinalizedQueryErrorV0::QueryMismatch("BlockId has invalid native shape")
        })?;
        let read = self
            .application
            .read_finalized_by_block_id_with_proof_v0(
                application_block_id,
                proof.proof_v0(),
                proof.authenticated_parent_timestamp_ms_v0(),
            )
            .map_err(|error| PocoNodeLabFinalizedQueryErrorV0::Application(error.to_string()))?;
        bind_finalized_query_v0(&proof, &read)?;
        Ok(PocoNodeLabFinalizedQueryV0 { proof, read })
    }

    /// Height-keyed counterpart to
    /// [`Self::read_finalized_by_block_id_v0`]. Only the current finalized
    /// height is answerable until historical proof storage is wired.
    pub fn read_finalized_by_height_v0(
        &self,
        height: u64,
    ) -> Result<PocoNodeLabFinalizedQueryV0, PocoNodeLabFinalizedQueryErrorV0> {
        let proof = self
            .finalized_proof_v0()
            .map_err(PocoNodeLabFinalizedQueryErrorV0::Proof)?;
        if height != proof.finalized_height_v0() {
            return Err(PocoNodeLabFinalizedQueryErrorV0::QueryMismatch(
                "height is not the current Core finalized tip",
            ));
        }
        let read = self
            .application
            .read_finalized_by_height_with_proof_v0(
                HeightV0::new(height),
                proof.proof_v0(),
                proof.authenticated_parent_timestamp_ms_v0(),
            )
            .map_err(|error| PocoNodeLabFinalizedQueryErrorV0::Application(error.to_string()))?;
        bind_finalized_query_v0(&proof, &read)?;
        Ok(PocoNodeLabFinalizedQueryV0 { proof, read })
    }

    pub const fn checkpoint_v0(&self) -> &ExternalNodeCheckpointV0 {
        &self.checkpoint
    }

    /// Installs an independently administered watermark behind the existing
    /// Ready signer journal.  The journal first confirms its current local
    /// head, then lets `W` claim that exact head, and finally rechecks the
    /// external value before this runtime remains usable.
    pub fn install_external_monotonic_watermark_v0(
        &mut self,
        external: Box<dyn ExternalMonotonicWatermarkV0 + Send>,
    ) -> Result<(), PocoNodeLabAuthorityErrorV0>
    where
        W: ExternalMonotonicWatermarkInjectionV0,
    {
        self.signer_journal
            .install_external_monotonic_watermark_v0(external)
            .map_err(PocoNodeLabAuthorityErrorV0::Signer)
    }

    /// Freshly audits the live Ready signer's complete Vote/TimeoutVote
    /// inventory and rejoins its exact operational watermark to this runtime's
    /// independent whole-node checkpoint.
    ///
    /// The returned projection is inert and has no caller-scalar constructor.
    /// It neither signs nor advances any namespace.
    pub fn fresh_clean_signer_inventory_v1(
        &mut self,
    ) -> Result<PocoNodeLabCleanSignerInventoryV1, PocoNodeLabAuthorityErrorV0> {
        let safety_facts = self
            .safety_store
            .confirm_node_checkpoint_head_exact_v0(self.core.safety_state())
            .map_err(PocoNodeLabAuthorityErrorV0::Safety)?;
        let signer_facts = self
            .signer_journal
            .confirm_node_checkpoint_head_exact_v0()
            .map_err(PocoNodeLabAuthorityErrorV0::Signer)?;
        if !safety_facts.belongs_to_store_at_path_v0(&self.safety_store, self.safety_store.path())
            || !signer_facts.belongs_to_operational_journal_at_path_v0(
                &self.signer_journal,
                self.signer_journal.path(),
            )
        {
            return Err(PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
                "fresh Ready signer inventory lost exact owner affinity",
            ));
        }
        let signer_inventory = clean_signer_lifetime_inventory_v1(&signer_facts).ok_or(
            PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
                "fresh Ready signer Vote/TimeoutVote lifecycles are not individually clean",
            ),
        )?;
        let observed_checkpoint = self
            .checkpoint_store
            .load(self.checkpoint.scope())
            .map_err(PocoNodeLabAuthorityErrorV0::Checkpoint)?
            .ok_or(PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
                "whole-node checkpoint disappeared during fresh signer inventory audit",
            ))?;
        if observed_checkpoint != self.checkpoint {
            return Err(PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
                "whole-node checkpoint changed during fresh signer inventory audit",
            ));
        }
        require_checkpoint_heads_v0(self.checkpoint, &safety_facts, &signer_facts)?;
        Ok(PocoNodeLabCleanSignerInventoryV1 {
            exact_watermark: signer_facts.exact_watermark(),
            durable_vote_intent_count: signer_inventory.durable_vote_intent_count(),
            durable_timeout_intent_count: signer_inventory.durable_timeout_intent_count(),
            signed_vote_intent_count: signer_inventory.signed_vote_intent_count(),
            signed_timeout_intent_count: signer_inventory.signed_timeout_intent_count(),
            inventory_digest: signer_inventory.inventory_digest(),
            checkpoint_canonical_sha256: Sha256::digest(observed_checkpoint.encode_canonical())
                .into(),
        })
    }

    pub fn reconfirm_phase_neutral_exact_high_qc_v0(
        &mut self,
        certificate: &QuorumCertificate,
    ) -> Result<PocoNodeLabPhaseFactsV0, PocoNodeLabAuthorityErrorV0> {
        reconfirm_phase_neutral_exact_high_qc_v0(
            certificate,
            &self.core,
            &self.safety_store,
            &self.application,
            &mut self.signer_journal,
            &mut self.checkpoint_store,
            self.checkpoint,
            &self.application_head,
            &self.pending_executions,
            &self.proposal_journal,
            None,
        )?;
        Ok(self.phase_facts_v0())
    }

    /// Consumes one phase-Ready validator into an inert terminal owner after
    /// freshly joining every durable namespace.
    ///
    /// Terminalization is fail-closed: Core must have no transient validation,
    /// certificate-sync, signing, or finalization work; consensus finality and
    /// the native committed application must agree; every still-prepared native
    /// `P` must have one retained, freshly authenticated terminal `K`; and the
    /// independent checkpoint must name the exact Safety/signer heads plus
    /// either the committed application head or one such `K` row. Success
    /// destroys both live application capabilities before returning.
    pub fn into_terminal_owner_v0(
        mut self,
    ) -> Result<PocoNodeLabTerminalOwnerV0<W>, PocoNodeLabAuthorityErrorV0> {
        if !self
            .seal_authority
            .matches_application_finalization_authority_v0(&self.finalization_authority)
        {
            return Err(PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
                "terminal application authorities differ from the live Core",
            ));
        }
        let _proposal_binding = self.proposal_binding_v0()?;
        let safety = self.core.safety_state();
        let finalized = safety.finalized();
        let applied = safety.application_applied();
        let finalized_chain_root = *self.core.finalized_chain_root_v0().as_bytes();
        if finalized.height().get() == 0 {
            return Err(PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
                "terminal runtime requires a positive finalized cut",
            ));
        }
        if safety.safety_halt().is_some()
            || safety.pending_sign().is_some()
            || safety.pending_finalize().is_some()
            || safety.pending_finalization().is_some()
            || safety.pending_tc_high_qc_sync().is_some()
            || safety.pending_standalone_qc_sync().is_some()
            || !safety.finalization_queue().is_empty()
            || !safety.payload_validation_obligations().is_empty()
            || self.core.pending_validation_count() != 0
        {
            return Err(PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
                "terminal runtime retained transient Core or Safety work",
            ));
        }
        if finalized != applied {
            return Err(PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
                "terminal finalized and application-applied tips differ",
            ));
        }
        if finalized_chain_root == [0; 32] {
            return Err(PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
                "terminal Core finalized-prefix commitment is zero",
            ));
        }

        let committed = self
            .application
            .confirmed_committed_head_v0()
            .map_err(|error| PocoNodeLabAuthorityErrorV0::AuthorityChain(error.to_string()))?;
        if committed.block_id().as_bytes() != finalized.block_id().as_bytes()
            || committed.height().get() != finalized.height().get()
        {
            return Err(PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
                "terminal native committed head differs from finalized application_applied",
            ));
        }

        let application_config = self.application.config_v0();
        let application_store_id = application_config.store_id();
        if application_store_id == [0; 32] {
            return Err(PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
                "terminal native application store identity is zero",
            ));
        }
        let recovery_request = NativeApplicationRecoveryRequestV0::new(
            ChainIdV0::new(application_config.chain_id_v0())
                .map_err(|error| PocoNodeLabAuthorityErrorV0::AuthorityChain(error.to_string()))?,
            GenesisHashV0::new(application_config.genesis_hash_v0())
                .map_err(|error| PocoNodeLabAuthorityErrorV0::AuthorityChain(error.to_string()))?,
            Hash32V0::new(application_config.chain_descriptor_hash_v0()),
            Hash32V0::new(application_config.signer_policy_commitment_v0()),
            committed.clone(),
            NativeRecoveryWatermarksV0::new(0, 0, 0),
        )
        .map_err(|error| PocoNodeLabAuthorityErrorV0::AuthorityChain(error.to_string()))?;
        let recovery = self
            .application
            .recover(recovery_request)
            .map_err(|error| PocoNodeLabAuthorityErrorV0::AuthorityChain(error.to_string()))?;
        if recovery.head() != &committed {
            return Err(PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
                "terminal native recovery head differs from fresh committed readback",
            ));
        }
        let prepared_application_record_count = u64::try_from(self.pending_executions.len())
            .map_err(|_| {
                PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
                    "terminal prepared application record count overflows",
                )
            })?;
        match recovery.disposition() {
            NativeRecoveryDispositionV0::Exact if prepared_application_record_count == 0 => {}
            NativeRecoveryDispositionV0::ValidationReplayRequired { pending_records }
                if pending_records == prepared_application_record_count => {}
            _ => {
                return Err(PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
                    "terminal native recovery disposition differs from retained prepared P records",
                ));
            }
        }
        let application_durable_sequence = recovery.watermarks().application_commit();

        let safety_facts = self
            .safety_store
            .confirm_node_checkpoint_head_exact_v0(self.core.safety_state())
            .map_err(PocoNodeLabAuthorityErrorV0::Safety)?;
        let signer_facts = self
            .signer_journal
            .confirm_node_checkpoint_head_exact_v0()
            .map_err(PocoNodeLabAuthorityErrorV0::Signer)?;
        if !safety_facts.belongs_to_store_at_path_v0(&self.safety_store, self.safety_store.path())
            || !signer_facts.belongs_to_operational_journal_at_path_v0(
                &self.signer_journal,
                self.signer_journal.path(),
            )
            || signer_facts.pending_intent().is_some()
        {
            return Err(PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
                "terminal Safety or signer head lost exact owner affinity",
            ));
        }
        let signer_inventory = clean_signer_lifetime_inventory_v1(&signer_facts).ok_or(
            PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
                "terminal signer Vote/TimeoutVote lifecycles are not individually clean",
            ),
        )?;
        let observed_checkpoint = self
            .checkpoint_store
            .load(self.checkpoint.scope())
            .map_err(PocoNodeLabAuthorityErrorV0::Checkpoint)?
            .ok_or(PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
                "terminal whole-node checkpoint disappeared",
            ))?;
        if observed_checkpoint != self.checkpoint {
            return Err(PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
                "terminal whole-node checkpoint differs from the live runtime cut",
            ));
        }
        require_checkpoint_heads_v0(self.checkpoint, &safety_facts, &signer_facts)?;

        let mut proposal_validation_store = SqliteProposalValidationStoreV0::open(
            &self.proposal_journal.store_path,
            self.proposal_journal.scope,
            self.proposal_journal.minimum_durable_sequence,
        )
        .map_err(|error| PocoNodeLabAuthorityErrorV0::AuthorityChain(error.to_string()))?;
        let proposal_validation_durable_sequence = proposal_validation_store
            .durable_sequence_v0()
            .map_err(|error| PocoNodeLabAuthorityErrorV0::AuthorityChain(error.to_string()))?;
        if proposal_validation_store.path() != self.proposal_journal.store_path.as_path()
            || proposal_validation_store.scope_v0() != self.proposal_journal.scope
            || proposal_validation_store.store_id_v0() == [0; 32]
            || proposal_validation_durable_sequence < self.proposal_journal.minimum_durable_sequence
            || proposal_validation_durable_sequence % 3 != 0
        {
            return Err(PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
                "terminal proposal-validation journal is not one complete P/D/C/K sequence",
            ));
        }
        let proposal_terminal_audit = proposal_validation_store
            .confirm_terminal_k_audit_v0()
            .map_err(|error| PocoNodeLabAuthorityErrorV0::AuthorityChain(error.to_string()))?;
        if !proposal_terminal_audit.belongs_to_store_at_path_v0(
            &proposal_validation_store,
            &self.proposal_journal.store_path,
        ) || proposal_terminal_audit.scope_v0() != self.proposal_journal.scope
            || proposal_terminal_audit.store_id_v0() != proposal_validation_store.store_id_v0()
            || proposal_terminal_audit.owner_id_v0() != self.proposal_journal.owner_id
            || proposal_terminal_audit.store_sequence_v0() != proposal_validation_durable_sequence
        {
            return Err(PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
                "terminal proposal-validation aggregate lost exact store/owner affinity",
            ));
        }
        let submitted_height = proposal_terminal_audit.maximum_terminal_height_v0();
        let proposal_validation_terminal_row_count =
            proposal_terminal_audit.terminal_row_count_v0();
        let mut proposal_validation_owner_id = None;
        for (block_id, retained) in &self.pending_executions {
            let fresh_owner_id = reconfirm_terminal_retained_execution_v0(
                *block_id,
                retained,
                &self.application,
                &mut proposal_validation_store,
                proposal_validation_durable_sequence,
            )?;
            if fresh_owner_id != self.proposal_journal.owner_id
                || proposal_validation_owner_id.is_some_and(|expected| expected != fresh_owner_id)
            {
                return Err(PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
                    "terminal proposal-validation owner differs across fresh K rows or configuration",
                ));
            }
            proposal_validation_owner_id = Some(fresh_owner_id);
        }
        let proposal_validation_owner_id =
            proposal_validation_owner_id.ok_or(PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
                "terminal runtime has no retained K row for fresh proposal-owner readback",
            ))?;
        if proposal_validation_store
            .durable_sequence_v0()
            .map_err(|error| PocoNodeLabAuthorityErrorV0::AuthorityChain(error.to_string()))?
            != proposal_validation_durable_sequence
        {
            return Err(PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
                "terminal proposal-validation journal advanced during fresh readback",
            ));
        }
        if submitted_height < safety.high_qc().qc_ref().height().get()
            || safety.high_qc().qc_ref().height().get() < finalized.height().get()
        {
            return Err(PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
                "terminal submitted/high-QC/finalized heights are not monotonic",
            ));
        }

        let fields = self.checkpoint.fields();
        let expected_committed_row_checksum = application_head_checksum_v0(
            b"trnm.poco-node.lab-finalization.checkpoint-head.v0",
            &committed,
        );
        let expected_committed_application_owner = lab_genesis_hash_v0(
            b"trnm.poco-node.lab-finalization.application-owner.v0",
            &[
                application_config.chain_id_v0().as_bytes(),
                &application_config.genesis_hash_v0(),
                &application_store_id,
                &application_config.chain_descriptor_hash_v0(),
            ],
        );
        let expected_finalization_profile = lab_genesis_hash_v0(
            LAB_FINALIZATION_CHECKPOINT_PROFILE_DOMAIN_V0,
            &[b"committed-finalization"],
        );
        let expected_timeout_rebase_profile = lab_genesis_hash_v0(
            LAB_TIMEOUT_REBASE_CHECKPOINT_PROFILE_DOMAIN_V0,
            &[
                b"committed-application-anchor",
                b"retained-selected-high-qc-path",
            ],
        );
        let checkpoint_matches_committed = fields.application_block_id == finalized.block_id()
            && fields.application_height == finalized.height().get()
            && fields.application_state_root.as_bytes() == committed.state_root().as_bytes()
            && fields.application_view == finalized.view().get()
            && fields.application_timestamp_ms == finalized.timestamp_ms()
            && fields.application_host_config_ref == expected_committed_application_owner
            && fields.application_committed_head_row_checksum == expected_committed_row_checksum;
        let prepared_checkpoint_matches = self
            .pending_executions
            .values()
            .filter(|retained| {
                terminal_checkpoint_matches_retained_v0(
                    fields,
                    retained,
                    &proposal_validation_store,
                )
            })
            .count();
        let checkpoint_application = match (
            checkpoint_matches_committed,
            fields.application_projection_profile_ref,
            prepared_checkpoint_matches,
        ) {
            (true, profile, 0) if profile == expected_finalization_profile => {
                PocoNodeLabTerminalCheckpointApplicationV0::CommittedFinalization
            }
            (true, profile, 0) if profile == expected_timeout_rebase_profile => {
                PocoNodeLabTerminalCheckpointApplicationV0::CommittedTimeoutRebase
            }
            (false, _, 1) => PocoNodeLabTerminalCheckpointApplicationV0::PreparedProposalValidation,
            _ => {
                return Err(PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
                    "terminal checkpoint application record is absent, ambiguous, or has the wrong transition profile",
                ));
            }
        };

        let checkpoint_canonical_sha256 = Sha256::digest(self.checkpoint.encode_canonical()).into();
        let facts = PocoNodeLabTerminalCutV0 {
            checkpoint: self.checkpoint,
            checkpoint_canonical_sha256,
            checkpoint_application,
            current_view: safety_facts.state_v0().current_view(),
            high_qc: safety_facts.state_v0().high_qc().qc_ref(),
            finalized_block_id: finalized.block_id(),
            finalized_height: finalized.height().get(),
            finalized_view: finalized.view(),
            finalized_timestamp_ms: finalized.timestamp_ms(),
            finalized_chain_root,
            submitted_height,
            application_state_root: *committed.state_root().as_bytes(),
            application_commit_id: *committed.commit_id().as_bytes(),
            application_store_id,
            application_durable_sequence,
            application_committed_head_row_checksum: expected_committed_row_checksum,
            safety_journal_id: safety_facts.journal_id_v0(),
            safety_revision: safety_facts.revision_v0(),
            safety_state_record_checksum: safety_facts.state_record_checksum_v0(),
            safety_record_chain_checksum: safety_facts.chain_checksum_v0(),
            signer_journal_id: signer_facts.journal_id(),
            signer_profile_checksum: signer_facts.profile_checksum(),
            signer_exact_watermark: signer_facts.exact_watermark(),
            signer_intent_count: signer_facts.capacity().intent_count(),
            signer_event_count: signer_facts.capacity().event_count(),
            signer_durable_vote_intent_count: signer_inventory.durable_vote_intent_count(),
            signer_durable_timeout_intent_count: signer_inventory.durable_timeout_intent_count(),
            signer_signed_vote_intent_count: signer_inventory.signed_vote_intent_count(),
            signer_signed_timeout_intent_count: signer_inventory.signed_timeout_intent_count(),
            signer_inventory_digest: signer_inventory.inventory_digest(),
            proposal_validation_scope: *proposal_validation_store.scope_v0().as_bytes(),
            proposal_validation_store_id: proposal_validation_store.store_id_v0(),
            proposal_validation_owner_id: *proposal_validation_owner_id.as_bytes(),
            proposal_validation_durable_sequence,
            proposal_validation_terminal_row_count,
            prepared_application_record_count,
        };

        let Self {
            core,
            seal_authority,
            finalization_authority,
            safety_store,
            application,
            signer_journal,
            checkpoint_store,
            checkpoint: _,
            application_head: _,
            application_overlay: _,
            pending_executions: _,
            proposal_journal: _,
        } = self;
        drop(seal_authority);
        drop(finalization_authority);
        Ok(PocoNodeLabTerminalOwnerV0 {
            _core: core,
            _safety_store: safety_store,
            _application: application,
            _signer_journal: signer_journal,
            _checkpoint_store: checkpoint_store,
            _proposal_validation_store: proposal_validation_store,
            facts,
        })
    }

    pub(crate) fn consensus_context_for_epoch_observation_v0(
        &self,
    ) -> (
        &trnm_consensus_types::ValidatorSet,
        &trnm_consensus_types::ConsensusParametersV0,
    ) {
        (
            self.core.config().validator_set(),
            self.core.config().consensus_parameters(),
        )
    }

    /// Comparison-only commissioning hook for the external continuous owner.
    /// It exposes no Core/store/signing authority and prevents the network
    /// layer from reconstructing a consensus context from checkpoint scalars.
    pub fn matches_consensus_context_v0(
        &self,
        local_validator: trnm_consensus_types::ValidatorId,
        validator_set: &trnm_consensus_types::ValidatorSet,
        consensus_parameters: &trnm_consensus_types::ConsensusParametersV0,
    ) -> bool {
        self.core.config().local_validator() == local_validator
            && self.core.config().validator_set() == validator_set
            && self.core.config().consensus_parameters() == consensus_parameters
    }

    pub(crate) fn fresh_checkpoint_for_epoch_observation_v0(
        &mut self,
    ) -> Result<ExternalNodeCheckpointV0, PocoNodeLabAuthorityErrorV0> {
        let fresh = self
            .checkpoint_store
            .load(self.checkpoint.scope())
            .map_err(PocoNodeLabAuthorityErrorV0::Checkpoint)?
            .ok_or(PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
                "whole-node checkpoint disappeared during epoch observation",
            ))?;
        if fresh != self.checkpoint {
            return Err(PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
                "fresh whole-node checkpoint differs during epoch observation",
            ));
        }
        Ok(fresh)
    }

    /// Strictly decodes and compares one untrusted checkpoint without
    /// consuming or mutating the live runtime.
    pub fn verify_external_checkpoint_bytes_exact_v0(
        &self,
        encoded: &[u8],
    ) -> Result<ExternalNodeCheckpointV0, PocoNodeLabCheckpointComparisonErrorV0> {
        verify_checkpoint_bytes_exact_v0(self.checkpoint, encoded)
    }

    /// Creates the first plain-genesis laboratory cut and commits whole-node
    /// checkpoint generation zero before returning any signing-capable owner.
    ///
    /// The signer journal is initialized operationally by its storage crate,
    /// immediately consumed into the pinned form, joined to Core/Safety/App
    /// and the independent checkpoint, and activated only after a fresh CAS
    /// readback.  No state-sync anchor or authenticated-genesis parent is
    /// admitted by this path.
    pub fn initialize_fresh_ordinary_genesis_v0(
        config: PocoNodeLabFreshOrdinaryGenesisConfigV0<W>,
    ) -> Result<Self, PocoNodeLabAuthorityErrorV0> {
        let PocoNodeLabFreshOrdinaryGenesisConfigV0 {
            core_config,
            genesis_qc,
            safety_store_path,
            safety_record_limits,
            safety_maximum_database_bytes,
            application,
            expected_chain_descriptor_hash,
            expected_signer_policy_commitment,
            expected_initial_commit_id,
            signer_journal_path,
            signer_maximum_intents,
            signer_maximum_intent_bytes,
            signer_maximum_database_bytes,
            external_watermark,
            mut checkpoint_store,
            proposal_journal,
        } = config;
        if core_config
            .authenticated_genesis_application_parent_v0()
            .is_some()
        {
            return Err(PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
                "fresh ordinary runtime acquired an authenticated-genesis parent",
            ));
        }
        let core = Core::new(core_config.clone(), genesis_qc, &StrictEd25519Verifier)
            .map_err(PocoNodeLabAuthorityErrorV0::Core)?;
        if core.safety_state().state_sync_anchor().is_some() {
            return Err(PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
                "fresh ordinary runtime acquired a state-sync anchor",
            ));
        }
        let safety_profile = trnm_consensus_safety_store::SafetyStateStoreProfileV0::new(
            core_config.clone(),
            crate::STRICT_ED25519_VERIFIER_PROFILE_REF_V0,
            safety_record_limits,
            safety_maximum_database_bytes,
        )
        .map_err(PocoNodeLabAuthorityErrorV0::Safety)?;
        let mut safety_store = SqliteSafetyStateStoreV0::initialize_new(
            safety_store_path,
            safety_profile,
            StrictEd25519Verifier,
            core.safety_state(),
        )
        .map_err(PocoNodeLabAuthorityErrorV0::Safety)?;
        safety_store
            .bind_core_v0(core.safety_state_persistence_binding_v0())
            .map_err(PocoNodeLabAuthorityErrorV0::Safety)?;
        let app_config = application.config_v0();
        if app_config.chain_id_v0() != core_config.validator_set().chain_id().as_str()
            || app_config.genesis_hash_v0()
                != *core_config.validator_set().genesis_hash().as_bytes()
            || app_config.validator_set_v0() != core_config.validator_set()
            || app_config.consensus_parameters_v0() != core_config.consensus_parameters()
            || app_config.initial_block_id_v0() != *core_config.genesis_block_id().as_bytes()
            || app_config.chain_descriptor_hash_v0() != expected_chain_descriptor_hash
            || app_config.signer_policy_commitment_v0() != expected_signer_policy_commitment
            || app_config.initial_commit_id_v0() != expected_initial_commit_id
        {
            return Err(PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
                "native application genesis trust inputs differ from plain Core",
            ));
        }
        let genesis_request = NativeApplicationGenesisRequestV0::new(
            ChainIdV0::new(app_config.chain_id_v0())
                .map_err(|error| PocoNodeLabAuthorityErrorV0::AuthorityChain(error.to_string()))?,
            GenesisHashV0::new(app_config.genesis_hash_v0())
                .map_err(|error| PocoNodeLabAuthorityErrorV0::AuthorityChain(error.to_string()))?,
            Hash32V0::new(app_config.chain_descriptor_hash_v0()),
            Hash32V0::new(app_config.signer_policy_commitment_v0()),
            StateRootV0::new(app_config.initial_state_root())
                .map_err(|error| PocoNodeLabAuthorityErrorV0::AuthorityChain(error.to_string()))?,
            app_config.initial_validator_set().clone(),
        )
        .map_err(|error| PocoNodeLabAuthorityErrorV0::AuthorityChain(error.to_string()))?;
        application
            .initialize(genesis_request)
            .map_err(|error| PocoNodeLabAuthorityErrorV0::AuthorityChain(error.to_string()))?;
        let application_head = application
            .confirmed_committed_head_v0()
            .map_err(|error| PocoNodeLabAuthorityErrorV0::AuthorityChain(error.to_string()))?;
        let genesis_tip = core.safety_state().application_applied();
        if application_head.height().get() != 0
            || application_head.block_id().as_bytes() != genesis_tip.block_id().as_bytes()
            || application_head.state_root().as_bytes() != &app_config.initial_state_root()
            || application_head.commit_id().as_bytes() != &expected_initial_commit_id
        {
            return Err(PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
                "native application genesis head differs from Core genesis cut",
            ));
        }
        let signer_profile = trnm_consensus_signer_journal::SignerJournalProfileV0::new(
            core_config.validator_set().clone(),
            core_config.local_validator(),
            crate::SIGNER_JOURNAL_PROFILE_REF_V0,
            crate::derive_signer_watermark_scope_v0(&core_config),
            signer_maximum_intents,
            signer_maximum_intent_bytes,
            signer_maximum_database_bytes,
        )
        .map_err(PocoNodeLabAuthorityErrorV0::Signer)?;
        let signer_journal = SqliteSignerJournalV0::initialize_new(
            signer_journal_path,
            signer_profile,
            external_watermark,
        )
        .map_err(PocoNodeLabAuthorityErrorV0::Signer)?;
        let mut pinned_signer = signer_journal
            .into_pinned_v0()
            .map_err(PocoNodeLabAuthorityErrorV0::Signer)?;
        let safety = safety_store
            .confirm_node_checkpoint_head_exact_v0(core.safety_state())
            .map_err(PocoNodeLabAuthorityErrorV0::Safety)?;
        let signer = pinned_signer
            .confirm_node_checkpoint_head_exact_v0()
            .map_err(PocoNodeLabAuthorityErrorV0::Signer)?;
        let checkpoint = fresh_genesis_checkpoint_v0(
            &core_config,
            &safety,
            &application,
            &application_head,
            &signer,
        )?;
        compare_and_confirm_checkpoint_v0(&mut checkpoint_store, None, checkpoint)?;
        let signer_journal = pinned_signer
            .activate_v0()
            .map_err(|failure| PocoNodeLabAuthorityErrorV0::Signer(failure.into_error()))?;
        let seal_authority = core
            .issue_application_seal_authority_v0()
            .map_err(PocoNodeLabAuthorityErrorV0::Core)?;
        let finalization_authority = core
            .issue_application_finalization_apply_authority_v0()
            .map_err(PocoNodeLabAuthorityErrorV0::Core)?;
        Ok(Self {
            core,
            seal_authority,
            finalization_authority,
            safety_store,
            application,
            signer_journal,
            checkpoint_store,
            checkpoint,
            application_head,
            application_overlay: None,
            pending_executions: BTreeMap::new(),
            proposal_journal,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_native_h1_ordinary_runtime_parts_v0(
        parts: PocoNodeNativeH1OrdinaryRuntimePartsV0<W>,
        proposal_journal: PocoNodeLabProposalJournalConfigV0,
    ) -> Result<Self, PocoNodeLabAuthorityErrorV0> {
        let PocoNodeNativeH1OrdinaryRuntimePartsV0 {
            core,
            seal_authority,
            startup_effects,
            retired_source_safety_store,
            safety_store,
            application,
            mut validation_store,
            validation_owner,
            mut signer,
            mut checkpoint_store,
            checkpoint,
            h2,
            h3,
        } = parts;
        let safety = core.safety_state();
        if !matches!(
            startup_effects.as_slice(),
            [Effect::ArmViewTimer { epoch, view }]
                if *epoch == safety.epoch() && *view == safety.current_view()
        ) || safety.revision() != 5
            || safety.pending_sign().is_some()
            || safety.pending_finalize().is_some()
            || safety.pending_tc_high_qc_sync().is_some()
            || safety.pending_standalone_qc_sync().is_some()
            || !safety.finalization_queue().is_empty()
            || safety.finalized() != safety.application_applied()
        {
            return Err(PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
                "native h1 takeover is not one exact revision-five ready cut",
            ));
        }
        if h2.safety_revision_v0() != 2
            || h3.safety_revision_v0() != 4
            || h2.binding_v0().route() != ProposalRouteV0::Synced
            || h3.binding_v0().route() != ProposalRouteV0::Synced
            || h2.binding_v0().chain_id().as_str()
                != core.config().validator_set().chain_id().as_str()
            || h3.binding_v0().chain_id().as_str()
                != core.config().validator_set().chain_id().as_str()
            || h2.binding_v0().genesis_hash().as_bytes()
                != core.config().validator_set().genesis_hash().as_bytes()
            || h3.binding_v0().genesis_hash().as_bytes()
                != core.config().validator_set().genesis_hash().as_bytes()
            || h2.binding_v0().active_validator_set_id().as_bytes()
                != core.config().validator_set().id().as_bytes()
            || h3.binding_v0().active_validator_set_id().as_bytes()
                != core.config().validator_set().id().as_bytes()
            || h2.binding_v0().view() >= h3.binding_v0().view()
            || h2.binding_v0().height().checked_next().ok() != Some(h3.binding_v0().height())
            || h3.binding_v0().parent() != h2.application_head_v0()
        {
            return Err(PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
                "native h2/h3 takeover bindings are not one exact successor path",
            ));
        }

        let committed = application
            .confirmed_committed_head_v0()
            .map_err(|error| PocoNodeLabAuthorityErrorV0::AuthorityChain(error.to_string()))?;
        let applied = safety.application_applied();
        if committed.height().get() != applied.height().get()
            || committed.block_id().as_bytes() != applied.block_id().as_bytes()
            || h2.binding_v0().parent() != &committed
        {
            return Err(PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
                "native h2 retained path does not start at the committed applied h1",
            ));
        }

        let validation_sequence = validation_store
            .durable_sequence_v0()
            .map_err(|error| PocoNodeLabAuthorityErrorV0::AuthorityChain(error.to_string()))?;
        if validation_store.path() != proposal_journal.store_path.as_path()
            || validation_store.scope_v0() != proposal_journal.scope
            || validation_store.store_id_v0() == [0; 32]
            || validation_owner != proposal_journal.owner_id
            || validation_sequence != NATIVE_H1_ORDINARY_TAKEOVER_VALIDATION_SEQUENCE_V0
            || proposal_journal.minimum_durable_sequence != validation_sequence
        {
            return Err(PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
                "proposal journal config differs from the exact h2/h3 takeover owner",
            ));
        }
        let (h2_id, h2_retained, h2_row_checksum) =
            retained_native_takeover_execution_v0(&application, &mut validation_store, &h2)?;
        let (h3_id, h3_retained, h3_row_checksum) =
            retained_native_takeover_execution_v0(&application, &mut validation_store, &h3)?;
        if h2_id == h3_id || h2_row_checksum == h3_row_checksum {
            return Err(PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
                "native h2/h3 retained executions are not distinct",
            ));
        }

        let high_qc = safety.high_qc().qc_ref();
        if high_qc.block_id().as_bytes() != h3.binding_v0().block_id().as_bytes()
            || high_qc.height().get() != h3.binding_v0().height().get()
            || high_qc.view().get() != h3.binding_v0().view()
            || safety.current_view().get().checked_sub(1) != Some(high_qc.view().get())
        {
            return Err(PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
                "revision-five Core high QC differs from retained h3",
            ));
        }

        let safety_facts = safety_store
            .confirm_node_checkpoint_head_exact_v0(safety)
            .map_err(PocoNodeLabAuthorityErrorV0::Safety)?;
        let signer_facts = signer
            .confirm_node_checkpoint_head_exact_v0()
            .map_err(PocoNodeLabAuthorityErrorV0::Signer)?;
        let observed_checkpoint = checkpoint_store
            .load(checkpoint.scope())
            .map_err(PocoNodeLabAuthorityErrorV0::Checkpoint)?;
        let fields = checkpoint.fields();
        if !safety_facts.belongs_to_store_at_path_v0(&safety_store, safety_store.path())
            || !signer_facts.belongs_to_operational_journal_at_path_v0(&signer, signer.path())
            || signer_facts.pending_intent().is_some()
            || signer_facts.capacity().intent_count() != 0
            || signer_facts.capacity().event_count() != 0
            || observed_checkpoint != Some(checkpoint)
            || fields.scope != signer_facts.exact_watermark().scope()
            || fields.safety_journal_id != safety_facts.journal_id_v0()
            || fields.safety_verifier_profile_ref != safety_facts.verifier_profile_ref_v0()
            || fields.safety_revision != safety_facts.revision_v0()
            || fields.safety_state_record_checksum != safety_facts.state_record_checksum_v0()
            || fields.safety_record_chain_checksum != safety_facts.chain_checksum_v0()
            || fields.signer_journal_id != signer_facts.journal_id()
            || fields.signer_profile_checksum != signer_facts.profile_checksum()
            || fields.signer_exact_watermark != signer_facts.exact_watermark()
            || fields.application_block_id.as_bytes() != h3.binding_v0().block_id().as_bytes()
            || fields.application_height != h3.binding_v0().height().get()
            || fields.application_state_root.as_bytes()
                != h3.binding_v0().commitments().post_state_root().as_bytes()
            || fields.application_view != h3.binding_v0().view()
            || fields.application_timestamp_ms != h3.binding_v0().timestamp_ms()
            || fields.application_committed_head_row_checksum != h3_row_checksum
        {
            return Err(PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
                "whole-node checkpoint differs from the exact takeover Safety/App/signer cut",
            ));
        }

        let application_head = h3_retained.speculative_head.clone();
        let application_overlay = Some(h3_retained.overlay_ref);
        let mut pending_executions = BTreeMap::new();
        if pending_executions.insert(h2_id, h2_retained).is_some()
            || pending_executions.insert(h3_id, h3_retained).is_some()
        {
            return Err(PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
                "native takeover retained one duplicate execution block",
            ));
        }
        drop(validation_store);
        drop(retired_source_safety_store);
        drop(startup_effects);

        let finalization_authority = core
            .issue_application_finalization_apply_authority_v0()
            .map_err(PocoNodeLabAuthorityErrorV0::Core)?;
        if !seal_authority.matches_application_finalization_authority_v0(&finalization_authority) {
            return Err(PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
                "native takeover application authorities differ from the live Core",
            ));
        }
        let runtime = Self {
            core,
            seal_authority,
            finalization_authority,
            safety_store,
            application,
            signer_journal: signer,
            checkpoint_store,
            checkpoint,
            application_head,
            application_overlay,
            pending_executions,
            proposal_journal,
        };
        runtime.proposal_binding_v0()?;
        Ok(runtime)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn from_recovered_positive_checkpoint_v0(
        core: Core,
        mut safety_store: SqliteSafetyStateStoreV0<StrictEd25519Verifier>,
        application: DurableNativeApplicationV0,
        mut signer_journal: SqliteSignerJournalV0<W>,
        mut checkpoint_store: SqliteExternalNodeCheckpointStoreV0,
        proposal_journal: PocoNodeLabProposalJournalConfigV0,
    ) -> Result<Self, PocoNodeLabAuthorityErrorV0> {
        let safety = core.safety_state();
        let finalized = safety.finalized();
        let applied = safety.application_applied();
        if finalized.height().get() == 0
            || finalized != applied
            || safety.pending_sign().is_some()
            || safety.pending_finalize().is_some()
            || safety.high_qc().qc_ref().block_id() != finalized.block_id()
        {
            return Err(PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
                "runtime requires a positive, fully applied finalized tip with no pending sign/finalization and highQC at that tip",
            ));
        }

        let application_head = application
            .confirmed_committed_head_v0()
            .map_err(|error| PocoNodeLabAuthorityErrorV0::AuthorityChain(error.to_string()))?;
        if application_head.height().get() != applied.height().get()
            || application_head.block_id().as_bytes() != applied.block_id().as_bytes()
        {
            return Err(PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
                "durable application head differs from Core application_applied",
            ));
        }

        let safety_facts = safety_store
            .confirm_node_checkpoint_head_exact_v0(safety)
            .map_err(PocoNodeLabAuthorityErrorV0::Safety)?;
        let signer_facts = signer_journal
            .confirm_node_checkpoint_head_exact_v0()
            .map_err(PocoNodeLabAuthorityErrorV0::Signer)?;
        let checkpoint = checkpoint_store
            .load(signer_facts.exact_watermark().scope())
            .map_err(PocoNodeLabAuthorityErrorV0::Checkpoint)?
            .ok_or(PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
                "whole-node checkpoint is absent",
            ))?;
        let fields = checkpoint.fields();
        if fields.safety_journal_id != safety_facts.journal_id_v0()
            || fields.safety_verifier_profile_ref != safety_facts.verifier_profile_ref_v0()
            || fields.safety_revision != safety_facts.revision_v0()
            || fields.safety_state_record_checksum != safety_facts.state_record_checksum_v0()
            || fields.safety_record_chain_checksum != safety_facts.chain_checksum_v0()
            || fields.application_block_id.as_bytes() != application_head.block_id().as_bytes()
            || fields.application_height != application_head.height().get()
            || fields.application_state_root.as_bytes() != application_head.state_root().as_bytes()
            || fields.application_view != applied.view().get()
            || fields.application_timestamp_ms != applied.timestamp_ms()
            || fields.signer_journal_id != signer_facts.journal_id()
            || fields.signer_profile_checksum != signer_facts.profile_checksum()
            || fields.signer_exact_watermark != signer_facts.exact_watermark()
        {
            return Err(PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
                "whole-node checkpoint differs from the exact Core/Safety/App/signer cut",
            ));
        }

        let seal_authority = core
            .issue_application_seal_authority_v0()
            .map_err(PocoNodeLabAuthorityErrorV0::Core)?;
        let finalization_authority = core
            .issue_application_finalization_apply_authority_v0()
            .map_err(PocoNodeLabAuthorityErrorV0::Core)?;
        safety_store
            .bind_core_v0(core.safety_state_persistence_binding_v0())
            .map_err(PocoNodeLabAuthorityErrorV0::Safety)?;

        Ok(Self {
            core,
            seal_authority,
            finalization_authority,
            safety_store,
            application,
            signer_journal,
            checkpoint_store,
            checkpoint,
            application_head,
            application_overlay: None,
            pending_executions: BTreeMap::new(),
            proposal_journal,
        })
    }

    /// Returns the exact application parent and authenticated parent timestamp
    /// selected by this runtime.
    ///
    /// A speculative head must still have its retained durable execution and
    /// exact overlay. A committed head must match both a fresh application
    /// readback and Core's applied watermark. Any detached/substituted head is
    /// rejected instead of being converted into proposal input.
    pub fn proposal_parent_v0(
        &self,
    ) -> Result<PocoNodeLabProposalParentV0, PocoNodeLabAuthorityErrorV0> {
        let mut retained_match = None;
        for retained in self.pending_executions.values() {
            if retained.speculative_head == self.application_head {
                if retained_match.is_some()
                    || self.application_overlay != Some(retained.overlay_ref)
                {
                    return Err(PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
                        "speculative application parent is ambiguous or detached from its overlay",
                    ));
                }
                retained_match = Some(retained.executed.request().timestamp_ms());
            }
        }
        if let Some(authenticated_parent_timestamp_ms) = retained_match {
            return Ok(PocoNodeLabProposalParentV0 {
                application_head: self.application_head.clone(),
                authenticated_parent_timestamp_ms,
            });
        }
        if self.application_overlay.is_some() {
            return Err(PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
                "speculative application parent lacks its retained execution",
            ));
        }
        let committed = self
            .application
            .confirmed_committed_head_v0()
            .map_err(|error| PocoNodeLabAuthorityErrorV0::AuthorityChain(error.to_string()))?;
        let applied = self.core.safety_state().application_applied();
        if committed != self.application_head
            || committed.height().get() != applied.height().get()
            || committed.block_id().as_bytes() != applied.block_id().as_bytes()
        {
            return Err(PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
                "committed application parent differs from Core application_applied",
            ));
        }
        Ok(PocoNodeLabProposalParentV0 {
            application_head: committed,
            authenticated_parent_timestamp_ms: applied.timestamp_ms(),
        })
    }

    /// Returns the exact post-certificate proposal binding selected by Core
    /// and the native application. The high QC and native parent must name the
    /// same block/height before any network-layer proposal can be bound.
    pub fn proposal_binding_v0(
        &self,
    ) -> Result<PocoNodeLabProposalBindingV0, PocoNodeLabAuthorityErrorV0> {
        if self.core.safety_state().pending_tc_high_qc_sync().is_some()
            || self
                .core
                .safety_state()
                .pending_standalone_qc_sync()
                .is_some()
            || self.core.safety_state().pending_sign().is_some()
            || self.core.safety_state().pending_finalization().is_some()
        {
            return Err(PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
                "proposal binding requires a certificate-complete ready Core",
            ));
        }
        let parent = self.proposal_parent_v0()?;
        let high_qc = self.core.safety_state().high_qc().clone();
        let high = high_qc.qc_ref();
        if parent.application_head_v0().block_id().as_bytes() != high.block_id().as_bytes()
            || parent.application_head_v0().height().get() != high.height().get()
            || self.core.safety_state().current_view() <= high.view()
        {
            return Err(PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
                "authoritative high QC differs from the native proposal parent",
            ));
        }
        Ok(PocoNodeLabProposalBindingV0 {
            current_view: self.core.safety_state().current_view(),
            high_qc,
            parent,
        })
    }

    /// Builds and executes one exact non-empty successor preview from the
    /// runtime-selected parent. The returned parent must also be used to bind
    /// the network proposal's authenticated parent timestamp.
    pub fn preview_next_nonempty_v0(
        &self,
        transactions: Vec<Vec<u8>>,
        timestamp_ms: u64,
    ) -> Result<(PocoNodeLabProposalParentV0, NativeBlockPreviewV0), PocoNodeLabAuthorityErrorV0>
    {
        let parent = self.proposal_parent_v0()?;
        if transactions.is_empty() || timestamp_ms <= parent.authenticated_parent_timestamp_ms_v0()
        {
            return Err(PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
                "next preview must be non-empty and strictly newer than its authenticated parent",
            ));
        }
        let config = self.application.config_v0();
        let target_height = parent
            .application_head_v0()
            .height()
            .checked_next()
            .map_err(|error| PocoNodeLabAuthorityErrorV0::AuthorityChain(error.to_string()))?;
        let request = NativeBlockPreviewRequestV0::new(
            ChainIdV0::new(config.chain_id_v0())
                .map_err(|error| PocoNodeLabAuthorityErrorV0::AuthorityChain(error.to_string()))?,
            GenesisHashV0::new(config.genesis_hash_v0())
                .map_err(|error| PocoNodeLabAuthorityErrorV0::AuthorityChain(error.to_string()))?,
            parent.application_head_v0().clone(),
            HeightV0::new(target_height.get()),
            timestamp_ms,
            ValidatorSetIdV0::new(*self.core.config().validator_set().id().as_bytes())
                .map_err(|error| PocoNodeLabAuthorityErrorV0::AuthorityChain(error.to_string()))?,
            transactions,
        )
        .map_err(|error| PocoNodeLabAuthorityErrorV0::AuthorityChain(error.to_string()))?;
        let preview = self.preview_block_v0(&request)?;
        Ok((parent, preview))
    }

    /// Persists Core's exact local-timeout authorization and advances the
    /// whole-node checkpoint before exposing an inert signing owner.
    pub fn begin_local_timeout_v0(
        mut self,
    ) -> Result<PocoNodeLabInertTimeoutOwnerV0<W>, PocoNodeLabAuthorityErrorV0> {
        let source_checkpoint = self.checkpoint;
        let timeout_view = self.core.safety_state().current_view();
        let timeout_epoch = self.core.config().validator_set().epoch();
        let expected_high_qc = self.core.safety_state().high_qc().qc_ref();
        let safety_before =
            confirm_live_or_signature_released_safety_head_v0(&self.core, &self.safety_store)?;
        let signer_before = self
            .signer_journal
            .confirm_node_checkpoint_head_exact_v0()
            .map_err(PocoNodeLabAuthorityErrorV0::Signer)?;
        require_checkpoint_heads_v0(source_checkpoint, &safety_before, &signer_before)?;
        let effects = self
            .core
            .step(
                Input::LocalTimeout {
                    epoch: timeout_epoch,
                    view: timeout_view,
                },
                &StrictEd25519Verifier,
            )
            .map_err(PocoNodeLabAuthorityErrorV0::Core)?;
        let [Effect::PersistSafetyState(request)] = effects.as_slice() else {
            return Err(PocoNodeLabAuthorityErrorV0::UnexpectedEffect(
                "LocalTimeout did not yield exactly one Safety persistence",
            ));
        };
        match self
            .safety_store
            .persist_exact_v0(request, &SafetyTransitionContextV0::ordinary())
            .map_err(PocoNodeLabAuthorityErrorV0::Safety)?
        {
            SafetyPersistDispositionV0::Inserted
            | SafetyPersistDispositionV0::Existing
            | SafetyPersistDispositionV0::ConfirmedAfterCommitError => {}
        }
        let safety_after = self
            .safety_store
            .confirm_node_checkpoint_head_exact_v0(self.core.safety_state())
            .map_err(PocoNodeLabAuthorityErrorV0::Safety)?;
        let signer_after = self
            .signer_journal
            .confirm_node_checkpoint_head_exact_v0()
            .map_err(PocoNodeLabAuthorityErrorV0::Signer)?;
        if signer_after.journal_id() != signer_before.journal_id()
            || signer_after.profile_checksum() != signer_before.profile_checksum()
            || signer_after.identity() != signer_before.identity()
            || signer_after.exact_watermark() != signer_before.exact_watermark()
            || signer_after.capacity() != signer_before.capacity()
            || signer_after.tail() != signer_before.tail()
            || signer_after.pending_intent() != signer_before.pending_intent()
        {
            return Err(PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
                "signer journal changed while persisting a local timeout",
            ));
        }
        let timeout_checkpoint =
            safety_checkpoint_successor_v0(source_checkpoint, &safety_after, &signer_after)?;
        compare_and_confirm_checkpoint_v0(
            &mut self.checkpoint_store,
            Some(source_checkpoint),
            timeout_checkpoint,
        )?;
        let released = self
            .core
            .step(
                Input::StorageAck {
                    barrier: request.barrier(),
                },
                &StrictEd25519Verifier,
            )
            .map_err(PocoNodeLabAuthorityErrorV0::Core)?;
        let [Effect::RequestSignature { intent }] = released.as_slice() else {
            return Err(PocoNodeLabAuthorityErrorV0::UnexpectedEffect(
                "timeout StorageAck did not release exactly one signing request",
            ));
        };
        intent
            .validate(self.core.config().validator_set())
            .map_err(|error| PocoNodeLabAuthorityErrorV0::AuthorityChain(error.to_string()))?;
        let CanonicalSignPreimageV0::TimeoutVote(preimage) = intent.preimage() else {
            return Err(PocoNodeLabAuthorityErrorV0::UnexpectedEffect(
                "timeout persistence released a non-timeout intent",
            ));
        };
        if preimage.view() != timeout_view
            || preimage.high_qc() != expected_high_qc
            || intent.authorizing_safety_revision() != self.core.safety_state().revision()
            || self.core.safety_state().pending_sign().is_none()
        {
            return Err(PocoNodeLabAuthorityErrorV0::UnexpectedEffect(
                "timeout intent differs from the durable Core authorization",
            ));
        }
        let facts = PocoNodeLabInertTimeoutFactsV0 {
            view: timeout_view,
            high_qc: expected_high_qc,
            authorizing_safety_revision: intent.authorizing_safety_revision(),
            signing_root: *intent.signing_root().as_bytes(),
            checkpoint: timeout_checkpoint,
            signer_exact_watermark: signer_after.exact_watermark(),
        };
        Ok(PocoNodeLabInertTimeoutOwnerV0 {
            core: self.core,
            seal_authority: self.seal_authority,
            finalization_authority: self.finalization_authority,
            safety_store: self.safety_store,
            application: self.application,
            signer_journal: self.signer_journal,
            checkpoint_store: self.checkpoint_store,
            application_head: self.application_head,
            application_overlay: self.application_overlay,
            pending_executions: self.pending_executions,
            proposal_journal: self.proposal_journal,
            intent: intent.clone(),
            facts,
        })
    }

    /// Applies one strict ordinary QC from the Ready phase. The certificate
    /// need not contain, or even share coordinates with, a locally released
    /// Vote; Core is the sole certificate/safety authority.
    pub fn advance_quorum_certificate_v0(
        self,
        certificate: QuorumCertificate,
    ) -> Result<PocoNodeLabCertificateAdvanceV0<W>, PocoNodeLabAuthorityErrorV0> {
        self.advance_certificate_v0(Input::QuorumCertificate(certificate))
    }

    /// Applies one strict TC from the Ready phase and rebases the native
    /// speculative parent to Core's exact selected high QC before returning.
    pub fn advance_timeout_certificate_v0(
        self,
        certificate: TimeoutCertificateV0,
    ) -> Result<PocoNodeLabCertificateAdvanceV0<W>, PocoNodeLabAuthorityErrorV0> {
        self.advance_certificate_v0(Input::TimeoutCertificate(certificate))
    }

    fn advance_certificate_v0(
        mut self,
        input: Input,
    ) -> Result<PocoNodeLabCertificateAdvanceV0<W>, PocoNodeLabAuthorityErrorV0> {
        let source_checkpoint = self.checkpoint;
        let before = self.core.safety_state().clone();
        let is_timeout_certificate = matches!(&input, Input::TimeoutCertificate(_));
        if is_timeout_certificate {
            let committed = self
                .application
                .confirmed_committed_head_v0()
                .map_err(|error| PocoNodeLabAuthorityErrorV0::AuthorityChain(error.to_string()))?;
            let _ = require_fresh_checkpoint_application_join_v0(
                &self.application,
                &committed,
                source_checkpoint,
                &self.proposal_journal,
                &self.application_head,
                &self.pending_executions,
                None,
            )?;
        }
        let effects = self
            .core
            .step(input, &StrictEd25519Verifier)
            .map_err(PocoNodeLabAuthorityErrorV0::Core)?;
        if effects.is_empty() {
            if self.core.safety_state() != &before {
                return Err(PocoNodeLabAuthorityErrorV0::UnexpectedEffect(
                    "certificate changed Core without a persistence effect",
                ));
            }
            return self.finish_certificate_advance_v0(source_checkpoint, None);
        }
        let [Effect::PersistSafetyState(request)] = effects.as_slice() else {
            return Err(PocoNodeLabAuthorityErrorV0::UnexpectedEffect(
                "certificate did not yield exactly one Safety persistence effect",
            ));
        };
        if is_timeout_certificate {
            preflight_authoritative_high_qc_retained_path_v0(
                &self.core,
                &self.application,
                &self.proposal_journal,
                &self.pending_executions,
            )?;
        }
        match self
            .safety_store
            .persist_exact_v0(request, &SafetyTransitionContextV0::ordinary())
            .map_err(PocoNodeLabAuthorityErrorV0::Safety)?
        {
            SafetyPersistDispositionV0::Inserted
            | SafetyPersistDispositionV0::Existing
            | SafetyPersistDispositionV0::ConfirmedAfterCommitError => {}
        }
        let safety = self
            .safety_store
            .confirm_node_checkpoint_head_exact_v0(self.core.safety_state())
            .map_err(PocoNodeLabAuthorityErrorV0::Safety)?;
        let signer = self
            .signer_journal
            .confirm_node_checkpoint_head_exact_v0()
            .map_err(PocoNodeLabAuthorityErrorV0::Signer)?;
        let target_checkpoint = if is_timeout_certificate {
            timeout_rebase_checkpoint_successor_v0(
                source_checkpoint,
                &safety,
                &signer,
                &self.application,
            )?
        } else {
            safety_checkpoint_successor_v0(source_checkpoint, &safety, &signer)?
        };
        compare_and_confirm_checkpoint_v0(
            &mut self.checkpoint_store,
            Some(source_checkpoint),
            target_checkpoint,
        )?;
        let released = self
            .core
            .step(
                Input::StorageAck {
                    barrier: request.barrier(),
                },
                &StrictEd25519Verifier,
            )
            .map_err(PocoNodeLabAuthorityErrorV0::Core)?;
        let mut finalization = None;
        for effect in released {
            match effect {
                Effect::ArmViewTimer { .. } => {}
                Effect::Finalize(candidate) if finalization.is_none() => {
                    finalization = Some(*candidate);
                }
                _ => {
                    return Err(PocoNodeLabAuthorityErrorV0::UnexpectedEffect(
                        "certificate released an unsupported laboratory effect",
                    ));
                }
            }
        }
        self.finish_certificate_advance_v0(target_checkpoint, finalization)
    }

    fn finish_certificate_advance_v0(
        mut self,
        checkpoint: ExternalNodeCheckpointV0,
        finalization: Option<DurableFinalizationV0>,
    ) -> Result<PocoNodeLabCertificateAdvanceV0<W>, PocoNodeLabAuthorityErrorV0> {
        rebase_to_authoritative_high_qc_v0(
            &self.core,
            &self.application,
            checkpoint,
            &self.proposal_journal,
            &mut self.application_head,
            &mut self.application_overlay,
            &mut self.pending_executions,
        )?;
        if let Some(finalization) = finalization {
            if self.core.safety_state().pending_finalization() != Some(&finalization) {
                return Err(PocoNodeLabAuthorityErrorV0::UnexpectedEffect(
                    "released finalization differs from the durable queue front",
                ));
            }
            return Ok(PocoNodeLabCertificateAdvanceV0::PendingFinalization(
                Box::new(PocoNodeLabPendingFinalizationOwnerV0 {
                    finalization,
                    core: self.core,
                    seal_authority: self.seal_authority,
                    finalization_authority: self.finalization_authority,
                    safety_store: self.safety_store,
                    application: self.application,
                    signer_journal: self.signer_journal,
                    checkpoint_store: self.checkpoint_store,
                    checkpoint,
                    application_head: self.application_head,
                    application_overlay: self.application_overlay,
                    pending_executions: self.pending_executions,
                    proposal_journal: self.proposal_journal,
                }),
            ));
        }
        Ok(PocoNodeLabCertificateAdvanceV0::Ready(Box::new(Self {
            core: self.core,
            seal_authority: self.seal_authority,
            finalization_authority: self.finalization_authority,
            safety_store: self.safety_store,
            application: self.application,
            signer_journal: self.signer_journal,
            checkpoint_store: self.checkpoint_store,
            checkpoint,
            application_head: self.application_head,
            application_overlay: self.application_overlay,
            pending_executions: self.pending_executions,
            proposal_journal: self.proposal_journal,
        })))
    }

    /// Computes the four frozen-v0 application commitments for one exact
    /// non-empty candidate body without mutating any application sequence.
    ///
    /// The preview is inert proposal-construction input. Admission later
    /// recomputes the complete transition from the same pinned parent and
    /// rejects any header whose roots were substituted or synthesized.
    pub fn preview_block_v0(
        &self,
        request: &NativeBlockPreviewRequestV0,
    ) -> Result<NativeBlockPreviewV0, PocoNodeLabAuthorityErrorV0> {
        let config = self.application.config_v0();
        if request.transactions().is_empty()
            || request.chain_id().as_str() != config.chain_id_v0()
            || request.genesis_hash().as_bytes() != &config.genesis_hash_v0()
            || request.active_validator_set_id().as_bytes()
                != self.core.config().validator_set().id().as_bytes()
        {
            return Err(PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
                "native preview context differs from the live ordinary runtime",
            ));
        }
        self.application
            .preview_block_v0(request)
            .map_err(|error| PocoNodeLabAuthorityErrorV0::AuthorityChain(error.to_string()))
    }

    /// Drives exactly one ordinary, non-empty, finalized-parent Proposal to a
    /// private inert signing request.  The method consumes the runtime so no
    /// failed or partially advanced owner can be accidentally reused.
    pub fn drive_one_to_inert_request_v0(
        mut self,
        proposal: SignedProposalV0,
    ) -> Result<PocoNodeLabInertRequestOwnerV0<W>, PocoNodeLabAuthorityErrorV0> {
        let run_started = Instant::now();
        let block_id = proposal.block().id();
        let view = proposal.block().header().view();
        let initial_safety_revision = self.core.safety_state().revision();
        let initial_checkpoint = self.checkpoint;
        let mut stage_elapsed_ns = [0u64; 9];
        let mut stage_safety_revisions = [initial_safety_revision; 9];
        let mut stage_checkpoint_generations = [initial_checkpoint.generation(); 9];
        let mut stage_checkpoint_checksums = [initial_checkpoint.checkpoint_checksum(); 9];
        let mut mark_stage = |index: usize| {
            stage_elapsed_ns[index] = elapsed_ns_v0(run_started);
        };
        mark_stage(0);
        let obligation_effects = self
            .core
            .step(Input::Proposal(Box::new(proposal)), &StrictEd25519Verifier)
            .map_err(PocoNodeLabAuthorityErrorV0::Core)?;
        mark_stage(1);
        let [Effect::PersistSafetyState(obligation)] = obligation_effects.as_slice() else {
            return Err(PocoNodeLabAuthorityErrorV0::UnexpectedEffect(
                "Proposal did not yield exactly one Safety obligation persistence",
            ));
        };
        match self
            .safety_store
            .persist_exact_v0(obligation, &SafetyTransitionContextV0::ordinary())
            .map_err(PocoNodeLabAuthorityErrorV0::Safety)?
        {
            SafetyPersistDispositionV0::Inserted
            | SafetyPersistDispositionV0::Existing
            | SafetyPersistDispositionV0::ConfirmedAfterCommitError => {}
        }
        let obligation_revision = obligation.state().revision();
        stage_safety_revisions[2..5].fill(obligation_revision);
        mark_stage(2);
        let validation_effects = self
            .core
            .step(
                Input::StorageAck {
                    barrier: obligation.barrier(),
                },
                &StrictEd25519Verifier,
            )
            .map_err(PocoNodeLabAuthorityErrorV0::Core)?;
        let request = exact_proposal_validation_effect_v0(
            validation_effects.into_iter().map(|effect| match effect {
                Effect::ValidatePayload(request) => {
                    PocoNodeLabProposalStorageAckEffectV0::ValidatePayload(request)
                }
                Effect::ArmViewTimer { epoch, view } => {
                    PocoNodeLabProposalStorageAckEffectV0::ArmViewTimer { epoch, view }
                }
                _ => PocoNodeLabProposalStorageAckEffectV0::Unsupported,
            }),
            self.core.safety_state().epoch(),
            self.core.safety_state().current_view(),
        )?;
        let claimed: ClaimedPayloadValidationRequestV0 = request.try_claim().map_err(|_| {
            PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
                "Core-issued validation request was already claimed",
            )
        })?;

        let mut host = PocoNodeNativeProposalPHostV0::open_for_lab_v0(
            self.application,
            PocoNodeNativeProposalPHostConfigV0 {
                store_path: self.proposal_journal.store_path.clone(),
                scope: self.proposal_journal.scope,
                minimum_durable_sequence: self.proposal_journal.minimum_durable_sequence,
                owner_id: self.proposal_journal.owner_id,
                authenticated_application_head: self.application_head.clone(),
                authenticated_application_overlay: self.application_overlay,
                consensus_parameters: *self.core.config().consensus_parameters(),
                validator_set: self.core.config().validator_set().clone(),
            },
        )
        .map_err(authority_chain_error_v0)?;
        let p = host
            .execute_and_persist_p_v0(claimed)
            .map_err(authority_chain_error_v0)?;
        mark_stage(3);
        let accepted_d = match host
            .seal_valid_and_deliver_core_d_v0(
                p,
                &mut self.core,
                &self.seal_authority,
                &StrictEd25519Verifier,
            )
            .map_err(authority_chain_error_v0)?
        {
            PocoNodeNativeCoreDOutcomeV0::Applied(value) => *value,
            PocoNodeNativeCoreDOutcomeV0::NotApplied(pending) => {
                match host
                    .retry_core_d_v0(*pending)
                    .map_err(authority_chain_error_v0)?
                {
                    PocoNodeNativeCoreDOutcomeV0::Applied(value) => *value,
                    PocoNodeNativeCoreDOutcomeV0::NotApplied(_) => {
                        return Err(PocoNodeLabAuthorityErrorV0::PersistenceNotApplied("Core-D"));
                    }
                }
            }
        };
        let native_valid_revision = accepted_d.core_accepted_v0().completion_revision_v0();
        mark_stage(4);
        let safety_path = self.safety_store.path().to_path_buf();
        let acked_k = match host
            .persist_safety_c_and_ack_k_observed_v0(
                accepted_d,
                &mut self.safety_store,
                &safety_path,
                || {
                    stage_safety_revisions[5..].fill(native_valid_revision);
                    mark_stage(5);
                },
            )
            .map_err(authority_chain_error_v0)?
        {
            PocoNodeNativeKOutcomeV0::Applied(value) => *value,
            PocoNodeNativeKOutcomeV0::NotApplied(pending) => match host
                .retry_ack_k_v0(*pending, &self.safety_store, &safety_path)
                .map_err(authority_chain_error_v0)?
            {
                PocoNodeNativeKOutcomeV0::Applied(value) => *value,
                PocoNodeNativeKOutcomeV0::NotApplied(_) => {
                    return Err(PocoNodeLabAuthorityErrorV0::PersistenceNotApplied("K"));
                }
            },
        };
        mark_stage(6);
        let signer_path = self.signer_journal.path().to_path_buf();
        let checkpointed = match host
            .checkpoint_k_whole_node_v0(
                acked_k,
                &mut self.checkpoint_store,
                self.checkpoint,
                &self.safety_store,
                &safety_path,
                &mut self.signer_journal,
                &signer_path,
            )
            .map_err(authority_chain_error_v0)?
        {
            PocoNodeNativeWholeNodeCheckpointOutcomeV0::Applied(value) => *value,
            PocoNodeNativeWholeNodeCheckpointOutcomeV0::NotApplied(acked) => match host
                .checkpoint_k_whole_node_v0(
                    *acked,
                    &mut self.checkpoint_store,
                    self.checkpoint,
                    &self.safety_store,
                    &safety_path,
                    &mut self.signer_journal,
                    &signer_path,
                )
                .map_err(authority_chain_error_v0)?
            {
                PocoNodeNativeWholeNodeCheckpointOutcomeV0::Applied(value) => *value,
                PocoNodeNativeWholeNodeCheckpointOutcomeV0::NotApplied(_) => {
                    return Err(PocoNodeLabAuthorityErrorV0::PersistenceNotApplied(
                        "whole-node checkpoint",
                    ));
                }
            },
        };
        let final_checkpoint = *checkpointed.checkpoint_v0();
        stage_checkpoint_generations[7..].fill(final_checkpoint.generation());
        stage_checkpoint_checksums[7..].fill(final_checkpoint.checkpoint_checksum());
        mark_stage(7);
        let inert = host
            .release_inert_request_signature_v0(
                checkpointed,
                &mut self.core,
                &StrictEd25519Verifier,
            )
            .map_err(authority_chain_error_v0)?;
        mark_stage(8);
        let safety_facts = self
            .safety_store
            .confirm_node_checkpoint_head_exact_v0(self.core.safety_state())
            .map_err(PocoNodeLabAuthorityErrorV0::Safety)?;
        let signer_facts = self
            .signer_journal
            .confirm_node_checkpoint_head_exact_v0()
            .map_err(PocoNodeLabAuthorityErrorV0::Signer)?;
        let facts = inert_facts_v0(
            &inert,
            block_id,
            view,
            self.core.safety_state().revision(),
            safety_facts.state_record_checksum_v0(),
            safety_facts.chain_checksum_v0(),
            signer_facts.exact_watermark(),
            stage_elapsed_ns,
            stage_safety_revisions,
            stage_checkpoint_generations,
            stage_checkpoint_checksums,
        )?;
        Ok(PocoNodeLabInertRequestOwnerV0 {
            host,
            inert,
            core: self.core,
            seal_authority: self.seal_authority,
            finalization_authority: self.finalization_authority,
            safety_store: self.safety_store,
            signer_journal: self.signer_journal,
            checkpoint_store: self.checkpoint_store,
            application_head: self.application_head,
            pending_executions: self.pending_executions,
            proposal_journal: self.proposal_journal,
            facts,
        })
    }
}

/// Read-only facts exposed by the terminal laboratory owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PocoNodeLabInertRequestFactsV0 {
    block_id: BlockId,
    view: View,
    height: u64,
    authorizing_safety_revision: u64,
    signing_root: [u8; 32],
    checkpoint: ExternalNodeCheckpointV0,
    application_store_sequence: u64,
    application_row_checksum: [u8; 32],
    safety_record_checksum: [u8; 32],
    safety_chain_checksum: [u8; 32],
    signer_exact_watermark: trnm_consensus_signer_journal::SignerWatermarkV0,
    stage_elapsed_ns: [u64; 9],
    stage_safety_revisions: [u64; 9],
    stage_checkpoint_generations: [u64; 9],
    stage_checkpoint_checksums: [[u8; 32]; 9],
}

impl PocoNodeLabInertRequestFactsV0 {
    pub const fn block_id(&self) -> BlockId {
        self.block_id
    }

    pub const fn view(&self) -> View {
        self.view
    }

    pub const fn height(&self) -> u64 {
        self.height
    }

    pub const fn authorizing_safety_revision(&self) -> u64 {
        self.authorizing_safety_revision
    }

    pub const fn signing_root(&self) -> [u8; 32] {
        self.signing_root
    }

    pub const fn checkpoint(&self) -> ExternalNodeCheckpointV0 {
        self.checkpoint
    }

    pub const fn application_store_sequence(&self) -> u64 {
        self.application_store_sequence
    }

    pub const fn application_row_checksum(&self) -> [u8; 32] {
        self.application_row_checksum
    }

    pub const fn safety_record_checksum(&self) -> [u8; 32] {
        self.safety_record_checksum
    }

    pub const fn safety_chain_checksum(&self) -> [u8; 32] {
        self.safety_chain_checksum
    }

    pub const fn signer_exact_watermark(&self) -> trnm_consensus_signer_journal::SignerWatermarkV0 {
        self.signer_exact_watermark
    }

    /// Cumulative local monotonic measurements for the fixed nine-stage
    /// one-shot profile. They are never consensus timestamps or ordering
    /// authority.
    pub const fn stage_elapsed_ns(&self) -> [u64; 9] {
        self.stage_elapsed_ns
    }

    pub const fn stage_safety_revisions(&self) -> [u64; 9] {
        self.stage_safety_revisions
    }

    pub const fn stage_checkpoint_generations(&self) -> [u64; 9] {
        self.stage_checkpoint_generations
    }

    pub const fn stage_checkpoint_checksums(&self) -> [[u8; 32]; 9] {
        self.stage_checkpoint_checksums
    }
}

/// Linear owner of one checkpoint-authorized but still inert Vote request.
/// Signing can occur only through [`SignatureProducerV0`] after every durable
/// head and the independent checkpoint have been freshly revalidated.
pub struct PocoNodeLabInertRequestOwnerV0<W: ExternalMonotonicWatermarkV0> {
    host: PocoNodeNativeProposalPHostV0<DurableNativeApplicationV0>,
    inert: PocoNodeNativeInertRequestSignatureV0,
    core: Core,
    seal_authority: CoreIssuedApplicationSealAuthorityV0,
    finalization_authority: CoreIssuedApplicationFinalizationApplyAuthorityV0,
    safety_store: SqliteSafetyStateStoreV0<StrictEd25519Verifier>,
    signer_journal: SqliteSignerJournalV0<W>,
    checkpoint_store: SqliteExternalNodeCheckpointStoreV0,
    #[allow(dead_code)]
    application_head: ApplicationHeadV0,
    pending_executions: BTreeMap<BlockId, PocoNodeLabRetainedExecutionV0>,
    proposal_journal: PocoNodeLabProposalJournalConfigV0,
    facts: PocoNodeLabInertRequestFactsV0,
}

impl<W: ExternalMonotonicWatermarkV0> PocoNodeLabInertRequestOwnerV0<W> {
    pub const fn facts_v0(&self) -> &PocoNodeLabInertRequestFactsV0 {
        &self.facts
    }

    /// Inert BlockId-keyed application overlay produced by the exact durable
    /// P. It may be used only to preview a child body; it grants no finality,
    /// validation, Safety, or signing authority.
    pub fn next_application_parent_v0(
        &self,
    ) -> Result<ApplicationHeadV0, PocoNodeLabAuthorityErrorV0> {
        self.inert
            .overlay_parent_head_v0()
            .map_err(|error| PocoNodeLabAuthorityErrorV0::AuthorityChain(error.to_string()))
    }

    /// Journals and verifies the exact Vote signature, advances a second
    /// whole-node checkpoint which commits the new signer watermark, freshly
    /// rechecks Safety, and only then feeds `SignatureReady` to Core.
    ///
    /// The producer receives the signer journal's bounded
    /// `SignatureRequestV0`; neither the raw Core nor any storage/key owner is
    /// exposed. Success returns a non-forgeable outbound carrier joined to the
    /// retained node owner.
    pub fn sign_exact_vote_v0<P: SignatureProducerV0>(
        mut self,
        producer: &mut P,
    ) -> Result<PocoNodeLabSignedVoteOwnerV0<W>, PocoNodeLabAuthorityErrorV0> {
        let next_application_parent = self
            .inert
            .overlay_parent_head_v0()
            .map_err(|error| PocoNodeLabAuthorityErrorV0::AuthorityChain(error.to_string()))?;
        let next_application_overlay = self.inert.overlay_ref_v0();
        let retained = PocoNodeLabRetainedExecutionV0 {
            binding: self.inert.binding_v0().clone(),
            executed: self.inert.executed_for_finalization_v0(),
            view: self.facts.view,
            source_artifact_checksum: self.inert.source_artifact_checksum_v0(),
            validation_row_checksum: self.inert.application_row_checksum_v0(),
            overlay_ref: next_application_overlay,
            speculative_head: next_application_parent.clone(),
        };
        if self
            .pending_executions
            .insert(self.facts.block_id, retained)
            .is_some()
        {
            return Err(PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
                "one block acquired more than one retained execution artifact",
            ));
        }
        let source_checkpoint = self.facts.checkpoint;
        if *self.inert.checkpoint_v0() != source_checkpoint
            || self
                .checkpoint_store
                .load(source_checkpoint.scope())
                .map_err(PocoNodeLabAuthorityErrorV0::Checkpoint)?
                != Some(source_checkpoint)
        {
            return Err(PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
                "inert Vote checkpoint is not the exact external head",
            ));
        }
        let safety_before = self
            .safety_store
            .confirm_node_checkpoint_head_exact_v0(self.core.safety_state())
            .map_err(PocoNodeLabAuthorityErrorV0::Safety)?;
        let signer_before = self
            .signer_journal
            .confirm_node_checkpoint_head_exact_v0()
            .map_err(PocoNodeLabAuthorityErrorV0::Signer)?;
        require_checkpoint_heads_v0(source_checkpoint, &safety_before, &signer_before)?;

        let intent = self.inert.intent_v0().clone();
        intent
            .validate(self.core.config().validator_set())
            .map_err(|error| PocoNodeLabAuthorityErrorV0::AuthorityChain(error.to_string()))?;
        let CanonicalSignPreimageV0::Vote(preimage) = intent.preimage() else {
            return Err(PocoNodeLabAuthorityErrorV0::UnexpectedEffect(
                "inert signing request is not a Vote",
            ));
        };
        if preimage.block_id() != self.facts.block_id
            || preimage.view() != self.facts.view
            || preimage.height().get() != self.facts.height
            || intent.authorizing_safety_revision() != self.facts.authorizing_safety_revision
            || intent.signing_root().as_bytes() != &self.facts.signing_root
        {
            return Err(PocoNodeLabAuthorityErrorV0::UnexpectedEffect(
                "inert Vote intent differs from its retained authority facts",
            ));
        }

        let signature = self
            .signer_journal
            .sign_exact_v0(&intent, producer)
            .map_err(PocoNodeLabAuthorityErrorV0::Signer)?;
        let signer_after = self
            .signer_journal
            .confirm_node_checkpoint_head_exact_v0()
            .map_err(PocoNodeLabAuthorityErrorV0::Signer)?;
        let expected_sequence = signer_before
            .exact_watermark()
            .sequence()
            .checked_add(2)
            .ok_or(PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
                "signer watermark sequence exhausted",
            ))?;
        if signer_after.journal_id() != signer_before.journal_id()
            || signer_after.profile_checksum() != signer_before.profile_checksum()
            || signer_after.exact_watermark().scope() != signer_before.exact_watermark().scope()
            || signer_after.exact_watermark().journal_id()
                != signer_before.exact_watermark().journal_id()
            || signer_after.exact_watermark().sequence() != expected_sequence
            || signer_after.pending_intent().is_some()
            || signer_after.capacity().intent_count()
                != signer_before
                    .capacity()
                    .intent_count()
                    .checked_add(1)
                    .ok_or(PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
                        "signer intent accounting exhausted",
                    ))?
            || signer_after.capacity().event_count()
                != signer_before
                    .capacity()
                    .event_count()
                    .checked_add(2)
                    .ok_or(PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
                        "signer event accounting exhausted",
                    ))?
        {
            return Err(PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
                "signer journal did not advance by one exact prepared/signed pair",
            ));
        }

        // The signer must not be able to mutate or substitute Safety. Confirm
        // the still-pending Core authorization immediately before the external
        // checkpoint and SignatureReady transition.
        let safety_after_sign = self
            .safety_store
            .confirm_node_checkpoint_head_exact_v0(self.core.safety_state())
            .map_err(PocoNodeLabAuthorityErrorV0::Safety)?;
        if safety_after_sign.journal_id_v0() != safety_before.journal_id_v0()
            || safety_after_sign.revision_v0() != safety_before.revision_v0()
            || safety_after_sign.state_record_checksum_v0()
                != safety_before.state_record_checksum_v0()
            || safety_after_sign.chain_checksum_v0() != safety_before.chain_checksum_v0()
        {
            return Err(PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
                "Safety head changed while producing a Vote signature",
            ));
        }

        let signed_checkpoint =
            signer_checkpoint_successor_v0(source_checkpoint, &safety_after_sign, &signer_after)?;
        compare_and_confirm_checkpoint_v0(
            &mut self.checkpoint_store,
            Some(source_checkpoint),
            signed_checkpoint,
        )?;
        let effects = self
            .core
            .step(
                Input::SignatureReady {
                    id: SignId::new(intent.signing_root()),
                    signature,
                },
                &StrictEd25519Verifier,
            )
            .map_err(PocoNodeLabAuthorityErrorV0::Core)?;
        let [Effect::Broadcast(OutboundMessage::Vote(vote))] = effects.as_slice() else {
            return Err(PocoNodeLabAuthorityErrorV0::UnexpectedEffect(
                "Vote SignatureReady did not release exactly one Vote broadcast",
            ));
        };
        vote.verify(self.core.config().validator_set(), &StrictEd25519Verifier)
            .map_err(|error| PocoNodeLabAuthorityErrorV0::AuthorityChain(error.to_string()))?;
        if vote.block_id() != preimage.block_id()
            || vote.view() != preimage.view()
            || vote.height() != preimage.height()
            || vote.author() != intent.author()
            || vote.signature() != &signature
            || vote.signing_root() != intent.signing_root()
            || self.core.safety_state().pending_sign().is_some()
            || self.core.safety_state().revision() != intent.authorizing_safety_revision()
        {
            return Err(PocoNodeLabAuthorityErrorV0::UnexpectedEffect(
                "released Vote differs from the journaled canonical intent",
            ));
        }
        let facts = PocoNodeLabSignedVoteFactsV0 {
            block_id: vote.block_id(),
            view: vote.view(),
            height: vote.height().get(),
            signing_root: *vote.signing_root().as_bytes(),
            checkpoint: signed_checkpoint,
            signer_exact_watermark: signer_after.exact_watermark(),
        };
        Ok(PocoNodeLabSignedVoteOwnerV0 {
            host: self.host,
            core: self.core,
            seal_authority: self.seal_authority,
            finalization_authority: self.finalization_authority,
            safety_store: self.safety_store,
            signer_journal: self.signer_journal,
            checkpoint_store: self.checkpoint_store,
            application_head: next_application_parent,
            application_overlay: next_application_overlay,
            pending_executions: self.pending_executions,
            proposal_journal: self.proposal_journal,
            outbound: PocoNodeLabSignedVoteOutboundV0 { vote: vote.clone() },
            facts,
        })
    }
}

impl<W: ExternalMonotonicWatermarkV0> fmt::Debug for PocoNodeLabInertRequestOwnerV0<W> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PocoNodeLabInertRequestOwnerV0")
            .field("facts", &self.facts)
            .finish_non_exhaustive()
    }
}

/// Scalar readback of one released, journal-authenticated Vote.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PocoNodeLabSignedVoteFactsV0 {
    block_id: BlockId,
    view: View,
    height: u64,
    signing_root: [u8; 32],
    checkpoint: ExternalNodeCheckpointV0,
    signer_exact_watermark: trnm_consensus_signer_journal::SignerWatermarkV0,
}

impl PocoNodeLabSignedVoteFactsV0 {
    pub const fn block_id(&self) -> BlockId {
        self.block_id
    }

    pub const fn view(&self) -> View {
        self.view
    }

    pub const fn height(&self) -> u64 {
        self.height
    }

    pub const fn signing_root(&self) -> [u8; 32] {
        self.signing_root
    }

    pub const fn checkpoint(&self) -> ExternalNodeCheckpointV0 {
        self.checkpoint
    }

    pub const fn signer_exact_watermark(&self) -> trnm_consensus_signer_journal::SignerWatermarkV0 {
        self.signer_exact_watermark
    }
}

/// Non-forgeable carrier for the sole Vote released from Core.
///
/// The constructor and field are private. Callers may borrow the fully
/// verified wire value for transport, but cannot mint this proof-of-origin
/// wrapper from an arbitrary signature.
pub struct PocoNodeLabSignedVoteOutboundV0 {
    vote: Vote,
}

impl PocoNodeLabSignedVoteOutboundV0 {
    pub const fn vote_v0(&self) -> &Vote {
        &self.vote
    }
}

impl fmt::Debug for PocoNodeLabSignedVoteOutboundV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PocoNodeLabSignedVoteOutboundV0")
            .field("block_id", &self.vote.block_id())
            .field("view", &self.vote.view())
            .field("author", &self.vote.author())
            .finish_non_exhaustive()
    }
}

/// Live owner after exact journal signing and Core `SignatureReady`.
///
/// Storage owners and Core remain private. The only externally visible wire
/// value is the joined outbound carrier above.
pub struct PocoNodeLabSignedVoteOwnerV0<W: ExternalMonotonicWatermarkV0> {
    #[allow(dead_code)]
    host: PocoNodeNativeProposalPHostV0<DurableNativeApplicationV0>,
    #[allow(dead_code)]
    core: Core,
    seal_authority: CoreIssuedApplicationSealAuthorityV0,
    finalization_authority: CoreIssuedApplicationFinalizationApplyAuthorityV0,
    #[allow(dead_code)]
    safety_store: SqliteSafetyStateStoreV0<StrictEd25519Verifier>,
    #[allow(dead_code)]
    signer_journal: SqliteSignerJournalV0<W>,
    #[allow(dead_code)]
    checkpoint_store: SqliteExternalNodeCheckpointStoreV0,
    #[allow(dead_code)]
    application_head: ApplicationHeadV0,
    application_overlay: trnm_consensus_core::BlockIdOverlayRefV0,
    pending_executions: BTreeMap<BlockId, PocoNodeLabRetainedExecutionV0>,
    #[allow(dead_code)]
    proposal_journal: PocoNodeLabProposalJournalConfigV0,
    outbound: PocoNodeLabSignedVoteOutboundV0,
    facts: PocoNodeLabSignedVoteFactsV0,
}

impl<W: ExternalMonotonicWatermarkV0> PocoNodeLabSignedVoteOwnerV0<W> {
    pub const fn facts_v0(&self) -> &PocoNodeLabSignedVoteFactsV0 {
        &self.facts
    }

    pub fn phase_facts_v0(&self) -> PocoNodeLabPhaseFactsV0 {
        phase_facts_from_parts_v0(
            PocoNodeLabAuthorityPhaseV0::VoteSigned,
            &self.core,
            self.facts.checkpoint,
            &self.application_head,
        )
    }

    pub const fn outbound_v0(&self) -> &PocoNodeLabSignedVoteOutboundV0 {
        &self.outbound
    }

    pub fn reconfirm_phase_neutral_exact_high_qc_v0(
        &mut self,
        certificate: &QuorumCertificate,
    ) -> Result<PocoNodeLabPhaseFactsV0, PocoNodeLabAuthorityErrorV0> {
        let (application, validation_store) = self.host.application_and_validation_store_v0();
        reconfirm_phase_neutral_exact_high_qc_v0(
            certificate,
            &self.core,
            &self.safety_store,
            application,
            &mut self.signer_journal,
            &mut self.checkpoint_store,
            self.facts.checkpoint,
            &self.application_head,
            &self.pending_executions,
            &self.proposal_journal,
            Some(validation_store),
        )?;
        Ok(self.phase_facts_v0())
    }

    /// Advances the exact live Core with one fully verified ordinary QC. The
    /// QC is not required to include the locally released Vote.
    pub fn advance_quorum_certificate_v0(
        self,
        certificate: QuorumCertificate,
    ) -> Result<PocoNodeLabCertificateAdvanceV0<W>, PocoNodeLabAuthorityErrorV0> {
        self.into_ready_v0()?
            .advance_quorum_certificate_v0(certificate)
    }

    /// Advances the exact live Core with one fully verified TC. This does not
    /// sign a timeout vote and does not make TC a finality certificate.
    pub fn advance_timeout_certificate_v0(
        self,
        certificate: TimeoutCertificateV0,
    ) -> Result<PocoNodeLabCertificateAdvanceV0<W>, PocoNodeLabAuthorityErrorV0> {
        self.into_ready_v0()?
            .advance_timeout_certificate_v0(certificate)
    }

    /// A locally released Vote does not suppress the same-view pacemaker
    /// timeout. The completed proposal host is first reduced back to its sole
    /// application owner, then the shared Ready timeout chain is used.
    pub fn begin_local_timeout_v0(
        self,
    ) -> Result<PocoNodeLabInertTimeoutOwnerV0<W>, PocoNodeLabAuthorityErrorV0> {
        self.into_ready_v0()?.begin_local_timeout_v0()
    }

    fn into_ready_v0(
        self,
    ) -> Result<PocoNodeLabOrdinaryProposalRuntimeV0<W>, PocoNodeLabAuthorityErrorV0> {
        let application = self
            .host
            .into_application_after_inert_v0()
            .map_err(authority_chain_error_v0)?;
        Ok(PocoNodeLabOrdinaryProposalRuntimeV0 {
            core: self.core,
            seal_authority: self.seal_authority,
            finalization_authority: self.finalization_authority,
            safety_store: self.safety_store,
            application,
            signer_journal: self.signer_journal,
            checkpoint_store: self.checkpoint_store,
            checkpoint: self.facts.checkpoint,
            application_head: self.application_head,
            application_overlay: Some(self.application_overlay),
            pending_executions: self.pending_executions,
            proposal_journal: self.proposal_journal,
        })
    }
}

/// Result of applying one authenticated certificate to the laboratory Core.
pub enum PocoNodeLabCertificateAdvanceV0<W: ExternalMonotonicWatermarkV0> {
    Ready(Box<PocoNodeLabOrdinaryProposalRuntimeV0<W>>),
    PendingFinalization(Box<PocoNodeLabPendingFinalizationOwnerV0<W>>),
}

impl<W: ExternalMonotonicWatermarkV0> fmt::Debug for PocoNodeLabCertificateAdvanceV0<W> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ready(runtime) => formatter.debug_tuple("Ready").field(runtime).finish(),
            Self::PendingFinalization(owner) => formatter
                .debug_tuple("PendingFinalization")
                .field(owner)
                .finish(),
        }
    }
}

/// Linear owner of one exact Core finalization queue front.
pub struct PocoNodeLabPendingFinalizationOwnerV0<W: ExternalMonotonicWatermarkV0> {
    finalization: DurableFinalizationV0,
    core: Core,
    seal_authority: CoreIssuedApplicationSealAuthorityV0,
    finalization_authority: CoreIssuedApplicationFinalizationApplyAuthorityV0,
    safety_store: SqliteSafetyStateStoreV0<StrictEd25519Verifier>,
    application: DurableNativeApplicationV0,
    signer_journal: SqliteSignerJournalV0<W>,
    checkpoint_store: SqliteExternalNodeCheckpointStoreV0,
    checkpoint: ExternalNodeCheckpointV0,
    application_head: ApplicationHeadV0,
    application_overlay: Option<trnm_consensus_core::BlockIdOverlayRefV0>,
    pending_executions: BTreeMap<BlockId, PocoNodeLabRetainedExecutionV0>,
    proposal_journal: PocoNodeLabProposalJournalConfigV0,
}

impl<W: ExternalMonotonicWatermarkV0> PocoNodeLabPendingFinalizationOwnerV0<W> {
    pub fn target_block_id_v0(&self) -> BlockId {
        self.finalization.proof().finalized_block().header().id()
    }

    pub fn target_height_v0(&self) -> u64 {
        self.finalization
            .proof()
            .finalized_block()
            .header()
            .height()
            .get()
    }

    pub const fn checkpoint_v0(&self) -> &ExternalNodeCheckpointV0 {
        &self.checkpoint
    }

    pub fn verify_external_checkpoint_bytes_exact_v0(
        &self,
        encoded: &[u8],
    ) -> Result<ExternalNodeCheckpointV0, PocoNodeLabCheckpointComparisonErrorV0> {
        verify_checkpoint_bytes_exact_v0(self.checkpoint, encoded)
    }

    /// Consumes the exact queue-front owner, commits the retained execution
    /// artifact in the native application, mints the Core receipt only from a
    /// fresh committed readback, persists the resulting tag-3 Safety state,
    /// and advances the independent checkpoint before releasing deferred
    /// effects.
    pub fn apply_and_ack_finalization_v0(
        mut self,
    ) -> Result<PocoNodeLabCertificateAdvanceV0<W>, PocoNodeLabAuthorityErrorV0> {
        if self.core.safety_state().pending_finalization() != Some(&self.finalization) {
            return Err(PocoNodeLabAuthorityErrorV0::UnexpectedEffect(
                "pending finalization differs from the durable Core queue front",
            ));
        }
        let target = self.finalization.proof().finalized_block().header();
        let retained = self.pending_executions.remove(&target.id()).ok_or(
            PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
                "finalization target has no retained execution artifact",
            ),
        )?;
        if retained.overlay_ref != self.finalization.target_overlay_ref()
            || retained.executed.request().block_id().as_bytes() != target.id().as_bytes()
            || retained.executed.request().parent().block_id().as_bytes()
                != self
                    .finalization
                    .authenticated_parent()
                    .block_id()
                    .as_bytes()
            || retained.executed.request().height().get() != target.height().get()
        {
            return Err(PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
                "retained execution differs from the finalization carrier",
            ));
        }
        let source = self
            .core
            .safety_state()
            .payload_validation_completions()
            .iter()
            .find(|completion| {
                completion.result().artifact_ref().is_some_and(|artifact| {
                    artifact.overlay() == retained.overlay_ref
                        && artifact.source_artifact_checksum() == retained.source_artifact_checksum
                })
            })
            .cloned()
            .ok_or(PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
                "finalization target has no exact durable Valid completion",
            ))?;
        let prior_head = self
            .application
            .confirmed_committed_head_v0()
            .map_err(|error| PocoNodeLabAuthorityErrorV0::AuthorityChain(error.to_string()))?;
        if prior_head.block_id().as_bytes()
            != self
                .finalization
                .authenticated_parent()
                .block_id()
                .as_bytes()
            || prior_head.height().get() != self.finalization.authenticated_parent().height().get()
        {
            return Err(PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
                "native committed head differs from the finalization parent",
            ));
        }
        let permit = self
            .core
            .issue_application_finalization_permit_v0()
            .map_err(PocoNodeLabAuthorityErrorV0::Core)?;
        if permit.finalization() != &self.finalization
            || !self
                .finalization_authority
                .matches_application_finalization_permit_v0(&permit)
        {
            return Err(PocoNodeLabAuthorityErrorV0::UnexpectedEffect(
                "Core finalization permit differs from the installed application authority",
            ));
        }
        let commit_request = NativeApplicationCommitRequestV0::new(retained.executed.clone());
        let commit = self
            .application
            .commit_block(commit_request)
            .map_err(|error| PocoNodeLabAuthorityErrorV0::AuthorityChain(error.to_string()))?;
        let new_head = self
            .application
            .confirmed_committed_head_v0()
            .map_err(|error| PocoNodeLabAuthorityErrorV0::AuthorityChain(error.to_string()))?;
        if new_head != *commit.head()
            || new_head != retained.speculative_head
            || new_head.block_id().as_bytes() != target.id().as_bytes()
            || new_head.height().get() != target.height().get()
            || new_head.state_root().as_bytes()
                != retained
                    .executed
                    .request()
                    .expected()
                    .post_state_root()
                    .as_bytes()
        {
            return Err(PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
                "fresh application readback differs from the committed finalization",
            ));
        }
        let config = self.application.config_v0();
        let application_host_config_ref = lab_genesis_hash_v0(
            b"trnm.poco-node.lab-finalization.application-owner.v0",
            &[
                config.chain_id_v0().as_bytes(),
                &config.genesis_hash_v0(),
                &config.store_id(),
                &config.chain_descriptor_hash_v0(),
            ],
        );
        let prior_head_checksum = application_head_checksum_v0(
            b"trnm.poco-node.lab-finalization.prior-head.v0",
            &prior_head,
        );
        let new_head_checksum =
            application_head_checksum_v0(b"trnm.poco-node.lab-finalization.new-head.v0", &new_head);
        let accepted_source_checksum = trnm_consensus_core::native_valid_result_checksum_v0(
            source.result(),
        )
        .ok_or(PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
            "durable finalization source is not one canonical Valid result",
        ))?;
        let durable_sequence = commit.durable_sequence().to_be_bytes();
        let applied_job_row_checksum = lab_genesis_hash_v0(
            b"trnm.poco-node.lab-finalization.applied-job.v0",
            &[
                target.id().as_bytes(),
                &durable_sequence,
                &retained.source_artifact_checksum,
                &retained.overlay_ref.overlay_checksum(),
                &new_head_checksum,
            ],
        );
        let receipt_row_checksum = lab_genesis_hash_v0(
            b"trnm.poco-node.lab-finalization.receipt.v0",
            &[
                source.id().block_id().as_bytes(),
                &source.id().view().get().to_be_bytes(),
                &source.id().generation().to_be_bytes(),
                &accepted_source_checksum,
                &applied_job_row_checksum,
                &prior_head_checksum,
                &new_head_checksum,
            ],
        );
        let readback = self
            .finalization_authority
            .application_store_apply_readback_v0(
                &permit,
                source.route(),
                source.id(),
                target.height().get(),
                application_host_config_ref,
                prior_head_checksum,
                new_head_checksum,
                retained.source_artifact_checksum,
                accepted_source_checksum,
                applied_job_row_checksum,
                receipt_row_checksum,
            )
            .map_err(PocoNodeLabAuthorityErrorV0::Core)?;
        let receipt = self
            .finalization_authority
            .receipt_after_application_store_apply_v0(permit, readback)
            .map_err(|rejection| PocoNodeLabAuthorityErrorV0::Core(rejection.into_parts().0))?;
        let persistence = self
            .core
            .step_application_finalization_receipt_v0(receipt, &StrictEd25519Verifier)
            .map_err(|rejection| PocoNodeLabAuthorityErrorV0::Core(rejection.into_parts().0))?;
        let [Effect::PersistSafetyState(request)] = persistence.as_slice() else {
            return Err(PocoNodeLabAuthorityErrorV0::UnexpectedEffect(
                "application receipt did not yield exactly one tag-3 Safety persistence",
            ));
        };
        let preflight = self
            .safety_store
            .preflight_bound_native_finalization_applied_persistence_v0(request)
            .map_err(PocoNodeLabAuthorityErrorV0::Safety)?;
        let context = preflight
            .transition_context_v0()
            .map_err(PocoNodeLabAuthorityErrorV0::Safety)?;
        match self
            .safety_store
            .persist_exact_v0(request, &context)
            .map_err(PocoNodeLabAuthorityErrorV0::Safety)?
        {
            SafetyPersistDispositionV0::Inserted
            | SafetyPersistDispositionV0::Existing
            | SafetyPersistDispositionV0::ConfirmedAfterCommitError => {}
        }
        let _confirmed_finalization = self
            .safety_store
            .confirmed_native_finalization_applied_head_exact_v0(request.state(), &context)
            .map_err(PocoNodeLabAuthorityErrorV0::Safety)?;
        let safety = self
            .safety_store
            .confirm_node_checkpoint_head_exact_v0(self.core.safety_state())
            .map_err(PocoNodeLabAuthorityErrorV0::Safety)?;
        let signer = self
            .signer_journal
            .confirm_node_checkpoint_head_exact_v0()
            .map_err(PocoNodeLabAuthorityErrorV0::Signer)?;
        let target_checkpoint = finalization_checkpoint_successor_v0(
            self.checkpoint,
            &safety,
            &signer,
            &new_head,
            target.view().get(),
            target.timestamp_ms(),
            application_host_config_ref,
            preflight.state_record_checksum_v0(),
            receipt_row_checksum,
        )?;
        compare_and_confirm_checkpoint_v0(
            &mut self.checkpoint_store,
            Some(self.checkpoint),
            target_checkpoint,
        )?;
        let released = self
            .core
            .step(
                Input::StorageAck {
                    barrier: request.barrier(),
                },
                &StrictEd25519Verifier,
            )
            .map_err(PocoNodeLabAuthorityErrorV0::Core)?;
        let mut next_finalization = None;
        for effect in released {
            match effect {
                Effect::ArmViewTimer { .. } => {}
                Effect::Finalize(candidate) if next_finalization.is_none() => {
                    next_finalization = Some(*candidate);
                }
                _ => {
                    return Err(PocoNodeLabAuthorityErrorV0::UnexpectedEffect(
                        "finalization acknowledgement released an unsupported laboratory effect",
                    ));
                }
            }
        }
        self.application_head = new_head;
        self.application_overlay = None;
        rebase_to_authoritative_high_qc_v0(
            &self.core,
            &self.application,
            target_checkpoint,
            &self.proposal_journal,
            &mut self.application_head,
            &mut self.application_overlay,
            &mut self.pending_executions,
        )?;
        if let Some(finalization) = next_finalization {
            if self.core.safety_state().pending_finalization() != Some(&finalization) {
                return Err(PocoNodeLabAuthorityErrorV0::UnexpectedEffect(
                    "next finalization differs from the durable queue front",
                ));
            }
            self.finalization = finalization;
            self.checkpoint = target_checkpoint;
            return Ok(PocoNodeLabCertificateAdvanceV0::PendingFinalization(
                Box::new(self),
            ));
        }
        Ok(PocoNodeLabCertificateAdvanceV0::Ready(Box::new(
            PocoNodeLabOrdinaryProposalRuntimeV0 {
                core: self.core,
                seal_authority: self.seal_authority,
                finalization_authority: self.finalization_authority,
                safety_store: self.safety_store,
                application: self.application,
                signer_journal: self.signer_journal,
                checkpoint_store: self.checkpoint_store,
                checkpoint: target_checkpoint,
                application_head: self.application_head,
                application_overlay: self.application_overlay,
                pending_executions: self.pending_executions,
                proposal_journal: self.proposal_journal,
            },
        )))
    }
}

impl<W: ExternalMonotonicWatermarkV0> fmt::Debug for PocoNodeLabPendingFinalizationOwnerV0<W> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PocoNodeLabPendingFinalizationOwnerV0")
            .field("target_block_id", &self.target_block_id_v0())
            .field("target_height", &self.target_height_v0())
            .field("checkpoint_generation", &self.checkpoint.generation())
            .finish_non_exhaustive()
    }
}

impl<W: ExternalMonotonicWatermarkV0> fmt::Debug for PocoNodeLabSignedVoteOwnerV0<W> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PocoNodeLabSignedVoteOwnerV0")
            .field("facts", &self.facts)
            .field("outbound", &self.outbound)
            .finish_non_exhaustive()
    }
}

#[allow(clippy::too_many_arguments)]
fn inert_facts_v0(
    inert: &PocoNodeNativeInertRequestSignatureV0,
    expected_block_id: BlockId,
    expected_view: View,
    expected_safety_revision: u64,
    safety_record_checksum: [u8; 32],
    safety_chain_checksum: [u8; 32],
    signer_exact_watermark: trnm_consensus_signer_journal::SignerWatermarkV0,
    stage_elapsed_ns: [u64; 9],
    stage_safety_revisions: [u64; 9],
    stage_checkpoint_generations: [u64; 9],
    stage_checkpoint_checksums: [[u8; 32]; 9],
) -> Result<PocoNodeLabInertRequestFactsV0, PocoNodeLabAuthorityErrorV0> {
    let CanonicalSignPreimageV0::Vote(vote) = inert.intent_v0().preimage() else {
        return Err(PocoNodeLabAuthorityErrorV0::UnexpectedEffect(
            "terminal inert request is not a Vote",
        ));
    };
    if vote.block_id() != expected_block_id
        || vote.view() != expected_view
        || inert.intent_v0().authorizing_safety_revision() != expected_safety_revision
    {
        return Err(PocoNodeLabAuthorityErrorV0::UnexpectedEffect(
            "terminal inert Vote differs from the admitted Proposal",
        ));
    }
    Ok(PocoNodeLabInertRequestFactsV0 {
        block_id: vote.block_id(),
        view: vote.view(),
        height: vote.height().get(),
        authorizing_safety_revision: inert.intent_v0().authorizing_safety_revision(),
        signing_root: *inert.intent_v0().signing_root().as_bytes(),
        checkpoint: *inert.checkpoint_v0(),
        application_store_sequence: inert.application_store_sequence_v0(),
        application_row_checksum: inert.application_row_checksum_v0(),
        safety_record_checksum,
        safety_chain_checksum,
        signer_exact_watermark,
        stage_elapsed_ns,
        stage_safety_revisions,
        stage_checkpoint_generations,
        stage_checkpoint_checksums,
    })
}

fn elapsed_ns_v0(start: Instant) -> u64 {
    u64::try_from(start.elapsed().as_nanos()).unwrap_or(u64::MAX)
}

fn reconfirm_terminal_retained_execution_v0(
    block_id: BlockId,
    retained: &PocoNodeLabRetainedExecutionV0,
    application: &DurableNativeApplicationV0,
    validation_store: &mut SqliteProposalValidationStoreV0,
    terminal_store_sequence: u64,
) -> Result<ProposalValidationOwnerIdV0, PocoNodeLabAuthorityErrorV0> {
    let binding = &retained.binding;
    if block_id.as_bytes() != binding.block_id().as_bytes()
        || retained.view.get() != binding.view()
        || retained.validation_row_checksum == [0; 32]
        || retained.executed.request().parent() != binding.parent()
        || retained.executed.request().block_id() != binding.block_id()
        || retained.executed.request().height() != binding.height()
        || retained.executed.request().timestamp_ms() != binding.timestamp_ms()
        || retained.executed.request().active_validator_set_id()
            != binding.active_validator_set_id()
        || retained.executed.request().expected() != binding.commitments()
    {
        return Err(PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
            "terminal retained execution differs from its exact validation binding",
        ));
    }
    let fact = validation_store
        .inspect_exact_v0(binding)
        .map_err(|error| PocoNodeLabAuthorityErrorV0::AuthorityChain(error.to_string()))?;
    let checkpoint_facts = validation_store
        .confirm_proposal_validation_checkpoint_facts_exact_v0(binding)
        .map_err(|error| PocoNodeLabAuthorityErrorV0::AuthorityChain(error.to_string()))?;
    if fact.validation_id() != binding.validation_id() || checkpoint_facts.binding_v0() != binding {
        return Err(PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
            "terminal K validation identity or binding differs from fresh readback",
        ));
    }
    if fact.stage() != DurableValidationStageV0::Acked || fact.outbox_present() {
        return Err(PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
            "terminal K row is not ACKed or retains an outbox",
        ));
    }
    if fact.store_sequence() != terminal_store_sequence
        || checkpoint_facts.store_sequence_v0() != terminal_store_sequence
    {
        return Err(PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
            "terminal K fresh facts differ from the proposal store terminal sequence",
        ));
    }
    if fact.row_revision() == 0
        || fact.row_revision() > terminal_store_sequence
        || checkpoint_facts.row_revision_v0() != fact.row_revision()
    {
        return Err(PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
            "terminal K row revision is zero, future, or differs across fresh readbacks",
        ));
    }
    if checkpoint_facts.row_checksum_v0().as_bytes() != &retained.validation_row_checksum {
        return Err(PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
            "terminal K row checksum differs from its retained execution",
        ));
    }
    if checkpoint_facts.scope_v0() != validation_store.scope_v0()
        || checkpoint_facts.store_id_v0() != validation_store.store_id_v0()
        || !checkpoint_facts.belongs_to_store_at_path_v0(validation_store, validation_store.path())
    {
        return Err(PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
            "terminal K fresh facts lost exact proposal-store owner affinity",
        ));
    }
    let executed = validation_store
        .read_artifact_exact_v0(binding)
        .map_err(|error| PocoNodeLabAuthorityErrorV0::AuthorityChain(error.to_string()))?;
    if executed != retained.executed {
        return Err(PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
            "terminal retained execution differs from fresh K artifact readback",
        ));
    }
    let confirmed = application
        .confirm_durable_p_v0(&executed)
        .map_err(|error| PocoNodeLabAuthorityErrorV0::AuthorityChain(error.to_string()))?;
    let speculative_head = confirmed
        .overlay_parent_head_v0()
        .map_err(|error| PocoNodeLabAuthorityErrorV0::AuthorityChain(error.to_string()))?;
    let overlay_ref = trnm_consensus_core::BlockIdOverlayRefV0::new(
        BlockId::new(confirmed.block_id_v0()),
        BlockId::new(confirmed.parent_block_id_v0()),
        confirmed.overlay_checksum_v0(),
    );
    if confirmed.source_artifact_checksum_v0() != retained.source_artifact_checksum
        || confirmed.store_id_v0() != application.config_v0().store_id()
        || speculative_head != retained.speculative_head
        || overlay_ref != retained.overlay_ref
    {
        return Err(PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
            "terminal retained K differs from fresh durable P or its application store identity",
        ));
    }
    Ok(checkpoint_facts.owner_id_v0())
}

fn terminal_checkpoint_matches_retained_v0(
    fields: &crate::ExternalNodeCheckpointFieldsV0,
    retained: &PocoNodeLabRetainedExecutionV0,
    validation_store: &SqliteProposalValidationStoreV0,
) -> bool {
    let validation_scope = validation_store.scope_v0();
    let validation_store_id = validation_store.store_id_v0();
    let binding_chain_id = retained.binding.chain_id();
    let binding_genesis_hash = retained.binding.genesis_hash();
    let owner_parts = [
        validation_scope.as_bytes().as_slice(),
        validation_store_id.as_slice(),
        binding_chain_id.as_str().as_bytes(),
        binding_genesis_hash.as_bytes().as_slice(),
    ];
    let takeover_owner = lab_genesis_hash_v0(
        NATIVE_H1_ORDINARY_TAKEOVER_CHECKPOINT_OWNER_DOMAIN_V0,
        &owner_parts,
    );
    let takeover_profile = lab_genesis_hash_v0(
        NATIVE_H1_ORDINARY_TAKEOVER_CHECKPOINT_PROFILE_DOMAIN_V0,
        &[
            b"proposal-validation-schema-3",
            b"anchored-synced-terminal-k",
        ],
    );
    let native_k_owner = lab_genesis_hash_v0(NATIVE_K_CHECKPOINT_OWNER_DOMAIN_V0, &owner_parts);
    let native_k_profile = lab_genesis_hash_v0(
        NATIVE_K_CHECKPOINT_PROFILE_DOMAIN_V0,
        &[b"proposal-validation-schema-3", b"terminal-k"],
    );
    let takeover_projection = fields.application_host_config_ref == takeover_owner
        && fields.application_projection_profile_ref == takeover_profile;
    let native_k_projection = fields.application_host_config_ref == native_k_owner
        && fields.application_projection_profile_ref == native_k_profile;
    terminal_checkpoint_projection_matches_retained_v0(fields, retained)
        && (takeover_projection ^ native_k_projection)
}

fn terminal_checkpoint_projection_matches_retained_v0(
    fields: &crate::ExternalNodeCheckpointFieldsV0,
    retained: &PocoNodeLabRetainedExecutionV0,
) -> bool {
    fields.application_block_id.as_bytes() == retained.binding.block_id().as_bytes()
        && fields.application_height == retained.binding.height().get()
        && fields.application_state_root.as_bytes()
            == retained.binding.commitments().post_state_root().as_bytes()
        && fields.application_view == retained.binding.view()
        && fields.application_timestamp_ms == retained.binding.timestamp_ms()
        && fields.application_committed_head_row_checksum == retained.validation_row_checksum
}

fn retained_native_takeover_execution_v0(
    application: &DurableNativeApplicationV0,
    validation_store: &mut SqliteProposalValidationStoreV0,
    completed: &PocoNodeNativeAnchoredSuccessorCompletedV0,
) -> Result<(BlockId, PocoNodeLabRetainedExecutionV0, [u8; 32]), PocoNodeLabAuthorityErrorV0> {
    let binding = completed.binding_v0();
    let fact = validation_store
        .inspect_exact_v0(binding)
        .map_err(|error| PocoNodeLabAuthorityErrorV0::AuthorityChain(error.to_string()))?;
    let checkpoint_facts = validation_store
        .confirm_proposal_validation_checkpoint_facts_exact_v0(binding)
        .map_err(|error| PocoNodeLabAuthorityErrorV0::AuthorityChain(error.to_string()))?;
    if fact.validation_id() != binding.validation_id() {
        return Err(PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
            "native takeover validation row id differs from its binding",
        ));
    }
    if fact.stage() != DurableValidationStageV0::Acked || fact.outbox_present() {
        return Err(PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
            "native takeover validation row is not one terminal ACK",
        ));
    }
    if fact.store_sequence() != NATIVE_H1_ORDINARY_TAKEOVER_VALIDATION_SEQUENCE_V0
        || checkpoint_facts.store_sequence_v0()
            != NATIVE_H1_ORDINARY_TAKEOVER_VALIDATION_SEQUENCE_V0
    {
        return Err(PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
            "native takeover validation sequence is not the exact terminal K sequence",
        ));
    }
    if checkpoint_facts.binding_v0() != binding {
        return Err(PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
            "native takeover checkpoint binding differs from its validation row",
        ));
    }
    if checkpoint_facts.scope_v0() != validation_store.scope_v0()
        || checkpoint_facts.store_id_v0() != validation_store.store_id_v0()
        || !checkpoint_facts.belongs_to_store_at_path_v0(validation_store, validation_store.path())
    {
        return Err(PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
            "native takeover checkpoint is not owned by the exact validation store",
        ));
    }
    let executed = validation_store
        .read_artifact_exact_v0(binding)
        .map_err(|error| PocoNodeLabAuthorityErrorV0::AuthorityChain(error.to_string()))?;
    let confirmed = application
        .confirm_durable_p_v0(&executed)
        .map_err(|error| PocoNodeLabAuthorityErrorV0::AuthorityChain(error.to_string()))?;
    let source_artifact_checksum = confirmed.source_artifact_checksum_v0();
    let speculative_head = confirmed
        .overlay_parent_head_v0()
        .map_err(|error| PocoNodeLabAuthorityErrorV0::AuthorityChain(error.to_string()))?;
    let overlay_ref = trnm_consensus_core::BlockIdOverlayRefV0::new(
        BlockId::new(confirmed.block_id_v0()),
        BlockId::new(confirmed.parent_block_id_v0()),
        confirmed.overlay_checksum_v0(),
    );
    // The proposal-validation row digest and the durable application source
    // checksum intentionally use different hash domains.  `read_artifact_exact`
    // proves the former against the exact row and `confirm_durable_p` proves the
    // same canonical artifact bytes against the latter; comparing the two hash
    // values would reject every valid takeover.
    if checkpoint_facts.artifact_digest_v0().as_bytes() == &[0; 32] {
        return Err(PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
            "native takeover validation artifact digest is zero",
        ));
    }
    if source_artifact_checksum == [0; 32] {
        return Err(PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
            "native takeover durable source artifact checksum is zero",
        ));
    }
    if executed.request().parent() != binding.parent() {
        return Err(PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
            "native takeover execution parent differs from its binding",
        ));
    }
    if executed.request().block_id() != binding.block_id()
        || executed.request().height() != binding.height()
        || executed.request().timestamp_ms() != binding.timestamp_ms()
    {
        return Err(PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
            "native takeover execution coordinate differs from its binding",
        ));
    }
    if executed.request().active_validator_set_id() != binding.active_validator_set_id() {
        return Err(PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
            "native takeover validator-set id differs from its binding",
        ));
    }
    if executed.request().expected() != binding.commitments() {
        return Err(PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
            "native takeover execution commitments differ from its binding",
        ));
    }
    if &speculative_head != completed.application_head_v0() {
        return Err(PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
            "native takeover durable application head differs from completed K",
        ));
    }
    if overlay_ref != completed.overlay_v0() {
        return Err(PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
            "native takeover durable overlay differs from completed K",
        ));
    }
    if speculative_head.block_id() != binding.block_id()
        || speculative_head.height() != binding.height()
        || speculative_head.state_root() != binding.commitments().post_state_root()
    {
        return Err(PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
            "native takeover durable application head differs from its binding",
        ));
    }
    let block_id = BlockId::new(*binding.block_id().as_bytes());
    Ok((
        block_id,
        PocoNodeLabRetainedExecutionV0 {
            binding: binding.clone(),
            executed,
            view: View::new(binding.view()),
            source_artifact_checksum,
            validation_row_checksum: *checkpoint_facts.row_checksum_v0().as_bytes(),
            overlay_ref,
            speculative_head,
        },
        *checkpoint_facts.row_checksum_v0().as_bytes(),
    ))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FreshCheckpointApplicationJoinV0 {
    Committed,
    Prepared { block_id: BlockId, height: u64 },
}

fn require_fresh_checkpoint_application_join_v0(
    application: &DurableNativeApplicationV0,
    committed: &ApplicationHeadV0,
    checkpoint: ExternalNodeCheckpointV0,
    proposal_journal: &PocoNodeLabProposalJournalConfigV0,
    application_head: &ApplicationHeadV0,
    pending_executions: &BTreeMap<BlockId, PocoNodeLabRetainedExecutionV0>,
    live_proposal_validation_store: Option<&mut SqliteProposalValidationStoreV0>,
) -> Result<FreshCheckpointApplicationJoinV0, PocoNodeLabAuthorityErrorV0> {
    let fields = checkpoint.fields();
    let checkpoint_matches_committed = fields.application_block_id.as_bytes()
        == committed.block_id().as_bytes()
        && fields.application_height == committed.height().get()
        && fields.application_state_root.as_bytes() == committed.state_root().as_bytes();
    if checkpoint_matches_committed {
        if pending_executions.contains_key(&BlockId::new(*committed.block_id().as_bytes())) {
            return Err(PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
                "committed application checkpoint remains ambiguously retained as prepared P",
            ));
        }
        return Ok(FreshCheckpointApplicationJoinV0::Committed);
    }

    let mut reopened_proposal_validation_store;
    let proposal_validation_store = if let Some(store) = live_proposal_validation_store {
        store
    } else {
        reopened_proposal_validation_store = SqliteProposalValidationStoreV0::open(
            &proposal_journal.store_path,
            proposal_journal.scope,
            proposal_journal.minimum_durable_sequence,
        )
        .map_err(|error| PocoNodeLabAuthorityErrorV0::AuthorityChain(error.to_string()))?;
        &mut reopened_proposal_validation_store
    };
    let terminal_store_sequence = proposal_validation_store
        .durable_sequence_v0()
        .map_err(|error| PocoNodeLabAuthorityErrorV0::AuthorityChain(error.to_string()))?;
    let mut matching = pending_executions
        .values()
        .filter(|retained| terminal_checkpoint_projection_matches_retained_v0(fields, retained));
    let retained = matching
        .next()
        .ok_or(PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
            "checkpoint is neither the committed application nor one retained terminal K",
        ))?;
    if matching.next().is_some()
        || &retained.speculative_head != application_head
        || !terminal_checkpoint_matches_retained_v0(fields, retained, proposal_validation_store)
    {
        return Err(PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
            "prepared application checkpoint is ambiguous or differs from its store identity",
        ));
    }
    let fresh_owner = reconfirm_terminal_retained_execution_v0(
        BlockId::new(*retained.speculative_head.block_id().as_bytes()),
        retained,
        application,
        proposal_validation_store,
        terminal_store_sequence,
    )?;
    if fresh_owner != proposal_journal.owner_id {
        return Err(PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
            "prepared application checkpoint differs from its fresh K owner",
        ));
    }
    if proposal_validation_store
        .durable_sequence_v0()
        .map_err(|error| PocoNodeLabAuthorityErrorV0::AuthorityChain(error.to_string()))?
        != terminal_store_sequence
    {
        return Err(PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
            "proposal-validation journal advanced during checkpoint-owner readback",
        ));
    }
    Ok(FreshCheckpointApplicationJoinV0::Prepared {
        block_id: BlockId::new(*retained.speculative_head.block_id().as_bytes()),
        height: retained.speculative_head.height().get(),
    })
}

fn confirm_live_or_signature_released_safety_head_v0(
    core: &Core,
    safety_store: &SqliteSafetyStateStoreV0<StrictEd25519Verifier>,
) -> Result<ConfirmedSafetyNodeCheckpointFactsV0, PocoNodeLabAuthorityErrorV0> {
    let durable_safety = safety_store
        .head()
        .map_err(PocoNodeLabAuthorityErrorV0::Safety)?;
    if durable_safety.state() != core.safety_state()
        && !core
            .safety_state()
            .matches_signature_released_successor_of_v0(durable_safety.state())
    {
        return Err(PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
            "live Safety is neither the durable head nor its exact signature-release successor",
        ));
    }
    safety_store
        .confirm_node_checkpoint_head_exact_v0(durable_safety.state())
        .map_err(PocoNodeLabAuthorityErrorV0::Safety)
}

#[allow(clippy::too_many_arguments)]
fn reconfirm_phase_neutral_exact_high_qc_v0<W: ExternalMonotonicWatermarkV0>(
    certificate: &QuorumCertificate,
    core: &Core,
    safety_store: &SqliteSafetyStateStoreV0<StrictEd25519Verifier>,
    application: &DurableNativeApplicationV0,
    signer_journal: &mut SqliteSignerJournalV0<W>,
    checkpoint_store: &mut SqliteExternalNodeCheckpointStoreV0,
    checkpoint: ExternalNodeCheckpointV0,
    application_head: &ApplicationHeadV0,
    pending_executions: &BTreeMap<BlockId, PocoNodeLabRetainedExecutionV0>,
    proposal_journal: &PocoNodeLabProposalJournalConfigV0,
    live_proposal_validation_store: Option<&mut SqliteProposalValidationStoreV0>,
) -> Result<(), PocoNodeLabAuthorityErrorV0> {
    certificate
        .verify(core.config().validator_set(), &StrictEd25519Verifier)
        .map_err(|error| PocoNodeLabAuthorityErrorV0::AuthorityChain(error.to_string()))?;
    let Some(authoritative) = core.safety_state().high_qc().as_ordinary() else {
        return Err(PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
            "exact ordinary QC replay has no authoritative ordinary high QC",
        ));
    };
    if certificate.id() != authoritative.id() || certificate != authoritative {
        return Err(PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
            "QC replay differs from the exact authoritative high QC",
        ));
    }

    let safety = confirm_live_or_signature_released_safety_head_v0(core, safety_store)?;
    let signer = signer_journal
        .confirm_node_checkpoint_head_exact_v0()
        .map_err(PocoNodeLabAuthorityErrorV0::Signer)?;
    if !safety.belongs_to_store_at_path_v0(safety_store, safety_store.path())
        || !signer.belongs_to_operational_journal_at_path_v0(signer_journal, signer_journal.path())
        || signer.pending_intent().is_some()
    {
        return Err(PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
            "exact QC replay lost fresh Safety or signer owner affinity",
        ));
    }
    let observed_checkpoint = checkpoint_store
        .load(checkpoint.scope())
        .map_err(PocoNodeLabAuthorityErrorV0::Checkpoint)?
        .ok_or(PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
            "exact QC replay whole-node checkpoint disappeared",
        ))?;
    if observed_checkpoint != checkpoint {
        return Err(PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
            "exact QC replay checkpoint differs from fresh CAS readback",
        ));
    }
    require_checkpoint_heads_v0(checkpoint, &safety, &signer)?;

    let applied = core.safety_state().application_applied();
    let committed = application
        .confirmed_committed_head_v0()
        .map_err(|error| PocoNodeLabAuthorityErrorV0::AuthorityChain(error.to_string()))?;
    if committed.block_id().as_bytes() != applied.block_id().as_bytes()
        || committed.height().get() != applied.height().get()
    {
        return Err(PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
            "exact QC replay native committed head differs from Core application_applied",
        ));
    }
    let _ = require_fresh_checkpoint_application_join_v0(
        application,
        &committed,
        checkpoint,
        proposal_journal,
        application_head,
        pending_executions,
        live_proposal_validation_store,
    )?;
    Ok(())
}

/// Freshly authenticates the complete retained application path selected by
/// Core before a TC can advance Safety or the independent checkpoint.
///
/// The source checkpoint may still name the timed-out proposal, so validating
/// only that source K is insufficient: a copied scalar high-QC or an absent
/// ancestor could otherwise be discovered only after the CAS. Every selected
/// P/K row is therefore rejoined to the exact live proposal store and durable
/// native application while all stores are still unchanged.
fn preflight_authoritative_high_qc_retained_path_v0(
    core: &Core,
    application: &DurableNativeApplicationV0,
    proposal_journal: &PocoNodeLabProposalJournalConfigV0,
    pending_executions: &BTreeMap<BlockId, PocoNodeLabRetainedExecutionV0>,
) -> Result<(), PocoNodeLabAuthorityErrorV0> {
    let safety = core.safety_state();
    if safety.pending_tc_high_qc_sync().is_some() || safety.pending_standalone_qc_sync().is_some() {
        return Err(PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
            "TC preflight retained an unresolved high-QC execution target",
        ));
    }
    let applied = safety.application_applied();
    let high_qc = safety.high_qc().qc_ref();
    let committed = application
        .confirmed_committed_head_v0()
        .map_err(|error| PocoNodeLabAuthorityErrorV0::AuthorityChain(error.to_string()))?;
    if committed.block_id().as_bytes() != applied.block_id().as_bytes()
        || committed.height().get() != applied.height().get()
        || high_qc.height().get() < applied.height().get()
        || (high_qc.height() == applied.height() && high_qc.block_id() != applied.block_id())
    {
        return Err(PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
            "TC selected high-QC path conflicts with the committed applied head",
        ));
    }
    if high_qc.height() == applied.height() {
        return Ok(());
    }

    let mut validation_store = SqliteProposalValidationStoreV0::open(
        &proposal_journal.store_path,
        proposal_journal.scope,
        proposal_journal.minimum_durable_sequence,
    )
    .map_err(|error| PocoNodeLabAuthorityErrorV0::AuthorityChain(error.to_string()))?;
    let terminal_store_sequence = validation_store
        .durable_sequence_v0()
        .map_err(|error| PocoNodeLabAuthorityErrorV0::AuthorityChain(error.to_string()))?;
    let mut cursor_block = high_qc.block_id();
    let mut cursor_height = high_qc.height().get();
    let mut child_view = None;
    let mut is_selected_head = true;
    while cursor_height > applied.height().get() {
        let matching = pending_executions
            .iter()
            .filter(|(key, retained)| {
                **key == cursor_block
                    && retained.executed.request().block_id().as_bytes() == cursor_block.as_bytes()
                    && retained.speculative_head.block_id().as_bytes() == cursor_block.as_bytes()
                    && retained.executed.request().height().get() == cursor_height
                    && retained.speculative_head.height().get() == cursor_height
            })
            .count();
        if matching != 1 {
            return Err(PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
                "TC selected high-QC path lacks one exact retained execution",
            ));
        }
        let retained = pending_executions.get(&cursor_block).ok_or(
            PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
                "TC selected high-QC retained execution disappeared",
            ),
        )?;
        if retained.overlay_ref.block_id() != cursor_block
            || retained.overlay_ref.parent_block_id().as_bytes()
                != retained.executed.request().parent().block_id().as_bytes()
            || retained.speculative_head.state_root().as_bytes()
                != retained
                    .executed
                    .request()
                    .expected()
                    .post_state_root()
                    .as_bytes()
            || retained.source_artifact_checksum == [0; 32]
            || child_view.is_some_and(|view| retained.view >= view)
            || (is_selected_head && retained.view != high_qc.view())
        {
            return Err(PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
                "TC selected high-QC execution has an ambiguous coordinate or parent",
            ));
        }
        let owner = reconfirm_terminal_retained_execution_v0(
            cursor_block,
            retained,
            application,
            &mut validation_store,
            terminal_store_sequence,
        )?;
        if owner != proposal_journal.owner_id {
            return Err(PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
                "TC selected high-QC path differs from the proposal-store owner",
            ));
        }
        let parent = retained.executed.request().parent();
        if parent.height().get().checked_add(1) != Some(cursor_height) {
            return Err(PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
                "TC selected high-QC path is not height-contiguous",
            ));
        }
        child_view = Some(retained.view);
        is_selected_head = false;
        cursor_block = BlockId::new(*parent.block_id().as_bytes());
        cursor_height = parent.height().get();
    }
    if cursor_height != applied.height().get()
        || cursor_block != applied.block_id()
        || validation_store
            .durable_sequence_v0()
            .map_err(|error| PocoNodeLabAuthorityErrorV0::AuthorityChain(error.to_string()))?
            != terminal_store_sequence
    {
        return Err(PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
            "TC selected high-QC path does not terminate at the unchanged application/store cut",
        ));
    }
    Ok(())
}

fn rebase_to_authoritative_high_qc_v0(
    core: &Core,
    application: &DurableNativeApplicationV0,
    checkpoint: ExternalNodeCheckpointV0,
    proposal_journal: &PocoNodeLabProposalJournalConfigV0,
    application_head: &mut ApplicationHeadV0,
    application_overlay: &mut Option<trnm_consensus_core::BlockIdOverlayRefV0>,
    pending_executions: &mut BTreeMap<BlockId, PocoNodeLabRetainedExecutionV0>,
) -> Result<(), PocoNodeLabAuthorityErrorV0> {
    let safety = core.safety_state();
    if safety.pending_tc_high_qc_sync().is_some() || safety.pending_standalone_qc_sync().is_some() {
        return Err(PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
            "certificate retained an unresolved high-QC execution target",
        ));
    }
    let applied = safety.application_applied();
    let high_qc = safety.high_qc().qc_ref();
    let committed = application
        .confirmed_committed_head_v0()
        .map_err(|error| PocoNodeLabAuthorityErrorV0::AuthorityChain(error.to_string()))?;
    if committed.block_id().as_bytes() != applied.block_id().as_bytes()
        || committed.height().get() != applied.height().get()
    {
        return Err(PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
            "native committed head differs from Core application_applied during rebase",
        ));
    }
    if let FreshCheckpointApplicationJoinV0::Prepared { block_id, height } =
        require_fresh_checkpoint_application_join_v0(
            application,
            &committed,
            checkpoint,
            proposal_journal,
            application_head,
            pending_executions,
            None,
        )?
    {
        if block_id != high_qc.block_id() || height != high_qc.height().get() {
            return Err(PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
                "prepared application checkpoint is not the authoritative high-QC head",
            ));
        }
    }

    if high_qc.height().get() < applied.height().get()
        || (high_qc.height() == applied.height() && high_qc.block_id() != applied.block_id())
    {
        return Err(PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
            "authoritative high QC conflicts with the committed applied head",
        ));
    }

    let mut retained_path = BTreeSet::new();
    let mut cursor_block = high_qc.block_id();
    let mut cursor_height = high_qc.height().get();
    let mut child_view = None;
    let mut target = None;
    while cursor_height > applied.height().get() {
        let matching = pending_executions
            .iter()
            .filter(|(key, retained)| {
                **key == cursor_block
                    && retained.executed.request().block_id().as_bytes() == cursor_block.as_bytes()
                    && retained.speculative_head.block_id().as_bytes() == cursor_block.as_bytes()
                    && retained.executed.request().height().get() == cursor_height
                    && retained.speculative_head.height().get() == cursor_height
            })
            .count();
        if matching != 1 {
            return Err(PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
                "authoritative high-QC path lacks one exact retained execution",
            ));
        }
        let retained = pending_executions.get(&cursor_block).ok_or(
            PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
                "authoritative high-QC retained execution disappeared",
            ),
        )?;
        if retained.overlay_ref.block_id() != cursor_block
            || retained.overlay_ref.parent_block_id().as_bytes()
                != retained.executed.request().parent().block_id().as_bytes()
            || retained.speculative_head.state_root().as_bytes()
                != retained
                    .executed
                    .request()
                    .expected()
                    .post_state_root()
                    .as_bytes()
            || retained.source_artifact_checksum == [0; 32]
            || child_view.is_some_and(|view| retained.view >= view)
        {
            return Err(PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
                "retained high-QC execution has an ambiguous coordinate or parent",
            ));
        }
        if target.is_none() {
            if retained.view != high_qc.view() {
                return Err(PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
                    "authoritative high QC differs from its retained execution view",
                ));
            }
            target = Some((retained.speculative_head.clone(), retained.overlay_ref));
        }
        let parent = retained.executed.request().parent();
        if parent.height().get().checked_add(1) != Some(cursor_height) {
            return Err(PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
                "retained high-QC path is not height-contiguous",
            ));
        }
        retained_path.insert(cursor_block);
        child_view = Some(retained.view);
        cursor_block = BlockId::new(*parent.block_id().as_bytes());
        cursor_height = parent.height().get();
    }
    if cursor_height != applied.height().get() || cursor_block != applied.block_id() {
        return Err(PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
            "retained high-QC path does not terminate at the committed applied head",
        ));
    }

    pending_executions.retain(|block_id, _| retained_path.contains(block_id));
    if let Some((head, overlay)) = target {
        *application_head = head;
        *application_overlay = Some(overlay);
    } else {
        *application_head = committed;
        *application_overlay = None;
    }
    Ok(())
}

fn phase_facts_from_parts_v0(
    phase: PocoNodeLabAuthorityPhaseV0,
    core: &Core,
    checkpoint: ExternalNodeCheckpointV0,
    application_head: &ApplicationHeadV0,
) -> PocoNodeLabPhaseFactsV0 {
    let safety = core.safety_state();
    let finalized = safety.finalized();
    let applied = safety.application_applied();
    let fields = checkpoint.fields();
    PocoNodeLabPhaseFactsV0 {
        phase,
        checkpoint,
        current_view: safety.current_view(),
        high_qc: safety.high_qc().qc_ref(),
        pending_timeout_certificate_id: safety
            .pending_tc_high_qc_sync()
            .map(|pending| pending.certificate_id()),
        finalized_block_id: finalized.block_id(),
        finalized_height: finalized.height().get(),
        finalized_chain_root: *core.finalized_chain_root_v0().as_bytes(),
        application_applied_block_id: applied.block_id(),
        application_applied_height: applied.height().get(),
        proposal_parent_block_id: BlockId::new(*application_head.block_id().as_bytes()),
        proposal_parent_height: application_head.height().get(),
        safety_revision: fields.safety_revision,
        safety_record_checksum: fields.safety_state_record_checksum,
        safety_chain_checksum: fields.safety_record_chain_checksum,
        signer_exact_watermark: fields.signer_exact_watermark,
    }
}

fn finalized_proof_from_core_v0(
    core: &Core,
) -> Result<PocoNodeLabFinalizedProofV0, PocoNodeLabAuthorityErrorV0> {
    let safety = core.safety_state();
    let (proof, authenticated_parent_timestamp_ms) =
        if let Some(finalization) = safety.last_finalization() {
            (
                finalization.proof().clone(),
                finalization.authenticated_parent().timestamp_ms(),
            )
        } else if let Some(anchor) = safety.state_sync_anchor() {
            (
                anchor.proof().clone(),
                anchor.authenticated_parent().timestamp_ms(),
            )
        } else {
            return Err(PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
                "Ready runtime has no durable finalized proof provenance",
            ));
        };

    proof
        .verify(
            core.config().validator_set(),
            None,
            core.config().consensus_parameters(),
            authenticated_parent_timestamp_ms,
            &StrictEd25519Verifier,
        )
        .map_err(|_| {
            PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
                "durable finalized proof failed strict signature/context verification",
            )
        })?;

    let header = proof.finalized_block().header();
    let finalized = safety.finalized();
    let configured_validator_set = core.config().validator_set();
    if header.id() != finalized.block_id()
        || header.height() != finalized.height()
        || header.view() != finalized.view()
        || header.timestamp_ms() != finalized.timestamp_ms()
        || header.validator_set_id() != configured_validator_set.id()
        || header.genesis_hash() != configured_validator_set.genesis_hash()
        || header.chain_id() != configured_validator_set.chain_id()
        || header.protocol_version() != configured_validator_set.protocol_version()
        || header.consensus_parameters_hash() != core.config().consensus_parameters().hash()
    {
        return Err(PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
            "durable finalized proof differs from the live finalized tip or validator scope",
        ));
    }

    let finalized_chain_root = *core.finalized_chain_root_v0().as_bytes();
    if finalized_chain_root == [0; 32]
        || header.state_root().as_bytes() == &[0; 32]
        || header.receipts_root().as_bytes() == &[0; 32]
    {
        return Err(PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
            "durable finalized proof has an empty state, receipt, or chain root",
        ));
    }

    Ok(PocoNodeLabFinalizedProofV0 {
        proof_id: proof.id(),
        finalized_block_id: header.id(),
        finalized_height: header.height().get(),
        validator_set_id: header.validator_set_id(),
        state_root: header.state_root(),
        receipts_root: header.receipts_root(),
        authenticated_parent_timestamp_ms,
        finalized_chain_root,
        proof,
    })
}

fn bind_finalized_query_v0(
    proof: &PocoNodeLabFinalizedProofV0,
    read: &FinalizedNativeApplicationReadV0,
) -> Result<(), PocoNodeLabFinalizedQueryErrorV0> {
    let head = read
        .finalized_head_v0()
        .map_err(|error| PocoNodeLabFinalizedQueryErrorV0::Application(error.to_string()))?;
    if head.block_id().as_bytes() != proof.finalized_block_id_v0().as_bytes()
        || head.height().get() != proof.finalized_height_v0()
        || head.state_root().as_bytes() != proof.state_root_v0().as_bytes()
        || read.receipts_root_v0().as_bytes() != proof.receipts_root_v0().as_bytes()
    {
        return Err(PocoNodeLabFinalizedQueryErrorV0::QueryMismatch(
            "application readback roots or coordinates differ from FinalityProofV0",
        ));
    }
    Ok(())
}

fn require_checkpoint_heads_v0(
    checkpoint: ExternalNodeCheckpointV0,
    safety: &trnm_consensus_safety_store::ConfirmedSafetyNodeCheckpointFactsV0,
    signer: &trnm_consensus_signer_journal::ConfirmedSignerNodeCheckpointFactsV0,
) -> Result<(), PocoNodeLabAuthorityErrorV0> {
    let fields = checkpoint.fields();
    if fields.scope != signer.exact_watermark().scope()
        || fields.safety_journal_id != safety.journal_id_v0()
        || fields.safety_verifier_profile_ref != safety.verifier_profile_ref_v0()
        || fields.safety_revision != safety.revision_v0()
        || fields.safety_state_record_checksum != safety.state_record_checksum_v0()
        || fields.safety_record_chain_checksum != safety.chain_checksum_v0()
        || fields.signer_journal_id != signer.journal_id()
        || fields.signer_profile_checksum != signer.profile_checksum()
        || fields.signer_exact_watermark != signer.exact_watermark()
    {
        return Err(PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
            "whole-node checkpoint differs from the exact Safety/signer heads",
        ));
    }
    Ok(())
}

fn require_same_safety_head_v0(
    before: &trnm_consensus_safety_store::ConfirmedSafetyNodeCheckpointFactsV0,
    after: &trnm_consensus_safety_store::ConfirmedSafetyNodeCheckpointFactsV0,
) -> Result<(), PocoNodeLabAuthorityErrorV0> {
    if after.journal_id_v0() != before.journal_id_v0()
        || after.verifier_profile_ref_v0() != before.verifier_profile_ref_v0()
        || after.revision_v0() != before.revision_v0()
        || after.state_record_checksum_v0() != before.state_record_checksum_v0()
        || after.chain_checksum_v0() != before.chain_checksum_v0()
    {
        return Err(PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
            "Safety head changed while producing a signature",
        ));
    }
    Ok(())
}

fn require_one_exact_signer_pair_v0(
    before: &trnm_consensus_signer_journal::ConfirmedSignerNodeCheckpointFactsV0,
    after: &trnm_consensus_signer_journal::ConfirmedSignerNodeCheckpointFactsV0,
) -> Result<(), PocoNodeLabAuthorityErrorV0> {
    let expected_sequence = before.exact_watermark().sequence().checked_add(2).ok_or(
        PocoNodeLabAuthorityErrorV0::InvalidBootstrap("signer watermark sequence exhausted"),
    )?;
    let expected_intents = before.capacity().intent_count().checked_add(1).ok_or(
        PocoNodeLabAuthorityErrorV0::InvalidBootstrap("signer intent accounting exhausted"),
    )?;
    let expected_events = before.capacity().event_count().checked_add(2).ok_or(
        PocoNodeLabAuthorityErrorV0::InvalidBootstrap("signer event accounting exhausted"),
    )?;
    if after.journal_id() != before.journal_id()
        || after.profile_checksum() != before.profile_checksum()
        || after.exact_watermark().scope() != before.exact_watermark().scope()
        || after.exact_watermark().journal_id() != before.exact_watermark().journal_id()
        || after.exact_watermark().sequence() != expected_sequence
        || after.pending_intent().is_some()
        || after.capacity().intent_count() != expected_intents
        || after.capacity().event_count() != expected_events
    {
        return Err(PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
            "signer journal did not advance by one exact prepared/signed pair",
        ));
    }
    Ok(())
}

fn signer_checkpoint_successor_v0(
    predecessor: ExternalNodeCheckpointV0,
    safety: &trnm_consensus_safety_store::ConfirmedSafetyNodeCheckpointFactsV0,
    signer: &trnm_consensus_signer_journal::ConfirmedSignerNodeCheckpointFactsV0,
) -> Result<ExternalNodeCheckpointV0, PocoNodeLabAuthorityErrorV0> {
    let fields = predecessor.fields();
    if fields.safety_journal_id != safety.journal_id_v0()
        || fields.safety_verifier_profile_ref != safety.verifier_profile_ref_v0()
        || fields.safety_revision != safety.revision_v0()
        || fields.safety_state_record_checksum != safety.state_record_checksum_v0()
        || fields.safety_record_chain_checksum != safety.chain_checksum_v0()
        || fields.signer_journal_id != signer.journal_id()
        || fields.signer_profile_checksum != signer.profile_checksum()
        || fields.scope != signer.exact_watermark().scope()
    {
        return Err(PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
            "signed checkpoint successor does not preserve its durable owners",
        ));
    }
    let mut target = *fields;
    target.generation = predecessor.generation().checked_add(1).ok_or(
        PocoNodeLabAuthorityErrorV0::InvalidBootstrap("whole-node checkpoint generation exhausted"),
    )?;
    target.predecessor_checksum = predecessor.checkpoint_checksum();
    target.signer_exact_watermark = signer.exact_watermark();
    ExternalNodeCheckpointV0::new(target)
        .map_err(|error| PocoNodeLabAuthorityErrorV0::AuthorityChain(error.to_string()))
}

fn safety_checkpoint_successor_v0(
    predecessor: ExternalNodeCheckpointV0,
    safety: &trnm_consensus_safety_store::ConfirmedSafetyNodeCheckpointFactsV0,
    signer: &trnm_consensus_signer_journal::ConfirmedSignerNodeCheckpointFactsV0,
) -> Result<ExternalNodeCheckpointV0, PocoNodeLabAuthorityErrorV0> {
    let fields = predecessor.fields();
    let expected_revision = fields.safety_revision.checked_add(1).ok_or(
        PocoNodeLabAuthorityErrorV0::InvalidBootstrap("Safety revision exhausted"),
    )?;
    if fields.scope != signer.exact_watermark().scope()
        || fields.signer_journal_id != signer.journal_id()
        || fields.signer_profile_checksum != signer.profile_checksum()
        || fields.signer_exact_watermark != signer.exact_watermark()
        || fields.safety_journal_id != safety.journal_id_v0()
        || fields.safety_verifier_profile_ref != safety.verifier_profile_ref_v0()
        || safety.revision_v0() != expected_revision
    {
        return Err(PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
            "Safety checkpoint successor differs from its durable owners",
        ));
    }
    let mut target = *fields;
    target.generation = predecessor.generation().checked_add(1).ok_or(
        PocoNodeLabAuthorityErrorV0::InvalidBootstrap("whole-node checkpoint generation exhausted"),
    )?;
    target.predecessor_checksum = predecessor.checkpoint_checksum();
    target.safety_revision = safety.revision_v0();
    target.safety_state_record_checksum = safety.state_record_checksum_v0();
    target.safety_record_chain_checksum = safety.chain_checksum_v0();
    ExternalNodeCheckpointV0::new(target)
        .map_err(|error| PocoNodeLabAuthorityErrorV0::AuthorityChain(error.to_string()))
}

/// Advances the independent checkpoint for one accepted TC while replacing a
/// now-detached speculative K projection with the exact committed application
/// anchor. The selected high-QC path remains authenticated by retained P/K
/// records and is installed in memory only after this CAS succeeds.
///
/// Keeping the checkpoint at the timed-out proposal would make a same-height
/// rebound impossible (`native K` successors require a strictly older
/// application predecessor) and would make recovery claim a parent which Core
/// no longer selected. This successor changes Safety and the application
/// projection in one generation; it never rewinds the checkpoint generation,
/// Safety revision, signer watermark, or committed application store.
fn timeout_rebase_checkpoint_successor_v0(
    predecessor: ExternalNodeCheckpointV0,
    safety: &trnm_consensus_safety_store::ConfirmedSafetyNodeCheckpointFactsV0,
    signer: &trnm_consensus_signer_journal::ConfirmedSignerNodeCheckpointFactsV0,
    application: &DurableNativeApplicationV0,
) -> Result<ExternalNodeCheckpointV0, PocoNodeLabAuthorityErrorV0> {
    let fields = predecessor.fields();
    let expected_revision = fields.safety_revision.checked_add(1).ok_or(
        PocoNodeLabAuthorityErrorV0::InvalidBootstrap("Safety revision exhausted"),
    )?;
    let state = safety.state_v0();
    let finalized = state.finalized();
    let applied = state.application_applied();
    let committed = application
        .confirmed_committed_head_v0()
        .map_err(|error| PocoNodeLabAuthorityErrorV0::AuthorityChain(error.to_string()))?;
    let config = application.config_v0();
    let application_store_id = config.store_id();
    if fields.scope != signer.exact_watermark().scope()
        || fields.signer_journal_id != signer.journal_id()
        || fields.signer_profile_checksum != signer.profile_checksum()
        || fields.signer_exact_watermark != signer.exact_watermark()
        || fields.safety_journal_id != safety.journal_id_v0()
        || fields.safety_verifier_profile_ref != safety.verifier_profile_ref_v0()
        || safety.revision_v0() != expected_revision
        || finalized != applied
        || committed.block_id().as_bytes() != applied.block_id().as_bytes()
        || committed.height().get() != applied.height().get()
        || application_store_id == [0; 32]
    {
        return Err(PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
            "timeout rebase checkpoint successor differs from its durable owners",
        ));
    }

    let application_owner = lab_genesis_hash_v0(
        b"trnm.poco-node.lab-finalization.application-owner.v0",
        &[
            config.chain_id_v0().as_bytes(),
            &config.genesis_hash_v0(),
            &application_store_id,
            &config.chain_descriptor_hash_v0(),
        ],
    );
    let application_profile = lab_genesis_hash_v0(
        LAB_TIMEOUT_REBASE_CHECKPOINT_PROFILE_DOMAIN_V0,
        &[
            b"committed-application-anchor",
            b"retained-selected-high-qc-path",
        ],
    );
    let committed_head_row = application_head_checksum_v0(
        b"trnm.poco-node.lab-finalization.checkpoint-head.v0",
        &committed,
    );
    let safety_revision = safety.revision_v0().to_be_bytes();
    let current_view = state.current_view().get().to_be_bytes();
    let high_qc = state.high_qc();
    let high_qc_view = high_qc.qc_ref().view().get().to_be_bytes();
    let high_qc_height = high_qc.qc_ref().height().get().to_be_bytes();
    let finalized_view = finalized.view().get().to_be_bytes();
    let finalized_height = finalized.height().get().to_be_bytes();
    let signer_sequence = signer.exact_watermark().sequence().to_be_bytes();
    let application_safety_binding = lab_genesis_hash_v0(
        b"trnm.poco-node.lab-timeout-rebase.safety-binding.v0",
        &[
            &safety.journal_id_v0(),
            &safety.verifier_profile_ref_v0(),
            &safety_revision,
            &safety.state_record_checksum_v0(),
            &safety.chain_checksum_v0(),
            high_qc.id().as_bytes(),
            &high_qc_view,
            &high_qc_height,
            high_qc.qc_ref().block_id().as_bytes(),
            &current_view,
            &signer.journal_id(),
            &signer_sequence,
            &signer.exact_watermark().chain_checksum(),
            &committed_head_row,
        ],
    );
    let recovery_closure = lab_genesis_hash_v0(
        b"trnm.poco-node.lab-timeout-rebase.recovery-closure.v0",
        &[
            &predecessor.checkpoint_checksum(),
            &application_owner,
            &application_profile,
            &application_safety_binding,
            &committed_head_row,
            finalized.block_id().as_bytes(),
            &finalized_view,
            &finalized_height,
            &finalized.timestamp_ms().to_be_bytes(),
        ],
    );

    let mut target = *fields;
    target.generation = predecessor.generation().checked_add(1).ok_or(
        PocoNodeLabAuthorityErrorV0::InvalidBootstrap("whole-node checkpoint generation exhausted"),
    )?;
    target.predecessor_checksum = predecessor.checkpoint_checksum();
    target.safety_revision = safety.revision_v0();
    target.safety_state_record_checksum = safety.state_record_checksum_v0();
    target.safety_record_chain_checksum = safety.chain_checksum_v0();
    target.application_host_config_ref = application_owner;
    target.application_projection_profile_ref = application_profile;
    target.application_safety_binding_manifest_checksum = application_safety_binding;
    target.application_committed_head_row_checksum = committed_head_row;
    target.application_recovery_closure_checksum = recovery_closure;
    target.application_block_id = BlockId::new(*committed.block_id().as_bytes());
    target.application_height = committed.height().get();
    target.application_state_root =
        trnm_consensus_types::StateRoot::new(*committed.state_root().as_bytes());
    target.application_view = finalized.view().get();
    target.application_timestamp_ms = finalized.timestamp_ms();
    ExternalNodeCheckpointV0::new(target)
        .map_err(|error| PocoNodeLabAuthorityErrorV0::AuthorityChain(error.to_string()))
}

#[allow(clippy::too_many_arguments)]
fn finalization_checkpoint_successor_v0(
    predecessor: ExternalNodeCheckpointV0,
    safety: &trnm_consensus_safety_store::ConfirmedSafetyNodeCheckpointFactsV0,
    signer: &trnm_consensus_signer_journal::ConfirmedSignerNodeCheckpointFactsV0,
    committed_head: &ApplicationHeadV0,
    committed_view: u64,
    committed_timestamp_ms: u64,
    application_host_config_ref: [u8; 32],
    finalization_safety_checksum: [u8; 32],
    finalization_receipt_checksum: [u8; 32],
) -> Result<ExternalNodeCheckpointV0, PocoNodeLabAuthorityErrorV0> {
    let fields = predecessor.fields();
    let expected_revision = fields.safety_revision.checked_add(1).ok_or(
        PocoNodeLabAuthorityErrorV0::InvalidBootstrap("Safety revision exhausted"),
    )?;
    if fields.scope != signer.exact_watermark().scope()
        || fields.signer_journal_id != signer.journal_id()
        || fields.signer_profile_checksum != signer.profile_checksum()
        || fields.signer_exact_watermark != signer.exact_watermark()
        || fields.safety_journal_id != safety.journal_id_v0()
        || fields.safety_verifier_profile_ref != safety.verifier_profile_ref_v0()
        || safety.revision_v0() != expected_revision
        || application_host_config_ref == [0; 32]
        || finalization_safety_checksum == [0; 32]
        || finalization_receipt_checksum == [0; 32]
    {
        return Err(PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
            "finalization checkpoint successor differs from its durable owners",
        ));
    }
    let head_row = application_head_checksum_v0(
        b"trnm.poco-node.lab-finalization.checkpoint-head.v0",
        committed_head,
    );
    let application_profile = lab_genesis_hash_v0(
        LAB_FINALIZATION_CHECKPOINT_PROFILE_DOMAIN_V0,
        &[b"committed-finalization"],
    );
    let closure = lab_genesis_hash_v0(
        b"trnm.poco-node.lab-finalization.checkpoint-closure.v0",
        &[
            &predecessor.checkpoint_checksum(),
            &finalization_safety_checksum,
            &finalization_receipt_checksum,
            &head_row,
            &safety.chain_checksum_v0(),
        ],
    );
    let mut target = *fields;
    target.generation = predecessor.generation().checked_add(1).ok_or(
        PocoNodeLabAuthorityErrorV0::InvalidBootstrap("whole-node checkpoint generation exhausted"),
    )?;
    target.predecessor_checksum = predecessor.checkpoint_checksum();
    target.safety_revision = safety.revision_v0();
    target.safety_state_record_checksum = safety.state_record_checksum_v0();
    target.safety_record_chain_checksum = safety.chain_checksum_v0();
    target.application_host_config_ref = application_host_config_ref;
    target.application_projection_profile_ref = application_profile;
    target.application_safety_binding_manifest_checksum = finalization_safety_checksum;
    target.application_committed_head_row_checksum = head_row;
    target.application_recovery_closure_checksum = closure;
    target.application_block_id = BlockId::new(*committed_head.block_id().as_bytes());
    target.application_height = committed_head.height().get();
    target.application_state_root =
        trnm_consensus_types::StateRoot::new(*committed_head.state_root().as_bytes());
    target.application_view = committed_view;
    target.application_timestamp_ms = committed_timestamp_ms;
    ExternalNodeCheckpointV0::new(target)
        .map_err(|error| PocoNodeLabAuthorityErrorV0::AuthorityChain(error.to_string()))
}

fn application_head_checksum_v0(domain: &[u8], head: &ApplicationHeadV0) -> [u8; 32] {
    let height = head.height().get().to_be_bytes();
    lab_genesis_hash_v0(
        domain,
        &[
            &height,
            head.block_id().as_bytes(),
            head.state_root().as_bytes(),
            head.commit_id().as_bytes(),
        ],
    )
}

fn verify_checkpoint_bytes_exact_v0(
    live: ExternalNodeCheckpointV0,
    encoded: &[u8],
) -> Result<ExternalNodeCheckpointV0, PocoNodeLabCheckpointComparisonErrorV0> {
    let observed = ExternalNodeCheckpointV0::decode_canonical_exact(encoded).map_err(|_| {
        PocoNodeLabCheckpointComparisonErrorV0 {
            class: PocoNodeLabCheckpointComparisonClassV0::Malformed,
        }
    })?;
    if observed == live {
        return Ok(observed);
    }
    let class = if observed.scope() == live.scope() && observed.generation() < live.generation() {
        PocoNodeLabCheckpointComparisonClassV0::Stale
    } else {
        PocoNodeLabCheckpointComparisonClassV0::Mismatch
    };
    Err(PocoNodeLabCheckpointComparisonErrorV0 { class })
}

fn compare_and_confirm_checkpoint_v0<S: ExternalNodeCheckpointStoreV0>(
    store: &mut S,
    expected: Option<ExternalNodeCheckpointV0>,
    target: ExternalNodeCheckpointV0,
) -> Result<(), PocoNodeLabAuthorityErrorV0> {
    if store
        .load(target.scope())
        .map_err(PocoNodeLabAuthorityErrorV0::Checkpoint)?
        != expected
    {
        return Err(PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
            "whole-node checkpoint source differs before CAS",
        ));
    }
    for _ in 0..2 {
        let _ = store.compare_and_advance(expected, target);
        match store
            .load(target.scope())
            .map_err(PocoNodeLabAuthorityErrorV0::Checkpoint)?
        {
            Some(observed) if observed == target => return Ok(()),
            observed if observed == expected => {}
            _ => {
                return Err(PocoNodeLabAuthorityErrorV0::InvalidBootstrap(
                    "whole-node checkpoint entered a third state",
                ));
            }
        }
    }
    Err(PocoNodeLabAuthorityErrorV0::PersistenceNotApplied(
        "whole-node checkpoint CAS",
    ))
}

fn fresh_genesis_checkpoint_v0(
    core: &trnm_consensus_core::CoreConfig,
    safety: &trnm_consensus_safety_store::ConfirmedSafetyNodeCheckpointFactsV0,
    application: &DurableNativeApplicationV0,
    head: &ApplicationHeadV0,
    signer: &trnm_consensus_signer_journal::ConfirmedSignerNodeCheckpointFactsV0,
) -> Result<ExternalNodeCheckpointV0, PocoNodeLabAuthorityErrorV0> {
    let config = application.config_v0();
    let app_owner = lab_genesis_hash_v0(
        b"trnm.poco-node.lab-fresh-genesis.application-owner.v0",
        &[
            core.validator_set().chain_id().as_bytes(),
            core.validator_set().genesis_hash().as_bytes(),
            &config.store_id(),
            &config.chain_descriptor_hash_v0(),
        ],
    );
    let projection = lab_genesis_hash_v0(
        b"trnm.poco-node.lab-fresh-genesis.projection.v0",
        &[b"native-execution-schema-3", b"ordinary-genesis"],
    );
    let safety_binding = lab_genesis_hash_v0(
        b"trnm.poco-node.lab-fresh-genesis.safety-binding.v0",
        &[
            &safety.journal_id_v0(),
            &safety.verifier_profile_ref_v0(),
            &safety.core_config_ref_v0(),
            &safety.state_record_checksum_v0(),
            &safety.chain_checksum_v0(),
        ],
    );
    let head_row = lab_genesis_hash_v0(
        b"trnm.poco-node.lab-fresh-genesis.head.v0",
        &[
            head.block_id().as_bytes(),
            head.state_root().as_bytes(),
            head.commit_id().as_bytes(),
        ],
    );
    let closure = lab_genesis_hash_v0(
        b"trnm.poco-node.lab-fresh-genesis.closure.v0",
        &[
            &config.store_id(),
            &config.initial_commit_id_v0(),
            &config.initial_state_root(),
            &signer.journal_id(),
            &signer.profile_checksum(),
        ],
    );
    ExternalNodeCheckpointV0::new(crate::ExternalNodeCheckpointFieldsV0 {
        scope: signer.exact_watermark().scope(),
        generation: 0,
        predecessor_checksum: [0; 32],
        safety_journal_id: safety.journal_id_v0(),
        safety_verifier_profile_ref: safety.verifier_profile_ref_v0(),
        safety_revision: safety.revision_v0(),
        safety_state_record_checksum: safety.state_record_checksum_v0(),
        safety_record_chain_checksum: safety.chain_checksum_v0(),
        application_host_config_ref: app_owner,
        application_projection_profile_ref: projection,
        application_safety_binding_manifest_checksum: safety_binding,
        application_committed_head_row_checksum: head_row,
        application_recovery_closure_checksum: closure,
        application_block_id: core.genesis_block_id(),
        application_height: 0,
        application_state_root: trnm_consensus_types::StateRoot::new(*head.state_root().as_bytes()),
        application_view: 0,
        application_timestamp_ms: core.trusted_genesis_timestamp_ms(),
        signer_journal_id: signer.journal_id(),
        signer_profile_checksum: signer.profile_checksum(),
        signer_exact_watermark: signer.exact_watermark(),
    })
    .map_err(|error| PocoNodeLabAuthorityErrorV0::AuthorityChain(error.to_string()))
}

fn lab_genesis_hash_v0(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
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

fn authority_chain_error_v0(
    error: PocoNodeNativeProposalPHostErrorV0<NativeApplicationExecutionErrorV0>,
) -> PocoNodeLabAuthorityErrorV0 {
    PocoNodeLabAuthorityErrorV0::AuthorityChain(error.to_string())
}

#[derive(Debug)]
pub enum PocoNodeLabAuthorityErrorV0 {
    InvalidBootstrap(&'static str),
    UnexpectedEffect(&'static str),
    PersistenceNotApplied(&'static str),
    AuthorityChain(String),
    Core(CoreError),
    Safety(SafetyStoreErrorV0),
    Signer(SignerJournalErrorV0),
    Checkpoint(ExternalNodeCheckpointStoreErrorV0),
}

impl fmt::Display for PocoNodeLabAuthorityErrorV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidBootstrap(reason) => write!(formatter, "invalid lab bootstrap: {reason}"),
            Self::UnexpectedEffect(reason) => write!(formatter, "unexpected Core effect: {reason}"),
            Self::PersistenceNotApplied(stage) => {
                write!(
                    formatter,
                    "lab persistence did not apply after retry: {stage}"
                )
            }
            Self::AuthorityChain(reason) => write!(formatter, "native authority chain: {reason}"),
            Self::Core(error) => write!(formatter, "Core: {error}"),
            Self::Safety(error) => write!(formatter, "SafetyStore: {error}"),
            Self::Signer(error) => write!(formatter, "signer journal: {error}"),
            Self::Checkpoint(error) => write!(formatter, "whole-node checkpoint: {error}"),
        }
    }
}

impl Error for PocoNodeLabAuthorityErrorV0 {}
