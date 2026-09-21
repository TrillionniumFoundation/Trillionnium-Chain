//! Concrete continuing-author activation at the exact initial full14E cut.
//! The owner retains every physical store and never returns its Core or signer.
use crate::{
    epoch_node_checkpoint_v1::*, ConfirmedRetiredEpochNodeCheckpointV1, ExternalNodeCheckpointV0,
    SqliteEpochNodeCheckpointStoreV1,
};
use anyhow::{ensure, Context, Result};
use sha2::{Digest, Sha256};
use trnm_consensus_core::{
    native_valid_result_checksum_v0, BlockIdOverlayRefV0, CoreIssuedApplicationSealAuthorityV0,
    Effect, Input, PayloadValidationRequest, PendingEpochHostDriverV1,
    PreparedEpochCoreActivationV1, SignIntent,
};
use trnm_consensus_safety_store::{
    ConfirmedEpochSafetyHeadV1, EpochSafetyHeadPinV1, NativeValidHostManifestV0,
    NativeValidTransitionV0, SafetyTransitionContextV0, SqliteEpochSafetyJournalV1,
};
use trnm_consensus_signer_journal::{
    ConfirmedOrdinarySignerRetirementV1, ExternalMonotonicWatermarkV0, ExternalSignerRetirementV1,
    RetiredSqliteSignerJournalV1, SqliteSignerJournalV0,
};
use trnm_consensus_types::{
    decode_application_payload_v0_exact, decode_double_vote_evidence_v0_exact, BlockBodyV0,
    BlockId, BlockKind, CanonicalSignIntentV0, CanonicalSignable, SignedProposalV0,
};
use trnm_native_execution_v0::{
    AuthenticatedEpochApplicationEdgeV1, DurableExecutionHistoryStatusV0,
    DurableNativeApplicationV0, PreparedNativeEpochExecutionV1,
};

struct PendingEpochCommitV1 {
    prepared: PreparedNativeEpochExecutionV1,
    overlay_digest: [u8; 32],
    epoch: u64,
    view: u64,
    timestamp_ms: u64,
}

/// Ordered phases of the candidate first-new execution owner.
///
/// This is a read-only projection of the real owner state.  It is intentionally
/// separate from Safety14 and cannot mint an activation, signer lease, or Core
/// authority.  The transition methods below require the predecessor phase before
/// consuming their one-shot operation, so a stale or partially reconstructed
/// owner cannot skip proposal admission, native P/D/C, or persist-before-sign.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirstNewEpochPhaseV1 {
    /// The authenticated edge is installed and no first-new obligation exists.
    Activated,
    /// Core has durably retained exactly one first-new payload-validation request.
    ProposalAdmitted,
    /// Native P and Core D/Safety C are durable; the exact Vote is pending.
    NativePrepared,
    /// The Vote has been durably signed/released; strict K/finality is pending.
    VoteReleased,
    /// Native K and the independent application checkpoint both name C+3.
    Committed,
}

/// Exact owner readback for a progressed first-new proposal after a process
/// crash.  This is deliberately a read-only receipt: it does not recreate a
/// Core driver or release a pending vote.  A caller must still run the
/// dedicated progressed-obligation replay before resuming any signing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProgressedEpochRecoveryReadbackV1 {
    pub block_id: [u8; 32],
    pub safety_revision: u64,
    pub p_sequence: u64,
    pub p_digest: [u8; 32],
    pub artifact_digest: [u8; 32],
}

/// Exact readback of the first-new proposal validation cut before native P.
///
/// This is intentionally an inert receipt.  The compact Safety record retains
/// the complete proposal obligation, but does not by itself authorize a
/// callback, application execution, vote, or signer lease after a restart.
/// A later authenticated body/WAL replay protocol must consume this receipt
/// before any resumed validation can be admitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PendingEpochValidationRecoveryReadbackV1 {
    pub block_id: [u8; 32],
    pub safety_revision: u64,
    pub validation_view: u64,
    pub validation_generation: u64,
    pub proposal_root: [u8; 32],
}

/// Candidate activation owns the live continuing author, including virgin new
/// custody. No unchecked Core/input forwarding, raw signer handle or signing
/// callback is exposed. Ordinary event driving is a separate checked method.
///
/// ```compile_fail
/// use trnm_poco_node::CandidateEpochRuntimeV1;
/// use trnm_consensus_signer_journal::{ExternalSignerRetirementV1, ExternalMonotonicWatermarkV0};
/// fn require_clone<T: Clone>() {}
/// fn duplicate<W: ExternalSignerRetirementV1, N: ExternalMonotonicWatermarkV0>() {
///     require_clone::<CandidateEpochRuntimeV1<W, N>>();
/// }
/// ```
pub struct CandidateEpochRuntimeV1<W: ExternalSignerRetirementV1, N: ExternalMonotonicWatermarkV0> {
    driver: PendingEpochHostDriverV1,
    journal: SqliteEpochSafetyJournalV1,
    pin: EpochSafetyHeadPinV1,
    application: DurableNativeApplicationV0,
    edge: AuthenticatedEpochApplicationEdgeV1,
    retired: RetiredSqliteSignerJournalV1<W>,
    retirement: ConfirmedOrdinarySignerRetirementV1,
    ordinary: SqliteSignerJournalV0<N>,
    checkpoint_store: SqliteEpochNodeCheckpointStoreV1,
    checkpoint: EpochNodeCheckpointV1,
    origin: ExternalNodeCheckpointV0,
    startup: Vec<Effect>,
    /// One process-local Core-issued authority retained by the private native
    /// application host for every validation generation.
    seal_authority: CoreIssuedApplicationSealAuthorityV0,
    /// The one native P that passed Core D and Safety C.  It is retained until
    /// the strict first-new finality proof commits K; dropping it would make a
    /// later finality callback unable to bind itself to the validated block.
    pending_epoch_commit: Option<PendingEpochCommitV1>,
    /// Core's one live validation request after proposal admission. It is
    /// consumed only by `execute_admitted_epoch_proposal_v1`, which joins the
    /// request to a fresh native P readback and the retained Core seal
    /// authority; a request digest alone cannot unlock a vote.
    pending_validation: Option<PayloadValidationRequest>,
    fenced: bool,
}

fn epoch_transition_digest(domain: &str, parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"trnm.poco-node.epoch-native-valid.v1");
    hasher.update((domain.len() as u64).to_be_bytes());
    hasher.update(domain.as_bytes());
    for part in parts {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part);
    }
    hasher.finalize().into()
}
impl<W: ExternalSignerRetirementV1, N: ExternalMonotonicWatermarkV0> CandidateEpochRuntimeV1<W, N> {
    /// Return the exact first-new phase derived from live Core, native and
    /// checkpoint owners.  Inconsistent combinations are rejected rather than
    /// mapped to the nearest phase, because a phase tag is never authority.
    pub fn first_new_phase_v1(&self) -> Result<FirstNewEpochPhaseV1> {
        let application_parent_id = self.edge.application_parent().block_id();
        let application_parent = application_parent_id.as_bytes();
        let application_block = self.checkpoint.fields().application.block_id;
        let pending_sign = self.driver.state().pending_sign();
        let pending_finalize = self.driver.state().pending_finalize();
        let obligations = self.driver.state().payload_validation_obligations();

        if application_block != *application_parent {
            ensure!(
                self.pending_validation.is_none()
                    && self.pending_epoch_commit.is_none()
                    && pending_sign.is_none()
                    && pending_finalize.is_none()
                    && obligations.is_empty(),
                "committed first-new phase retains an unresolved Core obligation"
            );
            return Ok(FirstNewEpochPhaseV1::Committed);
        }

        if self.pending_validation.is_some() {
            ensure!(
                self.pending_epoch_commit.is_none()
                    && pending_sign.is_none()
                    && pending_finalize.is_none()
                    && obligations.len() == 1,
                "first-new proposal phase has an inconsistent Core obligation"
            );
            return Ok(FirstNewEpochPhaseV1::ProposalAdmitted);
        }

        if self.pending_epoch_commit.is_some() {
            ensure!(
                pending_finalize.is_none() && obligations.is_empty(),
                "first-new native phase retains an unresolved validation/finalize state"
            );
            return match pending_sign {
                Some(SignIntent::Vote { .. }) => Ok(FirstNewEpochPhaseV1::NativePrepared),
                None => Ok(FirstNewEpochPhaseV1::VoteReleased),
                Some(SignIntent::TimeoutVote { .. }) => Err(anyhow::anyhow!(
                    "first-new native phase retained a timeout instead of the exact Vote"
                )),
            };
        }

        ensure!(
            pending_sign.is_none() && pending_finalize.is_none() && obligations.is_empty(),
            "activated first-new phase retains an unresolved Core obligation"
        );
        Ok(FirstNewEpochPhaseV1::Activated)
    }

    fn require_first_new_phase_v1(&self, expected: FirstNewEpochPhaseV1) -> Result<()> {
        let actual = self.first_new_phase_v1()?;
        ensure!(
            actual == expected,
            "first-new phase ordering: expected {expected:?}, observed {actual:?}"
        );
        Ok(())
    }

    /// Consume every actual owner. The exact journal9/native/original retirement/
    /// new virgin custody cut is checked before and after the independent schema2
    /// migration and sync. Only then does the private driver receive its ACK.
    #[allow(clippy::too_many_arguments)]
    pub fn activate_continuing_v1(
        prepared: PreparedEpochCoreActivationV1,
        journal: SqliteEpochSafetyJournalV1,
        pin: EpochSafetyHeadPinV1,
        application: DurableNativeApplicationV0,
        edge: AuthenticatedEpochApplicationEdgeV1,
        mut retired: RetiredSqliteSignerJournalV1<W>,
        retired_checkpoint: ConfirmedRetiredEpochNodeCheckpointV1,
        mut ordinary: SqliteSignerJournalV0<N>,
    ) -> Result<Self> {
        ensure!(
            retired_checkpoint.belongs_to_retired_owner_v1(&mut retired),
            "retired checkpoint owner changed"
        );
        let origin = *retired_checkpoint.checkpoint_v1();
        let mut driver = prepared.into_candidate_host_pending_v1();
        let retirement = retired.confirm_retirement_v1()?;
        let target = join_initial(
            &driver,
            &journal,
            pin,
            &application,
            &edge,
            &mut retired,
            &retirement,
            &mut ordinary,
            &origin,
        )?;
        // Consume the typed retirement checkpoint only after every other join.
        // A failed or uncertain migration drops all live owners with this call.
        let old_store = retired_checkpoint.into_epoch_lineage_source_v1(&mut retired)?;
        let mut checkpoint_store =
            SqliteEpochNodeCheckpointStoreV1::migrate_continuing_v0(old_store, &origin, &target)?;
        ensure!(
            join_initial(
                &driver,
                &journal,
                pin,
                &application,
                &edge,
                &mut retired,
                &retirement,
                &mut ordinary,
                &origin
            )? == target,
            "owners changed after composite persistence"
        );
        checkpoint_store.confirm_exact(&target)?;
        let startup = ack_initial(&mut driver)?;
        let seal_authority = driver
            .issue_application_seal_authority_v1()
            .map_err(|e| anyhow::anyhow!("epoch seal authority: {e:?}"))?;
        Ok(Self {
            driver,
            journal,
            pin,
            application,
            edge,
            retired,
            retirement,
            ordinary,
            checkpoint_store,
            checkpoint: target,
            origin,
            startup,
            seal_authority,
            pending_epoch_commit: None,
            pending_validation: None,
            fenced: false,
        })
    }

    /// Recover only the exact initial activation cut from independently expected
    /// schema2 bytes. Progressed Safety or signer decisions reject until their
    /// dedicated whole-owner replay protocol is implemented.
    #[allow(clippy::too_many_arguments)]
    pub fn recover_initial_continuing_v1(
        mut journal: SqliteEpochSafetyJournalV1,
        application: DurableNativeApplicationV0,
        edge: AuthenticatedEpochApplicationEdgeV1,
        mut retired: RetiredSqliteSignerJournalV1<W>,
        mut ordinary: SqliteSignerJournalV0<N>,
        mut checkpoint_store: SqliteEpochNodeCheckpointStoreV1,
        expected: EpochNodeCheckpointV1,
    ) -> Result<Self> {
        ensure!(
            expected.fields().phase == EpochCheckpointPhaseV1::ActivationCommitted
                && expected.fields().role == EpochCheckpointRoleV1::Continuing
                && expected.fields().predecessor_kind == EpochCheckpointPredecessorV1::TerminalV0,
            "unsupported recovery phase"
        );
        checkpoint_store.confirm_exact(&expected)?;
        let origin = checkpoint_store.original_v0(&expected)?;
        let cut = expected.fields().target_safety;
        let pin = EpochSafetyHeadPinV1 {
            journal_id: cut.journal_id,
            revision: cut.revision,
            chain_checksum: cut.chain_checksum,
        };
        let (_, mut driver) = journal.prepare_candidate_host_initial_recovery_v1(pin)?;
        let retirement = retired.confirm_retirement_v1()?;
        ensure!(
            join_initial(
                &driver,
                &journal,
                pin,
                &application,
                &edge,
                &mut retired,
                &retirement,
                &mut ordinary,
                &origin
            )? == expected,
            "recovered owners differ from independent activation checkpoint"
        );
        checkpoint_store.confirm_exact(&expected)?;
        ensure!(
            join_initial(
                &driver,
                &journal,
                pin,
                &application,
                &edge,
                &mut retired,
                &retirement,
                &mut ordinary,
                &origin
            )? == expected,
            "recovered owners changed before ACK"
        );
        let startup = ack_initial(&mut driver)?;
        let seal_authority = driver
            .issue_application_seal_authority_v1()
            .map_err(|e| anyhow::anyhow!("epoch seal authority recovery: {e:?}"))?;
        Ok(Self {
            driver,
            journal,
            pin,
            application,
            edge,
            retired,
            retirement,
            ordinary,
            checkpoint_store,
            checkpoint: expected,
            origin,
            startup,
            seal_authority,
            pending_epoch_commit: None,
            pending_validation: None,
            fenced: false,
        })
    }

    /// Reconcile a crash after first-new P/D/C and before native K.
    ///
    /// The journal9 state and native P are independently durable at this cut,
    /// but the Core driver intentionally cannot be recreated by guessing an
    /// outbox or by treating a checkpoint scalar as authority.  This method
    /// therefore performs the complete owner-affine readback and returns a
    /// typed receipt while leaving all owners unbound and unable to sign.  A
    /// future progressed-obligation replay may consume this receipt after it
    /// has independently revalidated the proposal and finality proof.
    #[allow(clippy::too_many_arguments)]
    pub fn recover_progressed_obligation_readback_v1(
        journal: SqliteEpochSafetyJournalV1,
        application: DurableNativeApplicationV0,
        edge: AuthenticatedEpochApplicationEdgeV1,
        mut retired: RetiredSqliteSignerJournalV1<W>,
        mut ordinary: SqliteSignerJournalV0<N>,
        mut checkpoint_store: SqliteEpochNodeCheckpointStoreV1,
        expected: EpochNodeCheckpointV1,
        block_id: [u8; 32],
    ) -> Result<ProgressedEpochRecoveryReadbackV1> {
        ensure!(
            expected.fields().phase == EpochCheckpointPhaseV1::Ordinary
                && expected.fields().role == EpochCheckpointRoleV1::Continuing
                && expected.fields().predecessor_kind == EpochCheckpointPredecessorV1::V1,
            "progressed recovery requires an ordinary V1 checkpoint"
        );
        ensure!(
            expected.fields().application.block_id
                == *edge.application_parent().block_id().as_bytes(),
            "progressed recovery requires the pre-K application checkpoint"
        );
        checkpoint_store.confirm_exact(&expected)?;
        let app = expected.fields().application;
        let pin = EpochSafetyHeadPinV1 {
            journal_id: expected.fields().target_safety.journal_id,
            revision: expected.fields().target_safety.revision,
            chain_checksum: expected.fields().target_safety.chain_checksum,
        };
        let (confirmed, recovery) = journal.prepare_recovery_v1(pin)?;
        ensure!(
            confirmed.state_v1() == recovery.state(),
            "recovered Safety state changed during strict reconstruction"
        );
        let state = recovery.state();
        ensure!(
            state.payload_validation_obligations().is_empty()
                && state.pending_finalize().is_none()
                && matches!(
                    state.pending_sign(),
                    Some(SignIntent::Vote {
                        block_id: pending_block,
                        ..
                    }) if *pending_block == trnm_consensus_types::BlockId::new(block_id)
                ),
            "progressed recovery does not contain the exact post-C vote obligation"
        );
        ensure!(
            confirmed.state_record_checksum_v1() == expected.fields().target_safety.record_checksum
                && confirmed.revision_v1() == expected.fields().target_safety.revision
                && confirmed.belongs_to_store_at_path_v1(&journal, journal.path_v1()),
            "recovered Safety cut differs from the independent checkpoint"
        );

        let prepared = application.reopen_prepared_epoch_execution_v1(block_id)?;
        let p = application.confirm_prepared_epoch_execution_v1(&prepared)?;
        let header = p.prepared().header()?;
        ensure!(
            header.id().as_bytes() == &block_id
                && header.block_kind() == BlockKind::EpochHandoff
                && header.height().get() == edge.first_application_height()
                && p.prepared().application_parent() == edge.application_parent(),
            "recovered native P differs from the authenticated first-new edge"
        );
        ensure!(
            application.confirmed_committed_head_v0()? == *edge.application_parent(),
            "native K unexpectedly advanced before progressed recovery"
        );
        let native = application.confirm_epoch_application_edge_v1(&edge)?;
        let row = native.durable_checkpoint();
        let head = row.target_head_v0()?;
        ensure!(
            native.strict_activation_binding_v1().as_bytes()
                == &expected.fields().phase_authority_binding
                && row.p_digest_v0() == app.p_digest
                && row.artifact_digest_v0() == app.artifact_digest
                && row.overlay_digest_v0() == app.overlay_digest
                && row.p_sequence_v0() == app.p_sequence
                && row.commit_sequence_v0() == Some(app.commit_sequence)
                && row.store_id_v0() == app.native_store_id
                && head.block_id().as_bytes() == &app.block_id
                && head.state_root().as_bytes() == &app.state_root
                && head.commit_id().as_bytes() == &app.native_commit_id
                && head.height().get() == app.height
                && native.belongs_to_application_at_path(&application, application.path()),
            "recovered native pre-K checkpoint changed"
        );

        let retirement = retired.confirm_retirement_v1()?;
        ensure!(
            retirement.belongs_to_owner_v1(&mut retired)
                && retirement.record_v1().checksum_v1()
                    == expected
                        .fields()
                        .retired
                        .context("missing retired custody")?
                        .retirement_record_checksum,
            "recovered retired custody changed"
        );
        let signer = ordinary.confirm_node_checkpoint_head_exact_v0()?;
        let mark = signer.exact_watermark();
        let expected_ordinary = expected
            .fields()
            .ordinary
            .context("missing ordinary custody")?;
        ensure!(
            signer.belongs_to_operational_journal_at_path_v0(&ordinary, ordinary.path())
                && mark.scope() == expected_ordinary.scope
                && mark.journal_id() == expected_ordinary.journal_id
                && signer.profile_checksum() == expected_ordinary.profile_checksum
                && signer.pending_intent().is_none(),
            "recovered ordinary custody changed"
        );
        checkpoint_store.confirm_exact(&expected)?;
        Ok(ProgressedEpochRecoveryReadbackV1 {
            block_id,
            safety_revision: confirmed.revision_v1(),
            p_sequence: p.prepared().persist_sequence(),
            p_digest: p.prepared().p_digest(),
            artifact_digest: p.prepared().artifact_digest(),
        })
    }

    /// Reconcile a crash after first-new proposal admission and before native
    /// P.  This cut has one durable Core payload-validation obligation and the
    /// old application head; it must never be mistaken for a permission to
    /// recreate the validation callback or a proposal vote.  The complete
    /// proposal is authenticated by the journal's strict epoch-record
    /// recovery, then joined to every custody owner and the independent
    /// checkpoint.  The returned receipt is comparison evidence only.
    #[allow(clippy::too_many_arguments)]
    pub fn recover_pending_epoch_validation_readback_v1(
        journal: SqliteEpochSafetyJournalV1,
        application: DurableNativeApplicationV0,
        edge: AuthenticatedEpochApplicationEdgeV1,
        mut retired: RetiredSqliteSignerJournalV1<W>,
        mut ordinary: SqliteSignerJournalV0<N>,
        mut checkpoint_store: SqliteEpochNodeCheckpointStoreV1,
        expected: EpochNodeCheckpointV1,
        block_id: [u8; 32],
    ) -> Result<PendingEpochValidationRecoveryReadbackV1> {
        ensure!(
            expected.fields().phase == EpochCheckpointPhaseV1::Ordinary
                && expected.fields().role == EpochCheckpointRoleV1::Continuing
                && expected.fields().predecessor_kind == EpochCheckpointPredecessorV1::V1,
            "pending validation recovery requires an ordinary V1 checkpoint"
        );
        ensure!(
            expected.fields().application.block_id
                == *edge.application_parent().block_id().as_bytes(),
            "pending validation recovery requires the pre-P application checkpoint"
        );
        checkpoint_store.confirm_exact(&expected)?;
        let app = expected.fields().application;
        let pin = EpochSafetyHeadPinV1 {
            journal_id: expected.fields().target_safety.journal_id,
            revision: expected.fields().target_safety.revision,
            chain_checksum: expected.fields().target_safety.chain_checksum,
        };
        let (confirmed, recovery) = journal.prepare_recovery_v1(pin)?;
        ensure!(
            confirmed.state_v1() == recovery.state(),
            "recovered Safety state changed during strict reconstruction"
        );
        let state = recovery.state();
        let [obligation] = state.payload_validation_obligations() else {
            anyhow::bail!("pending validation recovery requires exactly one durable obligation");
        };
        ensure!(
            obligation.route() == trnm_consensus_core::PayloadValidationRouteV0::Proposal
                && obligation.proposal().block().id().as_bytes() == &block_id
                && obligation.proposal().block().header().epoch()
                    == edge.new_validator_set().epoch()
                && obligation.proposal().block().header().block_kind() == BlockKind::EpochHandoff
                && obligation.proposal().block().header().height().get()
                    == edge.first_application_height()
                && obligation.first_recorded_revision() == expected.fields().target_safety.revision
                && state.pending_sign().is_none()
                && state.pending_finalize().is_none()
                && state.payload_validation_completions().is_empty(),
            "recovered validation obligation differs from the exact first-new cut"
        );
        ensure!(
            confirmed.state_record_checksum_v1() == expected.fields().target_safety.record_checksum
                && confirmed.revision_v1() == expected.fields().target_safety.revision
                && confirmed.belongs_to_store_at_path_v1(&journal, journal.path_v1()),
            "recovered Safety validation cut differs from the independent checkpoint"
        );
        ensure!(
            application.confirmed_committed_head_v0()? == *edge.application_parent(),
            "native application advanced before pending validation recovery"
        );
        ensure!(
            edge.durable_checkpoint()
                .belongs_to_application_at_path_v0(&application, application.path(),),
            "native activation edge owner changed"
        );
        ensure!(
            edge.strict_activation_binding_v1()? == expected.fields().phase_authority_binding
                && edge.durable_checkpoint().p_digest_v0() == app.p_digest
                && edge.durable_checkpoint().artifact_digest_v0() == app.artifact_digest
                && edge.durable_checkpoint().overlay_digest_v0() == app.overlay_digest
                && edge.durable_checkpoint().p_sequence_v0() == app.p_sequence
                && edge.durable_checkpoint().commit_sequence_v0() == Some(app.commit_sequence)
                && edge
                    .durable_checkpoint()
                    .target_head_v0()?
                    .block_id()
                    .as_bytes()
                    == &app.block_id,
            "native pre-P checkpoint changed"
        );

        let retirement = retired.confirm_retirement_v1()?;
        ensure!(
            retirement.belongs_to_owner_v1(&mut retired)
                && retirement.record_v1().checksum_v1()
                    == expected
                        .fields()
                        .retired
                        .context("missing retired custody")?
                        .retirement_record_checksum,
            "recovered retired custody changed"
        );
        let signer = ordinary.confirm_node_checkpoint_head_exact_v0()?;
        let mark = signer.exact_watermark();
        let expected_ordinary = expected
            .fields()
            .ordinary
            .context("missing ordinary custody")?;
        ensure!(
            signer.belongs_to_operational_journal_at_path_v0(&ordinary, ordinary.path())
                && mark.scope() == expected_ordinary.scope
                && mark.journal_id() == expected_ordinary.journal_id
                && signer.profile_checksum() == expected_ordinary.profile_checksum
                && signer.pending_intent().is_none(),
            "recovered ordinary custody changed"
        );
        checkpoint_store.confirm_exact(&expected)?;
        Ok(PendingEpochValidationRecoveryReadbackV1 {
            block_id,
            safety_revision: confirmed.revision_v1(),
            validation_view: obligation.id().view().get(),
            validation_generation: obligation.id().generation(),
            proposal_root: *obligation.proposal().proposal_signing_root().as_bytes(),
        })
    }

    /// Sign the first new-epoch timeout through three physical checkpoints:
    /// pending intent, signed journal, and released Safety outbox. Every failure
    /// consumes all owners; no broadcast can escape a failed persistence cut.
    pub fn sign_initial_timeout_v1<P: trnm_consensus_signer_journal::SignatureProducerV0>(
        mut self,
        producer: &mut P,
    ) -> Result<(Self, trnm_consensus_types::TimeoutVote)> {
        self.confirm_initial_activation_v1()?;
        let effects = self
            .driver
            .step_v1(Input::LocalTimeout {
                epoch: self.driver.config().validator_set().epoch(),
                view: trnm_consensus_types::View::new(1),
            })
            .map_err(|e| anyhow::anyhow!("initial timeout: {e:?}"))?;
        let [Effect::PersistSafetyState(request)] = effects.as_slice() else {
            anyhow::bail!("timeout did not persist one signing obligation");
        };
        let head = self.journal.persist_exact_v1(
            self.pin,
            request,
            &SafetyTransitionContextV0::ordinary(),
        )?;
        self.pin = head.pin_v1();
        let ordinary = self
            .checkpoint
            .fields()
            .ordinary
            .context("missing live ordinary cut")?;
        self.advance_exact_cut_v1(safety_cut(&head), ordinary)?;
        self.journal.confirm_exact_request_v1(
            self.pin,
            request,
            &SafetyTransitionContextV0::ordinary(),
        )?;
        let released = self
            .driver
            .step_v1(Input::StorageAck {
                barrier: request.barrier(),
            })
            .map_err(|e| anyhow::anyhow!("timeout persistence ACK: {e:?}"))?;
        let [Effect::RequestSignature { intent }] = released.as_slice() else {
            anyhow::bail!("timeout ACK did not yield exactly one intent");
        };
        ensure!(
            matches!(
                intent.preimage(),
                trnm_consensus_types::CanonicalSignPreimageV0::TimeoutVote(_)
            ) && intent.authorizing_safety_revision() == self.pin.revision,
            "unexpected timeout intent"
        );
        self.confirm_current_cut_v1()?;
        let before = self.ordinary.confirm_node_checkpoint_head_exact_v0()?;
        // The journal calls its external service again while reserving the
        // intent. Recheck the other physical owners at the actual key boundary,
        // after those callbacks, and again before returning the signature.
        let mut guarded = FreshEpochSignatureProducerV1 {
            producer,
            expected: intent,
            confirm: || {
                confirm_key_owners_v1(
                    &self.driver,
                    &self.journal,
                    self.pin,
                    &self.application,
                    &self.edge,
                    &mut self.retired,
                    &self.retirement,
                    &mut self.checkpoint_store,
                    &self.checkpoint,
                    EpochKeyProvenanceV5::Timeout,
                )
            },
        };
        let signature = self.ordinary.sign_exact_v0(intent, &mut guarded)?;
        let after = self.ordinary.confirm_node_checkpoint_head_exact_v0()?;
        ensure!(
            before.exact_watermark().sequence().checked_add(2)
                == Some(after.exact_watermark().sequence())
                && before.journal_id() == after.journal_id()
                && before.profile_checksum() == after.profile_checksum()
                && after.pending_intent().is_none(),
            "signature did not persist exact one journal pair"
        );
        let mark = after.exact_watermark();
        let signed_cut = EpochOrdinaryCustodyCutV1 {
            scope: mark.scope(),
            journal_id: mark.journal_id(),
            profile_checksum: after.profile_checksum(),
            sequence: mark.sequence(),
            chain_checksum: mark.chain_checksum(),
        };
        self.advance_exact_cut_v1(self.checkpoint.fields().target_safety, signed_cut)?;
        self.confirm_current_cut_v1()?;
        let signed_state = self.driver.state().clone();
        let outbound = self
            .driver
            .step_v1(Input::SignatureReady {
                id: trnm_consensus_core::SignId::new(intent.signing_root()),
                signature,
            })
            .map_err(|e| anyhow::anyhow!("timeout signature delivery: {e:?}"))?;
        let [Effect::Broadcast(trnm_consensus_core::OutboundMessage::TimeoutVote(vote))] =
            outbound.as_slice()
        else {
            anyhow::bail!("timeout signature yielded unexpected effect");
        };
        vote.verify(
            self.driver.config().validator_set(),
            &trnm_consensus_crypto::StrictEd25519Verifier,
        )
        .map_err(|e| anyhow::anyhow!("timeout verification: {e:?}"))?;
        ensure!(
            vote.author() == intent.author()
                && vote.signing_root() == intent.signing_root()
                && vote.signature() == &signature
                && self.driver.state().pending_sign().is_none(),
            "released timeout differs from persisted signature"
        );
        let effects = self
            .driver
            .persist_signature_release_v1(&signed_state)
            .map_err(|e| anyhow::anyhow!("signature release persistence: {e:?}"))?;
        let [Effect::PersistSafetyState(request)] = effects.as_slice() else {
            anyhow::bail!("release did not persist one Safety cut");
        };
        let head = self.journal.persist_exact_v1(
            self.pin,
            request,
            &SafetyTransitionContextV0::ordinary(),
        )?;
        self.pin = head.pin_v1();
        self.advance_exact_cut_v1(safety_cut(&head), signed_cut)?;
        self.journal.confirm_exact_request_v1(
            self.pin,
            request,
            &SafetyTransitionContextV0::ordinary(),
        )?;
        let ack = self
            .driver
            .step_v1(Input::StorageAck {
                barrier: request.barrier(),
            })
            .map_err(|e| anyhow::anyhow!("signature release ACK: {e:?}"))?;
        ensure!(
            ack.is_empty(),
            "signature release ACK yielded new authority"
        );
        self.confirm_current_cut_v1()?;
        self.startup.clear();
        Ok((self, vote.clone()))
    }
    fn advance_exact_cut_v1(
        &mut self,
        safety: EpochSafetyCutV1,
        ordinary: EpochOrdinaryCustodyCutV1,
    ) -> Result<()> {
        let application = self.checkpoint.fields().application;
        self.advance_exact_cut_with_application_v1(safety, ordinary, application)
    }
    fn advance_exact_cut_with_application_v1(
        &mut self,
        safety: EpochSafetyCutV1,
        ordinary: EpochOrdinaryCustodyCutV1,
        application: EpochApplicationCutV1,
    ) -> Result<()> {
        self.checkpoint_store.confirm_exact(&self.checkpoint)?;
        let application_changed = application != self.checkpoint.fields().application;
        if !application_changed {
            ensure!(
                self.fresh_current_cuts_v1()? == (safety, ordinary),
                "physical cut differs before CAS"
            );
        } else {
            // The native commit is already durable, while the independent
            // node checkpoint still names its predecessor.  Validate every
            // non-application owner before publishing the successor CAS.
            ensure!(
                self.fresh_custody_cuts_v1()? == (safety, ordinary),
                "physical custody differs before application CAS"
            );
        }
        let mut f = *self.checkpoint.fields();
        f.phase = EpochCheckpointPhaseV1::Ordinary;
        f.predecessor_kind = EpochCheckpointPredecessorV1::V1;
        f.generation = f
            .generation
            .checked_add(1)
            .context("checkpoint generation exhausted")?;
        f.predecessor_checksum = self.checkpoint.checksum();
        f.target_safety = safety;
        f.ordinary = Some(ordinary);
        f.application = application;
        let next = EpochNodeCheckpointV1::new(f)?;
        self.checkpoint_store
            .compare_and_advance(&self.checkpoint, &next)?;
        self.checkpoint = next;
        if application_changed {
            self.confirm_current_cut_after_application_v1()
        } else {
            self.confirm_current_cut_v1()
        }
    }
    fn confirm_current_cut_v1(&mut self) -> Result<()> {
        ensure!(!self.fenced, "epoch runtime fenced");
        self.checkpoint_store.confirm_exact(&self.checkpoint)?;
        ensure!(
            self.fresh_current_cuts_v1()?
                == (
                    self.checkpoint.fields().target_safety,
                    self.checkpoint
                        .fields()
                        .ordinary
                        .context("missing active custody")?
                ),
            "live cut differs from independent checkpoint"
        );
        self.checkpoint_store.confirm_exact(&self.checkpoint)?;
        Ok(())
    }
    fn fresh_current_cuts_v1(&mut self) -> Result<(EpochSafetyCutV1, EpochOrdinaryCustodyCutV1)> {
        let (safety, ordinary) = self.fresh_custody_cuts_v1()?;
        confirm_native_application_cut_v3(&self.application, &self.edge, &self.checkpoint)?;
        Ok((safety, ordinary))
    }

    /// Freshly confirms the independent checkpoint after native K has moved
    /// the application head to the first committed block of the new epoch.
    /// The activation edge intentionally still names the predecessor head,
    /// so `confirm_epoch_application_edge_v1` cannot be reused here.  This
    /// read joins the exact checkpoint block to the fully revalidated native
    /// committed row while retaining the same owner/path and activation
    /// binding checks as the pre-K confirmation.
    fn confirm_current_cut_after_application_v1(&mut self) -> Result<()> {
        ensure!(!self.fenced, "epoch runtime fenced");
        self.checkpoint_store.confirm_exact(&self.checkpoint)?;
        ensure!(
            self.fresh_custody_cuts_v1()?
                == (
                    self.checkpoint.fields().target_safety,
                    self.checkpoint
                        .fields()
                        .ordinary
                        .context("missing active custody")?
                ),
            "live custody differs from independent checkpoint"
        );
        confirm_native_application_cut_v3(&self.application, &self.edge, &self.checkpoint)?;
        self.checkpoint_store.confirm_exact(&self.checkpoint)?;
        Ok(())
    }

    /// Read the Safety, retired custody and ordinary signer cuts without
    /// consulting the application head.  K uses this between the durable
    /// native commit and the independent checkpoint CAS: at that instant the
    /// application has intentionally advanced while the checkpoint still
    /// names the old committed head.
    fn fresh_custody_cuts_v1(&mut self) -> Result<(EpochSafetyCutV1, EpochOrdinaryCustodyCutV1)> {
        let safety = self.journal.fresh_read_v1(self.pin)?;
        ensure!(
            safety.state_v1() == self.driver.state()
                && safety.belongs_to_store_at_path_v1(&self.journal, self.journal.path_v1()),
            "current Safety owner mismatch"
        );
        ensure!(
            self.retirement.belongs_to_owner_v1(&mut self.retired)
                && self.retirement.record_v1().checksum_v1()
                    == self
                        .checkpoint
                        .fields()
                        .retired
                        .context("missing original retirement")?
                        .retirement_record_checksum,
            "retired custody changed"
        );
        let signer = self.ordinary.confirm_node_checkpoint_head_exact_v0()?;
        let mark = signer.exact_watermark();
        let expected = self
            .checkpoint
            .fields()
            .ordinary
            .context("missing ordinary custody")?;
        ensure!(
            signer.belongs_to_operational_journal_at_path_v0(&self.ordinary, self.ordinary.path())
                && mark.scope() == expected.scope
                && mark.journal_id() == expected.journal_id
                && signer.profile_checksum() == expected.profile_checksum
                && self.ordinary.profile().validator_set() == self.driver.config().validator_set()
                && self.ordinary.profile().author() == self.driver.config().local_validator()
                && signer.pending_intent().is_none(),
            "ordinary custody changed or has unresolved decision"
        );
        Ok((
            safety_cut(&safety),
            EpochOrdinaryCustodyCutV1 {
                scope: mark.scope(),
                journal_id: mark.journal_id(),
                profile_checksum: signer.profile_checksum(),
                sequence: mark.sequence(),
                chain_checksum: mark.chain_checksum(),
            },
        ))
    }

    /// Freshly revalidate the exact initial cut; comparison bytes grant no lease.
    pub fn confirm_initial_activation_v1(&mut self) -> Result<EpochNodeCheckpointV1> {
        ensure!(!self.fenced, "epoch candidate fenced");
        let result = (|| {
            self.checkpoint_store.confirm_exact(&self.checkpoint)?;
            ensure!(
                join_initial(
                    &self.driver,
                    &self.journal,
                    self.pin,
                    &self.application,
                    &self.edge,
                    &mut self.retired,
                    &self.retirement,
                    &mut self.ordinary,
                    &self.origin
                )? == self.checkpoint,
                "epoch initial owners changed"
            );
            self.checkpoint_store.confirm_exact(&self.checkpoint)?;
            Ok(self.checkpoint)
        })();
        if result.is_err() {
            self.fenced = true;
        }
        result
    }
    /// Startup may only contain the first-view timer, minted after the actual
    /// composite persistence barrier. It can be obtained once after fresh join.
    pub fn take_initial_timer_effects_v1(&mut self) -> Result<Vec<Effect>> {
        self.confirm_initial_activation_v1()?;
        Ok(std::mem::take(&mut self.startup))
    }

    /// Install or resume the native schema7 commit owner after the complete
    /// initial activation cut is joined. This adapter is candidate-only and
    /// remains detached from proposal, signing, and public sync paths; every
    /// retry rechecks all physical owners before returning.
    pub fn ensure_incremental_epoch_commit_owner_v1(&mut self) -> Result<()> {
        self.confirm_initial_activation_v1()?;
        self.application
            .ensure_incremental_epoch_commit_owner_v1(&self.edge)?;
        self.confirm_current_cut_v1()
    }

    /// Admit one authenticated proposal at the first new-epoch runtime
    /// boundary and durably persist Core's validation obligation.
    ///
    /// This method stops at the durable Core validation obligation. The
    /// follow-up execution method owns native P/D/C; callers must not
    /// synthesize a `PayloadValidated` result from header digests. A crash at
    /// this point leaves the Safety obligation durable and recovery remains
    /// fail-closed until the dedicated progressed-obligation protocol joins it.
    ///
    /// The operation consumes the runtime on error.  This prevents a caller
    /// from reusing a partially advanced Core/Safety owner after a failed
    /// persistence or checkpoint CAS.
    pub fn admit_epoch_proposal_v1(mut self, proposal: SignedProposalV0) -> Result<Self> {
        self.confirm_current_cut_v1()?;
        ensure!(
            self.checkpoint.fields().application.block_id
                == *self.edge.application_parent().block_id().as_bytes(),
            "first-new epoch crossing already committed; repeated crossing rejected"
        );
        ensure!(
            self.pending_validation.is_none(),
            "epoch proposal validation is already pending"
        );
        self.require_first_new_phase_v1(FirstNewEpochPhaseV1::Activated)?;
        ensure!(
            proposal.block().header().epoch() == self.driver.state().epoch(),
            "proposal belongs to a different epoch"
        );
        ensure!(
            proposal.block().header().block_kind() == BlockKind::EpochHandoff
                && proposal.block().header().height().get() == self.edge.first_application_height(),
            "proposal is not the exact first new-epoch application block"
        );
        ensure!(
            self.driver.state().pending_sign().is_none()
                && self.driver.state().pending_finalize().is_none()
                && self
                    .driver
                    .state()
                    .payload_validation_obligations()
                    .is_empty(),
            "epoch proposal admission requires a settled Core state"
        );

        let effects = self
            .driver
            .step_v1(Input::Proposal(Box::new(proposal)))
            .map_err(|error| anyhow::anyhow!("epoch proposal admission: {error:?}"))?;
        let [Effect::PersistSafetyState(request)] = effects.as_slice() else {
            anyhow::bail!("epoch proposal did not yield one Safety persistence barrier");
        };
        let head = self.journal.persist_exact_v1(
            self.pin,
            request,
            &SafetyTransitionContextV0::ordinary(),
        )?;
        self.pin = head.pin_v1();
        let ordinary = self
            .checkpoint
            .fields()
            .ordinary
            .context("missing live ordinary cut")?;
        self.advance_exact_cut_v1(safety_cut(&head), ordinary)?;
        self.journal.confirm_exact_request_v1(
            self.pin,
            request,
            &SafetyTransitionContextV0::ordinary(),
        )?;

        let released = self
            .driver
            .step_v1(Input::StorageAck {
                barrier: request.barrier(),
            })
            .map_err(|error| anyhow::anyhow!("epoch proposal validation ACK: {error:?}"))?;
        let mut validation = None;
        for effect in released {
            match effect {
                Effect::ValidatePayload(candidate) if validation.is_none() => {
                    validation = Some(candidate)
                }
                Effect::ArmViewTimer { .. } => {}
                _ => {
                    anyhow::bail!("epoch proposal admission yielded an unexpected post-ACK effect")
                }
            }
        }
        self.pending_validation =
            Some(validation.context("epoch proposal admission yielded no validation request")?);
        self.confirm_current_cut_v1()?;
        Ok(self)
    }

    /// Execute the exact admitted first-new proposal through the real native
    /// epoch owner and Core's typed D carrier. The native owner durably writes
    /// P and reads it back before the seal is minted; the Core carrier then
    /// supplies the exact NativeValid persistence request. Journal9 C is
    /// persisted with transition facts derived from the live request, P, D,
    /// and Core post-ack manifest, followed by the exact Core StorageAck. No
    /// signer is called here; the returned effects may contain the pending
    /// Core vote intent and must be handled by the separate persist-before-sign
    /// path.
    pub fn execute_admitted_epoch_proposal_v1(mut self) -> Result<(Self, Vec<Effect>)> {
        self.confirm_current_cut_v1()?;
        self.require_first_new_phase_v1(FirstNewEpochPhaseV1::ProposalAdmitted)?;
        ensure!(
            self.pending_epoch_commit.is_none(),
            "an admitted epoch P is already awaiting finality"
        );
        // The durable native epoch owner is deliberately entered through its
        // explicit schema-4 bridge.  This is a real migration from the
        // ordinary committed checkpoint, not an implicit open-time upgrade;
        // retrying after a crash is idempotent and still revalidates the
        // authenticated application parent.
        self.application
            .upgrade_epoch_schema_v1(self.edge.application_parent())?;
        self.confirm_current_cut_v1()?;
        let delivery = self.compute_admitted_epoch_valid_v2()?;
        let effects = self.persist_epoch_valid_delivery_v1(
            &delivery.accepted,
            &delivery.confirmed,
            delivery.route,
            delivery.validation_id,
        )?;
        let header = delivery.prepared.header()?;
        self.pending_epoch_commit = Some(PendingEpochCommitV1 {
            prepared: delivery.prepared,
            overlay_digest: delivery.confirmed.overlay_checksum(),
            epoch: header.epoch().get(),
            view: header.view().get(),
            timestamp_ms: header.timestamp_ms(),
        });
        self.confirm_current_cut_v1()?;
        Ok((self, effects))
    }

    /// Complete the online first-new Vote path after native P/D/C.
    ///
    /// `execute_admitted_epoch_proposal_v1` has already durably installed Core's
    /// NativeValid transition and ACKed it; at that point the retained
    /// `SignIntent::Vote` is an obligation, not a signer capability. This
    /// method persists the exact signer intent through the node-owned journal,
    /// revalidates every other owner before and after the producer call, then
    /// delivers and durably releases the exact signature. A failed join fences
    /// the owner and cannot be retried with a different statement.
    pub fn sign_pending_epoch_vote_v1<P: trnm_consensus_signer_journal::SignatureProducerV0>(
        mut self,
        producer: &mut P,
    ) -> Result<(Self, trnm_consensus_core::OutboundMessage)> {
        self.confirm_current_cut_v1()?;
        self.require_first_new_phase_v1(FirstNewEpochPhaseV1::NativePrepared)?;
        self.finish_pending_application_vote_v3(producer)
    }

    // Each private caller freshly confirms its owner cut and its concrete
    // phase first. This shared tail preserves the full custody/P/Valid checks
    // immediately around the actual key producer, including its callbacks.
    fn finish_pending_application_vote_v3<P: trnm_consensus_signer_journal::SignatureProducerV0>(
        self,
        producer: &mut P,
    ) -> Result<(Self, trnm_consensus_core::OutboundMessage)> {
        self.finish_pending_vote_v5(producer, None)
    }

    fn finish_pending_vote_v5<P: trnm_consensus_signer_journal::SignatureProducerV0>(
        mut self,
        producer: &mut P,
        seal: Option<SealVoteProvenanceV5<'_>>,
    ) -> Result<(Self, trnm_consensus_core::OutboundMessage)> {
        let intent = match self.driver.state().pending_sign().cloned() {
            Some(SignIntent::Vote { .. }) => self
                .driver
                .state()
                .pending_sign()
                .cloned()
                .context("pending epoch Vote disappeared")?,
            Some(_) => anyhow::bail!("epoch online signing retained a non-Vote intent"),
            None => anyhow::bail!("epoch online Vote intent is not pending"),
        };
        let (authorizing_safety_revision, view, height, block_id) = match &intent {
            SignIntent::Vote {
                authorizing_safety_revision,
                view,
                height,
                block_id,
                ..
            } => (*authorizing_safety_revision, *view, *height, *block_id),
            SignIntent::TimeoutVote { .. } => unreachable!("Vote match above"),
        };
        if let Some(seal) = seal {
            ensure!(
                self.pending_epoch_commit.is_none() && seal.proposal.block().id() == block_id,
                "pending seal Vote provenance mismatch"
            );
        } else {
            ensure!(
                self.pending_epoch_commit
                    .as_ref()
                    .and_then(|pending| pending.prepared.header().ok().map(|header| header.id()))
                    == Some(block_id),
                "pending Vote is not bound to the retained native P"
            );
        }
        let canonical = CanonicalSignIntentV0::vote(
            self.driver.config().validator_set(),
            self.driver.config().local_validator(),
            authorizing_safety_revision,
            view,
            height,
            block_id,
        )
        .map_err(|error| anyhow::anyhow!("canonical epoch Vote intent: {error:?}"))?;
        ensure!(
            canonical.signing_root() == intent.signing_root(),
            "Core Vote intent differs from canonical signer request"
        );
        let before = self.ordinary.confirm_node_checkpoint_head_exact_v0()?;
        let mut guarded = FreshEpochSignatureProducerV1 {
            producer,
            expected: &canonical,
            confirm: || {
                confirm_key_owners_v1(
                    &self.driver,
                    &self.journal,
                    self.pin,
                    &self.application,
                    &self.edge,
                    &mut self.retired,
                    &self.retirement,
                    &mut self.checkpoint_store,
                    &self.checkpoint,
                    match seal {
                        Some(seal) => EpochKeyProvenanceV5::Seal(seal),
                        None => EpochKeyProvenanceV5::Application(
                            &self
                                .pending_epoch_commit
                                .as_ref()
                                .context("application Vote P missing")?
                                .prepared,
                        ),
                    },
                )
            },
        };
        let signature = self.ordinary.sign_exact_v0(&canonical, &mut guarded)?;
        let after = self.ordinary.confirm_node_checkpoint_head_exact_v0()?;
        ensure!(
            after.exact_watermark().sequence() == before.exact_watermark().sequence() + 2
                && before.journal_id() == after.journal_id()
                && before.profile_checksum() == after.profile_checksum()
                && after.pending_intent().is_none(),
            "online epoch Vote did not persist one signer intent pair"
        );
        let mark = after.exact_watermark();
        let signed_cut = EpochOrdinaryCustodyCutV1 {
            scope: mark.scope(),
            journal_id: mark.journal_id(),
            profile_checksum: after.profile_checksum(),
            sequence: mark.sequence(),
            chain_checksum: mark.chain_checksum(),
        };
        // The C transition already names the exact pending Vote Safety state;
        // only the ordinary signer custody changes at this boundary.
        self.advance_exact_cut_v1(self.checkpoint.fields().target_safety, signed_cut)?;
        let signed_state = self.driver.state().clone();
        let outbound = self
            .driver
            .step_v1(Input::SignatureReady {
                id: trnm_consensus_core::SignId::new(canonical.signing_root()),
                signature,
            })
            .map_err(|error| anyhow::anyhow!("online epoch Vote signature delivery: {error:?}"))?;
        let [Effect::Broadcast(message)] = outbound.as_slice() else {
            anyhow::bail!("online epoch Vote yielded unexpected effect")
        };
        let vote = match message {
            trnm_consensus_core::OutboundMessage::Vote(vote) => vote,
            _ => anyhow::bail!("online epoch signature yielded non-Vote broadcast"),
        };
        vote.verify(
            self.driver.config().validator_set(),
            &trnm_consensus_crypto::StrictEd25519Verifier,
        )
        .map_err(|error| anyhow::anyhow!("online epoch Vote verification: {error:?}"))?;
        ensure!(
            vote.author() == canonical.author()
                && vote.signing_root() == canonical.signing_root()
                && vote.signature() == &signature
                && self.driver.state().pending_sign().is_none(),
            "online epoch Vote differs from persisted signer intent"
        );
        let effects = self
            .driver
            .persist_signature_release_v1(&signed_state)
            .map_err(|error| anyhow::anyhow!("online epoch Vote release: {error:?}"))?;
        let [Effect::PersistSafetyState(request)] = effects.as_slice() else {
            anyhow::bail!("online epoch Vote release did not persist one Safety cut")
        };
        let head = self.journal.persist_exact_v1(
            self.pin,
            request,
            &SafetyTransitionContextV0::ordinary(),
        )?;
        self.pin = head.pin_v1();
        self.advance_exact_cut_v1(safety_cut(&head), signed_cut)?;
        self.journal.confirm_exact_request_v1(
            self.pin,
            request,
            &SafetyTransitionContextV0::ordinary(),
        )?;
        let ack = self
            .driver
            .step_v1(Input::StorageAck {
                barrier: request.barrier(),
            })
            .map_err(|error| anyhow::anyhow!("online epoch Vote release ACK: {error:?}"))?;
        ensure!(
            ack.is_empty(),
            "online epoch Vote release yielded unexpected authority"
        );
        self.confirm_current_cut_v1()?;
        self.startup.clear();
        Ok((self, message.clone()))
    }

    /// Verify and commit strict first-new finality for the exact native P
    /// retained by `execute_admitted_epoch_proposal_v1`.  The finality proof
    /// is bounded by the caller-owned Cev0 budget; malformed, substituted or
    /// replayed proofs fail closed before the native K CAS.  The independent
    /// node checkpoint is advanced only after native K's fresh readback.
    pub fn commit_admitted_epoch_finality_v1(
        mut self,
        proof_bytes: &[u8],
        budget: &mut trnm_consensus_types::Cev0AdmissionBudgetV0,
    ) -> Result<Self> {
        self.confirm_current_cut_v1()?;
        self.require_first_new_phase_v1(FirstNewEpochPhaseV1::VoteReleased)?;
        let pending = self
            .pending_epoch_commit
            .take()
            .context("no admitted epoch P is awaiting finality")?;
        let committed = match self.application.commit_epoch_finality_bytes_v1(
            &pending.prepared,
            proof_bytes,
            budget,
        ) {
            Ok(committed) => committed,
            Err(error) => {
                // The native owner remains authoritative on a failed proof;
                // discard the one-shot continuation so a caller cannot retry
                // with a different proof against the same P in this process.
                self.fenced = true;
                return Err(error.context("epoch strict finality/K"));
            }
        };
        ensure!(
            committed.belongs_to_application(&self.application),
            "epoch K committed readback lost native owner affinity"
        );
        let head = committed.head();
        ensure!(
            head.block_id().as_bytes() == pending.prepared.header()?.id().as_bytes(),
            "epoch K committed head does not match retained P"
        );
        let old = self.checkpoint.fields().application;
        let application = EpochApplicationCutV1 {
            block_id: *head.block_id().as_bytes(),
            height: head.height().get(),
            epoch: pending.epoch,
            view: pending.view,
            timestamp_ms: pending.timestamp_ms,
            state_root: *head.state_root().as_bytes(),
            native_store_id: old.native_store_id,
            native_commit_id: *head.commit_id().as_bytes(),
            p_sequence: pending.prepared.persist_sequence(),
            p_digest: committed.p_digest(),
            artifact_digest: pending.prepared.artifact_digest(),
            overlay_digest: pending.overlay_digest,
            commit_sequence: committed.commit_sequence(),
        };
        let safety = self.checkpoint.fields().target_safety;
        let ordinary = self
            .checkpoint
            .fields()
            .ordinary
            .context("missing live ordinary cut")?;
        if let Err(error) =
            self.advance_exact_cut_with_application_v1(safety, ordinary, application)
        {
            // Native K is already durable.  A failed independent checkpoint
            // CAS must therefore stop this owner rather than permit a second
            // proposal/finality attempt against a mismatched cut.
            self.fenced = true;
            return Err(error.context("epoch K independent checkpoint CAS"));
        }
        self.pending_epoch_commit = None;
        Ok(self)
    }

    /// Reopen the exact post-P/D/C cut after a process-shaped restart and
    /// resume its one durable Vote intent. The journal installs a fresh Core
    /// process affinity only after a second exact read; native, custody and
    /// checkpoint joins are checked before the signer is touched. The signer
    /// journal persists the intent before producing the signature, and the
    /// Safety release is persisted and read back before this method returns.
    #[allow(clippy::too_many_arguments)]
    pub fn recover_progressed_continuing_v1<
        P: trnm_consensus_signer_journal::SignatureProducerV0,
    >(
        mut journal: SqliteEpochSafetyJournalV1,
        application: DurableNativeApplicationV0,
        edge: AuthenticatedEpochApplicationEdgeV1,
        mut retired: RetiredSqliteSignerJournalV1<W>,
        retirement: ConfirmedOrdinarySignerRetirementV1,
        mut ordinary: SqliteSignerJournalV0<N>,
        mut checkpoint_store: SqliteEpochNodeCheckpointStoreV1,
        expected: EpochNodeCheckpointV1,
        block_id: [u8; 32],
        producer: &mut P,
    ) -> Result<(Self, Vec<Effect>)> {
        ensure!(
            expected.fields().phase == EpochCheckpointPhaseV1::Ordinary
                && expected.fields().role == EpochCheckpointRoleV1::Continuing
                && expected.fields().predecessor_kind == EpochCheckpointPredecessorV1::V1,
            "progressed recovery requires an ordinary V1 checkpoint"
        );
        checkpoint_store.confirm_exact(&expected)?;
        let pin = EpochSafetyHeadPinV1 {
            journal_id: expected.fields().target_safety.journal_id,
            revision: expected.fields().target_safety.revision,
            chain_checksum: expected.fields().target_safety.chain_checksum,
        };
        let (confirmed, driver) = journal.prepare_candidate_host_progressed_recovery_v1(pin)?;
        let Some(SignIntent::Vote {
            block_id: pending, ..
        }) = driver.state().pending_sign()
        else {
            anyhow::bail!("progressed recovery did not retain one Vote intent");
        };
        ensure!(
            pending.as_bytes() == &block_id,
            "progressed Vote block differs"
        );
        ensure!(
            confirmed
                .transition_context_v1()
                .native_valid_transition()
                .is_some(),
            "progressed recovery is not a NativeValid cut"
        );
        ensure!(
            retirement.belongs_to_owner_v1(&mut retired)
                && retirement.record_v1().checksum_v1()
                    == expected
                        .fields()
                        .retired
                        .context("missing retired custody")?
                        .retirement_record_checksum,
            "retired custody changed during progressed recovery"
        );
        let signer = ordinary.confirm_node_checkpoint_head_exact_v0()?;
        let mark = signer.exact_watermark();
        let expected_ordinary = expected
            .fields()
            .ordinary
            .context("missing ordinary custody")?;
        ensure!(
            signer.belongs_to_operational_journal_at_path_v0(&ordinary, ordinary.path())
                && mark.scope() == expected_ordinary.scope
                && mark.journal_id() == expected_ordinary.journal_id
                && signer.profile_checksum() == expected_ordinary.profile_checksum
                && signer.pending_intent().is_none(),
            "ordinary signer custody changed before resumed Vote"
        );
        ensure!(
            application.confirmed_committed_head_v0()? == *edge.application_parent(),
            "progressed recovery application head is not pre-K"
        );
        let prepared = application.reopen_prepared_epoch_execution_v1(block_id)?;
        let confirmed_native = application.confirm_prepared_epoch_execution_v1(&prepared)?;
        let native_parent = prepared.application_parent();
        let app = expected.fields().application;
        ensure!(
            edge.strict_activation_binding_v1()? == expected.fields().phase_authority_binding
                && confirmed_native
                    .belongs_to_application_at_path(&application, application.path())
                && confirmed_native.commit_sequence().is_none()
                && native_parent.block_id().as_bytes() == &app.block_id
                && native_parent.state_root().as_bytes() == &app.state_root
                && native_parent.commit_id().as_bytes() == &app.native_commit_id,
            "progressed recovery native P differs from checkpoint"
        );
        let header = prepared.header()?;
        let origin = checkpoint_store.original_v0(&expected)?;
        let seal_authority = driver
            .issue_application_seal_authority_v1()
            .map_err(|e| anyhow::anyhow!("progressed recovery seal authority: {e:?}"))?;
        let pending_epoch_commit = Some(PendingEpochCommitV1 {
            epoch: header.epoch().get(),
            view: header.view().get(),
            timestamp_ms: header.timestamp_ms(),
            overlay_digest: confirmed_native.overlay_checksum(),
            prepared,
        });
        let mut runtime = Self {
            driver,
            journal,
            pin,
            application,
            edge,
            retired,
            retirement,
            ordinary,
            checkpoint_store,
            checkpoint: expected,
            origin,
            startup: Vec::new(),
            seal_authority,
            pending_epoch_commit,
            pending_validation: None,
            fenced: false,
        };
        runtime.confirm_current_cut_v1()?;
        let intent = runtime
            .driver
            .state()
            .pending_sign()
            .cloned()
            .context("progressed Vote intent disappeared")?;
        let canonical = match &intent {
            SignIntent::Vote {
                authorizing_safety_revision,
                view,
                height,
                block_id,
                ..
            } => CanonicalSignIntentV0::vote(
                runtime.driver.config().validator_set(),
                runtime.driver.config().local_validator(),
                *authorizing_safety_revision,
                *view,
                *height,
                *block_id,
            )
            .map_err(|e| anyhow::anyhow!("canonical Vote intent: {e:?}"))?,
            _ => anyhow::bail!("progressed recovery retained a non-Vote intent"),
        };
        let before = runtime.ordinary.confirm_node_checkpoint_head_exact_v0()?;
        let mut guarded = FreshEpochSignatureProducerV1 {
            producer,
            expected: &canonical,
            confirm: || {
                confirm_key_owners_v1(
                    &runtime.driver,
                    &runtime.journal,
                    runtime.pin,
                    &runtime.application,
                    &runtime.edge,
                    &mut runtime.retired,
                    &runtime.retirement,
                    &mut runtime.checkpoint_store,
                    &runtime.checkpoint,
                    EpochKeyProvenanceV5::Application(
                        &runtime
                            .pending_epoch_commit
                            .as_ref()
                            .context("resumed Vote P missing")?
                            .prepared,
                    ),
                )
            },
        };
        let signature = runtime.ordinary.sign_exact_v0(&canonical, &mut guarded)?;
        let after = runtime.ordinary.confirm_node_checkpoint_head_exact_v0()?;
        ensure!(
            after.exact_watermark().sequence() == before.exact_watermark().sequence() + 2
                && after.pending_intent().is_none(),
            "resumed Vote did not persist one signer intent pair"
        );
        let signed_state = runtime.driver.state().clone();
        let outbound = runtime
            .driver
            .step_v1(Input::SignatureReady {
                id: trnm_consensus_core::SignId::new(canonical.signing_root()),
                signature,
            })
            .map_err(|e| anyhow::anyhow!("resumed Vote signature delivery: {e:?}"))?;
        let [Effect::Broadcast(message)] = outbound.as_slice() else {
            anyhow::bail!("resumed Vote signature yielded unexpected effect");
        };
        let vote = match message {
            trnm_consensus_core::OutboundMessage::Vote(vote) => vote,
            _ => anyhow::bail!("resumed signature yielded non-Vote broadcast"),
        };
        vote.verify(
            runtime.driver.config().validator_set(),
            &trnm_consensus_crypto::StrictEd25519Verifier,
        )
        .map_err(|e| anyhow::anyhow!("resumed Vote verification: {e:?}"))?;
        ensure!(
            vote.author() == canonical.author()
                && vote.signing_root() == canonical.signing_root()
                && vote.signature() == &signature
                && runtime.driver.state().pending_sign().is_none(),
            "resumed Vote differs from durable signer intent"
        );
        let release = runtime
            .driver
            .persist_signature_release_v1(&signed_state)
            .map_err(|e| anyhow::anyhow!("resumed Vote release: {e:?}"))?;
        let [Effect::PersistSafetyState(request)] = release.as_slice() else {
            anyhow::bail!("resumed Vote release did not persist Safety");
        };
        let head = runtime.journal.persist_exact_v1(
            runtime.pin,
            request,
            &SafetyTransitionContextV0::ordinary(),
        )?;
        runtime.pin = head.pin_v1();
        let mark = after.exact_watermark();
        let signed_cut = EpochOrdinaryCustodyCutV1 {
            scope: mark.scope(),
            journal_id: mark.journal_id(),
            profile_checksum: after.profile_checksum(),
            sequence: mark.sequence(),
            chain_checksum: mark.chain_checksum(),
        };
        runtime.advance_exact_cut_v1(safety_cut(&head), signed_cut)?;
        runtime.journal.confirm_exact_request_v1(
            runtime.pin,
            request,
            &SafetyTransitionContextV0::ordinary(),
        )?;
        let ack = runtime
            .driver
            .step_v1(Input::StorageAck {
                barrier: request.barrier(),
            })
            .map_err(|e| anyhow::anyhow!("resumed Vote release ACK: {e:?}"))?;
        ensure!(
            ack.is_empty(),
            "resumed Vote release yielded extra authority"
        );
        runtime.confirm_current_cut_v1()?;
        Ok((runtime, vec![Effect::Broadcast(message.clone())]))
    }

    /// Returns a read-only copy of the still-unresolved Core request.
    ///
    /// Cloning this carrier does not clone its one-consumer claim.  A native
    /// application host must claim the request and present the resulting
    /// Core-issued permit together with its private durable seal before any
    /// Valid delivery can proceed.
    pub fn pending_epoch_proposal_validation_v1(&self) -> Option<PayloadValidationRequest> {
        self.pending_validation.clone()
    }
}
// Private adapter: caller-supplied verifiers cannot mint or bypass this join.
struct FreshEpochSignatureProducerV1<'a, P, F> {
    producer: &'a mut P,
    expected: &'a trnm_consensus_types::CanonicalSignIntentV0,
    confirm: F,
}
impl<P, F> trnm_consensus_signer_journal::SignatureProducerV0
    for FreshEpochSignatureProducerV1<'_, P, F>
where
    P: trnm_consensus_signer_journal::SignatureProducerV0,
    F: FnMut() -> Result<()>,
{
    fn sign(
        &mut self,
        request: trnm_consensus_signer_journal::SignatureRequestV0<'_>,
    ) -> std::result::Result<
        trnm_consensus_types::SignatureBytes,
        trnm_consensus_signer_journal::SignatureProducerErrorV0,
    > {
        use trnm_consensus_signer_journal::SignatureProducerErrorV0;
        if request.intent() != self.expected {
            return Err(SignatureProducerErrorV0::Rejected);
        }
        (self.confirm)().map_err(|_| SignatureProducerErrorV0::Rejected)?;
        let signature = self.producer.sign(request)?;
        (self.confirm)().map_err(|_| SignatureProducerErrorV0::Rejected)?;
        Ok(signature)
    }
}
#[allow(clippy::too_many_arguments)]
fn confirm_key_owners_v1<W: ExternalSignerRetirementV1>(
    driver: &PendingEpochHostDriverV1,
    journal: &SqliteEpochSafetyJournalV1,
    pin: EpochSafetyHeadPinV1,
    application: &DurableNativeApplicationV0,
    edge: &AuthenticatedEpochApplicationEdgeV1,
    retired: &mut RetiredSqliteSignerJournalV1<W>,
    retirement: &ConfirmedOrdinarySignerRetirementV1,
    store: &mut SqliteEpochNodeCheckpointStoreV1,
    checkpoint: &EpochNodeCheckpointV1,
    provenance: EpochKeyProvenanceV5<'_>,
) -> Result<()> {
    store.confirm_exact(checkpoint)?;
    let safety = journal.fresh_read_v1(pin)?;
    ensure!(
        safety_cut(&safety) == checkpoint.fields().target_safety
            && safety.state_v1() == driver.state()
            && safety.belongs_to_store_at_path_v1(journal, journal.path_v1()),
        "Safety changed at key boundary"
    );
    confirm_native_application_cut_v3(application, edge, checkpoint)?;
    ensure!(
        retirement.belongs_to_owner_v1(retired)
            && retirement.record_v1().checksum_v1()
                == checkpoint
                    .fields()
                    .retired
                    .context("missing retired key cut")?
                    .retirement_record_checksum,
        "retired custody changed at key boundary"
    );
    // The signer owns its own pending-intent transaction/watermark. The V1 cut
    // deliberately still names the pre-signature head; only its exact two-event
    // successor can be installed after the signed journal returns.
    ensure!(
        safety.belongs_to_store_at_path_v1(journal, journal.path_v1())
            && edge
                .durable_checkpoint()
                .belongs_to_application_at_path_v0(application, application.path()),
        "owner changed during key-boundary confirmation"
    );
    match provenance {
        EpochKeyProvenanceV5::Application(prepared) => {
            confirm_pending_vote_native_v2(driver, application, Some(prepared))?;
            let header = prepared.header()?;
            if header.block_kind() == BlockKind::EpochCheckpoint {
                confirm_checkpoint_selection_v4(application, edge, checkpoint, &header)?;
            }
        }
        EpochKeyProvenanceV5::Timeout => {
            ensure!(
                matches!(
                    driver.state().pending_sign(),
                    Some(SignIntent::TimeoutVote { .. })
                ),
                "timeout key boundary lacks its exact obligation"
            );
            confirm_pending_vote_native_v2(driver, application, None)?;
        }
        EpochKeyProvenanceV5::Seal(seal) => {
            confirm_seal_vote_provenance_v5(driver, application, edge, seal)?;
        }
    }
    store.confirm_exact(checkpoint)?;
    Ok(())
}

fn ack_initial(driver: &mut PendingEpochHostDriverV1) -> Result<Vec<Effect>> {
    ensure!(
        driver.activation_persistence_pending_v1(),
        "initial ACK already consumed"
    );
    let effects = driver
        .step_v1(Input::StorageAck {
            barrier: driver.initial_persistence_v1().barrier(),
        })
        .map_err(|e| anyhow::anyhow!("initial Core ACK: {e:?}"))?;
    ensure!(
        effects.len() == 1
            && effects
                .iter()
                .all(|e| matches!(e, Effect::ArmViewTimer { .. })),
        "initial ACK emitted unexpected authority"
    );
    Ok(effects)
}
fn safety_cut(head: &ConfirmedEpochSafetyHeadV1) -> EpochSafetyCutV1 {
    EpochSafetyCutV1 {
        journal_id: head.journal_id_v1(),
        context_ref: head.context_ref_v1(),
        revision: head.revision_v1(),
        record_checksum: head.state_record_checksum_v1(),
        chain_checksum: head.chain_checksum_v1(),
    }
}
#[allow(clippy::too_many_arguments)]
fn join_initial<W: ExternalSignerRetirementV1, N: ExternalMonotonicWatermarkV0>(
    driver: &PendingEpochHostDriverV1,
    journal: &SqliteEpochSafetyJournalV1,
    pin: EpochSafetyHeadPinV1,
    application: &DurableNativeApplicationV0,
    edge: &AuthenticatedEpochApplicationEdgeV1,
    retired: &mut RetiredSqliteSignerJournalV1<W>,
    retirement: &ConfirmedOrdinarySignerRetirementV1,
    ordinary: &mut SqliteSignerJournalV0<N>,
    origin: &ExternalNodeCheckpointV0,
) -> Result<EpochNodeCheckpointV1> {
    let safety = journal.confirm_exact_request_v1(
        pin,
        driver.initial_persistence_v1(),
        &SafetyTransitionContextV0::ordinary(),
    )?;
    ensure!(
        safety.belongs_to_store_at_path_v1(journal, journal.path_v1())
            && safety.state_v1() == driver.state(),
        "Safety owner/state mismatch"
    );
    let epoch = driver
        .state()
        .epoch_state_v1()
        .context("missing strict epoch state")?;
    let strict = epoch
        .strict_context()
        .map_err(|e| anyhow::anyhow!("strict Core epoch context: {e:?}"))?;
    let activation = strict.activation();
    let native = application.confirm_epoch_application_edge_v1(edge)?;
    let row = native.durable_checkpoint();
    let header = native.checkpoint_header();
    let terminal = native.terminal_old_header();
    let config = driver.config();
    let new = config.validator_set();
    let author = config.local_validator();
    ensure!(
        native.belongs_to_application_at_path(application, application.path())
            && row.status_v0() == DurableExecutionHistoryStatusV0::Committed
            && native.old_validator_set() == epoch.old_validator_set()
            && native.old_parameters() == epoch.old_parameters()
            && native.new_validator_set() == new
            && native.new_parameters() == config.consensus_parameters()
            && native.strict_activation_binding_v1().as_bytes() == &epoch.activation_binding()
            && header == epoch.checkpoint_header()
            && terminal == epoch.terminal_old_header()
            && row.artifact_digest_v0() == epoch.checkpoint_artifact().source_artifact_checksum()
            && row.overlay_digest_v0() == epoch.checkpoint_artifact().overlay().overlay_checksum(),
        "native strict joint, P or configuration mismatch"
    );
    ensure!(
        retirement.belongs_to_owner_v1(retired) && retirement.record_v1() == retired.record_v1(),
        "retired owner changed"
    );
    let retired_profile = retired.profile_v1();
    let record = *retired.record_v1();
    ensure!(
        retired_profile.validator_set() == epoch.old_validator_set()
            && retired_profile.author() == author
            && record.host_cut_v1().owner_generation.checked_add(1)
                == Some(epoch.owner_generation())
            && record.host_cut_v1().safety_revision == origin.fields().safety_revision
            && record.host_cut_v1().safety_record_checksum
                == origin.fields().safety_state_record_checksum
            && record.host_cut_v1().native_committed_cut
                == origin.fields().application_committed_head_row_checksum
            && record.terminal_watermark_v1() == origin.fields().signer_exact_watermark
            && record.source_profile_checksum_v1() == origin.fields().signer_profile_checksum,
        "original retired custody/independent cut mismatch"
    );
    let old_key = epoch
        .old_validator_set()
        .validator(author)
        .context("continuing author absent from old set")?
        .consensus_key();
    let new_key = new
        .validator(author)
        .context("continuing author absent from new set")?
        .consensus_key();
    ensure!(
        old_key == new_key,
        "continuing key migration requires separate custody protocol"
    );
    let signer = ordinary.confirm_node_checkpoint_head_exact_v0()?;
    ensure!(
        signer.belongs_to_operational_journal_at_path_v0(ordinary, ordinary.path())
            && ordinary.profile().validator_set() == new
            && ordinary.profile().author() == author
            && ordinary.profile().signer_profile_ref() == retired_profile.signer_profile_ref()
            && signer.exact_watermark().sequence() == 0
            && signer.tail().is_none()
            && signer.pending_intent().is_none()
            && signer.capacity().intent_count() == 0
            && signer.capacity().event_count() == 0
            && signer.exact_watermark().scope() != record.source_v1().scope()
            && signer.journal_id() != record.source_v1().journal_id(),
        "new ordinary custody is not exact distinct virgin continuing owner"
    );
    let source = safety.migration_source_v1();
    let source_pin = source.pin_v1();
    let source_cut = EpochSafetyCutV1 {
        journal_id: source_pin.journal_id,
        context_ref: source.context_ref_v1(),
        revision: source_pin.revision,
        record_checksum: source.state_record_checksum_v1(),
        chain_checksum: source_pin.chain_checksum,
    };
    ensure!(
        source.initial_revision_v1() == safety.revision_v1(),
        "initial activation journal already progressed"
    );
    let head = row.target_head_v0()?;
    let watermark = signer.exact_watermark();
    let terminal_watermark = record.terminal_watermark_v1();
    let target = EpochNodeCheckpointV1::new(EpochNodeCheckpointFieldsV1 {
        phase: EpochCheckpointPhaseV1::ActivationCommitted,
        role: EpochCheckpointRoleV1::Continuing,
        predecessor_kind: EpochCheckpointPredecessorV1::TerminalV0,
        lineage_id: origin.scope(),
        origin_checksum: epoch_origin_checksum_v1(&origin.encode_canonical()),
        generation: origin
            .generation()
            .checked_add(1)
            .context("node generation exhausted")?,
        predecessor_checksum: origin.checkpoint_checksum(),
        genesis_hash: new.genesis_hash().into_bytes(),
        chain_id: new.chain_id(),
        protocol_version: new.protocol_version().get(),
        epoch: new.epoch().get(),
        author,
        validator_set_id: new.id().into_bytes(),
        parameters_hash: config.consensus_parameters().hash().into_bytes(),
        owner_generation: epoch.owner_generation(),
        phase_authority_binding: epoch.activation_binding(),
        source_safety: Some(source_cut),
        target_safety: safety_cut(&safety),
        edge: EpochApplicationEdgeCutV1 {
            checkpoint_block_id: header.id().into_bytes(),
            checkpoint_height: header.height().get(),
            checkpoint_state_root: header.state_root().into_bytes(),
            terminal_old_block_id: terminal.id().into_bytes(),
            terminal_old_height: terminal.height().get(),
            terminal_old_view: terminal.view().get(),
            terminal_old_qc_id: activation.terminal_old_qc().id().into_bytes(),
            native_authorization_id: native.authorization_id(),
        },
        application: EpochApplicationCutV1 {
            block_id: *head.block_id().as_bytes(),
            height: head.height().get(),
            epoch: header.epoch().get(),
            view: header.view().get(),
            timestamp_ms: header.timestamp_ms(),
            state_root: *head.state_root().as_bytes(),
            native_store_id: row.store_id_v0(),
            native_commit_id: *head.commit_id().as_bytes(),
            p_sequence: row.p_sequence_v0(),
            p_digest: row.p_digest_v0(),
            artifact_digest: row.artifact_digest_v0(),
            overlay_digest: row.overlay_digest_v0(),
            commit_sequence: row
                .commit_sequence_v0()
                .context("checkpoint is not committed")?,
        },
        retired: Some(EpochRetiredCustodyCutV1 {
            epoch: retired_profile.epoch().get(),
            author: retired_profile.author(),
            validator_set_id: retired_profile.validator_set_id().into_bytes(),
            parameters_hash: epoch.old_parameters().hash().into_bytes(),
            scope: record.source_v1().scope(),
            journal_id: record.source_v1().journal_id(),
            profile_checksum: record.source_profile_checksum_v1(),
            source_sequence: record.source_v1().sequence(),
            source_chain_checksum: record.source_v1().chain_checksum(),
            terminal_sequence: terminal_watermark.sequence(),
            terminal_chain_checksum: terminal_watermark.chain_checksum(),
            retirement_record_checksum: record.checksum_v1(),
        }),
        ordinary: Some(EpochOrdinaryCustodyCutV1 {
            scope: watermark.scope(),
            journal_id: watermark.journal_id(),
            profile_checksum: signer.profile_checksum(),
            sequence: watermark.sequence(),
            chain_checksum: watermark.chain_checksum(),
        }),
    })?;
    target.validate_first_continuing_v0(origin)?;
    ensure!(
        retirement.belongs_to_owner_v1(retired)
            && signer.belongs_to_operational_journal_at_path_v0(ordinary, ordinary.path())
            && safety.belongs_to_store_at_path_v1(journal, journal.path_v1())
            && native.belongs_to_application_at_path(application, application.path()),
        "owners changed during activation join"
    );
    Ok(target)
}

include!("epoch_first_finalization_v2.inc");

#[cfg(all(test, feature = "epoch-runtime-test-fixtures"))]
#[path = "epoch_runtime_candidate_v1_tests.rs"]
mod tests;

include!("epoch_ordinary_continuation_v3.inc");

// One exact native-cut check shared by ordinary owner refresh, post-K refresh,
// and both sides of the actual key producer. The independent checkpoint fixes
// every committed-P comparison; the immutable edge fixes original authority.
fn confirm_native_application_cut_v3(
    application: &DurableNativeApplicationV0,
    edge: &AuthenticatedEpochApplicationEdgeV1,
    checkpoint: &EpochNodeCheckpointV1,
) -> Result<()> {
    let app = checkpoint.fields().application;
    if app.block_id == *edge.application_parent().block_id().as_bytes() {
        let native = application.confirm_epoch_application_edge_v1(edge)?;
        let row = native.durable_checkpoint();
        let head = row.target_head_v0()?;
        ensure!(
            native.strict_activation_binding_v1().as_bytes()
                == &checkpoint.fields().phase_authority_binding
                && row.p_digest_v0() == app.p_digest
                && row.artifact_digest_v0() == app.artifact_digest
                && row.overlay_digest_v0() == app.overlay_digest
                && row.p_sequence_v0() == app.p_sequence
                && row.commit_sequence_v0() == Some(app.commit_sequence)
                && row.store_id_v0() == app.native_store_id
                && head.block_id().as_bytes() == &app.block_id
                && head.state_root().as_bytes() == &app.state_root
                && head.commit_id().as_bytes() == &app.native_commit_id
                && head.height().get() == app.height
                && native.belongs_to_application_at_path(application, application.path()),
            "native activation checkpoint changed"
        );
    } else {
        // After strict first-new K the immutable activation edge still
        // names the old checkpoint parent.  Requiring that edge's old
        // head here would reject the intended progressed application cut.
        // Freshly validate the complete committed row at the checkpoint's
        // current application block instead, while retaining the edge's
        // owner/path check and the checkpoint's persisted authority cut.
        ensure!(
            edge.durable_checkpoint()
                .belongs_to_application_at_path_v0(application, application.path(),),
            "native activation edge owner changed"
        );
        let prepared = application.reopen_prepared_epoch_execution_v1(app.block_id)?;
        let confirmed = application.confirm_prepared_epoch_execution_v1(&prepared)?;
        let head = prepared.overlay_parent_head()?;
        let header = prepared.header()?;
        let committed = application.confirmed_committed_head_v0()?;
        ensure!(
            edge.strict_activation_binding_v1()? == checkpoint.fields().phase_authority_binding
                && confirmed.commit_sequence() == Some(app.commit_sequence)
                && confirmed.prepared().p_digest() == app.p_digest
                && confirmed.prepared().artifact_digest() == app.artifact_digest
                && confirmed.overlay_checksum() == app.overlay_digest
                && confirmed.prepared().persist_sequence() == app.p_sequence
                && confirmed.belongs_to_application_at_path(application, application.path())
                && head.block_id().as_bytes() == &app.block_id
                && head.state_root().as_bytes() == &app.state_root
                && head.commit_id().as_bytes() == &app.native_commit_id
                && head.height().get() == app.height
                && committed == head
                && application.config_v0().store_id() == app.native_store_id
                && header.epoch() == edge.new_validator_set().epoch()
                && header.epoch().get() == app.epoch
                && header.view().get() == app.view
                && header.timestamp_ms() == app.timestamp_ms
                && header.validator_set_id() == edge.new_validator_set().id()
                && header.consensus_parameters_hash() == edge.new_parameters().hash(),
            "native progressed application checkpoint changed"
        );
    }
    Ok(())
}

include!("epoch_checkpoint_preparation_v4.inc");

include!("epoch_pre_handoff_v5.inc");
