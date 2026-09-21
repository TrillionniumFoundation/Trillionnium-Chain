// Actual journal9/native13 retirement. No caller-provided scalar can create this owner.
struct OutgoingEpochSourceV6<W: ExternalSignerRetirementV1> {
    driver: PendingEpochHostDriverV1,
    journal: SqliteEpochSafetyJournalV1,
    pin: EpochSafetyHeadPinV1,
    application: DurableNativeApplicationV0,
    edge: AuthenticatedEpochApplicationEdgeV1,
    incoming_retired: RetiredSqliteSignerJournalV1<W>,
    incoming_retirement: ConfirmedOrdinarySignerRetirementV1,
    predecessor: EpochNodeCheckpointV1,
    prepared: PreparedNativeEpochExecutionV1,
    selection: Box<trnm_native_execution_v0::ComputedLaterEpochSelectionV1>,
    receipt: Box<trnm_native_execution_v0::CommittedLaterEpochPreHandoffV1>,
    seals: Vec<SignedProposalV0>,
}

impl<W: ExternalSignerRetirementV1> OutgoingEpochSourceV6<W> {
    fn confirm(&mut self) -> Result<trnm_consensus_signer_journal::SignerRetirementHostCutV1> {
        let state = self.driver.state();
        let p = self.predecessor.fields();
        let head = self.journal.fresh_read_v1(self.pin)?;
        ensure!(
            p.phase == EpochCheckpointPhaseV1::Ordinary
                && head.belongs_to_store_at_path_v1(&self.journal, self.journal.path_v1())
                && head.state_v1() == state
                && safety_cut(&head) == p.target_safety
                && head.owner_generation_v1() == p.owner_generation
                && state.finalized() == state.application_applied()
                && state.application_applied().block_id().as_bytes() == &p.application.block_id
                && state.pending_sign().is_none()
                && state.pending_finalize().is_none()
                && state.finalization_queue().is_empty()
                && state.payload_validation_obligations().is_empty()
                && state.old_epoch_boundary_v1().is_some_and(|b| {
                    b.phase(state)
                        == trnm_consensus_core::OldEpochBoundaryPhaseV1::CheckpointApplied
                }),
            "outgoing retirement source is not the exact settled journal9 cut"
        );
        ensure!(
            self.incoming_retirement
                .belongs_to_owner_v1(&mut self.incoming_retired)
                && Some(self.incoming_retirement.record_v1().checksum_v1())
                    == p.retired.map(|r| r.retirement_record_checksum),
            "incoming retired custody changed"
        );
        confirm_native_application_cut_v3(&self.application, &self.edge, &self.predecessor)?;
        ensure!(
            self.receipt.belongs_to_application(&self.application)
                && self.receipt.head().block_id().as_bytes() == &p.application.block_id
                && self.receipt.commit_sequence() == p.application.commit_sequence,
            "outgoing native13 receipt changed"
        );
        // Receipt recovery above re-runs native historical cutoff selection.
        // The planning API intentionally refuses a checkpoint already committed.
        let cutoff = self.application.reopen_prepared_epoch_execution_v1(
            *self.selection.cutoff_head().block_id().as_bytes(),
        )?;
        let cutoff = self
            .application
            .confirm_prepared_epoch_execution_v1(&cutoff)?;
        ensure!(
            cutoff.prepared().overlay_parent_head()? == *self.selection.cutoff_head()
                && cutoff.prepared().p_digest() == self.selection.cutoff_p_digest()
                && cutoff.prepared().persist_sequence() == self.selection.cutoff_p_sequence()
                && cutoff.commit_sequence() == Some(self.selection.cutoff_commit_sequence()),
            "outgoing retained cutoff identity changed"
        );
        let context = self.receipt.strict_context();
        let proof = state
            .last_finalization_proof()
            .context("outgoing original finality missing")?;
        ensure!(
            self.driver.config().validator_set() == context.old_validator_set()
                && self.driver.config().consensus_parameters()
                    == context.old_consensus_parameters()
                && context.new_validator_set() == self.selection.new_validator_set()
                && context.new_consensus_parameters() == self.selection.new_parameters()
                && context.next_epoch_commitment_digest()
                    == self.selection.next_epoch_commitment().id()
                && context.checkpoint_finality_proof_id() == proof.id()
                && proof.finalized_block().header() == self.receipt.header()
                && self.seals.len() == 2
                && proof.child().header() == self.seals[0].block().header()
                && proof.grandchild().header() == self.seals[1].block().header()
                && state.old_epoch_boundary_v1().is_some_and(|b| {
                    self.seals
                        .iter()
                        .all(|seal| b.seals().iter().filter(|p| *p == seal).count() == 1)
                }),
            "outgoing retirement original proof/configuration changed"
        );
        let native = self
            .application
            .confirm_prepared_epoch_execution_v1(&self.prepared)?;
        let header = native.prepared().header()?;
        ensure!(
            native.commit_sequence() == Some(p.application.commit_sequence)
                && header == *self.receipt.header()
                && native.prepared().p_digest() == p.application.p_digest
                && native.artifact_checksum() == p.application.artifact_digest
                && native.overlay_checksum() == p.application.overlay_digest
                && state
                    .payload_validation_completions()
                    .iter()
                    .filter(|c| {
                        c.id().block_id() == header.id()
                            && c.result().artifact_ref().is_some_and(|a| {
                                a.source_artifact_checksum() == native.artifact_checksum()
                                    && a.overlay().block_id() == header.id()
                                    && a.overlay().parent_block_id() == header.parent_id()
                                    && a.overlay().overlay_checksum() == native.overlay_checksum()
                            })
                    })
                    .count()
                    == 1,
            "outgoing retirement lacks original committed P/Core Valid"
        );
        let final_head = self.journal.fresh_read_v1(self.pin)?;
        ensure!(
            final_head.state_v1() == state && safety_cut(&final_head) == p.target_safety,
            "outgoing Safety changed during source readback"
        );
        Ok(trnm_consensus_signer_journal::SignerRetirementHostCutV1 {
            owner_generation: p.owner_generation,
            native_committed_cut: self.receipt.committed_owner_cut_ref_v1(),
            safety_revision: head.revision_v1(),
            safety_record_checksum: head.state_record_checksum_v1(),
        })
    }
}

/// Consumed ordinary custody after real outgoing native13 retirement. It has
/// no ordinary signing, Core step, joint-signature or activation API.
///
/// ```compile_fail
/// use trnm_poco_node::EpochRetirementRuntimeV6;
/// use trnm_consensus_signer_journal::ExternalSignerRetirementV1;
/// fn copy<W: ExternalSignerRetirementV1, N: ExternalSignerRetirementV1>(v: EpochRetirementRuntimeV6<W,N>) {
///     let _ = v.clone();
/// }
/// ```
#[must_use]
pub struct EpochRetirementRuntimeV6<W: ExternalSignerRetirementV1, N: ExternalSignerRetirementV1> {
    source: Box<OutgoingEpochSourceV6<W>>,
    retired: RetiredSqliteSignerJournalV1<N>,
    retirement: ConfirmedOrdinarySignerRetirementV1,
    checkpoint_store: SqliteEpochNodeCheckpointStoreV1,
    checkpoint: EpochNodeCheckpointV1,
    fenced: bool,
}

impl<W: ExternalSignerRetirementV1, N: ExternalSignerRetirementV1> EpochPreHandoffRuntimeV5<W, N> {
    /// Retire only this owner's current N signer. Every error consumes the live
    /// owner, including local/external retirement and independent CAS uncertainty.
    pub fn retire_outgoing_epoch_v6(mut self) -> Result<EpochRetirementRuntimeV6<W, N>> {
        let predecessor = self.settled_pre_handoff_cut_v5()?;
        let mut inner = self.inner.take().context("outgoing owner fenced")?;
        ensure!(
            inner.prepared.len() == 1 && inner.applied,
            "outgoing P not settled"
        );
        let prepared = inner.prepared.pop().context("outgoing P missing")?.prepared;
        let CandidateEpochRuntimeV1 {
            driver,
            journal,
            pin,
            application,
            edge,
            retired: incoming_retired,
            retirement: incoming_retirement,
            mut ordinary,
            mut checkpoint_store,
            checkpoint,
            ..
        } = *inner.runtime;
        ensure!(checkpoint == predecessor, "outgoing predecessor changed");
        let mut source = Box::new(OutgoingEpochSourceV6 {
            driver,
            journal,
            pin,
            application,
            edge,
            incoming_retired,
            incoming_retirement,
            predecessor,
            prepared,
            selection: self.selection,
            receipt: self
                .receipt
                .take()
                .context("outgoing native13 receipt missing")?,
            seals: self.seals,
        });
        let host = source.confirm()?;
        let original = ordinary.confirm_node_checkpoint_head_exact_v0()?;
        let original_path = ordinary.path().to_path_buf();
        let expected = predecessor
            .fields()
            .ordinary
            .context("outgoing custody missing")?;
        let mark = original.exact_watermark();
        ensure!(
            original.belongs_to_operational_journal_at_path_v0(&ordinary, &original_path)
                && original.pending_intent().is_none()
                && mark.scope() == expected.scope
                && mark.journal_id() == expected.journal_id
                && mark.sequence() == expected.sequence
                && mark.chain_checksum() == expected.chain_checksum
                && original.profile_checksum() == expected.profile_checksum
                && ordinary.profile().validator_set() == source.driver.config().validator_set()
                && ordinary.profile().author() == source.driver.config().local_validator(),
            "outgoing original ordinary owner differs from independent checkpoint"
        );
        let intent = outgoing_intent_v6(&source)?;
        // Repeat the native/Safety source after external callbacks immediately
        // before invoking the producer that irreversibly removes signing authority.
        ensure!(
            source.confirm()? == host,
            "outgoing source changed before retirement"
        );
        checkpoint_store.confirm_exact(&predecessor)?;
        let mut retired =
            ordinary.retire_for_handoff_v1(source.receipt.strict_context(), &intent, host)?;
        ensure!(
            original.belongs_to_retired_journal_at_path_v1(&retired, &original_path),
            "retirement replaced the actual original owner"
        );
        let retirement = retired.confirm_retirement_v1()?;
        let mut owner = EpochRetirementRuntimeV6 {
            source,
            retired,
            retirement,
            checkpoint_store,
            checkpoint: predecessor,
            fenced: false,
        };
        let target = owner.join_target_v6()?;
        owner.checkpoint_store.confirm_exact(&predecessor)?;
        owner
            .checkpoint_store
            .compare_and_advance(&predecessor, &target)?;
        owner.checkpoint = target;
        owner.confirm_retired_cut_v6()?;
        Ok(owner)
    }
}

fn outgoing_intent_v6<W: ExternalSignerRetirementV1>(
    source: &OutgoingEpochSourceV6<W>,
) -> Result<trnm_consensus_types::CanonicalHandoffSignIntentV1> {
    let context = source.receipt.strict_context();
    trnm_consensus_types::CanonicalHandoffSignIntentV1::old_set(
        context.descriptor(),
        context.old_validator_set(),
        context.new_validator_set(),
        context.old_consensus_parameters(),
        context.new_consensus_parameters(),
        source.driver.config().local_validator(),
    )
    .map_err(|e| anyhow::anyhow!("outgoing canonical retirement intent: {e:?}"))
}

impl<W: ExternalSignerRetirementV1, N: ExternalSignerRetirementV1> EpochRetirementRuntimeV6<W, N> {
    fn join_target_v6(&mut self) -> Result<EpochNodeCheckpointV1> {
        let host = self.source.confirm()?;
        ensure!(
            self.retirement.belongs_to_owner_v1(&mut self.retired),
            "outgoing retired owner changed"
        );
        let record = self.retirement.record_v1();
        let intent = outgoing_intent_v6(&self.source)?;
        let context = self.source.receipt.strict_context();
        let profile = self.retired.profile_v1();
        let mut fields = *self.source.predecessor.fields();
        let ordinary = fields
            .ordinary
            .context("outgoing predecessor lacks ordinary custody")?;
        ensure!(
            record.host_cut_v1() == host
                && record.pre_handoff_binding_v1() == context.binding_ref()
                && record.descriptor_digest_v1()
                    == *intent.preimage().descriptor_digest().as_bytes()
                && record.old_handoff_intent_fingerprint_v1() == *intent.fingerprint().as_bytes()
                && record.source_v1().scope() == ordinary.scope
                && record.source_v1().journal_id() == ordinary.journal_id
                && record.source_v1().sequence() == ordinary.sequence
                && record.source_v1().chain_checksum() == ordinary.chain_checksum
                && record.source_profile_checksum_v1() == ordinary.profile_checksum
                && profile.profile_checksum() == ordinary.profile_checksum
                && profile.validator_set() == context.old_validator_set()
                && profile.author() == fields.author,
            "outgoing retirement differs from exact source/configuration"
        );
        let d = context.descriptor().fields();
        fields.phase = EpochCheckpointPhaseV1::EpochRetiredNative13;
        fields.role = if context
            .new_validator_set()
            .validators()
            .iter()
            .any(|v| v.id() == fields.author)
        {
            EpochCheckpointRoleV1::Continuing
        } else {
            EpochCheckpointRoleV1::Removed
        };
        fields.predecessor_kind = EpochCheckpointPredecessorV1::V1;
        fields.generation = fields
            .generation
            .checked_add(1)
            .context("outgoing node generation exhausted")?;
        fields.predecessor_checksum = self.source.predecessor.checksum();
        fields.phase_authority_binding = context.binding_ref();
        fields.source_safety = Some(fields.target_safety);
        fields.edge = EpochApplicationEdgeCutV1 {
            checkpoint_block_id: *self.source.receipt.header().id().as_bytes(),
            checkpoint_height: self.source.receipt.header().height().get(),
            checkpoint_state_root: *self.source.receipt.header().state_root().as_bytes(),
            terminal_old_block_id: *d.terminal_old_block_id.as_bytes(),
            terminal_old_height: d.terminal_old_height.get(),
            terminal_old_view: d.terminal_old_view.get(),
            terminal_old_qc_id: *d.terminal_old_qc_digest.as_bytes(),
            native_authorization_id: host.native_committed_cut,
        };
        fields.retired = Some(EpochRetiredCustodyCutV1 {
            epoch: fields.epoch,
            author: fields.author,
            validator_set_id: fields.validator_set_id,
            parameters_hash: fields.parameters_hash,
            scope: record.source_v1().scope(),
            journal_id: record.source_v1().journal_id(),
            profile_checksum: record.source_profile_checksum_v1(),
            source_sequence: record.source_v1().sequence(),
            source_chain_checksum: record.source_v1().chain_checksum(),
            terminal_sequence: record.terminal_watermark_v1().sequence(),
            terminal_chain_checksum: record.terminal_watermark_v1().chain_checksum(),
            retirement_record_checksum: record.checksum_v1(),
        });
        fields.ordinary = None;
        ensure!(
            self.source.confirm()? == host,
            "outgoing source changed after external retirement readback"
        );
        let target = EpochNodeCheckpointV1::new(fields)?;
        target.validate_successor_of(&self.source.predecessor)?;
        Ok(target)
    }

    /// Fresh comparison only. An uncertainty fences this retained terminal owner.
    pub fn confirm_retired_cut_v6(&mut self) -> Result<EpochNodeCheckpointV1> {
        ensure!(!self.fenced, "outgoing retired owner fenced");
        let result = (|| {
            self.checkpoint_store.confirm_exact(&self.checkpoint)?;
            ensure!(
                self.join_target_v6()? == self.checkpoint,
                "outgoing retired cut changed"
            );
            self.checkpoint_store.confirm_exact(&self.checkpoint)?;
            Ok(self.checkpoint)
        })();
        if result.is_err() {
            self.fenced = true;
        }
        result
    }
}
