pub enum ReconcileOutcomeV1 {
    CommitRequired(CommitPlanV1),
    Permit(SignaturePermitV1),
}

#[derive(Debug)]
pub struct CrossStoreCoordinatorV1 {
    config: CoordinatorConfigV1,
    current_checkpoint: Option<WholeNodeCheckpointV1>,
    current_watermark: Option<ExternalWatermarkV1>,
    fenced: bool,
}

impl CrossStoreCoordinatorV1 {
    pub fn open(
        config: CoordinatorConfigV1,
        checkpoint: Option<WholeNodeCheckpointV1>,
        watermark: Option<ExternalWatermarkV1>,
    ) -> Result<Self, CoordinatorErrorV1> {
        validate_checkpoint_watermark_relation(config, checkpoint, watermark)?;
        Ok(Self {
            config,
            current_checkpoint: checkpoint,
            current_watermark: watermark,
            fenced: false,
        })
    }

    pub const fn is_fenced(&self) -> bool {
        self.fenced
    }

    pub fn reconcile(
        &mut self,
        cut: CandidateCutV1,
        observed_checkpoint: Option<WholeNodeCheckpointV1>,
        observed_watermark: Option<ExternalWatermarkV1>,
    ) -> Result<ReconcileOutcomeV1, CoordinatorErrorV1> {
        if self.fenced {
            return Err(CoordinatorErrorV1::Fenced);
        }
        validate_cut(self.config, cut)?;

        if let Some(current) = self.current_checkpoint {
            if cut.target == current.target {
                validate_replay_cut(cut, current, self.current_watermark)?;
                if observed_checkpoint != self.current_checkpoint
                    || observed_watermark != self.current_watermark
                {
                    return self.fence(classify_observed_state(
                        self.current_checkpoint,
                        self.current_watermark,
                        observed_checkpoint,
                        observed_watermark,
                        self.current_checkpoint,
                        self.current_watermark,
                    ));
                }
                return Ok(ReconcileOutcomeV1::Permit(SignaturePermitV1 {
                    target: current.target,
                    checkpoint_generation: current.generation,
                    checkpoint_scope: current.checkpoint_scope,
                    namespace_scope: self.config.namespace_scope,
                    application_store_id: self.config.application_store_id,
                    safety_store_id: self.config.safety_store_id,
                    signer_journal_id: self.config.signer_journal_id,
                    node_id: self.config.node_id,
                    signer_key_id: self.config.signer_key_id,
                    custody_policy_hash: self.config.custody_policy_hash,
                    process_generation: self.config.process_generation,
                }));
            }
            validate_monotonic_successor(cut, current, self.current_watermark)?;
        }

        let (target_checkpoint, target_watermark) = build_targets(
            self.config,
            cut,
            self.current_checkpoint,
            self.current_watermark,
        )?;

        if observed_checkpoint == self.current_checkpoint
            && observed_watermark == self.current_watermark
        {
            return Ok(ReconcileOutcomeV1::CommitRequired(CommitPlanV1 {
                checkpoint: target_checkpoint,
                watermark: target_watermark,
            }));
        }
        if observed_checkpoint == Some(target_checkpoint)
            && observed_watermark == Some(target_watermark)
        {
            self.current_checkpoint = Some(target_checkpoint);
            self.current_watermark = Some(target_watermark);
            return Ok(ReconcileOutcomeV1::Permit(SignaturePermitV1 {
                target: cut.target,
                checkpoint_generation: target_checkpoint.generation,
                checkpoint_scope: target_checkpoint.checkpoint_scope,
                namespace_scope: self.config.namespace_scope,
                application_store_id: self.config.application_store_id,
                safety_store_id: self.config.safety_store_id,
                signer_journal_id: self.config.signer_journal_id,
                node_id: self.config.node_id,
                signer_key_id: self.config.signer_key_id,
                custody_policy_hash: self.config.custody_policy_hash,
                process_generation: self.config.process_generation,
            }));
        }

        self.fence(classify_observed_state(
            self.current_checkpoint,
            self.current_watermark,
            observed_checkpoint,
            observed_watermark,
            Some(target_checkpoint),
            Some(target_watermark),
        ))
    }

    fn fence<T>(&mut self, error: CoordinatorErrorV1) -> Result<T, CoordinatorErrorV1> {
        self.fenced = true;
        Err(error)
    }
}

fn validate_cut(
    config: CoordinatorConfigV1,
    cut: CandidateCutV1,
) -> Result<(), CoordinatorErrorV1> {
    if cut.application.namespace_scope != config.namespace_scope
        || cut.safety.namespace_scope != config.namespace_scope
        || cut.signer.namespace_scope != config.namespace_scope
    {
        return Err(CoordinatorErrorV1::NamespaceMismatch);
    }
    if cut.application.store_id != config.application_store_id
        || cut.safety.store_id != config.safety_store_id
        || cut.signer.journal_id != config.signer_journal_id
    {
        return Err(CoordinatorErrorV1::StoreIdentityMismatch);
    }
    if cut.signer.signer_key_id != config.signer_key_id
        || cut.signer.custody_policy_hash != config.custody_policy_hash
    {
        return Err(CoordinatorErrorV1::CustodyBindingMismatch);
    }
    if cut.signer.process_generation != config.process_generation {
        return Err(CoordinatorErrorV1::ProcessGenerationMismatch);
    }
    if !cut.application.durable {
        return Err(CoordinatorErrorV1::ApplicationNotDurable);
    }
    if !cut.safety.durable {
        return Err(CoordinatorErrorV1::SafetyNotDurable);
    }
    if !cut.signer.durable {
        return Err(CoordinatorErrorV1::SignerIntentNotDurable);
    }
    if cut.safety.transition_tag != SAFETY_FINALIZATION_TAG_V1 {
        return Err(CoordinatorErrorV1::WrongSafetyTransitionTag);
    }
    if cut.application.sequence == 0 || cut.safety.revision == 0 || cut.signer.sequence == 0 {
        return Err(CoordinatorErrorV1::ZeroSequence);
    }
    let target = cut.target;
    if cut.application.height != target.height
        || cut.application.block_id != target.block_id
        || cut.application.body_hash != target.body_hash
        || cut.application.application_root != target.application_root
        || cut.application.receipts_root != target.receipts_root
    {
        return Err(CoordinatorErrorV1::ApplicationTargetMismatch);
    }
    if cut.safety.epoch != target.epoch
        || cut.safety.view != target.view
        || cut.safety.height != target.height
        || cut.safety.block_id != target.block_id
        || cut.safety.body_hash != target.body_hash
        || cut.safety.application_root != target.application_root
        || cut.safety.safety_state_hash != target.safety_state_hash
    {
        return Err(CoordinatorErrorV1::SafetyTargetMismatch);
    }
    if cut.signer.epoch != target.epoch
        || cut.signer.view != target.view
        || cut.signer.block_id != target.block_id
        || cut.signer.sign_intent_hash != target.sign_intent_hash
        || cut.signer.signing_root != target.signing_root
    {
        return Err(CoordinatorErrorV1::SignerTargetMismatch);
    }
    Ok(())
}

fn validate_checkpoint_watermark_relation(
    config: CoordinatorConfigV1,
    checkpoint: Option<WholeNodeCheckpointV1>,
    watermark: Option<ExternalWatermarkV1>,
) -> Result<(), CoordinatorErrorV1> {
    match (checkpoint, watermark) {
        (None, None) => Ok(()),
        (Some(checkpoint), Some(watermark)) => {
            if checkpoint.checkpoint_scope != config.checkpoint_scope
                || checkpoint.namespace_scope != config.namespace_scope
                || watermark.checkpoint_scope != config.checkpoint_scope
                || watermark.namespace_scope != config.namespace_scope
            {
                return Err(CoordinatorErrorV1::NamespaceMismatch);
            }
            if checkpoint.application_store_id != config.application_store_id
                || checkpoint.safety_store_id != config.safety_store_id
                || checkpoint.signer_journal_id != config.signer_journal_id
                || watermark.application_store_id != config.application_store_id
                || watermark.safety_store_id != config.safety_store_id
                || watermark.journal_id != config.signer_journal_id
            {
                return Err(CoordinatorErrorV1::StoreIdentityMismatch);
            }
            if checkpoint.node_id != config.node_id
                || watermark.node_id != config.node_id
                || checkpoint.signer_key_id != config.signer_key_id
                || watermark.signer_key_id != config.signer_key_id
                || checkpoint.custody_policy_hash != config.custody_policy_hash
                || watermark.custody_policy_hash != config.custody_policy_hash
            {
                return Err(CoordinatorErrorV1::CustodyBindingMismatch);
            }
            if checkpoint.process_generation != config.process_generation
                || watermark.process_generation != config.process_generation
            {
                return Err(CoordinatorErrorV1::ProcessGenerationMismatch);
            }
            if checkpoint.application_store_id != watermark.application_store_id
                || checkpoint.safety_store_id != watermark.safety_store_id
                || checkpoint.signer_journal_id != watermark.journal_id
                || checkpoint.external_watermark_sequence != watermark.sequence
                || checkpoint.generation != watermark.checkpoint_generation
                || checkpoint.generation == 0
                || checkpoint.predecessor_generation.checked_add(1)
                    != Some(checkpoint.generation)
                || checkpoint.application_sequence == 0
                || checkpoint.safety_revision == 0
                || checkpoint.signer_sequence == 0
                || watermark.sequence == 0
                || checkpoint.target.epoch != watermark.epoch
                || checkpoint.target.view != watermark.view
                || checkpoint.target.height != watermark.height
                || checkpoint.safety_revision != watermark.safety_revision
                || checkpoint.signer_sequence != watermark.signer_sequence
                || checkpoint.target.signing_root != watermark.signing_root
            {
                return Err(CoordinatorErrorV1::CheckpointWatermarkMismatch);
            }
            Ok(())
        }
        _ => Err(CoordinatorErrorV1::MixedCommit),
    }
}

fn validate_replay_cut(
    cut: CandidateCutV1,
    checkpoint: WholeNodeCheckpointV1,
    watermark: Option<ExternalWatermarkV1>,
) -> Result<(), CoordinatorErrorV1> {
    let watermark = watermark.ok_or(CoordinatorErrorV1::MixedCommit)?;
    if cut.application.sequence != checkpoint.application_sequence
        || cut.safety.revision != checkpoint.safety_revision
        || cut.signer.sequence != checkpoint.signer_sequence
        || watermark.checkpoint_generation != checkpoint.generation
    {
        return Err(CoordinatorErrorV1::SameHeightConflict);
    }
    Ok(())
}

fn validate_monotonic_successor(
    cut: CandidateCutV1,
    checkpoint: WholeNodeCheckpointV1,
    watermark: Option<ExternalWatermarkV1>,
) -> Result<(), CoordinatorErrorV1> {
    let watermark = watermark.ok_or(CoordinatorErrorV1::MixedCommit)?;
    if cut.target.height < checkpoint.target.height {
        return Err(CoordinatorErrorV1::HeightRollback);
    }
    if cut.target.height == checkpoint.target.height {
        return Err(CoordinatorErrorV1::SameHeightConflict);
    }
    if (cut.target.epoch, cut.target.view) <= (checkpoint.target.epoch, checkpoint.target.view) {
        return Err(CoordinatorErrorV1::RoundRollback);
    }
    if cut.application.sequence <= checkpoint.application_sequence
        || cut.safety.revision <= checkpoint.safety_revision
        || cut.signer.sequence <= checkpoint.signer_sequence
        || watermark.sequence == u64::MAX
    {
        return Err(CoordinatorErrorV1::SequenceRollback);
    }
    Ok(())
}

fn build_targets(
    config: CoordinatorConfigV1,
    cut: CandidateCutV1,
    predecessor_checkpoint: Option<WholeNodeCheckpointV1>,
    predecessor_watermark: Option<ExternalWatermarkV1>,
) -> Result<(WholeNodeCheckpointV1, ExternalWatermarkV1), CoordinatorErrorV1> {
    let (predecessor_generation, generation) = match predecessor_checkpoint {
        Some(checkpoint) => (
            checkpoint.generation,
            checkpoint
                .generation
                .checked_add(1)
                .ok_or(CoordinatorErrorV1::ArithmeticOverflow)?,
        ),
        None => (0, 1),
    };
    let watermark_sequence = match predecessor_watermark {
        Some(watermark) => watermark
            .sequence
            .checked_add(1)
            .ok_or(CoordinatorErrorV1::ArithmeticOverflow)?,
        None => 1,
    };
    let checkpoint = WholeNodeCheckpointV1 {
        checkpoint_scope: config.checkpoint_scope,
        namespace_scope: config.namespace_scope,
        application_store_id: config.application_store_id,
        safety_store_id: config.safety_store_id,
        signer_journal_id: config.signer_journal_id,
        generation,
        predecessor_generation,
        target: cut.target,
        application_sequence: cut.application.sequence,
        safety_revision: cut.safety.revision,
        signer_sequence: cut.signer.sequence,
        external_watermark_sequence: watermark_sequence,
        node_id: config.node_id,
        signer_key_id: config.signer_key_id,
        custody_policy_hash: config.custody_policy_hash,
        process_generation: config.process_generation,
    };
    let watermark = ExternalWatermarkV1 {
        namespace_scope: config.namespace_scope,
        checkpoint_scope: config.checkpoint_scope,
        application_store_id: config.application_store_id,
        safety_store_id: config.safety_store_id,
        journal_id: config.signer_journal_id,
        sequence: watermark_sequence,
        checkpoint_generation: generation,
        epoch: cut.target.epoch,
        view: cut.target.view,
        height: cut.target.height,
        safety_revision: cut.safety.revision,
        signer_sequence: cut.signer.sequence,
        signing_root: cut.target.signing_root,
        node_id: config.node_id,
        signer_key_id: config.signer_key_id,
        custody_policy_hash: config.custody_policy_hash,
        process_generation: config.process_generation,
    };
    Ok((checkpoint, watermark))
}

fn classify_observed_state(
    current_checkpoint: Option<WholeNodeCheckpointV1>,
    current_watermark: Option<ExternalWatermarkV1>,
    observed_checkpoint: Option<WholeNodeCheckpointV1>,
    observed_watermark: Option<ExternalWatermarkV1>,
    target_checkpoint: Option<WholeNodeCheckpointV1>,
    target_watermark: Option<ExternalWatermarkV1>,
) -> CoordinatorErrorV1 {
    let checkpoint_known = observed_checkpoint == current_checkpoint
        || observed_checkpoint == target_checkpoint;
    let watermark_known = observed_watermark == current_watermark
        || observed_watermark == target_watermark;
    if checkpoint_known
        && watermark_known
        && ((observed_checkpoint == current_checkpoint
            && observed_watermark == target_watermark)
            || (observed_checkpoint == target_checkpoint
                && observed_watermark == current_watermark))
    {
        CoordinatorErrorV1::MixedCommit
    } else {
        CoordinatorErrorV1::ThirdState
    }
}
