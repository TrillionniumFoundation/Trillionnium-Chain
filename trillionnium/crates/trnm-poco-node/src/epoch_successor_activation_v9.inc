// Actual successor ownership. Historical Core data is comparison-only after
// the original driver is consumed; it cannot be converted back into a driver.
use trnm_consensus_core::{
    CoreConfig, EpochPreparationV2, EpochSafetyStateRecordContextV2, PendingEpochHostDriverV2,
    PreparedEpochCoreActivationV2, SafetyState,
};
use trnm_consensus_safety_store::{
    ConfirmedEpochSafetyHeadV4, EpochSafetyHeadPinV4, EpochSafetyJournalProfileV4,
    EpochSafetySourceKindV4, EpochSafetySourceOwnerV4, SqliteEpochSafetyJournalV4,
};

// Box both alternatives to retain the existing default thread-stack budget.
enum OutgoingEpochCoreV9 {
    Live(Box<PendingEpochHostDriverV1>),
    Historical(Box<(CoreConfig, SafetyState)>),
}
impl OutgoingEpochCoreV9 {
    fn state(&self) -> &SafetyState {
        match self {
            Self::Live(driver) => driver.state(),
            Self::Historical(value) => &value.1,
        }
    }
    fn config(&self) -> &CoreConfig {
        match self {
            Self::Live(driver) => driver.config(),
            Self::Historical(value) => &value.0,
        }
    }
    fn prepare_successor(
        &mut self,
        context: &EpochSafetyStateRecordContextV2<'_>,
    ) -> Result<PreparedEpochCoreActivationV2> {
        ensure!(
            matches!(self, Self::Live(_)),
            "successor Core already consumed"
        );
        let historical = Box::new((self.config().clone(), self.state().clone()));
        let Self::Live(driver) = std::mem::replace(self, Self::Historical(historical)) else {
            unreachable!("checked live Core")
        };
        let prepared = (*driver)
            .prepare_next_epoch_v2(context)
            .map_err(|e| anyhow::anyhow!("actual successor Core preparation: {e:?}"))?;
        ensure!(
            prepared.predecessor() == self.state(),
            "successor predecessor changed"
        );
        Ok(prepared)
    }
}

/// Actual native13 / Journal12 continuing owner. No generic Core, signer or
/// recovery conversion is exposed. The retained V8 source remains distinct.
///
/// ```compile_fail
/// use trnm_poco_node::SuccessorEpochRuntimeV9;
/// use trnm_consensus_signer_journal::{ExternalSignerRetirementV1, ExternalMonotonicWatermarkV0};
/// fn copy<W: ExternalSignerRetirementV1, N: ExternalSignerRetirementV1, H: ExternalMonotonicWatermarkV0, O: ExternalMonotonicWatermarkV0>(v: SuccessorEpochRuntimeV9<W,N,H,O>) {
///     let _ = v.clone();
/// }
/// ```
#[must_use]
pub struct SuccessorEpochRuntimeV9<
    W: ExternalSignerRetirementV1,
    N: ExternalSignerRetirementV1,
    H: ExternalMonotonicWatermarkV0,
    O: ExternalMonotonicWatermarkV0,
> {
    source: Box<EpochHandoffAttachedRuntimeV8<W, N, H>>,
    driver: Box<PendingEpochHostDriverV2>,
    journal: Box<SqliteEpochSafetyJournalV4>,
    profile: Box<EpochSafetyJournalProfileV4>,
    pin: EpochSafetyHeadPinV4,
    ordinary: SqliteSignerJournalV0<O>,
    checkpoint: EpochNodeCheckpointV1,
    startup: Vec<Effect>,
    fenced: bool,
}

impl<
        W: ExternalSignerRetirementV1,
        N: ExternalSignerRetirementV1,
        H: ExternalMonotonicWatermarkV0,
    > EpochHandoffAttachedRuntimeV8<W, N, H>
{
    /// Consume the actual settled Core, Journal9 source and attached native13
    /// owner. Any failure consumes custody; no uncertain ACK/signature escapes.
    #[inline(never)]
    pub fn activate_successor_v9<O: ExternalMonotonicWatermarkV0>(
        self,
        preparation: EpochPreparationV2,
        target_journal: impl AsRef<std::path::Path>,
        mut ordinary: SqliteSignerJournalV0<O>,
    ) -> Result<SuccessorEpochRuntimeV9<W, N, H, O>> {
        let mut source = Box::new(self);
        let parts = source.prepare_successor_parts_v9(preparation, &mut ordinary)?;
        let mut runtime =
            Self::initialize_successor_v9(source, parts, ordinary, target_journal.as_ref())?;
        runtime.publish_initial_v9()?;
        Ok(*runtime)
    }

    // Finish the large canonical/Core construction frame before entering the
    // independent Journal9-to-Journal12 source recovery stack.
    #[inline(never)]
    fn prepare_successor_parts_v9<O: ExternalMonotonicWatermarkV0>(
        &mut self,
        preparation: EpochPreparationV2,
        ordinary: &mut SqliteSignerJournalV0<O>,
    ) -> Result<Box<PreparedSuccessorPartsV9>> {
        let original = self.confirm_attached_cut_v8()?;
        ensure!(
            original.fields().role == EpochCheckpointRoleV1::Continuing,
            "successor requires continuing membership"
        );
        let activation = preparation.authority_v2();
        let source = &self.roles.retired.source;
        let old = source.driver.config();
        let next = source.receipt.strict_context();
        let proof = source
            .driver
            .state()
            .last_finalization_proof()
            .context("successor original finality missing")?;
        ensure!(
            activation.binding_ref().as_bytes() == &self.edge.successor_binding()
                && activation.old_validator_set() == old.validator_set()
                && activation.old_consensus_parameters() == old.consensus_parameters()
                && activation.new_validator_set() == next.new_validator_set()
                && activation.new_consensus_parameters() == next.new_consensus_parameters()
                && activation.old_checkpoint_finality() == proof
                && activation
                    .authorization_cev0_bytes()
                    .map_err(|e| anyhow::anyhow!("successor authorization bytes: {e:?}"))?
                    .as_slice()
                    == self.kernel.as_ref(),
            "successor preparation differs from original attached evidence"
        );
        let config = CoreConfig::new(
            old.local_validator(),
            activation.new_validator_set().clone(),
            *activation.new_consensus_parameters(),
            old.trusted_genesis_timestamp_ms(),
            old.max_blocks(),
            old.max_observed_messages(),
        )
        .map_err(|e| anyhow::anyhow!("successor Core config: {e:?}"))?;
        let old_key = old
            .validator_set()
            .validator(old.local_validator())
            .context("outgoing author missing")?
            .consensus_key();
        let new_key = config
            .validator_set()
            .validator(config.local_validator())
            .context("incoming author missing")?
            .consensus_key();
        ensure!(
            old_key == new_key,
            "successor key rotation requires distinct custody protocol"
        );
        let artifact = source
            .driver
            .state()
            .payload_validation_completions()
            .iter()
            .filter(|v| v.id().block_id() == source.receipt.header().id())
            .map(|v| v.result().artifact_ref())
            .collect::<Vec<_>>();
        ensure!(
            artifact.len() == 1,
            "successor exact checkpoint Valid missing"
        );
        let artifact = artifact[0].context("successor checkpoint invalid")?;
        ensure!(
            artifact.source_artifact_checksum() == original.fields().application.artifact_digest
                && artifact.overlay().overlay_checksum()
                    == original.fields().application.overlay_digest,
            "successor checkpoint artifact differs"
        );
        let generation = original
            .fields()
            .owner_generation
            .checked_add(1)
            .context("successor owner generation exhausted")?;
        let limits =
            trnm_consensus_core::minimum_epoch_safety_record_limits_v2(&config, &preparation)
                .map_err(|e| anyhow::anyhow!("successor record limits: {e:?}"))?;
        let context = EpochSafetyStateRecordContextV2::new(
            &config,
            preparation,
            artifact,
            generation,
            limits,
        )
        .map_err(|e| anyhow::anyhow!("successor context: {e:?}"))?;
        let profile = EpochSafetyJournalProfileV4::from_journal9_v4(
            self.roles.retired.source.journal.immutable_profile_v1(),
            &context,
        )?;
        // Reject foreign/nonvirgin custody before creating the target journal.
        let selected = ordinary.confirm_node_checkpoint_head_exact_v0()?;
        validate_new_custody_v9(self, &config, ordinary, &selected)?;
        self.confirm_attached_cut_v8()?;
        selected.confirm_local_owner_v1(ordinary)?;
        let prepared = self
            .roles
            .retired
            .source
            .driver
            .prepare_successor(&context)?;
        Ok(Box::new(PreparedSuccessorPartsV9 {
            original,
            profile: Box::new(profile),
            prepared: Box::new(prepared),
        }))
    }

    #[inline(never)]
    fn initialize_successor_v9<O: ExternalMonotonicWatermarkV0>(
        source: Box<Self>,
        parts: Box<PreparedSuccessorPartsV9>,
        ordinary: SqliteSignerJournalV0<O>,
        target_journal: &std::path::Path,
    ) -> Result<Box<SuccessorEpochRuntimeV9<W, N, H, O>>> {
        let (journal, initial) = SqliteEpochSafetyJournalV4::initialize_from_source_v4(
            target_journal,
            (*parts.profile).clone(),
            EpochSafetySourceOwnerV4::Journal9(
                &source.roles.retired.source.journal,
                source.roles.retired.source.pin,
            ),
            &parts.prepared,
        )?;
        let pin = initial.pin_v4();
        Ok(Box::new(SuccessorEpochRuntimeV9 {
            source,
            driver: Box::new((*parts.prepared).into_candidate_host_pending_v2()),
            journal: Box::new(journal),
            profile: parts.profile,
            pin,
            ordinary,
            checkpoint: parts.original,
            startup: Vec::new(),
            fenced: false,
        }))
    }
}

struct PreparedSuccessorPartsV9 {
    original: EpochNodeCheckpointV1,
    profile: Box<EpochSafetyJournalProfileV4>,
    prepared: Box<PreparedEpochCoreActivationV2>,
}

fn safety_cut_v9(head: &ConfirmedEpochSafetyHeadV4) -> EpochSafetyCutV1 {
    EpochSafetyCutV1 {
        journal_id: head.journal_id_v4(),
        context_ref: head.context_ref_v4(),
        revision: head.revision_v4(),
        record_checksum: head.state_record_checksum_v4(),
        chain_checksum: head.chain_checksum_v4(),
    }
}

fn validate_new_custody_v9<
    W: ExternalSignerRetirementV1,
    N: ExternalSignerRetirementV1,
    H: ExternalMonotonicWatermarkV0,
    O: ExternalMonotonicWatermarkV0,
>(
    source: &EpochHandoffAttachedRuntimeV8<W, N, H>,
    config: &CoreConfig,
    ordinary: &SqliteSignerJournalV0<O>,
    head: &trnm_consensus_signer_journal::ConfirmedSignerNodeCheckpointFactsV0,
) -> Result<()> {
    let retired = &source.roles.retired.retired;
    let mark = head.exact_watermark();
    let prior = retired.record_v1().terminal_watermark_v1();
    ensure!(
        head.belongs_to_operational_journal_at_path_v0(ordinary, ordinary.path())
            && ordinary.profile().validator_set() == config.validator_set()
            && ordinary.profile().author() == config.local_validator()
            && ordinary.profile().signer_profile_ref() == retired.profile_v1().signer_profile_ref()
            && mark.sequence() == 0
            && head.tail().is_none()
            && head.pending_intent().is_none()
            && head.capacity().intent_count() == 0
            && head.capacity().event_count() == 0
            && mark.scope() != prior.scope()
            && mark.journal_id() != prior.journal_id(),
        "successor custody is not exact distinct virgin owner"
    );
    Ok(())
}

impl<
        W: ExternalSignerRetirementV1,
        N: ExternalSignerRetirementV1,
        H: ExternalMonotonicWatermarkV0,
        O: ExternalMonotonicWatermarkV0,
    > SuccessorEpochRuntimeV9<W, N, H, O>
{
    #[inline(never)]
    fn publish_initial_v9(&mut self) -> Result<()> {
        let target = self.join_initial_v9()?;
        self.source
            .roles
            .retired
            .checkpoint_store
            .compare_and_advance(&self.checkpoint, &target)?;
        self.checkpoint = target;
        self.confirm_activated_cut_v9()?;
        let barrier = self.driver.initial_persistence_v2().barrier();
        let startup = self
            .driver
            .step_v2(Input::StorageAck { barrier })
            .map_err(|e| anyhow::anyhow!("successor initial ACK: {e:?}"))?;
        ensure!(
            matches!(startup.as_slice(), [Effect::ArmViewTimer { .. }]),
            "successor initial ACK emitted unexpected action"
        );
        self.startup = startup;
        self.confirm_activated_cut_v9()?;
        Ok(())
    }

    #[inline(never)]
    fn join_initial_v9(&mut self) -> Result<EpochNodeCheckpointV1> {
        ensure!(!self.fenced, "successor owner fenced");
        let ordinary = self.ordinary.confirm_node_checkpoint_head_exact_v0()?;
        validate_new_custody_v9(
            &self.source,
            self.driver.config(),
            &self.ordinary,
            &ordinary,
        )?;
        // Last external callbacks occur in this actual source confirmation.
        self.source.confirm_native_and_custody_v8()?;
        ordinary.confirm_local_owner_v1(&self.ordinary)?;
        let old = self
            .source
            .roles
            .retired
            .source
            .journal
            .fresh_read_v1(self.source.roles.retired.source.pin)?;
        let fresh = self.journal.confirm_exact_request_v4(
            self.pin,
            self.driver.initial_persistence_v2(),
            &SafetyTransitionContextV0::ordinary(),
        )?;
        let original = self.source.checkpoint;
        let epoch = self
            .driver
            .state()
            .epoch_state_v1()
            .context("successor epoch state missing")?;
        let migration = fresh.migration_source_v4();
        let source_pin = migration.pin_v4();
        ensure!(
            fresh.belongs_to_store_at_path_v4(&self.journal, self.journal.path_v4())
                && fresh.state_v4() == self.driver.state()
                && fresh.owner_generation_v4() == epoch.owner_generation()
                && old.state_v1() == self.source.roles.retired.source.driver.state()
                && safety_cut(&old) == original.fields().target_safety
                && source_pin.kind == EpochSafetySourceKindV4::Journal9
                && source_pin.journal_id == old.journal_id_v1()
                && source_pin.revision == old.revision_v1()
                && source_pin.chain_checksum == old.chain_checksum_v1()
                && migration.state_record_checksum_v4() == old.state_record_checksum_v1()
                && migration.context_ref_v4() == old.context_ref_v1()
                && migration.profile_ref_v4()
                    == self
                        .source
                        .roles
                        .retired
                        .source
                        .journal
                        .immutable_profile_v1()
                        .profile_ref_v1()
                && migration.initial_revision_v4() == fresh.revision_v4()
                && epoch.activation_binding() == self.source.edge.successor_binding(),
            "successor source/target physical journal join differs"
        );
        let record = epoch
            .preparation_record_v2()
            .context("successor complete prefix missing")?;
        let mark = ordinary.exact_watermark();
        let mut fields = *original.fields();
        fields.phase = EpochCheckpointPhaseV1::SuccessorActivationNative13Journal12;
        fields.generation = fields
            .generation
            .checked_add(1)
            .context("successor generation exhausted")?;
        fields.predecessor_checksum = original.checksum();
        fields.epoch = self.driver.config().validator_set().epoch().get();
        fields.validator_set_id = self.driver.config().validator_set().id().into_bytes();
        fields.parameters_hash = self
            .driver
            .config()
            .consensus_parameters()
            .hash()
            .into_bytes();
        fields.owner_generation = epoch.owner_generation();
        fields.source_safety = Some(original.fields().target_safety);
        fields.target_safety = safety_cut_v9(&fresh);
        fields.ordinary = Some(EpochOrdinaryCustodyCutV1 {
            scope: mark.scope(),
            journal_id: mark.journal_id(),
            profile_checksum: ordinary.profile_checksum(),
            sequence: mark.sequence(),
            chain_checksum: mark.chain_checksum(),
        });
        fields.phase_authority_binding = epoch_transition_digest(
            "trnm.node.successor-activation.v9",
            &[
                &original.checksum(),
                &12u16.to_be_bytes(),
                &self.profile.profile_ref_v4(),
                &fresh.context_ref_v4(),
                &source_pin.journal_id,
                &source_pin.revision.to_be_bytes(),
                &source_pin.chain_checksum,
                &migration.profile_ref_v4(),
                &migration.context_ref_v4(),
                &migration.state_record_checksum_v4(),
                &record.root_binding_v2(),
                &record.terminal_binding_v2(),
                &record.digest_v2(),
                &attached_edge_digest_v8(&self.source.edge),
                &ordinary.profile_checksum(),
                &mark.scope(),
                &mark.journal_id(),
                &mark.chain_checksum(),
            ],
        );
        let target = EpochNodeCheckpointV1::new(fields)?;
        target.validate_successor_of(&original)?;
        Ok(target)
    }

    /// Read-only exact activated cut. Any failure permanently fences this owner.
    pub fn confirm_activated_cut_v9(&mut self) -> Result<EpochNodeCheckpointV1> {
        ensure!(!self.fenced, "successor owner fenced");
        let result = (|| {
            self.source
                .roles
                .retired
                .checkpoint_store
                .confirm_exact(&self.checkpoint)?;
            ensure!(
                self.join_initial_v9()? == self.checkpoint,
                "successor independent cut differs"
            );
            self.source
                .roles
                .retired
                .checkpoint_store
                .confirm_exact(&self.checkpoint)?;
            Ok(self.checkpoint)
        })();
        if result.is_err() {
            self.fenced = true;
        }
        result
    }

    /// Release only the actual one-time post-ACK startup timer after fresh joins.
    pub fn take_startup_effects_v9(&mut self) -> Result<Vec<Effect>> {
        self.confirm_activated_cut_v9()?;
        Ok(std::mem::take(&mut self.startup))
    }
}
