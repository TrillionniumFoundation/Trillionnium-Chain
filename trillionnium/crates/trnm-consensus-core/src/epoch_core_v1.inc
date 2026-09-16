/// An inert activation proposal after consuming the previous live Core owner.
/// It retains the exact pending persistence request and its private Core affinity,
/// but exposes no step, StorageAck, signing, timer, or signer-lease API.
#[derive(Debug)]
pub struct PreparedEpochCoreActivationV1 {
    core: Box<Core>,
    predecessor: Box<SafetyState>,
    initial_request: SafetyStatePersistenceV0,
}
impl PreparedEpochCoreActivationV1 {
    pub fn config(&self) -> &CoreConfig {
        self.core.config()
    }
    pub fn state(&self) -> &SafetyState {
        self.core.safety_state()
    }
    pub fn predecessor(&self) -> &SafetyState {
        &self.predecessor
    }
    pub fn initial_persistence_v1(&self) -> &SafetyStatePersistenceV0 {
        &self.initial_request
    }
    pub fn persistence_binding_v1(&self) -> SafetyStatePersistenceBindingV0 {
        self.core.safety_state_persistence_binding_v0()
    }
}
impl OldEpochBoundaryCoreV1 {
    /// Consumes rather than clones the old consensus owner. This alone cannot
    /// retire the independently held old ordinary signer or create a new one.
    pub fn prepare_epoch_activation_v1(
        self,
        context: &crate::EpochSafetyStateRecordContextV1<'_>,
    ) -> Result<PreparedEpochCoreActivationV1> {
        let core = self.core;
        core.validate_runtime(&trnm_consensus_crypto::StrictEd25519Verifier, true)?;
        if core.pending_persistence.is_some() || core.awaiting_signature {
            return Err(CoreError::InvalidRecovery(
                "epoch activation has a pending live owner cut",
            ));
        }
        prepare_epoch_from_terminal_v1(&core.config, &core.safety, context)
    }
}
impl StrictOldEpochTerminalRecoveryV1 {
    /// Strict terminal evidence can propose the same deterministic activation
    /// record after a crash. The result remains inert; the journal must freshly
    /// match its actual source owner and the host must join native/custody cuts.
    pub fn prepare_epoch_activation_v1(
        &self,
        context: &crate::EpochSafetyStateRecordContextV1<'_>,
    ) -> Result<PreparedEpochCoreActivationV1> {
        prepare_epoch_from_terminal_v1(&self.config, &self.state, context)
    }
}

/// Complete strict 14E recovery facts. This deliberately has no Core input,
/// persistence ACK, callback replay, signing or lease API. Reconciled physical
/// owners must still be joined before the host may resume any recorded outbox.
#[derive(Debug)]
pub struct StrictEpochCoreRecoveryV1 {
    config: CoreConfig,
    state: Box<SafetyState>,
    context_ref: [u8; 32],
    record_checksum: [u8; 32],
}
impl StrictEpochCoreRecoveryV1 {
    pub fn config(&self) -> &CoreConfig {
        &self.config
    }
    pub fn state(&self) -> &SafetyState {
        &self.state
    }
    pub const fn context_ref(&self) -> [u8; 32] {
        self.context_ref
    }
    pub const fn record_checksum(&self) -> [u8; 32] {
        self.record_checksum
    }
    /// Proposes the next epoch only at the exact settled checkpoint. This
    /// advances neither this journal nor the native state or signer custody.
    pub fn prepare_next_epoch_v1(
        &self,
        context: &crate::EpochSafetyStateRecordContextV1<'_>,
    ) -> Result<PreparedEpochCoreActivationV1> {
        prepare_epoch_from_terminal_v1(&self.config, &self.state, context)
    }
}
fn prepare_epoch_from_terminal_v1(
    old_config: &CoreConfig,
    old: &SafetyState,
    context: &crate::EpochSafetyStateRecordContextV1<'_>,
) -> Result<PreparedEpochCoreActivationV1> {
    Core::validate_persisted_state_v0(
        old_config,
        old,
        &trnm_consensus_crypto::StrictEd25519Verifier,
    )?;
    let epoch = context.epoch();
    let activation = context.runtime().activation();
    if old.pending_sign().is_some()
        || old.pending_finalize().is_some()
        || !old.finalization_queue().is_empty()
        || !old.payload_validation_obligations().is_empty()
        || old.pending_tc_high_qc_sync().is_some()
        || old.pending_standalone_qc_sync().is_some()
        || old.safety_halt().is_some()
        || old.finalized() != old.application_applied()
        || old_config.validator_set() != activation.old_validator_set()
        || old_config.consensus_parameters() != activation.old_consensus_parameters()
        || old_config.local_validator() != context.core_config().local_validator()
        || old
            .old_epoch_boundary_v1()
            .map(|b| b.owner_generation().checked_add(1))
            != Some(Some(epoch.owner_generation()))
        || old.last_finalization_proof() != Some(activation.old_checkpoint_finality())
        || old.last_finalization().map(|f| f.target_overlay_ref())
            != Some(epoch.checkpoint_artifact().overlay())
        || old.finalized()
            != crate::QualifiedFinalizedTipV1::from_header(epoch.checkpoint_header()).tip()
    {
        return Err(CoreError::InvalidRecovery(
            "epoch activation predecessor is unresolved, foreign, or not exact checkpoint",
        ));
    }
    let state = SafetyState::from_epoch_activation_v1(
        context.core_config(),
        epoch.clone(),
        old.revision(),
    )?;
    let mut core = Core::empty(context.core_config().clone(), state, false);
    let effects = core.persist(Vec::new())?;
    let [Effect::PersistSafetyState(initial_request)] = effects.as_slice() else {
        return Err(CoreError::InvalidRecovery(
            "epoch activation did not produce its exact persistence barrier",
        ));
    };
    core.validate_runtime(&trnm_consensus_crypto::StrictEd25519Verifier, true)?;
    Ok(PreparedEpochCoreActivationV1 {
        core: Box::new(core),
        predecessor: Box::new(old.clone()),
        initial_request: initial_request.clone(),
    })
}

impl Core {
    pub fn prepare_epoch_recovery_v1(
        record: &crate::UnverifiedSafetyStateRecordV0,
        context: &crate::EpochSafetyStateRecordContextV1<'_>,
        expected_record_checksum: [u8; 32],
    ) -> Result<StrictEpochCoreRecoveryV1> {
        if record.state().epoch_state_v1() != Some(context.epoch()) {
            return Err(CoreError::InvalidRecovery(
                "full epoch recovery context differs",
            ));
        }
        Self::validate_persisted_state_v0(
            context.core_config(),
            record.state(),
            &trnm_consensus_crypto::StrictEd25519Verifier,
        )?;
        let raw = crate::encode_epoch_safety_record_v1(record.state(), context)
            .map_err(|_| CoreError::InvalidRecovery("full epoch recovery canonical encoding"))?;
        let exact = crate::decode_epoch_safety_record_v1_exact(&raw, context)
            .map_err(|_| CoreError::InvalidRecovery("full epoch recovery exact readback"))?;
        if expected_record_checksum == [0; 32]
            || record.record_checksum() != expected_record_checksum
            || exact.record_checksum() != expected_record_checksum
        {
            return Err(CoreError::InvalidRecovery(
                "full epoch record differs from expected cut",
            ));
        }
        Ok(StrictEpochCoreRecoveryV1 {
            config: context.core_config().clone(),
            state: Box::new(record.state().clone()),
            context_ref: crate::epoch_safety_record_context_ref_v1(context)
                .map_err(|_| CoreError::InvalidRecovery("full epoch context reference"))?,
            record_checksum: expected_record_checksum,
        })
    }
    fn exact_durable_header_v0(&self, id: BlockId) -> Option<&BlockHeader> {
        self.safety
            .last_finalization()
            .into_iter()
            .chain(self.safety.finalization_queue().iter())
            .flat_map(|f| {
                [
                    f.proof().finalized_block().header(),
                    f.proof().child().header(),
                    f.proof().grandchild().header(),
                ]
            })
            .find(|header| header.id() == id)
    }
    fn reconstruct_durable_finalization_v1(
        &self,
        durable: &DurableFinalizationV0,
    ) -> Result<DurableFinalizationV0> {
        if durable.epoch_application_parent_v1().is_some() {
            let epoch = self
                .safety
                .epoch_state_v1()
                .ok_or(CoreError::UnsupportedEpochAnchor)?;
            DurableFinalizationV0::for_epoch_application_v1(
                epoch,
                durable.proof().clone(),
                durable.target_overlay_ref(),
            )
        } else {
            DurableFinalizationV0::new(
                durable.authenticated_parent(),
                durable.proof().clone(),
                durable.target_overlay_ref(),
            )
        }
    }
    fn verify_durable_finalization_v1<V: SignatureVerifier>(
        &self,
        durable: &DurableFinalizationV0,
        verifier: &V,
    ) -> Result<()> {
        if let Some(epoch) = self.safety.epoch_state_v1() {
            epoch.strict_context()?.verify_finality_v1(
                durable.proof(),
                durable.consensus_parent_tip_v1().timestamp_ms(),
                &mut trnm_consensus_types::Cev0AdmissionBudgetV0::for_parameters(
                    self.config.consensus_parameters(),
                ),
            )?;
        } else {
            durable.proof().verify(
                self.config.validator_set(),
                None,
                self.config.consensus_parameters(),
                durable.authenticated_parent().timestamp_ms(),
                verifier,
            )?;
        }
        Ok(())
    }
    fn verify_timeout_certificate_v1<V: SignatureVerifier>(
        &self,
        certificate: &TimeoutCertificateV0,
        verifier: &V,
    ) -> Result<()> {
        if let Some(epoch) = self.safety.epoch_state_v1() {
            epoch.strict_context()?.verify_timeout_certificate_v1(
                certificate,
                &mut trnm_consensus_types::Cev0AdmissionBudgetV0::for_parameters(
                    self.config.consensus_parameters(),
                ),
            )?;
        } else {
            certificate.verify(self.config.validator_set(), None, verifier)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod epoch_consumer_tests_v1 {
    use super::*;
    use crate::{
        epoch_state_tests_v1 as fixture, BlockIdOverlayRefV0, ValidatedPayloadArtifactRefV0,
    };
    use trnm_consensus_crypto::StrictEd25519Verifier;

    #[test]
    fn first_new_three_chain_preserves_both_parents_and_rejects_missing_p() {
        run_first_new_three_chain(&[1, 2, 3, 4]);
    }

    #[test]
    fn tc_before_first_new_retains_the_exact_anchor_in_durable_obligation_and_queue() {
        run_first_new_three_chain(&[3, 5, 8, 9]);
    }

    fn run_first_new_three_chain(views: &[u64]) {
        let runtime = fixture::runtime();
        let config = fixture::config(&runtime);
        let chain = fixture::first_chain(&runtime, views);
        let limits = crate::minimum_epoch_safety_record_limits_v1(&config, &runtime).unwrap();
        let artifact = fixture::artifact(&runtime);
        let context =
            crate::EpochSafetyStateRecordContextV1::new(&config, runtime, artifact, 2, limits)
                .unwrap();
        let state =
            SafetyState::from_epoch_activation_v1(&config, context.epoch().clone(), 42).unwrap();
        // Private pure-engine harness: no native/SafetyStore/custody owner is
        // issued by this test or by this internal constructor.
        let mut core = Core::empty(config.clone(), state, false);
        let checkpoint = core.safety.finalized();
        let terminal = context.epoch().terminal_old_header();
        let first = &chain[0].0;
        let id = core.next_validation_id(first).unwrap();
        core.insert_payload_validation_obligation(PayloadValidationRouteV0::Proposal, id, first)
            .unwrap();
        core.pending_validations
            .insert(id, PendingPayloadValidationV0::new(first.clone()));
        core.safety.next_revision().unwrap();
        core.validate_payload_validation_obligations(&StrictEd25519Verifier, true)
            .unwrap();
        let parent = core.safety.payload_validation_obligations()[0].parent();
        assert_eq!(parent.tip(), checkpoint);
        assert_eq!(parent.consensus_parent_tip_v1().block_id(), terminal.id());
        assert_eq!(parent.consensus_parent_tip_v1().view(), View::new(0));
        let raw = crate::encode_epoch_safety_record_v1(&core.safety, &context).unwrap();
        let decoded = crate::decode_epoch_safety_record_v1_exact(&raw, &context).unwrap();
        assert_eq!(decoded.state(), &core.safety);
        let recovery =
            Core::prepare_epoch_recovery_v1(&decoded, &context, decoded.record_checksum()).unwrap();
        assert_eq!(recovery.state(), &core.safety);
        assert_eq!(recovery.state().payload_validation_obligations().len(), 1);
        assert!(Core::prepare_epoch_recovery_v1(&decoded, &context, [0; 32]).is_err());
        let mut substituted = core.safety.payload_validation_obligations().to_vec();
        substituted[0] = DurablePayloadValidationObligationV0::new(
            PayloadValidationRouteV0::Proposal,
            id,
            first.clone(),
            PayloadValidationParentV0::from_finalized_exact_header(terminal.clone()),
            id.generation(),
        );
        let exact = core.safety.payload_validation_obligations().to_vec();
        core.safety.set_payload_validation_obligations(substituted);
        assert!(core
            .validate_payload_validation_obligations(&StrictEd25519Verifier, true)
            .is_err());
        core.safety.set_payload_validation_obligations(exact);
        core.remove_payload_validation_obligation(PayloadValidationRouteV0::Proposal, id)
            .unwrap();
        core.pending_validations.clear();
        for (index, (proposal, _, commitments)) in chain.iter().enumerate() {
            core.blocks.insert_verified_proposal(proposal, &[]).unwrap();
            let h = proposal.block().header();
            let overlay = if index == 0 {
                BlockIdOverlayRefV0::for_epoch_application_v1(
                    h.id(),
                    checkpoint.block_id(),
                    terminal.id(),
                    context.epoch().activation_binding(),
                    [0x31; 32],
                )
                .unwrap()
            } else {
                BlockIdOverlayRefV0::new(h.id(), h.parent_id(), [index as u8; 32])
            };
            let result = PayloadValidationResult::authorized_valid_v0(
                *commitments,
                ValidatedPayloadArtifactRefV0::new(overlay, [0x73; 32]),
            );
            core.validate_payload_artifact_parent(proposal, result)
                .unwrap();
            if index == 0 {
                let wrong = PayloadValidationResult::authorized_valid_v0(
                    *commitments,
                    ValidatedPayloadArtifactRefV0::new(
                        BlockIdOverlayRefV0::new(h.id(), h.parent_id(), [0x74; 32]),
                        [0x75; 32],
                    ),
                );
                assert!(core
                    .validate_payload_artifact_parent(proposal, wrong)
                    .is_err());
            }
            // Handoff plus its child is insufficient; every payload result
            // on the certified three-chain is needed before finality advances.
            if index == 2 {
                assert!(core
                    .blocks
                    .detect_three_chain_suffix(
                        &chain[2].1,
                        config.validator_set(),
                        config.consensus_parameters(),
                        checkpoint,
                        core.safety.epoch_state_v1()
                    )
                    .unwrap()
                    .is_empty());
                assert_eq!(core.safety.finalized(), checkpoint);
                assert!(core.safety.finalization_queue().is_empty());
            }
            core.blocks
                .record_payload_validation_for_proposal(proposal, result)
                .unwrap();
            core.record_payload_terminal_fact(h.id(), result).unwrap();
            core.safety.next_revision().unwrap();
        }
        let before_finality = core.safety.clone();
        core.process_verified_ready_qc(&chain[3].1, &StrictEd25519Verifier)
            .unwrap();
        assert_eq!(core.safety.application_applied(), checkpoint);
        assert_eq!(core.safety.finalization_queue().len(), 2);
        let first_final = &core.safety.finalization_queue()[0];
        assert_eq!(first_final.authenticated_parent(), checkpoint);
        assert_eq!(
            first_final.consensus_parent_tip_v1().block_id(),
            terminal.id()
        );
        assert_eq!(
            first_final.target_overlay_ref().parent_block_id(),
            checkpoint.block_id()
        );
        assert_eq!(
            core.safety.finalization_queue()[1]
                .authenticated_parent()
                .block_id(),
            chain[0].0.block().id()
        );
        core.persist(Vec::new()).unwrap();
        core.validate_runtime(&StrictEd25519Verifier, true).unwrap();
        Core::validate_persisted_successor_v0(
            &config,
            &before_finality,
            &core.safety,
            &StrictEd25519Verifier,
        )
        .unwrap();
        let mut missing_edge = core.safety.clone();
        missing_edge.set_finalization_queue(Vec::new());
        assert!(Core::validate_persisted_successor_v0(
            &config,
            &before_finality,
            &missing_edge,
            &StrictEd25519Verifier
        )
        .is_err());
        let raw = crate::encode_epoch_safety_record_v1(&core.safety, &context).unwrap();
        assert_eq!(
            crate::decode_epoch_safety_record_v1_exact(&raw, &context)
                .unwrap()
                .state(),
            &core.safety
        );
    }
}
