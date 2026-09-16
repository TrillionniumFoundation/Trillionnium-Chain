/// An inert activation proposal after consuming the previous live Core owner.
/// It exposes no step, StorageAck, signing, timer, or persistence-binding API.
/// The actual host must persist this exact record and join native+custody+store
/// owners before a new live owner can exist.
#[derive(Debug)]
pub struct PreparedEpochCoreActivationV1 {
    config: CoreConfig,
    state: SafetyState,
    predecessor: SafetyState,
}
impl PreparedEpochCoreActivationV1 {
    pub fn config(&self) -> &CoreConfig { &self.config }
    pub fn state(&self) -> &SafetyState { &self.state }
    pub fn predecessor(&self) -> &SafetyState { &self.predecessor }
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
        let old = &core.safety;
        let epoch = context.epoch();
        let activation = context.runtime().activation();
        if core.pending_persistence.is_some() || core.awaiting_signature
            || old.pending_sign().is_some() || old.pending_finalize().is_some()
            || !old.finalization_queue().is_empty() || !old.payload_validation_obligations().is_empty()
            || old.pending_tc_high_qc_sync().is_some() || old.pending_standalone_qc_sync().is_some()
            || old.safety_halt().is_some() || old.finalized() != old.application_applied()
            || core.config.validator_set() != activation.old_validator_set()
            || core.config.consensus_parameters() != activation.old_consensus_parameters()
            || core.config.local_validator() != context.core_config().local_validator()
            || old.old_epoch_boundary_v1().map(|b| b.owner_generation().checked_add(1)) != Some(Some(epoch.owner_generation()))
            || old.last_finalization_proof() != Some(activation.old_checkpoint_finality())
            || old.last_finalization().map(|f| f.target_overlay_ref()) != Some(epoch.checkpoint_artifact().overlay())
            || old.finalized() != crate::QualifiedFinalizedTipV1::from_header(epoch.checkpoint_header()).tip()
        {
            return Err(CoreError::InvalidRecovery("epoch activation predecessor is unresolved, foreign, or not exact checkpoint"));
        }
        let revision = old.revision().checked_add(1).ok_or(CoreError::ArithmeticOverflow("epoch activation revision"))?;
        let state = SafetyState::from_epoch_activation_v1(context.core_config(), epoch.clone(), revision)?;
        Core::validate_persisted_state_v0(context.core_config(), &state, &trnm_consensus_crypto::StrictEd25519Verifier)?;
        Ok(PreparedEpochCoreActivationV1 { config: context.core_config().clone(), state, predecessor: core.safety })
    }
}

impl Core {
    fn exact_durable_header_v0(&self, id: BlockId) -> Option<&BlockHeader> {
        self.safety.last_finalization().into_iter()
            .chain(self.safety.finalization_queue().iter())
            .flat_map(|f| [f.proof().finalized_block().header(), f.proof().child().header(), f.proof().grandchild().header()])
            .find(|header| header.id() == id)
    }
    fn reconstruct_durable_finalization_v1(&self, durable: &DurableFinalizationV0) -> Result<DurableFinalizationV0> {
        if durable.epoch_application_parent_v1().is_some() {
            let epoch = self.safety.epoch_state_v1().ok_or(CoreError::UnsupportedEpochAnchor)?;
            DurableFinalizationV0::for_epoch_application_v1(epoch, durable.proof().clone(), durable.target_overlay_ref())
        } else {
            DurableFinalizationV0::new(durable.authenticated_parent(), durable.proof().clone(), durable.target_overlay_ref())
        }
    }
    fn verify_durable_finalization_v1<V: SignatureVerifier>(&self, durable: &DurableFinalizationV0, verifier: &V) -> Result<()> {
        if let Some(epoch) = self.safety.epoch_state_v1() {
            epoch.strict_context()?.verify_finality_v1(durable.proof(), durable.consensus_parent_tip_v1().timestamp_ms(),
                &mut trnm_consensus_types::Cev0AdmissionBudgetV0::for_parameters(self.config.consensus_parameters()))?;
        } else {
            durable.proof().verify(self.config.validator_set(), None, self.config.consensus_parameters(),
                durable.authenticated_parent().timestamp_ms(), verifier)?;
        }
        Ok(())
    }
    fn verify_timeout_certificate_v1<V: SignatureVerifier>(&self, certificate: &TimeoutCertificateV0, verifier: &V) -> Result<()> {
        if let Some(epoch) = self.safety.epoch_state_v1() {
            epoch.strict_context()?.verify_timeout_certificate_v1(certificate,
                &mut trnm_consensus_types::Cev0AdmissionBudgetV0::for_parameters(self.config.consensus_parameters()))?;
        } else { certificate.verify(self.config.validator_set(), None, verifier)?; }
        Ok(())
    }
}
