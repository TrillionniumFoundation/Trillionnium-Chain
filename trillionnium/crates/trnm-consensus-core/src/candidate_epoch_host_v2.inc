/// Default-off codec2 trusted-host driver, not a durable activation receipt.
/// Core and its original request affinity stay private. The physical host must
/// join journal10, native state, custody and its independent checkpoint before
/// delivering the initial ACK. No V1 conversion or selectable verifier exists.
///
/// ```compile_fail
/// use trnm_consensus_core::PendingEpochHostDriverV2;
/// fn require_clone<T: Clone>() {}
/// require_clone::<PendingEpochHostDriverV2>();
/// ```
/// ```compile_fail
/// use trnm_consensus_core::PreparedEpochCoreActivationV2;
/// fn downgrade(p: PreparedEpochCoreActivationV2) {
///     p.into_candidate_host_pending_v2().into_candidate_host_pending_v1();
/// }
/// ```
#[derive(Debug)]
pub struct PendingEpochHostDriverV2 {
    core: Box<Core>,
    initial_request: SafetyStatePersistenceV0,
    activation_pending: bool,
}

impl PreparedEpochCoreActivationV2 {
    /// Consume the original codec2 preparation without acknowledging storage.
    pub fn into_candidate_host_pending_v2(self) -> PendingEpochHostDriverV2 {
        PendingEpochHostDriverV2 {
            core: self.inner.core,
            initial_request: self.inner.initial_request,
            activation_pending: true,
        }
    }
}

impl StrictEpochCoreRecoveryV2 {
    /// Reconstruct only the canonical initial codec2 cut, with a fresh process
    /// affinity. This does not bind or acknowledge any physical journal owner.
    #[inline(never)]
    pub fn into_candidate_host_initial_pending_v2(self) -> Result<PendingEpochHostDriverV2> {
        let StrictEpochCoreRecoveryV1 { config, state, .. } = self.inner;
        let epoch = state.epoch_state_v1().ok_or(CoreError::InvalidRecovery(
            "codec2 candidate recovery lacks full epoch context",
        ))?;
        if epoch.preparation_record_v2().is_none() {
            return Err(CoreError::InvalidRecovery(
                "codec2 candidate recovery lacks provenance",
            ));
        }
        let initial = Box::new(SafetyState::from_epoch_activation_v1(
            &config,
            epoch.clone(),
            state.revision(),
        )?);
        if initial != state {
            return Err(CoreError::InvalidRecovery(
                "codec2 candidate initial recovery rejects progressed or pending-outbox state",
            ));
        }
        let barrier = BarrierId::new(state.revision());
        let mut core = Box::new(Core::empty(config, *state, false));
        core.pending_persistence = Some(PendingPersistence {
            barrier,
            deferred: vec![DeferredEffect::ArmViewTimer],
            safety_rules_shadow_transition: None,
            safety_rules_shadow_predecessor_digest: None,
        });
        let initial_request = SafetyStatePersistenceV0::new(
            barrier,
            Box::new(core.safety.clone()),
            None,
            None,
            None,
            Arc::clone(&core.persistence_affinity.0),
            CorePersistenceSealV0::new(),
        );
        core.validate_runtime(&trnm_consensus_crypto::StrictEd25519Verifier, true)?;
        Ok(PendingEpochHostDriverV2 {
            core,
            initial_request,
            activation_pending: true,
        })
    }
}

impl PendingEpochHostDriverV2 {
    pub fn config(&self) -> &CoreConfig {
        self.core.config()
    }
    pub fn state(&self) -> &SafetyState {
        self.core.safety_state()
    }
    pub fn initial_persistence_v2(&self) -> &SafetyStatePersistenceV0 {
        &self.initial_request
    }
    pub fn persistence_binding_v2(&self) -> SafetyStatePersistenceBindingV0 {
        self.core.safety_state_persistence_binding_v0()
    }
    pub const fn activation_persistence_pending_v2(&self) -> bool {
        self.activation_pending
    }
    fn require_activated_v2(&self) -> Result<()> {
        if self.activation_pending {
            Err(CoreError::EpochActivationPersistencePending)
        } else {
            Ok(())
        }
    }
    pub fn step_v2(&mut self, input: Input) -> Result<Vec<Effect>> {
        if self.activation_pending {
            match &input {
                Input::StorageAck { barrier } if *barrier == self.initial_request.barrier() => {}
                Input::StorageAck { .. } => return Err(CoreError::UnexpectedStorageAck),
                _ => return Err(CoreError::EpochActivationPersistencePending),
            }
        }
        let effects = self
            .core
            .step(input, &trnm_consensus_crypto::StrictEd25519Verifier)?;
        // A failed ACK leaves the pending gate and private Core unchanged.
        self.activation_pending = false;
        Ok(effects)
    }
    pub fn issue_application_seal_authority_v2(
        &self,
    ) -> Result<CoreIssuedApplicationSealAuthorityV0> {
        self.require_activated_v2()?;
        self.core.issue_application_seal_authority_v0()
    }
    pub fn issue_application_finalization_apply_authority_v2(
        &self,
    ) -> Result<CoreIssuedApplicationFinalizationApplyAuthorityV0> {
        self.require_activated_v2()?;
        self.core
            .issue_application_finalization_apply_authority_v0()
    }
    pub fn issue_application_finalization_permit_v2(
        &self,
    ) -> Result<CoreIssuedApplicationFinalizationPermitV0> {
        self.require_activated_v2()?;
        self.core.issue_application_finalization_permit_v0()
    }
    pub fn step_application_sealed_valid_v2(
        &mut self,
        proof: &ApplicationSealedValidV0,
    ) -> Result<Vec<Effect>> {
        self.require_activated_v2()?;
        self.core
            .step_application_sealed_valid_v0(proof, &trnm_consensus_crypto::StrictEd25519Verifier)
    }

    /// Accept one epoch Valid callback and retain Core's typed D carrier. The
    /// carrier owns the exact Safety persistence request, completion revision,
    /// result checksum, and delivery digest; callers must persist that
    /// request before acknowledging it.
    pub fn step_application_sealed_valid_to_delivery_v2(
        &mut self,
        proof: &ApplicationSealedValidV0,
    ) -> Result<CoreAcceptedApplicationValidDV0> {
        self.require_activated_v2()?;
        self.core.step_application_sealed_valid_to_delivery_v0(
            proof,
            &trnm_consensus_crypto::StrictEd25519Verifier,
        )
    }
    pub fn step_application_finalization_receipt_v2(
        &mut self,
        receipt: ApplicationFinalizationReceiptV0,
    ) -> core::result::Result<Vec<Effect>, ApplicationFinalizationReceiptRejectionV0> {
        if let Err(error) = self.require_activated_v2() {
            return Err(ApplicationFinalizationReceiptRejectionV0::new(
                error,
                Box::new(receipt),
            ));
        }
        self.core.step_application_finalization_receipt_v0(
            receipt,
            &trnm_consensus_crypto::StrictEd25519Verifier,
        )
    }
    pub fn persist_signature_release_v2(
        &mut self,
        released_from: &SafetyState,
    ) -> Result<Vec<Effect>> {
        self.require_activated_v2()?;
        self.core.persist_signature_release_v0(
            released_from,
            &trnm_consensus_crypto::StrictEd25519Verifier,
        )
    }
}

impl PendingEpochHostDriverV2 {
    /// Consume a settled live codec2 owner into one inert exact successor.
    pub fn prepare_next_epoch_v2(
        self,
        context: &crate::EpochSafetyStateRecordContextV2<'_>,
    ) -> Result<PreparedEpochCoreActivationV2> {
        prepare_next_epoch_from_candidate_v2(self.core, self.activation_pending, context)
    }
}

#[cfg(feature = "candidate-epoch-host-v1")]
impl PendingEpochHostDriverV1 {
    /// Upgrade a settled live codec1 owner through the same strict codec2
    /// prefix-extension check. Both candidate features must be explicit.
    pub fn prepare_next_epoch_v2(
        self,
        context: &crate::EpochSafetyStateRecordContextV2<'_>,
    ) -> Result<PreparedEpochCoreActivationV2> {
        prepare_next_epoch_from_candidate_v2(self.core, self.activation_pending, context)
    }
}

#[inline(never)]
fn prepare_next_epoch_from_candidate_v2(
    core: Box<Core>,
    activation_pending: bool,
    context: &crate::EpochSafetyStateRecordContextV2<'_>,
) -> Result<PreparedEpochCoreActivationV2> {
    if activation_pending {
        return Err(CoreError::EpochActivationPersistencePending);
    }
    if core.pending_persistence.is_some() || core.awaiting_signature {
        return Err(CoreError::InvalidRecovery(
            "epoch activation has a pending live owner cut",
        ));
    }
    core.validate_runtime(&trnm_consensus_crypto::StrictEd25519Verifier, true)?;
    prepare_epoch_from_terminal_v2(&core.config, &core.safety, context)
}
