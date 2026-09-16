/// The sole public live owner for schema14's outgoing epoch. All consensus
/// inputs and callbacks use strict Ed25519; no generic verifier or mutable Core
/// escapes. This wraps the existing Core state machine, not a parallel engine.
/// New-set activation and ordinary signer retirement are deliberately absent.
///
/// ```compile_fail
/// use trnm_consensus_core::OldEpochBoundaryCoreV1;
/// fn duplicate<T: Clone>() {}
/// duplicate::<OldEpochBoundaryCoreV1>();
/// ```
#[derive(Debug)]
pub struct OldEpochBoundaryCoreV1 {
    core: Core,
}

impl Core {
    /// Consumes the quiescent old Core only after strict key/state validation.
    /// The returned migration request must cross a schema14-aware durable store
    /// before the owner's first StorageAck; journal7 cannot acknowledge it.
    pub fn into_old_epoch_boundary_v1(
        mut self,
        owner_generation: u64,
    ) -> Result<(OldEpochBoundaryCoreV1, Vec<Effect>)> {
        trnm_consensus_crypto::validate_validator_set_strict_ed25519_v0(
            self.config.validator_set(),
        )?;
        self.validate_runtime(&trnm_consensus_crypto::StrictEd25519Verifier, true)?;
        let effects = self.prepare_old_epoch_boundary_v1(owner_generation)?;
        Ok((OldEpochBoundaryCoreV1 { core: self }, effects))
    }
}

impl OldEpochBoundaryCoreV1 {
    pub fn config(&self) -> &CoreConfig {
        self.core.config()
    }
    pub fn safety_state(&self) -> &SafetyState {
        self.core.safety_state()
    }
    pub fn safety_state_persistence_binding_v0(&self) -> SafetyStatePersistenceBindingV0 {
        self.core.safety_state_persistence_binding_v0()
    }
    pub fn issue_application_seal_authority_v0(
        &self,
    ) -> Result<CoreIssuedApplicationSealAuthorityV0> {
        self.core.issue_application_seal_authority_v0()
    }
    pub fn issue_application_finalization_apply_authority_v0(
        &self,
    ) -> Result<CoreIssuedApplicationFinalizationApplyAuthorityV0> {
        self.core
            .issue_application_finalization_apply_authority_v0()
    }
    pub fn step_v1(&mut self, input: Input) -> Result<Vec<Effect>> {
        self.core
            .step(input, &trnm_consensus_crypto::StrictEd25519Verifier)
    }
    pub fn step_application_sealed_valid_v1(
        &mut self,
        proof: &ApplicationSealedValidV0,
    ) -> Result<Vec<Effect>> {
        self.core
            .step_application_sealed_valid_v0(proof, &trnm_consensus_crypto::StrictEd25519Verifier)
    }
    pub fn step_application_finalization_receipt_v1(
        &mut self,
        receipt: ApplicationFinalizationReceiptV0,
    ) -> core::result::Result<Vec<Effect>, crate::ApplicationFinalizationReceiptRejectionV0> {
        self.core.step_application_finalization_receipt_v0(
            receipt,
            &trnm_consensus_crypto::StrictEd25519Verifier,
        )
    }
    pub fn persist_signature_release_v1(
        &mut self,
        released_from: &SafetyState,
    ) -> Result<Vec<Effect>> {
        self.core.persist_signature_release_v0(
            released_from,
            &trnm_consensus_crypto::StrictEd25519Verifier,
        )
    }
}

/// Strictly recovered terminal old-epoch evidence, still inert. A stored hash,
/// public scalar tuple, or user-supplied verifier cannot create a live owner.
/// The later host must join actual journal8, COMMITTED native checkpoint and
/// shared signer-custody capabilities before any activation API is added.
#[derive(Debug)]
pub struct StrictOldEpochTerminalRecoveryV1 {
    config: CoreConfig,
    state: SafetyState,
    context_ref: [u8; 32],
    record_checksum: [u8; 32],
    owner_generation: u64,
}
impl StrictOldEpochTerminalRecoveryV1 {
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
    pub const fn owner_generation(&self) -> u64 {
        self.owner_generation
    }
}

impl Core {
    /// Exact, strict recovery of the stable CheckpointApplied cut only. Earlier
    /// P/D/sign/finalization crash cuts require dedicated joins and are rejected.
    /// This returns no mutable Core, timer, sign request, or scalar activation.
    pub fn prepare_old_epoch_terminal_recovery_v1(
        record: &crate::UnverifiedSafetyStateRecordV0,
        context: &crate::SafetyStateRecordContextV0<'_>,
        expected_record_checksum: [u8; 32],
        expected_owner_generation: u64,
    ) -> Result<StrictOldEpochTerminalRecoveryV1> {
        let config = context.core_config();
        let state = record.state();
        trnm_consensus_crypto::validate_validator_set_strict_ed25519_v0(config.validator_set())?;
        Self::validate_persisted_state_v0(
            config,
            state,
            &trnm_consensus_crypto::StrictEd25519Verifier,
        )?;
        let boundary = state
            .old_epoch_boundary_v1()
            .ok_or(CoreError::InvalidRecovery(
                "terminal recovery requires outgoing schema14",
            ))?;
        if boundary.owner_generation() != expected_owner_generation
            || boundary.phase(state) != crate::OldEpochBoundaryPhaseV1::CheckpointApplied
            || state.finalized() != state.application_applied()
            || state.pending_sign().is_some()
            || state.pending_finalize().is_some()
            || !state.finalization_queue().is_empty()
            || !state.payload_validation_obligations().is_empty()
            || state.pending_tc_high_qc_sync().is_some()
            || state.pending_standalone_qc_sync().is_some()
            || state.state_sync_anchor().is_some()
            || state.safety_halt().is_some()
            || state
                .payload_validation_completions()
                .iter()
                .any(|c| c.first_recorded_revision() == state.revision())
        {
            return Err(CoreError::InvalidRecovery(
                "old epoch terminal recovery has an unresolved or foreign cut",
            ));
        }
        let proof = state
            .last_finalization_proof()
            .ok_or(CoreError::InvalidRecovery(
                "terminal checkpoint lacks complete finality proof",
            ))?;
        if proof.finalized_block().header().block_kind() != BlockKind::EpochCheckpoint
            || proof.child().header().block_kind() != BlockKind::EpochSeal1
            || proof.grandchild().header().block_kind() != BlockKind::EpochSeal2
            || !boundary.checkpoints().iter().any(|c| {
                c.proposal().block().header() == proof.finalized_block().header()
                    && c.proposal().witness() == proof.finalized_block().witness()
            })
            || ![proof.child(), proof.grandchild()].iter().all(|certified| {
                boundary.seals().iter().any(|s| {
                    s.block().header() == certified.header() && s.witness() == certified.witness()
                })
            })
        {
            return Err(CoreError::InvalidRecovery(
                "terminal recovery proof differs from retained checkpoint/seals",
            ));
        }
        let raw =
            crate::encode_old_epoch_boundary_safety_record_v1(state, context).map_err(|_| {
                CoreError::InvalidRecovery(
                    "terminal outgoing record cannot be canonically re-encoded",
                )
            })?;
        let exact = crate::decode_old_epoch_boundary_safety_record_v1_exact(&raw, context)
            .map_err(|_| {
                CoreError::InvalidRecovery("terminal outgoing record failed exact context readback")
            })?;
        if record.record_checksum() != expected_record_checksum
            || exact.record_checksum() != expected_record_checksum
        {
            return Err(CoreError::InvalidRecovery(
                "terminal outgoing record differs from independently pinned journal head",
            ));
        }
        Ok(StrictOldEpochTerminalRecoveryV1 {
            config: config.clone(),
            state: state.clone(),
            context_ref: crate::old_epoch_boundary_record_context_ref_v1(context)
                .map_err(|_| CoreError::InvalidRecovery("terminal outgoing context"))?,
            record_checksum: expected_record_checksum,
            owner_generation: expected_owner_generation,
        })
    }
}
