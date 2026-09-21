/// Inert codec2 activation. This owner deliberately has no V1 candidate host
/// conversion: a separately versioned journal must join its actual source,
/// native checkpoint and custody before any acknowledgement can run Core.
/// ```compile_fail
/// use trnm_consensus_core::PreparedEpochCoreActivationV2;
/// fn activate(p: PreparedEpochCoreActivationV2) { p.into_candidate_host_pending_v1(); }
/// ```
#[derive(Debug)]
pub struct PreparedEpochCoreActivationV2 {
    inner: PreparedEpochCoreActivationV1,
}
impl PreparedEpochCoreActivationV2 {
    pub fn config(&self) -> &CoreConfig {
        self.inner.config()
    }
    pub fn state(&self) -> &SafetyState {
        self.inner.state()
    }
    pub fn predecessor(&self) -> &SafetyState {
        self.inner.predecessor()
    }
    pub fn initial_persistence_v2(&self) -> &SafetyStatePersistenceV0 {
        self.inner.initial_persistence_v1()
    }
    pub fn persistence_binding_v2(&self) -> SafetyStatePersistenceBindingV0 {
        self.inner.persistence_binding_v1()
    }
}
/// Strictly checked complete codec2 recovery facts, with no live Core or
/// existing journal9 conversion. Public scalars are comparison pins only.
/// ```compile_fail
/// use trnm_consensus_core::StrictEpochCoreRecoveryV2;
/// fn activate(p: StrictEpochCoreRecoveryV2) { p.into_candidate_host_initial_pending_v1(); }
/// ```
#[derive(Debug)]
pub struct StrictEpochCoreRecoveryV2 {
    inner: StrictEpochCoreRecoveryV1,
}
impl StrictEpochCoreRecoveryV2 {
    pub fn config(&self) -> &CoreConfig {
        self.inner.config()
    }
    pub fn state(&self) -> &SafetyState {
        self.inner.state()
    }
    pub const fn context_ref(&self) -> [u8; 32] {
        self.inner.context_ref()
    }
    pub const fn record_checksum(&self) -> [u8; 32] {
        self.inner.record_checksum()
    }
    pub fn prepare_next_epoch_v2(
        &self,
        context: &crate::EpochSafetyStateRecordContextV2<'_>,
    ) -> Result<PreparedEpochCoreActivationV2> {
        prepare_epoch_from_terminal_v2(self.config(), self.state(), context)
    }
}
impl OldEpochBoundaryCoreV1 {
    pub fn prepare_epoch_activation_v2(
        self,
        context: &crate::EpochSafetyStateRecordContextV2<'_>,
    ) -> Result<PreparedEpochCoreActivationV2> {
        let core = self.core;
        core.validate_runtime(&trnm_consensus_crypto::StrictEd25519Verifier, true)?;
        if core.pending_persistence.is_some() || core.awaiting_signature {
            return Err(CoreError::InvalidRecovery(
                "epoch activation has a pending live owner cut",
            ));
        }
        prepare_epoch_from_terminal_v2(&core.config, &core.safety, context)
    }
}
impl StrictOldEpochTerminalRecoveryV1 {
    pub fn prepare_epoch_activation_v2(
        &self,
        context: &crate::EpochSafetyStateRecordContextV2<'_>,
    ) -> Result<PreparedEpochCoreActivationV2> {
        prepare_epoch_from_terminal_v2(&self.config, &self.state, context)
    }
}
impl StrictEpochCoreRecoveryV1 {
    pub fn prepare_next_epoch_v2(
        &self,
        context: &crate::EpochSafetyStateRecordContextV2<'_>,
    ) -> Result<PreparedEpochCoreActivationV2> {
        prepare_epoch_from_terminal_v2(&self.config, &self.state, context)
    }
}
fn prepare_epoch_from_terminal_v2(
    old_config: &CoreConfig,
    old: &SafetyState,
    context: &crate::EpochSafetyStateRecordContextV2<'_>,
) -> Result<PreparedEpochCoreActivationV2> {
    context
        .epoch()
        .check_predecessor_provenance_v2(old.epoch_state_v1())?;
    Ok(PreparedEpochCoreActivationV2 {
        inner: prepare_epoch_from_terminal_common_v2(
            old_config,
            old,
            context.core_config(),
            context.epoch(),
            context.runtime(),
        )?,
    })
}
impl Core {
    pub fn prepare_epoch_recovery_v2(
        record: &crate::UnverifiedSafetyStateRecordV0,
        context: &crate::EpochSafetyStateRecordContextV2<'_>,
        expected_record_checksum: [u8; 32],
    ) -> Result<StrictEpochCoreRecoveryV2> {
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
        let raw = crate::encode_epoch_safety_record_v2(record.state(), context)
            .map_err(|_| CoreError::InvalidRecovery("full epoch recovery canonical encoding"))?;
        let exact = crate::decode_epoch_safety_record_v2_exact(&raw, context)
            .map_err(|_| CoreError::InvalidRecovery("full epoch recovery exact readback"))?;
        if expected_record_checksum == [0; 32]
            || record.record_checksum() != expected_record_checksum
            || exact.record_checksum() != expected_record_checksum
        {
            return Err(CoreError::InvalidRecovery(
                "full epoch record differs from expected cut",
            ));
        }
        Ok(StrictEpochCoreRecoveryV2 {
            inner: StrictEpochCoreRecoveryV1 {
                config: context.core_config().clone(),
                state: Box::new(record.state().clone()),
                context_ref: crate::epoch_safety_record_context_ref_v2(context)
                    .map_err(|_| CoreError::InvalidRecovery("full epoch context reference"))?,
                record_checksum: expected_record_checksum,
            },
        })
    }
}

#[cfg(feature = "candidate-epoch-host-v2")]
include!("candidate_epoch_host_v2.inc");

#[cfg(test)]
#[path = "epoch_core_v2_tests.rs"]
mod epoch_core_v2_tests;
