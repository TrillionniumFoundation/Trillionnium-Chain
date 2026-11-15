//! Read-only complete-journal commitment for the separate M12 recovery owner.
//! Computing this digest grants no dispatch or recovery authority. A witness
//! must authenticate it from outside the local backup domain before live use.
use super::*;
use sha2::Sha512;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GenerationRecoveryCheckpointV3 {
    pub sequence: u64,
    pub root: [u8; 64],
}

pub(super) fn checkpoint_from_parts_v3(
    context: [u8; 64],
    events: u64,
    event_root: Hash,
) -> Result<GenerationRecoveryCheckpointV3> {
    let sequence = events
        .checked_add(1)
        .ok_or(NativeBudgetErrorV1::Invalid("GENERATION_RECOVERY_SEQUENCE"))?;
    let mut hash = Sha512::new();
    hash.update(b"TRNM/M12/full-generation-recovery/checkpoint/v3\0");
    hash.update(context);
    hash.update(sequence.to_be_bytes());
    hash.update(event_root);
    Ok(GenerationRecoveryCheckpointV3 {
        sequence,
        root: hash.finalize().into(),
    })
}

impl NativeGenerationStoreV2 {
    /// Bind the actual read/write transaction to the head authenticated by the
    /// V3 owner. This is an ephemeral guard, not a new stored schema or a trust
    /// source. Only the external owner decides whether `expected` is current.
    pub fn with_recovery_fence_v3<T>(
        &mut self,
        expected: GenerationRecoveryCheckpointV3,
        action: impl FnOnce(&mut Self) -> Result<T>,
    ) -> Result<(T, GenerationRecoveryCheckpointV3)> {
        require(
            self.recovery_expected_v3.is_none()
                && expected.sequence > 0
                && expected.root != [0; 64],
            "GENERATION_RECOVERY_FENCE_ACTIVE",
        )?;
        self.recovery_expected_v3 = Some(expected);
        self.recovery_committed_v3 = None;
        let outcome = action(self);
        let committed = self.recovery_committed_v3.take().unwrap_or(expected);
        self.recovery_expected_v3 = None;
        outcome.map(|value| (value, committed))
    }

    pub(super) fn check_recovery_expected_v3(&self, events: u64, root: Hash) -> Result<()> {
        if let Some(expected) = self.recovery_committed_v3.or(self.recovery_expected_v3) {
            require(
                checkpoint_from_parts_v3(self.recovery_context_v3()?, events, root)? == expected,
                "GENERATION_RECOVERY_TRANSACTION_HEAD",
            )?;
        }
        Ok(())
    }

    /// Includes the full configuration and the randomly generated durable
    /// journal identity. A copied configuration cannot register a replacement
    /// journal under an existing independently pinned witness binding.
    pub fn recovery_context_v3(&self) -> Result<[u8; 64]> {
        let config = encode(&self.configuration)?;
        let mut hash = Sha512::new();
        hash.update(b"TRNM/M12/full-generation-recovery/context/v3\0");
        hash.update((config.len() as u64).to_be_bytes());
        hash.update(config);
        hash.update(self.journal_identity);
        Ok(hash.finalize().into())
    }

    /// Replays and validates all events in one read transaction. The zero-event
    /// journal has checkpoint sequence one; the original V2 schema and event
    /// bytes remain unchanged. This root cannot authenticate an unanchored log.
    pub fn recovery_checkpoint_v3(&self) -> Result<GenerationRecoveryCheckpointV3> {
        let tx = self.connection.unchecked_transaction()?;
        let (_, events, event_root) = load(&tx, &self.configuration, self.journal_identity, None)?;
        let point = checkpoint_from_parts_v3(self.recovery_context_v3()?, events, event_root)?;
        tx.commit()?;
        Ok(point)
    }
}
