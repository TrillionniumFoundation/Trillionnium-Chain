use crate::{
    error::{error, NativeBoundaryErrorCodeV0, NativeBoundaryResultV0},
    primitives::{ApplicationHeadV0, ChainIdV0, GenesisHashV0, Hash32V0},
};

/// Independent monotonic positions joined during native application recovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativeRecoveryWatermarksV0 {
    application_commit: u64,
    validation_journal: u64,
    finalization_journal: u64,
}

impl NativeRecoveryWatermarksV0 {
    pub const fn new(
        application_commit: u64,
        validation_journal: u64,
        finalization_journal: u64,
    ) -> Self {
        Self {
            application_commit,
            validation_journal,
            finalization_journal,
        }
    }

    pub const fn application_commit(self) -> u64 {
        self.application_commit
    }

    pub const fn validation_journal(self) -> u64 {
        self.validation_journal
    }

    pub const fn finalization_journal(self) -> u64 {
        self.finalization_journal
    }

    pub const fn dominates(self, other: Self) -> bool {
        self.application_commit >= other.application_commit
            && self.validation_journal >= other.validation_journal
            && self.finalization_journal >= other.finalization_journal
    }
}

/// Exact startup binding supplied by the node's authenticated recovery owner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeApplicationRecoveryRequestV0 {
    chain_id: ChainIdV0,
    genesis_hash: GenesisHashV0,
    chain_descriptor_hash: Hash32V0,
    signer_policy_commitment: Hash32V0,
    expected_head: ApplicationHeadV0,
    minimum_watermarks: NativeRecoveryWatermarksV0,
}

impl NativeApplicationRecoveryRequestV0 {
    pub fn new(
        chain_id: ChainIdV0,
        genesis_hash: GenesisHashV0,
        chain_descriptor_hash: Hash32V0,
        signer_policy_commitment: Hash32V0,
        expected_head: ApplicationHeadV0,
        minimum_watermarks: NativeRecoveryWatermarksV0,
    ) -> NativeBoundaryResultV0<Self> {
        Ok(Self {
            chain_id,
            genesis_hash,
            chain_descriptor_hash: chain_descriptor_hash
                .require_nonzero("recovery.chain_descriptor_hash")?,
            signer_policy_commitment: signer_policy_commitment
                .require_nonzero("recovery.signer_policy_commitment")?,
            expected_head,
            minimum_watermarks,
        })
    }

    pub const fn chain_id(&self) -> &ChainIdV0 {
        &self.chain_id
    }

    pub const fn genesis_hash(&self) -> GenesisHashV0 {
        self.genesis_hash
    }

    pub const fn chain_descriptor_hash(&self) -> Hash32V0 {
        self.chain_descriptor_hash
    }

    pub const fn signer_policy_commitment(&self) -> Hash32V0 {
        self.signer_policy_commitment
    }

    pub const fn expected_head(&self) -> &ApplicationHeadV0 {
        &self.expected_head
    }

    pub const fn minimum_watermarks(&self) -> NativeRecoveryWatermarksV0 {
        self.minimum_watermarks
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeRecoveryDispositionV0 {
    Exact,
    ValidationReplayRequired { pending_records: u64 },
    FinalizationReplayRequired { pending_records: u64 },
}

/// Recovered application facts. A rollback or incompatible binding is an error,
/// never a recovery disposition. Until an authenticated ancestry proof is part
/// of this boundary, every disposition requires the exact expected head;
/// `*ReplayRequired` describes pending journal work, not permission to accept a
/// lower or same-height substitute head.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeApplicationRecoveryResultV0 {
    request: NativeApplicationRecoveryRequestV0,
    head: ApplicationHeadV0,
    watermarks: NativeRecoveryWatermarksV0,
    disposition: NativeRecoveryDispositionV0,
}

impl NativeApplicationRecoveryResultV0 {
    pub fn new(
        request: &NativeApplicationRecoveryRequestV0,
        head: ApplicationHeadV0,
        watermarks: NativeRecoveryWatermarksV0,
        disposition: NativeRecoveryDispositionV0,
    ) -> NativeBoundaryResultV0<Self> {
        if !watermarks.dominates(request.minimum_watermarks()) {
            return Err(error(
                NativeBoundaryErrorCodeV0::InvalidTransition,
                "recovery.watermarks",
            ));
        }
        if &head != request.expected_head() {
            return Err(error(
                NativeBoundaryErrorCodeV0::BindingMismatch,
                "recovery.head",
            ));
        }
        match disposition {
            NativeRecoveryDispositionV0::Exact => {}
            NativeRecoveryDispositionV0::ValidationReplayRequired { pending_records }
            | NativeRecoveryDispositionV0::FinalizationReplayRequired { pending_records } => {
                if pending_records == 0 {
                    return Err(error(
                        NativeBoundaryErrorCodeV0::ZeroValue,
                        "recovery.pending_records",
                    ));
                }
            }
        }
        Ok(Self {
            request: request.clone(),
            head,
            watermarks,
            disposition,
        })
    }

    pub const fn request(&self) -> &NativeApplicationRecoveryRequestV0 {
        &self.request
    }

    pub const fn head(&self) -> &ApplicationHeadV0 {
        &self.head
    }

    pub const fn watermarks(&self) -> NativeRecoveryWatermarksV0 {
        self.watermarks
    }

    pub const fn disposition(&self) -> NativeRecoveryDispositionV0 {
        self.disposition
    }
}
