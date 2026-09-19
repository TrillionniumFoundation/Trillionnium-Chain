//! Candidate-only binding between a finalized public transaction receipt and
//! a durable native state-sync session.
//!
//! This module does not verify finality or complete a state-sync snapshot. It
//! joins two already-authenticated owner readbacks so a host cannot publish a
//! transaction receipt against a different block, height, state root or sync
//! generation. The production listener and network transport remain outside
//! this crate and the activation flag in `transaction_driver` stays false.

use std::{error::Error, fmt};

use trnm_state_sync_v0::{
    NativeStateSyncBindingV1, NativeStateSyncReadbackV1, NativeStateSyncStoreErrorV1,
    SqliteNativeStateSyncStoreV1,
};
use trnm_tx_lifecycle_v0::{Digest32V0, FinalizedReadbackV0, TxFinalizationErrorV0};

const TX_NATIVE_SYNC_BINDING_DOMAIN_V0: &[u8] = b"trnm.tx.native-state-sync-binding.v0";

/// The exact cross-owner identity returned after a transaction readback and a
/// native state-sync durable readback agree. This is a receipt binding, not a
/// finality proof, state-root proof or completed snapshot capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FinalizedTxNativeStateSyncBindingV0 {
    pub tx_id: Digest32V0,
    pub block_id: Digest32V0,
    pub height: u64,
    pub state_root: Digest32V0,
    pub execution_receipt_digest: Digest32V0,
    pub finality_proof_digest: Digest32V0,
    pub sync_binding_digest: Digest32V0,
    pub sync_manifest_digest: Digest32V0,
    pub sync_progress_digest: Digest32V0,
    pub binding_digest: Digest32V0,
}

impl FinalizedTxNativeStateSyncBindingV0 {
    #[must_use]
    pub fn canonical_digest(&self) -> Digest32V0 {
        Digest32V0::hash(
            TX_NATIVE_SYNC_BINDING_DOMAIN_V0,
            &[
                &self.tx_id.0,
                &self.block_id.0,
                &self.height.to_be_bytes(),
                &self.state_root.0,
                &self.execution_receipt_digest.0,
                &self.finality_proof_digest.0,
                &self.sync_binding_digest.0,
                &self.sync_manifest_digest.0,
                &self.sync_progress_digest.0,
            ],
        )
    }
}

/// A mismatch is deterministic protocol input; a SQLite error leaves the
/// owner's durable state unresolved and must be recovered by the host.
#[derive(Debug)]
pub enum FinalizedTxNativeStateSyncBindingErrorV0 {
    Store(NativeStateSyncStoreErrorV1),
    BindingDigestMismatch,
    ManifestDigestMismatch,
    BlockMismatch,
    HeightMismatch,
    StateRootMismatch,
}

impl fmt::Display for FinalizedTxNativeStateSyncBindingErrorV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Store(error) => write!(formatter, "native state-sync readback failed: {error}"),
            Self::BindingDigestMismatch => {
                formatter.write_str("state-sync binding digest mismatch")
            }
            Self::ManifestDigestMismatch => {
                formatter.write_str("state-sync manifest digest mismatch")
            }
            Self::BlockMismatch => {
                formatter.write_str("finalized block differs from state-sync block")
            }
            Self::HeightMismatch => {
                formatter.write_str("finalized height differs from state-sync height")
            }
            Self::StateRootMismatch => {
                formatter.write_str("finalized state root differs from state-sync state root")
            }
        }
    }
}

impl Error for FinalizedTxNativeStateSyncBindingErrorV0 {}

/// Result of the candidate transaction-finality to native state-sync join.
/// The two fields are deliberately returned together only after both owners
/// have produced their independent readbacks. This type does not imply that
/// the finality journal write and the SQLite read are one atomic transaction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FinalizedTxNativeStateSyncApplyV0 {
    pub finalized: FinalizedReadbackV0,
    pub sync_binding: FinalizedTxNativeStateSyncBindingV0,
}

/// Failure from the composed candidate path. `Finality` means the transaction
/// owner did not durably apply the source claim. `Sync` means finality may
/// already be durable, but the fresh state-sync readback could not be joined;
/// callers must recover and retry the read-only join before publication.
#[derive(Debug)]
pub enum FinalizedTxNativeStateSyncApplyErrorV0<ReadbackError, JournalError> {
    Finality(TxFinalizationErrorV0<ReadbackError, JournalError>),
    Sync(FinalizedTxNativeStateSyncBindingErrorV0),
}

impl<ReadbackError, JournalError> fmt::Display
    for FinalizedTxNativeStateSyncApplyErrorV0<ReadbackError, JournalError>
where
    ReadbackError: fmt::Display,
    JournalError: fmt::Display,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Finality(error) => write!(formatter, "finality readback failed: {error}"),
            Self::Sync(error) => write!(formatter, "state-sync join failed: {error}"),
        }
    }
}

impl<ReadbackError, JournalError> Error
    for FinalizedTxNativeStateSyncApplyErrorV0<ReadbackError, JournalError>
where
    ReadbackError: Error + 'static,
    JournalError: Error + 'static,
{
}

fn bind_readbacks(
    finalized: &FinalizedReadbackV0,
    binding: NativeStateSyncBindingV1,
    sync_readback: NativeStateSyncReadbackV1,
) -> Result<FinalizedTxNativeStateSyncBindingV0, FinalizedTxNativeStateSyncBindingErrorV0> {
    if sync_readback.binding_digest != binding.binding_digest {
        return Err(FinalizedTxNativeStateSyncBindingErrorV0::BindingDigestMismatch);
    }
    if sync_readback.manifest_digest != binding.manifest_digest {
        return Err(FinalizedTxNativeStateSyncBindingErrorV0::ManifestDigestMismatch);
    }
    if finalized.ordered.block_id.0 != binding.terminal_block_digest.0 {
        return Err(FinalizedTxNativeStateSyncBindingErrorV0::BlockMismatch);
    }
    if finalized.ordered.height != binding.height {
        return Err(FinalizedTxNativeStateSyncBindingErrorV0::HeightMismatch);
    }
    if finalized.finality.state_root.0 != binding.state_root.0 {
        return Err(FinalizedTxNativeStateSyncBindingErrorV0::StateRootMismatch);
    }
    let mut joined = FinalizedTxNativeStateSyncBindingV0 {
        tx_id: finalized.tx_id,
        block_id: finalized.ordered.block_id,
        height: finalized.ordered.height,
        state_root: finalized.finality.state_root,
        execution_receipt_digest: finalized.execution.receipt_digest,
        finality_proof_digest: finalized.finality.finality_proof_digest,
        sync_binding_digest: Digest32V0(binding.binding_digest.0),
        sync_manifest_digest: Digest32V0(binding.manifest_digest.0),
        sync_progress_digest: Digest32V0(sync_readback.progress_digest.0),
        binding_digest: Digest32V0([0; 32]),
    };
    joined.binding_digest = joined.canonical_digest();
    Ok(joined)
}

/// Bind an already-authoritative public transaction readback to the exact
/// durable native state-sync store identity. `readback_v1` runs before any
/// binding is returned, so stale/tampered SQLite metadata cannot be published
/// as a receipt. Partial sync progress is represented by its digest; callers
/// must use the native session's `verify_complete` before claiming a snapshot.
pub fn bind_finalized_readback_to_native_state_sync_store_v1(
    finalized: &FinalizedReadbackV0,
    store: &SqliteNativeStateSyncStoreV1,
) -> Result<FinalizedTxNativeStateSyncBindingV0, FinalizedTxNativeStateSyncBindingErrorV0> {
    let (binding, sync_readback) = store
        .binding_and_readback_v1()
        .map_err(FinalizedTxNativeStateSyncBindingErrorV0::Store)?;
    bind_readbacks(finalized, binding, sync_readback)
}

#[cfg(test)]
mod tests {
    use super::*;
    use trnm_state_sync_v0::Digest32V0 as StateDigest32V0;
    use trnm_tx_lifecycle_v0::{ExecutionReceiptV0, FinalityWitnessV0, OrderedPositionV0};

    fn digest(byte: u8) -> Digest32V0 {
        Digest32V0([byte; 32])
    }

    fn state_digest(byte: u8) -> StateDigest32V0 {
        StateDigest32V0([byte; 32])
    }

    fn binding() -> NativeStateSyncBindingV1 {
        NativeStateSyncBindingV1 {
            trust_path_digest: state_digest(1),
            terminal_block_digest: state_digest(2),
            checkpoint_digest: state_digest(3),
            manifest_digest: state_digest(4),
            height: 7,
            epoch: 2,
            state_root: state_digest(5),
            schema_digest: state_digest(6),
            application_version: 3,
            binding_digest: state_digest(7),
        }
    }

    fn finalized() -> FinalizedReadbackV0 {
        FinalizedReadbackV0 {
            tx_id: Digest32V0([8; 32]),
            sender: digest(9),
            nonce: 1,
            ordered: OrderedPositionV0 {
                block_id: Digest32V0([2; 32]),
                height: 7,
                transaction_index: 0,
            },
            execution: ExecutionReceiptV0 {
                tx_id: Digest32V0([8; 32]),
                ordered: OrderedPositionV0 {
                    block_id: Digest32V0([2; 32]),
                    height: 7,
                    transaction_index: 0,
                },
                pre_state_root: digest(10),
                post_state_root: digest(5),
                receipt_digest: digest(11),
                event_root: digest(12),
                fee_charged: 1,
                success: true,
            },
            finality: FinalityWitnessV0 {
                block_id: Digest32V0([2; 32]),
                height: 7,
                state_root: digest(5),
                finality_proof_digest: digest(13),
            },
            broadcast: None,
        }
    }

    fn readback(binding: NativeStateSyncBindingV1) -> NativeStateSyncReadbackV1 {
        NativeStateSyncReadbackV1 {
            binding_digest: binding.binding_digest,
            manifest_digest: binding.manifest_digest,
            received_chunk_count: 1,
            received_bytes: 32,
            progress_digest: state_digest(14),
        }
    }

    #[test]
    fn exact_finalized_readback_binds_to_sync_identity_and_progress() {
        let binding = binding();
        let joined = bind_readbacks(&finalized(), binding, readback(binding)).unwrap();
        assert_eq!(joined.block_id, digest(2));
        assert_eq!(joined.state_root, digest(5));
        assert_eq!(joined.sync_progress_digest, digest(14));
        assert_eq!(joined.binding_digest, joined.canonical_digest());
    }

    #[test]
    fn state_root_or_block_substitution_cannot_bind() {
        let binding = binding();
        let mut wrong = finalized();
        wrong.finality.state_root = digest(99);
        assert!(matches!(
            bind_readbacks(&wrong, binding, readback(binding)),
            Err(FinalizedTxNativeStateSyncBindingErrorV0::StateRootMismatch)
        ));
        let mut wrong = finalized();
        wrong.ordered.block_id = Digest32V0([98; 32]);
        assert!(matches!(
            bind_readbacks(&wrong, binding, readback(binding)),
            Err(FinalizedTxNativeStateSyncBindingErrorV0::BlockMismatch)
        ));
    }
}
