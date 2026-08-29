#![forbid(unsafe_code)]
//! TRNM-owned application boundary for frozen PoCO-BFT v0.
//!
//! The crate defines host-neutral request, result, execution, commit, proof,
//! snapshot, validator-transition, and recovery contracts. It deliberately
//! owns no networking, consensus driver, database, clock, signer, or runtime.
//! Implementations must validate every value again at a trust boundary.

mod application;
mod artifact;
mod error;
mod execution;
mod primitives;
mod recovery;
mod snapshot;
mod validator;

pub use application::{
    NativeApplicationCommitRequestV0, NativeApplicationCommitResultV0,
    NativeApplicationGenesisRequestV0, NativeApplicationGenesisResultV0, NativeApplicationV0,
    NativeBlockExecutionRequestV0, NativeBlockExecutionResultV0, NativeDeterministicInvalidV0,
    NativeExecutedBlockV0, NativeExpectedBlockCommitmentsV0, NativeUnavailableReasonV0,
    NativeUnavailableV0, MAX_BLOCK_BYTES_V0, MAX_BLOCK_TRANSACTIONS_V0,
    NativeFinalizationApplyOutcomeV0, NativeFinalizationApplyReadbackV0,
    NativeFinalizationEnqueueOutcomeV0, NativeFinalizationForkV0, NativeFinalizationIntentV0,
    NativeFinalizationQueueV0, NativeFinalizationRetryDispositionV0,
    MAX_FINALIZATION_QUEUE_ENTRIES_V0,
};
pub use artifact::{
    decode_native_executed_block_artifact_v0, encode_native_executed_block_artifact_v0,
    MAX_NATIVE_EXECUTED_BLOCK_ARTIFACT_BYTES_V0, NATIVE_EXECUTED_BLOCK_ARTIFACT_DOMAIN_V0,
    NATIVE_EXECUTED_BLOCK_ARTIFACT_VERSION_V0,
};
pub use error::{NativeBoundaryErrorCodeV0, NativeBoundaryErrorV0, NativeBoundaryResultV0};
pub use execution::{
    NativeEventAttributeV0, NativeEventV0, NativeExecutionReceiptV0, MAX_EVENTS_PER_RECEIPT_V0,
    MAX_EVENT_ATTRIBUTES_V0,
};
pub use primitives::{
    ApplicationCommitIdV0, ApplicationHeadV0, BlockIdV0, ChainIdV0, GenesisHashV0, Hash32V0,
    HeightV0, ReceiptsRootV0, StateRootV0, ValidatorSetIdV0,
};
pub use recovery::{
    NativeApplicationRecoveryRequestV0, NativeApplicationRecoveryResultV0,
    NativeRecoveryDispositionV0, NativeRecoveryWatermarksV0,
};
pub use snapshot::{
    NativeSnapshotChunkV0, NativeSnapshotManifestV0, NativeSnapshotRequestV0,
    NativeStateProofRequestV0, NativeStateProofSchemeV0, NativeStateProofV0,
};
pub use validator::{
    NativeValidatorSetTransitionV0, NativeValidatorSetV0, NativeValidatorV0, MAX_VALIDATORS_V0,
};

#[cfg(test)]
mod tests;
