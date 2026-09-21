//! Untrusted transport facts, independent of the candidate schema11 owner.
//! No constructor or field grants native, Core, signer or trust-anchor authority.
use trnm_consensus_types::EpochActivationEvidenceBytesV0;

pub const MAX_INCREMENTAL_FINALITY_LINKS_V2: usize = 256;
pub const MAX_INCREMENTAL_FINALITY_EPOCHS_V2: usize = 32;
pub const MAX_INCREMENTAL_FINALITY_BYTES_V2: usize = 64 * 1024 * 1024;
pub const MAX_INCREMENTAL_FINALITY_HEADER_BYTES_V2: usize = 4096;
pub const MAX_INCREMENTAL_FINALITY_ROOT_BYTES_V2: usize = 8 * 1024 * 1024;

/// Original consensus bytes for one real application link. A receiver must
/// independently verify the proof and the complete epoch evidence when present.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeIncrementalFinalityStepV2 {
    pub header_cev0: Vec<u8>,
    pub consensus_parent_header_cev0: Vec<u8>,
    pub proof: Vec<u8>,
    pub epoch_evidence: Option<EpochActivationEvidenceBytesV0>,
}

/// An inert data transfer object, not an aggregate consensus wire encoding.
/// Source-local receipt/P/sequence metadata deliberately has no field here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeIncrementalFinalityPathV2 {
    pub anchor_header_cev0: Vec<u8>,
    pub target_header_cev0: Vec<u8>,
    pub steps: Vec<NativeIncrementalFinalityStepV2>,
}
