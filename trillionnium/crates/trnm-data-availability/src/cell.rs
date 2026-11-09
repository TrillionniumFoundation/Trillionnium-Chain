//! Content-addressed cell bytes, independent of transaction DA and consensus.
//!
//! A caller pins a manifest ID from its existing release authority. Transport
//! checks bytes only; it cannot approve a model, select CURRENT or grant use.

use std::{fmt, io};

mod archive;
mod bep52;
mod bep52_peer;
mod cache_budget;
mod cache_wal;
mod closure;
mod content_v2;
mod custody;
mod delta;
pub mod discovery;
mod erasure;
#[cfg(test)]
mod historical_tcl3_cache_budget;
mod manifest;
mod model_root;
mod network;
mod placement;
pub mod pq;
mod recoverability;
mod release;
mod residency;
mod retained;
mod retention;
mod store;
mod tensor;
mod tensor_reader;
mod version;
mod version_content;

pub use archive::{
    CellReleaseRetentionConfigV2, CellReleaseRetentionContractV2, CellReleaseRetentionReadbackV2,
    CellReleaseRetentionStoreV2, MAX_CELL_ARCHIVE_CONTRACT_BYTES_V2,
};
pub use bep52::{
    CellBep52BindingV1, CellBep52ChunkProofV1, CellBep52MagnetV1, CELL_BEP52_PIECE_BYTES_V1,
    CELL_BEP52_PROFILE_V1, MAX_CELL_BEP52_INFO_BYTES_V1, MAX_CELL_BEP52_LEAVES_V1,
    MAX_CELL_BEP52_METAINFO_BYTES_V1, MAX_CELL_BEP52_PROOF_BYTES_V1,
};
pub use bep52_peer::{
    fetch_cell_bep52, fetch_cell_bep52_with_content, query_cell_bep52_dht_peers,
    CellBep52DhtHintsV1, CellBep52DhtNodeHintV1, CellBep52FetchReportV1, CellBep52PeerLimitsV1,
    CellBep52PeerSessionV1, CellBep52PeerUsageV1, CellBep52SeedV1, CELL_BEP52_PEER_PROFILE_V1,
    MAX_CELL_BEP52_DHT_RESPONSE_BYTES_V1, MAX_CELL_BEP52_PEER_FRAME_BYTES_V1,
};
pub use cache_budget::{CellCacheConfigV4, CellCacheUsageV2};
pub use closure::{
    CellClosureFileV1, CellFileRoleV1, CellLoaderContextV1, CellReleaseClosureV1,
    MAX_CELL_CLOSURE_BYTES_V1, MAX_CELL_CLOSURE_FILES_V1,
};
pub use content_v2::{
    CellContentClosureReadbackV2, CellContentClosureV2, CellContentDependencyV2,
    CellContentErrorV2, CellContentManifestV2, CellContentReadbackV2,
    CELL_CONTENT_DEPENDENCY_COUNT_V2, MAX_CELL_CONTENT_CLOSURE_BYTES_V2,
    MAX_CELL_CONTENT_MANIFEST_BYTES_V2,
};
pub use custody::{
    observe_release_custody, observe_version_custody, CellCustodyContinuationV1,
    CellCustodyPolicyPinV1, CellCustodyProbeBudgetV1, CellCustodyProbeUsageV1,
    CellCustodyRecoveryActionV1, CellCustodyRenewalActionV1, CellCustodyReplicaObservationV1,
    CellCustodyReplicaPinV1, CellCustodyReplicaStateV1, CellCustodySponsorObservationV1,
    CellCustodySponsorStateV1, CellReleaseCustodyPolicyV1, CellReleaseCustodyReportV1,
    CellVersionCustodyContinuationV1, CellVersionCustodyReplicaContinuationV1,
    CellVersionCustodyReportV1, MAX_CELL_CUSTODY_REPLICAS_V1,
};
pub use delta::{fetch_delta_to_file, CellChunkDeltaV1, CellDeltaPlanV1, MAX_CELL_DELTA_BYTES_V1};
pub use erasure::{
    CellRs46CacheTargetV1, CellRs46ChunkBindingV1, CellRs46CodewordV1, CellRs46ManifestBindingV1,
    CellRs46PlacementPolicyV1, CellRs46RepairBudgetV1, CellRs46RepairUsageV1, CellRs46RepairV1,
    CellRs46ShardInputV1, CellRs46ShardPlacementV1, CellRs46ShardV1,
    CELL_RS46_CODEWORD_WIRE_BYTES_V1, CELL_RS46_DATA_SHARDS_V1, CELL_RS46_PROFILE_V1,
    CELL_RS46_TOTAL_SHARDS_V1, MAX_CELL_RS46_SHARD_BYTES_V1, MAX_CELL_RS46_SHARD_WIRE_BYTES_V1,
};
pub use manifest::{
    CellChunkV1, CellContextV1, CellManifestV1, CellReleaseManifestV1, MAX_CELL_BYTES,
    MAX_CHUNK_BYTES,
};
pub use model_root::{CellModelReleaseRootV1, MAX_MODEL_RELEASE_ROOT_BYTES_V1};
pub use network::{
    fetch_cell, fetch_cell_persistent, fetch_cell_persistent_rarest_first,
    fetch_cell_persistent_rarest_first_to_file, fetch_cell_persistent_to_file,
    fetch_cell_rarest_first, fetch_cell_rarest_first_to_file, fetch_cell_to_file, serve_cells,
    serve_cells_bounded, serve_cells_bounded_with_availability,
    serve_cells_bounded_with_availability_and_ready, serve_cells_bounded_with_ready,
    serve_cells_persistent, serve_cells_persistent_rarest_first,
    serve_cells_persistent_rarest_first_with_ready, serve_cells_persistent_with_ready,
    CellFetchReportV1, CellPeerLimitsV1, CellPersistentFetchReportV2, CellPersistentPeerLimitsV2,
    CellPersistentServeLimitsV2, CellPersistentServeReportV2, CellServeLimitsV1, CellServeReportV1,
};
pub use placement::{
    evaluate_recovery_placement, CellRecoveryFaultAxisV1, CellRecoveryFaultEventV1,
    CellRecoveryFaultPolicyV1, CellRecoveryPartV1, CellRecoveryPlacementReportV1,
    CellRecoveryPlacementV1, CellRecoveryProviderPinV1, MAX_CELL_RECOVERY_FAULT_EVENTS_V1,
    MAX_CELL_RECOVERY_FAULT_SCENARIOS_V1, MAX_CELL_RECOVERY_PLACEMENTS_V1,
    MAX_CELL_RECOVERY_PROVIDERS_V1,
};
pub use recoverability::{
    CellRecoveryChunkDeficitV1, CellRecoveryChunkKeyV1, CellRecoveryPlacementPolicyV1,
    CellRetainedRs46ObservationV1, CellRetainedRs46RecoveryV1, CellRs46ProviderShardV1,
    CellRs46RecoveryBudgetV1, CellRs46RecoveryUsageV1, MAX_CELL_RS46_RECOVERY_CHUNKS_V1,
};
pub use release::{
    fetch_closure, fetch_closure_cancellable, fetch_closure_to_file,
    fetch_closure_with_options_to_file, fetch_model_release_to_file,
    fetch_model_release_with_options_to_file, fetch_release_to_file,
    fetch_release_with_options_to_file, fetch_tensor_model_to_file,
    fetch_tensor_model_with_options_to_file, read_pinned_release, CellClosureFetchReportV1,
    CellFetchTransportV2, CellModelReleaseFetchReportV1, CellReleaseFetchLimitsV1,
    CellReleaseFetchOptionsV2, CellReleaseFetchReportV1, CellTensorModelFetchReportV1,
    CellTransportFetchReportV2,
};
pub use residency::{
    CellLocalSelectionV1, CellResidencyConfigV1, CellResidencyPrepareReportV1,
    CellResidencyUsageV1, CellResidencyV1, CellResidentFileV1, CellResidentTensorFileV1,
    CellResidentTensorModelV1, CellResidentTensorV1, CellResidentViewV1, CellResidentWorkingSetV1,
};
pub use retained::{
    fetch_retained_version_set, CellRetainedFetchFailureV1, CellRetainedFetchObservationV1,
    CellRetainedFetchUsageV1, CellRetainedObjectV1, CellRetainedReadBudgetV1,
    CellRetainedReadUsageV1, CellRetainedSetOwnerV1, CellRetainedSetReadbackV1,
    CellRetainedVersionEntryV1, CellRetainedVersionSetV1, MAX_CELL_RETAINED_SET_BYTES_V1,
    MAX_CELL_RETAINED_VERSIONS_V1,
};

#[cfg(target_os = "linux")]
pub use residency::{CellSealedLoaderBundleV1, CellSealedLoaderFileV1, CellSealedLoaderLimitsV1};
pub use retention::{
    CellRetentionConfigV1, CellRetentionContractV1, CellRetentionReadbackV1, CellRetentionStoreV1,
};
pub use store::{CellReleaseLimitsV1, CellStoreV1};
pub use tensor::{
    CellTensorContractV1, CellTensorDTypeV1, CellTensorFileV1, CellTensorModelManifestV1,
    CellTensorReadbackV1, CellTensorSpecV1, MAX_CELL_TENSOR_CONTRACT_BYTES_V1,
    MAX_CELL_TENSOR_HEADER_BYTES_V1, MAX_CELL_TENSOR_MODEL_MANIFEST_BYTES_V1,
};
pub use version::{
    fetch_complete_version, CellVersionCommitmentV1, CellVersionFetchFailureV1,
    CellVersionFetchObservationV1, CellVersionFetchTransportReportV1, CellVersionLoaderContextV1,
    CellVersionManifestV1, CellVersionReadbackV1, MAX_CELL_VERSION_BYTES_V1,
    MAX_CELL_VERSION_MANIFESTS_V1,
};
pub use version_content::{
    CellContentDigestV2, CellContentReadSessionV2, CellContentReadUsageV2, CellFileContentV2,
    CellVersionContentV2, PinnedCellVersionContentV2, VerifiedCellVersionContentV2,
    MAX_CELL_VERSION_CONTENT_BYTES_V2,
};
#[cfg(target_os = "linux")]
pub use version_content::{
    CellSealedContentScopeV2, VerifiedCellSealedContentV2, VerifiedCellSealedVersionContentV2,
};

pub type CellDigestV1 = [u8; 32];
pub type CellResultV1<T> = Result<T, CellErrorV1>;

#[derive(Debug)]
pub enum CellErrorV1 {
    Invalid(&'static str),
    Io(io::Error),
    Sql(rusqlite::Error),
    Unavailable,
    CacheQuotaExceeded,
    CacheWriterBusy,
    ResponseByteBudgetExhausted {
        received_response_bytes: u64,
        max_response_bytes: u64,
    },
}

impl fmt::Display for CellErrorV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(reason) => write!(f, "cell: {reason}"),
            Self::Io(error) => write!(f, "cell I/O: {error}"),
            Self::Sql(error) => write!(f, "cell storage: {error}"),
            Self::Unavailable => f.write_str("cell: no configured peer supplied the pinned bytes"),
            Self::CacheQuotaExceeded => f.write_str("cell: CELL_CACHE_QUOTA_EXHAUSTED"),
            Self::CacheWriterBusy => f.write_str("cell: CELL_CACHE_WRITER_BUSY"),
            Self::ResponseByteBudgetExhausted {
                received_response_bytes,
                max_response_bytes,
            } => write!(
                f,
                "cell: CELL_RESPONSE_BYTE_BUDGET_EXHAUSTED received_response_bytes={received_response_bytes} max_response_bytes={max_response_bytes}"
            ),
        }
    }
}
impl std::error::Error for CellErrorV1 {}
impl From<io::Error> for CellErrorV1 {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}
impl From<rusqlite::Error> for CellErrorV1 {
    fn from(value: rusqlite::Error) -> Self {
        if matches!(&value, rusqlite::Error::SqliteFailure(_, Some(message))
            if message == "CHECK constraint failed: cell_cache_capacity")
        {
            return Self::CacheQuotaExceeded;
        }
        Self::Sql(value)
    }
}

pub(crate) fn require(ok: bool, reason: &'static str) -> CellResultV1<()> {
    if ok {
        Ok(())
    } else {
        Err(CellErrorV1::Invalid(reason))
    }
}

pub fn digest_hex(value: CellDigestV1) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub fn parse_digest(value: &str) -> CellResultV1<CellDigestV1> {
    require(
        value.len() == 64
            && value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "canonical digest",
    )?;
    let mut result = [0; 32];
    for (i, byte) in result.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[i * 2..i * 2 + 2], 16)
            .map_err(|_| CellErrorV1::Invalid("digest"))?;
    }
    Ok(result)
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod release_tests;

#[cfg(test)]
mod closure_tests;

#[cfg(test)]
mod model_root_tests;

#[cfg(test)]
mod delta_tests;

#[cfg(test)]
mod delta_network_tests;

#[cfg(test)]
mod tensor_tests;
