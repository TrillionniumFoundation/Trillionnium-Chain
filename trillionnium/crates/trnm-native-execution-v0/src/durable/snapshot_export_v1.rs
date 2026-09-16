//! Native snapshot transport uses the existing frozen manifest/chunk domains.
//! Export is read-only and restricted to an exact, freshly audited finalized
//! application head. It does not pin a remote trust anchor or activate recovery.

use super::*;
use std::sync::Arc;
use trnm_consensus_types::Cev0AdmissionBudgetV0;
use trnm_native_application::{HeightV0, NativeSnapshotManifestV0, NativeSnapshotRequestV0};

/// Owner-affined, read-only export identity. A different owner, changed source
/// sequence or changed snapshot invalidates it; a data-only manifest cannot
/// manufacture this value. No local SQLite connection is retained here.
///
/// ```compile_fail
/// use trnm_native_execution_v0::NativeSnapshotExportV1;
/// fn require_clone<T: Clone>() {}
/// require_clone::<NativeSnapshotExportV1>();
/// ```
#[derive(Debug)]
pub struct NativeSnapshotExportV1 {
    owner_affinity: Arc<()>,
    store_id: [u8; 32],
    sequence: u64,
    snapshot_digest: [u8; 32],
    manifest: NativeSnapshotManifestV0,
    finality_proof_id: [u8; 32],
}

impl NativeSnapshotExportV1 {
    pub const fn manifest(&self) -> &NativeSnapshotManifestV0 {
        &self.manifest
    }
    pub const fn snapshot_digest(&self) -> &[u8; 32] {
        &self.snapshot_digest
    }
    pub const fn finality_proof_id(&self) -> &[u8; 32] {
        &self.finality_proof_id
    }
}

pub(super) fn manifest_for_snapshot_v1(
    request: NativeSnapshotRequestV0,
    metadata: &MetadataV0,
) -> DurableResult<NativeSnapshotManifestV0> {
    let maximum = usize::try_from(request.maximum_chunk_bytes()).map_err(|_| {
        error(
            NativeApplicationExecutionErrorCodeV0::InvalidConfiguration,
            "snapshot.chunk_limit",
        )
    })?;
    // Bound descriptor allocation before iterating over the full snapshot.
    let count = metadata.snapshot.len().div_ceil(maximum);
    if count == 0 || count > trnm_native_application::MAX_SNAPSHOT_CHUNKS_V0 {
        return Err(error(
            NativeApplicationExecutionErrorCodeV0::InvalidConfiguration,
            "snapshot.chunk_count",
        ));
    }
    let mut chunks = Vec::with_capacity(count);
    for (index, bytes) in metadata.snapshot.chunks(maximum).enumerate() {
        let index = u32::try_from(index).map_err(|_| {
            error(
                NativeApplicationExecutionErrorCodeV0::CorruptStore,
                "snapshot.chunk_count",
            )
        })?;
        let digest = hash_domain(SNAPSHOT_CHUNK_DOMAIN_V0, &[&index.to_be_bytes(), bytes]);
        chunks.push(
            NativeSnapshotChunkV0::new(
                index,
                u32::try_from(bytes.len()).map_err(|_| {
                    error(
                        NativeApplicationExecutionErrorCodeV0::CorruptStore,
                        "snapshot.chunk_size",
                    )
                })?,
                Hash32V0::new(digest),
            )
            .map_err(|_| {
                error(
                    NativeApplicationExecutionErrorCodeV0::CorruptStore,
                    "snapshot.chunk",
                )
            })?,
        );
    }
    let chunk_digests = chunks
        .iter()
        .map(|chunk| chunk.digest().into_bytes())
        .collect::<Vec<_>>();
    let mut manifest_parts = Vec::with_capacity(chunk_digests.len() + 1);
    manifest_parts.push(metadata.snapshot_digest.as_slice());
    manifest_parts.extend(chunk_digests.iter().map(<[u8; 32]>::as_slice));
    let digest = hash_domain(SNAPSHOT_MANIFEST_DOMAIN_V0, &manifest_parts);
    NativeSnapshotManifestV0::new(request, chunks, Hash32V0::new(digest)).map_err(|_| {
        error(
            NativeApplicationExecutionErrorCodeV0::CorruptStore,
            "snapshot.manifest",
        )
    })
}

impl DurableNativeApplicationV0 {
    pub(crate) fn confirm_snapshot_identity_v1(
        &self,
    ) -> DurableResult<(ApplicationHeadV0, [u8; 32], u64)> {
        let _guard = self.lock_operation()?;
        let metadata = fresh_validate_v0(&self.path, &self.config)?;
        Ok((
            metadata.head,
            metadata.snapshot_digest,
            metadata.snapshot.len() as u64,
        ))
    }

    /// Verify actual strict finality plus an already COMMITTED native row,
    /// then freeze a transport identity for the exact current snapshot.
    /// Historical exports and implicit commit of PREPARED state are not allowed.
    #[allow(clippy::too_many_arguments)]
    pub fn begin_finalized_snapshot_export_v1(
        &self,
        proof_class: &str,
        proof_bytes: &[u8],
        height: HeightV0,
        authenticated_parent_timestamp_ms: u64,
        maximum_chunk_bytes: u32,
        budget: &mut Cev0AdmissionBudgetV0,
    ) -> Result<NativeSnapshotExportV1, crate::PocoFinalityCommitErrorV0> {
        let read = self.read_poco_finalized_bytes_v0(
            proof_class,
            proof_bytes,
            height,
            authenticated_parent_timestamp_ms,
            budget,
        )?;
        let _guard = self
            .lock_operation()
            .map_err(crate::PocoFinalityCommitErrorV0::Application)?;
        let metadata = fresh_validate_v0(&self.path, &self.config)
            .map_err(crate::PocoFinalityCommitErrorV0::Application)?;
        if &metadata.head != read.application().confirmed_head_v0()
            || metadata.head.height().get() != read.finality().finalized_height().get()
            || metadata.head.block_id().as_bytes()
                != read.finality().finalized_block_id().as_bytes()
            || metadata.head.state_root().as_bytes()
                != read.finality().finalized_state_root().as_bytes()
        {
            return Err(crate::PocoFinalityCommitErrorV0::Application(error(
                NativeApplicationExecutionErrorCodeV0::BindingMismatch,
                "snapshot_export.current_head",
            )));
        }
        let request = NativeSnapshotRequestV0::new(metadata.head.clone(), maximum_chunk_bytes)
            .map_err(|_| {
                crate::PocoFinalityCommitErrorV0::Application(error(
                    NativeApplicationExecutionErrorCodeV0::InvalidConfiguration,
                    "snapshot_export.chunk_limit",
                ))
            })?;
        let manifest = manifest_for_snapshot_v1(request, &metadata)
            .map_err(crate::PocoFinalityCommitErrorV0::Application)?;
        Ok(NativeSnapshotExportV1 {
            owner_affinity: Arc::clone(&self.owner_affinity),
            store_id: self.config.store_id,
            sequence: metadata.durable_sequence,
            snapshot_digest: metadata.snapshot_digest,
            manifest,
            finality_proof_id: *read.finality().proof().id().as_bytes(),
        })
    }

    /// Return one exact native chunk after fresh source readback. Source movement
    /// returns an error, never a mix of generations. The transport must bound its
    /// requests; this deliberately retains existing full-history validation cost.
    pub fn read_snapshot_chunk_v1(
        &self,
        export: &NativeSnapshotExportV1,
        index: u32,
    ) -> DurableResult<Vec<u8>> {
        if !Arc::ptr_eq(&export.owner_affinity, &self.owner_affinity)
            || export.store_id != self.config.store_id
        {
            return Err(error(
                NativeApplicationExecutionErrorCodeV0::BindingMismatch,
                "snapshot_export.owner",
            ));
        }
        let descriptor = export
            .manifest
            .chunks()
            .get(index as usize)
            .filter(|chunk| chunk.index() == index)
            .ok_or_else(|| {
                error(
                    NativeApplicationExecutionErrorCodeV0::BindingMismatch,
                    "snapshot_export.index",
                )
            })?;
        let _guard = self.lock_operation()?;
        let metadata = fresh_validate_v0(&self.path, &self.config)?;
        if metadata.durable_sequence != export.sequence
            || &metadata.head != export.manifest.request().head()
            || metadata.snapshot_digest != export.snapshot_digest
            || metadata.snapshot.len() as u64 != export.manifest.total_bytes()
        {
            return Err(error(
                NativeApplicationExecutionErrorCodeV0::BindingMismatch,
                "snapshot_export.source_changed",
            ));
        }
        let maximum = export.manifest.request().maximum_chunk_bytes() as usize;
        let start = (index as usize).checked_mul(maximum).ok_or_else(|| {
            error(
                NativeApplicationExecutionErrorCodeV0::BindingMismatch,
                "snapshot_export.offset",
            )
        })?;
        let end = start
            .checked_add(descriptor.byte_length() as usize)
            .ok_or_else(|| {
                error(
                    NativeApplicationExecutionErrorCodeV0::BindingMismatch,
                    "snapshot_export.length",
                )
            })?;
        let bytes = metadata.snapshot.get(start..end).ok_or_else(|| {
            error(
                NativeApplicationExecutionErrorCodeV0::BindingMismatch,
                "snapshot_export.range",
            )
        })?;
        let digest = hash_domain(SNAPSHOT_CHUNK_DOMAIN_V0, &[&index.to_be_bytes(), bytes]);
        if &digest != descriptor.digest().as_bytes() {
            return Err(error(
                NativeApplicationExecutionErrorCodeV0::CorruptStore,
                "snapshot_export.chunk_digest",
            ));
        }
        Ok(bytes.to_vec())
    }
}

impl NativeApplicationConfigV0 {
    pub(crate) fn decode_snapshot_reader_v1(
        &self,
        input: &mut impl std::io::Read,
        limits: crate::store::SnapshotReadLimitsV1,
    ) -> anyhow::Result<InMemoryNativeExecutionStoreV0> {
        InMemoryNativeExecutionStoreV0::decode_authenticated_snapshot_reader_v1(
            &self.chain_id,
            self.signers.clone(),
            self.parameters,
            input,
            limits,
        )
    }
}

/// An immutable, strictly finalized native snapshot pinned in owned memory.
/// Unlike `NativeSnapshotExportV1`, this is an explicitly historical read: the
/// source may advance or close without altering its bytes. No new database read
/// happens per chunk, and no execution, replay-floor or signing authority is
/// exported. Consumers still need an independently trusted finality proof.
///
/// The configured cap bounds this retained byte image, not transient allocations
/// made by the existing full-history validation or a consumer's decoded JMT.
///
/// ```compile_fail
/// use trnm_native_execution_v0::PinnedNativeSnapshotExportV1;
/// fn requires_clone<T: Clone>() {}
/// requires_clone::<PinnedNativeSnapshotExportV1>();
/// ```
#[derive(Debug)]
pub struct PinnedNativeSnapshotExportV1 {
    bytes: Vec<u8>,
    manifest: NativeSnapshotManifestV0,
    snapshot_digest: [u8; 32],
    finality_proof_id: [u8; 32],
}
impl PinnedNativeSnapshotExportV1 {
    pub const fn manifest(&self) -> &NativeSnapshotManifestV0 {
        &self.manifest
    }
    pub const fn snapshot_digest(&self) -> &[u8; 32] {
        &self.snapshot_digest
    }
    pub const fn finality_proof_id(&self) -> &[u8; 32] {
        &self.finality_proof_id
    }
    /// Returns a bounded slice of the already authenticated immutable image.
    /// No raw database handle, source-owner capability or mutable slice escapes.
    pub fn chunk(&self, index: u32) -> DurableResult<&[u8]> {
        let descriptor = self
            .manifest
            .chunks()
            .get(index as usize)
            .filter(|descriptor| descriptor.index() == index)
            .ok_or_else(|| {
                error(
                    NativeApplicationExecutionErrorCodeV0::BindingMismatch,
                    "pinned_snapshot.index",
                )
            })?;
        let start = (index as usize)
            .checked_mul(self.manifest.request().maximum_chunk_bytes() as usize)
            .ok_or_else(|| {
                error(
                    NativeApplicationExecutionErrorCodeV0::BindingMismatch,
                    "pinned_snapshot.offset",
                )
            })?;
        let end = start
            .checked_add(descriptor.byte_length() as usize)
            .ok_or_else(|| {
                error(
                    NativeApplicationExecutionErrorCodeV0::BindingMismatch,
                    "pinned_snapshot.length",
                )
            })?;
        self.bytes.get(start..end).ok_or_else(|| {
            error(
                NativeApplicationExecutionErrorCodeV0::CorruptStore,
                "pinned_snapshot.range",
            )
        })
    }
}

impl DurableNativeApplicationV0 {
    /// Consumes an exact owner-bound finalized export, revalidates its original
    /// source once, and retains the verified bytes. Source movement *before*
    /// pinning is rejected. After success the captured image is independent of
    /// source liveness; treating it as the source's newest head is not permitted.
    /// This does not delete audits, introduce an unchecked store cache or change
    /// the existing current-head export API's invalidation semantics.
    pub fn pin_finalized_snapshot_export_v1(
        &self,
        export: NativeSnapshotExportV1,
        maximum_retained_bytes: u64,
    ) -> DurableResult<PinnedNativeSnapshotExportV1> {
        if maximum_retained_bytes == 0
            || maximum_retained_bytes > 512 * 1024 * 1024
            || export.manifest.total_bytes() > maximum_retained_bytes
        {
            return Err(error(
                NativeApplicationExecutionErrorCodeV0::InvalidConfiguration,
                "pinned_snapshot.retained_limit",
            ));
        }
        if !Arc::ptr_eq(&export.owner_affinity, &self.owner_affinity)
            || export.store_id != self.config.store_id
        {
            return Err(error(
                NativeApplicationExecutionErrorCodeV0::BindingMismatch,
                "pinned_snapshot.owner",
            ));
        }
        let _guard = self.lock_operation()?;
        let metadata = fresh_validate_v0(&self.path, &self.config)?;
        if metadata.head != *export.manifest.request().head()
            || metadata.durable_sequence != export.sequence
            || metadata.snapshot_digest != export.snapshot_digest
            || metadata.snapshot.len() as u64 != export.manifest.total_bytes()
            || metadata.snapshot.len() as u64 > maximum_retained_bytes
        {
            return Err(error(
                NativeApplicationExecutionErrorCodeV0::BindingMismatch,
                "pinned_snapshot.source_changed",
            ));
        }
        let rebuilt = manifest_for_snapshot_v1(export.manifest.request().clone(), &metadata)?;
        if rebuilt != export.manifest {
            return Err(error(
                NativeApplicationExecutionErrorCodeV0::CorruptStore,
                "pinned_snapshot.manifest",
            ));
        }
        Ok(PinnedNativeSnapshotExportV1 {
            bytes: metadata.snapshot,
            manifest: export.manifest,
            snapshot_digest: metadata.snapshot_digest,
            finality_proof_id: export.finality_proof_id,
        })
    }
}
