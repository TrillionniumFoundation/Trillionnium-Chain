//! Concrete, non-executing native JMT staging. Domain decoding and tree
//! computation stay in M06; this module fixes the M13 composition boundary.
use std::{error::Error, fmt, path::PathBuf};

use trnm_consensus_types::BlockKind;
use trnm_native_execution_v0::{
    native_current_live_schema_digest_v1, recompute_native_current_live_v1,
    MAX_NATIVE_CURRENT_LIVE_BYTES_V1, NATIVE_CURRENT_LIVE_MAX_CHUNKS_V1 as MAX_NATIVE_CHUNKS,
    NATIVE_CURRENT_LIVE_MAX_CHUNK_BYTES_V1 as MAX_NATIVE_CHUNK_BYTES,
};
use trnm_state_sync_v0::{
    chunk_merkle_root_v0, Digest32V0, NativeApplicationCheckpointV1, NativeStateSyncBindingV1,
    NativeStateSyncReadbackV1, NativeStateSyncSessionV1, NativeVerifiedSnapshotV1, SnapshotChunkV0,
    SnapshotManifestV0, SqliteNativeStateSyncStoreV1, StateRootRecomputerV0,
    VerifiedNativeTrustPathV1,
};

#[derive(Debug)]
pub enum NativeLiveSyncErrorV1 {
    Profile,
    Native(String),
    Session(String),
    Store(String),
}
impl fmt::Display for NativeLiveSyncErrorV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Profile => f.write_str("native live snapshot profile mismatch"),
            Self::Native(e) => write!(f, "native live root validation failed: {e}"),
            Self::Session(e) => write!(f, "native live session rejected input: {e}"),
            Self::Store(e) => write!(f, "native live durable session rejected input: {e}"),
        }
    }
}
impl Error for NativeLiveSyncErrorV1 {}

// No public constructor or trait parameter can substitute a root producer.
struct NativeJmtRecomputerV1 {
    path: VerifiedNativeTrustPathV1,
}
impl StateRootRecomputerV0 for NativeJmtRecomputerV1 {
    type Error = NativeLiveSyncErrorV1;

    fn recompute_state_root<'a, I>(
        &self,
        schema_digest: Digest32V0,
        ordered_chunks: I,
    ) -> Result<Digest32V0, Self::Error>
    where
        I: IntoIterator<Item = &'a [u8]>,
    {
        if schema_digest != Digest32V0(native_current_live_schema_digest_v1()) {
            return Err(NativeLiveSyncErrorV1::Profile);
        }
        let mut bytes = Vec::new();
        let mut count = 0u32;
        for chunk in ordered_chunks {
            count = count.checked_add(1).ok_or(NativeLiveSyncErrorV1::Profile)?;
            let length = bytes
                .len()
                .checked_add(chunk.len())
                .ok_or(NativeLiveSyncErrorV1::Profile)?;
            if chunk.is_empty()
                || chunk.len() > MAX_NATIVE_CHUNK_BYTES
                || count as usize > MAX_NATIVE_CHUNKS
                || length > MAX_NATIVE_CURRENT_LIVE_BYTES_V1
            {
                return Err(NativeLiveSyncErrorV1::Profile);
            }
            bytes.extend_from_slice(chunk);
        }
        recompute_native_current_live_v1(
            &bytes,
            self.path.terminal_header(),
            self.path.terminal_validator_set(),
            self.path.terminal_parameters(),
        )
        .map(Digest32V0)
        .map_err(|e| NativeLiveSyncErrorV1::Native(format!("{e:#}")))
    }
}

fn application(
    path: &VerifiedNativeTrustPathV1,
) -> Result<NativeApplicationCheckpointV1, NativeLiveSyncErrorV1> {
    if !matches!(
        path.terminal_header().block_kind(),
        BlockKind::Regular | BlockKind::EpochCheckpoint | BlockKind::EpochHandoff
    ) {
        return Err(NativeLiveSyncErrorV1::Profile);
    }
    Ok(NativeApplicationCheckpointV1 {
        schema_digest: Digest32V0(native_current_live_schema_digest_v1()),
        application_version: path.terminal_header().height().get(),
    })
}

fn check_profile(manifest: &SnapshotManifestV0) -> Result<(), NativeLiveSyncErrorV1> {
    if manifest.schema_digest != Digest32V0(native_current_live_schema_digest_v1())
        || manifest.chunk_count == 0
        || manifest.chunk_count as usize > MAX_NATIVE_CHUNKS
        || manifest.maximum_chunk_bytes == 0
        || manifest.maximum_chunk_bytes as usize > MAX_NATIVE_CHUNK_BYTES
        || manifest.total_bytes == 0
        || manifest.total_bytes > MAX_NATIVE_CURRENT_LIVE_BYTES_V1 as u64
    {
        return Err(NativeLiveSyncErrorV1::Profile);
    }
    Ok(())
}

/// Inert transfer data. A receiver must independently verify finality and use
/// `NativeLiveStateSyncV1`; recomputing transport checksums alone is insufficient.
#[derive(Clone, Debug)]
pub struct NativeLiveTransferV1 {
    pub manifest: SnapshotManifestV0,
    pub chunks: Vec<SnapshotChunkV0>,
}

/// Package a genuine M08 current export under a verified terminal context.
/// This helper grants no download, install, execution, or signing authority.
pub fn prepare_native_live_transfer_v1(
    path: &VerifiedNativeTrustPathV1,
    bytes: &[u8],
) -> Result<NativeLiveTransferV1, NativeLiveSyncErrorV1> {
    recompute_native_current_live_v1(
        bytes,
        path.terminal_header(),
        path.terminal_validator_set(),
        path.terminal_parameters(),
    )
    .map_err(|e| NativeLiveSyncErrorV1::Native(format!("{e:#}")))?;
    let trust = path.snapshot_trust_path();
    let mut manifest = SnapshotManifestV0 {
        chain_id: trust.anchor().chain_id,
        protocol_digest: trust.anchor().protocol_digest,
        height: path.terminal_header().height().get(),
        epoch: path.terminal_header().epoch().get(),
        state_root: Digest32V0(*path.terminal_header().state_root().as_bytes()),
        chunk_root: Digest32V0([0; 32]),
        chunk_count: u32::try_from(bytes.len().div_ceil(MAX_NATIVE_CHUNK_BYTES))
            .map_err(|_| NativeLiveSyncErrorV1::Profile)?,
        maximum_chunk_bytes: MAX_NATIVE_CHUNK_BYTES as u32,
        total_bytes: bytes.len() as u64,
        schema_digest: Digest32V0(native_current_live_schema_digest_v1()),
        checkpoint_digest: trust.terminal().checkpoint_digest,
        manifest_digest: Digest32V0([0; 32]),
    };
    check_profile(&manifest)?;
    let binding = manifest.chunk_binding_digest();
    let chunks: Vec<_> = bytes
        .chunks(MAX_NATIVE_CHUNK_BYTES)
        .enumerate()
        .map(|(index, bytes)| SnapshotChunkV0 {
            manifest_digest: binding,
            index: index as u32,
            bytes: bytes.to_vec(),
            chunk_digest: SnapshotChunkV0::canonical_digest(binding, index as u32, bytes),
        })
        .collect();
    let digests: Vec<_> = chunks.iter().map(|chunk| chunk.chunk_digest).collect();
    manifest.chunk_root = chunk_merkle_root_v0(&digests);
    manifest.manifest_digest = manifest.canonical_digest();
    manifest
        .validate(trust)
        .map_err(|e| NativeLiveSyncErrorV1::Session(e.to_string()))?;
    Ok(NativeLiveTransferV1 { manifest, chunks })
}

/// A session whose verification always runs the concrete native JMT decoder.
/// It never accepts an arbitrary application schema/version or root adapter.
pub struct NativeLiveStateSyncV1 {
    session: NativeStateSyncSessionV1,
    recomputer: NativeJmtRecomputerV1,
}
impl NativeLiveStateSyncV1 {
    pub fn begin(
        path: VerifiedNativeTrustPathV1,
        manifest: SnapshotManifestV0,
    ) -> Result<Self, NativeLiveSyncErrorV1> {
        check_profile(&manifest)?;
        let app = application(&path)?;
        let session = NativeStateSyncSessionV1::begin(path.clone(), manifest, app)
            .map_err(|e| NativeLiveSyncErrorV1::Session(e.to_string()))?;
        Ok(Self {
            session,
            recomputer: NativeJmtRecomputerV1 { path },
        })
    }

    pub fn accept_chunk(&mut self, chunk: SnapshotChunkV0) -> Result<(), NativeLiveSyncErrorV1> {
        self.session
            .accept_chunk(chunk)
            .map_err(|e| NativeLiveSyncErrorV1::Session(e.to_string()))
    }

    pub fn missing_chunks(&self) -> Vec<u32> {
        self.session.missing_chunks()
    }

    pub fn binding(&self) -> NativeStateSyncBindingV1 {
        self.session.binding()
    }

    pub fn readback(&self) -> NativeStateSyncReadbackV1 {
        self.session.readback()
    }

    pub fn initialize_durable(
        &self,
        path: impl Into<PathBuf>,
    ) -> Result<SqliteNativeStateSyncStoreV1, NativeLiveSyncErrorV1> {
        SqliteNativeStateSyncStoreV1::initialize(path, &self.session)
            .map_err(|e| NativeLiveSyncErrorV1::Store(e.to_string()))
    }

    pub fn append_durable(
        &mut self,
        store: &SqliteNativeStateSyncStoreV1,
        chunk: SnapshotChunkV0,
    ) -> Result<NativeStateSyncReadbackV1, NativeLiveSyncErrorV1> {
        store
            .append_chunk_v1(&mut self.session, chunk)
            .map_err(|e| NativeLiveSyncErrorV1::Store(e.to_string()))?;
        Ok(self.session.readback())
    }

    /// Cold-open under the freshly verified path and native profile before any
    /// retained chunk BLOB is materialized. This avoids generic open/readback.
    pub fn open_durable(
        store_path: impl Into<PathBuf>,
        path: VerifiedNativeTrustPathV1,
        manifest: SnapshotManifestV0,
    ) -> Result<(SqliteNativeStateSyncStoreV1, Self), NativeLiveSyncErrorV1> {
        check_profile(&manifest)?;
        let app = application(&path)?;
        let (store, session) = SqliteNativeStateSyncStoreV1::resume_from_path_v1(
            store_path,
            path.clone(),
            manifest,
            app,
        )
        .map_err(|e| NativeLiveSyncErrorV1::Store(e.to_string()))?;
        Ok((
            store,
            Self {
                session,
                recomputer: NativeJmtRecomputerV1 { path },
            },
        ))
    }

    pub fn resume_durable(
        store: &SqliteNativeStateSyncStoreV1,
        path: VerifiedNativeTrustPathV1,
        manifest: SnapshotManifestV0,
    ) -> Result<Self, NativeLiveSyncErrorV1> {
        check_profile(&manifest)?;
        let app = application(&path)?;
        let session = store
            .resume_existing_v1(path.clone(), manifest, app)
            .map_err(|e| NativeLiveSyncErrorV1::Store(e.to_string()))?;
        Ok(Self {
            session,
            recomputer: NativeJmtRecomputerV1 { path },
        })
    }

    pub fn verify_complete(&self) -> Result<NativeLiveVerifiedStagingV1, NativeLiveSyncErrorV1> {
        self.session
            .verify_complete(&self.recomputer)
            .map(|snapshot| NativeLiveVerifiedStagingV1 { snapshot })
            .map_err(|e| NativeLiveSyncErrorV1::Session(e.to_string()))
    }
}

/// Proof-bound current leaves only. Replay history is not in the signed state
/// root, so this value cannot be used as an execution-ready owner or installer.
///
/// ```compile_fail
/// use trnm_poco_node_production_v0::NativeLiveVerifiedStagingV1;
/// let forged = NativeLiveVerifiedStagingV1 {};
/// ```
///
/// ```compile_fail
/// use trnm_poco_node_production_v0::NativeLiveVerifiedStagingV1;
/// use trnm_state_sync_v0::NativeVerifiedSnapshotV1;
/// fn promote(generic: NativeVerifiedSnapshotV1) -> NativeLiveVerifiedStagingV1 {
///     generic.into()
/// }
/// ```
pub struct NativeLiveVerifiedStagingV1 {
    snapshot: NativeVerifiedSnapshotV1,
}
impl NativeLiveVerifiedStagingV1 {
    pub fn binding(&self) -> NativeStateSyncBindingV1 {
        self.snapshot.binding()
    }
}
