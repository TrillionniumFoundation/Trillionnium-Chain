use crate::{
    error::{error, NativeBoundaryErrorCodeV0, NativeBoundaryResultV0},
    primitives::{ApplicationHeadV0, Hash32V0},
};

pub const MAX_SNAPSHOT_CHUNKS_V0: usize = 4_096;
pub const MAX_SNAPSHOT_CHUNK_BYTES_V0: u32 = 1024 * 1024;
pub const MAX_STATE_PROOF_KEY_BYTES_V0: usize = 4 * 1024;
pub const MAX_STATE_PROOF_VALUE_BYTES_V0: usize = 4 * 1024 * 1024;
pub const MAX_STATE_PROOF_BYTES_V0: usize = 8 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeStateProofSchemeV0 {
    JmtIcs23V0,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeStateProofRequestV0 {
    head: ApplicationHeadV0,
    key: Vec<u8>,
}

impl NativeStateProofRequestV0 {
    pub fn new(head: ApplicationHeadV0, key: Vec<u8>) -> NativeBoundaryResultV0<Self> {
        if key.is_empty() {
            return Err(error(NativeBoundaryErrorCodeV0::Empty, "state_proof.key"));
        }
        if key.len() > MAX_STATE_PROOF_KEY_BYTES_V0 {
            return Err(error(NativeBoundaryErrorCodeV0::TooLong, "state_proof.key"));
        }
        Ok(Self { head, key })
    }

    pub const fn head(&self) -> &ApplicationHeadV0 {
        &self.head
    }

    pub fn key(&self) -> &[u8] {
        &self.key
    }
}

/// Native state proof with an explicit scheme and root binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeStateProofV0 {
    request: NativeStateProofRequestV0,
    scheme: NativeStateProofSchemeV0,
    value: Option<Vec<u8>>,
    proof_bytes: Vec<u8>,
}

impl NativeStateProofV0 {
    pub fn new(
        request: NativeStateProofRequestV0,
        scheme: NativeStateProofSchemeV0,
        value: Option<Vec<u8>>,
        proof_bytes: Vec<u8>,
    ) -> NativeBoundaryResultV0<Self> {
        if value
            .as_ref()
            .is_some_and(|bytes| bytes.len() > MAX_STATE_PROOF_VALUE_BYTES_V0)
        {
            return Err(error(
                NativeBoundaryErrorCodeV0::TooLong,
                "state_proof.value",
            ));
        }
        if proof_bytes.is_empty() {
            return Err(error(
                NativeBoundaryErrorCodeV0::Empty,
                "state_proof.proof_bytes",
            ));
        }
        if proof_bytes.len() > MAX_STATE_PROOF_BYTES_V0 {
            return Err(error(
                NativeBoundaryErrorCodeV0::TooLong,
                "state_proof.proof_bytes",
            ));
        }
        Ok(Self {
            request,
            scheme,
            value,
            proof_bytes,
        })
    }

    pub const fn request(&self) -> &NativeStateProofRequestV0 {
        &self.request
    }

    pub const fn scheme(&self) -> NativeStateProofSchemeV0 {
        self.scheme
    }

    pub fn value(&self) -> Option<&[u8]> {
        self.value.as_deref()
    }

    pub fn proof_bytes(&self) -> &[u8] {
        &self.proof_bytes
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeSnapshotRequestV0 {
    head: ApplicationHeadV0,
    maximum_chunk_bytes: u32,
}

impl NativeSnapshotRequestV0 {
    pub fn new(head: ApplicationHeadV0, maximum_chunk_bytes: u32) -> NativeBoundaryResultV0<Self> {
        if maximum_chunk_bytes == 0 {
            return Err(error(
                NativeBoundaryErrorCodeV0::ZeroValue,
                "snapshot.maximum_chunk_bytes",
            ));
        }
        if maximum_chunk_bytes > MAX_SNAPSHOT_CHUNK_BYTES_V0 {
            return Err(error(
                NativeBoundaryErrorCodeV0::TooLong,
                "snapshot.maximum_chunk_bytes",
            ));
        }
        Ok(Self {
            head,
            maximum_chunk_bytes,
        })
    }

    pub const fn head(&self) -> &ApplicationHeadV0 {
        &self.head
    }

    pub const fn maximum_chunk_bytes(&self) -> u32 {
        self.maximum_chunk_bytes
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeSnapshotChunkV0 {
    index: u32,
    byte_length: u32,
    digest: Hash32V0,
}

impl NativeSnapshotChunkV0 {
    pub fn new(index: u32, byte_length: u32, digest: Hash32V0) -> NativeBoundaryResultV0<Self> {
        if byte_length == 0 {
            return Err(error(
                NativeBoundaryErrorCodeV0::ZeroValue,
                "snapshot_chunk.byte_length",
            ));
        }
        if byte_length > MAX_SNAPSHOT_CHUNK_BYTES_V0 {
            return Err(error(
                NativeBoundaryErrorCodeV0::TooLong,
                "snapshot_chunk.byte_length",
            ));
        }
        Ok(Self {
            index,
            byte_length,
            digest: digest.require_nonzero("snapshot_chunk.digest")?,
        })
    }

    pub const fn index(&self) -> u32 {
        self.index
    }

    pub const fn byte_length(&self) -> u32 {
        self.byte_length
    }

    pub const fn digest(&self) -> Hash32V0 {
        self.digest
    }
}

/// Manifest for an exact application head. Chunk descriptors are contiguous.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeSnapshotManifestV0 {
    request: NativeSnapshotRequestV0,
    chunks: Vec<NativeSnapshotChunkV0>,
    total_bytes: u64,
    manifest_digest: Hash32V0,
}

impl NativeSnapshotManifestV0 {
    pub fn new(
        request: NativeSnapshotRequestV0,
        chunks: Vec<NativeSnapshotChunkV0>,
        manifest_digest: Hash32V0,
    ) -> NativeBoundaryResultV0<Self> {
        if chunks.is_empty() {
            return Err(error(
                NativeBoundaryErrorCodeV0::Empty,
                "snapshot_manifest.chunks",
            ));
        }
        if chunks.len() > MAX_SNAPSHOT_CHUNKS_V0 {
            return Err(error(
                NativeBoundaryErrorCodeV0::TooMany,
                "snapshot_manifest.chunks",
            ));
        }
        let mut total_bytes = 0u64;
        for (expected_index, chunk) in chunks.iter().enumerate() {
            if usize::try_from(chunk.index()).ok() != Some(expected_index) {
                return Err(error(
                    NativeBoundaryErrorCodeV0::NonContiguous,
                    "snapshot_manifest.chunks",
                ));
            }
            if chunk.byte_length() > request.maximum_chunk_bytes() {
                return Err(error(
                    NativeBoundaryErrorCodeV0::TooLong,
                    "snapshot_manifest.chunk_byte_length",
                ));
            }
            total_bytes = total_bytes
                .checked_add(u64::from(chunk.byte_length()))
                .ok_or_else(|| {
                    error(
                        NativeBoundaryErrorCodeV0::Overflow,
                        "snapshot_manifest.total_bytes",
                    )
                })?;
        }
        Ok(Self {
            request,
            chunks,
            total_bytes,
            manifest_digest: manifest_digest.require_nonzero("snapshot_manifest.digest")?,
        })
    }

    pub const fn request(&self) -> &NativeSnapshotRequestV0 {
        &self.request
    }

    pub fn chunks(&self) -> &[NativeSnapshotChunkV0] {
        &self.chunks
    }

    pub const fn total_bytes(&self) -> u64 {
        self.total_bytes
    }

    pub const fn manifest_digest(&self) -> Hash32V0 {
        self.manifest_digest
    }
}
