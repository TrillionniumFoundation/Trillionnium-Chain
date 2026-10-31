//! Opt-in, local, content-addressed Cell chunk assembly. NOT networking, PQ
//! authentication, storage custody, consensus, model selection, or FinalUse.
//! The caller must pin the manifest identifier from an independent owner.
use sha2::{Digest, Sha256};

pub type CellSwarmDigestV0 = [u8; 32];
pub const MAX_CELL_SWARM_BYTES_V0: u64 = 64 * 1024 * 1024;
pub const MAX_CELL_SWARM_CHUNK_BYTES_V0: u32 = 1024 * 1024;
pub const MAX_CELL_SWARM_CHUNKS_V0: usize = 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CellSwarmErrorV0 {
    InvalidDescriptor,
    IncorrectPin,
    InvalidChunk,
    BadChunk,
    ConflictingChunk,
    MissingChunk,
    BadContent,
}

fn digest(tag: &[u8], parts: &[&[u8]]) -> CellSwarmDigestV0 {
    let mut hash = Sha256::new();
    hash.update(b"trnm.cell-swarm.local.v0\0");
    hash.update((tag.len() as u32).to_be_bytes());
    hash.update(tag);
    for part in parts {
        hash.update((part.len() as u64).to_be_bytes());
        hash.update(part);
    }
    hash.finalize().into()
}

fn chunk_digest(
    descriptor: &CellSwarmDescriptorV0,
    index: usize,
    bytes: &[u8],
) -> CellSwarmDigestV0 {
    let number = u32::try_from(index).expect("validated chunk index");
    digest(
        b"chunk",
        &[
            &descriptor.network,
            &descriptor.release_root,
            &descriptor.cell_id,
            &number.to_be_bytes(),
            bytes,
        ],
    )
}

fn content_digest(descriptor: &CellSwarmDescriptorV0, bytes: &[u8]) -> CellSwarmDigestV0 {
    digest(
        b"content",
        &[
            &descriptor.network,
            &descriptor.release_root,
            &descriptor.cell_id,
            bytes,
        ],
    )
}

fn chunk_tree_root(leaves: &[CellSwarmDigestV0]) -> CellSwarmDigestV0 {
    let mut level = leaves.to_vec();
    while level.len() > 1 {
        level = level
            .chunks(2)
            .map(|pair| {
                let right = pair.get(1).unwrap_or(&pair[0]);
                digest(b"tree-node", &[&pair[0], right])
            })
            .collect();
    }
    level[0]
}

/// Immutable byte-and-compatibility identity supplied by the artifact owner.
/// This descriptor is not a signature or a license to distribute the content.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CellSwarmDescriptorV0 {
    pub network: CellSwarmDigestV0,
    pub release_root: CellSwarmDigestV0,
    pub cell_id: CellSwarmDigestV0,
    pub total_bytes: u64,
    pub chunk_bytes: u32,
    pub content_digest: CellSwarmDigestV0,
    pub chunk_hashes: Vec<CellSwarmDigestV0>,
}

fn checked_count(descriptor: &CellSwarmDescriptorV0) -> Result<usize, CellSwarmErrorV0> {
    if descriptor.network == [0; 32]
        || descriptor.release_root == [0; 32]
        || descriptor.cell_id == [0; 32]
        || descriptor.content_digest == [0; 32]
        || descriptor.total_bytes == 0
        || descriptor.total_bytes > MAX_CELL_SWARM_BYTES_V0
        || descriptor.chunk_bytes == 0
        || descriptor.chunk_bytes > MAX_CELL_SWARM_CHUNK_BYTES_V0
    {
        return Err(CellSwarmErrorV0::InvalidDescriptor);
    }
    let count = descriptor
        .total_bytes
        .div_ceil(u64::from(descriptor.chunk_bytes));
    if count == 0
        || count > MAX_CELL_SWARM_CHUNKS_V0 as u64
        || descriptor.chunk_hashes.len() != count as usize
        || descriptor.chunk_hashes.iter().any(|hash| *hash == [0; 32])
    {
        return Err(CellSwarmErrorV0::InvalidDescriptor);
    }
    Ok(count as usize)
}

fn descriptor_digest(descriptor: &CellSwarmDescriptorV0) -> CellSwarmDigestV0 {
    let root = chunk_tree_root(&descriptor.chunk_hashes);
    digest(
        b"manifest",
        &[
            &descriptor.network,
            &descriptor.release_root,
            &descriptor.cell_id,
            &descriptor.total_bytes.to_be_bytes(),
            &descriptor.chunk_bytes.to_be_bytes(),
            &(descriptor.chunk_hashes.len() as u32).to_be_bytes(),
            &descriptor.content_digest,
            &root,
        ],
    )
}

#[derive(Clone, Debug)]
pub struct CellSwarmManifestV0 {
    descriptor: CellSwarmDescriptorV0,
    id: CellSwarmDigestV0,
}

impl CellSwarmManifestV0 {
    fn checked(descriptor: CellSwarmDescriptorV0) -> Result<Self, CellSwarmErrorV0> {
        checked_count(&descriptor)?;
        let id = descriptor_digest(&descriptor);
        Ok(Self { descriptor, id })
    }

    /// Deterministic fixture/producer helper, not publication authority.
    pub fn from_bytes(
        network: CellSwarmDigestV0,
        release_root: CellSwarmDigestV0,
        cell_id: CellSwarmDigestV0,
        chunk_bytes: u32,
        content: &[u8],
    ) -> Result<Self, CellSwarmErrorV0> {
        let total_bytes =
            u64::try_from(content.len()).map_err(|_| CellSwarmErrorV0::InvalidDescriptor)?;
        let mut descriptor = CellSwarmDescriptorV0 {
            network,
            release_root,
            cell_id,
            total_bytes,
            chunk_bytes,
            content_digest: [0; 32],
            chunk_hashes: Vec::new(),
        };
        if total_bytes == 0
            || total_bytes > MAX_CELL_SWARM_BYTES_V0
            || chunk_bytes == 0
            || chunk_bytes > MAX_CELL_SWARM_CHUNK_BYTES_V0
            || total_bytes.div_ceil(u64::from(chunk_bytes)) > MAX_CELL_SWARM_CHUNKS_V0 as u64
            || network == [0; 32]
            || release_root == [0; 32]
            || cell_id == [0; 32]
        {
            return Err(CellSwarmErrorV0::InvalidDescriptor);
        }
        descriptor.content_digest = content_digest(&descriptor, content);
        descriptor.chunk_hashes = content
            .chunks(chunk_bytes as usize)
            .enumerate()
            .map(|(i, bytes)| chunk_digest(&descriptor, i, bytes))
            .collect();
        Self::checked(descriptor)
    }

    /// Reconstruct only when an independent owner has pinned the manifest ID.
    pub fn from_descriptor(
        descriptor: CellSwarmDescriptorV0,
        expected_id: CellSwarmDigestV0,
    ) -> Result<Self, CellSwarmErrorV0> {
        let result = Self::checked(descriptor)?;
        if expected_id == [0; 32] || result.id != expected_id {
            return Err(CellSwarmErrorV0::IncorrectPin);
        }
        Ok(result)
    }

    pub fn id(&self) -> CellSwarmDigestV0 {
        self.id
    }

    pub fn descriptor(&self) -> &CellSwarmDescriptorV0 {
        &self.descriptor
    }
}

/// Byte receipt only. It does not authorize loading a Cell into Hepta.
pub struct VerifiedCellSwarmBytesV0 {
    bytes: Vec<u8>,
    manifest_id: CellSwarmDigestV0,
}

impl VerifiedCellSwarmBytesV0 {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn manifest_id(&self) -> CellSwarmDigestV0 {
        self.manifest_id
    }
}

pub struct CellSwarmAssemblerV0 {
    manifest: CellSwarmManifestV0,
    slots: Vec<Option<Vec<u8>>>,
    received: usize,
}

impl CellSwarmAssemblerV0 {
    pub fn new(
        manifest: CellSwarmManifestV0,
        independently_pinned_id: CellSwarmDigestV0,
    ) -> Result<Self, CellSwarmErrorV0> {
        if independently_pinned_id == [0; 32] || manifest.id != independently_pinned_id {
            return Err(CellSwarmErrorV0::IncorrectPin);
        }
        let count = checked_count(&manifest.descriptor)?;
        Ok(Self {
            manifest,
            slots: (0..count).map(|_| None).collect(),
            received: 0,
        })
    }

    /// Accept bytes from an untrusted source in any order. This does NOT
    /// authenticate the source or establish independent provider diversity.
    /// Returns true only for the first valid copy of a given index.
    pub fn offer(&mut self, index: usize, bytes: &[u8]) -> Result<bool, CellSwarmErrorV0> {
        if index >= self.slots.len() {
            return Err(CellSwarmErrorV0::InvalidChunk);
        }
        let offset = index * self.manifest.descriptor.chunk_bytes as usize;
        let remaining = self.manifest.descriptor.total_bytes as usize - offset;
        let expected = remaining.min(self.manifest.descriptor.chunk_bytes as usize);
        if bytes.len() != expected {
            return Err(CellSwarmErrorV0::InvalidChunk);
        }
        if let Some(first) = &self.slots[index] {
            return if first == bytes {
                Ok(false)
            } else {
                Err(CellSwarmErrorV0::ConflictingChunk)
            };
        }
        if chunk_digest(&self.manifest.descriptor, index, bytes)
            != self.manifest.descriptor.chunk_hashes[index]
        {
            return Err(CellSwarmErrorV0::BadChunk);
        }
        self.slots[index] = Some(bytes.to_vec());
        self.received += 1;
        Ok(true)
    }

    pub fn received(&self) -> usize {
        self.received
    }

    pub fn finish(self) -> Result<VerifiedCellSwarmBytesV0, CellSwarmErrorV0> {
        if self.received != self.slots.len() {
            return Err(CellSwarmErrorV0::MissingChunk);
        }
        let mut bytes = Vec::with_capacity(self.manifest.descriptor.total_bytes as usize);
        for entry in self.slots {
            bytes.extend_from_slice(&entry.ok_or(CellSwarmErrorV0::MissingChunk)?);
        }
        if content_digest(&self.manifest.descriptor, &bytes)
            != self.manifest.descriptor.content_digest
        {
            return Err(CellSwarmErrorV0::BadContent);
        }
        Ok(VerifiedCellSwarmBytesV0 {
            bytes,
            manifest_id: self.manifest.id,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (CellSwarmManifestV0, &'static [u8]) {
        let bytes = b"abcdefghijklmnopq";
        (CellSwarmManifestV0::from_bytes([1; 32], [2; 32], [3; 32], 4, bytes).unwrap(), bytes)
    }

    #[test]
    fn out_of_order_shards_reconstruct_under_owner_pin() {
        let (manifest, bytes) = fixture();
        let id = manifest.id();
        let reconstructed =
            CellSwarmManifestV0::from_descriptor(manifest.descriptor().clone(), id).unwrap();
        let mut assembler = CellSwarmAssemblerV0::new(reconstructed, id).unwrap();
        for index in [4, 1, 3, 0, 2] {
            assert!(assembler.offer(index, &bytes[index * 4..(index * 4 + 4).min(bytes.len())]).unwrap());
        }
        assert_eq!(assembler.received(), 5);
        let verified = assembler.finish().unwrap();
        assert_eq!(verified.bytes(), bytes);
        assert_eq!(verified.manifest_id(), id);
    }

    #[test]
    fn owner_pin_does_not_follow_manifest_or_network_substitution() {
        let (manifest, _) = fixture();
        let id = manifest.id();
        let mut changed = manifest.descriptor().clone();
        changed.network[0] ^= 1;
        assert_eq!(
            CellSwarmManifestV0::from_descriptor(changed, id).unwrap_err(),
            CellSwarmErrorV0::IncorrectPin
        );
        assert!(matches!(
            CellSwarmAssemblerV0::new(manifest, [9; 32]),
            Err(CellSwarmErrorV0::IncorrectPin)
        ));
    }

    #[test]
    fn malicious_shard_is_rejected_without_poisoning_valid_reassembly() {
        let (manifest, bytes) = fixture();
        let id = manifest.id();
        let mut assembler = CellSwarmAssemblerV0::new(manifest, id).unwrap();
        assert_eq!(assembler.offer(0, b"xbcd"), Err(CellSwarmErrorV0::BadChunk));
        assert_eq!(assembler.received(), 0);
        assert_eq!(assembler.offer(0, b"abcd"), Ok(true));
        assert_eq!(assembler.offer(0, b"abcd"), Ok(false));
        assert_eq!(
            assembler.offer(0, b"abce"),
            Err(CellSwarmErrorV0::ConflictingChunk)
        );
        assert_eq!(
            assembler.offer(99, b"test"),
            Err(CellSwarmErrorV0::InvalidChunk)
        );
        for index in 1..5 {
            assert!(assembler.offer(index, &bytes[index * 4..(index * 4 + 4).min(bytes.len())]).unwrap());
        }
        assert_eq!(assembler.finish().unwrap().bytes(), bytes);
    }

    #[test]
    fn incomplete_archive_never_becomes_verified_bytes() {
        let (manifest, _) = fixture();
        let id = manifest.id();
        let mut assembler = CellSwarmAssemblerV0::new(manifest, id).unwrap();
        assembler.offer(0, b"abcd").unwrap();
        assert!(matches!(assembler.finish(), Err(CellSwarmErrorV0::MissingChunk)));
    }

    #[test]
    fn malformed_shapes_reject_before_unbounded_allocation() {
        let (manifest, _) = fixture();
        let id = manifest.id();
        let mut bad = manifest.descriptor().clone();
        bad.total_bytes = MAX_CELL_SWARM_BYTES_V0 + 1;
        assert_eq!(
            CellSwarmManifestV0::from_descriptor(bad, id).unwrap_err(),
            CellSwarmErrorV0::InvalidDescriptor
        );
        let mut bad = manifest.descriptor().clone();
        bad.chunk_bytes = 0;
        assert_eq!(
            CellSwarmManifestV0::from_descriptor(bad, id).unwrap_err(),
            CellSwarmErrorV0::InvalidDescriptor
        );
        let mut bad = manifest.descriptor().clone();
        bad.chunk_hashes.clear();
        assert_eq!(
            CellSwarmManifestV0::from_descriptor(bad, id).unwrap_err(),
            CellSwarmErrorV0::InvalidDescriptor
        );
    }
}
