//! Explicit BEP 52 transport leaves over independently hashed TCM1 storage chunks.
//!
//! BEP 52 always hashes 16 KiB leaves. Its logical piece length in this profile
//! is the TCM1 storage chunk size; a piece hash is derived from the actual leaf
//! bytes, never from the ordinary SHA-256 of a larger storage chunk. This is a
//! separate profile from the existing 16 KiB-only binding and peer protocol.

use std::{io::Read, time::Instant};

use sha2::{Digest, Sha256};

use super::{
    digest_hex, require, store::verify_chunk_with_deadline, CellBep52MagnetV1, CellContextV1,
    CellDigestV1, CellErrorV1, CellManifestV1, CellReleaseLimitsV1, CellResultV1, CellStoreV1,
    MAX_CELL_BYTES,
};

mod peer;
pub use peer::{
    fetch_cell_bep52_storage_v2, CellBep52StorageFetchReportV2, CellBep52StorageSeedV2,
    CELL_BEP52_STORAGE_PEER_PROFILE_V2,
};

pub const CELL_BEP52_STORAGE_PROFILE_V2: &str = "cell-bep52-storage-binding-v2";
pub const CELL_BEP52_LEAF_BYTES_V2: u32 = 16_384;
pub const MAX_CELL_BEP52_STORAGE_PIECES_V2: usize = 16_384;
pub const MAX_CELL_BEP52_STORAGE_INFO_BYTES_V2: usize = 256;
pub const MAX_CELL_BEP52_STORAGE_METAINFO_BYTES_V2: usize =
    1024 + MAX_CELL_BEP52_STORAGE_PIECES_V2 * 32;
pub const MAX_CELL_BEP52_STORAGE_MAPPING_BYTES_V2: usize =
    MAPPING_HEADER_BYTES + MAX_CELL_BEP52_STORAGE_PIECES_V2 * 32;
pub const MAX_CELL_BEP52_LEAF_PROOF_BYTES_V2: usize = PROOF_HEADER_BYTES + 22 * 32;

const MAPPING_HEADER_BYTES: usize = 52;
const PROOF_HEADER_BYTES: usize = 109;
const MAX_LEAVES: u32 = (MAX_CELL_BYTES / CELL_BEP52_LEAF_BYTES_V2 as u64) as u32;
const MAPPING_DOMAIN: &[u8] = b"trnm.cell-bep52-storage-mapping.v2\0";

/// A content-addressed mapping between a pinned TCM1 and its BEP 52 piece roots.
///
/// Byte-reading constructors check every storage chunk and the ordered complete
/// payload digest. Importing an independently owner-pinned mapping establishes
/// only its declared identity. Transport-leaf verification is not a complete
/// TCM1 chunk check: acquisition publishes a storage chunk only after checking
/// its entire original SHA-256. Neither path grants availability or execution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CellBep52StorageBindingV2 {
    manifest: CellManifestV1,
    manifest_id: CellDigestV1,
    // At most 2 * 16,384 - 1 hashes, independent of the number of 16 KiB leaves.
    // For a single short file the first/only root is at the file's minimal
    // Merkle height, not the otherwise larger logical piece height.
    levels: Vec<Vec<CellDigestV1>>,
    mapping_id: CellDigestV1,
    info_hash: CellDigestV1,
}

impl CellBep52StorageBindingV2 {
    /// Derive the mapping from the complete original ordered byte stream. The
    /// same reservation covers all chunks, the final payload check and EOF.
    /// Reader I/O is cooperative and cannot be interrupted by this deadline.
    pub fn from_pinned_reader(
        manifest: &CellManifestV1,
        expected_manifest: CellDigestV1,
        expected_context: &CellContextV1,
        input: &mut impl Read,
        limits: CellReleaseLimitsV1,
    ) -> CellResultV1<Self> {
        check_pins(manifest, expected_manifest, expected_context)?;
        check_read_limits(manifest, limits)?;
        let binding = Self::from_chunks(manifest, expected_manifest, limits, |_, size| {
            let mut bytes = vec![0; size];
            input.read_exact(&mut bytes)?;
            Ok(bytes)
        })?;
        check_deadline(limits.deadline)?;
        require(
            input.read(&mut [0; 1])? == 0,
            "BEP52 storage input trailing bytes",
        )?;
        check_deadline(limits.deadline)?;
        Ok(binding)
    }

    /// Read actual cache bytes, not chunk declarations, using the caller's
    /// original reservation. Missing/corrupt bytes cannot produce a mapping.
    pub fn from_pinned_store(
        manifest: &CellManifestV1,
        expected_manifest: CellDigestV1,
        expected_context: &CellContextV1,
        store: &CellStoreV1,
        limits: CellReleaseLimitsV1,
    ) -> CellResultV1<Self> {
        check_pins(manifest, expected_manifest, expected_context)?;
        check_read_limits(manifest, limits)?;
        Self::from_chunks(manifest, expected_manifest, limits, |index, _| {
            store
                .chunk_with_deadline(manifest.chunks()[index].sha256, Some(limits.deadline))?
                .ok_or(CellErrorV1::Unavailable)
        })
    }

    fn from_chunks(
        manifest: &CellManifestV1,
        manifest_id: CellDigestV1,
        limits: CellReleaseLimitsV1,
        mut read: impl FnMut(usize, usize) -> CellResultV1<Vec<u8>>,
    ) -> CellResultV1<Self> {
        let mut full = Sha256::new();
        let mut roots = Vec::with_capacity(manifest.chunks().len());
        let width = subtree_width(manifest);
        for (index, expected) in manifest.chunks().iter().enumerate() {
            check_deadline(limits.deadline)?;
            let bytes = read(index, expected.size as usize)?;
            verify_chunk_with_deadline(expected, &bytes, Some(limits.deadline))?;
            full.update(&bytes);
            roots.push(leaf_levels(&bytes, width).last().unwrap()[0]);
            check_deadline(limits.deadline)?;
        }
        require(
            <CellDigestV1>::from(full.finalize()) == manifest.payload_sha256(),
            "BEP52 storage complete payload digest",
        )?;
        let binding = Self::from_roots(manifest, manifest_id, roots);
        check_deadline(limits.deadline)?;
        Ok(binding)
    }

    /// Import CBM2 only under three independent owner pins: TCM1, context and
    /// mapping ID. A peer's magnet or self-supplied mapping ID is not a pin.
    /// No payload bytes are read here; the imported declaration is verified
    /// against the original TCM1 chunk hash when that chunk is acquired.
    pub fn from_pinned_mapping(
        manifest: &CellManifestV1,
        expected_manifest: CellDigestV1,
        expected_context: &CellContextV1,
        expected_mapping: CellDigestV1,
        bytes: &[u8],
    ) -> CellResultV1<Self> {
        check_pins(manifest, expected_manifest, expected_context)?;
        require(
            (MAPPING_HEADER_BYTES + 32..=MAX_CELL_BEP52_STORAGE_MAPPING_BYTES_V2)
                .contains(&bytes.len()),
            "BEP52 storage mapping length",
        )?;
        require(
            mapping_digest(bytes) == expected_mapping,
            "BEP52 storage mapping pin",
        )?;
        require(&bytes[..4] == b"CBM2", "BEP52 storage mapping version")?;
        require(
            bytes[4..36] == expected_manifest,
            "BEP52 storage mapping manifest",
        )?;
        let size = u64::from_be_bytes(bytes[36..44].try_into().unwrap());
        let piece_bytes = u32::from_be_bytes(bytes[44..48].try_into().unwrap());
        let count = u32::from_be_bytes(bytes[48..52].try_into().unwrap()) as usize;
        require(
            size == manifest.size() && piece_bytes == manifest.chunk_bytes(),
            "BEP52 storage mapping byte layout",
        )?;
        require(
            count == manifest.chunks().len() && bytes.len() == MAPPING_HEADER_BYTES + count * 32,
            "BEP52 storage mapping coverage",
        )?;
        let roots = bytes[MAPPING_HEADER_BYTES..]
            .chunks_exact(32)
            .map(|hash| hash.try_into().unwrap())
            .collect();
        let binding = Self::from_roots(manifest, expected_manifest, roots);
        require(
            binding.mapping_id == expected_mapping,
            "BEP52 storage mapping canonical",
        )?;
        Ok(binding)
    }

    fn from_roots(
        manifest: &CellManifestV1,
        manifest_id: CellDigestV1,
        mut roots: Vec<CellDigestV1>,
    ) -> Self {
        let padding = zero_subtree(subtree_width(manifest).trailing_zeros());
        roots.resize(roots.len().next_power_of_two(), padding);
        let levels = build_levels(roots);
        let mut value = Self {
            manifest: manifest.clone(),
            manifest_id,
            levels,
            mapping_id: [0; 32],
            info_hash: [0; 32],
        };
        value.mapping_id = mapping_digest(&value.mapping_bytes());
        value.info_hash = Sha256::digest(value.info_bytes()).into();
        value
    }

    pub fn manifest(&self) -> &CellManifestV1 {
        &self.manifest
    }

    pub fn manifest_id(&self) -> CellDigestV1 {
        self.manifest_id
    }

    pub fn mapping_id(&self) -> CellDigestV1 {
        self.mapping_id
    }

    pub fn info_hash(&self) -> CellDigestV1 {
        self.info_hash
    }

    pub fn pieces_root(&self) -> CellDigestV1 {
        self.levels.last().unwrap()[0]
    }

    pub fn leaf_count(&self) -> u32 {
        self.manifest
            .size()
            .div_ceil(u64::from(CELL_BEP52_LEAF_BYTES_V2)) as u32
    }

    pub fn piece_roots(&self) -> &[CellDigestV1] {
        &self.levels[0][..self.manifest.chunks().len()]
    }

    /// Canonical CBM2 contains only actual storage-piece roots. SHA-256(raw
    /// storage bytes) stays in TCM1 and has a different meaning from these roots.
    pub fn mapping_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(MAPPING_HEADER_BYTES + self.piece_roots().len() * 32);
        out.extend_from_slice(b"CBM2");
        out.extend_from_slice(&self.manifest_id);
        out.extend_from_slice(&self.manifest.size().to_be_bytes());
        out.extend_from_slice(&self.manifest.chunk_bytes().to_be_bytes());
        out.extend_from_slice(&(self.piece_roots().len() as u32).to_be_bytes());
        for root in self.piece_roots() {
            out.extend_from_slice(root);
        }
        out
    }

    pub fn info_bytes(&self) -> Vec<u8> {
        let mut out = b"d9:file treed8:cell.bind0:d6:lengthi".to_vec();
        out.extend_from_slice(self.manifest.size().to_string().as_bytes());
        out.extend_from_slice(b"e11:pieces root32:");
        out.extend_from_slice(&self.pieces_root());
        out.extend_from_slice(b"eee12:meta versioni2e4:name8:cell.bin12:piece lengthi");
        out.extend_from_slice(self.manifest.chunk_bytes().to_string().as_bytes());
        out.extend_from_slice(b"ee");
        out
    }

    pub fn metainfo_bytes(&self) -> Vec<u8> {
        let mut out = b"d4:info".to_vec();
        out.extend_from_slice(&self.info_bytes());
        out.extend_from_slice(b"12:piece layersd");
        if self.manifest.chunks().len() > 1 {
            out.extend_from_slice(b"32:");
            out.extend_from_slice(&self.pieces_root());
            out.extend_from_slice((self.piece_roots().len() * 32).to_string().as_bytes());
            out.push(b':');
            for root in self.piece_roots() {
                out.extend_from_slice(root);
            }
        }
        out.extend_from_slice(b"ee");
        out
    }

    pub fn magnet(&self) -> CellBep52MagnetV1 {
        // The fixed syntax is shared; a magnet still supplies no owner pin.
        CellBep52MagnetV1::parse(&format!(
            "magnet:?xt=urn:btmh:1220{}",
            digest_hex(self.info_hash)
        ))
        .expect("canonical SHA-256 magnet")
    }

    pub fn verify_info_bytes(&self, bytes: &[u8]) -> CellResultV1<()> {
        require(
            bytes.len() <= MAX_CELL_BEP52_STORAGE_INFO_BYTES_V2 && bytes == self.info_bytes(),
            "BEP52 storage canonical info",
        )
    }

    pub fn verify_metainfo_bytes(&self, bytes: &[u8]) -> CellResultV1<()> {
        require(
            bytes.len() <= MAX_CELL_BEP52_STORAGE_METAINFO_BYTES_V2
                && bytes == self.metainfo_bytes(),
            "BEP52 storage canonical metainfo",
        )
    }

    /// The location is derived from fixed file, storage and leaf lengths. There
    /// is no peer-selected offset, overlap, gap or separate tensor interpretation.
    pub fn leaf_location(&self, index: u32) -> CellResultV1<CellBep52LeafLocationV2> {
        require(index < self.leaf_count(), "BEP52 storage leaf index")?;
        let offset = u64::from(index) * u64::from(CELL_BEP52_LEAF_BYTES_V2);
        Ok(CellBep52LeafLocationV2 {
            leaf_index: index,
            storage_index: (offset / u64::from(self.manifest.chunk_bytes())) as u32,
            storage_offset: (offset % u64::from(self.manifest.chunk_bytes())) as u32,
            payload_offset: offset,
            size: (self.manifest.size() - offset).min(u64::from(CELL_BEP52_LEAF_BYTES_V2)) as u32,
        })
    }

    /// Check both the entire original storage SHA-256 and the derived BEP 52
    /// subtree on the same actual byte slice before releasing it to a caller.
    pub fn verify_storage_chunk(&self, index: u32, bytes: &[u8]) -> CellResultV1<()> {
        self.verify_storage_chunk_until(index, bytes, None)
    }

    fn verify_storage_chunk_until(
        &self,
        index: u32,
        bytes: &[u8],
        deadline: Option<Instant>,
    ) -> CellResultV1<()> {
        self.checked_chunk_levels(index, bytes, deadline)?;
        Ok(())
    }

    fn checked_chunk_levels(
        &self,
        index: u32,
        bytes: &[u8],
        deadline: Option<Instant>,
    ) -> CellResultV1<Vec<Vec<CellDigestV1>>> {
        let expected = self
            .manifest
            .chunks()
            .get(index as usize)
            .ok_or(CellErrorV1::Invalid("BEP52 storage chunk index"))?;
        verify_chunk_with_deadline(expected, bytes, deadline)?;
        let levels = leaf_levels(bytes, subtree_width(&self.manifest));
        let root = levels.last().unwrap()[0];
        if let Some(end) = deadline {
            check_deadline(end)?;
        }
        require(
            root == self.piece_roots()[index as usize],
            "BEP52 storage chunk subtree",
        )?;
        Ok(levels)
    }

    /// Check a chunk once and retain its at most 511 Merkle nodes while its
    /// immutable bytes are borrowed. Serving each leaf then takes only its
    /// logarithmic proof path instead of rehashing the whole 4 MiB chunk.
    pub fn verified_storage_chunk<'a>(
        &'a self,
        index: u32,
        bytes: &'a [u8],
    ) -> CellResultV1<CellBep52VerifiedStorageChunkV2<'a>> {
        let levels = self.checked_chunk_levels(index, bytes, None)?;
        Ok(CellBep52VerifiedStorageChunkV2 {
            binding: self,
            storage_index: index,
            bytes,
            levels,
        })
    }

    /// Produce a CBL2 companion proof from one actual, fully checked storage
    /// chunk. CBL2 is not the BitTorrent peer `hashes` message.
    pub fn leaf_proof(
        &self,
        index: u32,
        storage_bytes: &[u8],
    ) -> CellResultV1<CellBep52LeafProofV2> {
        let location = self.leaf_location(index)?;
        self.verified_storage_chunk(location.storage_index, storage_bytes)?
            .leaf_proof(index)
    }

    fn proof_from_levels(
        &self,
        location: CellBep52LeafLocationV2,
        local: &[Vec<CellDigestV1>],
    ) -> CellResultV1<CellBep52LeafProofV2> {
        let mut siblings = siblings_at(local, location.storage_offset / CELL_BEP52_LEAF_BYTES_V2);
        siblings.extend(siblings_at(&self.levels, location.storage_index));
        let proof = CellBep52LeafProofV2 {
            mapping: self.mapping_id,
            manifest: self.manifest_id,
            info_hash: self.info_hash,
            index: location.leaf_index,
            leaf_count: self.leaf_count(),
            siblings,
        };
        proof.validate_shape()?;
        Ok(proof)
    }

    /// Verify a transport leaf against the pinned mapping, not an entire TCM1
    /// storage chunk. Use the assembler before putting acquired data in cache.
    pub fn verify_transport_leaf(
        &self,
        proof: &CellBep52LeafProofV2,
        bytes: &[u8],
    ) -> CellResultV1<()> {
        proof.validate_shape()?;
        require(
            proof.mapping == self.mapping_id
                && proof.manifest == self.manifest_id
                && proof.info_hash == self.info_hash
                && proof.leaf_count == self.leaf_count(),
            "BEP52 storage leaf proof pins",
        )?;
        let location = self.leaf_location(proof.index)?;
        require(
            bytes.len() == location.size as usize,
            "BEP52 storage leaf length",
        )?;
        let mut hash = Sha256::digest(bytes).into();
        let mut position = proof.index;
        for sibling in &proof.siblings {
            hash = if position & 1 == 0 {
                hash_pair(hash, *sibling)
            } else {
                hash_pair(*sibling, hash)
            };
            position >>= 1;
        }
        require(hash == self.pieces_root(), "BEP52 storage leaf root")
    }

    pub fn begin_storage_chunk(
        &self,
        index: u32,
        deadline: Instant,
    ) -> CellResultV1<CellBep52StorageAssemblerV2<'_>> {
        check_deadline(deadline)?;
        let expected = self
            .manifest
            .chunks()
            .get(index as usize)
            .ok_or(CellErrorV1::Invalid("BEP52 storage chunk index"))?;
        Ok(CellBep52StorageAssemblerV2 {
            binding: self,
            storage_index: index,
            bytes: Vec::with_capacity(expected.size as usize),
            deadline,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CellBep52LeafLocationV2 {
    pub leaf_index: u32,
    pub storage_index: u32,
    pub storage_offset: u32,
    pub payload_offset: u64,
    pub size: u32,
}

/// A borrowed, byte-verified storage chunk for bounded repeated leaf serving.
pub struct CellBep52VerifiedStorageChunkV2<'a> {
    binding: &'a CellBep52StorageBindingV2,
    storage_index: u32,
    bytes: &'a [u8],
    levels: Vec<Vec<CellDigestV1>>,
}

impl CellBep52VerifiedStorageChunkV2<'_> {
    pub fn first_leaf_index(&self) -> u32 {
        self.storage_index * (self.binding.manifest.chunk_bytes() / CELL_BEP52_LEAF_BYTES_V2)
    }

    pub fn leaf_count(&self) -> u32 {
        self.bytes.len().div_ceil(CELL_BEP52_LEAF_BYTES_V2 as usize) as u32
    }

    pub fn leaf_bytes(&self, index: u32) -> CellResultV1<&[u8]> {
        let location = self.binding.leaf_location(index)?;
        require(
            location.storage_index == self.storage_index,
            "BEP52 storage served chunk",
        )?;
        let start = location.storage_offset as usize;
        Ok(&self.bytes[start..start + location.size as usize])
    }

    pub fn leaf_proof(&self, index: u32) -> CellResultV1<CellBep52LeafProofV2> {
        let location = self.binding.leaf_location(index)?;
        require(
            location.storage_index == self.storage_index,
            "BEP52 storage served chunk",
        )?;
        self.binding.proof_from_levels(location, &self.levels)
    }
}

/// At most one existing TCM1 chunk (4 MiB). Verified leaf bytes stay private
/// until the exact ordered chunk has also passed its original TCM1 digest.
pub struct CellBep52StorageAssemblerV2<'a> {
    binding: &'a CellBep52StorageBindingV2,
    storage_index: u32,
    bytes: Vec<u8>,
    deadline: Instant,
}

impl CellBep52StorageAssemblerV2<'_> {
    pub fn received_bytes(&self) -> u32 {
        self.bytes.len() as u32
    }

    pub fn push(&mut self, proof: &CellBep52LeafProofV2, bytes: &[u8]) -> CellResultV1<()> {
        check_deadline(self.deadline)?;
        let location = self.binding.leaf_location(proof.index)?;
        require(
            location.storage_index == self.storage_index
                && location.storage_offset as usize == self.bytes.len(),
            "BEP52 storage assembly order",
        )?;
        self.binding.verify_transport_leaf(proof, bytes)?;
        check_deadline(self.deadline)?;
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }

    pub fn finish(self) -> CellResultV1<Vec<u8>> {
        self.binding.verify_storage_chunk_until(
            self.storage_index,
            &self.bytes,
            Some(self.deadline),
        )?;
        Ok(self.bytes)
    }

    /// Publish only a complete original storage chunk. Rejected/incomplete leaf
    /// sequences never write a cache row; the original deadline also covers
    /// writer contention and the cache's publication checkpoint.
    pub fn finish_into_store(self, store: &CellStoreV1) -> CellResultV1<()> {
        let expected = self.binding.manifest.chunks()[self.storage_index as usize].clone();
        let deadline = self.deadline;
        let bytes = self.finish()?;
        store.put_chunk_with_deadline(&expected, &bytes, Some(deadline))
    }
}

/// CBL2 has explicit mapping, manifest and infohash pins. The leaf index fixes
/// both Merkle orientation and the byte location; siblings are bottom-up.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CellBep52LeafProofV2 {
    mapping: CellDigestV1,
    manifest: CellDigestV1,
    info_hash: CellDigestV1,
    index: u32,
    leaf_count: u32,
    siblings: Vec<CellDigestV1>,
}

impl CellBep52LeafProofV2 {
    pub fn index(&self) -> u32 {
        self.index
    }

    pub fn leaf_count(&self) -> u32 {
        self.leaf_count
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(PROOF_HEADER_BYTES + self.siblings.len() * 32);
        out.extend_from_slice(b"CBL2");
        out.extend_from_slice(&self.mapping);
        out.extend_from_slice(&self.manifest);
        out.extend_from_slice(&self.info_hash);
        out.extend_from_slice(&self.index.to_be_bytes());
        out.extend_from_slice(&self.leaf_count.to_be_bytes());
        out.push(self.siblings.len() as u8);
        for sibling in &self.siblings {
            out.extend_from_slice(sibling);
        }
        out
    }

    pub fn decode(bytes: &[u8]) -> CellResultV1<Self> {
        require(
            (PROOF_HEADER_BYTES..=MAX_CELL_BEP52_LEAF_PROOF_BYTES_V2).contains(&bytes.len()),
            "BEP52 storage leaf proof length",
        )?;
        require(&bytes[..4] == b"CBL2", "BEP52 storage leaf proof version")?;
        let index = u32::from_be_bytes(bytes[100..104].try_into().unwrap());
        let leaf_count = u32::from_be_bytes(bytes[104..108].try_into().unwrap());
        let depth = proof_depth(leaf_count, index)?;
        require(
            bytes[108] as usize == depth && bytes.len() == PROOF_HEADER_BYTES + depth * 32,
            "BEP52 storage leaf proof depth",
        )?;
        let proof = Self {
            mapping: bytes[4..36].try_into().unwrap(),
            manifest: bytes[36..68].try_into().unwrap(),
            info_hash: bytes[68..100].try_into().unwrap(),
            index,
            leaf_count,
            siblings: bytes[PROOF_HEADER_BYTES..]
                .chunks_exact(32)
                .map(|hash| hash.try_into().unwrap())
                .collect(),
        };
        proof.validate_shape()?;
        Ok(proof)
    }

    fn validate_shape(&self) -> CellResultV1<()> {
        require(
            self.siblings.len() == proof_depth(self.leaf_count, self.index)?,
            "BEP52 storage leaf proof depth",
        )?;
        let mut padding = [0; 32];
        for (height, sibling) in self.siblings.iter().enumerate() {
            let sibling_start = ((self.index >> height) ^ 1) << height;
            if sibling_start >= self.leaf_count {
                require(*sibling == padding, "BEP52 storage leaf padding subtree")?;
            }
            padding = hash_pair(padding, padding);
        }
        Ok(())
    }
}

fn check_pins(
    manifest: &CellManifestV1,
    expected_manifest: CellDigestV1,
    expected_context: &CellContextV1,
) -> CellResultV1<()> {
    manifest.validate()?;
    require(
        manifest.id() == expected_manifest,
        "BEP52 storage manifest pin",
    )?;
    require(
        manifest.context() == expected_context,
        "BEP52 storage context pin",
    )?;
    require(
        manifest.chunks().len() <= MAX_CELL_BEP52_STORAGE_PIECES_V2,
        "BEP52 storage piece count",
    )
}

fn check_read_limits(manifest: &CellManifestV1, limits: CellReleaseLimitsV1) -> CellResultV1<()> {
    require(
        manifest.size() <= limits.max_payload_bytes
            && manifest.chunks().len() as u64 <= limits.max_chunks,
        "BEP52 storage read reservation",
    )?;
    check_deadline(limits.deadline)
}

fn check_deadline(deadline: Instant) -> CellResultV1<()> {
    require(Instant::now() <= deadline, "BEP52 storage deadline")
}

fn subtree_width(manifest: &CellManifestV1) -> usize {
    if manifest.chunks().len() == 1 {
        manifest
            .size()
            .div_ceil(u64::from(CELL_BEP52_LEAF_BYTES_V2))
            .next_power_of_two() as usize
    } else {
        (manifest.chunk_bytes() / CELL_BEP52_LEAF_BYTES_V2) as usize
    }
}

fn leaf_levels(bytes: &[u8], width: usize) -> Vec<Vec<CellDigestV1>> {
    let mut leaves: Vec<_> = bytes
        .chunks(CELL_BEP52_LEAF_BYTES_V2 as usize)
        .map(|leaf| Sha256::digest(leaf).into())
        .collect();
    leaves.resize(width, [0; 32]);
    build_levels(leaves)
}

fn build_levels(leaves: Vec<CellDigestV1>) -> Vec<Vec<CellDigestV1>> {
    let mut levels = vec![leaves];
    while levels.last().unwrap().len() > 1 {
        levels.push(
            levels
                .last()
                .unwrap()
                .chunks_exact(2)
                .map(|pair| hash_pair(pair[0], pair[1]))
                .collect(),
        );
    }
    levels
}

fn siblings_at(levels: &[Vec<CellDigestV1>], index: u32) -> Vec<CellDigestV1> {
    let mut position = index as usize;
    levels[..levels.len() - 1]
        .iter()
        .map(|level| {
            let sibling = level[position ^ 1];
            position >>= 1;
            sibling
        })
        .collect()
}

fn proof_depth(leaf_count: u32, index: u32) -> CellResultV1<usize> {
    require(
        (1..=MAX_LEAVES).contains(&leaf_count),
        "BEP52 storage leaf count",
    )?;
    require(index < leaf_count, "BEP52 storage leaf index")?;
    Ok(leaf_count.next_power_of_two().trailing_zeros() as usize)
}

fn zero_subtree(height: u32) -> CellDigestV1 {
    let mut hash = [0; 32];
    for _ in 0..height {
        hash = hash_pair(hash, hash);
    }
    hash
}

fn hash_pair(left: CellDigestV1, right: CellDigestV1) -> CellDigestV1 {
    let mut hash = Sha256::new();
    hash.update(left);
    hash.update(right);
    hash.finalize().into()
}

fn mapping_digest(bytes: &[u8]) -> CellDigestV1 {
    let mut hash = Sha256::new();
    hash.update(MAPPING_DOMAIN);
    hash.update(bytes);
    hash.finalize().into()
}

#[cfg(test)]
mod tests;
