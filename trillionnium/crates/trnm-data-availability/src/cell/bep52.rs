//! Offline, explicitly pinned raw-payload binding to a restricted BitTorrent v2
//! descriptor. This adds no discovery, network access, cache write or authority.
//! TCM1, its context, and complete-payload verification remain authoritative.

use sha2::{Digest, Sha256};

use super::{
    digest_hex, parse_digest, require, store::verify_chunk, CellContextV1, CellDigestV1,
    CellManifestV1, CellResultV1,
};

pub const CELL_BEP52_PROFILE_V1: &str = "cell-bep52-binding-v1";
pub const CELL_BEP52_PIECE_BYTES_V1: u32 = 16_384;
pub const MAX_CELL_BEP52_LEAVES_V1: usize = 16_384;
pub const MAX_CELL_BEP52_INFO_BYTES_V1: usize = 256;
pub const MAX_CELL_BEP52_METAINFO_BYTES_V1: usize = 1024 + MAX_CELL_BEP52_LEAVES_V1 * 32;
pub const MAX_CELL_BEP52_PROOF_BYTES_V1: usize = PROOF_HEADER_BYTES + 14 * 32;

const PROOF_HEADER_BYTES: usize = 77;
const MAGNET_PREFIX: &str = "magnet:?xt=urn:btmh:1220";

/// Syntax-checked location hint, never a Cell pin or an authorization.
///
/// This deliberately narrow BEP 9 v2 profile accepts only one SHA2-256 exact
/// topic with canonical lowercase hex. It accepts no tracker/peer addresses,
/// percent encoding, display names, fragments, alternate codecs or SHA-1.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CellBep52MagnetV1 {
    info_hash: CellDigestV1,
}

impl CellBep52MagnetV1 {
    pub fn parse(uri: &str) -> CellResultV1<Self> {
        require(
            uri.len() == MAGNET_PREFIX.len() + 64 && uri.starts_with(MAGNET_PREFIX),
            "BEP52 magnet profile",
        )?;
        Ok(Self {
            info_hash: parse_digest(&uri[MAGNET_PREFIX.len()..])?,
        })
    }

    pub fn info_hash(&self) -> CellDigestV1 {
        self.info_hash
    }

    pub fn encode(&self) -> String {
        format!("{MAGNET_PREFIX}{}", digest_hex(self.info_hash))
    }
}

/// A derived mapping from the owner's exact TCM1/context pins to one canonical
/// BEP 52 single-file descriptor for the raw payload, named `cell.bin`.
///
/// Only nonempty TCM1 objects with 16 KiB chunks are supported. A larger TCM1
/// chunk's SHA-256 is not a BEP 52 subtree root and is never reinterpreted as one.
/// Construction checks declarations, not the existence of any payload bytes.
/// Same payload bytes in different Cell contexts can share an infohash; only
/// the independent owner pins establish which context is authorized.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CellBep52BindingV1 {
    manifest: CellManifestV1,
    manifest_id: CellDigestV1,
    // At most 2 * 16,384 - 1 digests. Padding leaves are zero digests, not
    // SHA-256(empty) and not SHA-256(a zero-filled 16 KiB block).
    levels: Vec<Vec<CellDigestV1>>,
    info_hash: CellDigestV1,
}

impl CellBep52BindingV1 {
    /// The expected pins must come from the existing release owner, not a peer
    /// advertisement, magnet, or untrusted manifest supplied by the same peer.
    pub fn from_pinned_manifest(
        manifest: &CellManifestV1,
        expected_manifest: CellDigestV1,
        expected_context: &CellContextV1,
    ) -> CellResultV1<Self> {
        manifest.validate()?;
        require(manifest.context() == expected_context, "BEP52 context pin")?;
        require(manifest.id() == expected_manifest, "BEP52 manifest pin")?;
        require(
            manifest.chunk_bytes() == CELL_BEP52_PIECE_BYTES_V1,
            "BEP52 requires 16 KiB TCM1 chunks",
        )?;
        require(
            (1..=MAX_CELL_BEP52_LEAVES_V1).contains(&manifest.chunks().len()),
            "BEP52 leaf count",
        )?;

        let mut leaves: Vec<_> = manifest.chunks().iter().map(|c| c.sha256).collect();
        leaves.resize(leaves.len().next_power_of_two(), [0; 32]);
        let mut levels = vec![leaves];
        while levels.last().unwrap().len() > 1 {
            let parent = levels
                .last()
                .unwrap()
                .chunks_exact(2)
                .map(|pair| hash_pair(pair[0], pair[1]))
                .collect();
            levels.push(parent);
        }
        let mut binding = Self {
            manifest: manifest.clone(),
            manifest_id: expected_manifest,
            levels,
            info_hash: [0; 32],
        };
        binding.info_hash = Sha256::digest(binding.info_bytes()).into();
        Ok(binding)
    }

    pub fn manifest(&self) -> &CellManifestV1 {
        &self.manifest
    }

    pub fn manifest_id(&self) -> CellDigestV1 {
        self.manifest_id
    }

    pub fn pieces_root(&self) -> CellDigestV1 {
        self.levels.last().unwrap()[0]
    }

    pub fn info_hash(&self) -> CellDigestV1 {
        self.info_hash
    }

    /// Exact canonical bencoding, whose SHA-256 is the full v2 infohash.
    /// The display name is fixed data, not a filesystem output path.
    pub fn info_bytes(&self) -> Vec<u8> {
        let mut out = b"d9:file treed8:cell.bind0:d6:lengthi".to_vec();
        out.extend_from_slice(self.manifest.size().to_string().as_bytes());
        out.extend_from_slice(b"e11:pieces root32:");
        out.extend_from_slice(&self.pieces_root());
        out.extend_from_slice(b"eee12:meta versioni2e4:name8:cell.bin12:piece lengthi16384ee");
        out
    }

    /// Canonical metainfo includes the piece-layers dictionary even when empty.
    /// Only actual leaves appear; tree-balancing padding leaves are omitted.
    pub fn metainfo_bytes(&self) -> Vec<u8> {
        let mut out = b"d4:info".to_vec();
        out.extend_from_slice(&self.info_bytes());
        out.extend_from_slice(b"12:piece layersd");
        if self.manifest.chunks().len() > 1 {
            out.extend_from_slice(b"32:");
            out.extend_from_slice(&self.pieces_root());
            out.extend_from_slice((self.manifest.chunks().len() * 32).to_string().as_bytes());
            out.push(b':');
            for chunk in self.manifest.chunks() {
                out.extend_from_slice(&chunk.sha256);
            }
        }
        out.extend_from_slice(b"ee");
        out
    }

    pub fn magnet(&self) -> CellBep52MagnetV1 {
        CellBep52MagnetV1 {
            info_hash: self.info_hash,
        }
    }

    pub fn verify_magnet(&self, uri: &str) -> CellResultV1<()> {
        require(
            CellBep52MagnetV1::parse(uri)?.info_hash == self.info_hash,
            "BEP52 infohash pin",
        )
    }

    /// Require exact profile bytes; never hash a lossy decode/re-encode of
    /// attacker-controlled bencoding. This is not a general torrent parser.
    pub fn verify_info_bytes(&self, bytes: &[u8]) -> CellResultV1<()> {
        require(
            bytes.len() <= MAX_CELL_BEP52_INFO_BYTES_V1,
            "BEP52 info size",
        )?;
        require(
            bytes == self.info_bytes().as_slice(),
            "BEP52 canonical info binding",
        )
    }

    /// Checking only the infohash would leave piece layers outside the check.
    /// Exact comparison here also rejects missing/reordered/extra layer hashes.
    pub fn verify_metainfo_bytes(&self, bytes: &[u8]) -> CellResultV1<()> {
        require(
            bytes.len() <= MAX_CELL_BEP52_METAINFO_BYTES_V1,
            "BEP52 metainfo size",
        )?;
        require(
            bytes == self.metainfo_bytes().as_slice(),
            "BEP52 canonical metainfo binding",
        )
    }

    /// Produce a bounded Cell companion proof. Its CBP1 encoding is not the
    /// BitTorrent `hashes` peer message, which needs a separate wire adapter.
    pub fn chunk_proof(&self, index: u32) -> CellResultV1<CellBep52ChunkProofV1> {
        require(
            index < self.manifest.chunks().len() as u32,
            "BEP52 chunk index",
        )?;
        let mut position = index as usize;
        let siblings = self.levels[..self.levels.len() - 1]
            .iter()
            .map(|level| {
                let sibling = level[position ^ 1];
                position >>= 1;
                sibling
            })
            .collect();
        Ok(CellBep52ChunkProofV1 {
            manifest: self.manifest_id,
            info_hash: self.info_hash,
            index,
            leaf_count: self.manifest.chunks().len() as u32,
            siblings,
        })
    }

    /// Check exact internal/external pins, proof shape, original TCM1 chunk
    /// length/hash and the BEP 52 root. Does not write to the cache or establish
    /// complete payload SHA-256, release closure, availability, or FinalUse.
    pub fn verify_chunk(&self, proof: &CellBep52ChunkProofV1, bytes: &[u8]) -> CellResultV1<()> {
        proof.validate_shape()?;
        require(
            proof.manifest == self.manifest_id && proof.info_hash == self.info_hash,
            "BEP52 proof pins",
        )?;
        require(
            proof.leaf_count as usize == self.manifest.chunks().len(),
            "BEP52 proof coverage",
        )?;
        let chunk = &self.manifest.chunks()[proof.index as usize];
        verify_chunk(chunk, bytes)?;
        let mut hash = chunk.sha256;
        let mut position = proof.index;
        for sibling in &proof.siblings {
            hash = if position & 1 == 0 {
                hash_pair(hash, *sibling)
            } else {
                hash_pair(*sibling, hash)
            };
            position >>= 1;
        }
        require(hash == self.pieces_root(), "BEP52 chunk root")
    }
}

/// Unverified CBP1 companion proof, bound to both TCM1 and external infohash.
/// Siblings are bottom-up, with orientation derived solely from the index.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CellBep52ChunkProofV1 {
    manifest: CellDigestV1,
    info_hash: CellDigestV1,
    index: u32,
    leaf_count: u32,
    siblings: Vec<CellDigestV1>,
}

impl CellBep52ChunkProofV1 {
    pub fn index(&self) -> u32 {
        self.index
    }

    pub fn leaf_count(&self) -> u32 {
        self.leaf_count
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(PROOF_HEADER_BYTES + self.siblings.len() * 32);
        out.extend_from_slice(b"CBP1");
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
            (PROOF_HEADER_BYTES..=MAX_CELL_BEP52_PROOF_BYTES_V1).contains(&bytes.len()),
            "BEP52 proof size",
        )?;
        require(&bytes[..4] == b"CBP1", "BEP52 proof version")?;
        let leaf_count = u32::from_be_bytes(bytes[72..76].try_into().unwrap());
        let index = u32::from_be_bytes(bytes[68..72].try_into().unwrap());
        let depth = proof_depth(leaf_count, index)?;
        require(
            bytes[76] as usize == depth && bytes.len() == PROOF_HEADER_BYTES + depth * 32,
            "BEP52 proof depth",
        )?;
        let proof = Self {
            manifest: bytes[4..36].try_into().unwrap(),
            info_hash: bytes[36..68].try_into().unwrap(),
            index,
            leaf_count,
            siblings: bytes[PROOF_HEADER_BYTES..]
                .chunks_exact(32)
                .map(|chunk| chunk.try_into().unwrap())
                .collect(),
        };
        proof.validate_shape()?;
        Ok(proof)
    }

    fn validate_shape(&self) -> CellResultV1<()> {
        require(
            self.siblings.len() == proof_depth(self.leaf_count, self.index)?,
            "BEP52 proof depth",
        )?;
        let mut zero_subtree = [0; 32];
        for (height, sibling) in self.siblings.iter().enumerate() {
            let sibling_start = ((self.index >> height) ^ 1) << height;
            if sibling_start >= self.leaf_count {
                require(*sibling == zero_subtree, "BEP52 padding subtree")?;
            }
            zero_subtree = hash_pair(zero_subtree, zero_subtree);
        }
        Ok(())
    }
}

fn proof_depth(leaf_count: u32, index: u32) -> CellResultV1<usize> {
    require(
        (1..=MAX_CELL_BEP52_LEAVES_V1 as u32).contains(&leaf_count),
        "BEP52 leaf count",
    )?;
    require(index < leaf_count, "BEP52 chunk index")?;
    Ok(leaf_count.next_power_of_two().trailing_zeros() as usize)
}

fn hash_pair(left: CellDigestV1, right: CellDigestV1) -> CellDigestV1 {
    let mut hash = Sha256::new();
    hash.update(left);
    hash.update(right);
    hash.finalize().into()
}

#[cfg(test)]
mod tests;
