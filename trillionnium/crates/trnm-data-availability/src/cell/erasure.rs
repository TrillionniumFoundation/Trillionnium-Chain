//! Fixed RS(6,4) erasure coding of one independently pinned TCM1 chunk.
//! This is a byte-recovery component, not authentication of providers, a
//! retention contract, a network adapter, or an execution authorization.

use sha2::{Digest, Sha256};

use super::{
    require, store::verify_chunk, CellChunkV1, CellContextV1, CellDigestV1, CellErrorV1,
    CellManifestV1, CellResultV1, MAX_CHUNK_BYTES,
};

pub const CELL_RS46_PROFILE_V1: &str = "cell-rs46-chunk-v1";
pub const CELL_RS46_DATA_SHARDS_V1: usize = 4;
pub const CELL_RS46_TOTAL_SHARDS_V1: usize = 6;
pub const MAX_CELL_RS46_SHARD_BYTES_V1: usize = MAX_CHUNK_BYTES as usize / 4;
pub const MAX_CELL_RS46_SHARD_WIRE_BYTES_V1: usize =
    SHARD_HEADER_BYTES + MAX_CELL_RS46_SHARD_BYTES_V1;

const SHARD_HEADER_BYTES: usize = 81;
const MAX_CHUNK_INDEX: u32 = 16_383;

// GF(256), polynomial x^8+x^4+x^3+x^2+1 (0x11d), low bit = x^0.
// V[i,j] = i^j in this field for i=0..5,j=0..3, with 0^0=1.
// G = V * inverse(V[0..4]); the first four rows are systematic.
const GENERATOR: [[u8; 4]; 6] = [
    [1, 0, 0, 0],
    [0, 1, 0, 0],
    [0, 0, 1, 0],
    [0, 0, 0, 1],
    [27, 28, 18, 20],
    [28, 27, 20, 18],
];

/// Exact original chunk identity derived from the release owner's TCM1 and
/// complete context pins. No erasure descriptor can replace those pins.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CellRs46ChunkBindingV1 {
    manifest: CellDigestV1,
    index: u32,
    chunk: CellChunkV1,
}

/// Borrow one immutable owner-pinned TCM1 after validating it exactly once.
/// Selecting a chunk is then constant-size work, avoiding repeated whole-
/// manifest validation/hash scans during a complete multi-chunk recovery.
#[derive(Clone, Copy, Debug)]
pub struct CellRs46ManifestBindingV1<'a> {
    manifest: &'a CellManifestV1,
    id: CellDigestV1,
}

impl<'a> CellRs46ManifestBindingV1<'a> {
    pub fn new(
        manifest: &'a CellManifestV1,
        expected_manifest: CellDigestV1,
        expected_context: &CellContextV1,
    ) -> CellResultV1<Self> {
        manifest.validate()?;
        require(manifest.context() == expected_context, "RS46 context pin")?;
        require(manifest.id() == expected_manifest, "RS46 manifest pin")?;
        Ok(Self {
            manifest,
            id: expected_manifest,
        })
    }

    pub fn manifest(&self) -> &'a CellManifestV1 {
        self.manifest
    }

    pub fn manifest_id(&self) -> CellDigestV1 {
        self.id
    }

    pub fn chunk(&self, index: u32) -> CellResultV1<CellRs46ChunkBindingV1> {
        let chunk = self
            .manifest
            .chunks()
            .get(index as usize)
            .ok_or(CellErrorV1::Invalid("RS46 chunk index"))?;
        Ok(CellRs46ChunkBindingV1 {
            manifest: self.id,
            index,
            chunk: chunk.clone(),
        })
    }
}

impl CellRs46ChunkBindingV1 {
    pub fn from_pinned_manifest(
        manifest: &CellManifestV1,
        expected_manifest: CellDigestV1,
        expected_context: &CellContextV1,
        index: u32,
    ) -> CellResultV1<Self> {
        CellRs46ManifestBindingV1::new(manifest, expected_manifest, expected_context)?.chunk(index)
    }

    pub fn manifest_id(&self) -> CellDigestV1 {
        self.manifest
    }

    pub fn chunk_index(&self) -> u32 {
        self.index
    }

    pub fn source_bytes(&self) -> u32 {
        self.chunk.size
    }

    pub fn shard_bytes(&self) -> usize {
        self.chunk.size.div_ceil(4) as usize
    }

    /// Verify original length/SHA-256 before allocating a codeword. Four data
    /// shards cover the source in order, followed by at most three zero bytes.
    pub fn encode_chunk(&self, bytes: &[u8]) -> CellResultV1<[CellRs46ShardV1; 6]> {
        verify_chunk(&self.chunk, bytes)?;
        let length = self.shard_bytes();
        let data: [Vec<u8>; 4] = std::array::from_fn(|index| {
            let mut shard = vec![0; length];
            let start = index * length;
            if start < bytes.len() {
                let count = length.min(bytes.len() - start);
                shard[..count].copy_from_slice(&bytes[start..start + count]);
            }
            shard
        });
        let inputs = std::array::from_fn(|index| data[index].as_slice());
        let parity4 = apply_row(GENERATOR[4], inputs);
        let parity5 = apply_row(GENERATOR[5], inputs);
        let [d0, d1, d2, d3] = data;
        let mut index = 0;
        Ok([d0, d1, d2, d3, parity4, parity5].map(|bytes| {
            let shard = CellRs46ShardV1 {
                manifest: self.manifest,
                chunk_index: self.index,
                source_size: self.chunk.size,
                source_sha256: self.chunk.sha256,
                index,
                bytes,
            };
            index += 1;
            shard
        }))
    }

    /// Recover from four to six distinct, ascending-index shards. Checks all
    /// supplied shards, including extras beyond the four used for decoding.
    ///
    /// Corruption is refused, not corrected by searching alternate subsets.
    /// Shard headers/digests are not authenticated provider statements. Only
    /// the final original TCM1 chunk SHA-256 and exact zero padding permit a
    /// return. Complete Cell/release verification remains a separate operation.
    pub fn recover_chunk(&self, shards: &[CellRs46ShardV1]) -> CellResultV1<Vec<u8>> {
        require(
            (4..=6).contains(&shards.len()),
            "RS46 requires four to six shards",
        )?;
        require(
            shards.windows(2).all(|pair| pair[0].index < pair[1].index),
            "RS46 shard order/duplicates",
        )?;
        for shard in shards {
            shard.validate_shape()?;
            require(
                shard.manifest == self.manifest
                    && shard.chunk_index == self.index
                    && shard.source_size == self.chunk.size
                    && shard.source_sha256 == self.chunk.sha256,
                "RS46 original chunk pin",
            )?;
        }
        let rows = std::array::from_fn(|index| GENERATOR[shards[index].index as usize]);
        let inverse = invert(rows)?;
        let inputs = std::array::from_fn(|index| shards[index].bytes.as_slice());
        let recovered: [Vec<u8>; 4] =
            std::array::from_fn(|index| apply_row(inverse[index], inputs));
        let mut bytes = Vec::with_capacity(4 * self.shard_bytes());
        for shard in &recovered {
            bytes.extend_from_slice(shard);
        }
        require(
            bytes[self.chunk.size as usize..]
                .iter()
                .all(|byte| *byte == 0),
            "RS46 zero padding",
        )?;
        bytes.truncate(self.chunk.size as usize);
        verify_chunk(&self.chunk, &bytes)?;
        let data = std::array::from_fn(|index| recovered[index].as_slice());
        for shard in shards {
            let consistent = if shard.index < 4 {
                shard.bytes == recovered[shard.index as usize]
            } else {
                shard.bytes == apply_row(GENERATOR[shard.index as usize], data)
            };
            require(consistent, "RS46 inconsistent extra shard")?;
        }
        Ok(bytes)
    }
}

/// Untrusted CRS1 shard. A successful decode establishes shape only. The
/// domain-separated ID is useful for byte addressing, not original validity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CellRs46ShardV1 {
    manifest: CellDigestV1,
    chunk_index: u32,
    source_size: u32,
    source_sha256: CellDigestV1,
    index: u8,
    bytes: Vec<u8>,
}

impl CellRs46ShardV1 {
    pub fn index(&self) -> u8 {
        self.index
    }

    pub fn payload(&self) -> &[u8] {
        &self.bytes
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(SHARD_HEADER_BYTES + self.bytes.len());
        out.extend_from_slice(b"CRS1");
        out.extend_from_slice(&self.manifest);
        out.extend_from_slice(&self.chunk_index.to_be_bytes());
        out.extend_from_slice(&self.source_size.to_be_bytes());
        out.extend_from_slice(&self.source_sha256);
        out.push(self.index);
        out.extend_from_slice(&(self.bytes.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.bytes);
        out
    }

    pub fn id(&self) -> CellDigestV1 {
        let mut hash = Sha256::new();
        hash.update(b"trnm.cell-rs46-shard.v1\0");
        hash.update(self.encode());
        hash.finalize().into()
    }

    pub fn decode(bytes: &[u8]) -> CellResultV1<Self> {
        require(
            (SHARD_HEADER_BYTES + 1..=MAX_CELL_RS46_SHARD_WIRE_BYTES_V1).contains(&bytes.len()),
            "RS46 shard wire size",
        )?;
        require(&bytes[..4] == b"CRS1", "RS46 shard version")?;
        let source_size = u32::from_be_bytes(bytes[40..44].try_into().unwrap());
        require(
            (1..=MAX_CHUNK_BYTES).contains(&source_size),
            "RS46 source size",
        )?;
        let chunk_index = u32::from_be_bytes(bytes[36..40].try_into().unwrap());
        require(
            chunk_index <= MAX_CHUNK_INDEX && bytes[76] < 6,
            "RS46 shard index",
        )?;
        let declared = u32::from_be_bytes(bytes[77..81].try_into().unwrap());
        require(
            declared == source_size.div_ceil(4)
                && bytes.len() == SHARD_HEADER_BYTES + declared as usize,
            "RS46 shard coverage",
        )?;
        Ok(Self {
            manifest: bytes[4..36].try_into().unwrap(),
            chunk_index,
            source_size,
            source_sha256: bytes[44..76].try_into().unwrap(),
            index: bytes[76],
            bytes: bytes[SHARD_HEADER_BYTES..].to_vec(),
        })
    }

    fn validate_shape(&self) -> CellResultV1<()> {
        require(
            (1..=MAX_CHUNK_BYTES).contains(&self.source_size),
            "RS46 source size",
        )?;
        require(
            self.chunk_index <= MAX_CHUNK_INDEX && self.index < 6,
            "RS46 shard index",
        )?;
        require(
            self.bytes.len() == self.source_size.div_ceil(4) as usize,
            "RS46 shard coverage",
        )
    }
}

fn apply_row(coefficients: [u8; 4], inputs: [&[u8]; 4]) -> Vec<u8> {
    // Inputs are already shape-checked against the same pinned source size.
    // Four 256-byte tables bound multiplication work and avoid a bit loop per
    // payload byte. They carry no secret signing/encryption material.
    let tables: [[u8; 256]; 4] = std::array::from_fn(|column| {
        std::array::from_fn(|value| gf_mul(coefficients[column], value as u8))
    });
    (0..inputs[0].len())
        .map(|offset| {
            (0..4).fold(0, |value, column| {
                value ^ tables[column][inputs[column][offset] as usize]
            })
        })
        .collect()
}

fn invert(matrix: [[u8; 4]; 4]) -> CellResultV1<[[u8; 4]; 4]> {
    let mut augmented: [[u8; 8]; 4] = std::array::from_fn(|row| {
        std::array::from_fn(|column| {
            if column < 4 {
                matrix[row][column]
            } else {
                u8::from(column - 4 == row)
            }
        })
    });
    for column in 0..4 {
        let pivot = (column..4)
            .find(|row| augmented[*row][column] != 0)
            .ok_or(CellErrorV1::Invalid("RS46 singular matrix"))?;
        augmented.swap(column, pivot);
        let scale = gf_pow(augmented[column][column], 254);
        for value in &mut augmented[column] {
            *value = gf_mul(*value, scale);
        }
        let normalized = augmented[column];
        for (row, values) in augmented.iter_mut().enumerate() {
            if row != column {
                let factor = values[column];
                for (value, pivot) in values.iter_mut().zip(normalized) {
                    *value ^= gf_mul(factor, pivot);
                }
            }
        }
    }
    Ok(std::array::from_fn(|row| {
        std::array::from_fn(|column| augmented[row][column + 4])
    }))
}

fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut product = 0;
    while b != 0 {
        if b & 1 != 0 {
            product ^= a;
        }
        let high_bit = a & 0x80;
        a <<= 1;
        if high_bit != 0 {
            a ^= 0x1d;
        }
        b >>= 1;
    }
    product
}

fn gf_pow(mut value: u8, mut exponent: u8) -> u8 {
    let mut result = 1;
    while exponent != 0 {
        if exponent & 1 != 0 {
            result = gf_mul(result, value);
        }
        value = gf_mul(value, value);
        exponent >>= 1;
    }
    result
}

#[cfg(test)]
mod tests;
