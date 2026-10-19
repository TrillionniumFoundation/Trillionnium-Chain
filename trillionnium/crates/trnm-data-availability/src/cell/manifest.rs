use std::io::{Cursor, Read};

use sha2::{Digest, Sha256};

use super::{require, CellDigestV1, CellErrorV1, CellResultV1};

pub const MAX_CHUNK_BYTES: u32 = 4 * 1024 * 1024;
pub const MAX_CELL_BYTES: u64 = 64 * 1024 * 1024 * 1024;
pub(crate) const MAX_MANIFEST_BYTES: usize = 1024 * 1024;
const MAX_CHUNKS: usize = 16_384;

/// Hashes bind exact external model dependencies and layout, never their quality.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CellContextV1 {
    pub family: String,
    pub base: CellDigestV1,
    pub parent: CellDigestV1,
    pub tokenizer: CellDigestV1,
    pub layout: CellDigestV1,
    pub runtime: CellDigestV1,
}

impl CellContextV1 {
    pub fn validate(&self) -> CellResultV1<()> {
        require(
            !self.family.is_empty()
                && self.family.len() <= 64
                && self
                    .family
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)),
            "model family",
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CellChunkV1 {
    pub size: u32,
    pub sha256: CellDigestV1,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CellManifestV1 {
    context: CellContextV1,
    size: u64,
    payload_sha256: CellDigestV1,
    chunk_bytes: u32,
    chunks: Vec<CellChunkV1>,
}

impl CellManifestV1 {
    pub(crate) fn new(
        context: CellContextV1,
        size: u64,
        payload_sha256: CellDigestV1,
        chunk_bytes: u32,
        chunks: Vec<CellChunkV1>,
    ) -> CellResultV1<Self> {
        let value = Self {
            context,
            size,
            payload_sha256,
            chunk_bytes,
            chunks,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn context(&self) -> &CellContextV1 {
        &self.context
    }
    pub fn size(&self) -> u64 {
        self.size
    }
    pub fn payload_sha256(&self) -> CellDigestV1 {
        self.payload_sha256
    }
    pub fn chunks(&self) -> &[CellChunkV1] {
        &self.chunks
    }

    pub fn validate(&self) -> CellResultV1<()> {
        self.context.validate()?;
        require(
            (16_384..=MAX_CHUNK_BYTES).contains(&self.chunk_bytes)
                && self.chunk_bytes.is_power_of_two(),
            "chunk size",
        )?;
        require(self.size > 0 && self.size <= MAX_CELL_BYTES, "cell size")?;
        require(
            !self.chunks.is_empty() && self.chunks.len() <= MAX_CHUNKS,
            "chunk count",
        )?;
        let expected = self.size.div_ceil(u64::from(self.chunk_bytes));
        require(expected == self.chunks.len() as u64, "chunk coverage")?;
        for (index, chunk) in self.chunks.iter().enumerate() {
            let offset = index as u64 * u64::from(self.chunk_bytes);
            let size = (self.size - offset).min(u64::from(self.chunk_bytes));
            require(u64::from(chunk.size) == size, "chunk length")?;
        }
        Ok(())
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(224 + self.chunks.len() * 36);
        out.extend_from_slice(b"TCM1");
        out.push(self.context.family.len() as u8);
        out.extend_from_slice(self.context.family.as_bytes());
        for value in [
            self.context.base,
            self.context.parent,
            self.context.tokenizer,
            self.context.layout,
            self.context.runtime,
        ] {
            out.extend_from_slice(&value);
        }
        out.extend_from_slice(&self.size.to_be_bytes());
        out.extend_from_slice(&self.payload_sha256);
        out.extend_from_slice(&self.chunk_bytes.to_be_bytes());
        out.extend_from_slice(&(self.chunks.len() as u32).to_be_bytes());
        for chunk in &self.chunks {
            out.extend_from_slice(&chunk.size.to_be_bytes());
            out.extend_from_slice(&chunk.sha256);
        }
        out
    }

    pub fn id(&self) -> CellDigestV1 {
        let mut hash = Sha256::new();
        hash.update(b"trnm.cell-manifest.v1\0");
        hash.update(self.encode());
        hash.finalize().into()
    }

    pub fn decode(bytes: &[u8]) -> CellResultV1<Self> {
        require(bytes.len() <= MAX_MANIFEST_BYTES, "manifest length")?;
        let mut input = Cursor::new(bytes);
        require(read_array::<4>(&mut input)? == *b"TCM1", "manifest version")?;
        let family_len = usize::from(read_array::<1>(&mut input)?[0]);
        require((1..=64).contains(&family_len), "family length")?;
        let mut family = vec![0; family_len];
        input.read_exact(&mut family)?;
        let context = CellContextV1 {
            family: String::from_utf8(family)
                .map_err(|_| CellErrorV1::Invalid("family encoding"))?,
            base: read_array(&mut input)?,
            parent: read_array(&mut input)?,
            tokenizer: read_array(&mut input)?,
            layout: read_array(&mut input)?,
            runtime: read_array(&mut input)?,
        };
        let size = u64::from_be_bytes(read_array(&mut input)?);
        let payload_sha256 = read_array(&mut input)?;
        let chunk_bytes = u32::from_be_bytes(read_array(&mut input)?);
        let count = u32::from_be_bytes(read_array(&mut input)?) as usize;
        require((1..=MAX_CHUNKS).contains(&count), "chunk count")?;
        require(
            bytes.len() as u64 - input.position() == count as u64 * 36,
            "manifest coverage",
        )?;
        let mut chunks = Vec::with_capacity(count);
        for _ in 0..count {
            chunks.push(CellChunkV1 {
                size: u32::from_be_bytes(read_array(&mut input)?),
                sha256: read_array(&mut input)?,
            });
        }
        Self::new(context, size, payload_sha256, chunk_bytes, chunks)
    }
}

fn read_array<const N: usize>(input: &mut Cursor<&[u8]>) -> CellResultV1<[u8; N]> {
    let mut value = [0; N];
    input.read_exact(&mut value)?;
    Ok(value)
}
