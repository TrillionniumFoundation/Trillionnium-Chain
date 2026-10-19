//! Content-addressed cell bytes, independent of transaction DA and consensus.
//!
//! A caller pins a manifest ID from its existing release authority. Transport
//! checks bytes only; it cannot approve a model, select CURRENT or grant use.

use std::{fmt, io};

mod manifest;
mod network;
mod store;

pub use manifest::{CellChunkV1, CellContextV1, CellManifestV1, MAX_CELL_BYTES, MAX_CHUNK_BYTES};
pub use network::{fetch_cell, serve_cells, CellFetchReportV1, CellPeerLimitsV1};
pub use store::CellStoreV1;

pub type CellDigestV1 = [u8; 32];
pub type CellResultV1<T> = Result<T, CellErrorV1>;

#[derive(Debug)]
pub enum CellErrorV1 {
    Invalid(&'static str),
    Io(io::Error),
    Sql(rusqlite::Error),
    Unavailable,
}

impl fmt::Display for CellErrorV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(reason) => write!(f, "cell: {reason}"),
            Self::Io(error) => write!(f, "cell I/O: {error}"),
            Self::Sql(error) => write!(f, "cell storage: {error}"),
            Self::Unavailable => f.write_str("cell: no configured peer supplied the pinned bytes"),
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
