//! Allocation-free preflight for the exact bincode-1.3 / RISC Zero-3.0.6 shape.
//!
//! This is a resource gate, never a proof check. Generic deserialization is
//! allowed only after every variable-length field has been checked here. The
//! allowlist excludes nested assumption receipts, unknown kinds and arbitrary
//! journals. Refusal means this research service did not evaluate the proof;
//! it is not a consensus-invalid verdict. No fallback executes native W1.
use std::fmt;

pub const MAX_RECEIPT_BYTES: usize = 128 * 1024 * 1024;
pub const MAX_SEGMENTS: usize = 2048;
pub const MAX_SEAL_WORDS: usize = 256 * 1024;
pub const JOURNAL_BYTES: usize = 4 + 7 * 32;
pub const MAX_PADDED_CYCLES: u64 = 256 * 1024 * 1024;
const OUTPUT_WORDS: usize = 90; // risc0-circuit-rv32im 4.0.5 CircuitInfo.
const MIN_SEAL_WORDS: usize = 1 + OUTPUT_WORDS + 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BoundaryError {
    Refused(&'static str),
    Malformed(&'static str),
}

impl fmt::Display for BoundaryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Refused(reason) => write!(f, "Refused (not evaluated): {reason}"),
            Self::Malformed(reason) => write!(f, "Malformed certificate encoding: {reason}"),
        }
    }
}
impl std::error::Error for BoundaryError {}

type Result<T> = std::result::Result<T, BoundaryError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BoundedShape {
    pub segments: usize,
    pub padded_cycles: u64,
    pub maximum_po2: u32,
}

struct Cursor<'a> {
    remaining: &'a [u8],
}

impl<'a> Cursor<'a> {
    fn take(&mut self, bytes: usize) -> Result<&'a [u8]> {
        if bytes > self.remaining.len() {
            return Err(BoundaryError::Malformed("truncated field"));
        }
        let (value, remaining) = self.remaining.split_at(bytes);
        self.remaining = remaining;
        Ok(value)
    }
    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn length(&mut self, cap: usize, label: &'static str) -> Result<usize> {
        let length = self.u64()?;
        if length > cap as u64 {
            return Err(BoundaryError::Refused(label));
        }
        Ok(length as usize)
    }
    fn state(&mut self) -> Result<()> {
        match self.u32()? {
            0 => self.take(4 + 32)?, // MaybePruned::Value(SystemState).
            1 => self.take(32)?,     // MaybePruned::Pruned(Digest).
            _ => return Err(BoundaryError::Malformed("unknown state variant")),
        };
        Ok(())
    }
    fn input(&mut self) -> Result<()> {
        match self.u32()? {
            0 if self.take(1)? == [0] => Ok(()), // Value(None).
            0 => Err(BoundaryError::Refused("unsupported claim input")),
            1 => self.take(32).map(|_| ()),
            _ => Err(BoundaryError::Malformed("unknown input variant")),
        }
    }
    fn journal(&mut self) -> Result<()> {
        let length = self.length(JOURNAL_BYTES, "journal byte budget")?;
        if length != JOURNAL_BYTES {
            return Err(BoundaryError::Refused("journal is not the fixed PWJ1 size"));
        }
        self.take(length)?;
        Ok(())
    }
    fn output(&mut self) -> Result<()> {
        match self.u32()? {
            1 => {
                self.take(32)?;
                return Ok(());
            }
            0 => {}
            _ => return Err(BoundaryError::Malformed("unknown output variant")),
        }
        match self.take(1)? {
            [0] => return Ok(()),
            [1] => {}
            _ => return Err(BoundaryError::Malformed("invalid output option")),
        }
        match self.u32()? {
            0 => self.journal()?,
            1 => {
                self.take(32)?;
            }
            _ => return Err(BoundaryError::Malformed("unknown journal variant")),
        }
        match self.u32()? {
            0 => {
                self.length(0, "nonempty claim assumptions are unsupported")?;
            }
            1 => {
                if self.take(32)? != [0u8; 32] {
                    return Err(BoundaryError::Refused("unresolved claim assumptions"));
                }
            }
            _ => return Err(BoundaryError::Malformed("unknown assumptions variant")),
        }
        Ok(())
    }
    fn claim(&mut self) -> Result<()> {
        self.state()?;
        self.state()?;
        match self.u32()? {
            0 | 1 => {
                self.u32()?;
            }
            2 | 3 => {}
            _ => return Err(BoundaryError::Malformed("unknown exit-code variant")),
        }
        self.input()?;
        self.output()
    }
}

fn seal_shape(word_count: usize, version: u32, po2: u32) -> Result<u64> {
    if word_count < MIN_SEAL_WORDS {
        return Err(BoundaryError::Malformed("empty or incomplete seal header"));
    }
    if word_count > MAX_SEAL_WORDS {
        return Err(BoundaryError::Refused("segment seal word budget"));
    }
    if version != 2 {
        return Err(BoundaryError::Refused("unsupported RV32IM seal version"));
    }
    if !(13..=20).contains(&po2) {
        return Err(BoundaryError::Refused("segment proof dimension budget"));
    }
    Ok(1u64 << po2)
}

pub fn check_seal(words: &[u32]) -> Result<u64> {
    if words.len() < MIN_SEAL_WORDS {
        return Err(BoundaryError::Malformed("empty or incomplete seal header"));
    }
    seal_shape(words.len(), words[0], words[1 + OUTPUT_WORDS])
}

pub fn check_padded_cycles(total: u64) -> Result<()> {
    if total > MAX_PADDED_CYCLES {
        return Err(BoundaryError::Refused("total padded proof-cycle budget"));
    }
    Ok(())
}

/// Parse all lengths and supported variants without allocating any Vec/String.
/// Success says only that subsequent SDK deserialization has bounded shapes.
pub fn preflight(bytes: &[u8]) -> Result<BoundedShape> {
    if bytes.len() > MAX_RECEIPT_BYTES {
        return Err(BoundaryError::Refused("total certificate byte budget"));
    }
    let mut cursor = Cursor { remaining: bytes };
    if cursor.u32()? != 0 {
        return Err(BoundaryError::Refused(
            "only Composite receipts are supported",
        ));
    }
    let segments = cursor.length(MAX_SEGMENTS, "segment count budget")?;
    if segments == 0 {
        return Err(BoundaryError::Malformed("empty segment list"));
    }
    let mut padded_cycles = 0u64;
    let mut maximum_po2 = 0;
    for index in 0..segments {
        let words = cursor.length(MAX_SEAL_WORDS, "segment seal word budget")?;
        if words < MIN_SEAL_WORDS {
            return Err(BoundaryError::Malformed("empty or incomplete seal header"));
        }
        let seal = cursor.take(words * 4)?; // Multiplication follows the 2^18 bound.
        let version = u32::from_le_bytes(seal[..4].try_into().unwrap());
        let offset = 4 * (1 + OUTPUT_WORDS);
        let po2 = u32::from_le_bytes(seal[offset..offset + 4].try_into().unwrap());
        padded_cycles += seal_shape(words, version, po2)?;
        check_padded_cycles(padded_cycles)?;
        maximum_po2 = maximum_po2.max(po2);
        if cursor.u32()? as usize != index {
            return Err(BoundaryError::Malformed("noncanonical segment index"));
        }
        let hash_name_bytes = cursor.length(9, "hash-name string budget")?;
        if cursor.take(hash_name_bytes)? != b"poseidon2" {
            return Err(BoundaryError::Refused("unsupported commitment hash"));
        }
        cursor.take(32)?; // Segment verifier-parameter digest, checked by verifier.
        cursor.claim()?;
    }
    cursor.length(0, "nested assumption receipts are unsupported")?;
    cursor.take(32)?; // Composite verifier parameters.
    cursor.journal()?;
    cursor.take(32)?; // Receipt metadata: verifier-parameter digest only.
    if !cursor.remaining.is_empty() {
        return Err(BoundaryError::Malformed("trailing certificate bytes"));
    }
    Ok(BoundedShape {
        segments,
        padded_cycles,
        maximum_po2,
    })
}

#[cfg(test)]
#[path = "receipt_bounds_tests.rs"]
mod tests;
