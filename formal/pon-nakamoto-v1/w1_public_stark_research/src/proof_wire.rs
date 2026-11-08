//! Allocation-free admission of the frozen P3 0.8.0 / bincode 1.3.3 wire shape.
//!
//! The caller chooses the component; no unchecked input length selects a loop bound.
//! This is a structural admission check, never a proof verifier. All admitted
//! bytes still pass the canonical P3 decoder and the original PCS verifier.
//! Pruned Merkle paths have transcript-dependent lengths. We admit at most
//! 64 complete binary authentication paths and leave exact frontier checking
//! to P3. This bounds syntax, not wall time, total process memory or security.

use crate::arith_air::{DOT8_PREPROCESSED_WIDTH, DOT8_WIDTH};
use crate::arith_carry_air::{CARRY_PREPROCESSED_WIDTH, CARRY_WIDTH};
use crate::proof_config::{GOLDILOCKS_ORDER, LOG_BLOWUP, NUM_QUERIES};
use crate::sha_air::PREPROCESSED_WIDTH;
use crate::sha_schedule_air::{SCHEDULE_PREPROCESSED_WIDTH, SCHEDULE_SHA_WIDTH};
use p3_sha256_air::NUM_SHA256_COLS;

pub const SHA_MAGIC: &[u8; 8] = b"W1P3SHA1";
pub const ARITH_MAGIC: &[u8; 8] = b"W1P3ARI1";
pub const CARRY_MAGIC: &[u8; 8] = b"W1P3ACR2";
pub const PACKED_CARRY_MAGIC: &[u8; 8] = b"W1P3APC3";
pub const SCHEDULE_SHA_MAGIC: &[u8; 8] = b"W1P3SCS4";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Component {
    Sha,
    Arithmetic,
    Carry,
    PackedCarry,
    ScheduledSha,
}

impl Component {
    pub const fn magic(self) -> &'static [u8; 8] {
        match self {
            Self::Sha => SHA_MAGIC,
            Self::Arithmetic => ARITH_MAGIC,
            Self::Carry => CARRY_MAGIC,
            Self::PackedCarry => PACKED_CARRY_MAGIC,
            Self::ScheduledSha => SCHEDULE_SHA_MAGIC,
        }
    }

    pub const fn degree_bits(self) -> usize {
        match self {
            Self::Sha | Self::ScheduledSha => 13,
            Self::Arithmetic | Self::Carry => 17,
            Self::PackedCarry => 14,
        }
    }

    const fn width(self) -> usize {
        match self {
            Self::Sha => NUM_SHA256_COLS,
            Self::Arithmetic => DOT8_WIDTH,
            Self::Carry => CARRY_WIDTH,
            Self::PackedCarry => 5 * CARRY_WIDTH,
            Self::ScheduledSha => SCHEDULE_SHA_WIDTH,
        }
    }

    const fn preprocessed_width(self) -> usize {
        match self {
            Self::Sha => PREPROCESSED_WIDTH,
            Self::Arithmetic => DOT8_PREPROCESSED_WIDTH,
            Self::Carry => CARRY_PREPROCESSED_WIDTH,
            Self::PackedCarry => 5 * CARRY_PREPROCESSED_WIDTH,
            Self::ScheduledSha => SCHEDULE_PREPROCESSED_WIDTH,
        }
    }

    const fn quotient_chunks(self) -> usize {
        match self {
            Self::Sha | Self::ScheduledSha => 2,
            Self::Arithmetic | Self::Carry | Self::PackedCarry => 1,
        }
    }

    const fn reads_next(self) -> bool {
        matches!(self, Self::Sha | Self::ScheduledSha)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WireLimits {
    pub minimum_bytes: usize,
    pub maximum_bytes: usize,
    pub maximum_field_elements: usize,
    pub vector_headers: usize,
    pub maximum_merkle_siblings: usize,
}

/// A closed count of the frozen encoding. Extension elements are two base
/// elements, digest elements are four; each vector header is one fixed u64.
pub const fn limits(component: Component) -> WireLimits {
    let rounds = component.degree_bits();
    let width = component.width();
    let pre = component.preprocessed_width();
    let chunks = component.quotient_chunks();
    let next = if component.reads_next() { 1 } else { 0 };
    // trace + quotient commitments, each a one-digest cap.
    let mut fields = 8;
    let mut vectors = 2;
    // OOD openings: trace local/optional next, preprocessed local, quotient.
    fields += 2 * (width * (1 + next) + pre + 2 * chunks);
    vectors += 1 + next + 1 + 1 + chunks;
    // Batch PoW, round commitments and round PoW witnesses.
    fields += 1 + 4 * rounds + rounds;
    vectors += 2 + rounds;
    // Three input batches: trace, quotient chunks, preprocessed.
    fields += NUM_QUERIES * (width + 2 * chunks + pre);
    vectors += 1 + 3 * (2 + NUM_QUERIES) + NUM_QUERIES * (2 + chunks);
    let input_siblings = 3 * NUM_QUERIES * (rounds + LOG_BLOWUP);
    // Binary FRI: 64 one-element extension siblings per round, one path list.
    fields += rounds * NUM_QUERIES * 2;
    vectors += 1 + rounds * (2 + NUM_QUERIES);
    let fold_siblings =
        NUM_QUERIES * (rounds * (rounds + LOG_BLOWUP - 1) - rounds * (rounds - 1) / 2);
    // Final extension polynomial, query PoW, and OOD PoW witness.
    fields += 2 + 1 + 1;
    vectors += 1;
    let siblings = input_siblings + fold_siblings;
    // Magic + five Option tags + degree_bits. Tags: random commitment;
    // trace next; preprocessed local/next; random opened values. Five in all.
    let overhead = 8 + 5 + 8;
    let minimum = overhead + vectors * 8 + fields * 8;
    WireLimits {
        minimum_bytes: minimum,
        maximum_bytes: minimum + siblings * 32,
        maximum_field_elements: fields + siblings * 4,
        vector_headers: vectors,
        maximum_merkle_siblings: siblings,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WireScan {
    pub bytes: usize,
    pub field_elements: usize,
    pub vector_headers: usize,
    pub merkle_siblings: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WireError {
    pub offset: usize,
    pub reason: &'static str,
}

impl core::fmt::Display for WireError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "wire admission at {}: {}", self.offset, self.reason)
    }
}

impl std::error::Error for WireError {}

struct Cursor<'a> {
    bytes: &'a [u8],
    at: usize,
    fields: usize,
    vectors: usize,
    siblings: usize,
}

impl Cursor<'_> {
    fn error(&self, reason: &'static str) -> WireError {
        WireError {
            offset: self.at,
            reason,
        }
    }

    fn u64(&mut self) -> Result<u64, WireError> {
        let end = self
            .at
            .checked_add(8)
            .ok_or_else(|| self.error("offset overflow"))?;
        let value = self
            .bytes
            .get(self.at..end)
            .ok_or_else(|| self.error("truncated u64"))?;
        self.at = end;
        Ok(u64::from_le_bytes(
            value.try_into().expect("eight checked bytes"),
        ))
    }

    fn tag(&mut self, expected: u8) -> Result<(), WireError> {
        let value = *self
            .bytes
            .get(self.at)
            .ok_or_else(|| self.error("truncated option"))?;
        if value != expected {
            return Err(self.error("unexpected option tag"));
        }
        self.at += 1;
        Ok(())
    }

    fn length(&mut self, expected: usize) -> Result<(), WireError> {
        let n = self.u64()?;
        self.vectors += 1;
        if n != expected as u64 {
            return Err(self.error("fixed vector length"));
        }
        Ok(())
    }

    fn fields(&mut self, count: usize) -> Result<(), WireError> {
        for _ in 0..count {
            if self.u64()? >= GOLDILOCKS_ORDER {
                return Err(self.error("noncanonical Goldilocks element"));
            }
            self.fields += 1;
        }
        Ok(())
    }

    fn row(&mut self, count: usize, extension: bool) -> Result<(), WireError> {
        self.length(count)?;
        self.fields(count * if extension { 2 } else { 1 })
    }

    fn cap(&mut self) -> Result<(), WireError> {
        self.length(1)?;
        self.fields(4)
    }

    fn path(&mut self, log_height: usize) -> Result<(), WireError> {
        let n = self.u64()?;
        self.vectors += 1;
        let maximum = NUM_QUERIES * log_height;
        if n > maximum as u64 {
            return Err(self.error("Merkle frontier exceeds full-path bound"));
        }
        // Conversion and multiplication follow the checked constant upper bound.
        self.siblings += n as usize;
        self.fields(n as usize * 4)
    }
}

/// Scan all fields without allocating, hashing, reconstructing an AIR, or
/// choosing a loop bound from an unchecked value. Success admits decoding;
/// it does not authenticate the statement, commitments, paths or algebra.
pub fn scan_proof(bytes: &[u8], component: Component) -> Result<WireScan, WireError> {
    let bound = limits(component);
    if bytes.len() < bound.minimum_bytes || bytes.len() > bound.maximum_bytes {
        return Err(WireError {
            offset: 0,
            reason: "component envelope length",
        });
    }
    if !bytes.starts_with(component.magic()) {
        return Err(WireError {
            offset: 0,
            reason: "component envelope magic",
        });
    }
    let mut c = Cursor {
        bytes,
        at: 8,
        fields: 0,
        vectors: 0,
        siblings: 0,
    };
    c.cap()?;
    c.cap()?;
    c.tag(0)?; // no random commitment in this non-ZK profile
    c.row(component.width(), true)?;
    c.tag(u8::from(component.reads_next()))?;
    if component.reads_next() {
        c.row(component.width(), true)?;
    }
    c.tag(1)?;
    c.row(component.preprocessed_width(), true)?;
    c.tag(0)?; // no preprocessed next row
    c.length(component.quotient_chunks())?;
    for _ in 0..component.quotient_chunks() {
        c.row(2, true)?;
    }
    c.tag(0)?; // no random opened values
    c.fields(1)?; // batch PoW
    c.length(component.degree_bits())?;
    for _ in 0..component.degree_bits() {
        c.cap()?;
    }
    c.row(component.degree_bits(), false)?; // commit PoW witnesses
    c.length(3)?;
    for (matrices, width) in [
        (1, component.width()),
        (component.quotient_chunks(), 2),
        (1, component.preprocessed_width()),
    ] {
        c.length(NUM_QUERIES)?;
        for _ in 0..NUM_QUERIES {
            c.length(matrices)?;
            for _ in 0..matrices {
                c.row(width, false)?;
            }
        }
        c.path(component.degree_bits() + LOG_BLOWUP)?;
    }
    c.length(component.degree_bits())?;
    for round in 0..component.degree_bits() {
        c.length(NUM_QUERIES)?;
        for _ in 0..NUM_QUERIES {
            c.row(1, true)?;
        }
        c.path(component.degree_bits() + LOG_BLOWUP - round - 1)?;
    }
    c.row(1, true)?;
    c.fields(1)?; // query PoW
    if c.u64()? != component.degree_bits() as u64 {
        return Err(c.error("fixed trace degree"));
    }
    c.fields(1)?; // OOD PoW
    if c.at != bytes.len() {
        return Err(c.error("trailing bytes"));
    }
    debug_assert_eq!(c.vectors, bound.vector_headers);
    debug_assert!(c.fields <= bound.maximum_field_elements);
    debug_assert!(c.siblings <= bound.maximum_merkle_siblings);
    Ok(WireScan {
        bytes: c.at,
        field_elements: c.fields,
        vector_headers: c.vectors,
        merkle_siblings: c.siblings,
    })
}
