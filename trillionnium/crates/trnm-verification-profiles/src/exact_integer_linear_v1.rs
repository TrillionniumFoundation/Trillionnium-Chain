//! Bounded, context-bound normal form for the existing 3×257 integer insertion.
//!
//! This component verifies complete BA coordinates. It grants no admission,
//! reward, source independence, whole-model equivalence, or LLM qualification.
//! Its closed JSON grammar accepts exactly the canonical Python v1 bytes.

use sha2::{Digest, Sha256};
use std::fmt;

pub const ROWS: usize = 3;
pub const COLUMNS: usize = 257;
pub const MAX_RANK: usize = 8;
pub const FACTOR_BOUND: i64 = 32_767;
pub const DELTA_BOUND: i64 = 32_767;
pub const FIXED_SCALE: u32 = 1_024;
pub const MAX_FACTOR_COEFFICIENTS: usize = (ROWS + COLUMNS) * MAX_RANK;
pub const MIN_MULTIPLICATIONS: usize = ROWS * COLUMNS;
pub const MAX_MULTIPLICATIONS: usize = MIN_MULTIPLICATIONS * MAX_RANK;
pub const EXACT_CONTRACT_BYTES: usize = 372;
pub const MAX_CONTRACT_BYTES: usize = 1_024;
pub const MIN_ADAPTER_BYTES: usize = 660;
pub const MAX_ADAPTER_BYTES: usize = 32_768;
pub const CONSENSUS_AUTHORITY: bool = false;
pub const ECONOMIC_AUTHORITY: bool = false;
pub const GENERAL_MODEL_EQUIVALENCE: bool = false;
/// H("family", canonical(config/pon/model-family-v1.json)) at the source pin.
pub const INTEGER_LINEAR_FAMILY_V1: [u8; 32] = [
    0x89, 0xb9, 0x18, 0x18, 0x33, 0x08, 0xee, 0x94, 0xcc, 0x4e, 0x45, 0x57, 0x5a, 0xc1, 0x2f, 0x74,
    0xd5, 0xde, 0x70, 0x4d, 0x38, 0x52, 0x89, 0xdb, 0xe2, 0x75, 0x2d, 0xaa, 0x13, 0xa4, 0x7c, 0xef,
];

const NUMERIC: &str = "exact-BA-no-rounding-fixed-router-add-to-delta-v1";
const CONTRACT_SCHEMA: &str = "pon-exact-integer-linear-insertion-v1";
const ADAPTER_SCHEMA: &str = "pon-integer-linear-adapter-v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IntegerLinearErrorV1 {
    Length,
    CanonicalEncoding,
    Context,
    Family,
    Slot,
    Rank,
    Shape,
    FactorBound,
    DeltaBound,
    IntegerRange,
    ArithmeticOverflow,
    WorkBudget,
}

impl fmt::Display for IntegerLinearErrorV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "INTEGER_LINEAR:{self:?}")
    }
}

impl std::error::Error for IntegerLinearErrorV1 {}

type Result<T> = std::result::Result<T, IntegerLinearErrorV1>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IntegerLinearContextV1 {
    family: [u8; 32],
    parent_artifact: [u8; 32],
    slot: u8,
}

impl IntegerLinearContextV1 {
    /// Parent/family IDs must be independently supplied by the caller. This
    /// constructor does not load or authenticate the parent model artifact.
    pub fn new(family: [u8; 32], parent_artifact: [u8; 32], slot: u8) -> Result<Self> {
        if family != INTEGER_LINEAR_FAMILY_V1 {
            return Err(IntegerLinearErrorV1::Family);
        }
        if slot >= ROWS as u8 {
            return Err(IntegerLinearErrorV1::Slot);
        }
        Ok(Self {
            family,
            parent_artifact,
            slot,
        })
    }

    pub fn decode(raw: &[u8]) -> Result<Self> {
        if raw.len() != EXACT_CONTRACT_BYTES {
            return Err(IntegerLinearErrorV1::Length);
        }
        let mut p = Parser::new(raw);
        p.literal(b"{\"columns\":257,\"delta_bound\":32767,\"factor_bound\":32767,\"family\":")?;
        let family = p.digest()?;
        p.literal(format!(",\"numeric\":\"{NUMERIC}\",\"parent_artifact\":").as_bytes())?;
        let parent_artifact = p.digest()?;
        p.literal(format!(",\"rank_max\":8,\"rows\":3,\"scale\":1024,\"schema\":\"{CONTRACT_SCHEMA}\",\"slot\":").as_bytes())?;
        let slot = p.integer()?;
        p.literal(b"}")?;
        p.end()?;
        let slot = u8::try_from(slot).map_err(|_| IntegerLinearErrorV1::Slot)?;
        let context = Self::new(family, parent_artifact, slot)?;
        if context.canonical_bytes() != raw {
            return Err(IntegerLinearErrorV1::CanonicalEncoding);
        }
        Ok(context)
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        format!("{{\"columns\":257,\"delta_bound\":32767,\"factor_bound\":32767,\"family\":\"{}\",\"numeric\":\"{NUMERIC}\",\"parent_artifact\":\"{}\",\"rank_max\":8,\"rows\":3,\"scale\":1024,\"schema\":\"{CONTRACT_SCHEMA}\",\"slot\":{}}}", hex(&self.family), hex(&self.parent_artifact), self.slot).into_bytes()
    }

    pub fn contract_id(&self) -> [u8; 32] {
        hash(
            b"integer-linear-insertion-contract-v1",
            &self.canonical_bytes(),
        )
    }

    pub fn family(&self) -> [u8; 32] {
        self.family
    }

    pub fn parent_artifact(&self) -> [u8; 32] {
        self.parent_artifact
    }

    pub fn slot(&self) -> u8 {
        self.slot
    }
}

/// Private fields prevent a claimed matrix/fingerprint from being promoted to
/// verified output. Construction always decodes factors and recomputes full BA.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckedIntegerLinearUpdateV1 {
    context: IntegerLinearContextV1,
    delta: [[i32; COLUMNS]; ROWS],
    rank: usize,
    artifact: [u8; 32],
    function_fingerprint: [u8; 32],
}

impl CheckedIntegerLinearUpdateV1 {
    pub fn context(&self) -> &IntegerLinearContextV1 {
        &self.context
    }

    pub fn delta(&self) -> &[[i32; COLUMNS]; ROWS] {
        &self.delta
    }

    pub fn rank(&self) -> usize {
        self.rank
    }

    pub fn factor_coefficients(&self) -> usize {
        (ROWS + COLUMNS) * self.rank
    }

    /// Counts every declared product, including zero factors. It is a bounded
    /// arithmetic-operation count, not CPU time, energy or economic cost.
    pub fn product_multiplications(&self) -> usize {
        MIN_MULTIPLICATIONS * self.rank
    }

    pub fn artifact(&self) -> [u8; 32] {
        self.artifact
    }

    pub fn function_fingerprint(&self) -> [u8; 32] {
        self.function_fingerprint
    }

    pub fn normal_bytes(&self) -> Vec<u8> {
        format!(
            "{{\"contract\":\"{}\",\"delta\":{},\"schema\":\"pon-normalized-linear-update-v1\"}}",
            hex(&self.context.contract_id()),
            matrix_text(&self.delta)
        )
        .into_bytes()
    }

    /// Compare complete coordinates and complete context, never hashes alone.
    /// Unequal BA does not prove unequal argmax/router/full-model functions.
    pub fn same_declared_update(&self, other: &Self) -> bool {
        self.context == other.context && self.delta == other.delta
    }
}

/// The supplied context is an exact caller pin. An adapter cannot choose a new
/// parent, slot, family or numeric contract by placing its own ID in JSON.
pub fn verify_integer_linear_v1(
    context: &IntegerLinearContextV1,
    adapter_raw: &[u8],
    max_multiplications: usize,
) -> Result<CheckedIntegerLinearUpdateV1> {
    if !(MIN_ADAPTER_BYTES..=MAX_ADAPTER_BYTES).contains(&adapter_raw.len()) {
        return Err(IntegerLinearErrorV1::Length);
    }
    if !(MIN_MULTIPLICATIONS..=MAX_MULTIPLICATIONS).contains(&max_multiplications) {
        return Err(IntegerLinearErrorV1::WorkBudget);
    }
    let mut p = Parser::new(adapter_raw);
    p.literal(b"{\"A\":")?;
    let a = p.matrix(MAX_RANK, COLUMNS)?;
    if a.is_empty() {
        return Err(IntegerLinearErrorV1::Rank);
    }
    let rank = a.len();
    if MIN_MULTIPLICATIONS * rank > max_multiplications {
        return Err(IntegerLinearErrorV1::WorkBudget);
    }
    p.literal(b",\"B\":")?;
    let b = p.matrix(ROWS, rank)?;
    if b.len() != ROWS {
        return Err(IntegerLinearErrorV1::Shape);
    }
    p.literal(b",\"contract\":")?;
    if p.digest()? != context.contract_id() {
        return Err(IntegerLinearErrorV1::Context);
    }
    p.literal(format!(",\"schema\":\"{ADAPTER_SCHEMA}\"}}").as_bytes())?;
    p.end()?;

    // Even worst permitted intermediate magnitude is 8*32767^2=8,589,410,312.
    // checked i64 preserves cancellation while refusing arithmetic overflow.
    let mut delta = [[0_i32; COLUMNS]; ROWS];
    for (i, row) in delta.iter_mut().enumerate() {
        for (j, output) in row.iter_mut().enumerate() {
            let mut value = 0_i64;
            for (k, a_row) in a.iter().enumerate() {
                value = multiply_add(value, b[i][k], a_row[j])?;
            }
            if !(-DELTA_BOUND..=DELTA_BOUND).contains(&value) {
                return Err(IntegerLinearErrorV1::DeltaBound);
            }
            *output = i32::try_from(value).map_err(|_| IntegerLinearErrorV1::ArithmeticOverflow)?;
        }
    }
    let mut checked = CheckedIntegerLinearUpdateV1 {
        context: context.clone(),
        delta,
        rank,
        artifact: hash(b"integer-linear-adapter-v1", adapter_raw),
        function_fingerprint: [0; 32],
    };
    checked.function_fingerprint = hash(b"normalized-linear-update-v1", &checked.normal_bytes());
    Ok(checked)
}

fn multiply_add(accumulator: i64, left: i64, right: i64) -> Result<i64> {
    left.checked_mul(right)
        .and_then(|product| accumulator.checked_add(product))
        .ok_or(IntegerLinearErrorV1::ArithmeticOverflow)
}

fn hash(domain: &[u8], part: &[u8]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"TRNM-PON1\0");
    digest.update((domain.len() as u16).to_le_bytes());
    digest.update(domain);
    digest.update((part.len() as u32).to_le_bytes());
    digest.update(part);
    digest.finalize().into()
}

pub fn hex(digest: &[u8; 32]) -> String {
    const ALPHABET: &[u8] = b"0123456789abcdef";
    let mut value = String::with_capacity(64);
    for byte in digest {
        value.push(ALPHABET[(byte >> 4) as usize] as char);
        value.push(ALPHABET[(byte & 15) as usize] as char);
    }
    value
}

fn matrix_text(matrix: &[[i32; COLUMNS]; ROWS]) -> String {
    let rows: Vec<String> = matrix
        .iter()
        .map(|row| {
            format!(
                "[{}]",
                row.iter().map(i32::to_string).collect::<Vec<_>>().join(",")
            )
        })
        .collect();
    format!("[{}]", rows.join(","))
}

struct Parser<'a> {
    raw: &'a [u8],
    position: usize,
}

impl<'a> Parser<'a> {
    fn new(raw: &'a [u8]) -> Self {
        Self { raw, position: 0 }
    }

    fn literal(&mut self, value: &[u8]) -> Result<()> {
        let end = self
            .position
            .checked_add(value.len())
            .ok_or(IntegerLinearErrorV1::Length)?;
        if self.raw.get(self.position..end) != Some(value) {
            return Err(IntegerLinearErrorV1::CanonicalEncoding);
        }
        self.position = end;
        Ok(())
    }

    fn end(&self) -> Result<()> {
        if self.position != self.raw.len() {
            return Err(IntegerLinearErrorV1::CanonicalEncoding);
        }
        Ok(())
    }

    fn digest(&mut self) -> Result<[u8; 32]> {
        self.literal(b"\"")?;
        let end = self
            .position
            .checked_add(64)
            .ok_or(IntegerLinearErrorV1::Length)?;
        let value = self
            .raw
            .get(self.position..end)
            .ok_or(IntegerLinearErrorV1::Length)?;
        let mut digest = [0; 32];
        for (i, pair) in value.chunks_exact(2).enumerate() {
            fn digit(c: u8) -> Result<u8> {
                match c {
                    b'0'..=b'9' => Ok(c - b'0'),
                    b'a'..=b'f' => Ok(c - b'a' + 10),
                    _ => Err(IntegerLinearErrorV1::CanonicalEncoding),
                }
            }
            digest[i] = digit(pair[0])? * 16 + digit(pair[1])?;
        }
        self.position = end;
        self.literal(b"\"")?;
        Ok(digest)
    }

    fn integer(&mut self) -> Result<i64> {
        let negative = self.raw.get(self.position) == Some(&b'-');
        if negative {
            self.position += 1;
        }
        let first = *self
            .raw
            .get(self.position)
            .ok_or(IntegerLinearErrorV1::Length)?;
        if !first.is_ascii_digit() {
            return Err(IntegerLinearErrorV1::CanonicalEncoding);
        }
        let mut value = 0_i64;
        let start = self.position;
        while let Some(c) = self.raw.get(self.position).copied() {
            if !c.is_ascii_digit() {
                break;
            }
            value = value
                .checked_mul(10)
                .and_then(|v| v.checked_add(i64::from(c - b'0')))
                .ok_or(IntegerLinearErrorV1::IntegerRange)?;
            self.position += 1;
        }
        if (first == b'0' && self.position - start != 1) || (negative && value == 0) {
            return Err(IntegerLinearErrorV1::CanonicalEncoding);
        }
        Ok(if negative { -value } else { value })
    }

    fn matrix(&mut self, max_rows: usize, columns: usize) -> Result<Vec<Vec<i64>>> {
        self.literal(b"[")?;
        let mut rows = Vec::with_capacity(max_rows);
        if self.raw.get(self.position) == Some(&b']') {
            self.position += 1;
            return Ok(rows);
        }
        loop {
            if rows.len() == max_rows {
                return Err(IntegerLinearErrorV1::Shape);
            }
            self.literal(b"[")?;
            let mut row = Vec::with_capacity(columns);
            for column in 0..columns {
                if column != 0 {
                    self.literal(b",")?;
                }
                let value = self.integer()?;
                if !(-FACTOR_BOUND..=FACTOR_BOUND).contains(&value) {
                    return Err(IntegerLinearErrorV1::FactorBound);
                }
                row.push(value);
            }
            self.literal(b"]")?;
            rows.push(row);
            if self.raw.get(self.position) == Some(&b']') {
                self.position += 1;
                break;
            }
            self.literal(b",")?;
        }
        Ok(rows)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checked_arithmetic_defense_and_permitted_intermediate_bound() {
        assert_eq!(
            multiply_add(0, i64::MAX, 2),
            Err(IntegerLinearErrorV1::ArithmeticOverflow)
        );
        assert_eq!(
            multiply_add(i64::MAX, 1, 1),
            Err(IntegerLinearErrorV1::ArithmeticOverflow)
        );
        let maximum = FACTOR_BOUND * FACTOR_BOUND * MAX_RANK as i64;
        assert_eq!(maximum, 8_589_410_312);
        assert!(maximum > i64::from(i32::MAX));
        assert_eq!(
            multiply_add(maximum, -FACTOR_BOUND, FACTOR_BOUND),
            Ok(maximum - FACTOR_BOUND * FACTOR_BOUND)
        );
    }
}
