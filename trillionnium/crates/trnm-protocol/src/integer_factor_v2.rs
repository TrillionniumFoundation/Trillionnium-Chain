//! Exact tag23 payload codec. Decoding grants no model or signature authority.
use crate::pon_wire::{Hash, WireError};

pub const TAG: u8 = 23;
pub const PREFIX_BYTES: usize = 242;
pub const SCALE: u16 = 1024;
pub const ROWS: usize = 3;
pub const COLUMNS: usize = 257;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FactorWitnessV2 {
    pub rank: u8,
    pub slot: u8,
    pub family: Hash,
    pub parent_ref: Hash,
    pub parent_artifact: Hash,
    pub candidate_artifact: Hash,
    pub update_id: Hash,
    pub contribution_id: Hash,
    pub components_root: Hash,
    pub round: u64,
    /// Row-major B (3×rank), then row-major A (rank×257).
    pub factors: Vec<i16>,
}

impl FactorWitnessV2 {
    pub fn encode(&self) -> Result<Vec<u8>, WireError> {
        if !(1..=2).contains(&self.rank) || self.slot >= 3 {
            return Err(WireError::Limit);
        }
        if self.factors.len() != (ROWS + COLUMNS) * usize::from(self.rank)
            || self.factors.contains(&i16::MIN)
        {
            return Err(WireError::Noncanonical);
        }
        let mut raw = Vec::with_capacity(PREFIX_BYTES + 2 * self.factors.len());
        raw.extend(b"ILF2");
        raw.extend(2_u16.to_le_bytes());
        raw.extend([self.rank, self.slot]);
        raw.extend(SCALE.to_le_bytes());
        for value in [
            self.family,
            self.parent_ref,
            self.parent_artifact,
            self.candidate_artifact,
            self.update_id,
            self.contribution_id,
            self.components_root,
        ] {
            raw.extend(value);
        }
        raw.extend(self.round.to_le_bytes());
        for coefficient in &self.factors {
            raw.extend(coefficient.to_le_bytes());
        }
        Ok(raw)
    }

    pub fn decode(raw: &[u8]) -> Result<Self, WireError> {
        if raw.len() < PREFIX_BYTES {
            return Err(WireError::Length);
        }
        if raw[..4] != *b"ILF2"
            || raw[4..6] != 2_u16.to_le_bytes()
            || raw[8..10] != SCALE.to_le_bytes()
        {
            return Err(WireError::Version);
        }
        let rank = raw[6];
        let slot = raw[7];
        if !(1..=2).contains(&rank) || slot >= 3 {
            return Err(WireError::Limit);
        }
        if raw.len() != PREFIX_BYTES + 2 * (ROWS + COLUMNS) * usize::from(rank) {
            return Err(WireError::Length);
        }
        let digest = |index: usize| -> Hash {
            raw[10 + 32 * index..42 + 32 * index]
                .try_into()
                .expect("bounded")
        };
        let value = Self {
            rank,
            slot,
            family: digest(0),
            parent_ref: digest(1),
            parent_artifact: digest(2),
            candidate_artifact: digest(3),
            update_id: digest(4),
            contribution_id: digest(5),
            components_root: digest(6),
            round: u64::from_le_bytes(raw[234..242].try_into().expect("bounded")),
            factors: raw[PREFIX_BYTES..]
                .as_chunks::<2>()
                .0
                .iter()
                .map(|chunk| chunk.as_slice())
                .map(|c| i16::from_le_bytes([c[0], c[1]]))
                .collect(),
        };
        if value.encode()? != raw {
            return Err(WireError::Noncanonical);
        }
        Ok(value)
    }
}
