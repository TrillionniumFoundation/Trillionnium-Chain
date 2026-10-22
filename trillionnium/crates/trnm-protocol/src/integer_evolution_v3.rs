//! Explicit tag24 ILF3 codec. A decoded update grants no parent or model authority.
use crate::integer_factor_v2::{COLUMNS, ROWS, SCALE};
use crate::pon_wire::{Hash, WireError};

pub const TAG: u8 = 24;
pub const PREFIX_BYTES: usize = 242;
pub const MAX_RANK_SUM: usize = 3;
pub const MAX_OPERATIONS: usize = 3;
pub const MAX_PAYLOAD_BYTES: usize =
    PREFIX_BYTES + 2 * MAX_OPERATIONS + 2 * (ROWS + COLUMNS) * MAX_RANK_SUM;

/// Targets are base=0, router=1 and existing expert delta slots=2,3,4.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvolutionOperationV3 {
    pub target: u8,
    pub rank: u8,
    /// Row-major B (3 x rank), followed by row-major A (rank x 257).
    pub factors: Vec<i16>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvolutionWitnessV3 {
    /// Nonempty subset of the three existing routed experts; no arbitrary code/graph.
    pub active_experts: u8,
    pub family: Hash,
    pub parent_ref: Hash,
    pub parent_artifact: Hash,
    pub candidate_artifact: Hash,
    pub update_id: Hash,
    pub contribution_id: Hash,
    pub components_root: Hash,
    pub round: u64,
    pub operations: Vec<EvolutionOperationV3>,
}

impl EvolutionWitnessV3 {
    pub fn encode(&self) -> Result<Vec<u8>, WireError> {
        if !(1..=7).contains(&self.active_experts) || self.operations.len() > MAX_OPERATIONS {
            return Err(WireError::Limit);
        }
        let mut rank_sum = 0;
        let mut previous = None;
        for operation in &self.operations {
            if operation.target >= 5 || !(1..=2).contains(&operation.rank) {
                return Err(WireError::Limit);
            }
            if previous.is_some_and(|target| target >= operation.target)
                || operation.factors.len() != (ROWS + COLUMNS) * usize::from(operation.rank)
                || operation.factors.contains(&i16::MIN)
            {
                return Err(WireError::Noncanonical);
            }
            rank_sum += usize::from(operation.rank);
            previous = Some(operation.target);
        }
        if rank_sum > MAX_RANK_SUM {
            return Err(WireError::Limit);
        }
        let mut raw = Vec::with_capacity(MAX_PAYLOAD_BYTES);
        raw.extend(b"ILF3");
        raw.extend(3_u16.to_le_bytes());
        raw.extend([self.active_experts, self.operations.len() as u8]);
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
        for operation in &self.operations {
            raw.extend([operation.target, operation.rank]);
            for coefficient in &operation.factors {
                raw.extend(coefficient.to_le_bytes());
            }
        }
        Ok(raw)
    }

    pub fn decode(raw: &[u8]) -> Result<Self, WireError> {
        if !(PREFIX_BYTES..=MAX_PAYLOAD_BYTES).contains(&raw.len()) {
            return Err(WireError::Length);
        }
        if raw[..4] != *b"ILF3"
            || raw[4..6] != 3_u16.to_le_bytes()
            || raw[8..10] != SCALE.to_le_bytes()
        {
            return Err(WireError::Version);
        }
        let count = usize::from(raw[7]);
        if count > MAX_OPERATIONS || !(1..=7).contains(&raw[6]) {
            return Err(WireError::Limit);
        }
        let digest = |index: usize| -> Hash {
            raw[10 + 32 * index..42 + 32 * index]
                .try_into()
                .expect("bounded")
        };
        let mut operations = Vec::with_capacity(count);
        let mut position = PREFIX_BYTES;
        for _ in 0..count {
            let header = raw.get(position..position + 2).ok_or(WireError::Length)?;
            let target = header[0];
            let rank = header[1];
            if target >= 5 || !(1..=2).contains(&rank) {
                return Err(WireError::Limit);
            }
            position += 2;
            let end = position + 2 * (ROWS + COLUMNS) * usize::from(rank);
            let factors = raw
                .get(position..end)
                .ok_or(WireError::Length)?
                .chunks_exact(2)
                .map(|c| i16::from_le_bytes([c[0], c[1]]))
                .collect();
            operations.push(EvolutionOperationV3 {
                target,
                rank,
                factors,
            });
            position = end;
        }
        if position != raw.len() {
            return Err(WireError::Length);
        }
        let value = Self {
            active_experts: raw[6],
            family: digest(0),
            parent_ref: digest(1),
            parent_artifact: digest(2),
            candidate_artifact: digest(3),
            update_id: digest(4),
            contribution_id: digest(5),
            components_root: digest(6),
            round: u64::from_le_bytes(raw[234..242].try_into().expect("bounded")),
            operations,
        };
        if value.encode()? != raw {
            return Err(WireError::Noncanonical);
        }
        Ok(value)
    }
}
