use crate::Hash32;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MerkleDirection {
    Left,
    Right,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TranscriptProof {
    pub leaf: Hash32,
    pub path: Vec<Hash32>,
    pub directions: Vec<MerkleDirection>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TranscriptError {
    EmptySegment,
    EmptyTargets,
    InvalidRange {
        start_seq: u64,
        end_seq: u64,
    },
    MissingSequence {
        expected_seq: u64,
    },
    OrderMismatch {
        expected_seq: u64,
        got_seq: u64,
    },
    TargetOutOfRange {
        target_seq: u64,
        start_seq: u64,
        end_seq: u64,
    },
}

/// Built Merkle layers for a transcript segment. levels[0] is leaf layer,
/// levels[last][0] is root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TranscriptMerkleTree {
    pub(crate) levels: Vec<Vec<Hash32>>,
}

impl TranscriptMerkleTree {
    pub fn root(&self) -> Hash32 {
        self.levels
            .last()
            .and_then(|l| l.first().copied())
            .unwrap_or([0u8; 32])
    }

    pub fn leaf_count(&self) -> usize {
        self.levels.first().map_or(0, Vec::len)
    }

    pub fn proof(&self, target_index: usize) -> Option<TranscriptProof> {
        let leaves = self.levels.first()?;
        if target_index >= leaves.len() {
            return None;
        }

        let mut idx = target_index;
        let mut path = Vec::with_capacity(self.levels.len().saturating_sub(1));
        let mut directions = Vec::with_capacity(self.levels.len().saturating_sub(1));

        for level in self.levels.iter().take(self.levels.len().saturating_sub(1)) {
            let sibling_idx = if idx.is_multiple_of(2) {
                idx + 1
            } else {
                idx - 1
            };
            let sibling = if sibling_idx < level.len() {
                level[sibling_idx]
            } else {
                level[idx]
            };

            path.push(sibling);
            directions.push(if idx.is_multiple_of(2) {
                MerkleDirection::Right
            } else {
                MerkleDirection::Left
            });
            idx /= 2;
        }

        Some(TranscriptProof {
            leaf: leaves[target_index],
            path,
            directions,
        })
    }
}
