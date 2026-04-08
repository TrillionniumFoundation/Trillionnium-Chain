use crate::Hash32;
use sha2::{Digest, Sha256};

use super::{MerkleDirection, TranscriptProof};

pub fn verify_proof(root: &Hash32, proof: &TranscriptProof) -> bool {
    if proof.path.len() != proof.directions.len() {
        return false;
    }

    let mut acc = proof.leaf;
    for (sibling, direction) in proof.path.iter().zip(proof.directions.iter()) {
        acc = match direction {
            MerkleDirection::Left => hash_pair(sibling, &acc),
            MerkleDirection::Right => hash_pair(&acc, sibling),
        };
    }
    &acc == root
}

pub(super) fn build_merkle_levels(leaves: Vec<Hash32>) -> Vec<Vec<Hash32>> {
    if leaves.is_empty() {
        return vec![vec![[0u8; 32]]];
    }

    let mut levels = vec![leaves];
    while levels.last().is_some_and(|l| l.len() > 1) {
        let prev = levels.last().expect("level exists");
        let mut next = Vec::with_capacity(prev.len().div_ceil(2));
        let mut i = 0;
        while i < prev.len() {
            let left = prev[i];
            let right = if i + 1 < prev.len() {
                prev[i + 1]
            } else {
                left
            };
            next.push(hash_pair(&left, &right));
            i += 2;
        }
        levels.push(next);
    }

    levels
}

fn hash_pair(left: &Hash32, right: &Hash32) -> Hash32 {
    let mut hasher = Sha256::new();
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}
