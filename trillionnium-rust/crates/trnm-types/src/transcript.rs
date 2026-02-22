use crate::{Hash32, RelayAuthEnvelope};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

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
    levels: Vec<Vec<Hash32>>,
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
            let sibling_idx = if idx % 2 == 0 { idx + 1 } else { idx - 1 };
            let sibling = if sibling_idx < level.len() {
                level[sibling_idx]
            } else {
                level[idx]
            };

            path.push(sibling);
            directions.push(if idx % 2 == 0 {
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

pub fn relay_auth_envelope_hash(env: &RelayAuthEnvelope) -> Hash32 {
    let mut hasher = Sha256::new();
    hasher.update(RelayAuthEnvelope::SIGNING_DOMAIN_V1.as_bytes());
    hasher.update(b"|");
    hasher.update(env.chain_id.as_bytes());
    hasher.update(b"|");
    hasher.update(env.msg_type.as_bytes());
    hasher.update(b"|");
    hasher.update(env.version.as_bytes());
    hasher.update(b"|");
    hasher.update(env.task_id.as_bytes());
    hasher.update(b"|");
    hasher.update(env.session_id.as_bytes());
    hasher.update(b"|");
    hasher.update(env.seq.to_string().as_bytes());
    hasher.update(b"|");
    hasher.update(env.timestamp_ms.to_string().as_bytes());
    hasher.update(b"|");
    hasher.update(env.from.as_bytes());
    hasher.update(b"|");
    hasher.update(env.to.as_bytes());
    hasher.update(b"|");
    hasher.update(env.nonce.as_bytes());
    hasher.update(b"|");
    hasher.update(env.payload_hash.as_bytes());
    hasher.update(b"|");
    hasher.update(env.sig.as_bytes());
    hasher.finalize().into()
}

pub fn transcript_segment_root(
    envelopes: &[RelayAuthEnvelope],
    start_seq: u64,
    end_seq: u64,
) -> Result<Hash32, TranscriptError> {
    let tree = transcript_segment_tree(envelopes, start_seq, end_seq)?;
    Ok(tree.root())
}

pub fn transcript_segment_proof(
    envelopes: &[RelayAuthEnvelope],
    start_seq: u64,
    end_seq: u64,
    target_seq: u64,
) -> Result<(Hash32, TranscriptProof), TranscriptError> {
    let (root, mut proofs) = transcript_segment_proofs(envelopes, start_seq, end_seq, &[target_seq])?;
    Ok((root, proofs.remove(0)))
}

/// Batch API: build Merkle layers once, then generate proofs for multiple targets.
pub fn transcript_segment_proofs(
    envelopes: &[RelayAuthEnvelope],
    start_seq: u64,
    end_seq: u64,
    target_seqs: &[u64],
) -> Result<(Hash32, Vec<TranscriptProof>), TranscriptError> {
    let tree = transcript_segment_tree(envelopes, start_seq, end_seq)?;
    let root = tree.root();

    let mut out = Vec::with_capacity(target_seqs.len());
    for &target_seq in target_seqs {
        if target_seq < start_seq || target_seq > end_seq {
            return Err(TranscriptError::TargetOutOfRange {
                target_seq,
                start_seq,
                end_seq,
            });
        }
        let idx = (target_seq - start_seq) as usize;
        let proof = tree.proof(idx).ok_or(TranscriptError::TargetOutOfRange {
            target_seq,
            start_seq,
            end_seq,
        })?;
        out.push(proof);
    }

    Ok((root, out))
}

/// Build a transcript segment Merkle tree. Useful when caller needs root + many proofs.
pub fn transcript_segment_tree(
    envelopes: &[RelayAuthEnvelope],
    start_seq: u64,
    end_seq: u64,
) -> Result<TranscriptMerkleTree, TranscriptError> {
    let hashes = collect_segment_hashes(envelopes, start_seq, end_seq)?;
    Ok(TranscriptMerkleTree {
        levels: build_merkle_levels(hashes),
    })
}

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

fn collect_segment_hashes(
    envelopes: &[RelayAuthEnvelope],
    start_seq: u64,
    end_seq: u64,
) -> Result<Vec<Hash32>, TranscriptError> {
    if start_seq > end_seq {
        return Err(TranscriptError::InvalidRange { start_seq, end_seq });
    }

    let mut expected_seq = start_seq;
    let mut hashes = Vec::new();

    for env in envelopes {
        if env.seq < start_seq {
            continue;
        }
        if env.seq > end_seq {
            break;
        }
        if env.seq != expected_seq {
            return Err(TranscriptError::OrderMismatch {
                expected_seq,
                got_seq: env.seq,
            });
        }
        hashes.push(relay_auth_envelope_hash(env));
        expected_seq = expected_seq.saturating_add(1);
    }

    if hashes.is_empty() {
        return Err(TranscriptError::EmptySegment);
    }

    if expected_seq <= end_seq {
        return Err(TranscriptError::MissingSequence { expected_seq });
    }

    Ok(hashes)
}

fn build_merkle_levels(leaves: Vec<Hash32>) -> Vec<Vec<Hash32>> {
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
            let right = if i + 1 < prev.len() { prev[i + 1] } else { left };
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

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_env(seq: u64, nonce: &str) -> RelayAuthEnvelope {
        RelayAuthEnvelope {
            version: RelayAuthEnvelope::SPEC_VERSION.to_string(),
            chain_id: "trnm-mainnet".to_string(),
            task_id: "task-1".to_string(),
            session_id: "sess-1".to_string(),
            seq,
            timestamp_ms: 1_730_000_000_000 + seq as u128,
            msg_type: "INPUT_CHUNK".to_string(),
            from: "trnm1from".to_string(),
            to: "trnm1to".to_string(),
            nonce: nonce.to_string(),
            payload: vec![1, 2, 3],
            payload_hash: RelayAuthEnvelope::payload_hash_hex(&[1, 2, 3]),
            sig: format!("sig-{}", seq),
        }
    }

    #[test]
    fn transcript_proof_verify_pass() {
        let envs = vec![
            sample_env(1, "n1"),
            sample_env(2, "n2"),
            sample_env(3, "n3"),
        ];
        let (root, proof) = transcript_segment_proof(&envs, 1, 3, 2).expect("proof");
        assert!(verify_proof(&root, &proof));
    }

    #[test]
    fn transcript_proof_verify_fail_tampered_leaf() {
        let envs = vec![
            sample_env(1, "n1"),
            sample_env(2, "n2"),
            sample_env(3, "n3"),
        ];
        let (root, mut proof) = transcript_segment_proof(&envs, 1, 3, 2).expect("proof");
        proof.leaf[0] ^= 0x01;
        assert!(!verify_proof(&root, &proof));
    }

    #[test]
    fn transcript_segment_root_rejects_order_mismatch() {
        let envs = vec![
            sample_env(1, "n1"),
            sample_env(3, "n3"),
            sample_env(2, "n2"),
        ];
        let err = transcript_segment_root(&envs, 1, 3).unwrap_err();
        assert!(matches!(err, TranscriptError::OrderMismatch { .. }));
    }

    #[test]
    fn transcript_envelope_hash_uses_stable_field_order() {
        let env = sample_env(1, "n1");
        let h1 = relay_auth_envelope_hash(&env);

        let mut altered = env.clone();
        altered.sig = "sig-1x".to_string();
        let h2 = relay_auth_envelope_hash(&altered);

        assert_ne!(h1, h2);
    }

    #[test]
    fn transcript_batch_proofs_match_single_proof_api() {
        let envs = vec![
            sample_env(1, "n1"),
            sample_env(2, "n2"),
            sample_env(3, "n3"),
            sample_env(4, "n4"),
            sample_env(5, "n5"),
        ];

        let targets = [1, 3, 5];
        let (batch_root, batch_proofs) = transcript_segment_proofs(&envs, 1, 5, &targets).unwrap();
        for (i, seq) in targets.iter().enumerate() {
            let (single_root, single_proof) = transcript_segment_proof(&envs, 1, 5, *seq).unwrap();
            assert_eq!(batch_root, single_root);
            assert_eq!(batch_proofs[i], single_proof);
        }
    }

    #[test]
    fn transcript_batch_proof_hash_pair_count_estimate_is_lower() {
        // 近似性能对比：重复单点 proof 需要重复构建树层。
        let leaf_count = 64usize;
        let proof_count = 8usize;
        let levels = (leaf_count as f64).log2().ceil() as usize;
        let pair_hashes_per_build = leaf_count - 1;

        let old_total = pair_hashes_per_build * proof_count;
        let batch_total = pair_hashes_per_build + proof_count * levels;

        assert!(batch_total < old_total);
    }
}
