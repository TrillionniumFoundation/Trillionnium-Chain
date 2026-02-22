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

pub fn relay_auth_envelope_hash(env: &RelayAuthEnvelope) -> Hash32 {
    let mut hasher = Sha256::new();
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
    hasher.update(env.msg_type.as_bytes());
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
    let hashes = collect_segment_hashes(envelopes, start_seq, end_seq)?;
    Ok(merkle_root(&hashes))
}

pub fn transcript_segment_proof(
    envelopes: &[RelayAuthEnvelope],
    start_seq: u64,
    end_seq: u64,
    target_seq: u64,
) -> Result<(Hash32, TranscriptProof), TranscriptError> {
    if target_seq < start_seq || target_seq > end_seq {
        return Err(TranscriptError::TargetOutOfRange {
            target_seq,
            start_seq,
            end_seq,
        });
    }
    let hashes = collect_segment_hashes(envelopes, start_seq, end_seq)?;
    let target_index = (target_seq - start_seq) as usize;
    let (root, proof) = merkle_proof(&hashes, target_index);
    Ok((root, proof))
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

fn merkle_root(leaves: &[Hash32]) -> Hash32 {
    if leaves.is_empty() {
        return [0u8; 32];
    }

    let mut level = leaves.to_vec();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let mut i = 0;
        while i < level.len() {
            let left = level[i];
            let right = if i + 1 < level.len() {
                level[i + 1]
            } else {
                left
            };
            next.push(hash_pair(&left, &right));
            i += 2;
        }
        level = next;
    }

    level[0]
}

fn merkle_proof(leaves: &[Hash32], target_index: usize) -> (Hash32, TranscriptProof) {
    let mut level = leaves.to_vec();
    let mut idx = target_index;
    let mut path = Vec::new();
    let mut directions = Vec::new();

    while level.len() > 1 {
        let sibling_idx = if idx % 2 == 0 { idx + 1 } else { idx - 1 };
        let sibling = if sibling_idx < level.len() {
            level[sibling_idx]
        } else {
            level[idx]
        };

        if idx % 2 == 0 {
            path.push(sibling);
            directions.push(MerkleDirection::Right);
        } else {
            path.push(sibling);
            directions.push(MerkleDirection::Left);
        }

        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let mut i = 0;
        while i < level.len() {
            let left = level[i];
            let right = if i + 1 < level.len() {
                level[i + 1]
            } else {
                left
            };
            next.push(hash_pair(&left, &right));
            i += 2;
        }

        idx /= 2;
        level = next;
    }

    (
        level[0],
        TranscriptProof {
            leaf: leaves[target_index],
            path,
            directions,
        },
    )
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
}
