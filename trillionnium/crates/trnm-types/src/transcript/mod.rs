mod normalization;
mod records;
mod verification;

use crate::{Hash32, RelayAuthEnvelope};

pub use records::{MerkleDirection, TranscriptError, TranscriptMerkleTree, TranscriptProof};
pub use verification::verify_proof;

use normalization::collect_segment_hashes;
use verification::build_merkle_levels;

pub fn relay_auth_envelope_hash(env: &RelayAuthEnvelope) -> Hash32 {
    normalization::relay_auth_envelope_hash(env)
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
    let (root, mut proofs) =
        transcript_segment_proofs(envelopes, start_seq, end_seq, &[target_seq])?;
    Ok((root, proofs.remove(0)))
}

/// Batch API: build Merkle layers once, then generate proofs for multiple targets.
pub fn transcript_segment_proofs(
    envelopes: &[RelayAuthEnvelope],
    start_seq: u64,
    end_seq: u64,
    target_seqs: &[u64],
) -> Result<(Hash32, Vec<TranscriptProof>), TranscriptError> {
    if target_seqs.is_empty() {
        return Err(TranscriptError::EmptyTargets);
    }

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
    fn transcript_batch_proofs_reject_empty_targets() {
        let envs = vec![
            sample_env(1, "n1"),
            sample_env(2, "n2"),
            sample_env(3, "n3"),
        ];
        let err = transcript_segment_proofs(&envs, 1, 3, &[]).unwrap_err();
        assert!(matches!(err, TranscriptError::EmptyTargets));
    }

    #[test]
    fn transcript_single_proof_api_rejects_empty_batch_indirectly() {
        let envs = vec![sample_env(1, "n1")];
        let (root, proof) = transcript_segment_proof(&envs, 1, 1, 1).expect("single proof");
        assert!(verify_proof(&root, &proof));
    }

    #[test]
    fn transcript_batch_proof_hash_pair_count_estimate_is_lower() {
        // Approximate performance comparison: repeated single-point proofs need to rebuild the tree levels each time.
        let leaf_count = 64usize;
        let proof_count = 8usize;
        let levels = (leaf_count as f64).log2().ceil() as usize;
        let pair_hashes_per_build = leaf_count - 1;

        let old_total = pair_hashes_per_build * proof_count;
        let batch_total = pair_hashes_per_build + proof_count * levels;

        assert!(batch_total < old_total);
    }
}
