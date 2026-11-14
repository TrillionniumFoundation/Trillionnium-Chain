//! Exact raw A/B commitments used by native qualified-task parent admission.
//! These hashes are public statement data, not task eligibility or verified work.
use super::{Hash, WorkError, CELLS, PROOF_BYTES};
use trnm_protocol::pon_wire::hash;

/// Original manifest commitments, with the original domains and raw u32-LE
/// matrix bytes. Copying this data never creates a Node admission capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArtifactCommitments {
    pub model: Hash,
    pub input: Hash,
}

/// Preserve the native parent's original shape checks before hashing A/B.
/// This deliberately does not validate field elements, task, product, transcript,
/// ticket, target, registration, or the current parent. Full native replay and
/// the caller's original current-parent eligibility checks remain mandatory.
pub fn commitments(proof: &[u8]) -> Result<ArtifactCommitments, WorkError> {
    if proof.len() != PROOF_BYTES {
        return Err(WorkError::Length);
    }
    if proof.get(..4) != Some(b"PNW1") {
        return Err(WorkError::Version);
    }
    let size = CELLS * 4;
    Ok(ArtifactCommitments {
        model: hash(b"artifact", &[&proof[4..4 + size]]),
        input: hash(
            b"qualified-task-input-v1",
            &[&proof[4 + size..4 + 2 * size]],
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw_material() -> Vec<u8> {
        let mut proof = vec![0; PROOF_BYTES];
        proof[..4].copy_from_slice(b"PNW1");
        for (index, cell) in proof[4..4 + 2 * CELLS * 4].chunks_exact_mut(4).enumerate() {
            cell.copy_from_slice(&(index as u32).to_le_bytes());
        }
        proof
    }

    #[test]
    fn exact_original_domains_raw_bytes_and_matrix_boundaries() {
        let proof = raw_material();
        let expected = ArtifactCommitments {
            model: hash(b"artifact", &[&proof[4..4 + CELLS * 4]]),
            input: hash(
                b"qualified-task-input-v1",
                &[&proof[4 + CELLS * 4..4 + 2 * CELLS * 4]],
            ),
        };
        assert_eq!(commitments(&proof), Ok(expected));
        for (matrix, offset) in [
            (0, 4),
            (0, 4 + CELLS * 4 - 1),
            (1, 4 + CELLS * 4),
            (1, 4 + 2 * CELLS * 4 - 1),
        ] {
            let mut changed = proof.clone();
            changed[offset] ^= 1;
            let actual = commitments(&changed).unwrap();
            assert_eq!(actual.model == expected.model, matrix != 0);
            assert_eq!(actual.input == expected.input, matrix != 1);
        }
        // C and trace are validated by full replay, not by this shape/hash helper.
        for offset in [4 + 2 * CELLS * 4, PROOF_BYTES - 1] {
            let mut changed = proof.clone();
            changed[offset] ^= 1;
            assert_eq!(commitments(&changed), Ok(expected));
        }
    }

    #[test]
    fn shape_rejection_and_raw_noncanonical_bytes_preserve_parent_semantics() {
        let proof = raw_material();
        for length in [0, 4, PROOF_BYTES - 1, PROOF_BYTES + 1] {
            let mut changed = proof.clone();
            changed.resize(length, 0);
            assert_eq!(commitments(&changed), Err(WorkError::Length));
        }
        let mut changed = proof.clone();
        changed[0] ^= 1;
        assert_eq!(commitments(&changed), Err(WorkError::Version));
        let mut changed = proof;
        changed[4..8].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(
            commitments(&changed).unwrap().model,
            hash(b"artifact", &[&changed[4..4 + CELLS * 4]])
        );
        assert_eq!(
            super::super::precheck_proof_encoding(&changed),
            Err(WorkError::Field)
        );
    }
}
