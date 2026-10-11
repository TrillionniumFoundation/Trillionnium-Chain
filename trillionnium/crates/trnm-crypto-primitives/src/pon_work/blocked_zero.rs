//! Complete zero/zero W1 producer with bounded prefix working storage.
//! This is a local diagnostic algorithm, not verification or admission authority.
//! The original structured producer and native mining selection remain unchanged.
use super::{expand, producer_reduce, validate, Hash, WorkError, N, PROOF_BYTES, R};
use sha2::{Digest, Sha256};

const BLOCKS: usize = N / R;
type Tile = [u32; R * R];
type Prefixes = [Tile; BLOCKS];

/// Exact zero/zero task preparation. Other canonical materials are unsupported;
/// callers must not relabel an implicit generic fallback as this algorithm.
pub struct BlockedZeroPreparedTask {
    prefix: Vec<u8>,
}

impl BlockedZeroPreparedTask {
    pub fn new(a: &[u32], b: &[u32]) -> Result<Option<Self>, WorkError> {
        validate(a)?;
        validate(b)?;
        if a.iter().chain(b).any(|value| *value != 0) {
            return Ok(None);
        }
        let mut prefix = Vec::with_capacity(PROOF_BYTES);
        prefix.extend_from_slice(b"PNW1");
        prefix.resize(PROOF_BYTES - 32, 0);
        Ok(Some(Self { prefix }))
    }

    pub fn method(&self) -> &'static str {
        "blocked-zero-full-prefix-transcript"
    }

    pub fn prove(&self, challenge: Hash) -> Result<Vec<u8>, WorkError> {
        let el = expand(challenge, 0, N * R)?;
        let er = expand(challenge, 1, R * N)?;
        let fl = expand(challenge, 2, N * R)?;
        let fr = expand(challenge, 3, R * N)?;
        let digest = trace(challenge, &el, &er, &fl, &fr);
        let mut proof = self.prefix.clone();
        proof.extend_from_slice(&digest);
        Ok(proof)
    }
}

// For the first 8*(block+1) inner coordinates, S_block = ER_prefix * FL_prefix.
// All eight S matrices occupy 2048 bytes. A dot product plus the canonical
// cumulative value is below 8*q^2+q < 2^67, within the exact u128 reducer.
fn middle_prefixes(er: &[u32], fl: &[u32]) -> Prefixes {
    let mut prefixes = [[0; R * R]; BLOCKS];
    let mut middle = [0; R * R];
    for (block, prefix) in prefixes.iter_mut().enumerate() {
        for i in 0..R {
            for j in 0..R {
                let mut sum = u128::from(middle[i * R + j]);
                for k in block * R..(block + 1) * R {
                    sum += u128::from(er[i * N + k]) * u128::from(fl[k * R + j]);
                }
                middle[i * R + j] = producer_reduce(sum);
            }
        }
        *prefix = middle;
    }
    prefixes
}

// Only one row tile's EL * S_block matrices are materialized: another 2048 bytes.
// This replaces the old eight complete 64x64 outputs (128 KiB), not their fields:
// all 32,768 output words still have to be calculated and hashed in original order.
fn left_prefixes(el: &[u32], middle: &Prefixes, row: usize) -> Prefixes {
    let mut left = [[0; R * R]; BLOCKS];
    for (output, prefix) in left.iter_mut().zip(middle) {
        for i in 0..R {
            for j in 0..R {
                let mut sum = 0;
                for k in 0..R {
                    sum += u128::from(el[(row * R + i) * R + k]) * u128::from(prefix[k * R + j]);
                }
                output[i * R + j] = producer_reduce(sum);
            }
        }
    }
    left
}

fn trace(challenge: Hash, el: &[u32], er: &[u32], fl: &[u32], fr: &[u32]) -> Hash {
    let middle = middle_prefixes(er, fl);
    let mut right = [0; N * R];
    for i in 0..R {
        for j in 0..N {
            right[j * R + i] = fr[i * N + j];
        }
    }
    let mut transcript = Sha256::new();
    transcript.update(b"TRNM-PON-TRACE1\0");
    transcript.update(challenge);
    for bi in 0..BLOCKS {
        let left = left_prefixes(el, &middle, bi);
        for bj in 0..BLOCKS {
            for prefix in &left {
                let mut bytes = [0u8; R * R * 4];
                for i in 0..R {
                    for j in 0..R {
                        let mut sum = 0;
                        for k in 0..R {
                            sum += u128::from(prefix[i * R + k])
                                * u128::from(right[(bj * R + j) * R + k]);
                        }
                        let pos = (i * R + j) * 4;
                        bytes[pos..pos + 4].copy_from_slice(&producer_reduce(sum).to_le_bytes());
                    }
                }
                transcript.update(bytes);
            }
        }
    }
    transcript.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pon_work::{
        hash, mul, prove, structured::StructuredPreparedTask, task_id, verify, verify_reference,
        PreparedTask, CELLS, Q,
    };

    #[test]
    fn exact_task_detection_rejects_invalid_and_nonzero_material_without_fallback() {
        let zero = vec![0; CELLS];
        assert!(matches!(
            BlockedZeroPreparedTask::new(&[], &zero),
            Err(WorkError::Length)
        ));
        assert!(matches!(
            BlockedZeroPreparedTask::new(&zero, &vec![u32::MAX; CELLS]),
            Err(WorkError::Field)
        ));
        for position in [0, CELLS / 2, CELLS - 1] {
            let mut nonzero = zero.clone();
            nonzero[position] = 1;
            assert!(BlockedZeroPreparedTask::new(&nonzero, &zero)
                .unwrap()
                .is_none());
            assert!(BlockedZeroPreparedTask::new(&zero, &nonzero)
                .unwrap()
                .is_none());
        }
    }

    #[test]
    fn complete_proofs_match_old_zero_scalar_and_generic_across_challenges_and_reuse() {
        let mut a = vec![0; CELLS];
        let b = a.clone();
        let blocked = BlockedZeroPreparedTask::new(&a, &b).unwrap().unwrap();
        let generic = PreparedTask::new(&a, &b).unwrap();
        let old = StructuredPreparedTask::new(&a, &b).unwrap().unwrap();
        let task = task_id(&a, &b).unwrap();
        let before = blocked.prove([7; 32]).unwrap();
        for challenge in [
            [0; 32],
            [1; 32],
            [7; 32],
            [255; 32],
            hash(b"blocked-zero-test", &[b"distinct"]),
        ] {
            let proof = blocked.prove(challenge).unwrap();
            assert_eq!(proof.len(), PROOF_BYTES);
            assert_eq!(proof, prove(challenge, &a, &b).unwrap());
            assert_eq!(proof, generic.prove(challenge).unwrap());
            assert_eq!(proof, old.prove(challenge).unwrap());
            let ordinary = verify(challenge, task, [255; 32], &proof).unwrap();
            let reference = verify_reference(challenge, task, [255; 32], &proof).unwrap();
            assert_eq!(ordinary.ticket(), reference.ticket());
            assert_eq!(ordinary.product(), vec![0; CELLS]);
        }
        assert_eq!(before, blocked.prove([7; 32]).unwrap());
        // The preparation owns its exact mathematical input; changing a caller's
        // material cannot silently relabel it or grant a different task authority.
        a[CELLS - 1] = 1;
        assert_eq!(before, blocked.prove([7; 32]).unwrap());
        assert_eq!(
            verify([7; 32], task_id(&a, &b).unwrap(), [255; 32], &before).unwrap_err(),
            WorkError::Task
        );
    }

    #[test]
    fn all_prefix_cells_match_scalar_trace_with_extreme_noise_operands() {
        let top = (Q - 1) as u32;
        for case in 0..3 {
            let matrices: Vec<Vec<u32>> = (0..4)
                .map(|label| {
                    (0..N * R)
                        .map(|i| match case {
                            0 => top,
                            1 => {
                                if (i + label) % 3 == 0 {
                                    0
                                } else {
                                    top - ((i + label) % 17) as u32
                                }
                            }
                            _ => {
                                if label == 0 || label == 3 {
                                    0
                                } else {
                                    top
                                }
                            }
                        })
                        .collect()
                })
                .collect();
            let [el, er, fl, fr] = matrices.as_slice() else {
                unreachable!()
            };
            let a = mul(el, er, N, R, N);
            let b = mul(fl, fr, N, R, N);
            let mut expected = Sha256::new();
            expected.update(b"TRNM-PON-TRACE1\0");
            expected.update([case; 32]);
            for bi in 0..BLOCKS {
                for bj in 0..BLOCKS {
                    let mut cells = [0u32; R * R];
                    for bk in 0..BLOCKS {
                        for i in 0..R {
                            for j in 0..R {
                                let mut sum = u128::from(cells[i * R + j]);
                                for k in bk * R..(bk + 1) * R {
                                    sum += u128::from(a[(bi * R + i) * N + k])
                                        * u128::from(b[k * N + bj * R + j]);
                                }
                                cells[i * R + j] = (sum % Q) as u32;
                                expected.update(cells[i * R + j].to_le_bytes());
                            }
                        }
                    }
                }
            }
            let expected: Hash = expected.finalize().into();
            assert_eq!(trace([case; 32], el, er, fl, fr), expected);
        }
    }

    #[test]
    fn complete_zero_certificates_match_independent_python_oracle_vectors() {
        // Generated by formal/pon-nakamoto-v1/work_oracle.py using its original
        // scalar replay, not by either reassociated Rust producer.
        let zero = vec![0; CELLS];
        let prepared = BlockedZeroPreparedTask::new(&zero, &zero).unwrap().unwrap();
        for (byte, expected) in [
            (
                0,
                "d8111b2ad64c3dbd1fcab46e07507b6e071aa9608356a4b577b9c4e2182433a4",
            ),
            (
                7,
                "ba5e30e124e397a90f78f01ffcef19b408a4be9939be972cb0895a42a8679bb3",
            ),
            (
                255,
                "41917a90d1927ba85213f2ffdba37d1abb99ba462ff71be6d5a824fa28b4f78c",
            ),
        ] {
            assert_eq!(
                hex::encode(Sha256::digest(prepared.prove([byte; 32]).unwrap())),
                expected
            );
        }
    }
}
