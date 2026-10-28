//! Complete W1 transcripts for exactly one zero and one nonzero rank-one operand.
//! Exact factors are derived from all canonical task bytes. This local diagnostic
//! producer neither grants admission authority nor changes native mining selection.
use super::{
    expand, producer_reduce, structured::rank_one, validate, Hash, WorkError, N, PROOF_BYTES, R,
};
use sha2::{Digest, Sha256};

const BLOCKS: usize = N / R;
type Factors = [[u32; N * R]; BLOCKS];

/// A separate complete-proof algorithm with an explicit, narrow support domain.
/// Both zero, both nonzero, and non-rank-one counterparts return `None` after full
/// canonical validation. No generic producer substitutes for unsupported tasks.
pub struct BlockedOneZeroRankOnePreparedTask {
    zero_on_left: bool,
    left: Vec<u32>,
    right: Vec<u32>,
    prefix: Vec<u8>,
}

impl BlockedOneZeroRankOnePreparedTask {
    pub fn new(a: &[u32], b: &[u32]) -> Result<Option<Self>, WorkError> {
        validate(a)?;
        validate(b)?;
        let a_zero = a.iter().all(|value| *value == 0);
        let b_zero = b.iter().all(|value| *value == 0);
        if a_zero == b_zero {
            return Ok(None);
        }
        let Some((left, right)) = rank_one(if a_zero { b } else { a }) else {
            return Ok(None);
        };
        let mut prefix = Vec::with_capacity(PROOF_BYTES);
        prefix.extend_from_slice(b"PNW1");
        for value in a.iter().chain(b) {
            prefix.extend_from_slice(&value.to_le_bytes());
        }
        // The exact zero operand proves that the original product is zero. The
        // challenge-dependent transcript still needs complete computation.
        prefix.resize(PROOF_BYTES - 32, 0);
        Ok(Some(Self {
            zero_on_left: a_zero,
            left,
            right,
            prefix,
        }))
    }

    pub fn method(&self) -> &'static str {
        "blocked-one-zero-rank-one-full-prefix-transcript"
    }

    pub fn prove(&self, challenge: Hash) -> Result<Vec<u8>, WorkError> {
        let el = expand(challenge, 0, N * R)?;
        let er = expand(challenge, 1, R * N)?;
        let fl = expand(challenge, 2, N * R)?;
        let fr = expand(challenge, 3, R * N)?;
        let trace = self.transcript(challenge, &el, &er, &fl, &fr);
        let mut proof = self.prefix.clone();
        proof.extend_from_slice(&trace);
        Ok(proof)
    }

    fn transcript(&self, challenge: Hash, el: &[u32], er: &[u32], fl: &[u32], fr: &[u32]) -> Hash {
        // All eight contracted 64x8 factors occupy 16 KiB. Noise, the proof,
        // hashing state, and the right transpose are outside this array bound.
        let mut factors = [[0; N * R]; BLOCKS];
        let mut noise_middle = [0; R * R];
        let mut rank_middle = [0; R];
        for (block, factor) in factors.iter_mut().enumerate() {
            for i in 0..R {
                let mut rank_sum = u128::from(rank_middle[i]);
                for k in block * R..(block + 1) * R {
                    rank_sum += if self.zero_on_left {
                        u128::from(er[i * N + k]) * u128::from(self.left[k])
                    } else {
                        u128::from(self.right[k]) * u128::from(fl[k * R + i])
                    };
                }
                rank_middle[i] = producer_reduce(rank_sum);
                for j in 0..R {
                    let mut sum = u128::from(noise_middle[i * R + j]);
                    for k in block * R..(block + 1) * R {
                        sum += u128::from(er[i * N + k]) * u128::from(fl[k * R + j]);
                    }
                    noise_middle[i * R + j] = producer_reduce(sum);
                }
            }
            // Each sum contains exactly nine canonical field products, below
            // 9*q^2 < 2^68. Prefix updates are below 8*q^2+q. The existing exact
            // reducer's documented <2^70 precondition therefore holds.
            for i in 0..N {
                for j in 0..R {
                    let mut sum = if self.zero_on_left {
                        u128::from(rank_middle[j]) * u128::from(self.right[i])
                    } else {
                        u128::from(self.left[i]) * u128::from(rank_middle[j])
                    };
                    for k in 0..R {
                        sum += if self.zero_on_left {
                            u128::from(noise_middle[j * R + k]) * u128::from(fr[k * N + i])
                        } else {
                            u128::from(el[i * R + k]) * u128::from(noise_middle[k * R + j])
                        };
                    }
                    factor[i * R + j] = producer_reduce(sum);
                }
            }
        }
        if self.zero_on_left {
            emit_trace(challenge, el, &factors, true)
        } else {
            let mut right = [0; N * R];
            for i in 0..N {
                for j in 0..R {
                    right[i * R + j] = fr[j * N + i];
                }
            }
            emit_trace(challenge, &right, &factors, false)
        }
    }
}

fn emit_trace(challenge: Hash, constant: &[u32], factors: &Factors, zero_on_left: bool) -> Hash {
    let mut transcript = Sha256::new();
    transcript.update(b"TRNM-PON-TRACE1\0");
    transcript.update(challenge);
    for bi in 0..BLOCKS {
        for bj in 0..BLOCKS {
            for factor in factors {
                let (left, right) = if zero_on_left {
                    (constant, factor.as_slice())
                } else {
                    (factor.as_slice(), constant)
                };
                let mut bytes = [0u8; R * R * 4];
                for i in 0..R {
                    for j in 0..R {
                        let mut sum = 0;
                        for k in 0..R {
                            sum += u128::from(left[(bi * R + i) * R + k])
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

    fn dense_rank_one() -> Vec<u32> {
        (0..CELLS)
            .map(|position| ((position / N + 1) * (position % N + 3)) as u32)
            .collect()
    }

    #[test]
    fn only_exactly_one_zero_and_a_complete_nonzero_rank_one_material_are_supported() {
        let zero = vec![0; CELLS];
        let rank_one = dense_rank_one();
        for (a, b) in [(&zero, &rank_one), (&rank_one, &zero)] {
            assert!(BlockedOneZeroRankOnePreparedTask::new(a, b)
                .unwrap()
                .is_some());
        }
        for (a, b) in [(&zero, &zero), (&rank_one, &rank_one)] {
            assert!(BlockedOneZeroRankOnePreparedTask::new(a, b)
                .unwrap()
                .is_none());
        }
        let identity: Vec<_> = (0..CELLS).map(|p| u32::from(p / N == p % N)).collect();
        for position in [0, CELLS / 2, CELLS - 1] {
            let mut corrupted = rank_one.clone();
            corrupted[position] += 1;
            for unsupported in [&identity, &corrupted] {
                assert!(BlockedOneZeroRankOnePreparedTask::new(&zero, unsupported)
                    .unwrap()
                    .is_none());
                assert!(BlockedOneZeroRankOnePreparedTask::new(unsupported, &zero)
                    .unwrap()
                    .is_none());
            }
        }
        for (a, b) in [(&[][..], zero.as_slice()), (zero.as_slice(), &[][..])] {
            assert!(matches!(
                BlockedOneZeroRankOnePreparedTask::new(a, b),
                Err(WorkError::Length)
            ));
        }
        let invalid = vec![Q as u32; CELLS];
        for (a, b) in [(&invalid, &zero), (&zero, &invalid), (&invalid, &rank_one)] {
            assert!(matches!(
                BlockedOneZeroRankOnePreparedTask::new(a, b),
                Err(WorkError::Field)
            ));
        }
    }

    #[test]
    fn complete_proofs_and_tickets_match_scalar_generic_and_product_only_producers() {
        let zero = vec![0; CELLS];
        let rank_one = dense_rank_one();
        for (a, b) in [(&zero, &rank_one), (&rank_one, &zero)] {
            let prepared = BlockedOneZeroRankOnePreparedTask::new(a, b)
                .unwrap()
                .unwrap();
            let generic = PreparedTask::new(a, b).unwrap();
            let old = StructuredPreparedTask::new(a, b).unwrap().unwrap();
            assert_eq!(old.method(), "zero-product-full-transcript");
            let task = task_id(a, b).unwrap();
            for challenge in [
                [0; 32],
                [1; 32],
                [7; 32],
                [255; 32],
                hash(b"one-zero-test", &[b"distinct"]),
            ] {
                let proof = prepared.prove(challenge).unwrap();
                assert_eq!(proof.len(), PROOF_BYTES);
                assert_eq!(proof, prove(challenge, a, b).unwrap());
                assert_eq!(proof, generic.prove(challenge).unwrap());
                assert_eq!(proof, old.prove(challenge).unwrap());
                let ordinary = verify(challenge, task, [255; 32], &proof).unwrap();
                let reference = verify_reference(challenge, task, [255; 32], &proof).unwrap();
                assert_eq!(ordinary.ticket(), reference.ticket());
                assert_eq!(ordinary.product(), zero);
            }
        }
    }

    #[test]
    fn delayed_pivots_extreme_values_and_caller_mutation_preserve_exact_task_binding() {
        let zero = vec![0; CELLS];
        for pivot_row in [0, 7, N - 1] {
            let mut other = vec![0; CELLS];
            // Use an exact outer product with zeros before a nontrivial pivot.
            for i in pivot_row..N {
                for j in 11..N {
                    let u = Q - 1 - (i % 2) as u128;
                    let v = Q - 1 - (j % 3) as u128;
                    other[i * N + j] = (u * v % Q) as u32;
                }
            }
            for zero_on_left in [true, false] {
                let mut caller = other.clone();
                let (a, b) = if zero_on_left {
                    (&zero, &caller)
                } else {
                    (&caller, &zero)
                };
                let prepared = BlockedOneZeroRankOnePreparedTask::new(a, b)
                    .unwrap()
                    .unwrap();
                let task = task_id(a, b).unwrap();
                let before = prepared.prove([7; 32]).unwrap();
                assert_eq!(before, prove([7; 32], a, b).unwrap());
                caller[CELLS - 1] = ((u128::from(caller[CELLS - 1]) + 1) % Q) as u32;
                let changed_task = if zero_on_left {
                    task_id(&zero, &caller)
                } else {
                    task_id(&caller, &zero)
                }
                .unwrap();
                assert_eq!(prepared.prove([7; 32]).unwrap(), before);
                assert_eq!(
                    verify([7; 32], changed_task, [255; 32], &before).unwrap_err(),
                    WorkError::Task
                );
                assert_eq!(
                    verify([8; 32], task, [255; 32], &before).unwrap_err(),
                    WorkError::Transcript
                );
            }
        }
    }

    #[test]
    fn complete_certificates_match_original_independent_python_scalar_vectors() {
        let zero = vec![0; CELLS];
        let other = dense_rank_one();
        // Generated by unchanged formal/pon-nakamoto-v1/work_oracle.py, which
        // computes full noisy matrices and every canonical scalar prefix.
        for (zero_on_left, vectors) in [
            (
                true,
                [
                    (
                        0,
                        "1bb8fed8bad798f15cb6db8ef2366759314c2bb1934524ae35a9cc9c276373b1",
                    ),
                    (
                        7,
                        "e5b0c0194d0f99fcc92b441f554155434f8fed13e94a6fd72ed99aa067721dea",
                    ),
                    (
                        255,
                        "b6ce55d1f1c9a9f53f4d2802dead92d28f635b82d91a645f8b52f09b62b13ecb",
                    ),
                ],
            ),
            (
                false,
                [
                    (
                        0,
                        "1115c1c47d9bcff678d320d54640221e673d18ef575cb168b08e2ceba68d97f5",
                    ),
                    (
                        7,
                        "bb4045e6a71c9c1ca637c6fe72d21d487bdb5e00108b980d284e0877a7daa737",
                    ),
                    (
                        255,
                        "f75c3a06064224c479c6f7d3f26575b58dd365d026aab0e3a9f8510c6a7ce588",
                    ),
                ],
            ),
        ] {
            let (a, b) = if zero_on_left {
                (&zero, &other)
            } else {
                (&other, &zero)
            };
            let prepared = BlockedOneZeroRankOnePreparedTask::new(a, b)
                .unwrap()
                .unwrap();
            for (byte, expected) in vectors {
                assert_eq!(
                    hex::encode(Sha256::digest(prepared.prove([byte; 32]).unwrap())),
                    expected
                );
            }
        }
    }

    #[test]
    fn reassociated_trace_matches_every_scalar_prefix_under_extreme_noise_values() {
        let zero = vec![0; CELLS];
        let top = (Q - 1) as u32;
        let other = vec![top; CELLS];
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
            for (a, b) in [(&zero, &other), (&other, &zero)] {
                let prepared = BlockedOneZeroRankOnePreparedTask::new(a, b)
                    .unwrap()
                    .unwrap();
                let ap: Vec<_> = mul(el, er, N, R, N)
                    .into_iter()
                    .zip(a)
                    .map(|(x, y)| ((u128::from(x) + u128::from(*y)) % Q) as u32)
                    .collect();
                let bp: Vec<_> = mul(fl, fr, N, R, N)
                    .into_iter()
                    .zip(b)
                    .map(|(x, y)| ((u128::from(x) + u128::from(*y)) % Q) as u32)
                    .collect();
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
                                        sum += u128::from(ap[(bi * R + i) * N + k])
                                            * u128::from(bp[k * N + bj * R + j]);
                                    }
                                    cells[i * R + j] = (sum % Q) as u32;
                                    expected.update(cells[i * R + j].to_le_bytes());
                                }
                            }
                        }
                    }
                }
                assert_eq!(
                    prepared.transcript([case; 32], el, er, fl, fr),
                    <Hash>::from(expected.finalize())
                );
            }
        }
    }
}
