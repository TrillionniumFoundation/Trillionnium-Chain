//! Exact paid rank-bounded AB preparation. The complete challenge-dependent W1
//! transcript remains the existing kernel in `Task::attempt_with_progress`.
use super::super::{
    field_bytes, producer_mul, producer_reduce, validate, PreparedTask, WorkError, CELLS, N,
    PROOF_BYTES, Q,
};
use super::{PreparationUsed, LOW_RANK_BOUND};

struct Factors {
    rank: usize,
    left: Vec<u32>,
    right: Vec<u32>,
}

fn inverse(mut power: u32) -> u32 {
    debug_assert!(power != 0);
    // Q is the existing protocol prime. All products stay below q^2 and use
    // the existing exact reduction; there is no floating-point rank decision.
    let mut exponent = (Q - 2) as u64;
    let mut value = 1;
    while exponent != 0 {
        if exponent & 1 != 0 {
            value = producer_reduce(u128::from(value) * u128::from(power));
        }
        power = producer_reduce(u128::from(power) * u128::from(power));
        exponent >>= 1;
    }
    value
}

fn factor(matrix: &[u32]) -> Option<Factors> {
    // A caller validates ALL input words before either probe can stop early.
    // Each retained row is normalized at its own pivot and zero at every
    // earlier pivot. Pivots need not be numerically ordered (rows may begin
    // with zeros); elimination follows their discovery order.
    let mut rows: Vec<[u32; N]> = Vec::with_capacity(LOW_RANK_BOUND);
    let mut pivots = Vec::with_capacity(LOW_RANK_BOUND);
    let mut coefficients = vec![0; N * LOW_RANK_BOUND];
    for (row_index, original) in matrix.chunks_exact(N).enumerate() {
        let mut residual = [0; N];
        residual.copy_from_slice(original);
        for (basis, (&pivot, row)) in pivots.iter().zip(&rows).enumerate() {
            let scale = residual[pivot];
            coefficients[row_index * LOW_RANK_BOUND + basis] = scale;
            if scale != 0 {
                for (value, basis_value) in residual.iter_mut().zip(row) {
                    let delta = producer_reduce(u128::from(scale) * u128::from(*basis_value));
                    *value = producer_reduce(u128::from(*value) + Q - u128::from(delta));
                }
            }
        }
        if let Some(pivot) = residual.iter().position(|value| *value != 0) {
            if rows.len() == LOW_RANK_BOUND {
                // This is a proved lower bound of nine independent rows, not
                // an approximate rank or a paid-but-discarded successful task.
                return None;
            }
            let scale = residual[pivot];
            coefficients[row_index * LOW_RANK_BOUND + rows.len()] = scale;
            let reciprocal = inverse(scale);
            for value in &mut residual {
                *value = producer_reduce(u128::from(*value) * u128::from(reciprocal));
            }
            pivots.push(pivot);
            rows.push(residual);
        }
    }
    let rank = rows.len();
    Some(Factors {
        rank,
        left: coefficients
            .chunks_exact(LOW_RANK_BOUND)
            .flat_map(|row| row[..rank].iter().copied())
            .collect(),
        right: rows.into_iter().flatten().collect(),
    })
}

pub(super) fn prepare(a: &[u32], b: &[u32]) -> Result<(PreparedTask, PreparationUsed), WorkError> {
    validate(a)?;
    validate(b)?;
    let (product, used) = if let Some(factors) = factor(a) {
        let product = if factors.rank == 0 {
            vec![0; CELLS]
        } else {
            // A = U V, so AB = U (V B). Inner dimensions are at most N,
            // preserving the original exact reducer's <2^70 sum bound.
            let middle = producer_mul(&factors.right, b, factors.rank, N, N);
            producer_mul(&factors.left, &middle, N, factors.rank, N)
        };
        (product, PreparationUsed::LeftLowRank { rank: factors.rank })
    } else if let Some(factors) = factor(b) {
        let product = if factors.rank == 0 {
            vec![0; CELLS]
        } else {
            let middle = producer_mul(a, &factors.left, N, N, factors.rank);
            producer_mul(&middle, &factors.right, N, factors.rank, N)
        };
        (
            product,
            PreparationUsed::RightLowRank { rank: factors.rank },
        )
    } else {
        // Both failed probes and their temporary buffers have been paid for.
        // The fallback is explicit, and the ordinary dense constructor still
        // performs its own full validation/product/prefix work.
        return Ok((
            PreparedTask::new(a, b)?,
            PreparationUsed::DenseAfterRankBound,
        ));
    };
    let mut prefix = Vec::with_capacity(PROOF_BYTES);
    prefix.extend_from_slice(b"PNW1");
    for matrix in [a, b, product.as_slice()] {
        prefix.extend_from_slice(&field_bytes(matrix));
    }
    Ok((
        PreparedTask {
            a: a.to_vec(),
            b: b.to_vec(),
            prefix,
        },
        used,
    ))
}

#[cfg(test)]
mod tests {
    use super::super::{Arithmetic, Materialization, Progress, Task};
    use super::*;
    use crate::pon_work::{self, Hash, VerificationError, VerificationProgress};

    // A separately expressed remainder-based fixture has an identity minor,
    // so its declared rank is exact. Field extremes exercise normalization and
    // subtraction; rotated rows/columns cover nonmonotonic discovered pivots.
    fn matrix(rank: usize, shift: usize) -> Vec<u32> {
        let left: Vec<_> = (0..N * rank)
            .map(|p| {
                let (i, k) = (p / rank, p % rank);
                if i < rank {
                    u32::from(i == k)
                } else {
                    ((Q - 1 - (i * 101 + k * 17) as u128) % Q) as u32
                }
            })
            .collect();
        let right: Vec<_> = (0..rank * N)
            .map(|p| {
                let (k, j) = (p / N, p % N);
                if j < rank {
                    u32::from(j == k)
                } else {
                    ((Q - 1 - (j * 73 + k * 31) as u128) % Q) as u32
                }
            })
            .collect();
        (0..CELLS)
            .map(|p| {
                let i = (p / N + shift) % N;
                let j = (p % N + 2 * shift) % N;
                ((0..rank)
                    .map(|k| u128::from(left[i * rank + k]) * u128::from(right[k * N + j]))
                    .sum::<u128>()
                    % Q) as u32
            })
            .collect()
    }

    fn full_rank() -> Vec<u32> {
        (0..CELLS)
            .map(|p| {
                let (i, j) = (p / N, p % N);
                if i > j {
                    0
                } else if i == j {
                    (Q - 1) as u32
                } else {
                    ((Q - 1 - (i * 31 + j * 47) as u128) % Q) as u32
                }
            })
            .collect()
    }

    #[test]
    fn bounded_factorization_reconstructs_exact_full_field_rank_and_pivot_orders() {
        for rank in [0, 1, 2, 4, 8] {
            for shift in [0, 7, 63] {
                let input = matrix(rank, shift);
                let f = factor(&input).unwrap();
                assert_eq!(f.rank, rank);
                for i in 0..N {
                    for j in 0..N {
                        let observed = (0..rank)
                            .map(|k| {
                                u128::from(f.left[i * rank + k]) * u128::from(f.right[k * N + j])
                            })
                            .sum::<u128>()
                            % Q;
                        assert_eq!(
                            observed,
                            u128::from(input[i * N + j]),
                            "rank {rank}, shift {shift}, row {i}, col {j}"
                        );
                    }
                }
            }
        }
        assert!(factor(&matrix(9, 0)).is_none());
        assert!(factor(&full_rank()).is_none());
    }

    #[test]
    fn exact_rank_limit_chooses_left_then_right_and_explicit_paid_dense_fallback() {
        let dense = full_rank();
        let eight = matrix(8, 7);
        let nine = matrix(9, 0);
        for (a, b, expected) in [
            (&eight, &dense, PreparationUsed::LeftLowRank { rank: 8 }),
            (&dense, &eight, PreparationUsed::RightLowRank { rank: 8 }),
            (&nine, &dense, PreparationUsed::DenseAfterRankBound),
            (&dense, &nine, PreparationUsed::DenseAfterRankBound),
        ] {
            let actual = Task::with_rank_preparation(a, b, Arithmetic::FullLimb).unwrap();
            assert_eq!(actual.preparation_used(), expected);
            assert_eq!(
                actual.proof_prefix(),
                Task::new(a, b, Arithmetic::FullLimb)
                    .unwrap()
                    .proof_prefix()
            );
        }
        // The rank-nine identity minor is a one-cell change of rank eight.
        let mut almost = vec![0; CELLS];
        for i in 0..8 {
            almost[i * N + i] = 1;
        }
        assert_eq!(factor(&almost).unwrap().rank, 8);
        almost[8 * N + 8] = (Q - 1) as u32;
        assert!(factor(&almost).is_none());
    }

    #[test]
    fn both_inputs_are_fully_validated_before_zero_or_high_rank_shortcuts() {
        let zero = vec![0; CELLS];
        let mut invalid = full_rank();
        invalid[CELLS - 1] = Q as u32;
        for (a, b) in [(&zero, &invalid), (&invalid, &zero)] {
            assert!(matches!(prepare(a, b), Err(WorkError::Field)));
        }
        for length in [0, CELLS - 1, CELLS + 1] {
            let wrong = vec![0; length];
            for (a, b) in [(&zero, &wrong), (&wrong, &zero)] {
                assert!(matches!(prepare(a, b), Err(WorkError::Length)));
            }
        }
    }

    #[test]
    fn low_rank_complete_proofs_equal_both_original_kernels_and_verifiers() {
        let high = full_rank();
        for rank in [0, 1, 2, 4, 8, 9] {
            let low = matrix(rank, 7);
            for (a, b) in [(&low, &high), (&high, &low)] {
                let task_id = pon_work::task_id(a, b).unwrap();
                for arithmetic in [Arithmetic::Transposed, Arithmetic::FullLimb] {
                    let task = Task::with_rank_preparation(a, b, arithmetic).unwrap();
                    for context in [[0; 32], [255; 32]] {
                        let proof = task
                            .attempt(context, [255; 32], Materialization::TargetHit)
                            .unwrap()
                            .proof
                            .unwrap();
                        assert_eq!(proof, pon_work::prove(context, a, b).unwrap());
                        let production =
                            pon_work::verify(context, task_id, [255; 32], &proof).unwrap();
                        let reference =
                            pon_work::verify_reference(context, task_id, [255; 32], &proof)
                                .unwrap();
                        assert_eq!(production.product(), reference.product());
                    }
                }
            }
        }
    }

    #[test]
    fn misses_still_replay_all_tiles_and_cancelled_retries_preserve_the_same_task() {
        let a = matrix(4, 7);
        let b = full_rank();
        let task = Task::with_rank_preparation(&a, &b, Arithmetic::FullLimb).unwrap();
        let dense = Task::new(&a, &b, Arithmetic::FullLimb).unwrap();
        let mut target = [0; 32];
        target[31] = 1;
        for mode in [Materialization::EveryAttempt, Materialization::TargetHit] {
            let mut actual_points = Vec::new();
            let actual = task
                .attempt_with_progress([3; 32], target, mode, |p| {
                    actual_points.push(p);
                    Ok::<_, ()>(())
                })
                .unwrap();
            let mut expected_points = Vec::new();
            let expected = dense
                .attempt_with_progress([3; 32], target, mode, |p| {
                    expected_points.push(p);
                    Ok::<_, ()>(())
                })
                .unwrap();
            assert_eq!(actual, expected);
            assert!(!actual.target_hit);
            assert_eq!(actual_points, expected_points);
            assert_eq!(
                actual_points
                    .iter()
                    .filter(|p| matches!(
                        p,
                        Progress::Replay(VerificationProgress::TranscriptTile { .. })
                    ))
                    .count(),
                512
            );
            for cut in [0, actual_points.len() / 2, actual_points.len() - 1] {
                let mut seen = 0;
                let failed = task.attempt_with_progress([3; 32], target, mode, |_| {
                    let here = seen;
                    seen += 1;
                    if here == cut {
                        Err(cut)
                    } else {
                        Ok(())
                    }
                });
                assert_eq!(failed, Err(VerificationError::Cancelled(cut)));
                assert_eq!(seen, cut + 1);
                assert_eq!(task.attempt([3; 32], target, mode).unwrap(), expected);
            }
        }
        let mut called = false;
        assert_eq!(
            task.attempt_with_progress(
                [0; 32],
                Hash::default(),
                Materialization::TargetHit,
                |_| {
                    called = true;
                    Ok::<_, ()>(())
                }
            ),
            Err(VerificationError::Relation(WorkError::Target))
        );
        assert!(!called);
    }
}
