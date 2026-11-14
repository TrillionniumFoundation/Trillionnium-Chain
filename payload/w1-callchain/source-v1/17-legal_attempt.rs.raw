//! Experimental complete legal attempts with independent arithmetic and proof
//! materialization choices. None of these producer values is verified work.
//!
//! Every attempt computes the complete original challenge-bound transcript.
//! A losing ticket need not allocate its otherwise fixed PNW1 proof bytes.
//! Caching AB and delaying serialization do not change the relation or lottery.
use super::{
    evaluate_transcript_kernel_with_progress, field_bytes, hash, producer_reduce, relation_only,
    validate, Hash, PreparedTask, VerificationError, VerificationProgress, WorkError, CELLS, N,
    PROOF_BYTES,
};

mod low_rank;

/// Fixed diagnostic factorization limit. Detection, rejection and any dense
/// fallback are all part of task preparation, never free eligibility advice.
pub const LOW_RANK_BOUND: usize = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Arithmetic {
    Transposed,
    FullLimb,
}

/// Explicit fixed-product preparation, independent of challenge arithmetic.
/// Sparse skips only products with a zero operand after validating every word.
/// Neither choice skips any challenge-bound transcript tile or grants authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Preparation {
    Dense,
    Sparse,
}

/// Actual fixed-product constructor selected by a paid preparation. These
/// observations grant no work validity or protocol task eligibility.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PreparationUsed {
    Dense,
    Sparse,
    /// Both operands were proved to have exact rank one, then AB was formed
    /// as u(v^T x)y^T; this is distinct from the rank-bounded one-sided probe.
    CheckedRankOne,
    LeftLowRank {
        rank: usize,
    },
    RightLowRank {
        rank: usize,
    },
    DenseAfterRankBound,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Materialization {
    EveryAttempt,
    TargetHit,
}

/// Local producer cancellation points, never consensus invalidity or authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Progress {
    BeforeReplay,
    Replay(VerificationProgress),
    BeforeTicket,
    BeforeProof,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Attempt {
    pub challenge: Hash,
    pub trace: Hash,
    pub ticket: Hash,
    pub target_hit: bool,
    /// An eager miss has bytes; a lazy miss does not. Every hit has full bytes.
    /// These are locally generated, unverified bytes, not a VerifiedWork value.
    pub proof: Option<Vec<u8>>,
}

pub struct Task {
    prepared: PreparedTask,
    arithmetic: Arithmetic,
    preparation_used: PreparationUsed,
}

impl Task {
    /// Both arithmetic choices pay the same original AB/prefix preparation.
    /// Only the challenge-dependent transcript kernel differs in this experiment.
    pub fn new(a: &[u32], b: &[u32], arithmetic: Arithmetic) -> Result<Self, WorkError> {
        Self::with_preparation(a, b, arithmetic, Preparation::Dense)
    }

    /// The separately selected sparse arm pays its actual input scan, sparse
    /// index, complete fixed product and proof-prefix construction once. It
    /// supports all canonical fields, not just small integers or the model
    /// fixture. The original constructor and native producer remain dense.
    pub fn with_preparation(
        a: &[u32],
        b: &[u32],
        arithmetic: Arithmetic,
        preparation: Preparation,
    ) -> Result<Self, WorkError> {
        let (prepared, preparation_used) = match preparation {
            Preparation::Dense => (PreparedTask::new(a, b)?, PreparationUsed::Dense),
            Preparation::Sparse => (sparse_preparation(a, b)?, PreparationUsed::Sparse),
        };
        Ok(Self {
            prepared,
            arithmetic,
            preparation_used,
        })
    }

    /// Pay for exact rank-one recognition and the factored fixed AB product.
    /// Both matrices must have rank exactly one over the canonical field;
    /// rank zero and other unsupported inputs return None, never a dense
    /// fallback. Invalid lengths/words remain errors even when the other
    /// operand is unsupported or their mathematical product would be zero.
    /// The selected challenge transcript arithmetic is unchanged.
    pub fn with_rank_one_preparation(
        a: &[u32],
        b: &[u32],
        arithmetic: Arithmetic,
    ) -> Result<Option<Self>, WorkError> {
        validate(a)?;
        validate(b)?;
        let (Some((left_a, right_a)), Some((left_b, right_b))) = (
            super::structured::rank_one(a),
            super::structured::rank_one(b),
        ) else {
            return Ok(None);
        };
        // Recognition checked EVERY original word. For A=u*v^T, B=x*y^T,
        // AB=u*(v^T*x)*y^T; the dot product has 64 canonical products and
        // is below 2^70, within the original exact reducer's bound.
        let scale = producer_reduce(
            right_a
                .iter()
                .zip(left_b)
                .map(|(left, right)| u128::from(*left) * u128::from(right))
                .sum(),
        );
        let mut product = Vec::with_capacity(CELLS);
        for left in left_a {
            let scaled = producer_reduce(u128::from(left) * u128::from(scale));
            for &right in &right_b {
                product.push(producer_reduce(u128::from(scaled) * u128::from(right)));
            }
        }
        let mut prefix = Vec::with_capacity(PROOF_BYTES);
        prefix.extend_from_slice(b"PNW1");
        for matrix in [a, b, product.as_slice()] {
            prefix.extend_from_slice(&field_bytes(matrix));
        }
        Ok(Some(Self {
            prepared: PreparedTask {
                a: a.to_vec(),
                b: b.to_vec(),
                prefix,
            },
            arithmetic,
            preparation_used: PreparationUsed::CheckedRankOne,
        }))
    }

    /// Explicit new constructor, preserving the original two-arm preparation
    /// API and every old experiment selector. Try exact left rank <= 8, then
    /// right rank <= 8; pay ordinary dense preparation after both failed
    /// probes. No tolerance, factor witness or challenge result is trusted.
    pub fn with_rank_preparation(
        a: &[u32],
        b: &[u32],
        arithmetic: Arithmetic,
    ) -> Result<Self, WorkError> {
        let (prepared, preparation_used) = low_rank::prepare(a, b)?;
        Ok(Self {
            prepared,
            arithmetic,
            preparation_used,
        })
    }

    pub fn preparation_used(&self) -> PreparationUsed {
        self.preparation_used
    }

    /// Fixed mathematical bytes for separately timed evidence reconstruction.
    /// Access grants no task eligibility or acceptance of any transcript.
    pub fn proof_prefix(&self) -> &[u8] {
        &self.prepared.prefix
    }

    pub fn attempt(
        &self,
        challenge: Hash,
        target: Hash,
        materialization: Materialization,
    ) -> Result<Attempt, WorkError> {
        relation_only(
            self.attempt_with_progress(challenge, target, materialization, |_| {
                Ok::<_, std::convert::Infallible>(())
            }),
        )
    }

    pub fn attempt_with_progress<E>(
        &self,
        challenge: Hash,
        target: Hash,
        materialization: Materialization,
        mut progress: impl FnMut(Progress) -> Result<(), E>,
    ) -> Result<Attempt, VerificationError<E>> {
        if target == [0; 32] {
            return Err(WorkError::Target.into());
        }
        progress(Progress::BeforeReplay).map_err(VerificationError::Cancelled)?;
        let mut replay = |point| progress(Progress::Replay(point));
        let evaluated = match self.arithmetic {
            Arithmetic::Transposed => {
                evaluate_transcript_kernel_with_progress::<false, false, false, E>(
                    challenge,
                    &self.prepared.a,
                    &self.prepared.b,
                    &mut replay,
                )?
            }
            Arithmetic::FullLimb => {
                evaluate_transcript_kernel_with_progress::<true, false, true, E>(
                    challenge,
                    &self.prepared.a,
                    &self.prepared.b,
                    &mut replay,
                )?
            }
        };
        let trace = evaluated.trace;
        // All transcript intermediates are destroyed within the attempt. There
        // is no paid-in-a-later-cohort buffer or cross-challenge replay cache.
        drop(evaluated);
        let mut proof = None;
        if materialization == Materialization::EveryAttempt {
            progress(Progress::BeforeProof).map_err(VerificationError::Cancelled)?;
            let mut bytes = self.prepared.prefix.clone();
            bytes.extend_from_slice(&trace);
            proof = Some(bytes);
        }
        progress(Progress::BeforeTicket).map_err(VerificationError::Cancelled)?;
        let ticket = hash(b"ticket", &[&challenge, &trace]);
        let target_hit = ticket <= target;
        if materialization == Materialization::TargetHit && target_hit {
            progress(Progress::BeforeProof).map_err(VerificationError::Cancelled)?;
            let mut bytes = self.prepared.prefix.clone();
            bytes.extend_from_slice(&trace);
            proof = Some(bytes);
        }
        Ok(Attempt {
            challenge,
            trace,
            ticket,
            target_hit,
            proof,
        })
    }
}

fn sparse_preparation(a: &[u32], b: &[u32]) -> Result<PreparedTask, WorkError> {
    // A malformed word is an error even in a row/column whose product would be
    // zero. No modular canonicalization or implicit model-range trust is used.
    validate(a)?;
    validate(b)?;
    let right_rows: Vec<Vec<(usize, u32)>> = b
        .chunks_exact(N)
        .map(|row| {
            row.iter()
                .copied()
                .enumerate()
                .filter(|(_, value)| *value != 0)
                .collect()
        })
        .collect();
    let mut product = vec![0; CELLS];
    for (left, output) in a.chunks_exact(N).zip(product.chunks_exact_mut(N)) {
        let mut sums = [0_u128; N];
        for (k, &value) in left.iter().enumerate() {
            if value == 0 {
                continue;
            }
            for &(column, right) in &right_rows[k] {
                sums[column] += u128::from(value) * u128::from(right);
            }
        }
        // Each sum has at most 64 canonical products: 64*(q-1)^2 < 2^70,
        // within the original exact reducer's bound even for dense extremes.
        for (value, sum) in output.iter_mut().zip(sums) {
            *value = producer_reduce(sum);
        }
    }
    let mut prefix = Vec::with_capacity(PROOF_BYTES);
    prefix.extend_from_slice(b"PNW1");
    for matrix in [a, b, product.as_slice()] {
        prefix.extend_from_slice(&field_bytes(matrix));
    }
    Ok(PreparedTask {
        a: a.to_vec(),
        b: b.to_vec(),
        prefix,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pon_work::{self, CELLS, N, PROOF_BYTES, Q};

    fn contexts() -> [Hash; 3] {
        [[0; 32], [7; 32], [255; 32]]
    }

    fn outer(left: &[u32], right: &[u32]) -> Vec<u32> {
        left.iter()
            .flat_map(|x| {
                right
                    .iter()
                    .map(|y| producer_reduce(u128::from(*x) * u128::from(*y)))
            })
            .collect()
    }

    fn rank_one_pairs() -> Vec<(Vec<u32>, Vec<u32>)> {
        let high: Vec<_> = (0..N).map(|i| Q as u32 - 1 - i as u32).collect();
        let low: Vec<_> = (0..N).map(|i| (17 * i + 3) as u32).collect();
        let sparse: Vec<_> = (0..N)
            .map(|i| if i % 7 == 3 { high[i] } else { 0 })
            .collect();
        let mut v = vec![0; N];
        let mut x = vec![0; N];
        v[3] = 1;
        v[9] = 1;
        x[3] = 1;
        x[9] = Q as u32 - 1;
        vec![
            (outer(&high, &low), outer(&low, &high)),
            (outer(&sparse, &high), outer(&low, &sparse)),
            // Nonzero rank-one operands whose complete AB is zero.
            (outer(&high, &v), outer(&x, &low)),
        ]
    }

    #[test]
    fn checked_rank_one_preparation_matches_dense_sparse_and_independent_replay() {
        for (a, b) in rank_one_pairs() {
            let id = pon_work::task_id(&a, &b).unwrap();
            for arithmetic in [Arithmetic::Transposed, Arithmetic::FullLimb] {
                let rank = Task::with_rank_one_preparation(&a, &b, arithmetic)
                    .unwrap()
                    .unwrap();
                let dense = Task::new(&a, &b, arithmetic).unwrap();
                let sparse =
                    Task::with_preparation(&a, &b, arithmetic, Preparation::Sparse).unwrap();
                assert_eq!(rank.proof_prefix(), dense.proof_prefix());
                assert_eq!(rank.proof_prefix(), sparse.proof_prefix());
                for challenge in [[0; 32], [255; 32]] {
                    let expected = pon_work::prove(challenge, &a, &b).unwrap();
                    let actual = rank
                        .attempt(challenge, [255; 32], Materialization::TargetHit)
                        .unwrap();
                    assert_eq!(actual.proof.as_ref().unwrap(), &expected);
                    assert_eq!(
                        actual,
                        dense
                            .attempt(challenge, [255; 32], Materialization::TargetHit)
                            .unwrap()
                    );
                    assert_eq!(
                        actual,
                        sparse
                            .attempt(challenge, [255; 32], Materialization::TargetHit)
                            .unwrap()
                    );
                    let cold = Task::with_rank_one_preparation(&a, &b, arithmetic)
                        .unwrap()
                        .unwrap();
                    assert_eq!(
                        actual,
                        cold.attempt(challenge, [255; 32], Materialization::TargetHit)
                            .unwrap()
                    );
                    for verify in [pon_work::verify, pon_work::verify_reference] {
                        let work = verify(challenge, id, [255; 32], &expected).unwrap();
                        assert_eq!(work.challenge(), challenge);
                        assert_eq!(work.task(), id);
                        assert_eq!(work.ticket(), actual.ticket);
                        assert_eq!(
                            field_bytes(work.product()),
                            expected[4 + 2 * CELLS * 4..PROOF_BYTES - 32]
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn checked_rank_one_and_bounded_rank_preparation_share_bytes_but_keep_distinct_domains() {
        for (a, b) in rank_one_pairs() {
            let specialized = Task::with_rank_one_preparation(&a, &b, Arithmetic::FullLimb)
                .unwrap()
                .unwrap();
            let general = Task::with_rank_preparation(&a, &b, Arithmetic::FullLimb).unwrap();
            assert_eq!(
                specialized.preparation_used(),
                PreparationUsed::CheckedRankOne
            );
            assert_eq!(
                general.preparation_used(),
                PreparationUsed::LeftLowRank { rank: 1 }
            );
            assert_eq!(specialized.proof_prefix(), general.proof_prefix());
            let challenge = [0x65; 32];
            let original = pon_work::prove(challenge, &a, &b).unwrap();
            let mut specialized_points = Vec::new();
            let actual = specialized
                .attempt_with_progress(challenge, [255; 32], Materialization::TargetHit, |point| {
                    specialized_points.push(point);
                    Ok::<_, ()>(())
                })
                .unwrap();
            let mut general_points = Vec::new();
            let other = general
                .attempt_with_progress(challenge, [255; 32], Materialization::TargetHit, |point| {
                    general_points.push(point);
                    Ok::<_, ()>(())
                })
                .unwrap();
            assert_eq!(actual, other);
            assert_eq!(actual.proof.as_ref().unwrap(), &original);
            assert_eq!(specialized_points, general_points);
            assert_eq!(
                specialized_points
                    .iter()
                    .filter(|point| matches!(
                        point,
                        Progress::Replay(VerificationProgress::TranscriptTile { .. })
                    ))
                    .count(),
                512
            );
            let id = pon_work::task_id(&a, &b).unwrap();
            // Both independently implemented full verifiers check the actual
            // generated bytes; constructor agreement alone is not acceptance.
            for verify in [pon_work::verify, pon_work::verify_reference] {
                let work =
                    verify(challenge, id, [255; 32], actual.proof.as_ref().unwrap()).unwrap();
                assert_eq!(work.challenge(), challenge);
                assert_eq!(work.task(), id);
                assert_eq!(work.ticket(), actual.ticket);
                assert_eq!(
                    field_bytes(work.product()),
                    original[4 + 2 * CELLS * 4..PROOF_BYTES - 32]
                );
            }
            let mut near_zero_target = [0; 32];
            near_zero_target[31] = 1;
            let miss = specialized
                .attempt([0x66; 32], near_zero_target, Materialization::EveryAttempt)
                .unwrap();
            assert!(!miss.target_hit);
            assert_eq!(
                miss,
                general
                    .attempt([0x66; 32], near_zero_target, Materialization::EveryAttempt)
                    .unwrap()
            );
            assert_eq!(
                miss.proof.as_ref().unwrap(),
                &pon_work::prove([0x66; 32], &a, &b).unwrap()
            );
        }
        let (rank, _) = rank_one_pairs().remove(0);
        let zero = vec![0; CELLS];
        let identity: Vec<_> = (0..CELLS).map(|i| u32::from(i / N == i % N)).collect();
        for (a, b, expected) in [
            (&zero, &rank, PreparationUsed::LeftLowRank { rank: 0 }),
            (&identity, &rank, PreparationUsed::RightLowRank { rank: 1 }),
            (&rank, &identity, PreparationUsed::LeftLowRank { rank: 1 }),
            (&identity, &identity, PreparationUsed::DenseAfterRankBound),
        ] {
            assert!(Task::with_rank_one_preparation(a, b, Arithmetic::FullLimb)
                .unwrap()
                .is_none());
            let general = Task::with_rank_preparation(a, b, Arithmetic::FullLimb).unwrap();
            assert_eq!(general.preparation_used(), expected);
            assert_eq!(
                general.proof_prefix(),
                Task::new(a, b, Arithmetic::FullLimb)
                    .unwrap()
                    .proof_prefix()
            );
        }
    }

    #[test]
    fn checked_rank_one_preparation_refuses_other_ranks_and_hidden_malformed_words() {
        let (rank, _) = rank_one_pairs().remove(0);
        let zero = vec![0; CELLS];
        let identity: Vec<_> = (0..CELLS).map(|i| u32::from(i / N == i % N)).collect();
        let mut changed = rank.clone();
        changed[CELLS - 1] = (changed[CELLS - 1] + 1) % Q as u32;
        for arithmetic in [Arithmetic::Transposed, Arithmetic::FullLimb] {
            for unsupported in [&zero, &identity, &changed] {
                for (a, b) in [(unsupported, &rank), (&rank, unsupported)] {
                    assert!(Task::with_rank_one_preparation(a, b, arithmetic)
                        .unwrap()
                        .is_none());
                }
            }
            let mut malformed = rank.clone();
            malformed[CELLS - 1] = Q as u32;
            for other in [&zero, &identity, &rank] {
                for (a, b) in [(other, &malformed), (&malformed, other)] {
                    assert!(matches!(
                        Task::with_rank_one_preparation(a, b, arithmetic),
                        Err(WorkError::Field)
                    ));
                }
            }
            for length in [0, CELLS - 1, CELLS + 1] {
                let bad = vec![0; length];
                for (a, b) in [(&rank, &bad), (&bad, &rank)] {
                    assert!(matches!(
                        Task::with_rank_one_preparation(a, b, arithmetic),
                        Err(WorkError::Length)
                    ));
                }
            }
        }
    }

    #[test]
    fn checked_rank_one_preparation_preserves_complete_misses_and_cancellation() {
        let (a, b) = rank_one_pairs().remove(1);
        let rank = Task::with_rank_one_preparation(&a, &b, Arithmetic::FullLimb)
            .unwrap()
            .unwrap();
        let dense = Task::new(&a, &b, Arithmetic::FullLimb).unwrap();
        let mut target = [0; 32];
        target[31] = 1;
        for mode in [Materialization::EveryAttempt, Materialization::TargetHit] {
            let mut expected_points = Vec::new();
            let expected = dense
                .attempt_with_progress([3; 32], target, mode, |point| {
                    expected_points.push(point);
                    Ok::<_, ()>(())
                })
                .unwrap();
            let mut points = Vec::new();
            let actual = rank
                .attempt_with_progress([3; 32], target, mode, |point| {
                    points.push(point);
                    Ok::<_, ()>(())
                })
                .unwrap();
            assert!(!actual.target_hit);
            assert_eq!(actual, expected);
            assert_eq!(points, expected_points);
            let tiles: Vec<_> = points
                .iter()
                .enumerate()
                .filter_map(|(index, p)| {
                    matches!(
                        p,
                        Progress::Replay(VerificationProgress::TranscriptTile { .. })
                    )
                    .then_some(index)
                })
                .collect();
            assert_eq!(tiles.len(), 512);
            for cut in [0, tiles[0], *tiles.last().unwrap(), points.len() - 1] {
                let mut called = 0;
                let result = rank.attempt_with_progress([3; 32], target, mode, |_| {
                    let index = called;
                    called += 1;
                    if index == cut {
                        Err(cut)
                    } else {
                        Ok(())
                    }
                });
                assert_eq!(result, Err(VerificationError::Cancelled(cut)));
                assert_eq!(called, cut + 1);
                assert_eq!(rank.attempt([3; 32], target, mode).unwrap(), expected);
            }
        }
    }

    #[test]
    fn checked_rank_one_reuse_rejects_changed_challenge_transcript_and_product() {
        let (a, b) = rank_one_pairs().remove(0);
        let rank = Task::with_rank_one_preparation(&a, &b, Arithmetic::FullLimb)
            .unwrap()
            .unwrap();
        let id = pon_work::task_id(&a, &b).unwrap();
        let first = rank
            .attempt([11; 32], [255; 32], Materialization::TargetHit)
            .unwrap();
        let second = rank
            .attempt([12; 32], [255; 32], Materialization::TargetHit)
            .unwrap();
        assert_ne!(first.trace, second.trace);
        assert_ne!(first.ticket, second.ticket);
        let proof = first.proof.unwrap();
        let mut trace_mutation = proof.clone();
        trace_mutation[PROOF_BYTES - 1] ^= 1;
        let mut product_mutation = proof.clone();
        let offset = PROOF_BYTES - 36;
        let before = u32::from_le_bytes(proof[offset..offset + 4].try_into().unwrap());
        product_mutation[offset..offset + 4]
            .copy_from_slice(&((before + 1) % Q as u32).to_le_bytes());
        for verify in [pon_work::verify, pon_work::verify_reference] {
            assert_eq!(
                verify([12; 32], id, [255; 32], &proof).unwrap_err(),
                WorkError::Transcript
            );
            assert_eq!(
                verify([11; 32], id, [255; 32], &trace_mutation).unwrap_err(),
                WorkError::Transcript
            );
            assert_eq!(
                verify([11; 32], id, [255; 32], &product_mutation).unwrap_err(),
                WorkError::Product
            );
            assert_eq!(
                verify([11; 32], [0; 32], [255; 32], &proof).unwrap_err(),
                WorkError::Task
            );
        }
    }

    #[test]
    fn factorial_kernels_match_independent_reference_for_full_and_structured_fields() {
        let zero = vec![0; CELLS];
        let edge: Vec<u32> = (0..CELLS)
            .map(|i| {
                if i.is_multiple_of(3) {
                    Q as u32 - 1
                } else {
                    i as u32
                }
            })
            .collect();
        let rank: Vec<u32> = (0..CELLS)
            .map(|i| ((i / N + 1) * (i % N + 2)) as u32)
            .collect();
        for (a, b) in [
            (&edge, &rank),
            (&zero, &zero),
            (&zero, &rank),
            (&rank, &zero),
        ] {
            let task_id = pon_work::task_id(a, b).unwrap();
            for context in contexts() {
                let expected = pon_work::prove(context, a, b).unwrap();
                for arithmetic in [Arithmetic::Transposed, Arithmetic::FullLimb] {
                    let task = Task::new(a, b, arithmetic).unwrap();
                    for materialization in
                        [Materialization::EveryAttempt, Materialization::TargetHit]
                    {
                        let actual = task.attempt(context, [255; 32], materialization).unwrap();
                        assert!(actual.target_hit);
                        assert_eq!(actual.challenge, context);
                        assert_eq!(actual.proof.as_ref().unwrap(), &expected);
                        assert_eq!(actual.trace.as_slice(), &expected[PROOF_BYTES - 32..]);
                        assert_eq!(actual.ticket, hash(b"ticket", &[&context, &actual.trace]));
                        let accepted = pon_work::verify_reference(
                            context,
                            task_id,
                            [255; 32],
                            actual.proof.as_ref().unwrap(),
                        )
                        .unwrap();
                        assert_eq!(accepted.challenge(), context);
                        assert_eq!(accepted.task(), task_id);
                        assert_eq!(accepted.ticket(), actual.ticket);
                    }
                }
            }
        }
    }

    #[test]
    fn losing_attempt_still_replays_every_transcript_tile_without_lazy_serialization() {
        let zero = vec![0; CELLS];
        let mut target = [0; 32];
        target[31] = 1;
        for arithmetic in [Arithmetic::Transposed, Arithmetic::FullLimb] {
            let task = Task::new(&zero, &zero, arithmetic).unwrap();
            let mut identities = Vec::new();
            for materialization in [Materialization::EveryAttempt, Materialization::TargetHit] {
                let mut points = Vec::new();
                let attempt = task
                    .attempt_with_progress([3; 32], target, materialization, |point| {
                        points.push(point);
                        Ok::<_, ()>(())
                    })
                    .unwrap();
                assert!(!attempt.target_hit);
                assert_eq!(
                    points
                        .iter()
                        .filter(|p| matches!(
                            p,
                            Progress::Replay(VerificationProgress::TranscriptTile { .. })
                        ))
                        .count(),
                    512
                );
                assert_eq!(
                    points.contains(&Progress::BeforeProof),
                    materialization == Materialization::EveryAttempt
                );
                assert_eq!(
                    attempt.proof.is_some(),
                    materialization == Materialization::EveryAttempt
                );
                identities.push((attempt.challenge, attempt.trace, attempt.ticket));
            }
            assert_eq!(identities[0], identities[1]);
        }
    }

    #[test]
    fn every_stage_cancellation_returns_no_attempt_and_does_not_poison_retry() {
        let zero = vec![0; CELLS];
        for arithmetic in [Arithmetic::Transposed, Arithmetic::FullLimb] {
            let task = Task::new(&zero, &zero, arithmetic).unwrap();
            for mode in [Materialization::EveryAttempt, Materialization::TargetHit] {
                let baseline = task.attempt([9; 32], [255; 32], mode).unwrap();
                let mut all = Vec::new();
                task.attempt_with_progress([9; 32], [255; 32], mode, |p| {
                    all.push(p);
                    Ok::<_, ()>(())
                })
                .unwrap();
                // First/last noise expansion, matrix row and transcript tile,
                // plus each boundary: cancellation covers actual work stages.
                let mut cuts = vec![0, all.len() - 1];
                for predicate in [
                    (|p: &Progress| {
                        matches!(p, Progress::Replay(VerificationProgress::Noise { .. }))
                    }) as fn(&Progress) -> bool,
                    |p| matches!(p, Progress::Replay(VerificationProgress::MatrixRow { .. })),
                    |p| {
                        matches!(
                            p,
                            Progress::Replay(VerificationProgress::TranscriptTile { .. })
                        )
                    },
                    |p| *p == Progress::BeforeTicket,
                    |p| *p == Progress::BeforeProof,
                ] {
                    cuts.extend(all.iter().position(predicate));
                    cuts.extend(all.iter().rposition(predicate));
                }
                cuts.sort_unstable();
                cuts.dedup();
                for cut in cuts {
                    let mut observed = 0;
                    let result = task.attempt_with_progress([9; 32], [255; 32], mode, |_| {
                        let index = observed;
                        observed += 1;
                        if index == cut {
                            Err(cut)
                        } else {
                            Ok(())
                        }
                    });
                    assert_eq!(result, Err(VerificationError::Cancelled(cut)));
                    assert_eq!(observed, cut + 1);
                    assert_eq!(task.attempt([9; 32], [255; 32], mode).unwrap(), baseline);
                }
            }
        }
    }

    #[test]
    fn changed_challenge_and_task_never_gain_acceptance_from_cached_product() {
        let zero = vec![0; CELLS];
        let task_id = pon_work::task_id(&zero, &zero).unwrap();
        let task = Task::new(&zero, &zero, Arithmetic::FullLimb).unwrap();
        let first = task
            .attempt([11; 32], [255; 32], Materialization::TargetHit)
            .unwrap();
        let second = task
            .attempt([12; 32], [255; 32], Materialization::TargetHit)
            .unwrap();
        assert_ne!(first.trace, second.trace);
        assert_ne!(first.ticket, second.ticket);
        assert_eq!(
            pon_work::verify_reference([12; 32], task_id, [255; 32], first.proof.as_ref().unwrap())
                .unwrap_err(),
            WorkError::Transcript
        );
        assert_eq!(
            pon_work::verify_reference([11; 32], [0; 32], [255; 32], first.proof.as_ref().unwrap())
                .unwrap_err(),
            WorkError::Task
        );
    }

    #[test]
    fn boundary_target_is_inclusive_and_zero_target_refuses_before_work() {
        let zero = vec![0; CELLS];
        let task = Task::new(&zero, &zero, Arithmetic::Transposed).unwrap();
        let first = task
            .attempt([1; 32], [255; 32], Materialization::TargetHit)
            .unwrap();
        assert!(
            task.attempt([1; 32], first.ticket, Materialization::TargetHit)
                .unwrap()
                .target_hit
        );
        let mut called = false;
        assert_eq!(
            task.attempt_with_progress([1; 32], [0; 32], Materialization::TargetHit, |_| {
                called = true;
                Ok::<_, ()>(())
            }),
            Err(VerificationError::Relation(WorkError::Target))
        );
        assert!(!called);
    }

    #[test]
    fn preparation_never_reduces_noncanonical_fields_or_wrong_shapes() {
        let zero = vec![0; CELLS];
        for arithmetic in [Arithmetic::Transposed, Arithmetic::FullLimb] {
            assert!(matches!(
                Task::new(&[], &zero, arithmetic),
                Err(WorkError::Length)
            ));
            assert!(matches!(
                Task::new(&zero, &vec![Q as u32; CELLS], arithmetic),
                Err(WorkError::Field)
            ));
        }
    }

    #[test]
    fn sparse_preparation_matches_dense_and_independent_full_field_proofs() {
        let zero = vec![0; CELLS];
        let high = vec![Q as u32 - 1; CELLS];
        let sparse_left: Vec<_> = (0..CELLS)
            .map(|i| match i % 11 {
                0 => Q as u32 - 1,
                1 => (i as u32 * 219_613) % Q as u32,
                _ => 0,
            })
            .collect();
        let sparse_right: Vec<_> = (0..CELLS)
            .map(|i| match i % 13 {
                0 => Q as u32 - 7,
                1 => 8,
                _ => 0,
            })
            .collect();
        let padded: Vec<_> = (0..CELLS)
            .map(|i| if i / N < 15 && i % N == 0 { 237 } else { 0 })
            .collect();
        let bias: Vec<_> = (0..CELLS).map(|i| u32::from(i / N == 0)).collect();
        for (a, b) in [
            (&zero, &zero),
            (&zero, &high),
            (&high, &zero),
            (&high, &high),
            (&sparse_left, &sparse_right),
            (&padded, &bias),
        ] {
            let task_id = pon_work::task_id(a, b).unwrap();
            for arithmetic in [Arithmetic::Transposed, Arithmetic::FullLimb] {
                let dense = Task::new(a, b, arithmetic).unwrap();
                let sparse = Task::with_preparation(a, b, arithmetic, Preparation::Sparse).unwrap();
                assert_eq!(dense.proof_prefix(), sparse.proof_prefix());
                for challenge in [[0; 32], [255; 32]] {
                    let expected = pon_work::prove(challenge, a, b).unwrap();
                    let attempt = sparse
                        .attempt(challenge, [255; 32], Materialization::TargetHit)
                        .unwrap();
                    assert_eq!(attempt.proof.as_ref().unwrap(), &expected);
                    assert_eq!(
                        attempt,
                        dense
                            .attempt(challenge, [255; 32], Materialization::TargetHit)
                            .unwrap()
                    );
                    let native =
                        pon_work::verify(challenge, task_id, [255; 32], &expected).unwrap();
                    let reference =
                        pon_work::verify_reference(challenge, task_id, [255; 32], &expected)
                            .unwrap();
                    assert_eq!(native.product(), reference.product());
                }
            }
        }
    }

    #[test]
    fn sparse_preparation_rejects_hidden_noncanonical_words_and_wrong_lengths() {
        let zero = vec![0; CELLS];
        let mut malformed = zero.clone();
        // The invalid value is deliberately outside the active model rows and
        // has a zero multiplication partner. It must still be rejected.
        malformed[CELLS - 1] = Q as u32;
        for arithmetic in [Arithmetic::Transposed, Arithmetic::FullLimb] {
            for (a, b) in [(&zero, &malformed), (&malformed, &zero)] {
                assert!(matches!(
                    Task::with_preparation(a, b, arithmetic, Preparation::Sparse),
                    Err(WorkError::Field)
                ));
            }
            for length in [0, CELLS - 1, CELLS + 1] {
                let bad_length = vec![0; length];
                for (a, b) in [(&zero, &bad_length), (&bad_length, &zero)] {
                    assert!(matches!(
                        Task::with_preparation(a, b, arithmetic, Preparation::Sparse),
                        Err(WorkError::Length)
                    ));
                }
            }
        }
    }

    #[test]
    fn sparse_setup_keeps_complete_misses_callbacks_and_cancelled_retry() {
        let zero = vec![0; CELLS];
        let mut target = [0; 32];
        target[31] = 1;
        for arithmetic in [Arithmetic::Transposed, Arithmetic::FullLimb] {
            let dense = Task::new(&zero, &zero, arithmetic).unwrap();
            let sparse =
                Task::with_preparation(&zero, &zero, arithmetic, Preparation::Sparse).unwrap();
            for materialization in [Materialization::TargetHit, Materialization::EveryAttempt] {
                let mut expected_points = Vec::new();
                let expected = dense
                    .attempt_with_progress([3; 32], target, materialization, |point| {
                        expected_points.push(point);
                        Ok::<_, ()>(())
                    })
                    .unwrap();
                let mut points = Vec::new();
                let actual = sparse
                    .attempt_with_progress([3; 32], target, materialization, |point| {
                        points.push(point);
                        Ok::<_, ()>(())
                    })
                    .unwrap();
                assert!(!actual.target_hit);
                assert_eq!(actual, expected);
                assert_eq!(points, expected_points);
                assert_eq!(
                    points
                        .iter()
                        .filter(|p| matches!(
                            p,
                            Progress::Replay(VerificationProgress::TranscriptTile { .. })
                        ))
                        .count(),
                    512
                );
                let first_tile = points
                    .iter()
                    .position(|p| {
                        matches!(
                            p,
                            Progress::Replay(VerificationProgress::TranscriptTile { .. })
                        )
                    })
                    .unwrap();
                let last_tile = points
                    .iter()
                    .rposition(|p| {
                        matches!(
                            p,
                            Progress::Replay(VerificationProgress::TranscriptTile { .. })
                        )
                    })
                    .unwrap();
                for cut in [0, first_tile, last_tile, points.len() - 1] {
                    let mut observed = 0;
                    let result =
                        sparse.attempt_with_progress([3; 32], target, materialization, |_| {
                            let index = observed;
                            observed += 1;
                            if index == cut {
                                Err(cut)
                            } else {
                                Ok(())
                            }
                        });
                    assert_eq!(result, Err(VerificationError::Cancelled(cut)));
                    assert_eq!(observed, cut + 1);
                    assert_eq!(
                        sparse.attempt([3; 32], target, materialization).unwrap(),
                        expected
                    );
                }
            }
        }
    }
}
