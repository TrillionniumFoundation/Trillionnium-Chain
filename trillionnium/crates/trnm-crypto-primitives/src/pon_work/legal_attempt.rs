//! Experimental complete legal attempts with independent arithmetic and proof
//! materialization choices. None of these producer values is verified work.
//!
//! Every attempt computes the complete original challenge-bound transcript.
//! A losing ticket need not allocate its otherwise fixed PNW1 proof bytes.
//! Caching AB and delaying serialization do not change the relation or lottery.
use super::{
    evaluate_transcript_kernel_with_progress, hash, relation_only, Hash, PreparedTask,
    VerificationError, VerificationProgress, WorkError,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Arithmetic {
    Transposed,
    FullLimb,
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
}

impl Task {
    /// Both arithmetic choices pay the same original AB/prefix preparation.
    /// Only the challenge-dependent transcript kernel differs in this experiment.
    pub fn new(a: &[u32], b: &[u32], arithmetic: Arithmetic) -> Result<Self, WorkError> {
        Ok(Self {
            prepared: PreparedTask::new(a, b)?,
            arithmetic,
        })
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pon_work::{self, CELLS, N, PROOF_BYTES, Q};

    fn contexts() -> [Hash; 3] {
        [[0; 32], [7; 32], [255; 32]]
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
}
