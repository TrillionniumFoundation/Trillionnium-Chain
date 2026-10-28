//! Reject-only mathematical fact for one explicitly selected public task.
//!
//! Construction computes A*B independently of any claimed proof or challenge.
//! The immutable bounded fact can reject a wrong C before transcript replay.
//! Passing never constructs VerifiedWork, establishes task eligibility, or skips
//! the original full verifier. Unknown operands do not enter a growing cache.
use super::{precheck_proof_statement, task_id, validate, Hash, WorkError, CELLS, N, Q};

pub struct PublicProduct {
    task: Hash,
    operands: Box<[u8]>,
    product: Box<[u8]>,
}

impl PublicProduct {
    /// Trusted local setup, before serving requests. The cost belongs to setup;
    /// it is never silently charged to every request or called a work receipt.
    pub fn new(a: &[u32], b: &[u32]) -> Result<Self, WorkError> {
        validate(a)?;
        validate(b)?;
        let mut product = Vec::with_capacity(CELLS * 4);
        for row in 0..N {
            for column in 0..N {
                // At most 64 products below 2^64, so the exact sum fits u128.
                let sum: u128 = (0..N)
                    .map(|k| u128::from(a[row * N + k]) * u128::from(b[k * N + column]))
                    .sum();
                product.extend_from_slice(&((sum % Q) as u32).to_le_bytes());
            }
        }
        Ok(Self {
            task: task_id(a, b)?,
            operands: a
                .iter()
                .chain(b)
                .flat_map(|word| word.to_le_bytes())
                .collect::<Vec<_>>()
                .into_boxed_slice(),
            product: product.into_boxed_slice(),
        })
    }

    pub fn task(&self) -> Hash {
        self.task
    }

    /// Exact retained object bytes, not allocator overhead or process RSS.
    pub fn software_bytes(&self) -> usize {
        std::mem::size_of::<Self>() + self.operands.len() + self.product.len()
    }

    /// Returns true only when this fixed fact matched and C agreed. False means
    /// the task is outside this fact; the caller must perform ordinary replay.
    /// Both successful returns still require full W1 and current native checks.
    /// No allocation, insertion, authority cache, identity preference or hashcash.
    pub fn precheck(
        &self,
        challenge: Hash,
        expected_task: Hash,
        target: Hash,
        proof: &[u8],
    ) -> Result<bool, WorkError> {
        precheck_proof_statement(challenge, expected_task, target, proof)?;
        if expected_task != self.task || &proof[4..4 + CELLS * 8] != self.operands.as_ref() {
            return Ok(false);
        }
        if &proof[4 + CELLS * 8..4 + CELLS * 12] != self.product.as_ref() {
            return Err(WorkError::Product);
        }
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pon_work::{self, VerificationError, VerificationProgress, PROOF_BYTES};

    fn matrices() -> (Vec<u32>, Vec<u32>) {
        (
            (0..CELLS).map(|i| ((13 * i + 17) % 257) as u32).collect(),
            (0..CELLS).map(|i| ((29 * i + 31) % 263) as u32).collect(),
        )
    }

    #[test]
    fn late_product_attack_is_rejected_before_challenge_replay() {
        let (a, b) = matrices();
        let fact = PublicProduct::new(&a, &b).unwrap();
        let challenge = [7; 32];
        let mut proof = pon_work::prove(challenge, &a, &b).unwrap();
        let at = 4 + CELLS * 8;
        let word = u32::from_le_bytes(proof[at..at + 4].try_into().unwrap());
        proof[at..at + 4].copy_from_slice(&(((u128::from(word) + 1) % Q) as u32).to_le_bytes());
        let mut tiles = 0;
        let baseline = pon_work::verify_with_progress(
            challenge,
            fact.task(),
            [255; 32],
            &proof,
            &mut |point| {
                if matches!(point, VerificationProgress::TranscriptTile { .. }) {
                    tiles += 1;
                }
                Ok::<_, ()>(())
            },
        );
        assert!(matches!(
            baseline,
            Err(VerificationError::Relation(WorkError::Product))
        ));
        assert_eq!(tiles, (N / pon_work::R).pow(3));
        assert_eq!(
            fact.precheck(challenge, fact.task(), [255; 32], &proof),
            Err(WorkError::Product)
        );
    }

    #[test]
    fn passing_fact_cannot_bless_a_forged_transcript_or_another_task() {
        let (a, b) = matrices();
        let fact = PublicProduct::new(&a, &b).unwrap();
        let challenge = [9; 32];
        let mut proof = pon_work::prove(challenge, &a, &b).unwrap();
        assert!(fact
            .precheck(challenge, fact.task(), [255; 32], &proof)
            .unwrap());
        proof[PROOF_BYTES - 1] ^= 1;
        assert!(fact
            .precheck(challenge, fact.task(), [255; 32], &proof)
            .unwrap());
        assert!(matches!(
            pon_work::verify(challenge, fact.task(), [255; 32], &proof),
            Err(WorkError::Transcript)
        ));
        let zero = vec![0; CELLS];
        let other = pon_work::prove(challenge, &zero, &zero).unwrap();
        let other_task = task_id(&zero, &zero).unwrap();
        assert!(!fact
            .precheck(challenge, other_task, [255; 32], &other)
            .unwrap());
        assert_eq!(
            fact.precheck(challenge, fact.task(), [255; 32], &other),
            Err(WorkError::Task)
        );
    }

    #[test]
    fn exact_field_boundaries_and_statement_filters_remain_required() {
        for (a, b) in [
            (vec![0; CELLS], vec![0; CELLS]),
            (vec![(Q - 1) as u32; CELLS], vec![(Q - 1) as u32; CELLS]),
            matrices(),
        ] {
            let fact = PublicProduct::new(&a, &b).unwrap();
            assert_eq!(
                fact.software_bytes(),
                std::mem::size_of::<PublicProduct>() + CELLS * 12
            );
            for challenge in [[0; 32], [255; 32]] {
                let mut proof = pon_work::prove(challenge, &a, &b).unwrap();
                assert!(fact
                    .precheck(challenge, fact.task(), [255; 32], &proof)
                    .unwrap());
                pon_work::verify_reference(challenge, fact.task(), [255; 32], &proof).unwrap();
                assert_eq!(
                    fact.precheck(challenge, fact.task(), [0; 32], &proof),
                    Err(WorkError::Target)
                );
                proof[4..8].copy_from_slice(&(Q as u32).to_le_bytes());
                assert_eq!(
                    fact.precheck(challenge, fact.task(), [255; 32], &proof),
                    Err(WorkError::Field)
                );
            }
        }
        assert!(matches!(
            PublicProduct::new(&[0], &[0]),
            Err(WorkError::Length)
        ));
    }
}
