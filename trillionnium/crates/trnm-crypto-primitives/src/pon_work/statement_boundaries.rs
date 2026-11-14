//! Original-API controls: admission success is never complete work, and cached
//! arithmetic does not cover a new challenge or an evicted exact input.
use super::arithmetic_facts::{ArithmeticFactCache, ArithmeticObservation, FactError};
use super::*;

fn fixture(challenge: Hash) -> (Hash, Vec<u8>) {
    let a: Vec<u32> = (0..CELLS).map(|i| ((13 * i + 17) % 257) as u32).collect();
    let b: Vec<u32> = (0..CELLS).map(|i| ((29 * i + 31) % 263) as u32).collect();
    (task_id(&a, &b).unwrap(), prove(challenge, &a, &b).unwrap())
}

#[test]
fn original_scalar_error_order_precedes_all_arithmetic_cache_access() {
    let challenge = [73; 32];
    let (task, proof) = fixture(challenge);
    let mut bad_version = proof.clone();
    bad_version[0] ^= 1;
    let mut bad_field = proof.clone();
    bad_field[4..8].copy_from_slice(&(Q as u32).to_le_bytes());
    let mut bad_product_field = proof.clone();
    let at = 4 + 2 * CELLS * 4;
    bad_product_field[at..at + 4].copy_from_slice(&(Q as u32).to_le_bytes());
    let mut wrong_task = task;
    wrong_task[0] ^= 1;
    let mut low_target = [0; 32];
    low_target[31] = 1;
    let cases = [
        (&proof[..4], wrong_task, [0; 32], WorkError::Length),
        (&bad_version[..], wrong_task, [0; 32], WorkError::Version),
        (&bad_field[..], wrong_task, [0; 32], WorkError::Target),
        (
            &bad_product_field[..],
            wrong_task,
            [0; 32],
            WorkError::Target,
        ),
        (&bad_field[..], wrong_task, [255; 32], WorkError::Field),
        (
            &bad_product_field[..],
            wrong_task,
            [255; 32],
            WorkError::Field,
        ),
        (&proof[..], wrong_task, low_target, WorkError::Task),
        (&proof[..], task, low_target, WorkError::Target),
    ];
    let cache = ArithmeticFactCache::new(64).unwrap();
    for (bytes, expected_task, target, expected) in cases {
        assert_eq!(
            verify_reference(challenge, expected_task, target, bytes).unwrap_err(),
            expected
        );
        assert_eq!(
            verify(challenge, expected_task, target, bytes).unwrap_err(),
            expected
        );
        assert_eq!(
            verify_limb(challenge, expected_task, target, bytes).unwrap_err(),
            expected
        );
        let mut observation = ArithmeticObservation::default();
        let mut checkpoints = 0;
        let result = cache.verify_with_observation(
            challenge,
            expected_task,
            target,
            bytes,
            &mut |_| {
                checkpoints += 1;
                Ok::<(), ()>(())
            },
            &mut observation,
        );
        assert_eq!(result.unwrap_err(), FactError::Relation(expected));
        assert_eq!(checkpoints, 0);
        assert_eq!(observation, ArithmeticObservation::default());
    }
}

fn refuse(
    cache: &ArithmeticFactCache,
    challenge: Hash,
    task: Hash,
    proof: &[u8],
) -> (ArithmeticObservation, usize) {
    assert_eq!(
        precheck_proof_statement(challenge, task, [255; 32], proof),
        Ok(())
    );
    let mut observation = ArithmeticObservation::default();
    let mut tiles = 0;
    let mut reached_verified = false;
    let result = cache.verify_with_observation(
        challenge,
        task,
        [255; 32],
        proof,
        &mut |point| {
            tiles += usize::from(matches!(point, VerificationProgress::TranscriptTile { .. }));
            reached_verified |= matches!(point, VerificationProgress::BeforeVerifiedWork);
            Ok::<(), ()>(())
        },
        &mut observation,
    );
    assert_eq!(
        result.unwrap_err(),
        FactError::Relation(WorkError::Transcript)
    );
    assert!(!reached_verified);
    (observation, tiles)
}

#[test]
fn correct_product_false_trace_requires_full_replay_for_each_new_challenge() {
    let cache = ArithmeticFactCache::new(64).unwrap();
    for byte in [74, 75, 76] {
        let challenge = [byte; 32];
        let (task, mut proof) = fixture(challenge);
        // Keep the correct final product; only the claimed fresh trace is false.
        proof[PROOF_BYTES - 1] ^= 1;
        let (cold, tiles) = refuse(&cache, challenge, task, &proof);
        assert!(!cold.exact_fact_found);
        assert!(cold.transcript_entered && cold.transcript_completed);
        assert!(!cold.product_entered);
        assert_eq!(tiles, (N / R).pow(3));
        let (warm, tiles) = refuse(&cache, challenge, task, &proof);
        assert!(warm.exact_fact_found && warm.trace_reused);
        assert!(!warm.transcript_entered);
        assert_eq!(tiles, 0);
    }
}

#[test]
fn sixty_fifth_exact_challenge_does_not_turn_eviction_into_a_rejection_fact() {
    let cache = ArithmeticFactCache::new(64).unwrap();
    let mut first = None;
    for byte in 1..=65 {
        let challenge = [byte; 32];
        let (task, mut proof) = fixture(challenge);
        proof[PROOF_BYTES - 1] ^= 1;
        let (observation, tiles) = refuse(&cache, challenge, task, &proof);
        assert!(!observation.exact_fact_found);
        assert_eq!(tiles, (N / R).pow(3));
        if first.is_none() {
            first = Some((challenge, task, proof));
        }
    }
    let (challenge, task, proof) = first.unwrap();
    let (observation, tiles) = refuse(&cache, challenge, task, &proof);
    assert!(!observation.exact_fact_found);
    assert!(observation.transcript_completed);
    assert_eq!(tiles, (N / R).pow(3));
}
