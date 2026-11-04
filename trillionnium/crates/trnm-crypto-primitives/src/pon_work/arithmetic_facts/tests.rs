use super::{ArithmeticFactCache, FactError};
use crate::pon_work::{self, Hash, VerificationProgress, WorkError, CELLS, PROOF_BYTES, Q};
use std::convert::Infallible;

pub(super) fn fixture(seed: u8) -> (Hash, Hash, Vec<u8>) {
    let a: Vec<u32> = (0..CELLS).map(|i| (i % 31) as u32).collect();
    let b: Vec<u32> = (0..CELLS).map(|i| (i % 23) as u32).collect();
    let challenge = [seed; 32];
    (
        challenge,
        pon_work::task_id(&a, &b).unwrap(),
        pon_work::prove(challenge, &a, &b).unwrap(),
    )
}
pub(super) fn changed_product(proof: &[u8], cell: usize) -> Vec<u8> {
    let mut changed = proof.to_vec();
    let at = 4 + 8 * CELLS + cell * 4;
    let word = u32::from_le_bytes(changed[at..at + 4].try_into().unwrap());
    let word = ((u128::from(word) + 1) % Q) as u32;
    changed[at..at + 4].copy_from_slice(&word.to_le_bytes());
    changed
}
pub(super) fn reset_native_arithmetic() {
    pon_work::ARITHMETIC_TRANSCRIPT_REPLAYS.with(|n| n.set(0));
    pon_work::ARITHMETIC_TRANSCRIPT_COMPLETIONS.with(|n| n.set(0));
    pon_work::PRODUCT_RECONSTRUCTIONS.with(|n| n.set(0));
}
pub(super) fn native_arithmetic() -> (usize, usize, usize) {
    (
        pon_work::ARITHMETIC_TRANSCRIPT_REPLAYS.with(|n| n.get()),
        pon_work::ARITHMETIC_TRANSCRIPT_COMPLETIONS.with(|n| n.get()),
        pon_work::PRODUCT_RECONSTRUCTIONS.with(|n| n.get()),
    )
}

#[test]
fn completed_trace_arithmetic_is_reused_without_caching_a_rejection() {
    let (challenge, task, proof) = fixture(81);
    let mut bad_trace = proof.clone();
    bad_trace[PROOF_BYTES - 1] ^= 1;
    assert_eq!(
        pon_work::verify(challenge, task, [255; 32], &bad_trace).unwrap_err(),
        WorkError::Transcript
    );
    let cache = ArithmeticFactCache::new(1).unwrap();
    reset_native_arithmetic();
    let mut tiles = [0; 2];
    for observed in &mut tiles {
        let result =
            cache.verify_with_progress(challenge, task, [255; 32], &bad_trace, &mut |point| {
                if matches!(point, VerificationProgress::TranscriptTile { .. }) {
                    *observed += 1;
                }
                Ok::<(), Infallible>(())
            });
        assert_eq!(
            result.unwrap_err(),
            FactError::Relation(WorkError::Transcript)
        );
    }
    let actual = native_arithmetic();
    println!(
        "W1_ARITHMETIC_TRACE_REUSE actual_replays={} actual_completed={} actual_products={} tiles={tiles:?} invalid_accepted=0",
        actual.0, actual.1, actual.2
    );
    assert_eq!(
        actual,
        (1, 1, 0),
        "count the actual arithmetic kernel, not a cache-hit claim"
    );
    assert_eq!(tiles, [512, 0]);
}

#[test]
fn completed_product_arithmetic_survives_bad_current_claim_then_accepts_exact_valid_claim() {
    let (challenge, task, proof) = fixture(82);
    let first_bad = changed_product(&proof, 0);
    let second_bad = changed_product(&proof, CELLS - 1);
    for bad in [&first_bad, &second_bad] {
        assert_eq!(
            pon_work::verify(challenge, task, [255; 32], bad).unwrap_err(),
            WorkError::Product
        );
    }
    let expected = pon_work::verify(challenge, task, [255; 32], &proof).unwrap();
    let cache = ArithmeticFactCache::new(1).unwrap();
    reset_native_arithmetic();
    for bad in [&first_bad, &second_bad] {
        assert_eq!(
            cache.verify(challenge, task, [255; 32], bad).unwrap_err(),
            FactError::Relation(WorkError::Product)
        );
    }
    let actual = cache.verify(challenge, task, [255; 32], &proof).unwrap();
    assert_eq!(actual.challenge(), expected.challenge());
    assert_eq!(actual.task(), expected.task());
    assert_eq!(actual.ticket(), expected.ticket());
    assert_eq!(actual.product(), expected.product());
    let counts = native_arithmetic();
    println!(
        "W1_ARITHMETIC_PRODUCT_REUSE actual_replays={} actual_completed={} actual_products={} invalid_accepted=0 current_valid_exact=true",
        counts.0, counts.1, counts.2
    );
    assert_eq!(counts, (1, 1, 1), "both rejected declarations and the later valid declaration must use the same actual arithmetic result");
}
