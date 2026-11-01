use super::tests::{changed_product, native_arithmetic, reset_native_arithmetic};
use super::*;
use std::convert::Infallible;

fn field_edge_fixture(seed: u8) -> (Hash, Hash, Vec<u8>) {
    // Include values whose products need both limb carries and reduction near q.
    let a: Vec<u32> = (0..CELLS)
        .map(|i| (Q - 1 - ((i * 65537 + usize::from(seed)) % 1009) as u128) as u32)
        .collect();
    let b: Vec<u32> = (0..CELLS)
        .map(|i| match (i + usize::from(seed)) % 4 {
            0 => 0,
            1 => 1,
            2 => (Q - 1) as u32,
            _ => (Q - 1 - (i % 127) as u128) as u32,
        })
        .collect();
    let challenge = [seed; 32];
    let task = task_id(&a, &b).unwrap();
    (challenge, task, prove(challenge, &a, &b).unwrap())
}

fn value(
    result: Result<VerifiedWork, WorkError>,
) -> Result<(Hash, Hash, Hash, Vec<u32>), WorkError> {
    result.map(|work| {
        (
            work.challenge(),
            work.task(),
            work.ticket(),
            work.product().to_vec(),
        )
    })
}

#[test]
fn full_field_cold_claims_match_transposed_results_and_all_progress_boundaries() {
    for seed in [151, 152, 153] {
        let (challenge, task, proof) = field_edge_fixture(seed);
        let mut false_trace = proof.clone();
        false_trace[PROOF_BYTES - 1] ^= 1;
        let false_product = changed_product(&proof, CELLS - 1);
        for bytes in [&proof, &false_trace, &false_product] {
            let mut reference_progress = Vec::new();
            let expected = relation_only(verify_transposed_with_progress(
                challenge,
                task,
                [255; 32],
                bytes,
                &mut |point| {
                    reference_progress.push(point);
                    Ok::<_, Infallible>(())
                },
            ));
            let cache = ArithmeticFactCache::new(1).unwrap();
            let mut actual_progress = Vec::new();
            let actual =
                cache.verify_with_progress(challenge, task, [255; 32], bytes, &mut |point| {
                    actual_progress.push(point);
                    Ok::<_, Infallible>(())
                });
            let actual = match actual {
                Ok(work) => Ok(work),
                Err(FactError::Relation(error)) => Err(error),
                Err(other) => panic!("unexpected cache-local error: {other:?}"),
            };
            assert_eq!(value(actual), value(expected));
            assert_eq!(actual_progress, reference_progress);
        }
    }
}

#[test]
fn full_field_trace_upgrade_and_product_reuse_preserve_current_claim_checks() {
    let (challenge, task, proof) = field_edge_fixture(154);
    let expected = verify_transposed(challenge, task, [255; 32], &proof);
    let mut false_trace = proof.clone();
    false_trace[PROOF_BYTES - 1] ^= 1;
    let cache = ArithmeticFactCache::new(1).unwrap();
    reset_native_arithmetic();
    assert_eq!(
        cache
            .verify(challenge, task, [255; 32], &false_trace)
            .unwrap_err(),
        FactError::Relation(WorkError::Transcript)
    );
    assert_eq!(native_arithmetic(), (1, 1, 0));
    let upgraded = cache.verify(challenge, task, [255; 32], &proof).unwrap();
    assert_eq!(value(Ok(upgraded)), value(expected));
    assert_eq!(native_arithmetic(), (2, 2, 1));
    for cell in [0, CELLS / 2, CELLS - 1] {
        assert_eq!(
            cache
                .verify(challenge, task, [255; 32], &changed_product(&proof, cell))
                .unwrap_err(),
            FactError::Relation(WorkError::Product)
        );
    }
    assert!(cache.verify(challenge, task, [255; 32], &proof).is_ok());
    assert_eq!(native_arithmetic(), (2, 2, 1));
}

#[test]
fn cancelling_trace_upgrade_keeps_only_the_preexisting_completed_trace() {
    let (challenge, task, proof) = field_edge_fixture(155);
    let mut false_trace = proof.clone();
    false_trace[PROOF_BYTES - 1] ^= 1;
    for stop in [
        VerificationProgress::BeforeProduct,
        VerificationProgress::BeforeVerifiedWork,
    ] {
        let cache = ArithmeticFactCache::new(1).unwrap();
        assert_eq!(
            cache
                .verify(challenge, task, [255; 32], &false_trace)
                .unwrap_err(),
            FactError::Relation(WorkError::Transcript)
        );
        let mut observation = ArithmeticObservation::default();
        let result = cache.verify_with_observation(
            challenge,
            task,
            [255; 32],
            &proof,
            &mut |point| {
                if point == stop {
                    Err("cancel-upgrade")
                } else {
                    Ok(())
                }
            },
            &mut observation,
        );
        assert_eq!(result.unwrap_err(), FactError::Cancelled("cancel-upgrade"));
        assert_eq!(observation.publication, ArithmeticPublication::None);
        {
            let state = cache.state.lock().unwrap();
            let saved = state.entries[0].as_ref().unwrap();
            assert!(saved.arithmetic.product.is_none());
        }
        reset_native_arithmetic();
        assert_eq!(
            cache
                .verify(challenge, task, [255; 32], &false_trace)
                .unwrap_err(),
            FactError::Relation(WorkError::Transcript)
        );
        assert_eq!(native_arithmetic(), (0, 0, 0));
        assert!(cache.verify(challenge, task, [255; 32], &proof).is_ok());
        assert_eq!(native_arithmetic(), (1, 1, 1));
    }
}
