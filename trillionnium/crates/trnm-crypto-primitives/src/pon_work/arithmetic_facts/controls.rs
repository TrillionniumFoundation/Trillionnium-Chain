use super::super::verify_reference;
use super::tests::{changed_product, fixture, native_arithmetic, reset_native_arithmetic};
use super::*;
use std::convert::Infallible;
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::Duration;

fn observed(
    cache: &ArithmeticFactCache,
    challenge: Hash,
    task: Hash,
    target: Hash,
    proof: &[u8],
) -> (
    Result<VerifiedWork, FactError<Infallible>>,
    ArithmeticObservation,
) {
    let mut observation = ArithmeticObservation::default();
    let result = cache.verify_with_observation(
        challenge,
        task,
        target,
        proof,
        &mut no_cancellation,
        &mut observation,
    );
    (result, observation)
}
fn assert_exact(actual: &VerifiedWork, expected: &VerifiedWork) {
    assert_eq!(actual.challenge(), expected.challenge());
    assert_eq!(actual.task(), expected.task());
    assert_eq!(actual.ticket(), expected.ticket());
    assert_eq!(actual.product(), expected.product());
}

#[test]
fn every_warm_call_keeps_current_cheap_checks_and_the_original_error_order() {
    let (challenge, task, proof) = fixture(91);
    let cache = ArithmeticFactCache::new(2).unwrap();
    let verified = cache.verify(challenge, task, [255; 32], &proof).unwrap();
    let mut lower = verified.ticket();
    assert_ne!(lower, [0; 32]);
    for byte in lower.iter_mut().rev() {
        if *byte != 0 {
            *byte -= 1;
            break;
        }
        *byte = 255;
    }
    let mut bad_version = proof.clone();
    bad_version[0] = b'X';
    let mut cases = vec![
        (task, [255; 32], proof[..PROOF_BYTES - 1].to_vec()),
        (task, [0; 32], bad_version),
        ([0; 32], [255; 32], proof.clone()),
        (task, [0; 32], proof.clone()),
        (task, lower, proof.clone()),
    ];
    for at in [4, 4 + CELLS * 4, 4 + CELLS * 8] {
        let mut bad = proof.clone();
        bad[at..at + 4].copy_from_slice(&(Q as u32).to_le_bytes());
        cases.push(([0; 32], [255; 32], bad));
    }
    reset_native_arithmetic();
    for (current_task, current_target, bytes) in cases {
        let expected =
            verify_reference(challenge, current_task, current_target, &bytes).unwrap_err();
        let mut callbacks = 0;
        let mut observation = ArithmeticObservation::default();
        let result = cache.verify_with_observation(
            challenge,
            current_task,
            current_target,
            &bytes,
            &mut |_| {
                callbacks += 1;
                Ok::<(), Infallible>(())
            },
            &mut observation,
        );
        assert_eq!(result.unwrap_err(), FactError::Relation(expected));
        assert_eq!(callbacks, 0);
        assert_eq!(observation, ArithmeticObservation::default());
    }
    assert_eq!(native_arithmetic(), (0, 0, 0));
}

#[test]
fn exact_challenge_and_all_current_matrix_bytes_are_required_for_a_hit() {
    let (challenge, task, proof) = fixture(92);
    let cache = ArithmeticFactCache::new(4).unwrap();
    cache.verify(challenge, task, [255; 32], &proof).unwrap();
    let other_challenge = [93; 32];
    let expected = super::super::verify(other_challenge, task, [255; 32], &proof).unwrap_err();
    let (result, observation) = observed(&cache, other_challenge, task, [255; 32], &proof);
    assert_eq!(result.unwrap_err(), FactError::Relation(expected));
    assert!(!observation.exact_fact_found);
    assert!(observation.transcript_completed);
    for operand in 0..2 {
        let mut matrices: Vec<u32> = proof[4..4 + INPUT_BYTES]
            .chunks_exact(4)
            .map(|p| u32::from_le_bytes(p.try_into().unwrap()))
            .collect();
        matrices[operand * CELLS + CELLS - 1] += 1;
        let (a, b) = matrices.split_at(CELLS);
        let current_task = task_id(a, b).unwrap();
        let current_proof = prove(challenge, a, b).unwrap();
        let expected =
            super::super::verify(challenge, current_task, [255; 32], &current_proof).unwrap();
        let (result, observation) =
            observed(&cache, challenge, current_task, [255; 32], &current_proof);
        assert_exact(&result.unwrap(), &expected);
        assert!(!observation.exact_fact_found);
        assert!(observation.transcript_completed && observation.product_completed);
    }
    let (result, observation) = observed(&cache, challenge, task, [255; 32], &proof);
    assert!(result.is_ok());
    assert!(observation.trace_reused && observation.product_reused);
    assert!(!observation.transcript_entered);
}

#[test]
fn task_discriminator_alias_keeps_full_inputs_at_lookup_and_publication() {
    let (challenge, task, proof) = fixture(118);
    let original = verify_reference(challenge, task, [255; 32], &proof).unwrap();
    for operand in 0..2 {
        let mut matrices: Vec<u32> = proof[4..4 + INPUT_BYTES]
            .chunks_exact(4)
            .map(|part| u32::from_le_bytes(part.try_into().unwrap()))
            .collect();
        // The last word of either operand preserves the longest input prefix.
        matrices[operand * CELLS + CELLS - 1] += 1;
        let (a, b) = matrices.split_at(CELLS);
        let current_task = task_id(a, b).unwrap();
        let current_proof = prove(challenge, a, b).unwrap();
        let expected =
            verify_reference(challenge, current_task, [255; 32], &current_proof).unwrap();
        assert_ne!(current_task, task);

        for before_lookup in [true, false] {
            let cache = ArithmeticFactCache::new(2).unwrap();
            cache.verify(challenge, task, [255; 32], &proof).unwrap();
            let charge = cache.software_bytes();
            let mut aliased = false;
            if before_lookup {
                let mut state = cache.state.lock().unwrap();
                state.entries[0].as_mut().unwrap().input_task = current_task;
                aliased = true;
            }
            let mut observation = ArithmeticObservation::default();
            let result = cache.verify_with_observation(
                challenge,
                current_task,
                [255; 32],
                &current_proof,
                &mut |point| {
                    // Also inject the false discriminator after lookup and real
                    // arithmetic, immediately before publication. A racing
                    // candidate cannot replace the complete byte comparison.
                    if !before_lookup && point == VerificationProgress::BeforeVerifiedWork {
                        let mut state = cache.state.try_lock().unwrap();
                        state.entries[0].as_mut().unwrap().input_task = current_task;
                        aliased = true;
                    }
                    Ok::<(), ()>(())
                },
                &mut observation,
            );
            assert!(aliased);
            assert_exact(&result.unwrap(), &expected);
            assert!(!observation.exact_fact_found);
            assert!(observation.transcript_entered && observation.transcript_completed);
            assert!(observation.product_entered && observation.product_completed);
            assert_eq!(observation.publication, ArithmeticPublication::Product);
            assert_eq!(cache.software_bytes(), charge);
            assert!(charge <= MAX_ARITHMETIC_FACT_SOFTWARE_BYTES);
            {
                let state = cache.state.lock().unwrap();
                assert_eq!(state.entries.iter().flatten().count(), 2);
                let saved = state.entries[0].as_ref().unwrap();
                assert_eq!(saved.input_task, current_task);
                assert_eq!(saved.inputs.as_slice(), &proof[4..4 + INPUT_BYTES]);
                assert_eq!(
                    saved.arithmetic.product.as_ref().map(|value| value.as_slice()),
                    Some(original.product())
                );
                let inserted = state.entries[1].as_ref().unwrap();
                assert_eq!(inserted.input_task, current_task);
                assert_eq!(inserted.inputs.as_slice(), &current_proof[4..4 + INPUT_BYTES]);
            }
            let (warm, hit) = observed(&cache, challenge, current_task, [255; 32], &current_proof);
            assert_exact(&warm.unwrap(), &expected);
            assert!(hit.exact_fact_found && hit.trace_reused && hit.product_reused);
            assert!(!hit.transcript_entered && !hit.product_entered);
            // A damaged discriminator may cause a miss, never a wrong result.
            assert_exact(
                &cache.verify(challenge, task, [255; 32], &proof).unwrap(),
                &original,
            );
        }
    }
}

#[test]
fn trace_only_fact_must_recompute_product_before_accepting_a_new_matching_trace() {
    let (challenge, task, proof) = fixture(94);
    let mut bad = proof.clone();
    bad[PROOF_BYTES - 1] ^= 1;
    let cache = ArithmeticFactCache::new(1).unwrap();
    reset_native_arithmetic();
    ARITHMETIC_INPUT_DECODES.with(|count| count.set(0));
    let (result, trace) = observed(&cache, challenge, task, [255; 32], &bad);
    assert_eq!(
        result.unwrap_err(),
        FactError::Relation(WorkError::Transcript)
    );
    assert!(trace.transcript_completed);
    assert!(!trace.product_entered);
    assert_eq!(trace.publication, ArithmeticPublication::Trace);
    assert_eq!(native_arithmetic(), (1, 1, 0));
    ARITHMETIC_INPUT_DECODES.with(|count| assert_eq!(count.get(), 1));
    let (result, product) = observed(&cache, challenge, task, [255; 32], &proof);
    assert!(result.is_ok());
    assert!(product.exact_fact_found);
    assert!(!product.trace_reused && !product.product_reused);
    assert!(product.transcript_completed && product.product_completed);
    assert_eq!(product.publication, ArithmeticPublication::Product);
    assert_eq!(native_arithmetic(), (2, 2, 1));
    ARITHMETIC_INPUT_DECODES.with(|count| assert_eq!(count.get(), 2));
    let bad_product = changed_product(&proof, CELLS / 2);
    let (result, hit) = observed(&cache, challenge, task, [255; 32], &bad_product);
    assert_eq!(result.unwrap_err(), FactError::Relation(WorkError::Product));
    assert!(hit.trace_reused && hit.product_reused);
    assert!(!hit.transcript_entered && !hit.product_entered);
    assert_eq!(native_arithmetic(), (2, 2, 1));
    ARITHMETIC_INPUT_DECODES.with(|count| assert_eq!(count.get(), 2));
}

#[test]
fn warm_product_does_not_override_the_current_bad_trace_or_current_product() {
    let (challenge, task, proof) = fixture(95);
    let cache = ArithmeticFactCache::new(1).unwrap();
    cache.verify(challenge, task, [255; 32], &proof).unwrap();
    let mut bad = changed_product(&proof, 0);
    bad[PROOF_BYTES - 1] ^= 1;
    assert_eq!(
        super::super::verify(challenge, task, [255; 32], &bad).unwrap_err(),
        WorkError::Transcript
    );
    reset_native_arithmetic();
    let (result, observation) = observed(&cache, challenge, task, [255; 32], &bad);
    assert_eq!(
        result.unwrap_err(),
        FactError::Relation(WorkError::Transcript)
    );
    assert!(observation.trace_reused);
    assert!(!observation.product_reused);
    assert_eq!(native_arithmetic(), (0, 0, 0));
}

#[test]
fn cancellation_at_each_cold_boundary_publishes_no_new_fact_and_replays_on_retry() {
    let (challenge, task, proof) = fixture(96);
    for boundary in 0..4 {
        let cache = ArithmeticFactCache::new(1).unwrap();
        let mut product_seen = false;
        let mut cancelled = false;
        let mut observation = ArithmeticObservation::default();
        let result = cache.verify_with_observation(
            challenge,
            task,
            [255; 32],
            &proof,
            &mut |point| {
                if point == VerificationProgress::BeforeProduct {
                    product_seen = true;
                }
                let stop = match boundary {
                    0 => point == VerificationProgress::BeforeReplay,
                    1 => {
                        point
                            == (VerificationProgress::TranscriptTile {
                                row: 7,
                                column: 7,
                                inner: 7,
                            })
                    }
                    2 => {
                        product_seen && matches!(point, VerificationProgress::MatrixRow { row: 0 })
                    }
                    _ => point == VerificationProgress::BeforeVerifiedWork,
                };
                if stop {
                    cancelled = true;
                    Err("original-caller-cancelled")
                } else {
                    Ok(())
                }
            },
            &mut observation,
        );
        assert!(cancelled);
        assert_eq!(
            result.unwrap_err(),
            FactError::Cancelled("original-caller-cancelled")
        );
        assert_eq!(observation.publication, ArithmeticPublication::None);
        assert!(cache
            .state
            .lock()
            .unwrap()
            .entries
            .iter()
            .all(Option::is_none));
        reset_native_arithmetic();
        assert!(cache.verify(challenge, task, [255; 32], &proof).is_ok());
        assert_eq!(native_arithmetic(), (1, 1, 1));
    }
}

#[test]
fn cold_progress_is_original_and_warm_success_still_obeys_each_authorizing_boundary() {
    let (challenge, task, proof) = fixture(97);
    let mut original = Vec::new();
    let expected =
        super::super::verify_with_progress(challenge, task, [255; 32], &proof, &mut |point| {
            original.push(point);
            Ok::<(), Infallible>(())
        })
        .unwrap();
    let cache = ArithmeticFactCache::new(1).unwrap();
    let mut cold = Vec::new();
    let actual = cache
        .verify_with_progress(challenge, task, [255; 32], &proof, &mut |point| {
            cold.push(point);
            Ok::<(), Infallible>(())
        })
        .unwrap();
    assert_exact(&actual, &expected);
    assert_eq!(cold, original);
    for boundary in [
        VerificationProgress::BeforeReplay,
        VerificationProgress::BeforeProduct,
        VerificationProgress::BeforeVerifiedWork,
    ] {
        reset_native_arithmetic();
        let result = cache.verify_with_progress(challenge, task, [255; 32], &proof, &mut |point| {
            if point == boundary {
                Err("warm-caller-cancelled")
            } else {
                Ok(())
            }
        });
        assert_eq!(
            result.unwrap_err(),
            FactError::Cancelled("warm-caller-cancelled")
        );
        assert_eq!(native_arithmetic(), (0, 0, 0));
    }
}

#[test]
fn holding_the_cache_lock_never_waits_or_reports_reuse_instead_of_real_arithmetic() {
    let (challenge, task, proof) = fixture(98);
    let expected = super::super::verify(challenge, task, [255; 32], &proof).unwrap();
    let cache = ArithmeticFactCache::new(1).unwrap();
    let held = cache.state.lock().unwrap();
    reset_native_arithmetic();
    ARITHMETIC_INPUT_DECODES.with(|count| count.set(0));
    let (result, observation) = observed(&cache, challenge, task, [255; 32], &proof);
    assert_exact(&result.unwrap(), &expected);
    assert!(observation.lookup_contended);
    assert!(!observation.trace_reused && !observation.product_reused);
    assert!(observation.transcript_completed && observation.product_completed);
    assert_eq!(observation.publication, ArithmeticPublication::Contended);
    assert_eq!(native_arithmetic(), (1, 1, 1));
    ARITHMETIC_INPUT_DECODES.with(|count| assert_eq!(count.get(), 1));
    drop(held);
    reset_native_arithmetic();
    assert!(cache.verify(challenge, task, [255; 32], &proof).is_ok());
    assert_eq!(native_arithmetic(), (1, 1, 1));
    ARITHMETIC_INPUT_DECODES.with(|count| assert_eq!(count.get(), 2));
}

#[test]
fn no_callback_holds_the_cache_lock_and_reentrant_replacement_cannot_change_the_result() {
    let (challenge, task, proof) = fixture(99);
    let (other_challenge, other_task, other_proof) = fixture(100);
    let expected = super::super::verify(challenge, task, [255; 32], &proof).unwrap();
    let cache = ArithmeticFactCache::new(1).unwrap();
    cache.verify(challenge, task, [255; 32], &proof).unwrap();
    let mut replaced = false;
    let actual = cache
        .verify_with_progress(challenge, task, [255; 32], &proof, &mut |point| {
            assert!(cache.state.try_lock().is_ok());
            if point == VerificationProgress::BeforeProduct {
                cache
                    .verify(other_challenge, other_task, [255; 32], &other_proof)
                    .unwrap();
                replaced = true;
            }
            Ok::<(), Infallible>(())
        })
        .unwrap();
    assert!(replaced);
    assert_exact(&actual, &expected);
}

#[test]
fn a_late_trace_publication_cannot_downgrade_a_concurrently_completed_product() {
    let (challenge, task, proof) = fixture(101);
    let mut bad_trace = proof.clone();
    bad_trace[PROOF_BYTES - 1] ^= 1;
    let cache = Arc::new(ArithmeticFactCache::new(1).unwrap());
    let (ready_tx, ready_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let owner = cache.clone();
    let worker = thread::spawn(move || {
        let mut observation = ArithmeticObservation::default();
        let result = owner.verify_with_observation(
            challenge,
            task,
            [255; 32],
            &bad_trace,
            &mut |point| {
                if point
                    == (VerificationProgress::TranscriptTile {
                        row: 7,
                        column: 7,
                        inner: 7,
                    })
                {
                    ready_tx.send(()).map_err(|_| "test-control-disconnected")?;
                    release_rx
                        .recv_timeout(Duration::from_secs(5))
                        .map_err(|_| "test-control-timeout")?;
                }
                Ok::<(), &str>(())
            },
            &mut observation,
        );
        (result, observation)
    });
    ready_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    cache.verify(challenge, task, [255; 32], &proof).unwrap();
    release_tx.send(()).unwrap();
    let (result, publication) = worker.join().unwrap();
    assert_eq!(
        result.unwrap_err(),
        FactError::Relation(WorkError::Transcript)
    );
    assert_eq!(
        publication.publication,
        ArithmeticPublication::ExistingStrongerOrEqual
    );
    reset_native_arithmetic();
    let (result, hit) = observed(&cache, challenge, task, [255; 32], &proof);
    assert!(result.is_ok());
    assert!(hit.product_reused);
    assert_eq!(native_arithmetic(), (0, 0, 0));
}

#[test]
fn capacity_eviction_reopen_and_caller_owned_product_keep_exact_verification() {
    assert!(ArithmeticFactCache::new(0).is_err());
    assert!(ArithmeticFactCache::new(MAX_ARITHMETIC_FACT_SLOTS + 1).is_err());
    let largest = ArithmeticFactCache::new(MAX_ARITHMETIC_FACT_SLOTS).unwrap();
    assert!(largest.software_bytes() <= MAX_ARITHMETIC_FACT_SOFTWARE_BYTES);
    assert_eq!(
        largest.software_bytes(),
        largest.state.lock().unwrap().entries.capacity() * size_of::<Option<Fact>>()
            + size_of::<ArithmeticFactCache>()
    );
    assert!(largest.software_bytes() >= MAX_ARITHMETIC_FACT_SLOTS * (INPUT_BYTES + CELLS * 4));
    drop(largest);
    let (challenge, task, proof) = fixture(102);
    let (other_challenge, other_task, other_proof) = fixture(103);
    let cache = ArithmeticFactCache::new(1).unwrap();
    let charged = cache.software_bytes();
    reset_native_arithmetic();
    for (c, t, p) in [
        (challenge, task, &proof),
        (other_challenge, other_task, &other_proof),
        (challenge, task, &proof),
    ] {
        let (result, observation) = observed(&cache, c, t, [255; 32], p);
        assert!(result.is_ok());
        assert!(observation.lookup_probes <= cache.capacity());
        assert!(observation.publication_probes <= cache.capacity());
        assert_eq!(cache.software_bytes(), charged);
    }
    assert_eq!(native_arithmetic(), (3, 3, 3));
    let expected = super::super::verify(challenge, task, [255; 32], &proof).unwrap();
    let mut caller_owned = cache.verify(challenge, task, [255; 32], &proof).unwrap();
    caller_owned.product[0] ^= 1;
    assert_exact(
        &cache.verify(challenge, task, [255; 32], &proof).unwrap(),
        &expected,
    );
    let reopened = ArithmeticFactCache::new(1).unwrap();
    reset_native_arithmetic();
    assert!(reopened.verify(challenge, task, [255; 32], &proof).is_ok());
    assert_eq!(native_arithmetic(), (1, 1, 1));
}

#[test]
fn poisoned_cache_is_unavailable_but_cannot_override_earlier_current_grammar_errors() {
    let (challenge, task, proof) = fixture(104);
    let cache = Arc::new(ArithmeticFactCache::new(1).unwrap());
    let owner = cache.clone();
    assert!(thread::spawn(move || {
        let _held = owner.state.lock().unwrap();
        panic!("injected local cache poison");
    })
    .join()
    .is_err());
    reset_native_arithmetic();
    assert_eq!(
        cache
            .verify(challenge, task, [255; 32], &proof)
            .unwrap_err(),
        FactError::Unavailable
    );
    let mut malformed = proof;
    malformed[0] = b'X';
    assert_eq!(
        cache
            .verify(challenge, task, [255; 32], &malformed)
            .unwrap_err(),
        FactError::Relation(WorkError::Version)
    );
    assert_eq!(native_arithmetic(), (0, 0, 0));
}

#[test]
fn dense_zero_one_zero_identity_and_rank_one_claims_match_the_raw_oracle() {
    for shape in 0..6 {
        let a: Vec<u32> = (0..CELLS)
            .map(|i| match shape {
                1 | 2 => 0,
                4 => u32::from(i / N == i % N),
                5 => (i / N % 31) as u32,
                _ => (i % 31) as u32,
            })
            .collect();
        let b: Vec<u32> = (0..CELLS)
            .map(|i| match shape {
                1 | 3 => 0,
                4 => u32::from(i / N == i % N),
                5 => (i % N % 23) as u32,
                _ => (i % 23) as u32,
            })
            .collect();
        let challenge = [111 + shape as u8; 32];
        let task = task_id(&a, &b).unwrap();
        let proof = prove(challenge, &a, &b).unwrap();
        let expected = super::super::verify(challenge, task, [255; 32], &proof).unwrap();
        let cache = ArithmeticFactCache::new(1).unwrap();
        for cell in [0, CELLS / 2, CELLS - 1] {
            let bad = changed_product(&proof, cell);
            let raw = super::super::verify(challenge, task, [255; 32], &bad).unwrap_err();
            assert_eq!(
                cache.verify(challenge, task, [255; 32], &bad).unwrap_err(),
                FactError::Relation(raw)
            );
        }
        assert_exact(
            &cache.verify(challenge, task, [255; 32], &proof).unwrap(),
            &expected,
        );
    }
}
