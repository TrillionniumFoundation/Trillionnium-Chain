use super::*;
use std::sync::{Arc, Barrier};

fn material(case: u32) -> (Vec<u32>, Vec<u32>) {
    let mut a = vec![0; CELLS];
    let mut b = vec![0; CELLS];
    for i in 0..N {
        for j in 0..N {
            let at = i * N + j;
            (a[at], b[at]) = match case {
                0 => (0, 0),
                1 => (u32::from(i == j), u32::from(i == j)),
                2 => (((i + 1) * (j + 3)) as u32, ((i * 7 + j * 11) % 37) as u32),
                3 => (
                    if at.is_multiple_of(19) {
                        Q as u32 - 1
                    } else {
                        0
                    },
                    if at.is_multiple_of(23) {
                        Q as u32 - 2
                    } else {
                        0
                    },
                ),
                4 => (Q as u32 - 1, Q as u32 - 2),
                _ => {
                    let bytes = hash(
                        b"task-product-facts-test-material",
                        &[&case.to_le_bytes(), &(at as u64).to_le_bytes()],
                    );
                    let x = u32::from_le_bytes(bytes[..4].try_into().unwrap());
                    let y = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
                    ((u128::from(x) % Q) as u32, (u128::from(y) % Q) as u32)
                }
            };
        }
    }
    (a, b)
}
fn challenge(nonce: u64) -> Hash {
    hash(
        b"task-product-facts-test-challenge",
        &[&nonce.to_le_bytes()],
    )
}
fn observed(
    cache: &TaskProductFactCache,
    c: Hash,
    task: Hash,
    proof: &[u8],
) -> (VerifiedWork, ProductObservation, Vec<VerificationProgress>) {
    let mut observation = ProductObservation::default();
    let mut points = Vec::new();
    let value = cache
        .verify_with_observation(
            c,
            task,
            [255; 32],
            proof,
            &mut |point| {
                points.push(point);
                Ok::<_, ()>(())
            },
            &mut observation,
        )
        .unwrap();
    (value, observation, points)
}
fn compare(a: &VerifiedWork, b: &VerifiedWork) {
    assert_eq!(a.challenge(), b.challenge());
    assert_eq!(a.task(), b.task());
    assert_eq!(a.ticket(), b.ticket());
    assert_eq!(a.product(), b.product());
}
fn product_rows(points: &[VerificationProgress]) -> usize {
    points
        .iter()
        .skip_while(|p| **p != VerificationProgress::BeforeProduct)
        .filter(|p| matches!(p, VerificationProgress::MatrixRow { .. }))
        .count()
}

#[test]
fn fresh_challenges_match_independent_scalar_and_raw_for_structured_and_dense_material() {
    for case in 0..6 {
        let (a, b) = material(case);
        let task = task_id(&a, &b).unwrap();
        let cache = TaskProductFactCache::new(2).unwrap();
        for nonce in 0..3 {
            let c = challenge(100 * u64::from(case) + nonce);
            let proof = prove(c, &a, &b).unwrap();
            let reference = verify_reference(c, task, [255; 32], &proof).unwrap();
            let raw = super::super::verify(c, task, [255; 32], &proof).unwrap();
            let (actual, observation, points) = observed(&cache, c, task, &proof);
            compare(&actual, &reference);
            compare(&actual, &raw);
            assert!(observation.transcript_entered && observation.transcript_completed);
            assert_eq!(observation.product_reused, nonce != 0);
            assert_eq!(observation.product_reconstruction_completed, nonce == 0);
            assert_eq!(
                points
                    .iter()
                    .filter(|p| matches!(p, VerificationProgress::TranscriptTile { .. }))
                    .count(),
                512
            );
            assert_eq!(product_rows(&points), if nonce == 0 { 200 } else { 0 });
            assert_eq!(
                observation.publication,
                if nonce == 0 {
                    ProductPublication::Stored
                } else {
                    ProductPublication::None
                }
            );
        }
    }
}

#[test]
fn every_current_claim_is_checked_on_both_cold_and_warm_paths() {
    let (a, b) = material(5);
    let task = task_id(&a, &b).unwrap();
    let c = challenge(91);
    let proof = prove(c, &a, &b).unwrap();
    let mut wrong_trace = proof.clone();
    wrong_trace[PROOF_BYTES - 1] ^= 1;
    let mut wrong_c = proof.clone();
    let offset = 4 + 2 * CELLS * 4;
    let word = u32::from_le_bytes(wrong_c[offset..offset + 4].try_into().unwrap());
    wrong_c[offset..offset + 4]
        .copy_from_slice(&(((u128::from(word) + 1) % Q) as u32).to_le_bytes());
    let mut noncanonical = proof.clone();
    noncanonical[offset..offset + 4].copy_from_slice(&(Q as u32).to_le_bytes());
    let mut wrong_version = proof.clone();
    wrong_version[0] ^= 1;
    let mut wrong_task = task;
    wrong_task[0] ^= 1;
    let cases = [
        (
            c,
            task,
            [255; 32],
            wrong_trace.as_slice(),
            WorkError::Transcript,
        ),
        (c, task, [255; 32], wrong_c.as_slice(), WorkError::Product),
        (
            c,
            task,
            [255; 32],
            noncanonical.as_slice(),
            WorkError::Field,
        ),
        (
            c,
            task,
            [255; 32],
            wrong_version.as_slice(),
            WorkError::Version,
        ),
        (
            c,
            task,
            [255; 32],
            &proof[..PROOF_BYTES - 1],
            WorkError::Length,
        ),
        (c, wrong_task, [255; 32], proof.as_slice(), WorkError::Task),
        (c, task, [0; 32], proof.as_slice(), WorkError::Target),
        (
            challenge(92),
            task,
            [255; 32],
            proof.as_slice(),
            WorkError::Transcript,
        ),
    ];
    for warm in [false, true] {
        for (current, current_task, target, bytes, expected) in cases {
            let cache = TaskProductFactCache::new(1).unwrap();
            if warm {
                cache.verify(c, task, [255; 32], &proof).unwrap();
            }
            let mut observation = ProductObservation::default();
            let result = cache.verify_with_observation(
                current,
                current_task,
                target,
                bytes,
                &mut |_| Ok::<_, ()>(()),
                &mut observation,
            );
            assert!(matches!(result, Err(FactError::Relation(error)) if error == expected));
            assert!(
                matches!(super::super::verify(current, current_task, target, bytes), Err(error) if error == expected)
            );
            assert_eq!(observation.publication, ProductPublication::None);
            let (_, after, _) = observed(&cache, c, task, &proof);
            assert_eq!(after.product_reused, warm);
        }
    }
}

#[test]
fn equal_products_do_not_alias_different_exact_inputs_or_evicted_tasks() {
    let cache = TaskProductFactCache::new(1).unwrap();
    let (a, b) = material(0);
    let mut other_a = a.clone();
    other_a[117] = 9; // Both products remain zero, but A bytes differ.
    let materials = [(&a, &b), (&other_a, &b), (&a, &b)];
    for (index, (a, b)) in materials.into_iter().enumerate() {
        let c = challenge(index as u64);
        let task = task_id(a, b).unwrap();
        let proof = prove(c, a, b).unwrap();
        let (_, observation, _) = observed(&cache, c, task, &proof);
        assert!(!observation.exact_inputs_found);
        assert!(!observation.product_reused);
        assert!(observation.product_reconstruction_completed);
        assert_eq!(observation.publication, ProductPublication::Stored);
        assert!(observation.lookup_probes <= 1 && observation.publication_probes <= 1);
    }
}

#[test]
fn cancellation_never_publishes_a_new_fact_and_keeps_existing_positive_fact() {
    let (a, b) = material(4);
    let task = task_id(&a, &b).unwrap();
    let c = challenge(42);
    let proof = prove(c, &a, &b).unwrap();
    let cancellation_points = [
        VerificationProgress::BeforeReplay,
        VerificationProgress::Noise {
            label: 2,
            counter: 3,
        },
        VerificationProgress::MatrixRow { row: 9 },
        VerificationProgress::TranscriptTile {
            row: 0,
            column: 0,
            inner: 0,
        },
        VerificationProgress::TranscriptTile {
            row: 7,
            column: 7,
            inner: 7,
        },
        VerificationProgress::BeforeProduct,
        VerificationProgress::BeforeVerifiedWork,
    ];
    for warm in [false, true] {
        for cancel_at in cancellation_points {
            let cache = TaskProductFactCache::new(1).unwrap();
            if warm {
                cache.verify(c, task, [255; 32], &proof).unwrap();
            }
            let mut observation = ProductObservation::default();
            let result = cache.verify_with_observation(
                c,
                task,
                [255; 32],
                &proof,
                &mut |point| {
                    if point == cancel_at {
                        Err("cancel")
                    } else {
                        Ok(())
                    }
                },
                &mut observation,
            );
            assert!(matches!(result, Err(FactError::Cancelled("cancel"))));
            assert_eq!(observation.publication, ProductPublication::None);
            let (_, after, _) = observed(&cache, c, task, &proof);
            assert_eq!(after.product_reused, warm);
        }
    }
    let cache = TaskProductFactCache::new(1).unwrap();
    let mut in_product = false;
    assert!(matches!(
        cache.verify_with_progress(c, task, [255; 32], &proof, &mut |point| {
            if point == VerificationProgress::BeforeProduct {
                in_product = true;
            }
            if in_product && point == (VerificationProgress::MatrixRow { row: 5 }) {
                Err("product-cancel")
            } else {
                Ok(())
            }
        }),
        Err(FactError::Cancelled("product-cancel"))
    ));
    assert!(!observed(&cache, c, task, &proof).1.product_reused);
}

#[test]
fn strict_ticket_target_is_fresh_even_with_an_exact_product_fact() {
    let (a, b) = material(1);
    let task = task_id(&a, &b).unwrap();
    let c = challenge(19);
    let proof = prove(c, &a, &b).unwrap();
    let cache = TaskProductFactCache::new(1).unwrap();
    let valid = cache.verify(c, task, [255; 32], &proof).unwrap();
    let ticket = valid.ticket();
    assert_ne!(ticket, [0; 32]);
    cache.verify(c, task, ticket, &proof).unwrap();
    let mut smaller = ticket;
    for byte in smaller.iter_mut().rev() {
        let (value, borrow) = byte.overflowing_sub(1);
        *byte = value;
        if !borrow {
            break;
        }
    }
    let mut observation = ProductObservation::default();
    assert!(matches!(
        cache.verify_with_observation(
            c,
            task,
            smaller,
            &proof,
            &mut |_| Ok::<_, ()>(()),
            &mut observation
        ),
        Err(FactError::Relation(WorkError::Target))
    ));
    assert_eq!(observation, ProductObservation::default());
}

#[test]
fn contention_runs_complete_raw_math_without_waiting_or_publishing() {
    let cache = TaskProductFactCache::new(1).unwrap();
    let (a, b) = material(3);
    let c = challenge(55);
    let task = task_id(&a, &b).unwrap();
    let proof = prove(c, &a, &b).unwrap();
    let guard = cache.state.lock().unwrap();
    let (actual, observation, points) = observed(&cache, c, task, &proof);
    assert_eq!(
        actual.product(),
        verify_reference(c, task, [255; 32], &proof)
            .unwrap()
            .product()
    );
    assert!(observation.lookup_contended);
    assert!(observation.product_reconstruction_completed);
    assert!(!observation.product_reused);
    assert_eq!(observation.publication, ProductPublication::Contended);
    assert_eq!(product_rows(&points), 200);
    drop(guard);
    assert!(!observed(&cache, c, task, &proof).1.product_reused);
}

#[test]
fn poison_is_unavailability_and_does_not_change_raw_verification() {
    let cache = Arc::new(TaskProductFactCache::new(1).unwrap());
    let poisoned = Arc::clone(&cache);
    assert!(std::thread::spawn(move || {
        let _guard = poisoned.state.lock().unwrap();
        panic!("intentional cache-poison control");
    })
    .join()
    .is_err());
    let (a, b) = material(0);
    let c = challenge(2);
    let task = task_id(&a, &b).unwrap();
    let proof = prove(c, &a, &b).unwrap();
    assert!(matches!(
        cache.verify(c, task, [255; 32], &proof),
        Err(FactError::Unavailable)
    ));
    super::super::verify(c, task, [255; 32], &proof).unwrap();
}

#[test]
fn simultaneous_new_challenges_never_reuse_trace_or_publish_partial_arithmetic() {
    let cache = Arc::new(TaskProductFactCache::new(2).unwrap());
    let barrier = Arc::new(Barrier::new(4));
    let (a, b) = material(5);
    let task = task_id(&a, &b).unwrap();
    let fixtures: Vec<_> = (0..4)
        .map(|i| {
            let c = challenge(800 + i);
            (c, prove(c, &a, &b).unwrap())
        })
        .collect();
    let mut workers = Vec::new();
    for (c, proof) in fixtures {
        let cache = Arc::clone(&cache);
        let barrier = Arc::clone(&barrier);
        workers.push(std::thread::spawn(move || {
            barrier.wait();
            let (actual, observation, points) = observed(&cache, c, task, &proof);
            compare(
                &actual,
                &verify_reference(c, task, [255; 32], &proof).unwrap(),
            );
            assert!(observation.transcript_completed);
            assert_eq!(
                points
                    .iter()
                    .filter(|p| matches!(p, VerificationProgress::TranscriptTile { .. }))
                    .count(),
                512
            );
        }));
    }
    for worker in workers {
        worker.join().unwrap();
    }
    let c = challenge(900);
    let proof = prove(c, &a, &b).unwrap();
    let (_, observation, _) = observed(&cache, c, task, &proof);
    assert!(observation.product_reused);
}

#[test]
fn bounded_storage_includes_keys_products_tags_capacity_and_owner_metadata() {
    assert!(TaskProductFactCache::new(0).is_err());
    assert!(TaskProductFactCache::new(MAX_TASK_PRODUCT_FACT_SLOTS + 1).is_err());
    for capacity in [1, 2, MAX_TASK_PRODUCT_FACT_SLOTS] {
        let cache = TaskProductFactCache::new(capacity).unwrap();
        let state = cache.state.lock().unwrap();
        assert_eq!(cache.capacity(), capacity);
        assert_eq!(
            cache.software_bytes(),
            size_of::<TaskProductFactCache>()
                + state.entries.capacity() * size_of::<Option<Fact>>()
        );
        assert!(cache.software_bytes() >= capacity * (INPUT_BYTES + CELLS * 4));
        assert!(cache.software_bytes() <= MAX_TASK_PRODUCT_FACT_SOFTWARE_BYTES);
    }
}
