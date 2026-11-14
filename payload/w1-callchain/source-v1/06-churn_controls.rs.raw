//! Executable negative scope: a fixed-size round-robin cache is not a general
//! adversarial work admission or minimum-cost guarantee. Every rotating input
//! below is rejected, but every revisit still executes the complete transcript.
//! This is the actual mathematical kernel, not a model of the replacement rule.
use super::tests::{fixture, native_arithmetic, reset_native_arithmetic};
use super::*;
use std::convert::Infallible;

fn rotating_challenges_execute_every_transcript(capacity: usize) {
    let (_, task, mut proof) = fixture(187);
    proof[PROOF_BYTES - 1] ^= 1;
    let inputs = proof[4..4 + INPUT_BYTES].to_vec();
    let distinct = capacity + 1;
    let challenges: Vec<Hash> = (0..distinct)
        .map(|index| {
            let mut challenge = [0; 32];
            challenge[..8].copy_from_slice(&(index as u64).to_le_bytes());
            challenge[31] = 0xd4;
            challenge
        })
        .collect();
    // Use the retained raw implementation to establish the actual error for
    // every challenge before starting the counters. The maximum target is only
    // this mathematical control's input; no service target or ticket is changed.
    for challenge in &challenges {
        assert_eq!(
            super::super::verify(*challenge, task, [255; 32], &proof).unwrap_err(),
            WorkError::Transcript
        );
    }
    let cache = ArithmeticFactCache::new(capacity).unwrap();
    let software_bytes = cache.software_bytes();
    let allocated_slots = cache.state.lock().unwrap().entries.capacity();
    assert!(software_bytes <= MAX_ARITHMETIC_FACT_SOFTWARE_BYTES);
    reset_native_arithmetic();
    let mut calls = 0;
    let mut complete_tiles = 0;
    for cycle in 0..2 {
        for challenge in &challenges {
            let mut observation = ArithmeticObservation::default();
            let mut tiles = 0;
            let result = cache.verify_with_observation(
                *challenge,
                task,
                [255; 32],
                &proof,
                &mut |point| {
                    if matches!(point, VerificationProgress::TranscriptTile { .. }) {
                        tiles += 1;
                    }
                    Ok::<(), Infallible>(())
                },
                &mut observation,
            );
            assert_eq!(
                result.unwrap_err(),
                FactError::Relation(WorkError::Transcript)
            );
            assert_eq!(tiles, (N / R).pow(3));
            assert!(!observation.exact_fact_found);
            assert!(!observation.trace_reused && !observation.product_reused);
            assert!(observation.transcript_entered && observation.transcript_completed);
            assert!(!observation.product_entered && !observation.product_completed);
            assert_eq!(observation.publication, ArithmeticPublication::Trace);
            assert_eq!(observation.lookup_probes, capacity);
            assert_eq!(observation.publication_probes, capacity);
            calls += 1;
            complete_tiles += tiles;
            assert_eq!(native_arithmetic(), (calls, calls, 0));
            assert_eq!(cache.capacity(), capacity);
            assert_eq!(cache.software_bytes(), software_bytes);
            let state = cache.state.lock().unwrap();
            assert_eq!(state.entries.len(), capacity);
            assert_eq!(state.entries.capacity(), allocated_slots);
            assert!(state.replacement < capacity);
            let retained = state.entries.iter().flatten().count();
            assert_eq!(retained, calls.min(capacity));
            assert!(state.entries.iter().flatten().all(|entry| {
                entry.inputs.as_slice() == inputs.as_slice()
                    && entry.arithmetic.product.is_none()
                    && challenges.contains(&entry.challenge)
            }));
        }
        // At this exact cyclic boundary the oldest of capacity+1 distinct keys
        // is absent. Repeatedly revisiting all keys in the same order guarantees
        // another full miss cycle; no TTL, randomness or timing is involved.
        let state = cache.state.lock().unwrap();
        assert!(state
            .entries
            .iter()
            .flatten()
            .all(|entry| entry.challenge != challenges[0]));
        assert_eq!(calls, (cycle + 1) * distinct);
    }
    assert_eq!(calls, 2 * distinct);
    assert_eq!(complete_tiles, calls * 512);
    println!(
        "ARITHMETIC_CHURN_CONTROL capacity={capacity} distinct_challenges={distinct} \
         fixed_A_B=true cycles=2 calls={calls} complete_transcripts={calls} \
         complete_tiles={complete_tiles} cache_hits=0 retained_software_bytes={software_bytes} \
         all_results=Transcript service_or_physical_cost_bound=false"
    );
}

#[test]
fn three_rotating_challenges_over_two_slots_repeat_every_actual_transcript() {
    rotating_challenges_execute_every_transcript(2);
}

#[test]
fn sixty_five_rotating_challenges_over_sixty_four_slots_keep_zero_hits_and_bounded_storage() {
    rotating_challenges_execute_every_transcript(MAX_ARITHMETIC_FACT_SLOTS);
}
