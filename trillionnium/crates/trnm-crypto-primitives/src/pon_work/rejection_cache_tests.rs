use super::*;
use crate::pon_work::{prove, task_id, CELLS};

fn call(
    cache: &RejectionCache,
    challenge: Hash,
    task: Hash,
    target: Hash,
    proof: &[u8],
    cancel: Option<VerificationProgress>,
) -> (
    Result<VerifiedWork, VerificationError<&'static str>>,
    RejectionObservation,
    usize,
) {
    let mut observation = RejectionObservation::default();
    let mut tiles = 0;
    let result = cache.verify_with_observation(
        challenge,
        task,
        target,
        proof,
        &mut |point| {
            if matches!(point, VerificationProgress::TranscriptTile { .. }) {
                tiles += 1;
            }
            if Some(point) == cancel {
                Err("ORIGINAL_CALLER_CANCELLED")
            } else {
                Ok(())
            }
        },
        &mut observation,
    );
    (result, observation, tiles)
}

#[test]
fn observation_distinguishes_replayed_refusal_hit_cancellation_and_valid_work() {
    let cache = RejectionCache::new(1, MAX_REJECTION_CACHE_LIFETIME).unwrap();
    let zeros = vec![0; CELLS];
    let task = task_id(&zeros, &zeros).unwrap();
    let challenge = [91; 32];
    let target = [255; 32];
    let valid = prove(challenge, &zeros, &zeros).unwrap();
    let mut bad = valid.clone();
    bad[PROOF_BYTES - 1] ^= 1;
    let (result, cold, tiles) = call(&cache, challenge, task, target, &bad, None);
    assert!(matches!(
        result,
        Err(VerificationError::Relation(WorkError::Transcript))
    ));
    assert!(cold.key_hashed && cold.native_verifier_started && cold.native_verifier_returned);
    assert!(cold.full_replay_started);
    assert!(!cold.exact_fact_found && !cold.cached_rejection_returned);
    assert_eq!(cold.publication, RejectionPublication::Retained);
    assert_eq!(tiles, 512);

    let expiry = cache.slots.lock().unwrap()[0].unwrap().expires;
    let (result, warm, tiles) = call(&cache, challenge, task, target, &bad, None);
    assert!(matches!(
        result,
        Err(VerificationError::Relation(WorkError::Transcript))
    ));
    assert!(warm.exact_fact_found && warm.cached_rejection_returned);
    assert!(!warm.native_verifier_started && !warm.native_verifier_returned);
    assert!(!warm.full_replay_started);
    assert_eq!(warm.publication, RejectionPublication::None);
    assert_eq!(tiles, 0);
    assert_eq!(cache.slots.lock().unwrap()[0].unwrap().expires, expiry);

    let (result, cancelled, tiles) = call(
        &cache,
        challenge,
        task,
        target,
        &bad,
        Some(VerificationProgress::BeforeReplay),
    );
    assert_eq!(
        result.unwrap_err(),
        VerificationError::Cancelled("ORIGINAL_CALLER_CANCELLED")
    );
    assert!(cancelled.exact_fact_found);
    assert!(!cancelled.cached_rejection_returned && !cancelled.native_verifier_started);
    assert_eq!(tiles, 0);
    assert_eq!(cache.slots.lock().unwrap()[0].unwrap().expires, expiry);

    // A known-invalid variant cannot blacklist the valid proof. Valid returns
    // never populate a negative slot, and repeated valid calls still replay.
    for _ in 0..2 {
        let (result, actual, tiles) = call(&cache, challenge, task, target, &valid, None);
        assert!(result.is_ok());
        assert!(!actual.exact_fact_found && !actual.cached_rejection_returned);
        assert!(actual.native_verifier_started && actual.native_verifier_returned);
        assert!(actual.full_replay_started);
        assert_eq!(actual.publication, RejectionPublication::None);
        assert_eq!(tiles, 512);
    }

    let mut new_bad = bad.clone();
    new_bad[PROOF_BYTES - 2] ^= 1;
    let (result, cancelled, _) = call(
        &cache,
        challenge,
        task,
        target,
        &new_bad,
        Some(VerificationProgress::TranscriptTile {
            row: 4,
            column: 0,
            inner: 0,
        }),
    );
    assert_eq!(
        result.unwrap_err(),
        VerificationError::Cancelled("ORIGINAL_CALLER_CANCELLED")
    );
    assert!(cancelled.native_verifier_returned && cancelled.full_replay_started);
    assert_eq!(cancelled.publication, RejectionPublication::None);
    assert_eq!(cache.slots.lock().unwrap()[0].unwrap().expires, expiry);
}

#[test]
fn complete_key_expiry_collision_and_restart_keep_current_native_verification() {
    let cache = RejectionCache::new(1, MAX_REJECTION_CACHE_LIFETIME).unwrap();
    let zeros = vec![0; CELLS];
    let task = task_id(&zeros, &zeros).unwrap();
    let challenge = [92; 32];
    let target = [255; 32];
    let mut proof = prove(challenge, &zeros, &zeros).unwrap();
    proof[PROOF_BYTES - 1] ^= 1;
    let key = RejectionCache::key(challenge, task, target, &proof).unwrap();
    assert_eq!(
        key,
        hash(
            b"w1-exact-invalid-math-v1",
            &[PROFILE.as_bytes(), &challenge, &task, &target, &proof]
        )
    );
    assert_ne!(
        key,
        hash(
            b"w1-exact-invalid-math-v1",
            &[b"different-profile", &challenge, &task, &target, &proof]
        )
    );
    assert!(matches!(
        call(&cache, challenge, task, target, &proof, None).0,
        Err(VerificationError::Relation(WorkError::Transcript))
    ));

    let mut other_challenge = challenge;
    other_challenge[0] ^= 1;
    let mut other_target = target;
    other_target[31] -= 1;
    let mut other_task = task;
    other_task[0] ^= 1;
    let mut other_proof = proof.clone();
    other_proof[PROOF_BYTES - 2] ^= 1;
    for (challenge, task, target, proof) in [
        (other_challenge, task, target, proof.as_slice()),
        (challenge, task, other_target, proof.as_slice()),
        (challenge, other_task, target, proof.as_slice()),
        (challenge, task, target, other_proof.as_slice()),
    ] {
        assert_ne!(
            RejectionCache::key(challenge, task, target, proof),
            Some(key)
        );
        let (result, actual, _) = call(&cache, challenge, task, target, proof, None);
        let native = verify_with_progress(challenge, task, target, proof, &mut |_| {
            Ok::<(), &'static str>(())
        });
        assert_eq!(result.unwrap_err(), native.unwrap_err());
        assert!(!actual.exact_fact_found && !actual.cached_rejection_returned);
        assert!(actual.native_verifier_started && actual.native_verifier_returned);
    }

    // The one-slot cache has really been replaced. Its prior key gets no
    // retained verdict; restoring the original proof incurs a complete replay.
    assert_ne!(cache.slots.lock().unwrap()[0].unwrap().key, key);
    let (_, evicted, tiles) = call(&cache, challenge, task, target, &proof, None);
    assert!(!evicted.exact_fact_found && evicted.full_replay_started);
    assert_eq!(tiles, 512);
    // Set only this test's retained timestamp to the elapsed boundary. This
    // exercises actual expiry without sleeping or changing production clocks.
    cache.slots.lock().unwrap()[0].as_mut().unwrap().expires = Instant::now();
    let (_, expired, tiles) = call(&cache, challenge, task, target, &proof, None);
    assert!(!expired.exact_fact_found && expired.full_replay_started);
    assert_eq!(tiles, 512);

    let fresh = RejectionCache::new(1, MAX_REJECTION_CACHE_LIFETIME).unwrap();
    let (_, restarted, tiles) = call(&fresh, challenge, task, target, &proof, None);
    assert!(!restarted.exact_fact_found && restarted.full_replay_started);
    assert_eq!(tiles, 512);
    let mut wrong_version = proof;
    wrong_version[0] = b'X';
    let (result, version, tiles) = call(&cache, challenge, task, target, &wrong_version, None);
    assert_eq!(
        result.unwrap_err(),
        VerificationError::Relation(WorkError::Version)
    );
    assert!(!version.key_hashed && !version.exact_fact_found && !version.full_replay_started);
    assert_eq!(tiles, 0);
}

#[test]
fn retained_owner_bounds_count_allocated_slot_capacity() {
    let cache =
        RejectionCache::new(MAX_REJECTION_CACHE_SLOTS, MAX_REJECTION_CACHE_LIFETIME).unwrap();
    assert_eq!(cache.capacity(), 256);
    assert_eq!(cache.lifetime(), Duration::from_secs(30));
    let slots = cache.slots.lock().unwrap();
    assert_eq!(slots.len(), 256);
    assert!(slots.iter().all(Option::is_none));
    assert_eq!(
        cache.software_bytes(),
        size_of::<RejectionCache>() + slots.capacity() * size_of::<Option<InvalidFact>>()
    );
    assert!(cache.software_bytes() <= MAX_REJECTION_CACHE_SOFTWARE_BYTES);
    assert!(RejectionCache::new(MAX_REJECTION_CACHE_SLOTS + 1, Duration::from_secs(1)).is_none());
    assert!(
        RejectionCache::new(1, MAX_REJECTION_CACHE_LIFETIME + Duration::from_nanos(1)).is_none()
    );
}

#[test]
fn cheap_statement_refusal_records_native_outcome_without_cache_work() {
    let cache = RejectionCache::new(8, MAX_REJECTION_CACHE_LIFETIME).unwrap();
    let zeros = vec![0; CELLS];
    let task = task_id(&zeros, &zeros).unwrap();
    let challenge = [93; 32];
    let proof = prove(challenge, &zeros, &zeros).unwrap();
    let mut wrong_task = task;
    wrong_task[0] ^= 1;
    let mut low_target = [0; 32];
    low_target[31] = 1;
    for (task, target, expected) in [
        (wrong_task, [255; 32], WorkError::Task),
        (task, low_target, WorkError::Target),
    ] {
        let (result, observation, tiles) = call(
            &cache,
            challenge,
            task,
            target,
            &proof,
            Some(VerificationProgress::BeforeReplay),
        );
        assert_eq!(result.unwrap_err(), VerificationError::Relation(expected));
        assert!(observation.native_verifier_started && observation.native_verifier_returned);
        assert!(!observation.key_hashed && !observation.exact_fact_found);
        assert!(!observation.cached_rejection_returned && !observation.full_replay_started);
        assert!(!observation.lookup_contended && !observation.lookup_poisoned);
        assert_eq!(observation.publication, RejectionPublication::None);
        assert_eq!(tiles, 0);
    }
}

fn cache_test_key(selector: u64, identity: u8) -> Hash {
    let mut key = [0; 32];
    key[..8].copy_from_slice(&selector.to_le_bytes());
    key[31] = identity;
    key
}

#[test]
fn every_original_capacity_has_disjoint_bounded_sets_and_the_same_storage_bound() {
    for capacity in 1..=256 {
        let cache = RejectionCache::new(capacity, MAX_REJECTION_CACHE_LIFETIME).unwrap();
        assert_eq!(cache.capacity(), capacity);
        let slots = cache.slots.lock().unwrap();
        assert_eq!(slots.len(), capacity);
        assert!(slots.iter().all(Option::is_none));
        assert_eq!(
            cache.software_bytes(),
            size_of::<RejectionCache>() + slots.capacity() * size_of::<Option<InvalidFact>>()
        );
        assert!(cache.software_bytes() <= 32 * 1024);

        let mut sets = std::collections::BTreeSet::new();
        for selector in 0..=256 {
            let indices = RejectionCache::set_indices(cache_test_key(selector, 0), capacity);
            assert!((1..=4).contains(&indices.len()));
            assert!(indices.end <= capacity);
            sets.insert((indices.start, indices.end));
        }
        let mut covered = 0;
        for (start, end) in sets {
            assert_eq!(start, covered, "sets must neither overlap nor waste slots");
            covered = end;
        }
        assert_eq!(covered, capacity);
    }
}

#[test]
fn full_set_evicts_earliest_expiry_without_aliasing_keys_or_other_sets() {
    let cache = RejectionCache::new(8, MAX_REJECTION_CACHE_LIFETIME).unwrap();
    let keys = [1, 2, 3, 4].map(|identity| cache_test_key(0, identity));
    let neighbor = cache_test_key(1, 1);
    for key in keys {
        assert_eq!(
            cache.insert(key, WorkError::Transcript),
            RejectionPublication::Retained
        );
    }
    assert_eq!(
        cache.insert(neighbor, WorkError::Product),
        RejectionPublication::Retained
    );
    let mut observation = RejectionObservation::default();
    for key in keys {
        assert_eq!(
            cache.hit(key, &mut observation),
            Some(WorkError::Transcript)
        );
    }
    assert_eq!(cache.hit(cache_test_key(0, 99), &mut observation), None);
    assert_eq!(
        cache.hit(neighbor, &mut observation),
        Some(WorkError::Product)
    );

    let indices = RejectionCache::set_indices(keys[0], cache.capacity());
    assert_eq!(indices.len(), 4);
    let now = Instant::now();
    {
        let mut entries = cache.slots.lock().unwrap();
        for (entry, seconds) in entries[indices].iter_mut().zip([20, 18, 16, 19]) {
            entry.as_mut().unwrap().expires = now + Duration::from_secs(seconds);
        }
    }
    let fifth = cache_test_key(0, 5);
    assert_eq!(
        cache.insert(fifth, WorkError::Product),
        RejectionPublication::Retained
    );
    for key in [keys[0], keys[1], keys[3]] {
        assert_eq!(
            cache.hit(key, &mut observation),
            Some(WorkError::Transcript)
        );
    }
    assert_eq!(cache.hit(keys[2], &mut observation), None);
    assert_eq!(cache.hit(fifth, &mut observation), Some(WorkError::Product));
    assert_eq!(
        cache.hit(neighbor, &mut observation),
        Some(WorkError::Product)
    );
}

#[test]
fn completed_republication_reuses_exact_key_before_an_empty_slot_or_eviction() {
    let cache = RejectionCache::new(4, MAX_REJECTION_CACHE_LIFETIME).unwrap();
    let first = cache_test_key(0, 1);
    let retained = cache_test_key(0, 2);
    cache.insert(first, WorkError::Transcript);
    cache.insert(retained, WorkError::Product);
    // A vacant slot preceding an existing key must not create duplicate facts.
    cache.slots.lock().unwrap()[0] = None;
    assert_eq!(
        cache.insert(retained, WorkError::Product),
        RejectionPublication::Retained
    );
    {
        let entries = cache.slots.lock().unwrap();
        assert!(entries[0].is_none());
        assert_eq!(entries.iter().flatten().count(), 1);
        assert_eq!(entries[1].unwrap().key, retained);
    }
    for key in [first, cache_test_key(0, 3), cache_test_key(0, 4)] {
        cache.insert(key, WorkError::Transcript);
    }
    assert_eq!(
        cache.insert(retained, WorkError::Product),
        RejectionPublication::Retained
    );
    let entries = cache.slots.lock().unwrap();
    assert_eq!(entries.iter().flatten().count(), 4);
    assert_eq!(
        entries
            .iter()
            .flatten()
            .filter(|entry| entry.key == retained)
            .count(),
        1
    );
    assert_eq!(entries[1].unwrap().key, retained);
}

#[test]
fn expired_entries_miss_hits_do_not_extend_expiry_and_equal_deadlines_evict_first() {
    let cache = RejectionCache::new(4, MAX_REJECTION_CACHE_LIFETIME).unwrap();
    let keys = [1, 2, 3, 4].map(|identity| cache_test_key(0, identity));
    for key in keys {
        cache.insert(key, WorkError::Transcript);
    }
    let deadline = Instant::now() + Duration::from_secs(20);
    {
        let mut entries = cache.slots.lock().unwrap();
        for entry in entries.iter_mut().flatten() {
            entry.expires = deadline;
        }
        entries[2].as_mut().unwrap().expires = Instant::now();
    }
    let mut observation = RejectionObservation::default();
    assert_eq!(cache.hit(keys[2], &mut observation), None);
    assert_eq!(
        cache.hit(keys[0], &mut observation),
        Some(WorkError::Transcript)
    );
    assert_eq!(cache.slots.lock().unwrap()[0].unwrap().expires, deadline);
    let fifth = cache_test_key(0, 5);
    cache.insert(fifth, WorkError::Product);
    {
        let mut entries = cache.slots.lock().unwrap();
        assert_eq!(entries[2].unwrap().key, fifth);
        for entry in entries.iter_mut().flatten() {
            entry.expires = deadline;
        }
    }
    let sixth = cache_test_key(0, 6);
    cache.insert(sixth, WorkError::Product);
    assert_eq!(cache.hit(keys[0], &mut observation), None);
    for key in [keys[1], keys[3]] {
        assert_eq!(
            cache.hit(key, &mut observation),
            Some(WorkError::Transcript)
        );
    }
    assert_eq!(cache.hit(fifth, &mut observation), Some(WorkError::Product));
    assert_eq!(cache.slots.lock().unwrap()[0].unwrap().key, sixth);
}

#[test]
fn associative_publication_still_refuses_all_nonmathematical_errors() {
    let cache = RejectionCache::new(4, MAX_REJECTION_CACHE_LIFETIME).unwrap();
    for error in [
        WorkError::Length,
        WorkError::Version,
        WorkError::Field,
        WorkError::Task,
        WorkError::Target,
        WorkError::NoiseBudget,
    ] {
        assert_eq!(
            cache.insert(cache_test_key(0, 1), error),
            RejectionPublication::None
        );
    }
    assert!(cache.slots.lock().unwrap().iter().all(Option::is_none));
}

#[test]
fn real_colliding_proofs_replay_once_each_then_retain_exact_cancelable_refusals() {
    let cache = RejectionCache::new(8, MAX_REJECTION_CACHE_LIFETIME).unwrap();
    let zeros = vec![0; CELLS];
    let task = task_id(&zeros, &zeros).unwrap();
    let challenge = [94; 32];
    let target = [255; 32];
    let valid = prove(challenge, &zeros, &zeros).unwrap();
    let mut colliding = Vec::new();
    let mut original_slot = None;
    for nonce in 0_u64..1024 {
        let mut proof = valid.clone();
        let false_trace = hash(b"w1-associative-cache-test-v1", &[&nonce.to_le_bytes()]);
        assert_ne!(false_trace.as_slice(), &valid[PROOF_BYTES - 32..]);
        proof[PROOF_BYTES - 32..].copy_from_slice(&false_trace);
        let key = RejectionCache::key(challenge, task, target, &proof).unwrap();
        // Exercise an actual collision under the original direct-mapped rule,
        // with independently generated mathematical statements, not CI packets.
        let slot = u64::from_le_bytes(key[..8].try_into().unwrap()) as usize % 8;
        if slot != *original_slot.get_or_insert(slot) {
            continue;
        }
        colliding.push(proof);
        if colliding.len() == 4 {
            break;
        }
    }
    assert_eq!(colliding.len(), 4, "bounded synthetic collision search");
    for proof in &colliding {
        let (result, cold, tiles) = call(&cache, challenge, task, target, proof, None);
        assert_eq!(
            result.unwrap_err(),
            VerificationError::Relation(WorkError::Transcript)
        );
        assert!(cold.full_replay_started && cold.native_verifier_returned);
        assert!(!cold.exact_fact_found && !cold.cached_rejection_returned);
        assert_eq!(cold.publication, RejectionPublication::Retained);
        assert_eq!(tiles, 512);
    }
    let expiry_before: Vec<_> = cache
        .slots
        .lock()
        .unwrap()
        .iter()
        .flatten()
        .map(|entry| (entry.key, entry.expires))
        .collect();
    assert_eq!(expiry_before.len(), 4);
    for proof in colliding.iter().cycle().take(12) {
        let (result, warm, tiles) = call(&cache, challenge, task, target, proof, None);
        assert_eq!(
            result.unwrap_err(),
            VerificationError::Relation(WorkError::Transcript)
        );
        assert!(warm.exact_fact_found && warm.cached_rejection_returned);
        assert!(!warm.full_replay_started && !warm.native_verifier_started);
        assert_eq!(tiles, 0);
    }
    for proof in &colliding {
        let (result, cancelled, tiles) = call(
            &cache,
            challenge,
            task,
            target,
            proof,
            Some(VerificationProgress::BeforeReplay),
        );
        assert_eq!(
            result.unwrap_err(),
            VerificationError::Cancelled("ORIGINAL_CALLER_CANCELLED")
        );
        assert!(cancelled.exact_fact_found);
        assert!(!cancelled.cached_rejection_returned && !cancelled.full_replay_started);
        assert_eq!(tiles, 0);
    }
    let (result, native, tiles) = call(&cache, challenge, task, target, &valid, None);
    assert!(result.is_ok() && native.full_replay_started);
    assert_eq!(native.publication, RejectionPublication::None);
    assert_eq!(tiles, 512);
    let expiry_after: Vec<_> = cache
        .slots
        .lock()
        .unwrap()
        .iter()
        .flatten()
        .map(|entry| (entry.key, entry.expires))
        .collect();
    assert_eq!(expiry_after, expiry_before);
}
