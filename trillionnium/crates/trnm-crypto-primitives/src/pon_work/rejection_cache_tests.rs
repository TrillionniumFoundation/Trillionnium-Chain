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

    // One direct-mapped slot has really been replaced. Its prior key gets no
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
