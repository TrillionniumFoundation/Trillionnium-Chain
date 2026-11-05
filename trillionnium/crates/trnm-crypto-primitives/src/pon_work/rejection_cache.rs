//! Optional exact W1 mathematical rejection cache. No acceptance/authority cache.
//! A fresh forged trace still incurs full W1 replay; this protects ONLY exact
//! repeated bogus mathematical statements in the same local receiver epoch.
//! Contended or poisoned cache locks never delay the caller: lookup misses and
//! publication is skipped while the original verifier retains its checkpoints.
use super::{
    hash, verify_with_progress, Hash, VerificationError, VerificationProgress, VerifiedWork,
    WorkError, PROFILE, PROOF_BYTES,
};
use std::{
    sync::Mutex,
    time::{Duration, Instant},
};

#[cfg(test)]
std::thread_local! {
    // Actual bytes passed to this optional cache's full-proof digest. This is
    // separate from task hashing and arithmetic, and absent from production.
    static CACHE_KEY_PROOF_BYTES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[derive(Clone, Copy)]
struct InvalidFact {
    key: Hash,
    error: WorkError,
    expires: Instant,
}

/// Immutable negative mathematical facts only. Every caller must separately
/// recheck current parent, eligibility, expected target, time and body state.
/// The optional cache neither constructs VerifiedWork nor provides a CPU quota.
pub struct RejectionCache {
    slots: Mutex<Vec<Option<InvalidFact>>>,
    lifetime: Duration,
}

impl RejectionCache {
    /// A finite direct-mapped cache is deliberately not a second block registry.
    /// No caller ID, header height or work score grants priority or authority.
    pub fn new(slots: usize, lifetime: Duration) -> Option<Self> {
        if !(1..=256).contains(&slots) || lifetime.is_zero() || lifetime > Duration::from_secs(30) {
            return None;
        }
        Some(Self {
            slots: Mutex::new(vec![None; slots]),
            lifetime,
        })
    }

    fn key(challenge: Hash, task: Hash, target: Hash, bytes: &[u8]) -> Option<Hash> {
        // The original verifier refuses a wrong width before reading proof
        // bytes. An optional cache must not turn that constant-cost refusal
        // into an unbounded hash over an attacker-controlled buffer.
        if bytes.len() != PROOF_BYTES {
            return None;
        }
        #[cfg(test)]
        CACHE_KEY_PROOF_BYTES.with(|count| count.set(count.get() + bytes.len()));
        Some(hash(
            b"w1-exact-invalid-math-v1",
            &[PROFILE.as_bytes(), &challenge, &task, &target, bytes],
        ))
    }

    fn hit(&self, key: Hash) -> Option<WorkError> {
        // Optional reuse must not wait outside the caller's cancellation and
        // deadline checkpoints. Contention, like poison, is a cache miss.
        let entries = self.slots.try_lock().ok()?;
        let i = u64::from_le_bytes(key[..8].try_into().ok()?) as usize % entries.len();
        entries[i]
            .filter(|entry| entry.key == key && Instant::now() < entry.expires)
            .map(|entry| entry.error)
    }

    fn insert(&self, key: Hash, error: WorkError) {
        if !matches!(error, WorkError::Transcript | WorkError::Product) {
            return;
        }
        // Losing optional publication to contention or poison never delays or
        // changes the already completed mathematical refusal.
        if let Ok(mut entries) = self.slots.try_lock() {
            let i = (u64::from_le_bytes(key[..8].try_into().expect("32-byte key")) as usize)
                % entries.len();
            entries[i] = Some(InvalidFact {
                key,
                error,
                expires: Instant::now() + self.lifetime,
            });
        }
    }

    pub fn verify_with_progress<E>(
        &self,
        challenge: Hash,
        expected_task: Hash,
        target: Hash,
        proof: &[u8],
        progress: &mut impl FnMut(VerificationProgress) -> Result<(), E>,
    ) -> Result<VerifiedWork, VerificationError<E>> {
        // Keep the native Length, Version, zero-Target, Field ordering before
        // hashing all proof bytes for optional reuse. Delegate the first three
        // failures to the original verifier; the shared encoding filter then
        // checks every canonical field without allocating or hashing A/B.
        // Task/ticket checks stay with the native verifier on a miss, so this
        // filter does not add a second task hash to ordinary cold verification.
        if proof.len() != PROOF_BYTES || &proof[..4] != b"PNW1" || target == [0; 32] {
            return verify_with_progress(challenge, expected_task, target, proof, progress);
        }
        super::precheck_proof_encoding(proof)?;
        let Some(key) = Self::key(challenge, expected_task, target, proof) else {
            // Preserve the native error ordering and cancellation semantics;
            // malformed lengths never consult or populate the cache.
            return verify_with_progress(challenge, expected_task, target, proof, progress);
        };
        if let Some(error) = self.hit(key) {
            // A cached error is only a performance hint. Callers must still be
            // able to cancel, and must have checked present branch authority.
            progress(VerificationProgress::BeforeReplay).map_err(VerificationError::Cancelled)?;
            return Err(VerificationError::Relation(error));
        }
        let result = verify_with_progress(challenge, expected_task, target, proof, progress);
        if let Err(VerificationError::Relation(error)) = &result {
            self.insert(key, *error);
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pon_work::{prove, task_id, CELLS, PROOF_BYTES};
    use std::{sync::mpsc, thread};

    type WorkSummary = (Hash, Hash, Hash, Vec<u32>);
    type Observation = (
        Result<WorkSummary, VerificationError<&'static str>>,
        Vec<VerificationProgress>,
    );

    fn while_slots_locked<T: Send>(
        cache: &RejectionCache,
        operation: impl FnOnce() -> T + Send,
    ) -> T {
        thread::scope(|scope| {
            let held = cache.slots.lock().unwrap();
            let (finished, completion) = mpsc::channel();
            let worker = scope.spawn(move || {
                let result = operation();
                finished.send(()).unwrap();
                result
            });
            // Always release the lock before joining or asserting. A regression
            // to blocking cache access fails rather than stranding a worker.
            let completed_while_locked = completion.recv_timeout(Duration::from_secs(10));
            drop(held);
            let result = worker.join().unwrap();
            assert!(
                completed_while_locked.is_ok(),
                "optional rejection-cache access waited for the held slots lock"
            );
            result
        })
    }

    fn observed(
        cache: Option<&RejectionCache>,
        challenge: Hash,
        task: Hash,
        proof: &[u8],
        cancel: Option<VerificationProgress>,
    ) -> Observation {
        let mut points = Vec::new();
        let mut progress = |point| {
            points.push(point);
            if Some(point) == cancel {
                Err("CALLER_CANCELLED")
            } else {
                Ok(())
            }
        };
        let result = match cache {
            Some(cache) => {
                cache.verify_with_progress(challenge, task, [255; 32], proof, &mut progress)
            }
            None => verify_with_progress(challenge, task, [255; 32], proof, &mut progress),
        };
        (
            result.map(|work| {
                (
                    work.challenge(),
                    work.task(),
                    work.ticket(),
                    work.product().to_vec(),
                )
            }),
            points,
        )
    }

    #[test]
    fn contended_lookup_and_publication_keep_complete_native_replay() {
        let cache = RejectionCache::new(8, Duration::from_secs(30)).unwrap();
        let zeros = vec![0; CELLS];
        let task = task_id(&zeros, &zeros).unwrap();
        let challenge = [39; 32];
        let valid = prove(challenge, &zeros, &zeros).unwrap();
        let mut warm_false = valid.clone();
        warm_false[PROOF_BYTES - 1] ^= 1;
        let mut cold_false = valid.clone();
        cold_false[PROOF_BYTES - 2] ^= 1;
        let mut false_product = valid.clone();
        false_product[4 + 2 * CELLS * 4] = 1;
        assert!(matches!(
            observed(Some(&cache), challenge, task, &warm_false, None).0,
            Err(VerificationError::Relation(WorkError::Transcript))
        ));
        while_slots_locked(&cache, || {
            for proof in [&warm_false, &cold_false, &false_product, &valid] {
                let expected = observed(None, challenge, task, proof, None);
                let actual = observed(Some(&cache), challenge, task, proof, None);
                assert_eq!(actual, expected);
                assert_eq!(
                    actual
                        .1
                        .iter()
                        .filter(|point| matches!(
                            point,
                            VerificationProgress::TranscriptTile { .. }
                        ))
                        .count(),
                    512,
                    "even the previously cached false claim needs complete replay on contention"
                );
            }
        });
        let key = RejectionCache::key(challenge, task, [255; 32], &cold_false).unwrap();
        assert!(
            cache.hit(key).is_none(),
            "contended publication must be skipped"
        );
        // The original warm fact was neither invalidated nor replaced by a
        // contended caller; after release only its exact retransmission skips.
        let warm = observed(Some(&cache), challenge, task, &warm_false, None);
        assert_eq!(warm.1, vec![VerificationProgress::BeforeReplay]);
        assert!(matches!(
            warm.0,
            Err(VerificationError::Relation(WorkError::Transcript))
        ));
    }

    #[test]
    fn contended_cache_retains_caller_cancellation_and_cheap_errors() {
        let cache = RejectionCache::new(8, Duration::from_secs(30)).unwrap();
        let zeros = vec![0; CELLS];
        let task = task_id(&zeros, &zeros).unwrap();
        let challenge = [40; 32];
        let valid = prove(challenge, &zeros, &zeros).unwrap();
        while_slots_locked(&cache, || {
            for point in [
                VerificationProgress::BeforeReplay,
                VerificationProgress::TranscriptTile {
                    row: 7,
                    column: 7,
                    inner: 7,
                },
                VerificationProgress::BeforeProduct,
                VerificationProgress::BeforeVerifiedWork,
            ] {
                let expected = observed(None, challenge, task, &valid, Some(point));
                let actual = observed(Some(&cache), challenge, task, &valid, Some(point));
                assert_eq!(actual, expected);
                assert_eq!(
                    actual.0,
                    Err(VerificationError::Cancelled("CALLER_CANCELLED"))
                );
            }
            let mut bad_version = valid.clone();
            bad_version[0] = b'X';
            for proof in [&valid[..PROOF_BYTES - 1], bad_version.as_slice()] {
                let expected = observed(
                    None,
                    challenge,
                    task,
                    proof,
                    Some(VerificationProgress::BeforeReplay),
                );
                let actual = observed(
                    Some(&cache),
                    challenge,
                    task,
                    proof,
                    Some(VerificationProgress::BeforeReplay),
                );
                assert_eq!(actual, expected);
                assert!(actual.1.is_empty(), "cheap errors precede callbacks");
            }
        });
        assert!(cache.slots.lock().unwrap().iter().all(Option::is_none));
    }

    #[test]
    fn poisoned_cache_keeps_native_math_and_caller_cancellation() {
        let cache = RejectionCache::new(8, Duration::from_secs(30)).unwrap();
        let poisoned = thread::scope(|scope| {
            scope
                .spawn(|| {
                    let _held = cache.slots.lock().unwrap();
                    panic!("intentional rejection-cache poison control");
                })
                .join()
        });
        assert!(poisoned.is_err());
        assert!(cache.slots.is_poisoned());
        let zeros = vec![0; CELLS];
        let task = task_id(&zeros, &zeros).unwrap();
        let challenge = [41; 32];
        let valid = prove(challenge, &zeros, &zeros).unwrap();
        let mut false_trace = valid.clone();
        false_trace[PROOF_BYTES - 1] ^= 1;
        for proof in [&false_trace, &valid] {
            assert_eq!(
                observed(Some(&cache), challenge, task, proof, None),
                observed(None, challenge, task, proof, None)
            );
        }
        assert_eq!(
            observed(
                Some(&cache),
                challenge,
                task,
                &valid,
                Some(VerificationProgress::BeforeReplay),
            )
            .0,
            Err(VerificationError::Cancelled("CALLER_CANCELLED"))
        );
        assert!(cache.slots.is_poisoned());
    }

    #[test]
    fn malformed_width_has_no_cache_key_and_retains_native_length_precedence() {
        let cache = RejectionCache::new(8, Duration::from_secs(2)).unwrap();
        let challenge = [17; 32];
        let task = [23; 32];
        // Simultaneously invalid version, task and target must not change the
        // original Length verdict. A cancellation callback is never reached.
        for length in [0, 3, PROOF_BYTES - 1, PROOF_BYTES + 1, 1_048_576] {
            let proof = vec![255; length];
            assert!(RejectionCache::key(challenge, task, [0; 32], &proof).is_none());
            let result = cache.verify_with_progress(challenge, task, [0; 32], &proof, &mut |_| {
                Err::<(), _>("must not reach cancellation")
            });
            assert!(matches!(
                result,
                Err(VerificationError::Relation(WorkError::Length))
            ));
        }
        assert!(cache.slots.lock().unwrap().iter().all(Option::is_none));
    }

    #[test]
    fn cheap_structural_refusals_never_hash_the_whole_proof_for_optional_reuse() {
        let cache = RejectionCache::new(1, Duration::from_secs(30)).unwrap();
        let challenge = [47; 32];
        let zeros = vec![0; CELLS];
        let task = task_id(&zeros, &zeros).unwrap();
        let valid = prove(challenge, &zeros, &zeros).unwrap();
        let mut malformed = Vec::new();
        malformed.push((vec![255; PROOF_BYTES + 1], [0; 32], WorkError::Length));
        let mut version = valid.clone();
        version[0] = b'X';
        // Simultaneous failures exercise the original precedence, including
        // zero target before a noncanonical field word.
        version[4..8].copy_from_slice(&(super::super::Q as u32).to_le_bytes());
        malformed.push((version, [0; 32], WorkError::Version));
        malformed.push((valid.clone(), [0; 32], WorkError::Target));
        for matrix in 0..3 {
            for word in [0, CELLS - 1] {
                let mut fields = valid.clone();
                let start = 4 + (matrix * CELLS + word) * 4;
                fields[start..start + 4].copy_from_slice(&(super::super::Q as u32).to_le_bytes());
                malformed.push((fields.clone(), [0; 32], WorkError::Target));
                malformed.push((fields, [255; 32], WorkError::Field));
            }
        }
        for (proof, target, error) in malformed {
            let mut expected_points = Vec::new();
            let expected = verify_with_progress(challenge, task, target, &proof, &mut |point| {
                expected_points.push(point);
                Err::<(), _>("must not reach cancellation")
            });
            CACHE_KEY_PROOF_BYTES.with(|count| count.set(0));
            let mut actual_points = Vec::new();
            let actual =
                cache.verify_with_progress(challenge, task, target, &proof, &mut |point| {
                    actual_points.push(point);
                    Err::<(), _>("must not reach cancellation")
                });
            assert_eq!(expected.unwrap_err(), VerificationError::Relation(error));
            assert_eq!(actual.unwrap_err(), VerificationError::Relation(error));
            assert!(expected_points.is_empty());
            assert_eq!(actual_points, expected_points);
            assert_eq!(CACHE_KEY_PROOF_BYTES.with(std::cell::Cell::get), 0);
            assert!(cache.slots.lock().unwrap().iter().all(Option::is_none));
        }
        // Positive control for the counter and the complete native path: a
        // well-formed legal proof still hashes once and replays all 512 tiles.
        CACHE_KEY_PROOF_BYTES.with(|count| count.set(0));
        let accepted = observed(Some(&cache), challenge, task, &valid, None);
        assert!(accepted.0.is_ok());
        assert_eq!(
            CACHE_KEY_PROOF_BYTES.with(std::cell::Cell::get),
            PROOF_BYTES
        );
        assert_eq!(
            accepted
                .1
                .iter()
                .filter(|point| matches!(point, VerificationProgress::TranscriptTile { .. }))
                .count(),
            512
        );
    }

    #[test]
    fn false_transcript_replay_is_skipped_but_real_proof_still_passes() {
        let cache = RejectionCache::new(8, Duration::from_secs(2)).unwrap();
        let a = vec![0; CELLS];
        let task = task_id(&a, &a).unwrap();
        let challenge = [73; 32];
        let target = [255; 32];
        let valid = prove(challenge, &a, &a).unwrap();
        let mut bad = valid.clone();
        bad[PROOF_BYTES - 1] ^= 1;
        for expected in [512, 0] {
            let mut replays = 0;
            let r = cache.verify_with_progress(challenge, task, target, &bad, &mut |point| {
                if matches!(point, VerificationProgress::TranscriptTile { .. }) {
                    replays += 1;
                }
                Ok::<(), ()>(())
            });
            assert!(matches!(
                r,
                Err(VerificationError::Relation(WorkError::Transcript))
            ));
            assert_eq!(replays, expected);
        }
        assert!(cache
            .verify_with_progress(challenge, task, target, &valid, &mut |_| Ok::<(), ()>(()))
            .is_ok());
        let mut changed_context = challenge;
        changed_context[0] ^= 1;
        // A different challenge never inherits the old negative fact.
        let mut other_replay = 0;
        let _ = cache.verify_with_progress(changed_context, task, target, &bad, &mut |point| {
            if matches!(point, VerificationProgress::TranscriptTile { .. }) {
                other_replay += 1;
            }
            Ok::<(), ()>(())
        });
        assert_eq!(other_replay, 512);
    }

    #[test]
    fn four_distinct_from_zero_false_traces_each_owe_first_full_replay() {
        // The cache is strictly an EXACT retransmission defense, not an
        // attacker-cost floor and not a Sybil or arbitrary-trace defense.
        let cache = RejectionCache::new(64, Duration::from_secs(30)).unwrap();
        let zeros = vec![0; CELLS];
        let task = task_id(&zeros, &zeros).unwrap();
        let challenge = [81; 32];
        let target = [255; 32];
        let mut first = None;
        let mut digests = std::collections::BTreeSet::new();
        for nonce in 0_u64..4 {
            // Deliberately never call prove() or reuse a valid transcript.
            let fake = hash(
                b"w1-negative-cache-from-zero-v1",
                &[&challenge, &nonce.to_le_bytes()],
            );
            assert!(digests.insert(fake));
            let mut wire = vec![0u8; PROOF_BYTES];
            wire[..4].copy_from_slice(b"PNW1");
            wire[PROOF_BYTES - 32..].copy_from_slice(&fake);
            let mut tiles = 0;
            let result = cache.verify_with_progress(challenge, task, target, &wire, &mut |point| {
                if matches!(point, VerificationProgress::TranscriptTile { .. }) {
                    tiles += 1;
                }
                Ok::<(), ()>(())
            });
            assert!(matches!(
                result,
                Err(VerificationError::Relation(WorkError::Transcript))
            ));
            assert_eq!(
                tiles, 512,
                "new fake claim must not inherit prior negative fact"
            );
            if first.is_none() {
                first = Some(wire);
            }
        }
        let mut replayed = 0;
        let hit =
            cache.verify_with_progress(challenge, task, target, &first.unwrap(), &mut |point| {
                if matches!(point, VerificationProgress::TranscriptTile { .. }) {
                    replayed += 1;
                }
                Ok::<(), ()>(())
            });
        assert!(matches!(
            hit,
            Err(VerificationError::Relation(WorkError::Transcript))
        ));
        assert_eq!(
            replayed, 0,
            "only an exact cached false proof is short-circuited"
        );
    }

    #[test]
    fn local_cancellation_cannot_use_a_cached_fact_as_a_verdict() {
        let cache = RejectionCache::new(1, Duration::from_secs(1)).unwrap();
        let zeros = vec![0; CELLS];
        let challenge = [9; 32];
        let task = task_id(&zeros, &zeros).unwrap();
        let mut false_proof = prove(challenge, &zeros, &zeros).unwrap();
        false_proof[PROOF_BYTES - 1] ^= 1;
        let _ = cache.verify_with_progress(challenge, task, [255; 32], &false_proof, &mut |_| {
            Ok::<(), &str>(())
        });
        assert!(matches!(
            cache.verify_with_progress(challenge, task, [255; 32], &false_proof, &mut |_| Err::<
                (),
                _,
            >(
                "CANCEL"
            )),
            Err(VerificationError::Cancelled("CANCEL"))
        ));
        assert!(RejectionCache::new(0, Duration::from_secs(1)).is_none());
        assert!(RejectionCache::new(1, Duration::ZERO).is_none());
    }
}
