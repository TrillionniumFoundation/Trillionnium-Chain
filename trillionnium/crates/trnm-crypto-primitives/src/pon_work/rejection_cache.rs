//! Optional exact W1 mathematical rejection cache. No acceptance/authority cache.
//! New forged traces still each incur full W1 replay. Exact simultaneous
//! forgeries share one pending replay; unrelated colliding inputs NEVER wait.
//! This is optional local work conservation, not an admission cost floor.
use super::{
    hash, verify_with_progress, Hash, VerificationError, VerificationProgress, VerifiedWork,
    WorkError, PROFILE,
};
use std::{
    sync::{
        atomic::{AtomicU64, Ordering},
        Condvar, Mutex,
    },
    time::{Duration, Instant},
};

const WAIT_POLL: Duration = Duration::from_millis(5);

#[derive(Clone, Copy)]
struct InvalidFact {
    key: Hash,
    error: WorkError,
    expires: Instant,
}

enum State {
    Empty,
    Computing(Hash),
    Invalid(InvalidFact),
}
struct Slot {
    state: Mutex<State>,
    changed: Condvar,
}

/// Local observations only. A replay count is not Chainwork or consensus
/// evidence; waits are non-CPU scheduling observations.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RejectionCacheCounters {
    pub started_replays: u64,
    pub exact_hits: u64,
    pub wait_polls: u64,
    pub collision_bypasses: u64,
}

/// A finite direct-mapped negative mathematical fact cache.
/// An exact in-flight proof has one replay owner; distinct proofs are never
/// serialized by a hash-index collision. Each caller retains its own deadline,
/// cancellation and already-acquired ingress CPU reservation.
pub struct RejectionCache {
    slots: Box<[Slot]>,
    lifetime: Duration,
    started_replays: AtomicU64,
    exact_hits: AtomicU64,
    wait_polls: AtomicU64,
    collision_bypasses: AtomicU64,
}
fn count(value: &AtomicU64) {
    let _ = value.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
        Some(n.saturating_add(1))
    });
}
impl RejectionCache {
    /// A finite optional cache is never a second block registry or peer budget.
    pub fn new(slots: usize, lifetime: Duration) -> Option<Self> {
        if !(1..=256).contains(&slots)
            || lifetime.is_zero()
            || lifetime > Duration::from_secs(30)
        {
            return None;
        }
        Some(Self {
            slots: (0..slots)
                .map(|_| Slot {
                    state: Mutex::new(State::Empty),
                    changed: Condvar::new(),
                })
                .collect(),
            lifetime,
            started_replays: AtomicU64::new(0),
            exact_hits: AtomicU64::new(0),
            wait_polls: AtomicU64::new(0),
            collision_bypasses: AtomicU64::new(0),
        })
    }

    pub fn counters(&self) -> RejectionCacheCounters {
        RejectionCacheCounters {
            started_replays: self.started_replays.load(Ordering::Relaxed),
            exact_hits: self.exact_hits.load(Ordering::Relaxed),
            wait_polls: self.wait_polls.load(Ordering::Relaxed),
            collision_bypasses: self.collision_bypasses.load(Ordering::Relaxed),
        }
    }

    fn key(challenge: Hash, task: Hash, target: Hash, bytes: &[u8]) -> Hash {
        hash(
            b"w1-exact-invalid-math-v1",
            &[PROFILE.as_bytes(), &challenge, &task, &target, bytes],
        )
    }

    pub fn verify_with_progress<E>(
        &self,
        challenge: Hash,
        expected_task: Hash,
        target: Hash,
        proof: &[u8],
        progress: &mut impl FnMut(VerificationProgress) -> Result<(), E>,
    ) -> Result<VerifiedWork, VerificationError<E>> {
        let key = Self::key(challenge, expected_task, target, proof);
        let index = u64::from_le_bytes(key[..8].try_into().expect("32-byte SHA-256 key"))
            as usize
            % self.slots.len();
        let slot = &self.slots[index];

        loop {
            let mut state = match slot.state.lock() {
                Ok(locked) => locked,
                Err(_) => {
                    // A poisoned OPTIONAL cache is not mathematical-invalid
                    // Work and must never mint success or prevent full replay.
                    return verify_with_progress(
                        challenge,
                        expected_task,
                        target,
                        proof,
                        progress,
                    );
                }
            };
            match &*state {
                State::Invalid(fact)
                    if fact.key == key && Instant::now() < fact.expires =>
                {
                    let error = fact.error;
                    drop(state);
                    progress(VerificationProgress::BeforeReplay)
                        .map_err(VerificationError::Cancelled)?;
                    count(&self.exact_hits);
                    // Only the unchanged full verifier may ever mint
                    // VerifiedWork; this fast path returns a late negative fact.
                    return Err(VerificationError::Relation(error));
                }
                State::Computing(current) if *current == key => {
                    // No caller callback or arithmetic under the cache lock.
                    drop(state);
                    progress(VerificationProgress::BeforeReplay)
                        .map_err(VerificationError::Cancelled)?;
                    // Recheck after reacquiring: the leader may have completed.
                    let locked = match slot.state.lock() {
                        Ok(locked) => locked,
                        Err(_) => {
                            return verify_with_progress(
                                challenge,
                                expected_task,
                                target,
                                proof,
                                progress,
                            )
                        }
                    };
                    if matches!(&*locked, State::Computing(active) if *active == key) {
                        count(&self.wait_polls);
                        // Poll only the caller's existing cancellation/deadline
                        // callback; this creates no new TTL, worker or CPU credit.
                        match slot.changed.wait_timeout(locked, WAIT_POLL) {
                            Ok((guard, _)) => drop(guard),
                            Err(_) => {
                                return verify_with_progress(
                                    challenge,
                                    expected_task,
                                    target,
                                    proof,
                                    progress,
                                )
                            }
                        }
                    }
                }
                State::Computing(_) => {
                    // Different statements have distinct relation validity.
                    // A malicious slot-index collision cannot stall an honest
                    // independent proof behind an attacker-controlled leader.
                    drop(state);
                    count(&self.collision_bypasses);
                    return verify_with_progress(
                        challenge,
                        expected_task,
                        target,
                        proof,
                        progress,
                    );
                }
                State::Empty | State::Invalid(_) => {
                    *state = State::Computing(key);
                    drop(state);
                    let mut owner = Computing { slot, key };
                    count(&self.started_replays);
                    let result = verify_with_progress(
                        challenge,
                        expected_task,
                        target,
                        proof,
                        progress,
                    );
                    if let Err(VerificationError::Relation(error)) = &result {
                        if matches!(error, WorkError::Transcript | WorkError::Product) {
                            owner.publish(*error, self.lifetime);
                        }
                    }
                    // Valid work, cheap relation errors, cancellation, a
                    // poisoned lock or a panic must not publish a negative
                    // mathematical verdict. Drop wakes every existing waiter.
                    drop(owner);
                    return result;
                }
            }
        }
    }
}

struct Computing<'a> {
    slot: &'a Slot,
    key: Hash,
}
impl Computing<'_> {
    fn publish(&mut self, error: WorkError, lifetime: Duration) {
        if let Ok(mut state) = self.slot.state.lock() {
            if matches!(&*state, State::Computing(active) if *active == self.key) {
                *state = State::Invalid(InvalidFact {
                    key: self.key,
                    error,
                    expires: Instant::now() + lifetime,
                });
            }
        }
        self.slot.changed.notify_all();
    }
}
impl Drop for Computing<'_> {
    fn drop(&mut self) {
        if let Ok(mut state) = self.slot.state.lock() {
            if matches!(&*state, State::Computing(active) if *active == self.key) {
                *state = State::Empty;
            }
        }
        self.slot.changed.notify_all();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pon_work::{prove, task_id, CELLS, PROOF_BYTES};

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
        let mut replays = 0;
        for expected in [512, 0] {
            replays = 0;
            let r = cache.verify_with_progress(
                challenge, task, target, &bad, &mut |point| {
                    if matches!(point, VerificationProgress::TranscriptTile { .. }) {
                        replays += 1;
                    }
                    Ok::<(), ()>(())
                },
            );
            assert!(matches!(
                r,
                Err(VerificationError::Relation(WorkError::Transcript))
            ));
            assert_eq!(replays, expected);
        }
        assert!(cache
            .verify_with_progress(
                challenge, task, target, &valid, &mut |_| Ok::<(), ()>(())
            )
            .is_ok());
        let mut changed_context = challenge;
        changed_context[0] ^= 1;
        // A different challenge never inherits the old negative fact.
        let mut other_replay = 0;
        let _ = cache.verify_with_progress(
            changed_context, task, target, &bad, &mut |point| {
                if matches!(point, VerificationProgress::TranscriptTile { .. }) {
                    other_replay += 1;
                }
                Ok::<(), ()>(())
            },
        );
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
            let fake = hash(b"w1-negative-cache-from-zero-v1", &[
                &challenge,
                &nonce.to_le_bytes(),
            ]);
            assert!(digests.insert(fake));
            let mut wire = vec![0u8; PROOF_BYTES];
            wire[..4].copy_from_slice(b"PNW1");
            wire[PROOF_BYTES - 32..].copy_from_slice(&fake);
            let mut tiles = 0;
            let result = cache.verify_with_progress(
                challenge, task, target, &wire, &mut |point| {
                    if matches!(point, VerificationProgress::TranscriptTile { .. }) {
                        tiles += 1;
                    }
                    Ok::<(), ()>(())
                },
            );
            assert!(matches!(result,
                Err(VerificationError::Relation(WorkError::Transcript))));
            assert_eq!(tiles, 512, "new fake claim must not inherit prior negative fact");
            if first.is_none() {
                first = Some(wire);
            }
        }
        let mut replayed = 0;
        let hit = cache.verify_with_progress(
            challenge, task, target, &first.unwrap(), &mut |point| {
                if matches!(point, VerificationProgress::TranscriptTile { .. }) {
                    replayed += 1;
                }
                Ok::<(), ()>(())
            },
        );
        assert!(matches!(hit,
            Err(VerificationError::Relation(WorkError::Transcript))));
        assert_eq!(replayed, 0, "only an exact cached false proof is short-circuited");
    }

    #[test]
    fn local_cancellation_cannot_use_a_cached_fact_as_a_verdict() {
        let cache = RejectionCache::new(1, Duration::from_secs(1)).unwrap();
        let zeros = vec![0; CELLS];
        let challenge = [9; 32];
        let task = task_id(&zeros, &zeros).unwrap();
        let mut false_proof = prove(challenge, &zeros, &zeros).unwrap();
        false_proof[PROOF_BYTES - 1] ^= 1;
        let _ = cache.verify_with_progress(
            challenge, task, [255; 32], &false_proof, &mut |_| Ok::<(), &str>(())
        );
        assert!(matches!(
            cache.verify_with_progress(
                challenge, task, [255; 32], &false_proof, &mut |_| Err::<(), _>("CANCEL")
            ),
            Err(VerificationError::Cancelled("CANCEL"))
        ));
        assert!(RejectionCache::new(0, Duration::from_secs(1)).is_none());
        assert!(RejectionCache::new(1, Duration::ZERO).is_none());
    }
}
