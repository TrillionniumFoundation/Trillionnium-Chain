//! Optional exact W1 mathematical rejection cache. No acceptance/authority cache.
//! A fresh forged trace still incurs full W1 replay; this protects ONLY exact
//! repeated bogus mathematical statements in the same local receiver epoch.
use super::{
    hash, verify_with_progress, Hash, VerificationError, VerificationProgress, VerifiedWork,
    WorkError, PROFILE,
};
use std::{
    sync::Mutex,
    time::{Duration, Instant},
};

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

    fn key(challenge: Hash, task: Hash, target: Hash, bytes: &[u8]) -> Hash {
        hash(
            b"w1-exact-invalid-math-v1",
            &[PROFILE.as_bytes(), &challenge, &task, &target, bytes],
        )
    }

    fn hit(&self, key: Hash) -> Option<WorkError> {
        let entries = self.slots.lock().ok()?;
        let i = u64::from_le_bytes(key[..8].try_into().ok()?) as usize % entries.len();
        entries[i]
            .filter(|entry| entry.key == key && Instant::now() < entry.expires)
            .map(|entry| entry.error)
    }

    fn insert(&self, key: Hash, error: WorkError) {
        if !matches!(error, WorkError::Transcript | WorkError::Product) {
            return;
        }
        // Poisoning disables cache reuse, never mathematical verification.
        if let Ok(mut entries) = self.slots.lock() {
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
        let key = Self::key(challenge, expected_task, target, proof);
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
