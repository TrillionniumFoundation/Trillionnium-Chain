//! Optional bounded W1 mathematical rejection cache. No acceptance/authority cache.
//! A transcript fact binds challenge/A/B/claimed trace and is independent of
//! canonical claimed C. A product fact additionally binds that exact C. Fresh
//! forged traces still incur full W1 replay in the same local receiver epoch.
//! Contended or poisoned cache locks never delay the caller: lookup misses and
//! publication is skipped while the original verifier retains its checkpoints.
use super::{
    checked_proof_statement, hash, verify_checked_with_kernel, CheckedProofInputs, Hash,
    VerificationError, VerificationKernel, VerificationProgress, VerifiedWork, WorkError, CELLS,
    PROFILE, PROOF_BYTES,
};
use std::{
    sync::Mutex,
    time::{Duration, Instant},
};

#[cfg(test)]
std::thread_local! {
    // Actual proof bytes passed to this optional cache's two claim digests.
    // This excludes task hashing/arithmetic and is absent from production.
    static CACHE_KEY_PROOF_BYTES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[derive(Clone, Copy)]
struct ClaimKeys {
    transcript: Hash,
    product: Hash,
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

    fn key(challenge: Hash, task: Hash, target: Hash, bytes: &[u8]) -> Option<ClaimKeys> {
        // The original verifier refuses a wrong width before reading proof
        // bytes. An optional cache must not turn that constant-cost refusal
        // into an unbounded hash over an attacker-controlled buffer.
        if bytes.len() != PROOF_BYTES {
            return None;
        }
        #[cfg(test)]
        CACHE_KEY_PROOF_BYTES.with(|count| count.set(count.get() + bytes.len()));
        let input_end = 4 + 2 * CELLS * 4;
        let trace_start = PROOF_BYTES - 32;
        // A completed transcript mismatch depends on canonical A/B and the
        // exact claimed trace, not on any canonical claimed product. Bind the
        // original context/target too; no current authorization is cached.
        let transcript = hash(
            b"w1-negative-transcript-claim-v2",
            &[
                PROFILE.as_bytes(),
                &challenge,
                &task,
                &target,
                &bytes[..input_end],
                &bytes[trace_start..],
            ],
        );
        // The second domain reuses the bound input digest and additionally
        // binds exact C. Across both digests each proof byte is hashed once.
        let product = hash(
            b"w1-negative-product-claim-v2",
            &[&transcript, &bytes[input_end..trace_start]],
        );
        Some(ClaimKeys {
            transcript,
            product,
        })
    }

    fn hit(&self, keys: ClaimKeys) -> Option<WorkError> {
        // Optional reuse must not wait outside the caller's cancellation and
        // deadline checkpoints. Contention, like poison, is a cache miss.
        let entries = self.slots.try_lock().ok()?;
        let now = Instant::now();
        // One nonblocking lookup, at most two direct slots and no allocation.
        for (key, error) in [
            (keys.transcript, WorkError::Transcript),
            (keys.product, WorkError::Product),
        ] {
            let i = u64::from_le_bytes(key[..8].try_into().ok()?) as usize % entries.len();
            if entries[i].is_some_and(|entry| {
                entry.key == key && entry.error == error && now < entry.expires
            }) {
                return Some(error);
            }
        }
        None
    }

    fn insert(&self, keys: ClaimKeys, error: WorkError) {
        let key = match error {
            WorkError::Transcript => keys.transcript,
            WorkError::Product => keys.product,
            _ => return,
        };
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
        // Repeat the complete original cheap-check order against this call's
        // immutable bytes before any cache access: Length, Version, zero target,
        // C/A/B fields, task, then ticket. A hit never masks a current failure.
        let checked = checked_proof_statement(challenge, expected_task, target, proof)?;
        let key = Self::key(challenge, expected_task, target, proof).ok_or(WorkError::Length)?;
        if let Some(error) = self.hit(key) {
            // A cached error is only a performance hint. Callers must still be
            // able to cancel, and must have checked present branch authority.
            progress(VerificationProgress::BeforeReplay).map_err(VerificationError::Cancelled)?;
            return Err(VerificationError::Relation(error));
        }
        // Only a miss allocates/decodes A/B. Continue the same current checked
        // statement without rerunning its cheap checks or decoding inputs twice.
        let result = verify_checked_with_kernel(
            challenge,
            proof,
            CheckedProofInputs {
                matrices: checked.decode_inputs(),
                actual_task: checked.actual_task,
                ticket: checked.ticket,
            },
            progress,
            VerificationKernel::FullLimb,
        );
        if let Err(VerificationError::Relation(error)) = &result {
            self.insert(key, *error);
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pon_work::{prove, task_id, verify_with_progress, CELLS, PROOF_BYTES};
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
        // Reuse is limited to the same negative mathematical fact, not an
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
            "the retained exact false transcript fact is short-circuited"
        );
    }

    #[test]
    fn canonical_product_variants_reuse_the_same_negative_transcript_fact() {
        let cache = RejectionCache::new(64, Duration::from_secs(30)).unwrap();
        let zeros = vec![0; CELLS];
        let task = task_id(&zeros, &zeros).unwrap();
        let challenge = [83; 32];
        // No producer or legal transcript is used to create this fake claim.
        // The same challenge/task/trace already meets this explicit target;
        // changing only canonical C bytes requires no fresh ticket search.
        let fake = hash(b"w1-negative-cache-c-variant-v1", &[&challenge]);
        let mut wire = vec![0u8; PROOF_BYTES];
        wire[..4].copy_from_slice(b"PNW1");
        wire[PROOF_BYTES - 32..].copy_from_slice(&fake);
        let mut replay_counts = Vec::new();
        for word in [None, Some(0), Some(CELLS / 2), Some(CELLS - 1)] {
            let mut variant = wire.clone();
            if let Some(word) = word {
                let start = 4 + (2 * CELLS + word) * 4;
                variant[start..start + 4].copy_from_slice(&1_u32.to_le_bytes());
            }
            let (result, points) = observed(Some(&cache), challenge, task, &variant, None);
            assert_eq!(
                result,
                Err(VerificationError::Relation(WorkError::Transcript))
            );
            replay_counts.push(
                points
                    .iter()
                    .filter(|point| matches!(point, VerificationProgress::TranscriptTile { .. }))
                    .count(),
            );
        }
        assert_eq!(
            replay_counts,
            vec![512, 0, 0, 0],
            "C is not an input to the challenge/A/B transcript and must not defeat its negative fact"
        );
    }

    #[test]
    fn transcript_fact_keeps_current_cheap_checks_and_decodes_only_on_a_miss() {
        let cache = RejectionCache::new(8, Duration::from_secs(30)).unwrap();
        let zeros = vec![0; CELLS];
        let task = task_id(&zeros, &zeros).unwrap();
        let challenge = [84; 32];
        let valid = prove(challenge, &zeros, &zeros).unwrap();
        let mut bad_trace = valid.clone();
        bad_trace[PROOF_BYTES - 1] ^= 1;
        super::super::ARITHMETIC_INPUT_DECODES.with(|count| count.set(0));
        assert_eq!(
            observed(Some(&cache), challenge, task, &bad_trace, None).0,
            Err(VerificationError::Relation(WorkError::Transcript))
        );
        assert_eq!(
            super::super::ARITHMETIC_INPUT_DECODES.with(std::cell::Cell::get),
            1,
            "the cold miss must decode the current A/B once"
        );
        let product_start = 4 + 2 * CELLS * 4;
        let mut variant = bad_trace;
        variant[product_start] = 1;
        super::super::ARITHMETIC_INPUT_DECODES.with(|count| count.set(0));
        let warm = observed(Some(&cache), challenge, task, &variant, None);
        assert_eq!(
            warm.0,
            Err(VerificationError::Relation(WorkError::Transcript))
        );
        assert_eq!(warm.1, vec![VerificationProgress::BeforeReplay]);
        assert_eq!(
            super::super::ARITHMETIC_INPUT_DECODES.with(std::cell::Cell::get),
            0,
            "a negative fact hit has no decoded-matrix allocation"
        );
        let mut noncanonical = variant.clone();
        noncanonical[product_start..product_start + 4]
            .copy_from_slice(&(super::super::Q as u32).to_le_bytes());
        let mut wrong_task = task;
        wrong_task[0] ^= 1;
        let mut below_ticket = [0; 32];
        below_ticket[31] = 1;
        assert!(hash(b"ticket", &[&challenge, &variant[PROOF_BYTES - 32..]]) > below_ticket);
        for (proof, current_task, target, error) in [
            (noncanonical.clone(), task, [255; 32], WorkError::Field),
            (variant.clone(), wrong_task, [255; 32], WorkError::Task),
            (variant.clone(), task, below_ticket, WorkError::Target),
            // Zero target still wins over malformed C and a wrong task.
            (noncanonical, wrong_task, [0; 32], WorkError::Target),
        ] {
            let native = verify_with_progress(challenge, current_task, target, &proof, &mut |_| {
                Err::<(), _>("cheap failure must precede cancellation")
            });
            assert_eq!(native.unwrap_err(), VerificationError::Relation(error));
            CACHE_KEY_PROOF_BYTES.with(|count| count.set(0));
            super::super::ARITHMETIC_INPUT_DECODES.with(|count| count.set(0));
            let actual =
                cache.verify_with_progress(challenge, current_task, target, &proof, &mut |_| {
                    Err::<(), _>("cheap failure must precede cancellation")
                });
            assert_eq!(actual.unwrap_err(), VerificationError::Relation(error));
            assert_eq!(CACHE_KEY_PROOF_BYTES.with(std::cell::Cell::get), 0);
            assert_eq!(
                super::super::ARITHMETIC_INPUT_DECODES.with(std::cell::Cell::get),
                0
            );
        }
        let cancelled = observed(
            Some(&cache),
            challenge,
            task,
            &variant,
            Some(VerificationProgress::BeforeReplay),
        );
        assert_eq!(
            cancelled.0,
            Err(VerificationError::Cancelled("CALLER_CANCELLED"))
        );
        assert_eq!(cancelled.1, vec![VerificationProgress::BeforeReplay]);
        // The same A/B/challenge with its actual trace and C must still pass
        // the full native path; the negative fact supplies no authority.
        assert_eq!(
            observed(Some(&cache), challenge, task, &valid, None),
            observed(None, challenge, task, &valid, None)
        );
    }

    #[test]
    fn transcript_fact_binds_challenge_both_inputs_and_claimed_trace() {
        let zeros = vec![0; CELLS];
        let task = task_id(&zeros, &zeros).unwrap();
        let challenge = [85; 32];
        let mut bad_trace = prove(challenge, &zeros, &zeros).unwrap();
        bad_trace[PROOF_BYTES - 1] ^= 1;
        let mut other_challenge = challenge;
        other_challenge[0] ^= 1;
        let mut changed_input = zeros.clone();
        changed_input[CELLS - 1] = 1;
        let mut other_a = bad_trace.clone();
        other_a[4 + (CELLS - 1) * 4] = 1;
        let mut other_b = bad_trace.clone();
        other_b[4 + (2 * CELLS - 1) * 4] = 1;
        let mut other_trace = bad_trace.clone();
        other_trace[PROOF_BYTES - 2] ^= 1;
        for (current_challenge, current_task, proof) in [
            (other_challenge, task, bad_trace.clone()),
            (challenge, task_id(&changed_input, &zeros).unwrap(), other_a),
            (challenge, task_id(&zeros, &changed_input).unwrap(), other_b),
            (challenge, task, other_trace),
        ] {
            let cache = RejectionCache::new(8, Duration::from_secs(30)).unwrap();
            assert_eq!(
                observed(Some(&cache), challenge, task, &bad_trace, None).0,
                Err(VerificationError::Relation(WorkError::Transcript))
            );
            let native = observed(None, current_challenge, current_task, &proof, None);
            assert_eq!(
                native.0,
                Err(VerificationError::Relation(WorkError::Transcript))
            );
            assert!(native.1.iter().any(|point| matches!(
                point,
                VerificationProgress::TranscriptTile {
                    row: 7,
                    column: 7,
                    inner: 7
                }
            )));
            assert_eq!(
                observed(Some(&cache), current_challenge, current_task, &proof, None),
                native,
                "a changed transcript input or claim still owes complete native replay"
            );
        }
    }

    #[test]
    fn product_fact_binds_exact_c_and_does_not_reject_a_repaired_product() {
        let cache = RejectionCache::new(8, Duration::from_secs(30)).unwrap();
        let zeros = vec![0; CELLS];
        let task = task_id(&zeros, &zeros).unwrap();
        let challenge = [86; 32];
        let valid = prove(challenge, &zeros, &zeros).unwrap();
        let product_start = 4 + 2 * CELLS * 4;
        let mut bad_product = valid.clone();
        bad_product[product_start] = 1;
        assert_eq!(
            observed(Some(&cache), challenge, task, &bad_product, None),
            observed(None, challenge, task, &bad_product, None)
        );
        let warm = observed(Some(&cache), challenge, task, &bad_product, None);
        assert_eq!(warm.0, Err(VerificationError::Relation(WorkError::Product)));
        assert_eq!(warm.1, vec![VerificationProgress::BeforeReplay]);
        bad_product[product_start] = 2;
        assert_eq!(
            observed(Some(&cache), challenge, task, &bad_product, None),
            observed(None, challenge, task, &bad_product, None),
            "a different C must not inherit an exact Product failure"
        );
        let repaired = observed(Some(&cache), challenge, task, &valid, None);
        assert!(repaired.0.is_ok());
        assert_eq!(repaired, observed(None, challenge, task, &valid, None));
    }

    #[test]
    fn transcript_variant_hit_does_not_renew_ttl_and_partial_replay_is_not_cached() {
        let cache = RejectionCache::new(1, Duration::from_secs(30)).unwrap();
        let zeros = vec![0; CELLS];
        let task = task_id(&zeros, &zeros).unwrap();
        let challenge = [87; 32];
        let mut bad_trace = prove(challenge, &zeros, &zeros).unwrap();
        bad_trace[PROOF_BYTES - 1] ^= 1;
        let last_tile = VerificationProgress::TranscriptTile {
            row: 7,
            column: 7,
            inner: 7,
        };
        assert_eq!(
            observed(Some(&cache), challenge, task, &bad_trace, Some(last_tile)).0,
            Err(VerificationError::Cancelled("CALLER_CANCELLED"))
        );
        assert!(cache.slots.lock().unwrap().iter().all(Option::is_none));
        assert_eq!(
            observed(Some(&cache), challenge, task, &bad_trace, None),
            observed(None, challenge, task, &bad_trace, None)
        );
        let expires = cache.slots.lock().unwrap()[0].unwrap().expires;
        bad_trace[4 + 2 * CELLS * 4] = 1;
        assert_eq!(
            observed(Some(&cache), challenge, task, &bad_trace, None).1,
            vec![VerificationProgress::BeforeReplay]
        );
        assert_eq!(cache.slots.lock().unwrap()[0].unwrap().expires, expires);
        // Deterministic expiry control: no timing sleep or altered lifetime.
        cache.slots.lock().unwrap()[0].as_mut().unwrap().expires = Instant::now();
        assert_eq!(
            observed(Some(&cache), challenge, task, &bad_trace, None),
            observed(None, challenge, task, &bad_trace, None),
            "expired negative facts owe a fresh complete replay"
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
