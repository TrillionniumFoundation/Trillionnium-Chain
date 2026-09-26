//! Bounded host-only memoization of the original strict mathematical predicate.
//! A cache hit is never a trust/context/admission/currentness capability.
use alloc::vec::Vec;
use sha2::{Digest, Sha256};
use std::sync::Mutex;
use trnm_consensus_types::{SignatureBytes, SigningRoot, Validator};

const SLOTS: usize = 4096;
type ExactKey = [u8; 128];
static CACHE: Mutex<Option<PositiveCache>> = Mutex::new(None);

struct PositiveCache {
    slots: Vec<Option<ExactKey>>,
}
impl PositiveCache {
    fn try_new() -> Option<Self> {
        let mut slots = Vec::new();
        slots.try_reserve_exact(SLOTS).ok()?;
        slots.resize_with(SLOTS, || None);
        Some(Self { slots })
    }
    fn contains(&self, index: usize, key: &ExactKey) -> bool {
        self.slots[index].as_ref() == Some(key)
    }
    fn insert(&mut self, index: usize, key: ExactKey) {
        self.slots[index] = Some(key);
    }
}

fn exact_key(validator: &Validator, root: &SigningRoot, signature: &SignatureBytes) -> ExactKey {
    let mut key = [0; 128];
    key[..32].copy_from_slice(validator.consensus_key().as_bytes());
    key[32..64].copy_from_slice(root.as_bytes());
    key[64..].copy_from_slice(signature.as_bytes());
    key
}
fn index(key: &ExactKey) -> usize {
    let hash = Sha256::digest(key);
    usize::from(u16::from_le_bytes([hash[0], hash[1]])) % SLOTS
}

pub(super) fn verify(
    validator: &Validator,
    root: &SigningRoot,
    signature: &SignatureBytes,
) -> bool {
    verify_using(&CACHE, validator, root, signature)
}
fn verify_using(
    cache: &Mutex<Option<PositiveCache>>,
    validator: &Validator,
    root: &SigningRoot,
    signature: &SignatureBytes,
) -> bool {
    let key = exact_key(validator, root, signature);
    let slot = index(&key);
    // Never wait for cache ownership, and never keep a lock during verification.
    if let Ok(guard) = cache.try_lock() {
        if guard
            .as_ref()
            .is_some_and(|value| value.contains(slot, &key))
        {
            return true;
        }
    }
    let valid = super::verify_uncached(validator, root, signature);
    if valid {
        if let Ok(mut guard) = cache.try_lock() {
            if guard.is_none() {
                *guard = PositiveCache::try_new();
            }
            if let Some(value) = guard.as_mut() {
                value.insert(slot, key);
            }
        }
    }
    valid
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use trnm_consensus_types::{ConsensusPublicKey, ValidatorId, VotingPower};

    fn validator(key: [u8; 32]) -> Validator {
        Validator::new(
            ValidatorId::new([19; 32]),
            ConsensusPublicKey::new(key),
            VotingPower::new(1).unwrap(),
        )
        .unwrap()
    }
    fn fixture() -> (Validator, SigningRoot, SignatureBytes) {
        let signing = SigningKey::from_bytes(&[42; 32]);
        let root = SigningRoot::new([43; 32]);
        let signature = SignatureBytes::from_array(signing.sign(root.as_bytes()).to_bytes());
        (
            validator(signing.verifying_key().to_bytes()),
            root,
            signature,
        )
    }
    #[test]
    fn all_128_key_bytes_participate_even_in_the_same_slot() {
        let mut cache = PositiveCache::try_new().unwrap();
        let key = [17; 128];
        let slot = index(&key);
        cache.insert(slot, key);
        assert!(cache.contains(slot, &key));
        for byte in 0..128 {
            let mut altered = key;
            altered[byte] ^= 1;
            assert!(!cache.contains(slot, &altered), "byte {byte}");
        }
    }
    #[test]
    fn index_collision_is_eviction_not_signature_acceptance() {
        let mut cache = PositiveCache::try_new().unwrap();
        let key = [0; 128];
        let slot = index(&key);
        let collision = (1u64..100_000)
            .find_map(|value| {
                let mut next = key;
                next[..8].copy_from_slice(&value.to_le_bytes());
                (index(&next) == slot).then_some(next)
            })
            .expect("deterministic index collision fixture");
        cache.insert(slot, key);
        assert!(!cache.contains(slot, &collision));
        cache.insert(slot, collision);
        assert!(cache.contains(slot, &collision));
        assert!(!cache.contains(slot, &key));
        assert_eq!(cache.slots.len(), SLOTS);
    }
    #[test]
    fn unsuccessful_predicates_do_not_allocate_or_populate() {
        let (validator, root, signature) = fixture();
        let cache = Mutex::new(None);
        let mut wrong = *signature.as_bytes();
        wrong[0] ^= 1;
        assert!(!verify_using(
            &cache,
            &validator,
            &root,
            &SignatureBytes::from_array(wrong)
        ));
        assert!(!verify_using(
            &cache,
            &validator,
            &SigningRoot::new([44; 32]),
            &signature
        ));
        assert!(cache.lock().unwrap().is_none());
    }
    #[test]
    fn warmed_cache_preserves_strict_rejection_for_every_input_byte_mutation() {
        let (original, root, signature) = fixture();
        let cache = Mutex::new(None);
        assert!(verify_using(&cache, &original, &root, &signature));
        for byte in 0..128 {
            let mut key = *original.consensus_key().as_bytes();
            let mut changed_root = *root.as_bytes();
            let mut sig = *signature.as_bytes();
            match byte {
                0..32 => key[byte] ^= 1,
                32..64 => changed_root[byte - 32] ^= 1,
                _ => sig[byte - 64] ^= 1,
            }
            let changed_validator = validator(key);
            let changed_root = SigningRoot::new(changed_root);
            let changed_signature = SignatureBytes::from_array(sig);
            let original_result = super::super::verify_uncached(
                &changed_validator,
                &changed_root,
                &changed_signature,
            );
            assert!(!original_result, "mutation {byte}");
            assert_eq!(
                verify_using(
                    &cache,
                    &changed_validator,
                    &changed_root,
                    &changed_signature
                ),
                original_result
            );
        }
    }
    #[test]
    fn contended_cache_uses_the_uncached_predicate_without_waiting() {
        let (validator, root, signature) = fixture();
        let cache = Mutex::new(PositiveCache::try_new());
        let _held = cache.lock().unwrap();
        assert!(verify_using(&cache, &validator, &root, &signature));
        assert!(!verify_using(
            &cache,
            &validator,
            &SigningRoot::new([44; 32]),
            &signature
        ));
    }
    #[test]
    fn poisoned_cache_uses_the_uncached_predicate() {
        let (validator, root, signature) = fixture();
        let cache = Mutex::new(PositiveCache::try_new());
        assert!(std::panic::catch_unwind(|| {
            let _held = cache.lock().unwrap();
            panic!("controlled cache poison");
        })
        .is_err());
        assert!(cache.is_poisoned());
        assert!(verify_using(&cache, &validator, &root, &signature));
        assert!(!verify_using(
            &cache,
            &validator,
            &SigningRoot::new([44; 32]),
            &signature
        ));
    }
    #[test]
    fn concurrent_readers_cannot_mix_positive_and_negative_predicates() {
        let (validator, root, signature) = fixture();
        let cache = Mutex::new(None);
        std::thread::scope(|scope| {
            for _ in 0..4 {
                scope.spawn(|| {
                    for _ in 0..128 {
                        assert!(verify_using(&cache, &validator, &root, &signature));
                        assert!(!verify_using(
                            &cache,
                            &validator,
                            &SigningRoot::new([44; 32]),
                            &signature
                        ));
                    }
                });
            }
        });
        let guard = cache.lock().unwrap();
        assert_eq!(guard.as_ref().unwrap().slots.len(), SLOTS);
    }
    #[test]
    fn cold_and_warm_repetition_match_the_original_predicate() {
        let (validator, root, signature) = fixture();
        let cache = Mutex::new(None);
        let cold = std::time::Instant::now();
        for _ in 0..256 {
            assert!(super::super::verify_uncached(&validator, &root, &signature));
        }
        let cold_ns = cold.elapsed().as_nanos();
        let warm = std::time::Instant::now();
        for _ in 0..256 {
            assert!(verify_using(&cache, &validator, &root, &signature));
        }
        std::println!(
            "same_signature_repetitions=256 uncached_ns={cold_ns} cached_ns={}",
            warm.elapsed().as_nanos()
        );
        assert_eq!(core::mem::size_of::<Option<ExactKey>>() * SLOTS, 528_384);
    }
}
