//! Short scheduling delay for an exact body with a completed W1 math refusal.
//! This never returns a validity verdict. After the delay the original paid
//! body, current owner and full/cached W1 verifier still decide the request.
use super::{digest, Hash};
use std::sync::Mutex;
use std::time::{Duration, Instant};

const SLOTS: usize = 256;
const WAYS: usize = 4;
const DELAY: Duration = Duration::from_millis(500);

#[derive(Clone, Copy)]
struct Refusal {
    digest: Hash,
    until: Instant,
}

pub(super) struct BodyRefusals {
    // Fixed storage, shared by this service's reactor and existing workers.
    // No caller registry, durable rows, successful facts or extra worker.
    rows: Mutex<[Option<Refusal>; SLOTS]>,
}

impl Default for BodyRefusals {
    fn default() -> Self {
        Self {
            rows: Mutex::new([None; SLOTS]),
        }
    }
}

impl BodyRefusals {
    fn set(key: &Hash) -> std::ops::Range<usize> {
        let start = (usize::from(key[0]) % (SLOTS / WAYS)) * WAYS;
        start..start + WAYS
    }

    /// Called only after body authentication and a typed native negative fact.
    /// A failed optional lock never delays the completed work or changes it.
    pub(super) fn remember(&self, body_digest: &str, now: Instant) {
        let Ok(key) = digest(body_digest) else { return };
        let Some(until) = now.checked_add(DELAY) else {
            return;
        };
        let Ok(mut rows) = self.rows.try_lock() else {
            return;
        };
        let set = &mut rows[Self::set(&key)];
        let replacement = set
            .iter()
            .position(|entry| entry.is_some_and(|entry| entry.digest == key))
            .or_else(|| {
                set.iter()
                    .position(|entry| entry.is_none_or(|entry| entry.until <= now))
            })
            .unwrap_or_else(|| {
                set.iter()
                    .enumerate()
                    .min_by_key(|(_, entry)| entry.as_ref().expect("full set").until)
                    .expect("nonempty set")
                    .0
            });
        set[replacement] = Some(Refusal { digest: key, until });
    }

    /// Read once after the original signature and spent-token checks. Lookup
    /// cannot refresh a deadline, retain a grant or become rejection authority.
    pub(super) fn retry_at(&self, body_digest: &str, now: Instant) -> Option<Instant> {
        let key = digest(body_digest).ok()?;
        let rows = self.rows.try_lock().ok()?;
        rows[Self::set(&key)]
            .iter()
            .flatten()
            .find(|entry| entry.digest == key && now < entry.until)
            .map(|entry| entry.until)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_digest_delay_expires_without_lookup_refresh() {
        let cache = BodyRefusals::default();
        let now = Instant::now();
        let a = hex::encode([7; 32]);
        let b = hex::encode([8; 32]);
        assert_eq!(cache.retry_at(&a, now), None);
        cache.remember(&a, now);
        assert_eq!(cache.retry_at(&a, now), Some(now + DELAY));
        assert_eq!(cache.retry_at(&b, now), None);
        assert_eq!(
            cache.retry_at(&a, now + DELAY - Duration::from_nanos(1)),
            Some(now + DELAY)
        );
        assert_eq!(cache.retry_at(&a, now + DELAY), None);
        cache.remember("bad digest", now);
        assert_eq!(cache.retry_at("bad digest", now), None);
    }

    #[test]
    fn collisions_never_delay_a_different_body_and_storage_stays_bounded() {
        let cache = BodyRefusals::default();
        let now = Instant::now();
        for number in 0..1000u64 {
            let mut key = [0; 32];
            key[1..9].copy_from_slice(&number.to_le_bytes());
            let text = hex::encode(key);
            assert_eq!(cache.retry_at(&text, now), None);
            cache.remember(&text, now + Duration::from_nanos(number));
        }
        assert_eq!(cache.rows.lock().unwrap().iter().flatten().count(), WAYS);
        assert!(std::mem::size_of::<BodyRefusals>() <= 32 * 1024);
    }

    #[test]
    fn contention_and_poison_do_not_block_or_invent_delay() {
        let cache = BodyRefusals::default();
        let now = Instant::now();
        let key = hex::encode([6; 32]);
        let lock = cache.rows.lock().unwrap();
        cache.remember(&key, now);
        assert_eq!(cache.retry_at(&key, now), None);
        drop(lock);
        assert_eq!(cache.retry_at(&key, now), None);
        let _ = std::panic::catch_unwind(|| {
            let _lock = cache.rows.lock().unwrap();
            panic!("intentional poison");
        });
        cache.remember(&key, now);
        assert_eq!(cache.retry_at(&key, now), None);
    }
}
