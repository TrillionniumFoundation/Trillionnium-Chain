//! A bounded scheduling hint for an exact body already refused by native W1.
//!
//! Publication occurs only after the paid request's authenticated body digest
//! and the original native mathematical refusal. A Hello can only look up its
//! own digest. Waiting grants no authority and issues no verdict; once eligible,
//! the original challenge, signature, body, context, Host and verifier checks
//! still execute. New bodies and read operations never wait on an older body.
use std::{
    sync::Mutex,
    time::{Duration, Instant},
};

pub(super) const COOLDOWN_SLOTS: usize = 256;
pub(super) const COOLDOWN: Duration = Duration::from_millis(1000);

#[derive(Clone, Copy)]
struct Hint {
    body: [u8; 32],
    eligible_at: Instant,
}

pub(super) struct RejectionBackpressure {
    // One fixed allocation per live server, with no guest identity rows.
    hints: Mutex<Box<[Option<Hint>; COOLDOWN_SLOTS]>>,
}

impl Default for RejectionBackpressure {
    fn default() -> Self {
        Self {
            hints: Mutex::new(Box::new([None; COOLDOWN_SLOTS])),
        }
    }
}

impl RejectionBackpressure {
    /// Only the native verification completion path calls this method. Failure
    /// to retain this optional hint never changes the already established error.
    pub(super) fn completed_rejection(&self, body: [u8; 32], now: Instant) -> bool {
        let Ok(mut hints) = self.hints.try_lock() else {
            return false;
        };
        let slot = hints
            .iter()
            .position(|hint| hint.is_some_and(|hint| hint.body == body))
            .or_else(|| {
                hints
                    .iter()
                    .position(|hint| hint.is_none_or(|hint| now >= hint.eligible_at))
            });
        let Some(slot) = slot else {
            // No live hint is displaced to give a new body a scheduling claim.
            return false;
        };
        hints[slot] = Some(Hint {
            body,
            eligible_at: now + COOLDOWN,
        });
        true
    }

    pub(super) fn eligible_at(&self, op: u8, body: [u8; 32], now: Instant) -> Option<Instant> {
        if op != 1 {
            return None;
        }
        let hints = self.hints.try_lock().ok()?;
        hints.iter().flatten().find_map(|hint| {
            (hint.body == body && now < hint.eligible_at).then_some(hint.eligible_at)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hello_lookup_cannot_publish_refresh_or_delay_new_body_or_reads() {
        let hints = RejectionBackpressure::default();
        let now = Instant::now();
        for _ in 0..1000 {
            assert_eq!(hints.eligible_at(1, [7; 32], now), None);
        }
        assert!(hints.completed_rejection([7; 32], now));
        for op in 2..=8 {
            assert_eq!(hints.eligible_at(op, [7; 32], now), None);
        }
        assert_eq!(hints.eligible_at(1, [8; 32], now), None);
        assert_eq!(hints.eligible_at(1, [7; 32], now), Some(now + COOLDOWN));
        let late = now + COOLDOWN - Duration::from_nanos(1);
        assert_eq!(hints.eligible_at(1, [7; 32], late), Some(now + COOLDOWN));
        assert_eq!(hints.eligible_at(1, [7; 32], now + COOLDOWN), None);
        assert_eq!(hints.eligible_at(1, [7; 32], now + COOLDOWN * 2), None);
    }

    #[test]
    fn fixed_slots_do_not_evict_live_hints_and_expired_slots_are_reused() {
        let hints = RejectionBackpressure::default();
        let now = Instant::now();
        for value in 0..COOLDOWN_SLOTS {
            let mut key = [0; 32];
            key[..8].copy_from_slice(&(value as u64).to_le_bytes());
            assert!(hints.completed_rejection(key, now));
        }
        assert!(!hints.completed_rejection([255; 32], now));
        assert_eq!(hints.eligible_at(1, [0; 32], now), Some(now + COOLDOWN));
        assert!(hints.completed_rejection([255; 32], now + COOLDOWN));
        assert_eq!(hints.eligible_at(1, [0; 32], now + COOLDOWN), None);
        assert_eq!(
            hints.eligible_at(1, [255; 32], now + COOLDOWN),
            Some(now + COOLDOWN * 2)
        );
        assert!(std::mem::size_of::<[Option<Hint>; COOLDOWN_SLOTS]>() <= 16 * 1024);
    }

    #[test]
    fn contention_and_poison_only_omit_optional_scheduling_hints() {
        let hints = RejectionBackpressure::default();
        let now = Instant::now();
        assert!(hints.completed_rejection([7; 32], now));
        let held = hints.hints.lock().unwrap();
        assert_eq!(hints.eligible_at(1, [7; 32], now), None);
        assert!(!hints.completed_rejection([8; 32], now));
        drop(held);
        let _ = std::panic::catch_unwind(|| {
            let _held = hints.hints.lock().unwrap();
            panic!("intentional poison");
        });
        assert_eq!(hints.eligible_at(1, [7; 32], now), None);
        assert!(!hints.completed_rejection([8; 32], now));
    }
}
