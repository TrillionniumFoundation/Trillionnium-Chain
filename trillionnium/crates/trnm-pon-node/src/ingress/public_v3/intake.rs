//! Volatile admission resources owned by the existing shared CPU domain.
//!
//! These are the existing V3 limits, now aggregate across its listeners. No key,
//! connection, new listener or cloned domain gets another quota. This is local
//! overload protection, not peer entitlement, a host kernel cap or a new ledger.
use super::{
    mutating_operation, Result, CHALLENGES_PER_SECOND, CHALLENGE_BURST, READ_CHALLENGE_RESERVE,
};
use std::sync::{Arc, Mutex};
use std::time::Instant;

pub(super) struct ListenerIntake {
    // Controls aggregate spawned 3-worker listener services, their queue and
    // live spent-cookie tables under this CPU domain. Separate listener
    // rebuilds cannot exceed a finite worker/queue envelope.
    pub(super) listeners: Arc<Mutex<usize>>,
    pub(super) connections: Arc<Mutex<usize>>,
    pub(super) body_pool: Arc<Mutex<usize>>,
    pub(super) output_pool: Arc<Mutex<usize>>,
    pub(super) mutating_grants: Arc<Mutex<usize>>,
    pub(super) read_grants: Arc<Mutex<usize>>,
    challenges: Mutex<ChallengeBudget>,
}
struct ChallengeBudget {
    tokens: u64,
    updated: Instant,
}
impl ListenerIntake {
    pub(super) fn new() -> Self {
        Self::with_challenge_credit(CHALLENGE_BURST)
    }
    pub(super) fn after_process_restart() -> Self {
        Self::with_challenge_credit(0)
    }
    fn with_challenge_credit(tokens: u64) -> Self {
        Self {
            listeners: Arc::new(Mutex::new(0)),
            connections: Arc::new(Mutex::new(0)),
            body_pool: Arc::new(Mutex::new(0)),
            output_pool: Arc::new(Mutex::new(0)),
            mutating_grants: Arc::new(Mutex::new(0)),
            read_grants: Arc::new(Mutex::new(0)),
            challenges: Mutex::new(ChallengeBudget {
                tokens,
                updated: Instant::now(),
            }),
        }
    }
    // Caller tests the original lane FIFO head and absolute connection deadline
    // first. Count once BEFORE entropy/signing. Later cancellation never refunds
    // the already incurred challenge; an exhausted request remains in its old slot.
    pub(super) fn try_challenge(&self, op: u8, now: Instant) -> Result<bool> {
        let mut budget = self
            .challenges
            .lock()
            .map_err(|_| "PUBLIC_INTAKE_UNAVAILABLE")?;
        // A second listener can sample its clock before the first gets this lock.
        // Keep one monotonic refill watermark; never credit an interval twice.
        if let Some(elapsed) = now.checked_duration_since(budget.updated) {
            let credit = elapsed
                .as_millis()
                .saturating_mul(u128::from(CHALLENGES_PER_SECOND))
                / 1000;
            if credit > 0 {
                let credit = credit.min(u128::from(CHALLENGE_BURST)) as u64;
                budget.tokens = (budget.tokens + credit).min(CHALLENGE_BURST);
                budget.updated = now;
            }
        }
        if budget.tokens == 0 || (mutating_operation(op) && budget.tokens <= READ_CHALLENGE_RESERVE)
        {
            return Ok(false);
        }
        budget.tokens -= 1;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    #[test]
    fn shared_challenge_reserve_and_no_second_refill_at_stale_time() {
        let intake = ListenerIntake::new();
        let start = intake.challenges.lock().unwrap().updated;
        for _ in 0..CHALLENGE_BURST - READ_CHALLENGE_RESERVE {
            assert!(intake.try_challenge(1, start).unwrap());
        }
        assert!(!intake.try_challenge(1, start).unwrap());
        for _ in 0..READ_CHALLENGE_RESERVE {
            assert!(intake.try_challenge(2, start).unwrap());
        }
        assert!(!intake.try_challenge(2, start).unwrap());
        let later = start + Duration::from_millis(16);
        assert!(intake.try_challenge(2, later).unwrap());
        assert!(intake.try_challenge(2, start).unwrap());
        assert!(!intake.try_challenge(2, later).unwrap());
        assert_eq!(intake.challenges.lock().unwrap().updated, later);
    }
    #[test]
    fn cold_restart_has_no_challenge_burst_and_refills_from_its_own_clock() {
        let intake = ListenerIntake::after_process_restart();
        let start = intake.challenges.lock().unwrap().updated;
        assert!(!intake.try_challenge(2, start).unwrap());
        assert!(intake
            .try_challenge(2, start + Duration::from_millis(8))
            .unwrap());
        assert!(!intake
            .try_challenge(1, start + Duration::from_millis(8))
            .unwrap());
        assert_eq!(intake.challenges.lock().unwrap().tokens, 0);
    }
    #[test]
    fn concurrent_challenge_requests_share_one_burst_without_keys() {
        let intake = Arc::new(ListenerIntake::new());
        let start = intake.challenges.lock().unwrap().updated;
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let x = intake.clone();
                std::thread::spawn(move || {
                    (0..8)
                        .filter(|_| x.try_challenge(2, start).unwrap())
                        .count()
                })
            })
            .collect();
        let issued: usize = handles.into_iter().map(|h| h.join().unwrap()).sum();
        assert_eq!(issued, CHALLENGE_BURST as usize);
    }
    #[test]
    fn unavailable_challenge_lock_does_not_create_another_budget() {
        let intake = Arc::new(ListenerIntake::new());
        let x = intake.clone();
        assert!(std::thread::spawn(move || {
            let _guard = x.challenges.lock().unwrap();
            panic!("test-only lock poison");
        })
        .join()
        .is_err());
        assert_eq!(
            intake
                .try_challenge(2, Instant::now())
                .unwrap_err()
                .to_string(),
            "PUBLIC_INTAKE_UNAVAILABLE"
        );
    }
}
