//! Local proof-work admission. Bounds resources; does NOT prove Sybil safety or cost hardness.
//! Remote message fields never select the recovery port. The host keeps that capability.
//!
//! A caller must report the result of every proof verification through
//! [`Permit::complete`]. Rejected proofs consume a short-lived rejection budget before a
//! new expensive verification can start. This is a local DoS brake only: it cannot bind
//! a peer identity across connections and it does not make W1 hard or Sybil-safe.
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const DEFAULT_FAILURE_WINDOW: Duration = Duration::from_secs(1);
const DEFAULT_PER_PEER_REJECTIONS: usize = 2;
const DEFAULT_GLOBAL_REJECTIONS: usize = 32;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    GlobalBusy,
    GlobalRateLimited,
    PeerBusy,
    PeerRateLimited,
    Duplicate,
    Stopped,
    Poisoned,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationOutcome {
    Accepted,
    Rejected,
    Cancelled,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdmissionPolicy {
    pub failure_window: Duration,
    pub max_peer_rejections: usize,
    pub max_global_rejections: usize,
}
impl Default for AdmissionPolicy {
    fn default() -> Self {
        Self {
            failure_window: DEFAULT_FAILURE_WINDOW,
            max_peer_rejections: DEFAULT_PER_PEER_REJECTIONS,
            max_global_rejections: DEFAULT_GLOBAL_REJECTIONS,
        }
    }
}
#[derive(Default)]
struct FailureWindow {
    events: VecDeque<Instant>,
}
impl FailureWindow {
    fn purge(&mut self, now: Instant, window: Duration) {
        while self
            .events
            .front()
            .is_some_and(|at| now.saturating_duration_since(*at) >= window)
        {
            self.events.pop_front();
        }
    }
}
#[derive(Default)]
struct State {
    public: usize,
    recovery: usize,
    peers: BTreeMap<[u8; 32], usize>,
    active: BTreeSet<(bool, [u8; 32])>,
    failures: BTreeMap<[u8; 32], FailureWindow>,
    global_failures: VecDeque<Instant>,
    policy: AdmissionPolicy,
    generation: u64,
    stopped: bool,
}
#[derive(Clone)]
pub struct PublicIngress(Arc<Mutex<State>>);
/// Local-only recovery capability, not serializable or constructible from a peer packet.
pub struct RecoveryIngress(Arc<Mutex<State>>);
pub struct Permit {
    state: Arc<Mutex<State>>,
    peer: [u8; 32],
    digest: [u8; 32],
    recovery: bool,
    generation: u64,
}
/// Three public verifications plus one reserved recovery verification. No secret or chain authority.
pub fn bounded_ingress() -> (PublicIngress, RecoveryIngress) {
    bounded_ingress_with_policy(AdmissionPolicy::default())
}
/// Construct admission with an explicit local rejection budget.
///
/// This policy is deliberately local and ephemeral. It is not a consensus parameter and
/// must not be used as evidence of public Sybil resistance.
pub fn bounded_ingress_with_policy(policy: AdmissionPolicy) -> (PublicIngress, RecoveryIngress) {
    let state = Arc::new(Mutex::new(State {
        policy,
        ..State::default()
    }));
    (PublicIngress(state.clone()), RecoveryIngress(state))
}
fn purge_failures(s: &mut State, now: Instant) {
    let window = s.policy.failure_window;
    s.global_failures
        .retain(|at| now.saturating_duration_since(*at) < window);
    s.failures.retain(|_, failures| {
        failures.purge(now, window);
        !failures.events.is_empty()
    });
}
fn acquire(
    state: &Arc<Mutex<State>>,
    peer: [u8; 32],
    digest: [u8; 32],
    recovery: bool,
) -> Result<Permit, Refusal> {
    let mut s = state.lock().map_err(|_| Refusal::Poisoned)?;
    if s.stopped {
        return Err(Refusal::Stopped);
    }
    purge_failures(&mut s, Instant::now());
    if s.active.contains(&(recovery, digest)) {
        return Err(Refusal::Duplicate);
    }
    if recovery {
        if s.recovery >= 1 {
            return Err(Refusal::GlobalBusy);
        }
    } else {
        if s.global_failures.len() >= s.policy.max_global_rejections {
            return Err(Refusal::GlobalRateLimited);
        }
        if s
            .failures
            .get(&peer)
            .is_some_and(|failures| failures.events.len() >= s.policy.max_peer_rejections)
        {
            return Err(Refusal::PeerRateLimited);
        }
        if s.public >= 3 {
            return Err(Refusal::GlobalBusy);
        }
        if s.peers.get(&peer).copied().unwrap_or(0) >= 2 {
            return Err(Refusal::PeerBusy);
        }
    }
    s.active.insert((recovery, digest));
    if recovery {
        s.recovery += 1;
    } else {
        s.public += 1;
        *s.peers.entry(peer).or_default() += 1;
    }
    Ok(Permit {
        state: state.clone(),
        peer,
        digest,
        recovery,
        generation: s.generation,
    })
}
impl PublicIngress {
    pub fn try_acquire(&self, peer: [u8; 32], digest: [u8; 32]) -> Result<Permit, Refusal> {
        acquire(&self.0, peer, digest, false)
    }
}
impl RecoveryIngress {
    pub fn try_acquire(&self, digest: [u8; 32]) -> Result<Permit, Refusal> {
        acquire(&self.0, [0; 32], digest, true)
    }
    pub fn stop(&self) -> Result<(), Refusal> {
        let mut s = self.0.lock().map_err(|_| Refusal::Poisoned)?;
        s.stopped = true;
        s.generation = s.generation.checked_add(1).ok_or(Refusal::Stopped)?;
        Ok(())
    }
    /// Resume does not erase outstanding jobs; old permits retain their capacity until dropped.
    pub fn resume(&self) -> Result<(), Refusal> {
        self.0.lock().map_err(|_| Refusal::Poisoned)?.stopped = false;
        Ok(())
    }
}
impl Permit {
    pub fn cancelled(&self) -> bool {
        self.state
            .lock()
            .map(|s| s.stopped || s.generation != self.generation)
            .unwrap_or(true)
    }

    /// Report the result before releasing the verification slot.
    ///
    /// Invalid proofs are charged to both the peer and a bounded global rejection budget.
    /// The charge expires after the configured window. Accepted and cancelled work has no
    /// charge. Callers that drop a permit without reporting remain compatible with the
    /// historical candidate API; production admission must report every completed attempt.
    pub fn complete(self, outcome: VerificationOutcome) -> Result<(), Refusal> {
        if outcome == VerificationOutcome::Rejected && !self.recovery {
            let mut s = self.state.lock().map_err(|_| Refusal::Poisoned)?;
            let now = Instant::now();
            purge_failures(&mut s, now);
            s.global_failures.push_back(now);
            s.failures.entry(self.peer).or_default().events.push_back(now);
        }
        Ok(())
    }
}
impl Drop for Permit {
    fn drop(&mut self) {
        // Poisoning fences admission. Reclaiming counts never produces verified work.
        let mut s = self.state.lock().unwrap_or_else(|e| e.into_inner());
        s.active.remove(&(self.recovery, self.digest));
        if self.recovery {
            s.recovery -= 1;
        } else {
            s.public -= 1;
            if let Some(n) = s.peers.get_mut(&self.peer) {
                *n -= 1;
                if *n == 0 {
                    s.peers.remove(&self.peer);
                }
            }
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn public_flood_cannot_consume_reserved_recovery_capacity() {
        let (public, recovery) = bounded_ingress();
        let mut held = Vec::new();
        for i in 0..3 {
            held.push(public.try_acquire([i; 32], [i; 32]).unwrap());
        }
        for i in 0_u32..2000 {
            let mut id = [99; 32];
            id[..4].copy_from_slice(&i.to_le_bytes());
            assert!(matches!(
                public.try_acquire(id, id),
                Err(Refusal::GlobalBusy) | Err(Refusal::Duplicate)
            ));
        }
        let reserved = recovery.try_acquire([88; 32]).unwrap();
        assert!(!reserved.cancelled());
        drop(reserved);
        drop(held);
        assert!(public.try_acquire([7; 32], [7; 32]).is_ok());
    }
    #[test]
    fn duplicate_and_per_peer_bound_are_before_work() {
        let (public, _) = bounded_ingress();
        let a = public.try_acquire([1; 32], [1; 32]).unwrap();
        assert!(matches!(
            public.try_acquire([2; 32], [1; 32]),
            Err(Refusal::Duplicate)
        ));
        let b = public.try_acquire([1; 32], [2; 32]).unwrap();
        assert!(matches!(
            public.try_acquire([1; 32], [3; 32]),
            Err(Refusal::PeerBusy)
        ));
        drop((a, b));
    }
    #[test]
    fn stop_resume_does_not_erase_outstanding_work() {
        let (public, recovery) = bounded_ingress();
        let mut held = Vec::new();
        for i in 0..3 {
            held.push(public.try_acquire([i; 32], [i; 32]).unwrap());
        }
        recovery.stop().unwrap();
        assert!(held.iter().all(Permit::cancelled));
        recovery.resume().unwrap();
        assert!(matches!(
            public.try_acquire([7; 32], [7; 32]),
            Err(Refusal::GlobalBusy)
        ));
        drop(held);
        assert!(public.try_acquire([7; 32], [7; 32]).is_ok());
    }
    #[test]
    fn public_duplicate_cannot_pin_a_locally_requested_recovery_digest() {
        let (public, recovery) = bounded_ingress();
        let remote = public.try_acquire([1; 32], [9; 32]).unwrap();
        let local = recovery.try_acquire([9; 32]).unwrap();
        assert!(!remote.cancelled());
        assert!(!local.cancelled());
        assert!(matches!(
            recovery.try_acquire([9; 32]),
            Err(Refusal::Duplicate)
        ));
        drop(remote);
        assert!(matches!(
            recovery.try_acquire([9; 32]),
            Err(Refusal::Duplicate)
        ));
        drop(local);
        assert!(recovery.try_acquire([9; 32]).is_ok());
    }

    #[test]
    fn panic_unwind_releases_capacity() {
        let (public, _) = bounded_ingress();
        let p = public.clone();
        let result = std::panic::catch_unwind(move || {
            let _permit = p.try_acquire([1; 32], [2; 32]).unwrap();
            panic!("test unwind");
        });
        assert!(result.is_err());
        assert!(public.try_acquire([1; 32], [2; 32]).is_ok());
    }

    #[test]
    fn rejected_work_is_rate_limited_before_another_expensive_verification() {
        let (public, recovery) = bounded_ingress_with_policy(AdmissionPolicy {
            failure_window: Duration::from_millis(20),
            max_peer_rejections: 2,
            max_global_rejections: 4,
        });
        let peer = [7; 32];
        for i in 0..2 {
            let permit = public.try_acquire(peer, [i; 32]).unwrap();
            permit.complete(VerificationOutcome::Rejected).unwrap();
        }
        assert!(matches!(
            public.try_acquire(peer, [9; 32]),
            Err(Refusal::PeerRateLimited)
        ));
        // Recovery remains available even when public proof rejection debt is high.
        assert!(recovery.try_acquire([8; 32]).is_ok());
        std::thread::sleep(Duration::from_millis(25));
        assert!(public.try_acquire(peer, [9; 32]).is_ok());
    }

    #[test]
    fn global_rejection_budget_limits_sybil_like_peer_rotation_locally() {
        let (public, _) = bounded_ingress_with_policy(AdmissionPolicy {
            failure_window: Duration::from_secs(1),
            max_peer_rejections: 8,
            max_global_rejections: 2,
        });
        for i in 0..2 {
            let permit = public.try_acquire([i; 32], [i; 32]).unwrap();
            permit.complete(VerificationOutcome::Rejected).unwrap();
        }
        assert!(matches!(
            public.try_acquire([99; 32], [99; 32]),
            Err(Refusal::GlobalRateLimited)
        ));
    }
}
