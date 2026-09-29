//! Local proof-work admission. Bounds resources; does NOT prove Sybil safety or cost hardness.
//! Remote message fields never select the recovery port. The host keeps that capability.
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    GlobalBusy,
    PeerBusy,
    Duplicate,
    Stopped,
    Poisoned,
}
#[derive(Default)]
struct State {
    public: usize,
    recovery: usize,
    peers: BTreeMap<[u8; 32], usize>,
    active: BTreeSet<[u8; 32]>,
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
    let state = Arc::new(Mutex::new(State::default()));
    (PublicIngress(state.clone()), RecoveryIngress(state))
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
    if s.active.contains(&digest) {
        return Err(Refusal::Duplicate);
    }
    if recovery {
        if s.recovery >= 1 {
            return Err(Refusal::GlobalBusy);
        }
    } else {
        if s.public >= 3 {
            return Err(Refusal::GlobalBusy);
        }
        if s.peers.get(&peer).copied().unwrap_or(0) >= 2 {
            return Err(Refusal::PeerBusy);
        }
    }
    s.active.insert(digest);
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
}
impl Drop for Permit {
    fn drop(&mut self) {
        // Poisoning fences admission. Reclaiming counts never produces verified work.
        let mut s = self.state.lock().unwrap_or_else(|e| e.into_inner());
        s.active.remove(&self.digest);
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
}
