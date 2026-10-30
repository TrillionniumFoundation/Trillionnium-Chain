//! Explicit, volatile W1 mathematical-fact reuse. No block, task lease, current
//! target, branch, peer, revocation or execution authorization is cached.
//!
//! Every call repeats the original cheap checks. Only complete successful native
//! verification publishes a product. No negative cache exists, so an invalid
//! variant cannot poison a later valid statement. Original verifiers are unchanged.
use super::*;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Condvar, Mutex};
use std::time::Duration;

pub const MAX_FACT_SLOTS: usize = 256;
const WAIT_POLL: Duration = Duration::from_millis(5);

#[derive(Debug, PartialEq, Eq)]
pub enum FactError<E> {
    Relation(WorkError),
    Cancelled(E),
    /// Local lock integrity failure, not a declaration of invalid consensus work.
    Unavailable,
}
impl<E> From<WorkError> for FactError<E> {
    fn from(error: WorkError) -> Self {
        Self::Relation(error)
    }
}
impl<E> From<VerificationError<E>> for FactError<E> {
    fn from(error: VerificationError<E>) -> Self {
        match error {
            VerificationError::Relation(e) => Self::Relation(e),
            VerificationError::Cancelled(e) => Self::Cancelled(e),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FactCounters {
    pub full_replays: u64,
    pub hits: u64,
    pub wait_polls: u64,
    pub evictions: u64,
}
#[derive(Clone, Copy, PartialEq, Eq)]
struct Key {
    challenge: Hash,
    task: Hash,
    trace: Hash,
}
enum State {
    Empty,
    Computing(Key),
    Ready(Key, Vec<u32>),
}
struct Slot {
    state: Mutex<State>,
    changed: Condvar,
}

/// Bounded direct-mapped slots. A colliding task waits for the current computation
/// with the caller's cancellation callback; it never starts duplicate untracked
/// work. Callers must bound their own thread/request count and supply a deadline.
/// Each completed slot owns exactly CELLS u32s; this is not a process RSS bound.
pub struct WorkFactCache {
    slots: Box<[Slot]>,
    replays: AtomicU64,
    hits: AtomicU64,
    waits: AtomicU64,
    evictions: AtomicU64,
}
impl WorkFactCache {
    pub fn new(slots: usize) -> Result<Self, &'static str> {
        if !(1..=MAX_FACT_SLOTS).contains(&slots) {
            return Err("WORK_FACT_CAPACITY");
        }
        Ok(Self {
            slots: (0..slots)
                .map(|_| Slot {
                    state: Mutex::new(State::Empty),
                    changed: Condvar::new(),
                })
                .collect(),
            replays: AtomicU64::new(0),
            hits: AtomicU64::new(0),
            waits: AtomicU64::new(0),
            evictions: AtomicU64::new(0),
        })
    }
    pub fn capacity(&self) -> usize {
        self.slots.len()
    }
    pub fn counters(&self) -> FactCounters {
        FactCounters {
            full_replays: self.replays.load(Ordering::Relaxed),
            hits: self.hits.load(Ordering::Relaxed),
            wait_polls: self.waits.load(Ordering::Relaxed),
            evictions: self.evictions.load(Ordering::Relaxed),
        }
    }
    pub fn verify(
        &self,
        challenge: Hash,
        task: Hash,
        target: Hash,
        bytes: &[u8],
    ) -> Result<VerifiedWork, FactError<std::convert::Infallible>> {
        self.verify_with_progress(challenge, task, target, bytes, &mut no_cancellation)
    }
    pub fn verify_with_progress<E>(
        &self,
        challenge: Hash,
        task: Hash,
        target: Hash,
        bytes: &[u8],
        progress: &mut impl FnMut(VerificationProgress) -> Result<(), E>,
    ) -> Result<VerifiedWork, FactError<E>> {
        // Cheap errors retain their original order and cannot access/populate a slot.
        let checked = checked_proof_inputs(
            challenge,
            task,
            target,
            bytes,
            VerificationKernel::Transposed,
        )?;
        let ticket = checked.ticket;
        drop(checked); // No decoded caller matrices survive into a cache wait.
        let trace: Hash = bytes[PROOF_BYTES - 32..]
            .try_into()
            .map_err(|_| WorkError::Length)?;
        let key = Key {
            challenge,
            task,
            trace,
        };
        let index_hash = hash(
            b"w1-mathematical-fact-slot-v1",
            &[PROFILE.as_bytes(), &challenge, &task, &trace],
        );
        let index = u64::from_le_bytes(index_hash[..8].try_into().map_err(|_| WorkError::Length)?)
            % self.slots.len() as u64;
        let slot = &self.slots[index as usize];
        loop {
            progress(VerificationProgress::BeforeReplay).map_err(FactError::Cancelled)?;
            let mut state = slot.state.lock().map_err(|_| FactError::Unavailable)?;
            match &*state {
                State::Ready(saved, product) if *saved == key => {
                    let product = product.clone();
                    drop(state);
                    count(&self.hits);
                    progress(VerificationProgress::BeforeProduct).map_err(FactError::Cancelled)?;
                    let claimed = &bytes[4 + 8 * CELLS..4 + 12 * CELLS];
                    if !product
                        .iter()
                        .flat_map(|v| v.to_le_bytes())
                        .eq(claimed.iter().copied())
                    {
                        return Err(FactError::Relation(WorkError::Product));
                    }
                    progress(VerificationProgress::BeforeVerifiedWork)
                        .map_err(FactError::Cancelled)?;
                    return Ok(VerifiedWork {
                        challenge,
                        task,
                        ticket,
                        product,
                    });
                }
                State::Computing(_) => {
                    count(&self.waits);
                    let (guard, _) = slot
                        .changed
                        .wait_timeout(state, WAIT_POLL)
                        .map_err(|_| FactError::Unavailable)?;
                    drop(guard);
                    // Each waiter owns its cancellation; a failed leader does not
                    // transmit its error or authorization to another request.
                }
                State::Empty | State::Ready(_, _) => {
                    if matches!(*state, State::Ready(_, _)) {
                        count(&self.evictions);
                    }
                    *state = State::Computing(key);
                    drop(state);
                    let owner = Computing { slot, key };
                    count(&self.replays);
                    // Math and caller callbacks never execute under a slot lock.
                    let verified =
                        super::verify_with_progress(challenge, task, target, bytes, progress)?;
                    owner
                        .publish(verified.product.clone())
                        .map_err(|_| FactError::Unavailable)?;
                    return Ok(verified);
                }
            }
        }
    }
}
fn count(counter: &AtomicU64) {
    let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
        Some(n.saturating_add(1))
    });
}
struct Computing<'a> {
    slot: &'a Slot,
    key: Key,
}
impl Computing<'_> {
    fn publish(self, product: Vec<u32>) -> Result<(), ()> {
        let mut state = self.slot.state.lock().map_err(|_| ())?;
        if !matches!(&*state, State::Computing(key) if *key == self.key) {
            return Err(());
        }
        *state = State::Ready(self.key, product);
        self.slot.changed.notify_all();
        Ok(())
    }
}
impl Drop for Computing<'_> {
    fn drop(&mut self) {
        if let Ok(mut state) = self.slot.state.lock() {
            if matches!(&*state, State::Computing(key) if *key == self.key) {
                *state = State::Empty;
            }
        }
        // Includes native rejection, cancellation and unwind. No abandoned busy slot.
        self.slot.changed.notify_all();
    }
}

#[cfg(test)]
mod tests;
