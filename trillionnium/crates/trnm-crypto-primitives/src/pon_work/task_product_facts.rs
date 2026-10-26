//! Opt-in, bounded reuse of a positive A*B fact across different challenges.
//!
//! Every call checks the complete current PNW1 encoding, canonical A/B/C fields,
//! task and target, and replays the complete original challenge-bound transcript.
//! Only the challenge-independent product is reused, with exact A/B bytes as key.
//! A first fact is published only after full original arithmetic, all current
//! claims and the final cancellation checkpoint succeed. No task eligibility,
//! header, parent, ticket, rejection, trace or verification verdict is cached.
//!
//! This is a separate explicit owner. The original verifier, WorkFactCache,
//! ArithmeticFactCache and default Node path retain their existing behavior.
use super::*;
use std::mem::size_of;
use std::sync::{Mutex, TryLockError};

pub use super::facts::FactError;

pub const MAX_TASK_PRODUCT_FACT_SLOTS: usize = 64;
pub const MAX_TASK_PRODUCT_FACT_SOFTWARE_BYTES: usize = 4 * 1024 * 1024;
const INPUT_BYTES: usize = 2 * CELLS * 4;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ProductPublication {
    #[default]
    None,
    Stored,
    Existing,
    Contended,
}

/// Actual local path observations, not CPU, authority or minimum-work estimates.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ProductObservation {
    pub lookup_probes: usize,
    pub lookup_contended: bool,
    pub exact_inputs_found: bool,
    pub product_reused: bool,
    pub transcript_entered: bool,
    pub transcript_completed: bool,
    pub product_reconstruction_entered: bool,
    pub product_reconstruction_completed: bool,
    pub publication_probes: usize,
    pub publication: ProductPublication,
}

struct Fact {
    inputs: [u8; INPUT_BYTES],
    product: [u32; CELLS],
}
struct CacheState {
    entries: Vec<Option<Fact>>,
    replacement: usize,
}

/// Fixed-shape volatile mathematical facts for the compiled W1 PROFILE/N/R/Q.
/// There is no caller-selected shape, field, profile or serialized cache input.
/// At most capacity probes occur per lookup/publication. A contended lock causes
/// a fully charged original arithmetic path; no waiting thread is created.
/// `software_bytes` includes every retained key, product, slot tag, Vec capacity,
/// mutex and owner metadata. Allocator overhead, return values and per-call
/// arithmetic workspace are separate, so this is not an RSS or host-wide bound.
/// Lookup copies at most one 16-KiB product before releasing the lock.
/// Poison or an inconsistent positive fact is local unavailability, never work.
pub struct TaskProductFactCache {
    capacity: usize,
    software_bytes: usize,
    state: Mutex<CacheState>,
}
impl TaskProductFactCache {
    pub fn new(capacity: usize) -> Result<Self, &'static str> {
        if !(1..=MAX_TASK_PRODUCT_FACT_SLOTS).contains(&capacity) {
            return Err("WORK_TASK_PRODUCT_FACT_CAPACITY");
        }
        let mut entries = Vec::<Option<Fact>>::new();
        entries
            .try_reserve_exact(capacity)
            .map_err(|_| "WORK_TASK_PRODUCT_FACT_ALLOCATION")?;
        let software_bytes = entries
            .capacity()
            .checked_mul(size_of::<Option<Fact>>())
            .and_then(|n| n.checked_add(size_of::<Self>()))
            .ok_or("WORK_TASK_PRODUCT_FACT_CAPACITY")?;
        if software_bytes > MAX_TASK_PRODUCT_FACT_SOFTWARE_BYTES {
            return Err("WORK_TASK_PRODUCT_FACT_CAPACITY");
        }
        entries.resize_with(capacity, || None);
        Ok(Self {
            capacity,
            software_bytes,
            state: Mutex::new(CacheState {
                entries,
                replacement: 0,
            }),
        })
    }
    pub fn capacity(&self) -> usize {
        self.capacity
    }
    pub fn software_bytes(&self) -> usize {
        self.software_bytes
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
        self.verify_with_observation(
            challenge,
            task,
            target,
            bytes,
            progress,
            &mut ProductObservation::default(),
        )
    }
    pub fn verify_with_observation<E>(
        &self,
        challenge: Hash,
        task: Hash,
        target: Hash,
        bytes: &[u8],
        progress: &mut impl FnMut(VerificationProgress) -> Result<(), E>,
        observation: &mut ProductObservation,
    ) -> Result<VerifiedWork, FactError<E>> {
        *observation = ProductObservation::default();
        // Exactly the original cheap-check order, before cache access/callbacks.
        let checked = checked_proof_inputs(
            challenge,
            task,
            target,
            bytes,
            VerificationKernel::Transposed,
        )?;
        let inputs: &[u8; INPUT_BYTES] = bytes[4..4 + INPUT_BYTES]
            .try_into()
            .map_err(|_| FactError::Relation(WorkError::Length))?;
        let claimed_bytes = &bytes[4 + INPUT_BYTES..PROOF_BYTES - 32];
        let trace_claim = &bytes[PROOF_BYTES - 32..];
        progress(VerificationProgress::BeforeReplay).map_err(FactError::Cancelled)?;
        let saved = self.lookup(inputs, observation)?;
        observation.exact_inputs_found = saved.is_some();
        let (a, b) = checked.matrices.split_at(CELLS);
        observation.transcript_entered = true;
        let evaluated = evaluate_transposed_with_progress::<false, E>(challenge, a, b, progress)?;
        observation.transcript_completed = true;
        if evaluated.trace.as_slice() != trace_claim {
            return Err(FactError::Relation(WorkError::Transcript));
        }
        let product = if let Some(product) = saved {
            drop(evaluated);
            progress(VerificationProgress::BeforeProduct).map_err(FactError::Cancelled)?;
            observation.product_reused = true;
            product.to_vec()
        } else {
            observation.product_reconstruction_entered = true;
            let product = finish_transposed_with_progress(a, evaluated, progress)
                .map_err(FactError::Cancelled)?;
            observation.product_reconstruction_completed = true;
            product
        };
        if !matches_product(&product, claimed_bytes) {
            return Err(FactError::Relation(WorkError::Product));
        }
        progress(VerificationProgress::BeforeVerifiedWork).map_err(FactError::Cancelled)?;
        if !observation.product_reused {
            let fixed = product
                .as_slice()
                .try_into()
                .map_err(|_| FactError::Unavailable)?;
            self.publish(inputs, fixed, observation)?;
        }
        Ok(VerifiedWork {
            challenge,
            task: checked.actual_task,
            ticket: checked.ticket,
            product,
        })
    }
    fn lookup<E>(
        &self,
        inputs: &[u8; INPUT_BYTES],
        observation: &mut ProductObservation,
    ) -> Result<Option<[u32; CELLS]>, FactError<E>> {
        let state = match self.state.try_lock() {
            Ok(state) => state,
            Err(TryLockError::WouldBlock) => {
                observation.lookup_contended = true;
                return Ok(None);
            }
            Err(TryLockError::Poisoned(_)) => return Err(FactError::Unavailable),
        };
        for entry in &state.entries {
            observation.lookup_probes += 1;
            if let Some(entry) = entry {
                if entry.inputs == *inputs {
                    return Ok(Some(entry.product));
                }
            }
        }
        Ok(None)
    }
    fn publish<E>(
        &self,
        inputs: &[u8; INPUT_BYTES],
        product: [u32; CELLS],
        observation: &mut ProductObservation,
    ) -> Result<(), FactError<E>> {
        let mut state = match self.state.try_lock() {
            Ok(state) => state,
            Err(TryLockError::WouldBlock) => {
                observation.publication = ProductPublication::Contended;
                return Ok(());
            }
            Err(TryLockError::Poisoned(_)) => return Err(FactError::Unavailable),
        };
        let mut vacant = None;
        for (index, entry) in state.entries.iter().enumerate() {
            observation.publication_probes += 1;
            let Some(entry) = entry else {
                vacant.get_or_insert(index);
                continue;
            };
            if entry.inputs == *inputs {
                if entry.product != product {
                    return Err(FactError::Unavailable);
                }
                observation.publication = ProductPublication::Existing;
                return Ok(());
            }
        }
        let index = vacant.unwrap_or(state.replacement);
        state.entries[index] = Some(Fact {
            inputs: *inputs,
            product,
        });
        state.replacement = (index + 1) % self.capacity;
        observation.publication = ProductPublication::Stored;
        Ok(())
    }
}
fn matches_product(product: &[u32], bytes: &[u8]) -> bool {
    product
        .iter()
        .flat_map(|word| word.to_le_bytes())
        .eq(bytes.iter().copied())
}

#[cfg(test)]
mod tests;
