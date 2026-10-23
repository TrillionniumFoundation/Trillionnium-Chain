//! Opt-in reuse of fully computed W1 arithmetic, not a verification verdict.
//!
//! A slot contains exact current challenge/A/B bytes, a computed trace and an
//! optional computed product. It has no claimed trace/product, target, task row,
//! block, authorization, rejection or VerifiedWork. Every invocation repeats the
//! original cheap-check order and compares the current claims. A call returning
//! cancellation publishes no new fact; incomplete arithmetic is never retained.
//! Checkpoints are cooperative: bounded final comparison/publication can follow
//! the last checkpoint. This is not hard preemption or a zero-overrun promise.
//! A completed mismatching trace can
//! retain its positive arithmetic value without doing product corrections.
//!
//! This module does not change either the original raw verifier or WorkFactCache.
//! Callers must opt in, retain their current-context/CPU/deadline owner and report
//! arithmetic reuse separately from a fresh transcript replay. Contended cache
//! locks cause real, fully accounted raw arithmetic; no cache wait or helper work
//! thread is created. Poison is a local unavailability error, never valid work.
use super::*;
use std::mem::size_of;
use std::sync::{Mutex, TryLockError};

pub use super::facts::FactError;

pub const MAX_ARITHMETIC_FACT_SLOTS: usize = 64;
pub const MAX_ARITHMETIC_FACT_SOFTWARE_BYTES: usize = 4 * 1024 * 1024;
const INPUT_BYTES: usize = 2 * CELLS * 4;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ArithmeticPublication {
    #[default]
    None,
    Trace,
    Product,
    ExistingStrongerOrEqual,
    Contended,
}

/// Per-invocation facts about this implementation's actual path, never CPU/RSS
/// estimates or proof/execution authority. An entered path need not complete.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ArithmeticObservation {
    pub lookup_probes: usize,
    pub lookup_contended: bool,
    pub exact_fact_found: bool,
    pub trace_reused: bool,
    pub product_reused: bool,
    pub transcript_entered: bool,
    pub transcript_completed: bool,
    pub product_entered: bool,
    pub product_completed: bool,
    pub publication_probes: usize,
    pub publication: ArithmeticPublication,
}

#[derive(Clone, Copy)]
struct ComputedArithmetic {
    trace: Hash,
    product: Option<[u32; CELLS]>,
}
struct Fact {
    challenge: Hash,
    inputs: [u8; INPUT_BYTES],
    arithmetic: ComputedArithmetic,
}
struct CacheState {
    entries: Vec<Option<Fact>>,
    replacement: usize,
}

/// One bounded volatile owner. At most 64 fixed-size slots and at most capacity
/// probes per lookup/publication; there is no map growth, per-entry allocation,
/// persistence, expiry extension, single-flight waiter or retained caller error.
/// The charged retained Rust object storage is at most 4 MiB. This excludes
/// allocator bookkeeping, ordinary per-call verifier workspace and caller return
/// values, and is explicitly not a process RSS bound or a global cache allowance.
pub struct ArithmeticFactCache {
    capacity: usize,
    software_bytes: usize,
    state: Mutex<CacheState>,
}
impl ArithmeticFactCache {
    pub fn new(capacity: usize) -> Result<Self, &'static str> {
        if !(1..=MAX_ARITHMETIC_FACT_SLOTS).contains(&capacity) {
            return Err("WORK_ARITHMETIC_FACT_CAPACITY");
        }
        let mut entries: Vec<Option<Fact>> = Vec::new();
        entries
            .try_reserve_exact(capacity)
            .map_err(|_| "WORK_ARITHMETIC_FACT_ALLOCATION")?;
        let software_bytes = entries
            .capacity()
            .checked_mul(size_of::<Option<Fact>>())
            .and_then(|bytes| bytes.checked_add(size_of::<Self>()))
            .ok_or("WORK_ARITHMETIC_FACT_CAPACITY")?;
        if software_bytes > MAX_ARITHMETIC_FACT_SOFTWARE_BYTES {
            return Err("WORK_ARITHMETIC_FACT_CAPACITY");
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
            &mut ArithmeticObservation::default(),
        )
    }
    pub fn verify_with_observation<E>(
        &self,
        challenge: Hash,
        task: Hash,
        target: Hash,
        bytes: &[u8],
        progress: &mut impl FnMut(VerificationProgress) -> Result<(), E>,
        observation: &mut ArithmeticObservation,
    ) -> Result<VerifiedWork, FactError<E>> {
        *observation = ArithmeticObservation::default();
        // Current grammar, fields, task and target precede all cache access and
        // callbacks, exactly as in the retained original production verifier.
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
        let trace_claim = &bytes[PROOF_BYTES - 32..];
        let claimed_bytes = &bytes[4 + 2 * CELLS * 4..4 + 3 * CELLS * 4];
        progress(VerificationProgress::BeforeReplay).map_err(FactError::Cancelled)?;
        if let Some(arithmetic) = self.lookup(challenge, inputs, observation)? {
            observation.exact_fact_found = true;
            if arithmetic.trace.as_slice() != trace_claim {
                observation.trace_reused = true;
                return Err(FactError::Relation(WorkError::Transcript));
            }
            if let Some(product) = arithmetic.product {
                observation.trace_reused = true;
                observation.product_reused = true;
                progress(VerificationProgress::BeforeProduct).map_err(FactError::Cancelled)?;
                if !matches_product(&product, claimed_bytes) {
                    return Err(FactError::Relation(WorkError::Product));
                }
                progress(VerificationProgress::BeforeVerifiedWork).map_err(FactError::Cancelled)?;
                return Ok(VerifiedWork {
                    challenge,
                    task: checked.actual_task,
                    ticket: checked.ticket,
                    product: product.to_vec(),
                });
            }
            // A trace-only fact never supplies a product. If the new claim now
            // matches that trace, perform the original whole arithmetic replay.
        }
        let (a, b) = checked.matrices.split_at(CELLS);
        observation.transcript_entered = true;
        let evaluated = evaluate_transposed_with_progress::<false, E>(challenge, a, b, progress)?;
        observation.transcript_completed = true;
        let trace = evaluated.trace;
        if trace.as_slice() != trace_claim {
            self.publish(
                challenge,
                inputs,
                ComputedArithmetic {
                    trace,
                    product: None,
                },
                observation,
            )?;
            return Err(FactError::Relation(WorkError::Transcript));
        }
        observation.product_entered = true;
        let product = finish_transposed_with_progress(a, evaluated, progress)
            .map_err(FactError::Cancelled)?;
        observation.product_completed = true;
        let matches = matches_product(&product, claimed_bytes);
        if matches {
            progress(VerificationProgress::BeforeVerifiedWork).map_err(FactError::Cancelled)?;
        }
        let fixed_product = product
            .as_slice()
            .try_into()
            .map_err(|_| FactError::Unavailable)?;
        self.publish(
            challenge,
            inputs,
            ComputedArithmetic {
                trace,
                product: Some(fixed_product),
            },
            observation,
        )?;
        if !matches {
            return Err(FactError::Relation(WorkError::Product));
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
        challenge: Hash,
        inputs: &[u8; INPUT_BYTES],
        observation: &mut ArithmeticObservation,
    ) -> Result<Option<ComputedArithmetic>, FactError<E>> {
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
                // No digest alone grants a hit: compare the exact canonical A/B
                // bytes after the current call's field/task validation.
                if entry.challenge == challenge && entry.inputs == *inputs {
                    return Ok(Some(entry.arithmetic));
                }
            }
        }
        Ok(None)
    }
    fn publish<E>(
        &self,
        challenge: Hash,
        inputs: &[u8; INPUT_BYTES],
        arithmetic: ComputedArithmetic,
        observation: &mut ArithmeticObservation,
    ) -> Result<(), FactError<E>> {
        let mut state = match self.state.try_lock() {
            Ok(state) => state,
            Err(TryLockError::WouldBlock) => {
                observation.publication = ArithmeticPublication::Contended;
                return Ok(());
            }
            Err(TryLockError::Poisoned(_)) => return Err(FactError::Unavailable),
        };
        let mut vacant = None;
        for (index, entry) in state.entries.iter_mut().enumerate() {
            observation.publication_probes += 1;
            let Some(entry) = entry else {
                vacant.get_or_insert(index);
                continue;
            };
            if entry.challenge != challenge || entry.inputs != *inputs {
                continue;
            }
            if entry.arithmetic.trace != arithmetic.trace {
                return Err(FactError::Unavailable);
            }
            match (&entry.arithmetic.product, &arithmetic.product) {
                (Some(saved), Some(actual)) if saved != actual => {
                    return Err(FactError::Unavailable);
                }
                (None, Some(_)) => {
                    entry.arithmetic = arithmetic;
                    observation.publication = ArithmeticPublication::Product;
                }
                _ => observation.publication = ArithmeticPublication::ExistingStrongerOrEqual,
            }
            return Ok(());
        }
        let index = vacant.unwrap_or(state.replacement);
        state.entries[index] = Some(Fact {
            challenge,
            inputs: *inputs,
            arithmetic,
        });
        state.replacement = (index + 1) % self.capacity;
        observation.publication = if arithmetic.product.is_some() {
            ArithmeticPublication::Product
        } else {
            ArithmeticPublication::Trace
        };
        Ok(())
    }
}

fn matches_product(product: &[u32], claimed_bytes: &[u8]) -> bool {
    product
        .iter()
        .flat_map(|word| word.to_le_bytes())
        .eq(claimed_bytes.iter().copied())
}

#[cfg(test)]
mod churn_controls;
#[cfg(test)]
mod controls;
#[cfg(test)]
mod tests;
