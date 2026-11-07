//! Bounded ordering for starts in the original shared mutation CPU account.
//! A slot is scheduling metadata for an already dequeued paid task. It owns no
//! extra task/body, CPU credit, worker, grant, deadline or caller entitlement.
use super::PaidMutationCpuBudget;
use crate::{ensure, Result};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use std::time::Instant;

const CAPACITY: usize = super::super::MAX_MUTATING_GRANTS;

struct Waiter {
    sequence: u64,
    deadline: Instant,
    stop: Arc<AtomicBool>,
    cancelled: Arc<AtomicBool>,
}
impl Waiter {
    fn alive(&self, now: Instant) -> bool {
        now < self.deadline
            && !self.stop.load(Ordering::Acquire)
            && !self.cancelled.load(Ordering::Acquire)
    }
}

pub(super) struct CpuStartOrder {
    identity: Arc<()>,
    next: u64,
    slots: [Option<Waiter>; CAPACITY],
}
impl Default for CpuStartOrder {
    fn default() -> Self {
        Self {
            identity: Arc::new(()),
            next: 0,
            slots: std::array::from_fn(|_| None),
        }
    }
}
impl CpuStartOrder {
    fn retire(&mut self, now: Instant) {
        for slot in &mut self.slots {
            if slot.as_ref().is_some_and(|entry| !entry.alive(now)) {
                // The task owner still owns every original body/lane permit.
                // Another poll may retire ordering metadata, never live work.
                *slot = None;
            }
        }
    }
    fn register(
        &mut self,
        deadline: Instant,
        stop: Arc<AtomicBool>,
        cancelled: Arc<AtomicBool>,
        now: Instant,
    ) -> Result<u64> {
        super::super::task_alive(deadline, &stop, &cancelled)?;
        self.retire(now);
        let slot = self
            .slots
            .iter_mut()
            .find(|slot| slot.is_none())
            .ok_or("PUBLIC_QUEUE_BUSY")?;
        let sequence = self.next.checked_add(1).ok_or("PUBLIC_PENDING_ORDER")?;
        self.next = sequence;
        *slot = Some(Waiter {
            sequence,
            deadline,
            stop,
            cancelled,
        });
        Ok(sequence)
    }
    pub(super) fn allows(&mut self, sequence: Option<u64>, now: Instant) -> Result<bool> {
        self.retire(now);
        let mut head = None;
        let mut present = sequence.is_none();
        for entry in self.slots.iter().flatten() {
            if sequence == Some(entry.sequence) {
                present = true;
            }
            head = Some(head.map_or(entry.sequence, |old: u64| old.min(entry.sequence)));
        }
        // A retired or consumed token cannot be renewed, even if its flags are
        // later cleared or a caller supplies an older clock to a unit control.
        ensure(present, "PUBLIC_PENDING_ORDER")?;
        Ok(match sequence {
            Some(sequence) => head == Some(sequence),
            None => head.is_none(),
        })
    }
    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.slots.iter().flatten().count()
    }
    pub(super) fn remove(&mut self, sequence: u64) {
        if let Some(slot) = self.slots.iter_mut().find(|slot| {
            slot.as_ref()
                .is_some_and(|entry| entry.sequence == sequence)
        }) {
            *slot = None;
        }
    }
}

/// One task's queue token. It cannot be cloned or moved to another budget by a
/// caller. All uses acquire this exact account, and drop only removes metadata.
pub(in crate::ingress::public_v3) struct PendingCpuStart {
    budget: Arc<Mutex<PaidMutationCpuBudget>>,
    domain: Arc<()>,
    sequence: u64,
    pending: bool,
}
impl PendingCpuStart {
    pub(in crate::ingress::public_v3) fn register(
        budget: Arc<Mutex<PaidMutationCpuBudget>>,
        deadline: Instant,
        stop: Arc<AtomicBool>,
        cancelled: Arc<AtomicBool>,
    ) -> Result<Self> {
        let (sequence, domain) = {
            let mut account = budget
                .lock()
                .map_err(|_| "PUBLIC_MUTATION_CPU_UNAVAILABLE")?;
            let sequence =
                account
                    .cpu_starts
                    .register(deadline, stop, cancelled, Instant::now())?;
            (sequence, account.cpu_starts.identity.clone())
        };
        Ok(Self {
            budget,
            domain,
            sequence,
            pending: true,
        })
    }
    pub(in crate::ingress::public_v3) fn is_head(
        &self,
        budget: &mut PaidMutationCpuBudget,
        now: Instant,
    ) -> Result<bool> {
        ensure(
            self.pending && Arc::ptr_eq(&self.domain, &budget.cpu_starts.identity),
            "PUBLIC_PENDING_ORDER",
        )?;
        budget.cpu_starts.allows(Some(self.sequence), now)
    }
    pub(in crate::ingress::public_v3) fn reserve(
        &mut self,
        budget: &mut PaidMutationCpuBudget,
        now: Instant,
    ) -> Result<()> {
        ensure(
            self.pending && Arc::ptr_eq(&self.domain, &budget.cpu_starts.identity),
            "PUBLIC_PENDING_ORDER",
        )?;
        budget.reserve_with_order(now, Some(self.sequence))?;
        self.pending = false;
        Ok(())
    }
}
impl Drop for PendingCpuStart {
    fn drop(&mut self) {
        if !self.pending {
            return;
        }
        if let Ok(mut budget) = self.budget.lock() {
            budget.cpu_starts.remove(self.sequence);
        }
    }
}

#[cfg(test)]
#[path = "cpu_start_order_tests.rs"]
mod tests;
