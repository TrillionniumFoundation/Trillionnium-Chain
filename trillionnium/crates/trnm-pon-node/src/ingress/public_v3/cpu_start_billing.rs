//! Actual owner CPU spent before a start reservation, in the same scalar account.
//! This guard buys no quantum, worker, caller authority or permission to execute.
use super::super::PublicMetrics;
use super::{LiveRequestCpu, PaidMutationCpuBudget, PendingCpuStart, ThreadCpuStamp};
use crate::{ensure, Result};
use std::{
    marker::PhantomData,
    ops::{Deref, DerefMut},
    rc::Rc,
    sync::{Arc, Mutex, MutexGuard},
    thread,
    time::Instant,
};

pub(in crate::ingress::public_v3) struct AdmissionWaitCpu<'a> {
    budget: Arc<Mutex<PaidMutationCpuBudget>>,
    stamp: Option<ThreadCpuStamp>,
    clock_failed: bool,
    billed_ns: u64,
    measurement_unknown: bool,
    covered: bool,
    metrics: Option<&'a Mutex<PublicMetrics>>,
    // Drop must sample the original owner, including errors and panic unwinding.
    _same_thread: PhantomData<Rc<()>>,
}
/// Only this waiting owner's actual account can create this locked scope.
/// Borrowing the rolling stamp also forces this lock to drop before wait cleanup.
pub(in crate::ingress::public_v3) struct AdmissionCpuAccount<'a> {
    account: &'a Arc<Mutex<PaidMutationCpuBudget>>,
    budget: MutexGuard<'a, PaidMutationCpuBudget>,
    stamp: &'a mut Option<ThreadCpuStamp>,
    now: Instant,
}
impl Deref for AdmissionCpuAccount<'_> {
    type Target = PaidMutationCpuBudget;
    fn deref(&self) -> &Self::Target {
        &self.budget
    }
}
impl DerefMut for AdmissionCpuAccount<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.budget
    }
}
impl AdmissionCpuAccount<'_> {
    pub(in crate::ingress::public_v3) fn observed_at(&self) -> Instant {
        self.now
    }
    /// The typed lock proves which account is held; the live object must agree.
    /// No caller can put an unrelated state into this account's scope registry.
    fn registration_slot(&self, live: &LiveRequestCpu) -> Result<Option<usize>> {
        ensure(
            Arc::ptr_eq(self.account, &live.budget),
            "PUBLIC_MUTATION_CPU_UNAVAILABLE",
        )?;
        Ok(self
            .budget
            .cpu_scopes
            .iter()
            .position(|scope| scope.strong_count() == 0))
    }
    /// Construct, reserve, register and transfer under the same actual account
    /// lock. All fallible scope checks precede the original reservation; there is
    /// no user callback, new sample or observable unregistered live-owner window.
    pub(in crate::ingress::public_v3) fn reserve_owner(
        &mut self,
        turn: Option<&mut PendingCpuStart>,
    ) -> Result<(ThreadCpuStamp, Arc<LiveRequestCpu>)> {
        let Some(stamp) = self.stamp.as_ref() else {
            self.budget.unavailable = true;
            return Err("PUBLIC_MUTATION_CPU_UNAVAILABLE".into());
        };
        let live = Arc::new(LiveRequestCpu::unregistered(
            self.account.clone(),
            stamp.clone(),
        ));
        let slot = match self.registration_slot(&live) {
            Ok(Some(slot)) => slot,
            Ok(None)
                if !self.budget.unavailable
                    && self.budget.in_flight == super::MUTATION_CPU_WORKERS =>
            {
                // Both original owners are still live. A third attempt has no
                // capacity; its wait remains paid without fencing those owners.
                return Err("PUBLIC_MUTATION_CPU_BUDGET".into());
            }
            Ok(None) | Err(_) => {
                // Occupied scope slots without the original live reservations
                // are an accounting inconsistency, not spare execution credit.
                self.budget.unavailable = true;
                return Err("PUBLIC_MUTATION_CPU_UNAVAILABLE".into());
            }
        };
        // Keep the stamp armed on every refused attempt. Nothing after the
        // successful reservation can fail or execute an external callback.
        match turn {
            Some(turn) => turn.reserve(&mut self.budget, self.now)?,
            None => self.budget.reserve(self.now)?,
        }
        self.budget.cpu_scopes[slot] = Arc::downgrade(&live.state);
        match self.stamp.take() {
            Some(stamp) => Ok((stamp, live)),
            None => {
                self.budget.unavailable = true;
                Err("PUBLIC_MUTATION_CPU_UNAVAILABLE".into())
            }
        }
    }
}
fn sample_locked(
    stamp: &mut Option<ThreadCpuStamp>,
    clock_failed: &mut bool,
    billed_ns: &mut u64,
    measurement_unknown: &mut bool,
    budget: &mut PaidMutationCpuBudget,
    now: Instant,
) -> Result<()> {
    let measured = stamp.as_mut().and_then(ThreadCpuStamp::checkpoint);
    let Some(measured) = measured else {
        *clock_failed = true;
        *measurement_unknown = true;
        budget.unavailable = true;
        return Err("PUBLIC_MUTATION_CPU_UNAVAILABLE".into());
    };
    if let Err(error) = budget.charge_admission_wait(now, measured) {
        *measurement_unknown = true;
        return Err(error);
    }
    match billed_ns.checked_add(measured) {
        Some(total) => *billed_ns = total,
        None => *measurement_unknown = true,
    }
    if budget.unavailable {
        *measurement_unknown = true;
    }
    ensure(!budget.unavailable, "PUBLIC_MUTATION_CPU_UNAVAILABLE")
}
/// Read only the original two owner slots, then release the account before
/// looking at request registries. Existing progress locks request -> account.
fn scope_covers_current_thread(account: &Arc<Mutex<PaidMutationCpuBudget>>) -> Result<bool> {
    #[cfg(test)]
    let snapshot_reached;
    let (scopes, unavailable) = {
        let budget = account
            .lock()
            .map_err(|_| "PUBLIC_MUTATION_CPU_UNAVAILABLE")?;
        #[cfg(test)]
        {
            snapshot_reached = budget.scope_snapshot_reached.clone();
        }
        (budget.cpu_scopes.clone(), budget.unavailable)
    };
    #[cfg(test)]
    if let Some(reached) = snapshot_reached {
        reached.store(true, std::sync::atomic::Ordering::Release);
    }
    let current = thread::current().id();
    for scope in scopes {
        let Some(state) = scope.upgrade() else {
            continue;
        };
        let state = state
            .lock()
            .map_err(|_| "PUBLIC_MUTATION_CPU_UNAVAILABLE")?;
        ensure(
            !state.unavailable
                && (state.owner_finished || state.threads.contains_key(&state.owner_thread)),
            "PUBLIC_MUTATION_CPU_UNAVAILABLE",
        )?;
        if let Some(stamp) = state.threads.get(&current) {
            ensure(
                !unavailable && stamp.belongs_to_current_thread(),
                "PUBLIC_MUTATION_CPU_UNAVAILABLE",
            )?;
            return Ok(true);
        }
    }
    Ok(false)
}

impl<'a> AdmissionWaitCpu<'a> {
    pub(in crate::ingress::public_v3) fn new(
        budget: Arc<Mutex<PaidMutationCpuBudget>>,
        stamp: Option<ThreadCpuStamp>,
    ) -> Result<Self> {
        Self::with_metrics(budget, stamp, None)
    }
    pub(in crate::ingress::public_v3) fn with_metrics(
        budget: Arc<Mutex<PaidMutationCpuBudget>>,
        stamp: Option<ThreadCpuStamp>,
        metrics: Option<&'a Mutex<PublicMetrics>>,
    ) -> Result<Self> {
        let mut value = Self {
            budget,
            clock_failed: stamp.is_none(),
            measurement_unknown: stamp.is_none(),
            billed_ns: 0,
            covered: false,
            metrics,
            stamp,
            _same_thread: PhantomData,
        };
        // The supplied clock precedes this lookup. Uncovered attempts keep it;
        // covered attempts cannot create a second reservation or overlapping bill.
        match scope_covers_current_thread(&value.budget) {
            Ok(true) => {
                value.covered = true;
                value.stamp = None;
                if !value.clock_failed {
                    return Err("PUBLIC_MUTATION_CPU_BUDGET".into());
                }
            }
            Ok(false) if !value.clock_failed => return Ok(value),
            Ok(false) => {}
            Err(_) => {
                // Attribution is unknown: charging a second interval could
                // duplicate a poisoned original owner. Never invent a zero success.
                value.measurement_unknown = true;
                value.stamp = None;
            }
        }
        let mut budget = value
            .budget
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        budget.unavailable = true;
        drop(budget);
        Err("PUBLIC_MUTATION_CPU_UNAVAILABLE".into())
    }
    /// Sample and debit the guard's own account before testing start eligibility.
    /// No caller can substitute a different budget for the locked CPU interval.
    /// Negative credit remains debt until the original refill; it buys no work.
    pub(in crate::ingress::public_v3) fn lock_and_sample(
        &mut self,
    ) -> Result<AdmissionCpuAccount<'_>> {
        let mut budget = self
            .budget
            .lock()
            .map_err(|_| "PUBLIC_MUTATION_CPU_UNAVAILABLE")?;
        let now = Instant::now();
        sample_locked(
            &mut self.stamp,
            &mut self.clock_failed,
            &mut self.billed_ns,
            &mut self.measurement_unknown,
            &mut budget,
            now,
        )?;
        Ok(AdmissionCpuAccount {
            account: &self.budget,
            budget,
            stamp: &mut self.stamp,
            now,
        })
    }
    pub(in crate::ingress::public_v3) fn clock_failed(&self) -> bool {
        self.clock_failed
    }
}
impl Drop for AdmissionWaitCpu<'_> {
    fn drop(&mut self) {
        if self.stamp.is_some() {
            // Poison remains poison: retain any known final debit and fence work.
            let account = self.budget.clone();
            let mut budget = match account.lock() {
                Ok(budget) => budget,
                Err(error) => {
                    let mut budget = error.into_inner();
                    budget.unavailable = true;
                    budget
                }
            };
            let _ = sample_locked(
                &mut self.stamp,
                &mut self.clock_failed,
                &mut self.billed_ns,
                &mut self.measurement_unknown,
                &mut budget,
                Instant::now(),
            );
            self.stamp = None;
        }
        // Release the CPU-account lock before publishing listener-local telemetry.
        // A successful handoff samples nothing here: publication CPU belongs to
        // the paid owner interval beginning at that same transferred baseline.
        if let Some(metrics) = self.metrics {
            if let Ok(mut metrics) = metrics.lock() {
                let mut unknown = self.measurement_unknown;
                match metrics
                    .mutation_cpu_admission_wait_ns
                    .checked_add(self.billed_ns)
                {
                    Some(total) => metrics.mutation_cpu_admission_wait_ns = total,
                    None => unknown = true,
                }
                match metrics
                    .mutation_cpu_admission_wait_observations
                    .checked_add(1)
                {
                    Some(total) => metrics.mutation_cpu_admission_wait_observations = total,
                    None => unknown = true,
                }
                if self.covered {
                    match metrics
                        .mutation_cpu_admission_wait_covered_observations
                        .checked_add(1)
                    {
                        Some(total) => {
                            metrics.mutation_cpu_admission_wait_covered_observations = total
                        }
                        None => unknown = true,
                    }
                }
                if unknown {
                    metrics.mutation_cpu_admission_wait_unknown = metrics
                        .mutation_cpu_admission_wait_unknown
                        .saturating_add(1);
                }
            }
        }
    }
}

#[cfg(test)]
#[path = "cpu_start_billing_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "cpu_billing_scope_tests.rs"]
mod scope_tests;
