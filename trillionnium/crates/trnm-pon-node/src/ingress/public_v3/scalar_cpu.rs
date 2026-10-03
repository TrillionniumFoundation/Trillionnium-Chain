//! Shared original r9 scalar CPU accounting. A clone is the same volatile epoch.
//! Metering is separate from task/packet authority; Native outcomes remain intact.
use super::request_observation::ThreadCpuStamp;
use crate::{ensure, Result};
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex,
    },
    thread,
    time::Instant,
};
use trnm_mvcc_fee::pon_executor::{ExecutionWorkerAccounting, ExecutionWorkerInterval};

// Local receiver policy, independent of the caller's ticket-search algorithm.
pub(super) const MUTATION_CPU_BURST_NS: u64 = 2_000_000_000;
pub(super) const MUTATION_CPU_REFILL_NS_PER_SECOND: u64 = 250_000_000;
pub(super) const MUTATION_CPU_START_RESERVE_NS: u64 = 100_000_000;
pub(super) const MUTATION_CPU_WORKERS: usize = 2;

/// Volatile service-epoch accounting, never ledger or caller identity authority.
pub(super) struct PaidMutationCpuBudget {
    pub(super) credit_ns: i128,
    pub(super) updated: Instant,
    pub(super) in_flight: usize,
    pub(super) unavailable: bool,
}
impl PaidMutationCpuBudget {
    pub(super) fn new() -> Self {
        Self {
            credit_ns: i128::from(MUTATION_CPU_BURST_NS),
            updated: Instant::now(),
            in_flight: 0,
            unavailable: false,
        }
    }
    pub(super) fn refill(&mut self, now: Instant) {
        let elapsed = now.saturating_duration_since(self.updated).as_nanos();
        self.updated = now;
        let Some(credit) = elapsed
            .checked_mul(u128::from(MUTATION_CPU_REFILL_NS_PER_SECOND))
            .map(|n| n / 1_000_000_000)
            .and_then(|n| i128::try_from(n).ok())
            .and_then(|n| self.credit_ns.checked_add(n))
        else {
            self.unavailable = true;
            return;
        };
        // Refill cannot mint a second burst on top of outstanding start reserves.
        self.credit_ns = credit.min(self.credit_ceiling());
    }
    pub(super) fn credit_ceiling(&self) -> i128 {
        i128::from(MUTATION_CPU_BURST_NS)
            - (self.in_flight as i128) * i128::from(MUTATION_CPU_START_RESERVE_NS)
    }
    pub(super) fn reserve(&mut self, now: Instant) -> Result<()> {
        self.refill(now);
        ensure(!self.unavailable, "PUBLIC_MUTATION_CPU_UNAVAILABLE")?;
        ensure(
            self.in_flight < MUTATION_CPU_WORKERS
                && self.credit_ns >= i128::from(MUTATION_CPU_START_RESERVE_NS),
            "PUBLIC_MUTATION_CPU_BUDGET",
        )?;
        self.credit_ns -= i128::from(MUTATION_CPU_START_RESERVE_NS);
        self.in_flight += 1;
        Ok(())
    }
    pub(super) fn settle(&mut self, now: Instant, measured: Option<u64>) {
        self.refill(now);
        self.in_flight = self.in_flight.saturating_sub(1);
        if let Some(measured) = measured {
            match self
                .credit_ns
                .checked_add(i128::from(MUTATION_CPU_START_RESERVE_NS) - i128::from(measured))
            {
                Some(credit) => self.credit_ns = credit.min(self.credit_ceiling()),
                None => self.unavailable = true,
            }
        } else {
            // No fabricated zero or refund when actual accounting is unavailable.
            self.unavailable = true;
        }
    }
    /// Charge a known newly observed interval immediately. The start reserve
    /// remains outstanding until settlement; it is not charged a second time.
    pub(super) fn charge_live(&mut self, now: Instant, measured: u64) -> Result<()> {
        self.refill(now);
        let Some(credit) = self.credit_ns.checked_sub(i128::from(measured)) else {
            self.unavailable = true;
            return Err("PUBLIC_MUTATION_CPU_UNAVAILABLE".into());
        };
        self.credit_ns = credit;
        ensure(!self.unavailable, "PUBLIC_MUTATION_CPU_UNAVAILABLE")?;
        ensure(self.credit_ns >= 0, "PUBLIC_MUTATION_CPU_BUDGET")
    }
}
/// Only this request's live thread baselines. No State, packet, identity or
/// progress authority is cached. Locks are released before any native work.
pub(super) struct LiveRequestCpu {
    pub(super) budget: Arc<Mutex<PaidMutationCpuBudget>>,
    pub(super) state: Mutex<LiveRequestCpuState>,
    #[cfg(test)]
    pub(super) fail_next_sample: AtomicBool,
}
pub(super) struct LiveRequestCpuState {
    pub(super) threads: HashMap<thread::ThreadId, ThreadCpuStamp>,
    pub(super) charged_ns: u64,
    pub(super) refused: bool,
    pub(super) unavailable: bool,
}
impl LiveRequestCpu {
    pub(super) fn new(budget: Arc<Mutex<PaidMutationCpuBudget>>, owner: ThreadCpuStamp) -> Self {
        Self {
            budget,
            state: Mutex::new(LiveRequestCpuState {
                threads: [(thread::current().id(), owner)].into_iter().collect(),
                charged_ns: 0,
                refused: false,
                unavailable: false,
            }),
            #[cfg(test)]
            fail_next_sample: AtomicBool::new(false),
        }
    }
    pub(super) fn unknown(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.unavailable = true;
        }
        if let Ok(mut budget) = self.budget.lock() {
            budget.unavailable = true;
        }
    }
    pub(super) fn register_worker(&self, stamp: Option<ThreadCpuStamp>) {
        let Some(stamp) = stamp else {
            self.unknown();
            return;
        };
        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(error) => {
                drop(error);
                self.unknown();
                return;
            }
        };
        let id = thread::current().id();
        if state.threads.contains_key(&id) {
            drop(state);
            self.unknown();
            return;
        }
        state.threads.insert(id, stamp);
    }
    pub(super) fn observe(&self, remove: bool, enforce: bool) -> Result<()> {
        // All two-lock paths use request -> global. Neither is held across a
        // Work replay, envelope, State/root calculation, join or SQL call.
        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(error) => {
                // A PoisonError owns the failed lock guard; release it before
                // marking request/global accounting unavailable.
                drop(error);
                self.unknown();
                return Err("PUBLIC_MUTATION_CPU_UNAVAILABLE".into());
            }
        };
        let id = thread::current().id();
        let measured = state
            .threads
            .get_mut(&id)
            .and_then(ThreadCpuStamp::checkpoint);
        #[cfg(test)]
        let measured = if self.fail_next_sample.swap(false, Ordering::AcqRel) {
            None
        } else {
            measured
        };
        if remove {
            state.threads.remove(&id);
        }
        let Some(measured) = measured else {
            drop(state);
            self.unknown();
            return Err("PUBLIC_MUTATION_CPU_UNAVAILABLE".into());
        };
        let Some(total) = state.charged_ns.checked_add(measured) else {
            drop(state);
            self.unknown();
            return Err("PUBLIC_MUTATION_CPU_UNAVAILABLE".into());
        };
        state.charged_ns = total;
        let result: Result<()> = (|| {
            let mut budget = self
                .budget
                .lock()
                .map_err(|_| "PUBLIC_MUTATION_CPU_UNAVAILABLE")?;
            budget.charge_live(Instant::now(), measured)
        })();
        if let Err(error) = &result {
            if error.to_string() == "PUBLIC_MUTATION_CPU_BUDGET" {
                state.refused |= enforce;
            } else {
                state.unavailable = true;
            }
        }
        let unavailable = state.unavailable;
        let refused = state.refused;
        drop(state);
        if unavailable {
            self.unknown();
            return Err("PUBLIC_MUTATION_CPU_UNAVAILABLE".into());
        }
        // Final samples still charge after cancellation/debt. They never
        // replace an already completed native outcome with a new refusal.
        if enforce {
            ensure(!refused, "PUBLIC_MUTATION_CPU_BUDGET")?;
        }
        Ok(())
    }
    pub(super) fn checkpoint(&self) -> Result<()> {
        self.observe(false, true)
    }
    pub(super) fn finish_thread(&self) {
        let _ = self.observe(true, false);
    }
    pub(super) fn complete(&self) -> Option<u64> {
        let state = match self.state.lock() {
            Ok(state) => state,
            Err(error) => {
                drop(error);
                self.unknown();
                return None;
            }
        };
        if state.unavailable || !state.threads.is_empty() {
            drop(state);
            self.unknown();
            None
        } else {
            Some(state.charged_ns)
        }
    }
    pub(super) fn was_refused(&self) -> bool {
        self.state.lock().is_ok_and(|state| state.refused)
    }
}
/// Scalar, request-local intervals. No State/Output/observer schema changes.
#[derive(Default)]
pub(super) struct ScopedWorkerCpu {
    pub(super) spawned: AtomicU64,
    pub(super) started: AtomicU64,
    pub(super) finished: AtomicU64,
    pub(super) known: AtomicU64,
    pub(super) total_ns: AtomicU64,
    pub(super) unavailable: AtomicBool,
    pub(super) budget: Option<Arc<Mutex<PaidMutationCpuBudget>>>,
    pub(super) live: Option<Arc<LiveRequestCpu>>,
    #[cfg(test)]
    pub(super) fail_next_start: AtomicBool,
    #[cfg(test)]
    pub(super) fail_next_finish: AtomicBool,
}
impl ScopedWorkerCpu {
    pub(super) fn checkpoint(&self) -> Result<()> {
        self.live.as_ref().map_or(Ok(()), |live| live.checkpoint())
    }
    pub(super) fn unknown(&self) {
        self.unavailable.store(true, Ordering::Release);
        if let Some(live) = &self.live {
            live.unknown();
        }
        // A failed worker clock prevents another request start immediately;
        // it does not replace this request's already completed native outcome.
        if let Some(budget) = &self.budget {
            if let Ok(mut budget) = budget.lock() {
                budget.unavailable = true;
            }
        }
    }
    pub(super) fn add(&self, cell: &AtomicU64, value: u64) {
        if cell
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |old| {
                old.checked_add(value)
            })
            .is_err()
        {
            self.unknown();
        }
    }
    // The caller invokes this only after every actual scoped handle was joined.
    pub(super) fn complete(&self) -> Option<u64> {
        let spawned = self.spawned.load(Ordering::Acquire);
        let total = self.total_ns.load(Ordering::Acquire);
        if self.unavailable.load(Ordering::Acquire)
            || spawned != self.started.load(Ordering::Acquire)
            || spawned != self.finished.load(Ordering::Acquire)
            || spawned != self.known.load(Ordering::Acquire)
            || (spawned == 0 && total != 0)
        {
            self.unknown();
            None
        } else {
            Some(total)
        }
    }
}
pub(super) struct ScopedWorkerInterval<'a> {
    pub(super) collector: &'a ScopedWorkerCpu,
    pub(super) stamp: Option<ThreadCpuStamp>,
}
impl ExecutionWorkerInterval for ScopedWorkerInterval<'_> {}
impl Drop for ScopedWorkerInterval<'_> {
    fn drop(&mut self) {
        if let Some(live) = &self.collector.live {
            live.finish_thread();
        }
        let measured = self.stamp.take().and_then(ThreadCpuStamp::finish);
        #[cfg(test)]
        let measured = if self
            .collector
            .fail_next_finish
            .swap(false, Ordering::AcqRel)
        {
            None
        } else {
            measured
        };
        self.collector.add(&self.collector.finished, 1);
        if let Some(cpu) = measured {
            self.collector.add(&self.collector.total_ns, cpu);
            self.collector.add(&self.collector.known, 1);
        } else {
            self.collector.unknown();
        }
    }
}
impl ExecutionWorkerAccounting for ScopedWorkerCpu {
    fn worker_started(&self) -> Option<Box<dyn ExecutionWorkerInterval + '_>> {
        let stamp = ThreadCpuStamp::start();
        #[cfg(test)]
        let stamp = if self.fail_next_start.swap(false, Ordering::AcqRel) {
            None
        } else {
            stamp
        };
        self.add(&self.started, 1);
        if let Some(live) = &self.live {
            live.register_worker(stamp.clone());
        }
        if stamp.is_none() {
            self.unknown();
        }
        Some(Box::new(ScopedWorkerInterval {
            collector: self,
            stamp,
        }))
    }
    fn worker_spawn_succeeded(&self) {
        self.add(&self.spawned, 1);
    }
}
/// A clone shares the existing volatile service epoch; cloning never refills or
/// changes capacity. This metering handle is not a Native or task permission.
#[derive(Clone)]
pub struct ServiceMutationCpuDomain {
    budget: Arc<Mutex<PaidMutationCpuBudget>>,
}
impl ServiceMutationCpuDomain {
    pub(super) fn from_shared(budget: Arc<Mutex<PaidMutationCpuBudget>>) -> Self {
        Self { budget }
    }
    /// Explicit standalone local epoch for a trusted local caller. A serving
    /// miner must instead clone PublicServer::mutation_cpu_domain().
    pub fn standalone() -> Self {
        Self {
            budget: Arc::new(Mutex::new(PaidMutationCpuBudget::new())),
        }
    }
    pub fn shares_domain_with(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.budget, &other.budget)
    }
    /// Begin on the actual owner thread, after separate task-purpose authority
    /// but before expensive Native work. No ledger authority is minted here.
    pub fn begin(&self) -> Result<ServiceMutationCpuOperation> {
        let stamp = ThreadCpuStamp::start();
        let mut budget = self
            .budget
            .lock()
            .map_err(|_| "PUBLIC_MUTATION_CPU_UNAVAILABLE")?;
        if stamp.is_none() {
            budget.unavailable = true;
        }
        budget.reserve(Instant::now())?;
        drop(budget);
        let owner = stamp
            .as_ref()
            .ok_or("PUBLIC_MUTATION_CPU_UNAVAILABLE")?
            .clone();
        let live = Arc::new(LiveRequestCpu::new(self.budget.clone(), owner));
        Ok(ServiceMutationCpuOperation {
            budget: self.budget.clone(),
            stamp,
            live: live.clone(),
            settled: false,
            workers: ScopedWorkerCpu {
                budget: Some(self.budget.clone()),
                live: Some(live),
                ..ScopedWorkerCpu::default()
            },
        })
    }
}

/// Request-local actual owner plus scoped-worker samples. Moving the operation
/// to a different owner thread produces unknown accounting, never CPU zero.
pub struct ServiceMutationCpuOperation {
    budget: Arc<Mutex<PaidMutationCpuBudget>>,
    stamp: Option<ThreadCpuStamp>,
    live: Arc<LiveRequestCpu>,
    workers: ScopedWorkerCpu,
    settled: bool,
}
#[derive(Debug, serde::Serialize)]
pub struct ServiceMutationCpuSettlement {
    pub schema: &'static str,
    pub owner_cpu_ns: Option<u64>,
    pub scoped_worker_cpu_ns: Option<u64>,
    pub total_cpu_ns: Option<u64>,
    pub live_paid_cpu_ns: Option<u64>,
    pub residual_cpu_ns: Option<u64>,
    pub spawned_workers: u64,
    pub started_workers: u64,
    pub finished_workers: u64,
    pub known_workers: u64,
    pub live_refused: bool,
    pub accounting_unavailable: bool,
}
impl ServiceMutationCpuOperation {
    pub fn checkpoint(&self) -> Result<()> {
        self.live.checkpoint()
    }
    pub fn worker_accounting(&self) -> &dyn ExecutionWorkerAccounting {
        &self.workers
    }
    /// Only after every actual scope has been joined. O includes Work; adding a
    /// separate W would charge it twice. Settlement never returns a Native error.
    pub fn finish(mut self) -> ServiceMutationCpuSettlement {
        self.live.finish_thread();
        let already_charged = self.live.complete();
        let outer = self.stamp.take().and_then(ThreadCpuStamp::finish);
        let children = self.workers.complete();
        let charged = outer
            .zip(children)
            .and_then(|(owner, workers)| owner.checked_add(workers));
        let residual = charged
            .zip(already_charged)
            .and_then(|(total, paid)| total.checked_sub(paid));
        let budget_settled = if let Ok(mut budget) = self.budget.lock() {
            budget.settle(Instant::now(), residual);
            true
        } else {
            false
        };
        self.settled = true;
        ServiceMutationCpuSettlement {
            schema: "service-owner-scoped-thread-cpu-settlement-v1",
            owner_cpu_ns: outer,
            scoped_worker_cpu_ns: children,
            total_cpu_ns: charged,
            live_paid_cpu_ns: already_charged,
            residual_cpu_ns: residual,
            spawned_workers: self.workers.spawned.load(Ordering::Acquire),
            started_workers: self.workers.started.load(Ordering::Acquire),
            finished_workers: self.workers.finished.load(Ordering::Acquire),
            known_workers: self.workers.known.load(Ordering::Acquire),
            live_refused: self.live.was_refused(),
            accounting_unavailable: residual.is_none() || !budget_settled,
        }
    }
}
impl Drop for ServiceMutationCpuOperation {
    fn drop(&mut self) {
        if !self.settled {
            self.live.finish_thread();
            if let Ok(mut budget) = self.budget.lock() {
                budget.settle(Instant::now(), None);
            }
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
#[path = "scalar_cpu_tests.rs"]
mod tests;

/// Same actual operation's live sampler, with no new budget or worker scope.
/// A worker can sample only after its original RAII accounting registration.
#[derive(Clone)]
pub struct ServiceMutationCpuCheckpoint {
    live: Arc<LiveRequestCpu>,
}
impl ServiceMutationCpuCheckpoint {
    pub fn checkpoint(&self) -> Result<()> {
        self.live.checkpoint()
    }
}
impl ServiceMutationCpuOperation {
    pub fn checkpoint_handle(&self) -> ServiceMutationCpuCheckpoint {
        ServiceMutationCpuCheckpoint {
            live: self.live.clone(),
        }
    }
}
impl ServiceMutationCpuDomain {
    /// This reads no balance and changes no credit. A failed begin can separate
    /// unknown/poisoned accounting from the existing known budget refusal.
    pub fn accounting_available(&self) -> bool {
        self.budget.lock().is_ok_and(|budget| !budget.unavailable)
    }
}
