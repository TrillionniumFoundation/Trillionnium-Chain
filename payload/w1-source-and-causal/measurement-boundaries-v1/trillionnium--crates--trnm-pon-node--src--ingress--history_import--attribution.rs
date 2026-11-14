//! Bounded optional diagnostics for the original History owner and CPU wait.
//! No reservation, refill, Host decision, deadline or native result is changed.
use super::public_v3::request_observation::ThreadCpuStamp;
use crate::Result;
use serde::Serialize;
use std::{
    sync::{
        atomic::{AtomicU64, Ordering},
        Mutex,
    },
    time::{Duration, Instant},
};

// A page can reserve once for decode and once for empty-page activation;
// each packet reserves once. Reuse/overflow loses telemetry, never native work.
const MAX_CPU_WAITS: usize = 2;

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoryEpochSubstep {
    DomainLookup,
    DurableBegin,
}

#[derive(Clone, Copy, Debug, Serialize)]
pub struct HistoryNativeSpan {
    pub started_ns: Option<u64>,
    pub ended_ns: Option<u64>,
    pub wall_ns: Option<u64>,
    pub thread_cpu_ns: Option<u64>,
    pub completed: bool,
    pub accepted: Option<bool>,
    pub error_code: Option<&'static str>,
    pub unwound: bool,
}

#[derive(Clone, Copy, Debug, Serialize)]
pub struct HistoryEpochSubstepObservation {
    pub substep: HistoryEpochSubstep,
    pub span: HistoryNativeSpan,
}

#[derive(Clone, Copy, Debug, Serialize)]
pub struct HistoryCpuWaitObservation {
    pub span: HistoryNativeSpan,
    pub original_deadline_remaining_at_entry_ns: Option<u64>,
    pub original_deadline_remaining_at_exit_ns: Option<u64>,
    pub local_wait_ceiling_remaining_at_entry_ns: Option<u64>,
    pub last_reserve_deadline_remaining_ns: Option<u64>,
    pub last_sleep_deadline_remaining_ns: Option<u64>,
    pub reserve_attempts: u64,
    pub reserve_returns: u64,
    pub reserve_granted: u64,
    pub reserve_budget_refusals: u64,
    pub reserve_other_refusals: u64,
    pub sleep_calls_started: u64,
    pub sleep_calls_completed: u64,
    /// Absent until a real sleep is requested; unknown overflow stays absent.
    pub requested_sleep_ns: Option<u64>,
    /// Wall time surrounding the actual sleep, including scheduler overshoot.
    /// This is not a CPU-refill attribution or a scheduler-cause claim.
    pub actual_sleep_wall_ns: Option<u64>,
}

#[derive(Clone, Debug, Serialize)]
pub struct HistoryNativeAttributionSnapshot {
    pub schema: &'static str,
    pub owner_mode: Option<&'static str>,
    pub epoch_substeps: Vec<HistoryEpochSubstepObservation>,
    pub cpu_waits: Vec<HistoryCpuWaitObservation>,
    pub cpu_wait_capacity: usize,
    pub intervals_are_nested_not_additive: bool,
    pub observation_has_consensus_authority: bool,
    pub scope: &'static str,
}

#[derive(Default)]
struct Slots {
    owner_mode: Option<&'static str>,
    epoch: [Option<HistoryEpochSubstepObservation>; 2],
    waits: [Option<HistoryCpuWaitObservation>; MAX_CPU_WAITS],
}

pub(super) struct NativeAttribution {
    epoch: Instant,
    slots: Mutex<Slots>,
    failures: AtomicU64,
}
impl NativeAttribution {
    pub(super) fn new(epoch: Instant) -> Self {
        Self {
            epoch,
            slots: Mutex::new(Slots::default()),
            failures: AtomicU64::new(0),
        }
    }
    fn fail(&self) {
        let _ = self
            .failures
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                Some(n.saturating_add(1))
            });
    }
    pub(super) fn owner(&self, mode: &'static str) {
        if let Ok(mut slots) = self.slots.try_lock() {
            match slots.owner_mode {
                Some(existing) if existing != mode => self.fail(),
                _ => slots.owner_mode = Some(mode),
            }
        } else {
            self.fail();
        }
    }
    pub(super) fn snapshot(&self) -> (Option<HistoryNativeAttributionSnapshot>, u64) {
        let result = match self.slots.try_lock() {
            Ok(slots) => {
                let entered = slots.owner_mode.is_some()
                    || slots.epoch.iter().any(Option::is_some)
                    || slots.waits.iter().any(Option::is_some);
                entered.then(|| HistoryNativeAttributionSnapshot {
                    schema: "pon-local-history-native-attribution-v1",
                    owner_mode: slots.owner_mode,
                    epoch_substeps: slots.epoch.iter().flatten().copied().collect(),
                    cpu_waits: slots.waits.iter().flatten().copied().collect(),
                    cpu_wait_capacity: MAX_CPU_WAITS,
                    intervals_are_nested_not_additive: true,
                    observation_has_consensus_authority: false,
                    scope: "optional same-observer epoch; original domain lookup/durable begin nested in epoch-open; actual reserve calls and sleeps nested in CPU-wait; calling-thread CPU only; no budget-cause inference; live snapshots may be unfinished",
                })
            }
            Err(_) => {
                self.fail();
                None
            }
        };
        (result, self.failures.load(Ordering::Acquire))
    }
}

fn ns(duration: Duration) -> Option<u64> {
    u64::try_from(duration.as_nanos()).ok()
}
fn offset(now: Instant, epoch: Instant) -> Option<u64> {
    now.checked_duration_since(epoch).and_then(ns)
}
fn remaining(deadline: Instant, now: Instant) -> Option<u64> {
    ns(deadline.saturating_duration_since(now))
}

struct Span {
    start: Instant,
    cpu: Option<ThreadCpuStamp>,
    value: HistoryNativeSpan,
}
impl Span {
    fn start(epoch: Instant) -> Self {
        let start = Instant::now();
        Self {
            start,
            cpu: ThreadCpuStamp::start(),
            value: HistoryNativeSpan {
                started_ns: offset(start, epoch),
                ended_ns: None,
                wall_ns: None,
                thread_cpu_ns: None,
                completed: false,
                accepted: None,
                error_code: None,
                unwound: false,
            },
        }
    }
    fn returned<T>(&mut self, result: &Result<T>) {
        self.value.completed = true;
        self.value.accepted = Some(result.is_ok());
        self.value.error_code = result
            .as_ref()
            .err()
            .and_then(crate::Error::code)
            .map(crate::ErrorCode::as_str);
    }
    fn end(&mut self, epoch: Instant) -> Instant {
        let end = Instant::now();
        self.value.ended_ns = offset(end, epoch);
        self.value.wall_ns = offset(end, self.start);
        self.value.thread_cpu_ns = self.cpu.take().and_then(ThreadCpuStamp::finish);
        self.value.unwound = !self.value.completed;
        end
    }
}

struct EpochGuard<'a> {
    recorder: &'a NativeAttribution,
    substep: HistoryEpochSubstep,
    span: Span,
    recorded: bool,
}
impl Drop for EpochGuard<'_> {
    fn drop(&mut self) {
        self.span.end(self.recorder.epoch);
        if self.recorded {
            if let Ok(mut slots) = self.recorder.slots.try_lock() {
                slots.epoch[self.substep as usize] = Some(HistoryEpochSubstepObservation {
                    substep: self.substep,
                    span: self.span.value,
                });
            } else {
                self.recorder.fail();
            }
        }
    }
}
pub(super) fn observe_epoch<T>(
    recorder: Option<&NativeAttribution>,
    substep: HistoryEpochSubstep,
    action: impl FnOnce() -> Result<T>,
) -> Result<T> {
    let Some(recorder) = recorder else {
        return action();
    };
    let span = Span::start(recorder.epoch);
    let recorded = if let Ok(mut slots) = recorder.slots.try_lock() {
        let row = &mut slots.epoch[substep as usize];
        if row.is_none() {
            *row = Some(HistoryEpochSubstepObservation {
                substep,
                span: span.value,
            });
            true
        } else {
            recorder.fail();
            false
        }
    } else {
        recorder.fail();
        false
    };
    let mut guard = EpochGuard {
        recorder,
        substep,
        span,
        recorded,
    };
    let result = action();
    guard.span.returned(&result);
    result
}

pub(super) struct CpuWaitGuard<'a> {
    recorder: &'a NativeAttribution,
    slot: Option<usize>,
    deadline: Instant,
    span: Span,
    value: HistoryCpuWaitObservation,
}
impl<'a> CpuWaitGuard<'a> {
    pub(super) fn new(
        recorder: &'a NativeAttribution,
        deadline: Instant,
        wait_end: Instant,
    ) -> Self {
        let span = Span::start(recorder.epoch);
        let value = HistoryCpuWaitObservation {
            span: span.value,
            original_deadline_remaining_at_entry_ns: remaining(deadline, span.start),
            original_deadline_remaining_at_exit_ns: None,
            local_wait_ceiling_remaining_at_entry_ns: remaining(wait_end, span.start),
            last_reserve_deadline_remaining_ns: None,
            last_sleep_deadline_remaining_ns: None,
            reserve_attempts: 0,
            reserve_returns: 0,
            reserve_granted: 0,
            reserve_budget_refusals: 0,
            reserve_other_refusals: 0,
            sleep_calls_started: 0,
            sleep_calls_completed: 0,
            requested_sleep_ns: None,
            actual_sleep_wall_ns: None,
        };
        let slot = if let Ok(mut slots) = recorder.slots.try_lock() {
            slots
                .waits
                .iter()
                .position(Option::is_none)
                .inspect(|&index| {
                    slots.waits[index] = Some(value);
                })
        } else {
            None
        };
        if slot.is_none() {
            recorder.fail();
        }
        Self {
            recorder,
            slot,
            deadline,
            span,
            value,
        }
    }
    pub(super) fn reserve_started(&mut self) {
        self.value.reserve_attempts = self.value.reserve_attempts.saturating_add(1);
        self.value.last_reserve_deadline_remaining_ns = remaining(self.deadline, Instant::now());
    }
    pub(super) fn reserve_returned<T>(&mut self, result: &Result<T>) {
        self.value.reserve_returns = self.value.reserve_returns.saturating_add(1);
        match result {
            Ok(_) => self.value.reserve_granted += 1,
            Err(error) if error.is(crate::ErrorCode::PublicMutationCpuBudget) => {
                self.value.reserve_budget_refusals += 1;
            }
            Err(_) => self.value.reserve_other_refusals += 1,
        }
    }
    pub(super) fn sleep_started(&mut self, duration: Duration) -> Instant {
        let start = Instant::now();
        self.value.sleep_calls_started += 1;
        self.value.last_sleep_deadline_remaining_ns = remaining(self.deadline, start);
        self.value.requested_sleep_ns = if self.value.sleep_calls_started == 1 {
            ns(duration)
        } else {
            self.value
                .requested_sleep_ns
                .zip(ns(duration))
                .and_then(|(a, b)| a.checked_add(b))
        };
        start
    }
    pub(super) fn sleep_completed(&mut self, start: Instant) {
        let sample = offset(Instant::now(), start);
        self.value.sleep_calls_completed += 1;
        self.value.actual_sleep_wall_ns = if self.value.sleep_calls_completed == 1 {
            sample
        } else {
            self.value
                .actual_sleep_wall_ns
                .zip(sample)
                .and_then(|(a, b)| a.checked_add(b))
        };
    }
    pub(super) fn finish<T>(mut self, result: &Result<T>) {
        self.span.returned(result);
    }
}
impl Drop for CpuWaitGuard<'_> {
    fn drop(&mut self) {
        let end = self.span.end(self.recorder.epoch);
        self.value.span = self.span.value;
        self.value.original_deadline_remaining_at_exit_ns = remaining(self.deadline, end);
        if let Some(index) = self.slot {
            if let Ok(mut slots) = self.recorder.slots.try_lock() {
                slots.waits[index] = Some(self.value);
            } else {
                self.recorder.fail();
            }
        }
    }
}

#[cfg(test)]
mod tests;
