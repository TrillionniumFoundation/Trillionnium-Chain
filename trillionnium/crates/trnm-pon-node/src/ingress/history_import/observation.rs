//! Optional local import measurements. No resource, proof or owner authority.
use crate::ingress::public_v3::{
    request_observation::{TaskObservation, ThreadCpuStamp},
    SubmitPhaseObservation,
};
use serde::Serialize;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Mutex,
};
use std::time::Instant;
use trnm_protocol::pon_wire::Hash;

pub const MAX_HISTORY_IMPORT_OBSERVATION_PACKETS: usize = 16;

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoryHostPhase {
    Resolve,
    Initial,
    Checkpoint,
    Final,
}

/// Fixed aggregate over actual calls, including rejected and unwound calls.
/// `Resolve` includes opening/checking the current fixed Host context. The
/// other slots each time the actual existing KernelBudget::verify invocation.
#[derive(Clone, Copy, Debug, Serialize)]
pub struct HistoryHostObservation {
    pub phase: HistoryHostPhase,
    pub calls_started: u64,
    pub calls_completed: u64,
    pub calls_accepted: u64,
    pub calls_rejected: u64,
    pub calls_unfinished: u64,
    pub first_started_ns: Option<u64>,
    pub last_ended_ns: Option<u64>,
    pub wall_ns: Option<u64>,
    pub thread_cpu_ns: Option<u64>,
    pub wall_clock_unknown_calls: u64,
    pub cpu_clock_unknown_calls: u64,
    pub last_error_code: Option<&'static str>,
}
impl HistoryHostObservation {
    fn new(phase: HistoryHostPhase) -> Self {
        Self {
            phase,
            calls_started: 0,
            calls_completed: 0,
            calls_accepted: 0,
            calls_rejected: 0,
            calls_unfinished: 0,
            first_started_ns: None,
            last_ended_ns: None,
            wall_ns: None,
            thread_cpu_ns: None,
            wall_clock_unknown_calls: 0,
            cpu_clock_unknown_calls: 0,
            last_error_code: None,
        }
    }
}

fn host_slots() -> [HistoryHostObservation; 4] {
    [
        HistoryHostPhase::Resolve,
        HistoryHostPhase::Initial,
        HistoryHostPhase::Checkpoint,
        HistoryHostPhase::Final,
    ]
    .map(HistoryHostObservation::new)
}

#[derive(Clone, Copy, Default)]
struct Context {
    entered: bool,
    tip: Option<Hash>,
    after: Option<Hash>,
    supplied_packets: Option<usize>,
    packet_ids: [Option<Hash>; MAX_HISTORY_IMPORT_OBSERVATION_PACKETS],
}

/// One explicitly observed invocation of the existing importer. Reusing the
/// recorder marks measurement failure; it cannot reset the request deadline,
/// CPU account or a prior failure. Construct another observer for another page.
pub struct HistoryImportObserver {
    epoch: Instant,
    page: TaskObservation,
    packets: [TaskObservation; MAX_HISTORY_IMPORT_OBSERVATION_PACKETS],
    context: Mutex<Context>,
    failures: AtomicU64,
    host: Mutex<[HistoryHostObservation; 4]>,
}

#[derive(Clone, Debug, Serialize)]
pub struct HistoryPacketObservation {
    pub packet_index: usize,
    pub packet_id: Option<Hash>,
    pub phases: [SubmitPhaseObservation; 19],
}

#[derive(Clone, Debug, Serialize)]
pub struct HistoryImportObservationSnapshot {
    pub schema: &'static str,
    pub tip: Option<Hash>,
    pub after: Option<Hash>,
    pub supplied_packets: Option<usize>,
    pub packet_capacity: usize,
    pub phases: [SubmitPhaseObservation; 19],
    pub packets: Vec<HistoryPacketObservation>,
    pub measurement_failures: u64,
    pub host_checks: [HistoryHostObservation; 4],
    pub host_checks_are_nested_not_additive: bool,
    pub cpu_intervals_are_nested_not_additive: bool,
    pub phase_cpu_excludes_scoped_workers: bool,
    pub host_cpu_includes_each_calling_thread: bool,
    pub host_cpu_is_full_worker_cpu: bool,
    pub observation_has_consensus_authority: bool,
    pub clock_scope: &'static str,
}

impl Default for HistoryImportObserver {
    fn default() -> Self {
        Self::new()
    }
}
impl HistoryImportObserver {
    pub fn new() -> Self {
        let epoch = Instant::now();
        Self {
            epoch,
            page: TaskObservation::local(epoch),
            packets: std::array::from_fn(|_| TaskObservation::local(epoch)),
            context: Mutex::new(Context::default()),
            failures: AtomicU64::new(0),
            host: Mutex::new(host_slots()),
        }
    }
    fn fail(&self) {
        let _ = self
            .failures
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                Some(n.saturating_add(1))
            });
    }
    pub(super) fn enter(&self, tip: Hash, after: Hash, packets: usize) {
        match self.context.try_lock() {
            Ok(mut context) if !context.entered => {
                context.entered = true;
                context.tip = Some(tip);
                context.after = Some(after);
                context.supplied_packets = Some(packets);
            }
            _ => self.fail(),
        }
    }
    pub(super) fn page(&self) -> &TaskObservation {
        &self.page
    }
    pub(super) fn decoded_packet(&self, index: usize, id: Hash) {
        match self.context.try_lock() {
            Ok(mut context) if index < context.packet_ids.len() => {
                if context.packet_ids[index].is_some() {
                    self.fail();
                } else {
                    context.packet_ids[index] = Some(id);
                }
            }
            _ => self.fail(),
        }
    }
    pub(super) fn packet(&self, index: usize) -> Option<&TaskObservation> {
        let packet = self.packets.get(index);
        if packet.is_none() {
            self.fail();
        }
        packet
    }
    /// Snapshot after the synchronous import returned/unwound. A live snapshot
    /// can contain unfinished spans and does not establish service completion.
    pub fn snapshot(&self) -> HistoryImportObservationSnapshot {
        let host_checks = match self.host.lock() {
            Ok(host) => *host,
            Err(_) => {
                self.fail();
                host_slots()
            }
        };
        let context = match self.context.lock() {
            Ok(context) => *context,
            Err(_) => {
                self.fail();
                Context::default()
            }
        };
        let (phases, phase_failures) = self.page.phase_snapshot();
        let mut failures = self
            .failures
            .load(Ordering::Acquire)
            .saturating_add(phase_failures);
        let packets = self
            .packets
            .iter()
            .enumerate()
            .filter_map(|(index, packet)| {
                let (phases, phase_failures) = packet.phase_snapshot();
                failures = failures.saturating_add(phase_failures);
                (context.packet_ids[index].is_some() || phases.iter().any(|phase| phase.started))
                    .then_some(HistoryPacketObservation {
                        packet_index: index,
                        packet_id: context.packet_ids[index],
                        phases,
                    })
            })
            .collect();
        HistoryImportObservationSnapshot {
            schema: "pon-local-history-import-observation-v1",
            tip: context.tip,
            after: context.after,
            supplied_packets: context.supplied_packets,
            packet_capacity: MAX_HISTORY_IMPORT_OBSERVATION_PACKETS,
            phases,
            packets,
            measurement_failures: failures,
            host_checks,
            host_checks_are_nested_not_additive: true,
            cpu_intervals_are_nested_not_additive: true,
            phase_cpu_excludes_scoped_workers: true,
            host_cpu_includes_each_calling_thread: true,
            host_cpu_is_full_worker_cpu: false,
            observation_has_consensus_authority: false,
            clock_scope: "one observer-local monotonic epoch; page import includes packet and checkpoint Host spans; phase CPU is importer thread only; Host CPU sums each actual invoking thread's Host intervals, not complete worker CPU; resolve/initial/final Host spans are outside native import but inside client replay; network fetch is outside client replay",
        }
    }
}

fn add_sample(total: Option<u64>, sample: Option<u64>, first: bool) -> Option<u64> {
    if first {
        sample
    } else {
        total
            .zip(sample)
            .and_then(|(sum, next)| sum.checked_add(next))
    }
}

struct HostGuard<'a> {
    observer: &'a HistoryImportObserver,
    phase: HistoryHostPhase,
    start: Instant,
    cpu: Option<ThreadCpuStamp>,
    accepted: Option<bool>,
    error_code: Option<&'static str>,
    recorded: bool,
}
impl<'a> HostGuard<'a> {
    fn new(observer: &'a HistoryImportObserver, phase: HistoryHostPhase) -> Self {
        let start = Instant::now();
        let offset = start
            .checked_duration_since(observer.epoch)
            .and_then(|elapsed| u64::try_from(elapsed.as_nanos()).ok());
        let mut recorded = false;
        if let Ok(mut host) = observer.host.try_lock() {
            let row = &mut host[phase as usize];
            if let Some(count) = row.calls_started.checked_add(1) {
                row.first_started_ns = if count == 1 {
                    offset
                } else {
                    row.first_started_ns
                        .zip(offset)
                        .map(|(before, now)| before.min(now))
                };
                row.calls_started = count;
                recorded = true;
            } else {
                observer.fail();
            }
        } else {
            observer.fail();
        }
        Self {
            observer,
            phase,
            start,
            cpu: ThreadCpuStamp::start(),
            accepted: None,
            error_code: None,
            recorded,
        }
    }
    fn finish<T>(mut self, result: &crate::Result<T>) {
        self.accepted = Some(result.is_ok());
        self.error_code = result
            .as_ref()
            .err()
            .and_then(crate::Error::code)
            .map(crate::ErrorCode::as_str);
    }
}
impl Drop for HostGuard<'_> {
    fn drop(&mut self) {
        if !self.recorded {
            return;
        }
        let end = Instant::now();
        let ended = end
            .checked_duration_since(self.observer.epoch)
            .and_then(|elapsed| u64::try_from(elapsed.as_nanos()).ok());
        let wall = end
            .checked_duration_since(self.start)
            .and_then(|elapsed| u64::try_from(elapsed.as_nanos()).ok());
        let cpu = self.cpu.take().and_then(ThreadCpuStamp::finish);
        if let Ok(mut host) = self.observer.host.try_lock() {
            let row = &mut host[self.phase as usize];
            let first = row.calls_completed == 0 && row.calls_unfinished == 0;
            row.wall_ns = add_sample(row.wall_ns, wall, first);
            row.thread_cpu_ns = add_sample(row.thread_cpu_ns, cpu, first);
            row.last_ended_ns = if first {
                ended
            } else {
                row.last_ended_ns
                    .zip(ended)
                    .map(|(before, now)| before.max(now))
            };
            row.wall_clock_unknown_calls = row
                .wall_clock_unknown_calls
                .saturating_add(u64::from(wall.is_none()));
            row.cpu_clock_unknown_calls = row
                .cpu_clock_unknown_calls
                .saturating_add(u64::from(cpu.is_none()));
            match self.accepted {
                Some(accepted) => {
                    row.calls_completed = row.calls_completed.saturating_add(1);
                    if accepted {
                        row.calls_accepted = row.calls_accepted.saturating_add(1);
                    } else {
                        row.calls_rejected = row.calls_rejected.saturating_add(1);
                        row.last_error_code = self.error_code;
                    }
                }
                None => {
                    row.calls_unfinished = row.calls_unfinished.saturating_add(1);
                }
            }
            if wall.is_some() && row.wall_ns.is_none() && row.wall_clock_unknown_calls == 0 {
                self.observer.fail(); // Aggregate overflow cannot look like zero work.
            }
            if cpu.is_some() && row.thread_cpu_ns.is_none() && row.cpu_clock_unknown_calls == 0 {
                self.observer.fail();
            }
        } else {
            self.observer.fail();
        }
    }
}

pub(in crate::ingress) fn observe_host<T>(
    observer: Option<&HistoryImportObserver>,
    phase: HistoryHostPhase,
    action: impl FnOnce() -> crate::Result<T>,
) -> crate::Result<T> {
    let guard = observer.map(|observer| HostGuard::new(observer, phase));
    let result = action();
    if let Some(guard) = guard {
        guard.finish(&result);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    #[test]
    fn host_aggregate_retains_returns_unwind_and_unentered_unknowns() {
        let observer = HistoryImportObserver::new();
        let calls = AtomicUsize::new(0);
        observe_host(Some(&observer), HistoryHostPhase::Checkpoint, || {
            calls.fetch_add(1, Ordering::Relaxed);
            Ok(())
        })
        .unwrap();
        let refused = observe_host(Some(&observer), HistoryHostPhase::Checkpoint, || {
            calls.fetch_add(1, Ordering::Relaxed);
            Err::<(), _>("PUBLIC_REQUEST_CANCELLED".into())
        });
        assert!(refused
            .unwrap_err()
            .is(crate::ErrorCode::PublicRequestCancelled));
        let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _: crate::Result<()> =
                observe_host(Some(&observer), HistoryHostPhase::Checkpoint, || {
                    calls.fetch_add(1, Ordering::Relaxed);
                    panic!("diagnostic native call unwind");
                });
        }));
        assert!(panicked.is_err());
        let snapshot = observer.snapshot();
        let row = snapshot.host_checks[HistoryHostPhase::Checkpoint as usize];
        assert_eq!(calls.load(Ordering::Relaxed), 3);
        assert_eq!(
            (
                row.calls_started,
                row.calls_completed,
                row.calls_accepted,
                row.calls_rejected,
                row.calls_unfinished
            ),
            (3, 2, 1, 1, 1)
        );
        assert_eq!(row.last_error_code, Some("PUBLIC_REQUEST_CANCELLED"));
        assert!(row.wall_ns.is_some());
        assert!(row.last_ended_ns.unwrap() >= row.first_started_ns.unwrap());
        assert_eq!(snapshot.measurement_failures, 0);
        let absent = snapshot.host_checks[HistoryHostPhase::Final as usize];
        assert_eq!(absent.calls_started, 0);
        assert_eq!(absent.wall_ns, None);
        assert_eq!(absent.thread_cpu_ns, None);
    }

    #[test]
    fn host_capture_contention_never_changes_original_error_or_calls_action_twice() {
        let observer = HistoryImportObserver::new();
        let locked = observer.host.lock().unwrap();
        let calls = AtomicUsize::new(0);
        let result = observe_host(Some(&observer), HistoryHostPhase::Initial, || {
            calls.fetch_add(1, Ordering::Relaxed);
            Err::<(), _>("PUBLIC_REQUEST_DEADLINE".into())
        });
        drop(locked);
        assert!(result
            .unwrap_err()
            .is(crate::ErrorCode::PublicRequestDeadline));
        assert_eq!(calls.load(Ordering::Relaxed), 1);
        let snapshot = observer.snapshot();
        assert_eq!(snapshot.measurement_failures, 1);
        assert_eq!(
            snapshot.host_checks[HistoryHostPhase::Initial as usize].calls_started,
            0
        );
    }

    #[test]
    fn a_missing_host_cpu_sample_keeps_the_aggregate_unknown_after_known_returns() {
        let observer = HistoryImportObserver::new();
        let mut guard = HostGuard::new(&observer, HistoryHostPhase::Final);
        guard.cpu = None; // Exercise unavailable-clock accounting, not a zero sample.
        guard.finish(&Ok(()));
        observe_host(Some(&observer), HistoryHostPhase::Final, || Ok(())).unwrap();
        let row = observer.snapshot().host_checks[HistoryHostPhase::Final as usize];
        assert_eq!(row.calls_started, 2);
        assert_eq!(row.calls_completed, 2);
        assert!(row.cpu_clock_unknown_calls >= 1);
        assert_eq!(row.thread_cpu_ns, None);
        assert!(row.wall_ns.is_some());
    }
}
