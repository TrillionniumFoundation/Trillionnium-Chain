//! Optional local import measurements. No resource, proof or owner authority.
use crate::ingress::public_v3::{
    request_observation::{TaskObservation, ThreadCpuStamp},
    SubmitPhase, SubmitPhaseObservation,
};
use serde::Serialize;
use std::sync::{
    atomic::{AtomicU64, AtomicUsize, Ordering},
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

const HOST_PHASE_BUCKETS: usize = SubmitPhase::ALL.len() + 1;
const UNATTRIBUTED_HOST_PHASE: usize = HOST_PHASE_BUCKETS - 1;

struct HostRecords {
    phases: [HistoryHostObservation; 4],
    checkpoints: [HistoryHostObservation; HOST_PHASE_BUCKETS],
}
impl HostRecords {
    fn new() -> Self {
        Self {
            phases: host_slots(),
            checkpoints: [HistoryHostObservation::new(HistoryHostPhase::Checkpoint);
                HOST_PHASE_BUCKETS],
        }
    }
}

/// An exclusive classification of actual checkpoint CALLS by the already-open
/// native owner phase at call entry. Parallel worker calls inherit that owner
/// context; this does not claim their own phase CPU or a partition of runtime.
#[derive(Clone, Debug, Serialize)]
pub struct HistoryHostCheckpointPhase {
    pub owner_phase: Option<SubmitPhase>,
    pub calls: HistoryHostObservation,
}

#[derive(Clone, Debug, Serialize)]
pub struct HistoryHostCheckpointAttribution {
    pub schema: &'static str,
    pub buckets: [HistoryHostCheckpointPhase; HOST_PHASE_BUCKETS],
    pub all_checkpoint_calls_attributed: bool,
    pub has_consensus_authority: bool,
    pub scope: &'static str,
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
    active_packet: AtomicUsize,
    context: Mutex<Context>,
    failures: AtomicU64,
    host: Mutex<HostRecords>,
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
    pub host_checkpoint_attribution: HistoryHostCheckpointAttribution,
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
            active_packet: AtomicUsize::new(MAX_HISTORY_IMPORT_OBSERVATION_PACKETS),
            context: Mutex::new(Context::default()),
            failures: AtomicU64::new(0),
            host: Mutex::new(HostRecords::new()),
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
        if packet.is_some() {
            self.active_packet.store(index, Ordering::Release);
        } else {
            self.fail();
        }
        packet
    }

    fn checkpoint_phase(&self) -> usize {
        let observed = (|| {
            let index = self.active_packet.load(Ordering::Acquire);
            if let Some(packet) = self.packets.get(index) {
                if let Some(phase) = packet.active_phase()? {
                    return Ok(Some(phase));
                }
            }
            self.page.active_phase()
        })();
        match observed {
            Ok(Some(phase)) => phase as usize,
            Ok(None) => UNATTRIBUTED_HOST_PHASE,
            Err(()) => {
                self.fail();
                UNATTRIBUTED_HOST_PHASE
            }
        }
    }
    /// Snapshot after the synchronous import returned/unwound. A live snapshot
    /// can contain unfinished spans and does not establish service completion.
    pub fn snapshot(&self) -> HistoryImportObservationSnapshot {
        let (host_checks, checkpoints) = match self.host.lock() {
            Ok(host) => (host.phases, host.checkpoints),
            Err(_) => {
                self.fail();
                let host = HostRecords::new();
                (host.phases, host.checkpoints)
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
            host_checkpoint_attribution: HistoryHostCheckpointAttribution {
                schema: "pon-local-history-host-phase-attribution-v1",
                buckets: std::array::from_fn(|index| HistoryHostCheckpointPhase {
                    owner_phase: SubmitPhase::ALL.get(index).copied(),
                    calls: checkpoints[index],
                }),
                all_checkpoint_calls_attributed: failures == 0
                    && checkpoints[UNATTRIBUTED_HOST_PHASE].calls_started == 0
                    && checkpoints.iter().try_fold(0u64, |sum, row| {
                        sum.checked_add(row.calls_started)
                    }) == Some(host_checks[HistoryHostPhase::Checkpoint as usize].calls_started),
                has_consensus_authority: false,
                scope: "actual Host checkpoint calls classified once at entry by the innermost open owner phase; worker calls use the current owner phase context; absent or ambiguous contexts remain unattributed; the same existing call clocks feed aggregate and bucket records, which overlap; summed call wall intervals are not elapsed runtime and may overlap across threads; Host CPU includes each invoking thread, while native phase CPU excludes scoped workers; observer overhead remains in outer measured work",
            },
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
    checkpoint_phase: Option<usize>,
    start: Instant,
    cpu: Option<ThreadCpuStamp>,
    accepted: Option<bool>,
    error_code: Option<&'static str>,
    recorded: bool,
}
impl<'a> HostGuard<'a> {
    fn new(observer: &'a HistoryImportObserver, phase: HistoryHostPhase) -> Self {
        // This is an observation of existing spans, never another Host action.
        // It is lock-free and its overhead remains in the outer native span.
        let mut checkpoint_phase =
            matches!(phase, HistoryHostPhase::Checkpoint).then(|| observer.checkpoint_phase());
        let start = Instant::now();
        let offset = start
            .checked_duration_since(observer.epoch)
            .and_then(|elapsed| u64::try_from(elapsed.as_nanos()).ok());
        let mut recorded = false;
        let mut checkpoint_recorded = false;
        if let Ok(mut host) = observer.host.try_lock() {
            let HostRecords {
                phases,
                checkpoints,
            } = &mut *host;
            let rows = [
                Some(&mut phases[phase as usize]),
                checkpoint_phase.map(|index| &mut checkpoints[index]),
            ];
            for (index, row) in rows.into_iter().enumerate() {
                let Some(row) = row else { continue };
                if let Some(count) = row.calls_started.checked_add(1) {
                    row.first_started_ns = if count == 1 {
                        offset
                    } else {
                        row.first_started_ns
                            .zip(offset)
                            .map(|(before, now)| before.min(now))
                    };
                    row.calls_started = count;
                    if index == 0 {
                        recorded = true;
                    } else {
                        checkpoint_recorded = true;
                    }
                } else {
                    observer.fail();
                }
            }
        } else {
            observer.fail();
        }
        if !checkpoint_recorded {
            checkpoint_phase = None;
        }
        Self {
            observer,
            phase,
            checkpoint_phase,
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
            let HostRecords {
                phases,
                checkpoints,
            } = &mut *host;
            let rows = [
                Some(&mut phases[self.phase as usize]),
                self.checkpoint_phase.map(|index| &mut checkpoints[index]),
            ];
            for row in rows.into_iter().flatten() {
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
                if cpu.is_some() && row.thread_cpu_ns.is_none() && row.cpu_clock_unknown_calls == 0
                {
                    self.observer.fail();
                }
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
    fn host_checkpoints_follow_existing_native_spans_without_new_callbacks() {
        use crate::ingress::execution_observation::{self, Scope};
        use trnm_mvcc_fee::pon_executor::{ExecutionControl, ExecutionProgress};

        let observer = HistoryImportObserver::new();
        let calls = AtomicUsize::new(0);
        let original = || {
            observe_host(Some(&observer), HistoryHostPhase::Checkpoint, || {
                calls.fetch_add(1, Ordering::Relaxed);
                Ok(())
            })
        };
        let page = observer.page().phase(SubmitPhase::HistoryImport);
        original().unwrap();
        let packet = observer.packet(0).unwrap();
        let import = packet.phase(SubmitPhase::HistoryImport);
        let work = packet.phase(SubmitPhase::Work);
        original().unwrap();
        work.finish(true);
        let admission = packet.phase(SubmitPhase::Admission);
        execution_observation::run(
            Some(packet),
            &ExecutionControl::new(&|_| original(), &()),
            Scope::Held,
            |control| {
                // Each marker invokes the original hook BEFORE its observer
                // transition, so the boundary belongs to the preceding span.
                for point in [
                    ExecutionProgress::BeforeParentBinding,
                    ExecutionProgress::BeforeStateClone,
                    ExecutionProgress::BeforeCommitment,
                    ExecutionProgress::AfterCommitment,
                    ExecutionProgress::BeforePersistence,
                    ExecutionProgress::BeforeDurableCommit,
                ] {
                    (control.progress)(point)?;
                }
                Ok(())
            },
        )
        .unwrap();
        admission.finish(true);
        import.finish(true);
        page.finish(true);

        let snapshot = observer.snapshot();
        let attribution = &snapshot.host_checkpoint_attribution;
        assert_eq!(calls.load(Ordering::Relaxed), 8);
        assert_eq!(snapshot.measurement_failures, 0);
        assert!(attribution.all_checkpoint_calls_attributed);
        assert!(!attribution.has_consensus_authority);
        for (phase, expected) in [
            (SubmitPhase::HistoryImport, 1),
            (SubmitPhase::Work, 1),
            (SubmitPhase::AdmissionPrepare, 2),
            (SubmitPhase::Execution, 2),
            (SubmitPhase::RootCommitment, 1),
            (SubmitPhase::Commit, 1),
        ] {
            let bucket = &attribution.buckets[phase as usize];
            assert_eq!(bucket.owner_phase, Some(phase));
            assert_eq!(bucket.calls.calls_started, expected);
            assert_eq!(bucket.calls.calls_accepted, expected);
        }
        let total = snapshot.host_checks[HistoryHostPhase::Checkpoint as usize];
        assert_eq!(total.calls_started, 8);
        assert_eq!(
            attribution
                .buckets
                .iter()
                .map(|row| row.calls.wall_ns.unwrap_or(0))
                .sum::<u64>(),
            total.wall_ns.unwrap()
        );
        // These are identical call samples, not independently measured phase
        // CPU or disjoint elapsed-runtime intervals.
        let encoded = serde_json::to_value(&snapshot).unwrap();
        assert_eq!(encoded["schema"], "pon-local-history-import-observation-v1");
        assert_eq!(
            encoded["host_checkpoint_attribution"]["schema"],
            "pon-local-history-host-phase-attribution-v1"
        );
        assert_eq!(encoded["host_checks"].as_array().unwrap().len(), 4);
        assert_eq!(
            encoded["host_checkpoint_attribution"]["buckets"]
                .as_array()
                .unwrap()
                .len(),
            HOST_PHASE_BUCKETS
        );
    }

    #[test]
    fn checkpoint_attribution_keeps_errors_unwind_and_missing_clocks() {
        let observer = HistoryImportObserver::new();
        let packet = observer.packet(0).unwrap();
        let work = packet.phase(SubmitPhase::Work);
        let calls = AtomicUsize::new(0);
        let result = observe_host(Some(&observer), HistoryHostPhase::Checkpoint, || {
            calls.fetch_add(1, Ordering::Relaxed);
            Err::<(), _>("PUBLIC_REQUEST_DEADLINE".into())
        });
        assert!(result
            .unwrap_err()
            .is(crate::ErrorCode::PublicRequestDeadline));
        let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _: crate::Result<()> =
                observe_host(Some(&observer), HistoryHostPhase::Checkpoint, || {
                    calls.fetch_add(1, Ordering::Relaxed);
                    panic!("retain the original unwind");
                });
        }));
        assert!(panicked.is_err());
        let mut guard = HostGuard::new(&observer, HistoryHostPhase::Checkpoint);
        guard.cpu = None;
        guard.finish(&Ok(()));
        work.finish(false);
        let snapshot = observer.snapshot();
        let row = snapshot.host_checkpoint_attribution.buckets[SubmitPhase::Work as usize].calls;
        assert_eq!(calls.load(Ordering::Relaxed), 2);
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
        assert_eq!(row.last_error_code, Some("PUBLIC_REQUEST_DEADLINE"));
        assert_eq!(row.thread_cpu_ns, None);
        assert!(row.cpu_clock_unknown_calls >= 1);
        assert_eq!(snapshot.measurement_failures, 0);
    }

    #[test]
    fn unattributed_and_ambiguous_contexts_never_guess_or_change_original_action() {
        let observer = HistoryImportObserver::new();
        observe_host(Some(&observer), HistoryHostPhase::Checkpoint, || Ok(())).unwrap();
        let packet = observer.packet(0).unwrap();
        let work = packet.phase(SubmitPhase::Work);
        let context = packet.phase(SubmitPhase::Context);
        let calls = AtomicUsize::new(0);
        let result = observe_host(Some(&observer), HistoryHostPhase::Checkpoint, || {
            calls.fetch_add(1, Ordering::Relaxed);
            Err::<(), _>("PUBLIC_REQUEST_CANCELLED".into())
        });
        assert!(result
            .unwrap_err()
            .is(crate::ErrorCode::PublicRequestCancelled));
        context.finish(false);
        work.finish(false);
        let snapshot = observer.snapshot();
        assert_eq!(calls.load(Ordering::Relaxed), 1);
        assert_eq!(snapshot.measurement_failures, 1);
        assert!(
            !snapshot
                .host_checkpoint_attribution
                .all_checkpoint_calls_attributed
        );
        let unknown = &snapshot.host_checkpoint_attribution.buckets[UNATTRIBUTED_HOST_PHASE];
        assert_eq!(unknown.owner_phase, None);
        assert_eq!(unknown.calls.calls_started, 2);
        assert_eq!(unknown.calls.calls_rejected, 1);
    }

    #[test]
    fn worker_checkpoint_uses_owner_phase_without_relabeling_worker_cpu() {
        let observer = HistoryImportObserver::new();
        let packet = observer.packet(0).unwrap();
        let admission = packet.phase(SubmitPhase::Admission);
        let execution = packet.phase(SubmitPhase::Execution);
        std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    observe_host(Some(&observer), HistoryHostPhase::Checkpoint, || Ok(())).unwrap();
                })
                .join()
                .unwrap();
        });
        execution.finish(true);
        admission.finish(true);
        let snapshot = observer.snapshot();
        assert_eq!(
            snapshot.host_checkpoint_attribution.buckets[SubmitPhase::Execution as usize]
                .calls
                .calls_started,
            1
        );
        assert!(
            snapshot
                .host_checkpoint_attribution
                .all_checkpoint_calls_attributed
        );
        assert!(snapshot.phase_cpu_excludes_scoped_workers);
        assert!(snapshot.host_cpu_includes_each_calling_thread);
        assert!(!snapshot.host_cpu_is_full_worker_cpu);
    }

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
