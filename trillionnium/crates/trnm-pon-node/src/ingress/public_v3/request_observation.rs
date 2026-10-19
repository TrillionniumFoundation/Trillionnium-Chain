//! Optional bounded local measurements. Never ledger or transport authority.
use serde::Serialize;
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc, Mutex,
};
use std::thread::{self, ThreadId};
use std::time::Instant;
use trnm_protocol::pon_wire::Hash;

pub const MAX_REQUEST_OBSERVATION_RECORDS: usize = 16_384;

/// Fixed local Submit phases. Waiting for the Node is separate from work while
/// holding it. These observations are nested within dispatch, never CPU credit.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SubmitPhase {
    Decode,
    ContextOwnerWait,
    Context,
    Work,
    AdmissionOwnerWait,
    Admission,
    SubmitResult,
}
impl SubmitPhase {
    const ALL: [Self; 7] = [
        Self::Decode,
        Self::ContextOwnerWait,
        Self::Context,
        Self::Work,
        Self::AdmissionOwnerWait,
        Self::Admission,
        Self::SubmitResult,
    ];
}

#[derive(Clone, Copy, Debug, Serialize)]
pub struct SubmitPhaseObservation {
    pub phase: SubmitPhase,
    pub started: bool,
    pub completed: bool,
    pub accepted: Option<bool>,
    pub wall_ns: Option<u64>,
    /// Only the actual dispatch thread. M06 child CPU, reactor and response
    /// signing are outside this interval, not measured as zero.
    pub thread_cpu_ns: Option<u64>,
}
impl SubmitPhaseObservation {
    fn new(phase: SubmitPhase) -> Self {
        Self {
            phase,
            started: false,
            completed: false,
            accepted: None,
            wall_ns: None,
            thread_cpu_ns: None,
        }
    }
}

fn submit_phases() -> [SubmitPhaseObservation; 7] {
    SubmitPhase::ALL.map(SubmitPhaseObservation::new)
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ApplicationFramePhase {
    Hello,
    Challenge,
    Solution,
    Ready,
    Body,
    Response,
}

#[derive(Clone, Copy, Debug, Serialize)]
pub struct ApplicationFrameBytes {
    pub phase: ApplicationFramePhase,
    pub bytes_read: u64,
    pub bytes_written: u64,
    pub complete: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct PublicRequestObservation {
    pub connection_id: Option<u64>,
    pub operation: Option<u8>,
    pub body_digest: Option<Hash>,
    pub frames: [ApplicationFrameBytes; 6],
    pub application_bytes_read: Option<u64>,
    pub application_bytes_written: Option<u64>,
    pub physical_network_bytes: Option<u64>,
    pub full_work_started: bool,
    pub full_work_accepted: Option<bool>,
    pub full_work_thread_cpu_ns: Option<u64>,
    pub dispatch_started: bool,
    pub dispatch_accepted: Option<bool>,
    pub dispatch_thread_cpu_ns: Option<u64>,
    pub submit_phases: [SubmitPhaseObservation; 7],
    pub terminal_phase: Option<&'static str>,
    pub response_frame_complete: bool,
    pub connection_closed: bool,
    pub task_created: bool,
    pub task_closed: bool,
    pub observation_failed: bool,
    pub complete: bool,
}

impl PublicRequestObservation {
    fn new() -> Self {
        Self {
            connection_id: None,
            operation: None,
            body_digest: None,
            frames: [
                ApplicationFramePhase::Hello,
                ApplicationFramePhase::Challenge,
                ApplicationFramePhase::Solution,
                ApplicationFramePhase::Ready,
                ApplicationFramePhase::Body,
                ApplicationFramePhase::Response,
            ]
            .map(|phase| ApplicationFrameBytes {
                phase,
                bytes_read: 0,
                bytes_written: 0,
                complete: false,
            }),
            application_bytes_read: None,
            application_bytes_written: None,
            physical_network_bytes: None,
            full_work_started: false,
            full_work_accepted: None,
            full_work_thread_cpu_ns: None,
            dispatch_started: false,
            dispatch_accepted: None,
            dispatch_thread_cpu_ns: None,
            submit_phases: submit_phases(),
            terminal_phase: None,
            response_frame_complete: false,
            connection_closed: false,
            task_created: false,
            task_closed: false,
            observation_failed: false,
            complete: false,
        }
    }
}

// The socket reactor and the execution worker write disjoint observations.
// Sharing one try_lock made a normal frame/worker overlap look like lost data.
// Neither side may block the other to produce optional diagnostic evidence.
#[derive(Clone, Copy)]
struct TaskProgress {
    full_work_started: bool,
    full_work_accepted: Option<bool>,
    full_work_thread_cpu_ns: Option<u64>,
    dispatch_started: bool,
    dispatch_accepted: Option<bool>,
    dispatch_thread_cpu_ns: Option<u64>,
    submit_phases: [SubmitPhaseObservation; 7],
}
impl Default for TaskProgress {
    fn default() -> Self {
        Self {
            full_work_started: false,
            full_work_accepted: None,
            full_work_thread_cpu_ns: None,
            dispatch_started: false,
            dispatch_accepted: None,
            dispatch_thread_cpu_ns: None,
            submit_phases: submit_phases(),
        }
    }
}

struct Cell {
    row: Mutex<PublicRequestObservation>,
    task: Mutex<TaskProgress>,
    failed: AtomicBool,
    connection_closed: AtomicBool,
    task_created: AtomicBool,
    task_closed: AtomicBool,
}

struct Inner {
    capacity: usize,
    rows: Mutex<Vec<Arc<Cell>>>,
    seen: AtomicU64,
    omitted: AtomicU64,
    failures: AtomicU64,
    counter_overflow: AtomicBool,
}

impl Inner {
    fn count(&self, counter: &AtomicU64) {
        if counter
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
            .is_err()
        {
            self.counter_overflow.store(true, Ordering::Release);
        }
    }
}

/// Trusted operator observation only. First records are retained without eviction.
/// Capture failures/overflow do not alter any request admission or native result.
#[derive(Clone)]
pub struct PublicRequestObserver(Arc<Inner>);

#[derive(Clone, Debug, Serialize)]
pub struct PublicRequestObservationSnapshot {
    pub schema: &'static str,
    pub capacity: usize,
    pub accepted_connections_seen: u64,
    pub records_not_retained: u64,
    pub measurement_failures: u64,
    pub counter_overflow: bool,
    pub records: Vec<PublicRequestObservation>,
    pub observation_has_consensus_authority: bool,
    pub cpu_intervals_are_nested_not_additive: bool,
    pub cpu_includes_reactor_authentication_or_response_signing: bool,
    pub submit_phase_cpu_excludes_scoped_workers: bool,
    pub stream_bytes_are_physical_network_bytes: bool,
}

impl PublicRequestObserver {
    pub fn new(capacity: usize) -> super::Result<Self> {
        super::ensure(
            (1..=MAX_REQUEST_OBSERVATION_RECORDS).contains(&capacity),
            "PUBLIC_OBSERVATION_CAPACITY",
        )?;
        Ok(Self(Arc::new(Inner {
            capacity,
            rows: Mutex::new(Vec::with_capacity(capacity)),
            seen: AtomicU64::new(0),
            omitted: AtomicU64::new(0),
            failures: AtomicU64::new(0),
            counter_overflow: AtomicBool::new(false),
        })))
    }

    /// Prefer after actual service/worker joins. A live snapshot is explicitly incomplete.
    pub fn snapshot(&self) -> PublicRequestObservationSnapshot {
        let mut records = Vec::new();
        if let Ok(rows) = self.0.rows.lock() {
            for cell in rows.iter() {
                if let Ok(row) = cell.row.lock() {
                    let mut value = row.clone();
                    match cell.task.lock() {
                        Ok(task) => {
                            value.full_work_started = task.full_work_started;
                            value.full_work_accepted = task.full_work_accepted;
                            value.full_work_thread_cpu_ns = task.full_work_thread_cpu_ns;
                            value.dispatch_started = task.dispatch_started;
                            value.dispatch_accepted = task.dispatch_accepted;
                            value.dispatch_thread_cpu_ns = task.dispatch_thread_cpu_ns;
                            value.submit_phases = task.submit_phases;
                        }
                        Err(_) => {
                            cell.failed.store(true, Ordering::Release);
                            self.0.count(&self.0.failures);
                        }
                    }
                    value.connection_closed = cell.connection_closed.load(Ordering::Acquire);
                    value.task_created = cell.task_created.load(Ordering::Acquire);
                    value.task_closed = cell.task_closed.load(Ordering::Acquire);
                    value.observation_failed = cell.failed.load(Ordering::Acquire);
                    value.complete = value.connection_closed
                        && (!value.task_created || value.task_closed)
                        && !value.observation_failed;
                    if !value.observation_failed {
                        value.application_bytes_read = value
                            .frames
                            .iter()
                            .try_fold(0u64, |n, f| n.checked_add(f.bytes_read));
                        value.application_bytes_written = value
                            .frames
                            .iter()
                            .try_fold(0u64, |n, f| n.checked_add(f.bytes_written));
                    }
                    records.push(value);
                } else {
                    self.0.count(&self.0.failures);
                }
            }
        } else {
            self.0.count(&self.0.failures);
        }
        PublicRequestObservationSnapshot {
            schema: "public-v3-local-request-resource-observation-v2",
            capacity: self.0.capacity,
            accepted_connections_seen: self.0.seen.load(Ordering::Acquire),
            records_not_retained: self.0.omitted.load(Ordering::Acquire),
            measurement_failures: self.0.failures.load(Ordering::Acquire),
            counter_overflow: self.0.counter_overflow.load(Ordering::Acquire),
            records,
            observation_has_consensus_authority: false,
            cpu_intervals_are_nested_not_additive: true,
            cpu_includes_reactor_authentication_or_response_signing: false,
            submit_phase_cpu_excludes_scoped_workers: true,
            stream_bytes_are_physical_network_bytes: false,
        }
    }

    pub(super) fn connection(&self) -> Option<ConnectionObservation> {
        self.0.count(&self.0.seen);
        if let Ok(mut rows) = self.0.rows.try_lock() {
            if rows.len() < self.0.capacity {
                let cell = Arc::new(Cell {
                    row: Mutex::new(PublicRequestObservation::new()),
                    task: Mutex::new(TaskProgress::default()),
                    failed: AtomicBool::new(false),
                    connection_closed: AtomicBool::new(false),
                    task_created: AtomicBool::new(false),
                    task_closed: AtomicBool::new(false),
                });
                rows.push(cell.clone());
                return Some(ConnectionObservation {
                    cell,
                    inner: self.0.clone(),
                });
            }
        } else {
            self.0.count(&self.0.failures);
        }
        self.0.count(&self.0.omitted);
        None
    }
}

struct Handle {
    cell: Arc<Cell>,
    inner: Arc<Inner>,
}
impl Handle {
    fn update_task(&self, change: impl FnOnce(&mut TaskProgress)) {
        match self.cell.task.try_lock() {
            Ok(mut task) => change(&mut task),
            Err(_) => {
                self.cell.failed.store(true, Ordering::Release);
                self.inner.count(&self.inner.failures);
            }
        }
    }
    fn update(&self, change: impl FnOnce(&mut PublicRequestObservation) -> bool) {
        let success = self
            .cell
            .row
            .try_lock()
            .ok()
            .is_some_and(|mut row| change(&mut row));
        if !success {
            self.cell.failed.store(true, Ordering::Release);
            self.inner.count(&self.inner.failures);
        }
    }
}

pub(super) struct ConnectionObservation {
    cell: Arc<Cell>,
    inner: Arc<Inner>,
}
impl ConnectionObservation {
    fn handle(&self) -> Handle {
        Handle {
            cell: self.cell.clone(),
            inner: self.inner.clone(),
        }
    }
    pub(super) fn identity(&self, id: u64) {
        self.handle().update(|r| {
            r.connection_id = Some(id);
            true
        });
    }
    pub(super) fn request(&self, op: u8, digest: Hash) {
        self.handle().update(|r| {
            r.operation = Some(op);
            r.body_digest = Some(digest);
            true
        });
    }
    pub(super) fn frame(&self, phase: usize, read: usize, written: usize, complete: bool) {
        self.handle().update(|r| {
            let f = &mut r.frames[phase];
            let Some(rx) = f.bytes_read.checked_add(read as u64) else {
                return false;
            };
            let Some(tx) = f.bytes_written.checked_add(written as u64) else {
                return false;
            };
            f.bytes_read = rx;
            f.bytes_written = tx;
            f.complete |= complete;
            if phase == 5 && complete {
                r.response_frame_complete = true;
            }
            true
        });
    }
    pub(super) fn terminal(&self, phase: &'static str) {
        self.handle().update(|r| {
            r.terminal_phase = Some(phase);
            true
        });
    }
    pub(super) fn task(&self) -> TaskObservation {
        self.cell.task_created.store(true, Ordering::Release);
        TaskObservation(self.handle())
    }
}
impl Drop for ConnectionObservation {
    fn drop(&mut self) {
        self.cell.connection_closed.store(true, Ordering::Release);
    }
}

pub(in crate::ingress) struct TaskObservation(Handle);
impl TaskObservation {
    pub(in crate::ingress) fn phase(&self, phase: SubmitPhase) -> SubmitPhaseGuard<'_> {
        self.0.update_task(|r| {
            r.submit_phases[phase as usize].started = true;
        });
        SubmitPhaseGuard {
            observation: self,
            phase,
            started: Instant::now(),
            cpu: ThreadCpuStamp::start(),
            accepted: None,
        }
    }
    pub(super) fn dispatch_started(&self) {
        self.0.update_task(|r| {
            r.dispatch_started = true;
        });
    }
    pub(super) fn dispatch_finished(&self, cpu: Option<u64>, accepted: bool) {
        self.0.update_task(|r| {
            r.dispatch_thread_cpu_ns = cpu;
            r.dispatch_accepted = Some(accepted);
        });
    }
    pub(super) fn work_started(&self) {
        self.0.update_task(|r| {
            r.full_work_started = true;
        });
    }
    pub(super) fn work_finished(&self, cpu: Option<u64>, accepted: bool) {
        self.0.update_task(|r| {
            r.full_work_thread_cpu_ns = cpu;
            r.full_work_accepted = Some(accepted);
        });
    }
}

/// Drop retains an unfinished/panicked phase with unknown outcome. Measurement
/// failure never changes the request result, cancellation or resource account.
pub(in crate::ingress) struct SubmitPhaseGuard<'a> {
    observation: &'a TaskObservation,
    phase: SubmitPhase,
    started: Instant,
    cpu: Option<ThreadCpuStamp>,
    accepted: Option<bool>,
}
impl SubmitPhaseGuard<'_> {
    pub(in crate::ingress) fn finish(mut self, accepted: bool) {
        self.accepted = Some(accepted);
    }
}
impl Drop for SubmitPhaseGuard<'_> {
    fn drop(&mut self) {
        let wall = u64::try_from(self.started.elapsed().as_nanos()).ok();
        let cpu = self.cpu.take().and_then(ThreadCpuStamp::finish);
        self.observation.0.update_task(|r| {
            let phase = &mut r.submit_phases[self.phase as usize];
            phase.completed = self.accepted.is_some();
            phase.accepted = self.accepted;
            phase.wall_ns = wall;
            phase.thread_cpu_ns = cpu;
        });
    }
}
impl Drop for TaskObservation {
    fn drop(&mut self) {
        self.0.cell.task_closed.store(true, Ordering::Release);
    }
}

#[derive(Clone)]
pub(super) struct ThreadCpuStamp {
    thread: ThreadId,
    ns: u64,
}
impl ThreadCpuStamp {
    pub(super) fn start() -> Option<Self> {
        Some(Self {
            thread: thread::current().id(),
            ns: thread_cpu_ns()?,
        })
    }
    pub(super) fn finish(self) -> Option<u64> {
        if self.thread != thread::current().id() {
            return None;
        }
        thread_cpu_ns()?.checked_sub(self.ns)
    }
    /// Advance only an interval owned by this actual thread. A failed sample
    /// never resets its baseline or manufactures a zero charge.
    pub(super) fn checkpoint(&mut self) -> Option<u64> {
        if self.thread != thread::current().id() {
            return None;
        }
        let now = thread_cpu_ns()?;
        let elapsed = now.checked_sub(self.ns)?;
        self.ns = now;
        Some(elapsed)
    }
}

#[cfg(target_os = "linux")]
fn thread_cpu_ns() -> Option<u64> {
    use rustix::time::{clock_gettime_dynamic, ClockId, DynamicClockId};
    let stamp = clock_gettime_dynamic(DynamicClockId::Known(ClockId::ThreadCPUTime)).ok()?;
    let sec = u64::try_from(stamp.tv_sec).ok()?;
    let ns = u64::try_from(stamp.tv_nsec).ok()?;
    if ns >= 1_000_000_000 {
        return None;
    }
    sec.checked_mul(1_000_000_000)?.checked_add(ns)
}
#[cfg(not(target_os = "linux"))]
fn thread_cpu_ns() -> Option<u64> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Barrier;

    #[test]
    fn submit_phase_outcomes_are_bounded_and_keep_abandoned_measurements_unknown() {
        let observer = PublicRequestObserver::new(1).unwrap();
        let connection = observer.connection().unwrap();
        let task = connection.task();
        task.phase(SubmitPhase::Decode).finish(true);
        task.phase(SubmitPhase::Context).finish(false);
        let abandoned = task.phase(SubmitPhase::Work);
        drop(abandoned);
        let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _phase = task.phase(SubmitPhase::Admission);
            panic!("observation must retain unfinished admission");
        }));
        assert!(panicked.is_err());
        drop(task);
        drop(connection);
        let snapshot = observer.snapshot();
        assert_eq!(
            snapshot.schema,
            "public-v3-local-request-resource-observation-v2"
        );
        assert!(snapshot.submit_phase_cpu_excludes_scoped_workers);
        assert!(snapshot.cpu_intervals_are_nested_not_additive);
        assert!(!snapshot.observation_has_consensus_authority);
        assert_eq!(snapshot.measurement_failures, 0);
        let row = &snapshot.records[0];
        assert!(row.complete);
        assert_eq!(row.submit_phases.len(), 7);
        for (index, phase) in row.submit_phases.iter().enumerate() {
            assert_eq!(phase.phase, SubmitPhase::ALL[index]);
            match phase.phase {
                SubmitPhase::Decode | SubmitPhase::Context => {
                    assert!(phase.started && phase.completed);
                    assert_eq!(phase.accepted, Some(phase.phase == SubmitPhase::Decode));
                    assert!(phase.wall_ns.is_some());
                }
                SubmitPhase::Work | SubmitPhase::Admission => {
                    assert!(phase.started && !phase.completed);
                    assert_eq!(phase.accepted, None);
                    assert!(phase.wall_ns.is_some());
                }
                _ => {
                    assert!(!phase.started && !phase.completed);
                    assert_eq!(phase.accepted, None);
                    assert_eq!(phase.wall_ns, None);
                    assert_eq!(phase.thread_cpu_ns, None);
                }
            }
        }
    }

    #[test]
    fn submit_phase_capture_contention_is_optional_and_does_not_block_dispatch() {
        let observer = PublicRequestObserver::new(1).unwrap();
        let connection = observer.connection().unwrap();
        let task = connection.task();
        let guard = connection.cell.task.lock().unwrap();
        let result = crate::ingress::observe_submit_phase(Some(&task), SubmitPhase::Work, || {
            Err::<(), _>(crate::Error::from("FRAME_DEADLINE"))
        });
        assert_eq!(result.unwrap_err().to_string(), "FRAME_DEADLINE");
        drop(guard);
        drop(task);
        drop(connection);
        let snapshot = observer.snapshot();
        assert_eq!(snapshot.measurement_failures, 2);
        assert!(snapshot.records[0].observation_failed);
        assert!(!snapshot.records[0].complete);
        assert!(snapshot.records[0].connection_closed && snapshot.records[0].task_closed);
        assert_eq!(
            snapshot.records[0].submit_phases[SubmitPhase::Work as usize].accepted,
            None
        );
    }

    #[test]
    fn observed_native_submit_keeps_rejection_success_and_duplicate_phase_boundaries() {
        use crate::ingress::{dispatch_shared_with_execution_observation, Request};
        use crate::store::WorkCheckedPacket;
        use crate::{Node, Settings};
        use trnm_mvcc_fee::pon_executor::ExecutionControl;
        let dir = tempfile::tempdir().unwrap();
        let clock = crate::ingress::now().unwrap();
        let settings = Settings::development(Some(clock - 100)).unwrap();
        let node = Node::open(dir.path(), settings.clone(), 2).unwrap();
        let packet = node
            .make(
                settings.genesis(),
                vec![],
                crate::development_public(0).unwrap(),
                clock - 90,
                4096,
            )
            .unwrap();
        let node = Mutex::new(node);
        let observer = PublicRequestObserver::new(3).unwrap();
        let control = ExecutionControl::new(&|_| Ok::<(), crate::Error>(()), &());
        let invalid = observer.connection().unwrap();
        let task = invalid.task();
        let error = dispatch_shared_with_execution_observation(
            &node,
            Request::Submit {
                packet: "invalid hex".into(),
            },
            &mut |_| Ok(()),
            |_| panic!("invalid encoding cannot start work"),
            &control,
            Some(&task),
        )
        .unwrap_err();
        assert!(!error.requires_owner_stop());
        drop(task);
        drop(invalid);
        let request = || Request::Submit {
            packet: hex::encode(packet.encode().unwrap()),
        };
        let accepted = observer.connection().unwrap();
        let task = accepted.task();
        let reply = dispatch_shared_with_execution_observation(
            &node,
            request(),
            &mut |_| Ok(()),
            WorkCheckedPacket::verify,
            &control,
            Some(&task),
        )
        .unwrap();
        drop(task);
        drop(accepted);
        let duplicate = observer.connection().unwrap();
        let task = duplicate.task();
        let repeated = dispatch_shared_with_execution_observation(
            &node,
            request(),
            &mut |_| Ok(()),
            |_| panic!("durable duplicate must not replay work"),
            &control,
            Some(&task),
        )
        .unwrap();
        assert_eq!(reply["block"], repeated["block"]);
        drop(task);
        drop(duplicate);
        let snapshot = observer.snapshot();
        assert_eq!(snapshot.measurement_failures, 0);
        assert!(snapshot.records.iter().all(|row| row.complete));
        let invalid = &snapshot.records[0].submit_phases;
        assert_eq!(invalid[0].accepted, Some(false));
        assert!(invalid[1..].iter().all(|phase| !phase.started));
        assert!(snapshot.records[1].submit_phases.iter().all(|phase| {
            phase.started
                && phase.completed
                && phase.accepted == Some(true)
                && phase.wall_ns.is_some()
        }));
        for phase in &snapshot.records[2].submit_phases {
            let expected = matches!(
                phase.phase,
                SubmitPhase::Decode
                    | SubmitPhase::ContextOwnerWait
                    | SubmitPhase::Context
                    | SubmitPhase::SubmitResult
            );
            assert_eq!(phase.started, expected);
            assert_eq!(phase.accepted, expected.then_some(true));
        }
    }

    #[test]
    fn connection_observation_does_not_wait_for_independent_task_progress() {
        let observer = PublicRequestObserver::new(1).unwrap();
        let connection = observer.connection().unwrap();
        let task = connection.task();
        let guard = connection.cell.task.lock().unwrap();
        thread::scope(|scope| {
            scope
                .spawn(|| {
                    connection.identity(31);
                    connection.frame(4, 19, 0, true);
                    connection.frame(5, 0, 37, true);
                    connection.terminal("complete");
                })
                .join()
                .unwrap();
        });
        drop(guard);
        task.work_started();
        task.work_finished(Some(7), true);
        drop(task);
        drop(connection);
        let snapshot = observer.snapshot();
        let row = &snapshot.records[0];
        assert_eq!(snapshot.measurement_failures, 0);
        assert!(row.complete && row.response_frame_complete);
        assert_eq!(row.application_bytes_read, Some(19));
        assert_eq!(row.application_bytes_written, Some(37));
        assert_eq!(row.full_work_thread_cpu_ns, Some(7));
    }

    #[test]
    fn task_contention_still_records_unknown_without_blocking_release() {
        let observer = PublicRequestObserver::new(1).unwrap();
        let connection = observer.connection().unwrap();
        let task = connection.task();
        let guard = connection.cell.task.lock().unwrap();
        task.work_started(); // Same-writer contention remains an explicit failure.
        drop(guard);
        drop(task);
        drop(connection);
        let snapshot = observer.snapshot();
        assert_eq!(snapshot.measurement_failures, 1);
        assert!(snapshot.records[0].connection_closed && snapshot.records[0].task_closed);
        assert!(snapshot.records[0].observation_failed);
        assert!(!snapshot.records[0].complete);
        assert_eq!(snapshot.records[0].full_work_thread_cpu_ns, None);
    }

    #[test]
    fn independent_task_observation_survives_connection_frame_update() {
        let observer = PublicRequestObserver::new(1).unwrap();
        let connection = observer.connection().unwrap();
        let task = connection.task();
        let guard = connection.cell.row.lock().unwrap();
        let worker = thread::spawn(move || {
            task.work_started();
            task.work_finished(Some(17), false);
            task.dispatch_started();
            task.dispatch_finished(Some(23), false);
        });
        worker.join().unwrap();
        drop(guard);
        drop(connection);
        let snapshot = observer.snapshot();
        assert_eq!(snapshot.measurement_failures, 0);
        assert!(snapshot.records[0].complete);
        assert_eq!(snapshot.records[0].full_work_thread_cpu_ns, Some(17));
        assert_eq!(snapshot.records[0].dispatch_thread_cpu_ns, Some(23));
    }

    #[test]
    fn connection_and_task_close_on_different_threads_complete_once_without_aliasing() {
        let observer = PublicRequestObserver::new(2).unwrap();
        let first = observer.connection().unwrap();
        let second = observer.connection().unwrap();
        first.identity(7);
        first.request(1, [7; 32]);
        second.identity(8);
        second.request(2, [8; 32]);
        let task = first.task();
        let barrier = Arc::new(Barrier::new(2));
        let signal = barrier.clone();
        let worker = thread::spawn(move || {
            task.dispatch_started();
            task.dispatch_finished(None, false);
            signal.wait();
            signal.wait();
            drop(task);
        });
        barrier.wait();
        let live = observer.snapshot();
        assert!(live.records.iter().all(|r| !r.complete));
        drop(first);
        drop(second);
        barrier.wait();
        worker.join().unwrap();
        let closed = observer.snapshot();
        assert_eq!(closed.accepted_connections_seen, 2);
        assert_eq!(closed.records_not_retained, 0);
        assert!(closed.records.iter().all(|r| r.complete));
        assert!(closed.records[0].task_created && closed.records[0].task_closed);
        assert_eq!(closed.records[0].dispatch_accepted, Some(false));
        assert_eq!(closed.records[0].body_digest, Some([7; 32]));
        assert!(!closed.records[1].task_created);
        assert_eq!(closed.records[1].body_digest, Some([8; 32]));
    }

    #[test]
    fn bounded_records_and_saturating_counter_overflow_remain_explicit() {
        assert!(PublicRequestObserver::new(0).is_err());
        assert!(PublicRequestObserver::new(MAX_REQUEST_OBSERVATION_RECORDS).is_ok());
        assert!(PublicRequestObserver::new(MAX_REQUEST_OBSERVATION_RECORDS + 1).is_err());
        let observer = PublicRequestObserver::new(2).unwrap();
        drop(observer.connection().unwrap());
        drop(observer.connection().unwrap());
        assert!(observer.connection().is_none());
        let snapshot = observer.snapshot();
        assert_eq!(snapshot.records.len(), 2);
        assert_eq!(snapshot.accepted_connections_seen, 3);
        assert_eq!(snapshot.records_not_retained, 1);
        observer.0.seen.store(u64::MAX, Ordering::Relaxed);
        assert!(observer.connection().is_none());
        let snapshot = observer.snapshot();
        assert_eq!(snapshot.accepted_connections_seen, u64::MAX);
        assert!(snapshot.counter_overflow);
    }

    #[test]
    fn capture_contention_and_arithmetic_overflow_never_block_task_release() {
        let observer = PublicRequestObserver::new(2).unwrap();
        let connection = observer.connection().unwrap();
        let task = connection.task();
        let guard = connection.cell.row.lock().unwrap();
        connection.frame(0, 1, 0, false); // try_lock fails; no wait or propagated error.
        drop(guard);
        drop(connection);
        drop(task);
        let overflow = observer.connection().unwrap();
        overflow.cell.row.lock().unwrap().frames[0].bytes_read = u64::MAX;
        overflow.frame(0, 1, 0, false);
        drop(overflow);
        let snapshot = observer.snapshot();
        assert_eq!(snapshot.measurement_failures, 2);
        for row in snapshot.records {
            assert!(row.connection_closed && row.observation_failed);
            assert!(!row.complete);
            assert_eq!(row.application_bytes_read, None);
        }
    }

    #[test]
    fn cpu_clock_intervals_stay_on_the_execution_thread_and_are_nested() {
        let Some(outer) = ThreadCpuStamp::start() else {
            return;
        };
        let inner = ThreadCpuStamp::start().unwrap();
        let mut value = 1u64;
        for n in 0..100_000 {
            value = std::hint::black_box(value.wrapping_mul(3).wrapping_add(n));
        }
        assert_ne!(value, 0);
        let inner = inner.finish().unwrap();
        let outer = outer.finish().unwrap();
        assert!(outer >= inner && inner > 0);
        let wrong_thread = ThreadCpuStamp::start().unwrap();
        assert_eq!(
            thread::spawn(move || wrong_thread.finish()).join().unwrap(),
            None
        );
        let impossible_end = ThreadCpuStamp {
            thread: thread::current().id(),
            ns: u64::MAX,
        };
        assert_eq!(impossible_end.finish(), None);
    }
}
