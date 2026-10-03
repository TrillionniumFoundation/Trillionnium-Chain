//! Optional bounded local measurements. Never ledger or transport authority.
use serde::Serialize;
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc, Mutex,
};
use std::thread::{self, ThreadId};
use trnm_protocol::pon_wire::Hash;

pub const MAX_REQUEST_OBSERVATION_RECORDS: usize = 4096;

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

struct Cell {
    row: Mutex<PublicRequestObservation>,
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
            schema: "public-v3-local-request-resource-observation-v1",
            capacity: self.0.capacity,
            accepted_connections_seen: self.0.seen.load(Ordering::Acquire),
            records_not_retained: self.0.omitted.load(Ordering::Acquire),
            measurement_failures: self.0.failures.load(Ordering::Acquire),
            counter_overflow: self.0.counter_overflow.load(Ordering::Acquire),
            records,
            observation_has_consensus_authority: false,
            cpu_intervals_are_nested_not_additive: true,
            cpu_includes_reactor_authentication_or_response_signing: false,
            stream_bytes_are_physical_network_bytes: false,
        }
    }

    pub(super) fn connection(&self) -> Option<ConnectionObservation> {
        self.0.count(&self.0.seen);
        if let Ok(mut rows) = self.0.rows.try_lock() {
            if rows.len() < self.0.capacity {
                let cell = Arc::new(Cell {
                    row: Mutex::new(PublicRequestObservation::new()),
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

pub(super) struct TaskObservation(Handle);
impl TaskObservation {
    pub(super) fn dispatch_started(&self) {
        self.0.update(|r| {
            r.dispatch_started = true;
            true
        });
    }
    pub(super) fn dispatch_finished(&self, cpu: Option<u64>, accepted: bool) {
        self.0.update(|r| {
            r.dispatch_thread_cpu_ns = cpu;
            r.dispatch_accepted = Some(accepted);
            true
        });
    }
    pub(super) fn work_started(&self) {
        self.0.update(|r| {
            r.full_work_started = true;
            true
        });
    }
    pub(super) fn work_finished(&self, cpu: Option<u64>, accepted: bool) {
        self.0.update(|r| {
            r.full_work_thread_cpu_ns = cpu;
            r.full_work_accepted = Some(accepted);
            true
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
