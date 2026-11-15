//! Private, opt-in timing for one retained TCP test. Never a production logger.
//! Fixed buffers contain no request bodies, signatures, keys, paths or addresses.

use super::CellErrorV1;
use std::{
    cell::{Cell, RefCell},
    io,
    sync::{Arc, Mutex},
    time::Instant,
};

const CAPACITY: usize = 512;
const THREADS: usize = 4;

#[derive(Clone, Copy)]
struct Event {
    stage: &'static str,
    outcome: &'static str,
    at_ns: u128,
    deadline_ns: Option<u128>,
    remaining_ns: Option<u128>,
    expired: bool,
    service: Option<usize>,
    ordinal: u64,
    kind: Option<u8>,
    value: u64,
    io_kind: Option<io::ErrorKind>,
    os_error: Option<i32>,
}

struct Recorder {
    origin: Instant,
    role: &'static str,
    service: Option<usize>,
    ordinal: u64,
    kind: Option<u8>,
    events: Vec<Event>,
    overflow: usize,
    idle_count: u64,
    last_idle_start: Option<Instant>,
    last_idle_end: Option<Instant>,
    panicking: bool,
}

impl Recorder {
    fn push(
        &mut self,
        stage: &'static str,
        outcome: &'static str,
        at: Instant,
        deadline: Option<Instant>,
        value: u64,
        error: (Option<io::ErrorKind>, Option<i32>),
    ) {
        if self.events.len() == CAPACITY {
            self.overflow = self.overflow.saturating_add(1);
            return;
        }
        self.events.push(Event {
            stage,
            outcome,
            at_ns: at.saturating_duration_since(self.origin).as_nanos(),
            deadline_ns: deadline.map(|d| d.saturating_duration_since(self.origin).as_nanos()),
            remaining_ns: deadline.map(|d| d.saturating_duration_since(at).as_nanos()),
            expired: deadline.is_some_and(|d| at >= d),
            service: self.service,
            ordinal: self.ordinal,
            kind: self.kind,
            value,
            io_kind: error.0,
            os_error: error.1,
        });
    }
}

thread_local! {
    static ACTIVE: RefCell<Option<Recorder>> = const { RefCell::new(None) };
}

#[derive(Default)]
struct Finished {
    records: Vec<Recorder>,
    excess_threads: usize,
}

pub(super) struct Capture {
    origin: Instant,
    finished: Arc<Mutex<Finished>>,
    emitted: Cell<bool>,
}

#[derive(Clone)]
pub(super) struct Token {
    origin: Instant,
    finished: Arc<Mutex<Finished>>,
}

pub(super) struct Scope {
    finished: Arc<Mutex<Finished>>,
    installed: bool,
}

impl Capture {
    pub(super) fn new() -> Self {
        Self {
            origin: Instant::now(),
            finished: Arc::new(Mutex::new(Finished {
                records: Vec::with_capacity(THREADS),
                excess_threads: 0,
            })),
            emitted: Cell::new(false),
        }
    }

    pub(super) fn token(&self) -> Token {
        Token {
            origin: self.origin,
            finished: self.finished.clone(),
        }
    }

    // The target invokes this only after all service joins and caller work.
    // Drop is a fallback after ordinary fixture cleanup on early unwind.
    pub(super) fn emit(&self) {
        if self.emitted.replace(true) {
            return;
        }
        // Preserve libtest capture. Output is best effort and may be partial;
        // a printing panic must not replace the original test result or cause
        // a second unwind from Drop. Do not change the process panic hook.
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| self.emit_buffered()));
    }

    fn emit_buffered(&self) {
        let done = self.finished.lock().unwrap_or_else(|e| e.into_inner());
        eprintln!(
            "cell_rendezvous_timing schema=2 threads={} excess_threads={}",
            done.records.len(),
            done.excess_threads,
        );
        for record in &done.records {
            eprintln!(
                "cell_rendezvous_timing_buffer role={} last_service={:?} capacity={} used={} overflow={} panicking={}",
                record.role, record.service, CAPACITY, record.events.len(), record.overflow, record.panicking,
            );
            for (sequence, event) in record.events.iter().enumerate() {
                eprintln!(
                    "cell_rendezvous_timing_event role={} service={:?} ordinal={} kind={:?} sequence={} stage={} outcome={} at_ns={} deadline_ns={:?} remaining_ns={:?} expired={} value={} io_kind={:?} os_error={:?}",
                    record.role, event.service, event.ordinal, event.kind, sequence,
                    event.stage, event.outcome, event.at_ns, event.deadline_ns,
                    event.remaining_ns, event.expired, event.value, event.io_kind, event.os_error,
                );
            }
        }
    }
}

impl Drop for Capture {
    fn drop(&mut self) {
        self.emit();
    }
}

impl Token {
    pub(super) fn install(&self, role: &'static str, service: Option<usize>) -> Scope {
        let installed = ACTIVE.with(|slot| {
            let mut slot = slot.borrow_mut();
            if slot.is_some() {
                return false;
            }
            *slot = Some(Recorder {
                origin: self.origin,
                role,
                service,
                ordinal: 0,
                kind: None,
                events: Vec::with_capacity(CAPACITY),
                overflow: 0,
                idle_count: 0,
                last_idle_start: None,
                last_idle_end: None,
                panicking: false,
            });
            true
        });
        Scope {
            finished: self.finished.clone(),
            installed,
        }
    }
}

impl Drop for Scope {
    fn drop(&mut self) {
        if !self.installed {
            return;
        }
        if let Some(mut record) = ACTIVE.with(|slot| slot.borrow_mut().take()) {
            record.panicking = std::thread::panicking();
            let mut done = self.finished.lock().unwrap_or_else(|e| e.into_inner());
            if done.records.len() < THREADS {
                done.records.push(record);
            } else {
                done.excess_threads = done.excess_threads.saturating_add(1);
            }
        }
    }
}

// Outside a live transport request, ordinal zero and kind None mean unknown.
// A local aggregate read has no single service; never inherit a prior source.
pub(super) fn service(service: Option<usize>) {
    ACTIVE.with(|slot| {
        if let Some(record) = slot.borrow_mut().as_mut() {
            record.service = service;
            record.ordinal = 0;
            record.kind = None;
        }
    });
}

pub(super) fn request(ordinal: u64, kind: Option<u8>, deadline: Instant) {
    ACTIVE.with(|slot| {
        if let Some(record) = slot.borrow_mut().as_mut() {
            record.ordinal = ordinal;
            record.kind = kind;
            record.push(
                "request_deadline",
                "fixed",
                Instant::now(),
                Some(deadline),
                0,
                (None, None),
            );
        }
    });
}

pub(super) fn kind(kind: u8) {
    ACTIVE.with(|slot| {
        if let Some(record) = slot.borrow_mut().as_mut() {
            record.kind = Some(kind);
        }
    });
}

pub(super) fn poll_start() -> Option<Instant> {
    ACTIVE.with(|slot| slot.borrow().as_ref().map(|_| Instant::now()))
}

pub(super) fn idle_start(at: Option<Instant>) {
    ACTIVE.with(|slot| {
        if let Some(record) = slot.borrow_mut().as_mut() {
            record.idle_count = record.idle_count.saturating_add(1);
            record.last_idle_start = at;
            record.last_idle_end = None;
        }
    });
}

pub(super) fn idle_end() {
    ACTIVE.with(|slot| {
        if let Some(record) = slot.borrow_mut().as_mut() {
            record.last_idle_end = Some(Instant::now());
        }
    });
}

pub(super) fn accepted(ordinal: u64, start: Option<Instant>) {
    ACTIVE.with(|slot| {
        if let Some(record) = slot.borrow_mut().as_mut() {
            record.ordinal = ordinal;
            record.kind = None;
            if let Some(at) = record.last_idle_start {
                record.push(
                    "last_idle_start",
                    "observed",
                    at,
                    None,
                    record.idle_count,
                    (None, None),
                );
            }
            if let Some(at) = record.last_idle_end {
                record.push(
                    "last_idle_end",
                    "observed",
                    at,
                    None,
                    record.idle_count,
                    (None, None),
                );
            }
            if let Some(start) = start {
                record.push(
                    "accept",
                    "begin",
                    start,
                    None,
                    record.idle_count,
                    (None, None),
                );
            }
            // The caller has already constructed the original request deadline.
            // This is a user-space observation, not the kernel accept return.
            record.push(
                "accept_after_deadline",
                "observed",
                Instant::now(),
                None,
                record.idle_count,
                (None, None),
            );
            record.idle_count = 0;
            record.last_idle_start = None;
            record.last_idle_end = None;
        }
    });
}

pub(super) fn mark(stage: &'static str, deadline: Option<Instant>, value: u64) {
    record(stage, "observed", deadline, value, (None, None));
}

fn record(
    stage: &'static str,
    outcome: &'static str,
    deadline: Option<Instant>,
    value: u64,
    error: (Option<io::ErrorKind>, Option<i32>),
) {
    ACTIVE.with(|slot| {
        if let Some(recorder) = slot.borrow_mut().as_mut() {
            recorder.push(stage, outcome, Instant::now(), deadline, value, error);
        }
    });
}

pub(super) trait ObservedError {
    fn category(&self) -> (&'static str, Option<io::ErrorKind>, Option<i32>);
}

impl ObservedError for io::Error {
    fn category(&self) -> (&'static str, Option<io::ErrorKind>, Option<i32>) {
        ("io", Some(self.kind()), self.raw_os_error())
    }
}

impl ObservedError for rusqlite::Error {
    fn category(&self) -> (&'static str, Option<io::ErrorKind>, Option<i32>) {
        ("sql", None, None)
    }
}

impl ObservedError for CellErrorV1 {
    fn category(&self) -> (&'static str, Option<io::ErrorKind>, Option<i32>) {
        match self {
            Self::Io(error) => ("io", Some(error.kind()), error.raw_os_error()),
            Self::Invalid("discovery absolute deadline") => ("absolute_deadline", None, None),
            Self::Invalid(_) => ("invalid", None, None),
            Self::Sql(_) => ("sql", None, None),
            Self::Unavailable => ("unavailable", None, None),
            Self::CacheQuotaExceeded => ("cache_quota", None, None),
            Self::CacheWriterBusy => ("cache_writer_busy", None, None),
            Self::ResponseByteBudgetExhausted { .. } => ("response_byte_budget", None, None),
        }
    }
}

// No borrow of ACTIVE, shared lock or output spans the original operation.
// The surrounding macro evaluates the original expression exactly once. It
// introduces no closure, so borrowed MutexGuard/Transaction results retain
// their original borrow and lifetime semantics.
pub(super) fn begin(stage: &'static str, deadline: Instant) {
    record(stage, "begin", Some(deadline), 0, (None, None));
}

pub(super) fn finish<T, E: ObservedError>(
    stage: &'static str,
    deadline: Instant,
    result: &Result<T, E>,
) {
    match result {
        Ok(_) => record(stage, "ok", Some(deadline), 0, (None, None)),
        Err(error) => {
            let (category, kind, os) = error.category();
            record(stage, category, Some(deadline), 0, (kind, os));
        }
    }
}
