//! Explicit owner-local diagnostic intervals. Never returns a native decision.
use super::{cpu_ns, json, Arc, AtomicBool, Instant, Mutex, Ordering, ThreadId, Value};
use serde::Serialize;
use std::thread;

const COUNT: usize = 16;
const NAMES: [&str; COUNT] = [
    "resume_to_last_attach",
    "final_state",
    "final_continuity",
    "final_root",
    "before_publication",
    "publication_entry",
    "expected_steps",
    "publication_writes",
    "publication_event_writes",
    "publication_lifecycle",
    "publication_post_write_checks",
    "publication_events_check",
    "publication_readback",
    "publication_staging",
    "publication_tail",
    "after_publication",
];
#[derive(Clone, Copy)]
#[repr(usize)]
pub(crate) enum Phase {
    ResumeToLastAttach,
    FinalState,
    FinalContinuity,
    FinalRoot,
    BeforePublication,
    PublicationEntry,
    ExpectedSteps,
    PublicationWrites,
    PublicationEventWrites,
    PublicationLifecycle,
    PublicationPostWriteChecks,
    PublicationEventsCheck,
    PublicationReadback,
    PublicationStaging,
    PublicationTail,
    AfterPublication,
}
#[derive(Clone, Copy)]
struct Stamp {
    wall: Option<Instant>,
    cpu: Option<u64>,
    thread: ThreadId,
}
impl Stamp {
    fn now() -> Self {
        #[cfg(test)]
        CLOCK_READS.with(|n| n.set(n.get() + 1));
        Self {
            wall: Some(Instant::now()),
            cpu: cpu_ns(),
            thread: thread::current().id(),
        }
    }
    fn elapsed(self, end: Self) -> (Option<u64>, Option<u64>) {
        let wall = self
            .wall
            .zip(end.wall)
            .and_then(|(s, e)| e.checked_duration_since(s))
            .and_then(|d| u64::try_from(d.as_nanos()).ok());
        let cpu = (self.thread == end.thread)
            .then_some(())
            .and_then(|_| self.cpu.zip(end.cpu))
            .and_then(|(s, e)| e.checked_sub(s));
        (wall, cpu)
    }
}
#[derive(Clone, Copy, Serialize)]
struct Row {
    entered: Option<u64>,
    completed: Option<u64>,
    early_exit: Option<u64>,
    unwound: Option<u64>,
    samples: Option<u64>,
    wall_ns: Option<u64>,
    calling_thread_cpu_ns: Option<u64>,
    last_entry_elapsed_wall_ns: Option<u64>,
    last_entry_elapsed_cpu_ns: Option<u64>,
}
impl Default for Row {
    fn default() -> Self {
        Self {
            entered: Some(0),
            completed: Some(0),
            early_exit: Some(0),
            unwound: Some(0),
            samples: Some(0),
            wall_ns: None,
            calling_thread_cpu_ns: None,
            last_entry_elapsed_wall_ns: None,
            last_entry_elapsed_cpu_ns: None,
        }
    }
}
fn add(a: Option<u64>, b: Option<u64>) -> Option<u64> {
    a.zip(b).and_then(|(a, b)| a.checked_add(b))
}
fn sum(prior_samples: Option<u64>, prior: Option<u64>, next: Option<u64>) -> Option<u64> {
    if prior_samples == Some(0) {
        next
    } else {
        add(prior, next)
    }
}
impl Row {
    fn enter(&mut self, elapsed: (Option<u64>, Option<u64>)) {
        self.entered = add(self.entered, Some(1));
        self.last_entry_elapsed_wall_ns = elapsed.0;
        self.last_entry_elapsed_cpu_ns = elapsed.1;
    }
    fn close(&mut self, elapsed: (Option<u64>, Option<u64>), complete: bool, unwind: bool) {
        self.wall_ns = sum(self.samples, self.wall_ns, elapsed.0);
        self.calling_thread_cpu_ns = sum(self.samples, self.calling_thread_cpu_ns, elapsed.1);
        self.samples = add(self.samples, Some(1));
        if self.samples.is_none() {
            self.wall_ns = None;
            self.calling_thread_cpu_ns = None;
        }
        self.completed = add(self.completed, Some(u64::from(complete)));
        self.early_exit = add(self.early_exit, Some(u64::from(!complete)));
        self.unwound = add(self.unwound, Some(u64::from(unwind)));
    }
    fn merge(&mut self, next: Self) {
        if next.samples != Some(0) {
            self.wall_ns = sum(self.samples, self.wall_ns, next.wall_ns);
            self.calling_thread_cpu_ns = sum(
                self.samples,
                self.calling_thread_cpu_ns,
                next.calling_thread_cpu_ns,
            );
        }
        self.samples = add(self.samples, next.samples);
        if self.samples.is_none() {
            self.wall_ns = None;
            self.calling_thread_cpu_ns = None;
        }
        self.entered = add(self.entered, next.entered);
        self.completed = add(self.completed, next.completed);
        self.early_exit = add(self.early_exit, next.early_exit);
        self.unwound = add(self.unwound, next.unwound);
        if next.entered != Some(0) {
            self.last_entry_elapsed_wall_ns = next.last_entry_elapsed_wall_ns;
            self.last_entry_elapsed_cpu_ns = next.last_entry_elapsed_cpu_ns;
        }
    }
}
#[derive(Clone, Copy)]
struct Attempt {
    rows: [Row; COUNT],
    last_phase: usize,
    completed: bool,
    unwound: bool,
}
struct State {
    segments: Option<u64>,
    completed: Option<u64>,
    unwound: Option<u64>,
    totals: [Row; COUNT],
    last: Option<Attempt>,
}
impl Default for State {
    fn default() -> Self {
        Self {
            segments: Some(0),
            completed: Some(0),
            unwound: Some(0),
            totals: [Row::default(); COUNT],
            last: None,
        }
    }
}
#[derive(Default)]
pub(super) struct Accounting {
    state: Mutex<State>,
    failed: AtomicBool,
}
fn rows_json(rows: &[Row; COUNT]) -> Value {
    Value::Array(
        NAMES
            .iter()
            .zip(rows)
            .map(|(name, row)| json!({"phase":name,"totals":row}))
            .collect(),
    )
}
impl Accounting {
    pub(super) fn snapshot(&self) -> Value {
        let data = match self.state.try_lock() {
            Ok(s) => Some((s.segments, s.completed, s.unwound, s.totals, s.last)),
            Err(_) => {
                self.failed.store(true, Ordering::Relaxed);
                None
            }
        };
        let failed = self.failed.load(Ordering::Relaxed);
        let data = data.filter(|_| !failed);
        json!({"schema":"pon-native-legacy-activation-tail-v1","observation_failed":failed,
            "segments_observed":data.and_then(|d|d.0),"segments_completed":data.and_then(|d|d.1),"segments_unwound":data.and_then(|d|d.2),
            "phases":data.map(|d|rows_json(&d.3)),
            "last_observed_segment":data.and_then(|d|d.4).map(|a|json!({"last_phase":NAMES[a.last_phase],"completed":a.completed,"unwound":a.unwound,"phases":rows_json(&a.rows)})),
            "scope":"Fixed owner-local totals and latest exited resume segment only. Entry elapsed begins at activate_with_fault_and_progress, before its first progress call; it excludes earlier observed-history checking, RPC and importer work. FinalState entry measures elapsed at completion of all detach/attach steps. A segment starts only after a nonterminal intent is read and exits before caller cancellation cleanup. Multiple resume segments may share one activation origin. Completion means the original next source boundary was reached, never durable activation or qualification. Ordinary errors retain their prefix without recording error text; unwind is recorded on guard drop. Abort/process termination cannot emit it. Unentered, missing/reversed/cross-thread CPU clocks and overflowing totals remain null. A live guard is not yet in this snapshot. Existing Legacy/Host/import observations are nested and cannot be added.",
            "has_consensus_authority":false})
    }
    fn record(&self, a: Attempt) {
        let Ok(mut s) = self.state.try_lock() else {
            self.failed.store(true, Ordering::Relaxed);
            return;
        };
        s.segments = add(s.segments, Some(1));
        s.completed = add(s.completed, Some(u64::from(a.completed)));
        s.unwound = add(s.unwound, Some(u64::from(a.unwound)));
        for (total, row) in s.totals.iter_mut().zip(a.rows) {
            total.merge(row);
        }
        s.last = Some(a);
    }
}
pub(crate) struct Origin {
    accounting: Arc<Accounting>,
    start: Stamp,
}
impl Origin {
    pub(super) fn new(accounting: Arc<Accounting>) -> Self {
        Self {
            accounting,
            start: Stamp::now(),
        }
    }
    pub(crate) fn begin(&self) -> Observation {
        let now = Stamp::now();
        let mut rows = [Row::default(); COUNT];
        rows[0].enter(self.start.elapsed(now));
        Observation {
            accounting: self.accounting.clone(),
            origin: self.start,
            current: Phase::ResumeToLastAttach,
            started: now,
            rows,
            completed: false,
            sealed: false,
        }
    }
}
pub(crate) struct Observation {
    accounting: Arc<Accounting>,
    origin: Stamp,
    current: Phase,
    started: Stamp,
    rows: [Row; COUNT],
    completed: bool,
    sealed: bool,
}
impl Observation {
    /// None does not read either diagnostic clock or allocate.
    pub(crate) fn advance(observation: &mut Option<Self>, phase: Phase) {
        if let Some(o) = observation {
            o.advance_at(phase, Stamp::now());
        }
    }
    fn advance_at(&mut self, phase: Phase, now: Stamp) {
        self.rows[self.current as usize].close(self.started.elapsed(now), true, false);
        self.current = phase;
        self.started = now;
        self.rows[phase as usize].enter(self.origin.elapsed(now));
    }
    pub(crate) fn complete(observation: &mut Option<Self>) {
        if let Some(o) = observation {
            o.completed = true;
        }
    }
    fn seal(&mut self, end: Stamp, unwound: bool) {
        if self.sealed {
            return;
        }
        self.rows[self.current as usize].close(
            self.started.elapsed(end),
            self.completed && !unwound,
            unwound,
        );
        self.accounting.record(Attempt {
            rows: self.rows,
            last_phase: self.current as usize,
            completed: self.completed && !unwound,
            unwound,
        });
        self.sealed = true;
    }
}
impl Drop for Observation {
    fn drop(&mut self) {
        if !self.sealed {
            self.seal(Stamp::now(), thread::panicking());
        }
    }
}
#[cfg(test)]
thread_local! {static CLOCK_READS:std::cell::Cell<u64>=const{std::cell::Cell::new(0)};}
#[cfg(test)]
pub(crate) fn clock_reads() -> u64 {
    CLOCK_READS.with(std::cell::Cell::get)
}
#[cfg(test)]
mod tests;
