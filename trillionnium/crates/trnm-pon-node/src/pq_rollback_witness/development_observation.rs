//! Explicit development-only timing. No observation authorizes work or retry.
//! The caller establishes the original deadline before creating an observation.
use std::{
    cell::Cell,
    fmt::Write as _,
    io::Write,
    sync::atomic::{AtomicUsize, Ordering},
    thread::{self, ThreadId},
    time::{Duration, Instant},
};

const MAX_RECORDS: usize = 16;
const MAX_LINE_BYTES: usize = 2048;
const PREFIX: &str = "TRNM_PQ_WITNESS_PHASE ";
static EMITTED: AtomicUsize = AtomicUsize::new(0);

#[derive(Clone, Copy)]
pub(super) enum Kind {
    ClientCurrent,
    ClientCas,
    ServiceCurrent,
    ServiceCas,
    ServiceConnection,
}
impl Kind {
    fn label(self) -> &'static str {
        match self {
            Self::ClientCurrent => "client_current",
            Self::ClientCas => "client_cas",
            Self::ServiceCurrent => "service_current",
            Self::ServiceCas => "service_cas",
            Self::ServiceConnection => "service_connection",
        }
    }
}

#[derive(Clone, Copy)]
pub(super) enum Code {
    Deadline,
    Eof,
    Unavailable,
    Busy,
    CommitUncertain,
    Rollback,
    StorageIdentity,
    Schema,
    State,
    StateWidth,
    Other,
}
impl Code {
    fn label(self) -> &'static str {
        match self {
            Self::Deadline => "PQ_WITNESS_DEADLINE",
            Self::Eof => "PQ_WITNESS_EOF",
            Self::Unavailable => "PQ_WITNESS_UNAVAILABLE",
            Self::Busy => "PQ_WITNESS_BUSY",
            Self::CommitUncertain => "PQ_WITNESS_COMMIT_UNCERTAIN",
            Self::Rollback => "PQ_WITNESS_ROLLBACK",
            Self::StorageIdentity => "PQ_WITNESS_STORAGE_IDENTITY",
            Self::Schema => "PQ_WITNESS_SCHEMA",
            Self::State => "PQ_WITNESS_STATE",
            Self::StateWidth => "PQ_WITNESS_STATE_WIDTH",
            Self::Other => "other",
        }
    }
}

#[derive(Clone, Copy)]
#[repr(usize)]
pub(super) enum Phase {
    Challenge,
    Sign,
    Exchange,
    ReplyContext,
    ReplyVerify,
    FinalCheck,
    StorageEntry,
    RequestVerify,
    RequestContext,
    ReadState,
    CasPrepare,
    Commit,
    StorageFinal,
    ReplySign,
    WireRead,
    WireWrite,
    ServiceHandle,
}
const PHASES: [Phase; 17] = [
    Phase::Challenge,
    Phase::Sign,
    Phase::Exchange,
    Phase::ReplyContext,
    Phase::ReplyVerify,
    Phase::FinalCheck,
    Phase::StorageEntry,
    Phase::RequestVerify,
    Phase::RequestContext,
    Phase::ReadState,
    Phase::CasPrepare,
    Phase::Commit,
    Phase::StorageFinal,
    Phase::ReplySign,
    Phase::WireRead,
    Phase::WireWrite,
    Phase::ServiceHandle,
];
impl Phase {
    fn label(self) -> &'static str {
        match self {
            Self::Challenge => "challenge",
            Self::Sign => "sign_self_verify",
            Self::Exchange => "wire_exchange",
            Self::ReplyContext => "reply_context",
            Self::ReplyVerify => "reply_verify",
            Self::FinalCheck => "final_check",
            Self::StorageEntry => "storage_entry",
            Self::RequestVerify => "request_verify",
            Self::RequestContext => "request_context",
            Self::ReadState => "read_state",
            Self::CasPrepare => "cas_prepare",
            Self::Commit => "commit",
            Self::StorageFinal => "storage_final",
            Self::ReplySign => "reply_sign_self_verify",
            Self::WireRead => "wire_read",
            Self::WireWrite => "wire_write",
            Self::ServiceHandle => "service_handle",
        }
    }
}

#[cfg(test)]
thread_local! {
    static CLOCK_ATTEMPTS: Cell<usize> = const { Cell::new(0) };
}
fn now() -> Instant {
    #[cfg(test)]
    CLOCK_ATTEMPTS.with(|count| count.set(count.get().saturating_add(1)));
    Instant::now()
}
#[cfg(target_os = "linux")]
fn thread_cpu_ns() -> Option<u64> {
    #[cfg(test)]
    CLOCK_ATTEMPTS.with(|count| count.set(count.get().saturating_add(1)));
    use rustix::time::{clock_gettime_dynamic, ClockId, DynamicClockId};
    let stamp = clock_gettime_dynamic(DynamicClockId::Known(ClockId::ThreadCPUTime)).ok()?;
    let seconds = u64::try_from(stamp.tv_sec).ok()?;
    let nanos = u64::try_from(stamp.tv_nsec).ok()?;
    if nanos >= 1_000_000_000 {
        return None;
    }
    seconds.checked_mul(1_000_000_000)?.checked_add(nanos)
}
#[cfg(not(target_os = "linux"))]
fn thread_cpu_ns() -> Option<u64> {
    None
}
fn micros(duration: Duration) -> u64 {
    duration.as_micros().min(u64::MAX as u128) as u64
}
struct Stamp {
    wall: Instant,
    thread: ThreadId,
    cpu: Option<u64>,
}
impl Stamp {
    fn start() -> Self {
        Self {
            wall: now(),
            thread: thread::current().id(),
            cpu: thread_cpu_ns(),
        }
    }
    fn elapsed(&self) -> (Instant, u64, Option<u64>) {
        let end = now();
        let cpu = (self.thread == thread::current().id())
            .then(thread_cpu_ns)
            .flatten()
            .and_then(|end| end.checked_sub(self.cpu?));
        (end, micros(end.saturating_duration_since(self.wall)), cpu)
    }
}
#[derive(Clone, Copy)]
struct Cost {
    calls: u16,
    wall_us: u64,
    cpu_ns: Option<u64>,
}
impl Cost {
    const ZERO: Self = Self {
        calls: 0,
        wall_us: 0,
        cpu_ns: Some(0),
    };
}
pub(super) struct Operation {
    kind: Kind,
    started: Stamp,
    until: Instant,
    last: Cell<Option<Phase>>,
    costs: [Cell<Cost>; PHASES.len()],
}
impl Operation {
    pub(super) fn start(enabled: bool, kind: Kind, until: Instant) -> Option<Self> {
        if !enabled {
            return None;
        }
        Some(Self {
            kind,
            started: Stamp::start(),
            until,
            last: Cell::new(None),
            costs: std::array::from_fn(|_| Cell::new(Cost::ZERO)),
        })
    }
    pub(super) fn phase(&self, phase: Phase) -> Guard<'_> {
        self.last.set(Some(phase));
        Guard {
            operation: self,
            phase,
            started: Stamp::start(),
        }
    }
    fn complete(self, ok: bool, code: Option<Code>) -> Option<Record> {
        let (end, elapsed_us, cpu_ns) = self.started.elapsed();
        let deadline_elapsed = end >= self.until;
        if ok && !deadline_elapsed {
            return None;
        }
        Some(Record {
            kind: self.kind,
            ok,
            code,
            deadline_elapsed,
            elapsed_us,
            cpu_ns,
            last: self.last.get(),
            costs: self.costs.map(Cell::into_inner),
        })
    }
    pub(super) fn finish(self, ok: bool, code: Option<Code>) {
        if let Some(record) = self.complete(ok, code) {
            record.emit(&mut std::io::stderr().lock(), &EMITTED);
        }
    }
}
pub(super) struct Guard<'a> {
    operation: &'a Operation,
    phase: Phase,
    started: Stamp,
}
impl Drop for Guard<'_> {
    fn drop(&mut self) {
        let (_, wall_us, cpu_ns) = self.started.elapsed();
        let cell = &self.operation.costs[self.phase as usize];
        let previous = cell.get();
        cell.set(Cost {
            calls: previous.calls.saturating_add(1),
            wall_us: previous.wall_us.saturating_add(wall_us),
            cpu_ns: previous
                .cpu_ns
                .zip(cpu_ns)
                .and_then(|(a, b)| a.checked_add(b)),
        });
    }
}
struct Record {
    kind: Kind,
    ok: bool,
    code: Option<Code>,
    deadline_elapsed: bool,
    elapsed_us: u64,
    cpu_ns: Option<u64>,
    last: Option<Phase>,
    costs: [Cost; PHASES.len()],
}
fn optional_number(value: Option<u64>) -> String {
    value.map_or_else(|| "null".into(), |value| value.to_string())
}
fn optional_label(value: Option<&'static str>) -> String {
    value.map_or_else(|| "null".into(), |value| format!("\"{value}\""))
}
impl Record {
    fn render(&self) -> Option<String> {
        let mut out = format!("{{\"schema\":\"trnm-pq-witness-phase-v1\",\"kind\":\"{}\",\"ok\":{},\"error_code\":{},\"deadline_elapsed\":{},\"elapsed_us\":{},\"cpu_ns\":{},\"last_phase\":{},\"phase_cost_columns\":[\"phase\",\"calls\",\"wall_us\",\"cpu_ns\"],\"phases\":[",
            self.kind.label(), self.ok, optional_label(self.code.map(Code::label)),
            self.deadline_elapsed, self.elapsed_us, optional_number(self.cpu_ns),
            optional_label(self.last.map(Phase::label)));
        let mut first = true;
        for (phase, cost) in PHASES.iter().zip(self.costs) {
            if cost.calls == 0 {
                continue;
            }
            if !first {
                out.push(',');
            }
            first = false;
            write!(
                out,
                "[\"{}\",{},{},{}]",
                phase.label(),
                cost.calls,
                cost.wall_us,
                optional_number(cost.cpu_ns)
            )
            .ok()?;
        }
        out.push_str("]}");
        (out.len() <= MAX_LINE_BYTES).then_some(out)
    }
    fn emit(&self, writer: &mut impl Write, counter: &AtomicUsize) {
        let Some(line) = self.render() else {
            return;
        };
        if counter
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                (value < MAX_RECORDS).then_some(value + 1)
            })
            .is_ok()
        {
            // One bounded write attempt, even on interruption or partial output.
            // A truncated line is rejected by the collector, never retried here.
            let wire = format!("{PREFIX}{line}\n");
            let _ = writer.write(wire.as_bytes());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn every_phase_cost_slot_keeps_its_exact_label() {
        for (index, phase) in PHASES.iter().enumerate() {
            assert_eq!(*phase as usize, index);
        }
    }
    #[test]
    fn inactive_scope_observes_no_clock_and_keeps_original_deadline() {
        let until = Instant::now();
        CLOCK_ATTEMPTS.with(|count| count.set(0));
        assert!(Operation::start(false, Kind::ClientCurrent, until).is_none());
        assert_eq!(CLOCK_ATTEMPTS.with(Cell::get), 0);
        let observation = Operation::start(true, Kind::ClientCurrent, until).unwrap();
        {
            let _phase = observation.phase(Phase::Sign);
        }
        let record = observation.complete(true, None).unwrap();
        assert!(record.ok && record.deadline_elapsed);
        assert_eq!(record.costs[Phase::Sign as usize].calls, 1);
    }
    #[test]
    fn healthy_success_emits_nothing_but_failed_result_is_observed() {
        let until = Instant::now() + Duration::from_secs(30);
        assert!(Operation::start(true, Kind::ClientCas, until)
            .unwrap()
            .complete(true, None)
            .is_none());
        let failure = Operation::start(true, Kind::ClientCas, until)
            .unwrap()
            .complete(false, Some(Code::Deadline))
            .unwrap();
        assert!(!failure.ok && !failure.deadline_elapsed);
    }
    fn maximal_record() -> Record {
        Record {
            kind: Kind::ServiceConnection,
            ok: false,
            code: Some(Code::CommitUncertain),
            deadline_elapsed: true,
            elapsed_us: u64::MAX,
            cpu_ns: None,
            last: Some(Phase::ReplySign),
            costs: [Cost {
                calls: u16::MAX,
                wall_us: u64::MAX,
                cpu_ns: Some(u64::MAX),
            }; PHASES.len()],
        }
    }
    #[test]
    fn fixed_enum_projection_is_bounded_and_unknown_cpu_stays_null() {
        let line = maximal_record().render().unwrap();
        assert!(line.len() <= MAX_LINE_BYTES);
        assert!(line.contains("\"cpu_ns\":null"));
        assert!(line.contains("\"schema\":\"trnm-pq-witness-phase-v1\""));
        assert_eq!(
            line.matches("18446744073709551615").count(),
            1 + 2 * PHASES.len()
        );
        assert!(!line.contains("path") && !line.contains("key") && !line.contains("root"));
    }
    #[test]
    fn output_attempts_have_one_fixed_budget_and_no_write_retry() {
        let counter = AtomicUsize::new(0);
        let mut output = Vec::new();
        let record = maximal_record();
        for _ in 0..(MAX_RECORDS + 4) {
            record.emit(&mut output, &counter);
        }
        assert_eq!(counter.load(Ordering::Relaxed), MAX_RECORDS);
        assert_eq!(
            output.iter().filter(|byte| **byte == b'\n').count(),
            MAX_RECORDS
        );
        struct Refuse(usize, std::io::ErrorKind);
        impl Write for Refuse {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                self.0 += 1;
                Err(self.1.into())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        for kind in [
            std::io::ErrorKind::PermissionDenied,
            std::io::ErrorKind::Interrupted,
        ] {
            let counter = AtomicUsize::new(0);
            let mut writer = Refuse(0, kind);
            record.emit(&mut writer, &counter);
            assert_eq!(writer.0, 1);
            assert_eq!(counter.load(Ordering::Relaxed), 1);
        }
    }
}
