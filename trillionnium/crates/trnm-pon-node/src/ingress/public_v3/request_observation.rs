//! Optional bounded local measurements. Never ledger or transport authority.
use super::work_arithmetic::PublicArithmeticWorkObservation;
use serde::{ser::SerializeStruct, Serialize};
use std::fmt::{self, Write};
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc, Mutex, OnceLock,
};
use std::thread::{self, ThreadId};
use std::time::Instant;
use trnm_protocol::pon_wire::Hash;

pub const MAX_REQUEST_OBSERVATION_RECORDS: usize = 16_384;

const ERROR_DIAGNOSTIC_MESSAGE_BYTES: usize = 96;

/// A bounded copy of the actual Err's Display text and existing kind. The text
/// can be peer-controlled and has no typed-error or local-control authority.
/// Capture uses no heap allocation and never changes Error classification.
#[derive(Clone, Copy, Debug)]
pub struct ObservedErrorDiagnostic {
    kind: &'static str,
    bytes: [u8; ERROR_DIAGNOSTIC_MESSAGE_BYTES],
    len: usize,
    truncated: bool,
}
impl ObservedErrorDiagnostic {
    fn capture(error: &crate::Error) -> Self {
        use crate::ErrorKind;
        let kind = match error.kind() {
            ErrorKind::ProtocolInvalid => "protocol_invalid",
            ErrorKind::Capacity => "capacity",
            ErrorKind::Cancelled => "cancelled",
            ErrorKind::StaleContext => "stale_context",
            ErrorKind::IdentityConflict => "identity_conflict",
            ErrorKind::PolicyRefusal => "policy_refusal",
            ErrorKind::LocalStructure => "local_structure",
            ErrorKind::DependencyUnavailable => "dependency_unavailable",
            ErrorKind::Transport => "transport",
            ErrorKind::Serialization => "serialization",
            ErrorKind::RemoteRefusal => "remote_refusal",
            ErrorKind::Unclassified => "unclassified",
        };
        let mut value = Self {
            kind,
            bytes: [0; ERROR_DIAGNOSTIC_MESSAGE_BYTES],
            len: 0,
            truncated: false,
        };
        // This writer always succeeds, including after truncation. Formatting
        // is diagnostic-only; no parse, retry, cancellation or error conversion.
        let _ = write!(value, "{error}");
        value
    }
}
impl fmt::Write for ObservedErrorDiagnostic {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        if self.truncated {
            return Ok(());
        }
        let mut take = text.len().min(ERROR_DIAGNOSTIC_MESSAGE_BYTES - self.len);
        while !text.is_char_boundary(take) {
            take -= 1;
        }
        self.bytes[self.len..self.len + take].copy_from_slice(&text.as_bytes()[..take]);
        self.len += take;
        self.truncated = take != text.len();
        Ok(())
    }
}
impl Serialize for ObservedErrorDiagnostic {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let message =
            std::str::from_utf8(&self.bytes[..self.len]).map_err(serde::ser::Error::custom)?;
        let mut value = serializer.serialize_struct("ObservedErrorDiagnostic", 3)?;
        value.serialize_field("kind", self.kind)?;
        value.serialize_field("message_prefix", message)?;
        value.serialize_field("message_truncated", &self.truncated)?;
        value.end()
    }
}

/// Versioned additive diagnostic extension. Existing v4 typed codes and phase
/// shapes remain unchanged; old records without this extension remain unknown.
#[derive(Clone, Copy, Debug, Serialize)]
pub struct RequestErrorDiagnostics {
    schema: &'static str,
    has_control_authority: bool,
    messages_are_untrusted: bool,
    message_capacity_bytes: usize,
    pub dispatch: Option<ObservedErrorDiagnostic>,
    pub terminal: Option<ObservedErrorDiagnostic>,
}
impl Default for RequestErrorDiagnostics {
    fn default() -> Self {
        Self {
            schema: "public-v3-request-error-diagnostics-v1",
            has_control_authority: false,
            messages_are_untrusted: true,
            message_capacity_bytes: ERROR_DIAGNOSTIC_MESSAGE_BYTES,
            dispatch: None,
            terminal: None,
        }
    }
}

/// Additive, local settlement facts. The existing CpuSettle span measures the
/// actual call through the original budget/journal result, including refusal.
/// It overlaps the end of the existing dispatch CPU sample; never add the two.
/// An absent extension is unknown/unentered, not a successful settlement.
#[derive(Clone, Copy, Debug, Serialize)]
pub struct PublicCpuSettlementObservation {
    schema: &'static str,
    pub owner_cpu_known: bool,
    pub scoped_worker_cpu_known: bool,
    pub live_paid_cpu_known: bool,
    pub residual_cpu_known: bool,
    pub budget_settled: bool,
    /// None means this operation had no continuous-owner journal scope.
    pub continuous_journal_persisted: Option<bool>,
    has_control_authority: bool,
    interval_is_additive_to_dispatch_cpu: bool,
}
impl PublicCpuSettlementObservation {
    pub(super) fn capture(
        owner_cpu: Option<u64>,
        scoped_worker_cpu: Option<u64>,
        live_paid_cpu: Option<u64>,
        residual_cpu: Option<u64>,
        budget_settled: bool,
        continuous_journal_persisted: Option<bool>,
    ) -> Self {
        Self {
            schema: "public-v3-cpu-settlement-observation-v1",
            owner_cpu_known: owner_cpu.is_some(),
            scoped_worker_cpu_known: scoped_worker_cpu.is_some(),
            live_paid_cpu_known: live_paid_cpu.is_some(),
            residual_cpu_known: residual_cpu.is_some(),
            budget_settled,
            continuous_journal_persisted,
            has_control_authority: false,
            interval_is_additive_to_dispatch_cpu: false,
        }
    }
    pub(super) fn succeeded(&self) -> bool {
        self.owner_cpu_known
            && self.scoped_worker_cpu_known
            && self.live_paid_cpu_known
            && self.residual_cpu_known
            && self.budget_settled
            && self.continuous_journal_persisted != Some(false)
    }
}

/// Fixed local phases. Native/response phases are nested within dispatch; the
/// initial CPU reservation wait precedes dispatch. CpuSettle overlaps the final
/// dispatch CPU sample and continues through budget/journal settlement. None is
/// CPU credit and overlapping samples must not be added together.
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
    AdmissionPrepare,
    Execution,
    CommitOwnerWait,
    Commit,
    CpuWait,
    BodyDecode,
    ResponseEncoding,
    HistoryEpochOpen,
    HistoryEpochClose,
    HistoryImport,
    CpuSettle,
    RootCommitment,
}
impl SubmitPhase {
    const ALL: [Self; 19] = [
        Self::Decode,
        Self::ContextOwnerWait,
        Self::Context,
        Self::Work,
        Self::AdmissionOwnerWait,
        Self::Admission,
        Self::SubmitResult,
        Self::AdmissionPrepare,
        Self::Execution,
        Self::CommitOwnerWait,
        Self::Commit,
        Self::CpuWait,
        Self::BodyDecode,
        Self::ResponseEncoding,
        Self::HistoryEpochOpen,
        Self::HistoryEpochClose,
        Self::HistoryImport,
        Self::CpuSettle,
        Self::RootCommitment,
    ];

    fn parent(self) -> Option<Self> {
        match self {
            Self::AdmissionPrepare | Self::Execution | Self::CommitOwnerWait | Self::Commit => {
                Some(Self::Admission)
            }
            Self::RootCommitment => Some(Self::Execution),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize)]
pub struct SubmitPhaseObservation {
    pub phase: SubmitPhase,
    pub started: bool,
    pub completed: bool,
    pub accepted: Option<bool>,
    /// Exact typed error only. Unclassified errors remain unknown, never success.
    pub error_code: Option<&'static str>,
    /// Same observer-local monotonic epoch; neither timestamp is wall-clock UTC.
    pub started_ns: Option<u64>,
    pub ended_ns: Option<u64>,
    pub wall_ns: Option<u64>,
    /// Only the actual calling thread, excluding scoped M06 workers and reactor
    /// authentication. ResponseEncoding includes real serialization/signing.
    pub thread_cpu_ns: Option<u64>,
    pub parent_phase: Option<SubmitPhase>,
}
impl SubmitPhaseObservation {
    fn new(phase: SubmitPhase) -> Self {
        Self {
            phase,
            started: false,
            completed: false,
            accepted: None,
            error_code: None,
            started_ns: None,
            ended_ns: None,
            wall_ns: None,
            thread_cpu_ns: None,
            parent_phase: phase.parent(),
        }
    }
}

fn submit_phases() -> [SubmitPhaseObservation; 19] {
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

/// Cross-thread/async wait: wall time only, never fabricated thread CPU. The
/// queue interval starts when the paid body is complete and ends at dequeue.
#[derive(Clone, Copy, Debug, Serialize, Default)]
pub struct RequestWaitObservation {
    pub started_ns: Option<u64>,
    pub ended_ns: Option<u64>,
    pub wall_ns: Option<u64>,
    pub completed: bool,
    pub accepted: Option<bool>,
    pub error_code: Option<&'static str>,
}
impl RequestWaitObservation {
    fn start(epoch: Instant, started: Instant) -> Self {
        Self {
            started_ns: started
                .checked_duration_since(epoch)
                .and_then(|elapsed| u64::try_from(elapsed.as_nanos()).ok()),
            ..Self::default()
        }
    }
    fn finish(&mut self, epoch: Instant, result: Option<(bool, Option<&'static str>)>) {
        if self.started_ns.is_none() || (self.ended_ns.is_some() && self.completed) {
            return;
        }
        // A task may be dropped while unwinding a reactor transition before
        // that transition exposes its actual Err. Attach that known outcome
        // without moving the already observed end of the abandoned wait.
        self.ended_ns = self
            .ended_ns
            .or_else(|| u64::try_from(epoch.elapsed().as_nanos()).ok());
        self.wall_ns = self
            .ended_ns
            .zip(self.started_ns)
            .and_then(|(end, start)| end.checked_sub(start));
        self.completed = result.is_some();
        self.accepted = result.map(|(accepted, _)| accepted);
        self.error_code = result.and_then(|(_, error)| error);
    }
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
    /// Present only for the separately signed, explicit arithmetic-fact profile.
    /// The legacy full_work interval still measures actual complete-relation
    /// verification; it must not be interpreted as a fresh arithmetic replay.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub work_arithmetic: Option<PublicArithmeticWorkObservation>,
    pub dispatch_started: bool,
    pub dispatch_accepted: Option<bool>,
    pub dispatch_error_code: Option<&'static str>,
    pub error_diagnostics: RequestErrorDiagnostics,
    pub dispatch_thread_cpu_ns: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu_settlement: Option<PublicCpuSettlementObservation>,
    pub submit_phases: [SubmitPhaseObservation; 19],
    pub challenge_wait: RequestWaitObservation,
    pub grant_wait: RequestWaitObservation,
    pub paid_task_queue_wait: RequestWaitObservation,
    pub response_write: RequestWaitObservation,
    pub terminal_phase: Option<&'static str>,
    pub terminal_error_code: Option<&'static str>,
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
            work_arithmetic: None,
            dispatch_started: false,
            dispatch_accepted: None,
            dispatch_error_code: None,
            error_diagnostics: RequestErrorDiagnostics::default(),
            dispatch_thread_cpu_ns: None,
            cpu_settlement: None,
            submit_phases: submit_phases(),
            challenge_wait: RequestWaitObservation::default(),
            grant_wait: RequestWaitObservation::default(),
            paid_task_queue_wait: RequestWaitObservation::default(),
            response_write: RequestWaitObservation::default(),
            terminal_phase: None,
            terminal_error_code: None,
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
#[derive(Clone, Copy, Default)]
struct TaskProgress {
    full_work_started: bool,
    full_work_accepted: Option<bool>,
    full_work_thread_cpu_ns: Option<u64>,
    work_arithmetic: Option<PublicArithmeticWorkObservation>,
    dispatch_started: bool,
    dispatch_accepted: Option<bool>,
    dispatch_error_code: Option<&'static str>,
    dispatch_error_diagnostic: Option<ObservedErrorDiagnostic>,
    dispatch_thread_cpu_ns: Option<u64>,
    cpu_settlement: Option<PublicCpuSettlementObservation>,
    paid_task_queue_wait: RequestWaitObservation,
}
struct Cell {
    row: Mutex<PublicRequestObservation>,
    task: Mutex<TaskProgress>,
    phases: PhaseRecorder,
    failed: AtomicBool,
    connection_closed: AtomicBool,
    task_created: AtomicBool,
    task_closed: AtomicBool,
}

struct Inner {
    epoch: Instant,
    capacity: usize,
    rows: Box<[OnceLock<Arc<Cell>>]>,
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
    // Retained OR field: true in v3 because response signing is included. The
    // separate flags below prevent interpreting it as reactor CPU coverage.
    pub cpu_includes_reactor_authentication_or_response_signing: bool,
    pub cpu_includes_reactor_authentication: bool,
    pub dispatch_cpu_includes_paid_body_decode: bool,
    pub dispatch_cpu_includes_response_signing: bool,
    pub submit_phase_cpu_excludes_scoped_workers: bool,
    pub phase_parent_links_are_inclusive: bool,
    pub cpu_wait_is_outside_dispatch: bool,
    pub monotonic_epoch_is_observer_local: bool,
    pub stream_bytes_are_physical_network_bytes: bool,
}

impl PublicRequestObservationSnapshot {
    /// Check retained measurement coverage, not service success or consensus.
    /// Use after service/worker joins: a live snapshot is not an atomic view.
    pub fn coverage_complete(&self) -> bool {
        self.records_not_retained == 0
            && self.measurement_failures == 0
            && !self.counter_overflow
            && self.accepted_connections_seen == self.records.len() as u64
            && self
                .records
                .iter()
                .all(|row| row.complete && !row.observation_failed)
    }
}

impl PublicRequestObserver {
    pub fn new(capacity: usize) -> super::Result<Self> {
        super::ensure(
            (1..=MAX_REQUEST_OBSERVATION_RECORDS).contains(&capacity),
            "PUBLIC_OBSERVATION_CAPACITY",
        )?;
        Ok(Self(Arc::new(Inner {
            epoch: Instant::now(),
            capacity,
            rows: (0..capacity).map(|_| OnceLock::new()).collect(),
            seen: AtomicU64::new(0),
            omitted: AtomicU64::new(0),
            failures: AtomicU64::new(0),
            counter_overflow: AtomicBool::new(false),
        })))
    }

    /// Prefer after actual service/worker joins. A live snapshot is explicitly incomplete.
    pub fn snapshot(&self) -> PublicRequestObservationSnapshot {
        let mut records = Vec::new();
        // Registration publishes each slot once. Reading another record must
        // never hold a registry lock that can make an accepted connection vanish.
        for cell in self.0.rows.iter().filter_map(OnceLock::get) {
            if let Ok(row) = cell.row.lock() {
                let mut value = row.clone();
                match cell.task.lock() {
                    Ok(task) => {
                        value.full_work_started = task.full_work_started;
                        value.full_work_accepted = task.full_work_accepted;
                        value.full_work_thread_cpu_ns = task.full_work_thread_cpu_ns;
                        value.work_arithmetic = task.work_arithmetic;
                        value.dispatch_started = task.dispatch_started;
                        value.dispatch_accepted = task.dispatch_accepted;
                        value.dispatch_error_code = task.dispatch_error_code;
                        value.error_diagnostics.dispatch = task.dispatch_error_diagnostic;
                        value.dispatch_thread_cpu_ns = task.dispatch_thread_cpu_ns;
                        value.cpu_settlement = task.cpu_settlement;
                        value.paid_task_queue_wait = task.paid_task_queue_wait;
                    }
                    Err(_) => {
                        cell.failed.store(true, Ordering::Release);
                        self.0.count(&self.0.failures);
                    }
                }
                let (phases, phase_failures) = cell.phases.snapshot();
                value.submit_phases = phases;
                value.connection_closed = cell.connection_closed.load(Ordering::Acquire);
                value.task_created = cell.task_created.load(Ordering::Acquire);
                value.task_closed = cell.task_closed.load(Ordering::Acquire);
                value.observation_failed =
                    cell.failed.load(Ordering::Acquire) || phase_failures != 0;
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
        PublicRequestObservationSnapshot {
            schema: "public-v3-local-request-resource-observation-v4",
            capacity: self.0.capacity,
            accepted_connections_seen: self.0.seen.load(Ordering::Acquire),
            records_not_retained: self.0.omitted.load(Ordering::Acquire),
            measurement_failures: self
                .0
                .rows
                .iter()
                .filter_map(OnceLock::get)
                .fold(self.0.failures.load(Ordering::Acquire), |total, cell| {
                    total.saturating_add(cell.phases.failures())
                }),
            counter_overflow: self.0.counter_overflow.load(Ordering::Acquire),
            records,
            observation_has_consensus_authority: false,
            cpu_intervals_are_nested_not_additive: true,
            cpu_includes_reactor_authentication_or_response_signing: true,
            cpu_includes_reactor_authentication: false,
            dispatch_cpu_includes_paid_body_decode: true,
            dispatch_cpu_includes_response_signing: true,
            submit_phase_cpu_excludes_scoped_workers: true,
            phase_parent_links_are_inclusive: true,
            cpu_wait_is_outside_dispatch: true,
            monotonic_epoch_is_observer_local: true,
            stream_bytes_are_physical_network_bytes: false,
        }
    }

    pub(super) fn connection(&self) -> Option<ConnectionObservation> {
        // The checked counter reserves a unique slot before publication. It
        // never wraps, reuses a record or waits for a concurrent snapshot.
        let slot = match self
            .0
            .seen
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |seen| {
                seen.checked_add(1)
            }) {
            Ok(index) => usize::try_from(index)
                .ok()
                .and_then(|index| self.0.rows.get(index)),
            Err(_) => {
                self.0.counter_overflow.store(true, Ordering::Release);
                None
            }
        };
        if let Some(slot) = slot {
            let cell = Arc::new(Cell {
                row: Mutex::new(PublicRequestObservation::new()),
                task: Mutex::new(TaskProgress::default()),
                phases: PhaseRecorder::new(self.0.epoch),
                failed: AtomicBool::new(false),
                connection_closed: AtomicBool::new(false),
                task_created: AtomicBool::new(false),
                task_closed: AtomicBool::new(false),
            });
            if slot.set(cell.clone()).is_ok() {
                return Some(ConnectionObservation {
                    cell,
                    inner: self.0.clone(),
                    has_wait_observation: AtomicBool::new(false),
                });
            }
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
    has_wait_observation: AtomicBool,
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
                r.response_write
                    .finish(self.inner.epoch, Some((true, None)));
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
    pub(super) fn terminal_error(&self, phase: &'static str, error: &crate::Error) {
        let code = error.code().map(crate::ErrorCode::as_str);
        self.handle().update(|r| {
            r.terminal_phase = Some(phase);
            r.terminal_error_code = code;
            r.error_diagnostics.terminal = Some(ObservedErrorDiagnostic::capture(error));
            r.challenge_wait
                .finish(self.inner.epoch, Some((false, code)));
            r.grant_wait.finish(self.inner.epoch, Some((false, code)));
            r.response_write
                .finish(self.inner.epoch, Some((false, code)));
            true
        });
        self.handle().update_task(|r| {
            r.paid_task_queue_wait
                .finish(self.inner.epoch, Some((false, code)));
        });
    }
    pub(super) fn pending_started(&self, grant: bool, entered: Instant) {
        self.has_wait_observation.store(true, Ordering::Release);
        self.handle().update(|r| {
            let wait = if grant {
                &mut r.grant_wait
            } else {
                &mut r.challenge_wait
            };
            *wait = RequestWaitObservation::start(self.inner.epoch, entered);
            true
        });
    }
    pub(super) fn pending_granted(&self, grant: bool) {
        self.handle().update(|r| {
            let wait = if grant {
                &mut r.grant_wait
            } else {
                &mut r.challenge_wait
            };
            wait.finish(self.inner.epoch, Some((true, None)));
            true
        });
    }
    pub(super) fn response_started(&self) {
        self.has_wait_observation.store(true, Ordering::Release);
        self.handle().update(|r| {
            r.response_write = RequestWaitObservation::start(self.inner.epoch, Instant::now());
            true
        });
    }
    pub(super) fn task(&self) -> TaskObservation {
        self.cell.task_created.store(true, Ordering::Release);
        TaskObservation {
            network: Some(self.handle()),
            phases: self.cell.phases.clone(),
        }
    }
}
impl Drop for ConnectionObservation {
    fn drop(&mut self) {
        if self.has_wait_observation.load(Ordering::Acquire) {
            self.handle().update(|r| {
                r.challenge_wait.finish(self.inner.epoch, None);
                r.grant_wait.finish(self.inner.epoch, None);
                r.response_write.finish(self.inner.epoch, None);
                true
            });
        }
        self.cell.connection_closed.store(true, Ordering::Release);
    }
}

/// The same bounded phase recorder serves a network task and an explicitly
/// observed local History packet. Local packets create no connection or CPU
/// account and do not enter the listener's accepted-connection denominator.
pub(in crate::ingress) struct TaskObservation {
    network: Option<Handle>,
    phases: PhaseRecorder,
}
impl TaskObservation {
    pub(in crate::ingress) fn local(epoch: Instant) -> Self {
        Self {
            network: None,
            phases: PhaseRecorder::new(epoch),
        }
    }
    pub(in crate::ingress) fn phase_snapshot(&self) -> ([SubmitPhaseObservation; 19], u64) {
        self.phases.snapshot()
    }
    pub(in crate::ingress) fn measurement_failed(&self) {
        self.phases.failed();
    }
    pub(in crate::ingress) fn phase(&self, phase: SubmitPhase) -> SubmitPhaseGuard<'_> {
        self.phases.phase(phase)
    }
    fn update_task(&self, change: impl FnOnce(&mut TaskProgress)) {
        if let Some(network) = &self.network {
            network.update_task(change);
        }
    }
    pub(super) fn queue_started(&self, started: Instant) {
        if let Some(network) = &self.network {
            network.update_task(|r| {
                r.paid_task_queue_wait =
                    RequestWaitObservation::start(network.inner.epoch, started);
            });
        }
    }
    pub(super) fn queue_finished<T>(&self, result: &crate::Result<T>) {
        if let Some(network) = &self.network {
            let code = result
                .as_ref()
                .err()
                .and_then(crate::Error::code)
                .map(crate::ErrorCode::as_str);
            network.update_task(|r| {
                r.paid_task_queue_wait
                    .finish(network.inner.epoch, Some((result.is_ok(), code)));
            });
        }
    }
    pub(super) fn dispatch_started(&self) {
        self.update_task(|r| {
            r.dispatch_started = true;
        });
    }
    pub(super) fn dispatch_finished(&self, cpu: Option<u64>, accepted: bool) {
        self.update_task(|r| {
            r.dispatch_thread_cpu_ns = cpu;
            r.dispatch_accepted = Some(accepted);
        });
    }
    pub(super) fn settlement_finished(&self, actual: PublicCpuSettlementObservation) {
        self.update_task(|r| {
            if r.cpu_settlement.is_some() {
                self.measurement_failed();
            } else {
                r.cpu_settlement = Some(actual);
            }
        });
    }
    pub(super) fn dispatch_error(&self, error: &crate::Error) {
        self.update_task(|r| {
            r.dispatch_error_code = error.code().map(crate::ErrorCode::as_str);
            r.dispatch_error_diagnostic = Some(ObservedErrorDiagnostic::capture(error));
        });
    }
    pub(super) fn work_started(&self) {
        self.update_task(|r| {
            r.full_work_started = true;
        });
    }
    pub(super) fn work_arithmetic(&self, observation: PublicArithmeticWorkObservation) {
        self.update_task(|r| {
            r.work_arithmetic = Some(observation);
        });
    }
    pub(super) fn work_finished(&self, cpu: Option<u64>, accepted: bool) {
        self.update_task(|r| {
            r.full_work_thread_cpu_ns = cpu;
            r.full_work_accepted = Some(accepted);
        });
    }
}

#[derive(Clone)]
struct PhaseRecorder(Arc<PhaseRecorderInner>);
struct PhaseRecorderInner {
    epoch: Instant,
    rows: Mutex<[SubmitPhaseObservation; 19]>,
    failures: AtomicU64,
}
impl PhaseRecorder {
    fn new(epoch: Instant) -> Self {
        Self(Arc::new(PhaseRecorderInner {
            epoch,
            rows: Mutex::new(submit_phases()),
            failures: AtomicU64::new(0),
        }))
    }
    fn failed(&self) {
        // The diagnostic counter saturates; it never becomes service credit.
        let _ = self
            .0
            .failures
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                Some(n.saturating_add(1))
            });
    }
    fn failures(&self) -> u64 {
        self.0.failures.load(Ordering::Acquire)
    }
    fn update(&self, change: impl FnOnce(&mut [SubmitPhaseObservation; 19])) {
        match self.0.rows.try_lock() {
            Ok(mut rows) => change(&mut rows),
            Err(_) => self.failed(),
        }
    }
    fn snapshot(&self) -> ([SubmitPhaseObservation; 19], u64) {
        let rows = match self.0.rows.lock() {
            Ok(rows) => *rows,
            Err(_) => {
                self.failed();
                submit_phases()
            }
        };
        (rows, self.failures())
    }
    fn phase(&self, phase: SubmitPhase) -> SubmitPhaseGuard<'_> {
        let started = Instant::now();
        let started_ns = started
            .checked_duration_since(self.0.epoch)
            .and_then(|elapsed| u64::try_from(elapsed.as_nanos()).ok());
        let mut recordable = false;
        self.update(|rows| {
            let row = &mut rows[phase as usize];
            if row.started {
                // Fixed slots are single-entry. Never overwrite a previous
                // failure with a retry's success or hide an unbounded loop.
                self.failed();
            } else {
                row.started = true;
                row.started_ns = started_ns;
                recordable = true;
            }
        });
        SubmitPhaseGuard {
            observation: self,
            phase,
            started,
            cpu: ThreadCpuStamp::start(),
            accepted: None,
            error_code: None,
            recordable,
        }
    }
}

/// Drop retains an unfinished/panicked phase with unknown outcome. Measurement
/// failure never changes the request result, cancellation or resource account.
pub(in crate::ingress) struct SubmitPhaseGuard<'a> {
    observation: &'a PhaseRecorder,
    phase: SubmitPhase,
    started: Instant,
    cpu: Option<ThreadCpuStamp>,
    accepted: Option<bool>,
    error_code: Option<&'static str>,
    recordable: bool,
}
impl SubmitPhaseGuard<'_> {
    pub(in crate::ingress) fn finish(mut self, accepted: bool) {
        self.accepted = Some(accepted);
    }
    pub(in crate::ingress) fn finish_result<T>(mut self, result: &crate::Result<T>) {
        self.accepted = Some(result.is_ok());
        self.error_code = result
            .as_ref()
            .err()
            .and_then(crate::Error::code)
            .map(crate::ErrorCode::as_str);
    }
}
impl Drop for SubmitPhaseGuard<'_> {
    fn drop(&mut self) {
        if !self.recordable {
            return;
        }
        let ended = Instant::now();
        let wall = ended
            .checked_duration_since(self.started)
            .and_then(|elapsed| u64::try_from(elapsed.as_nanos()).ok());
        let ended_ns = ended
            .checked_duration_since(self.observation.0.epoch)
            .and_then(|elapsed| u64::try_from(elapsed.as_nanos()).ok());
        let cpu = self.cpu.take().and_then(ThreadCpuStamp::finish);
        self.observation.update(|rows| {
            let phase = &mut rows[self.phase as usize];
            if phase.ended_ns.is_some() {
                self.observation.failed();
                return;
            }
            phase.completed = self.accepted.is_some();
            phase.accepted = self.accepted;
            phase.error_code = self.error_code;
            phase.ended_ns = ended_ns;
            phase.wall_ns = wall;
            phase.thread_cpu_ns = cpu;
        });
    }
}
impl Drop for TaskObservation {
    fn drop(&mut self) {
        if let Some(network) = &self.network {
            network.update_task(|r| r.paid_task_queue_wait.finish(network.inner.epoch, None));
            network.cell.task_closed.store(true, Ordering::Release);
        }
    }
}

#[derive(Clone)]
pub(in crate::ingress) struct ThreadCpuStamp {
    thread: ThreadId,
    ns: u64,
}
impl ThreadCpuStamp {
    pub(in crate::ingress) fn start() -> Option<Self> {
        Some(Self {
            thread: thread::current().id(),
            ns: thread_cpu_ns()?,
        })
    }
    pub(in crate::ingress) fn finish(self) -> Option<u64> {
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
    fn error_diagnostics_preserve_typed_identity_origin_and_bounded_utf8() {
        for (error, expected_kind) in [
            (crate::Error::from("ROOT"), "unclassified"),
            (crate::Error::from("WORK:Transcript"), "unclassified"),
            (crate::Error::from("PUBLIC_REQUEST_CANCELLED"), "cancelled"),
            (crate::Error::remote("ROOT"), "remote_refusal"),
            (
                crate::Error::from("ROOT").local_integrity(),
                "local_structure",
            ),
            (
                crate::Error::from(std::io::Error::other("ROOT")),
                "transport",
            ),
        ] {
            let before = (
                error.code(),
                error.kind(),
                error.requires_owner_stop(),
                error.to_string(),
            );
            let observed = serde_json::to_value(ObservedErrorDiagnostic::capture(&error)).unwrap();
            assert_eq!(observed["kind"], expected_kind);
            assert_eq!(observed["message_prefix"], before.3);
            assert_eq!(observed["message_truncated"], false);
            assert_eq!(
                (
                    error.code(),
                    error.kind(),
                    error.requires_owner_stop(),
                    error.to_string()
                ),
                before
            );
            if error.kind() == crate::ErrorKind::RemoteRefusal {
                assert_eq!(observed["kind"], "remote_refusal");
                assert_eq!(error.code(), None);
                assert!(!error.requires_owner_stop());
            }
        }
        for (message, expected, truncated) in [
            ("x".repeat(96), "x".repeat(96), false),
            ("x".repeat(97), "x".repeat(96), true),
            (format!("{}界tail", "x".repeat(95)), "x".repeat(95), true),
        ] {
            let observed =
                serde_json::to_value(ObservedErrorDiagnostic::capture(&message.into())).unwrap();
            assert_eq!(observed["message_prefix"], expected);
            assert_eq!(observed["message_truncated"], truncated);
            assert!(
                observed["message_prefix"].as_str().unwrap().len()
                    <= ERROR_DIAGNOSTIC_MESSAGE_BYTES
            );
        }
    }

    #[test]
    fn dispatch_diagnostic_survives_distinct_terminal_cancellation_without_changing_codes() {
        let observer = PublicRequestObserver::new(2).unwrap();
        let connection = observer.connection().unwrap();
        let task = connection.task();
        task.dispatch_started();
        let error = crate::Error::from("ROOT");
        task.dispatch_error(&error);
        task.dispatch_finished(Some(1), false);
        connection.terminal_error("work", &crate::Error::from("PUBLIC_EOF"));
        drop(task);
        drop(connection);
        let abandoned = observer.connection().unwrap();
        drop(abandoned.task());
        drop(abandoned);
        let snapshot = observer.snapshot();
        assert!(snapshot.coverage_complete());
        let row = &snapshot.records[0];
        assert_eq!(row.dispatch_accepted, Some(false));
        assert_eq!(row.dispatch_error_code, None);
        assert_eq!(row.terminal_error_code, Some("PUBLIC_EOF"));
        let diagnostics = serde_json::to_value(row.error_diagnostics).unwrap();
        assert_eq!(diagnostics["dispatch"]["kind"], "unclassified");
        assert_eq!(diagnostics["dispatch"]["message_prefix"], "ROOT");
        assert_eq!(diagnostics["dispatch"]["message_truncated"], false);
        assert_eq!(diagnostics["terminal"]["message_prefix"], "PUBLIC_EOF");
        assert!(!error.requires_owner_stop());
        let unknown = &snapshot.records[1];
        assert!(unknown.error_diagnostics.dispatch.is_none());
        assert!(unknown.error_diagnostics.terminal.is_none());
        assert_eq!(unknown.dispatch_accepted, None);
        assert_eq!(unknown.terminal_error_code, None);
    }

    #[test]
    fn queue_cancellation_keeps_original_identity_and_dropped_wait_interval() {
        let observer = PublicRequestObserver::new(1).unwrap();
        let connection = observer.connection().unwrap();
        connection.identity(71);
        connection.request(1, [42; 32]);
        let task = connection.task();
        task.queue_started(Instant::now());
        drop(task); // Transition owns the Err; its moved task drops first.
        let before = observer.snapshot().records[0].paid_task_queue_wait;
        assert_eq!(before.accepted, None);
        connection.terminal_error("queue", &"PUBLIC_REQUEST_CANCELLED".into());
        drop(connection);
        let snapshot = observer.snapshot();
        assert!(snapshot.coverage_complete());
        let row = &snapshot.records[0];
        assert_eq!(row.connection_id, Some(71));
        assert_eq!(row.body_digest, Some([42; 32]));
        let queue = row.paid_task_queue_wait;
        assert_eq!(queue.ended_ns, before.ended_ns);
        assert_eq!(queue.wall_ns, before.wall_ns);
        assert!(queue.completed);
        assert_eq!(queue.accepted, Some(false));
        assert_eq!(queue.error_code, Some("PUBLIC_REQUEST_CANCELLED"));
        assert_eq!(row.grant_wait.started_ns, None);
        assert_eq!(row.grant_wait.wall_ns, None);
        assert!(row.submit_phases.iter().all(|phase| !phase.started));
    }

    #[test]
    fn error_diagnostic_contention_does_not_block_or_reclassify_rejection() {
        let observer = PublicRequestObserver::new(1).unwrap();
        let connection = observer.connection().unwrap();
        let task = connection.task();
        let held = connection.cell.task.lock().unwrap();
        let error = crate::Error::from("ROOT");
        task.dispatch_error(&error);
        assert_eq!(error.to_string(), "ROOT");
        assert_eq!(error.code(), None);
        assert!(!error.requires_owner_stop());
        drop(held);
        drop(task);
        drop(connection);
        let snapshot = observer.snapshot();
        assert_eq!(snapshot.measurement_failures, 1);
        assert!(snapshot.records[0].observation_failed);
        assert!(!snapshot.records[0].complete);
        assert!(snapshot.records[0].error_diagnostics.dispatch.is_none());
    }

    #[test]
    fn fixed_phase_slots_never_overwrite_a_previous_failure_with_a_retry() {
        for (message, expected) in [
            ("ROOT", None),
            ("PUBLIC_REQUEST_CANCELLED", Some("PUBLIC_REQUEST_CANCELLED")),
        ] {
            let observer = TaskObservation::local(Instant::now());
            observer
                .phase(SubmitPhase::Work)
                .finish_result(&Err::<(), _>(message.into()));
            let before = observer.phase_snapshot().0[SubmitPhase::Work as usize];
            observer.phase(SubmitPhase::Work).finish(true);
            let (phases, failures) = observer.phase_snapshot();
            let after = phases[SubmitPhase::Work as usize];
            assert_eq!(failures, 1);
            assert_eq!(after.accepted, Some(false));
            assert_eq!(after.error_code, expected);
            assert_eq!(after.started_ns, before.started_ns);
            assert_eq!(after.ended_ns, before.ended_ns);
            assert_eq!(after.thread_cpu_ns, before.thread_cpu_ns);
        }
    }

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
            "public-v3-local-request-resource-observation-v4"
        );
        assert!(snapshot.cpu_includes_reactor_authentication_or_response_signing);
        assert!(!snapshot.cpu_includes_reactor_authentication);
        assert!(snapshot.dispatch_cpu_includes_paid_body_decode);
        assert!(snapshot.dispatch_cpu_includes_response_signing);
        assert!(snapshot.submit_phase_cpu_excludes_scoped_workers);
        assert!(snapshot.cpu_intervals_are_nested_not_additive);
        assert!(!snapshot.observation_has_consensus_authority);
        assert_eq!(snapshot.measurement_failures, 0);
        let row = &snapshot.records[0];
        assert!(row.complete);
        assert_eq!(row.submit_phases.len(), SubmitPhase::ALL.len());
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
        let guard = connection.cell.phases.0.rows.lock().unwrap();
        let result = crate::ingress::observe_submit_phase(Some(&task), SubmitPhase::Work, || {
            Err::<(), _>(crate::Error::from("FRAME_DEADLINE"))
        });
        assert_eq!(result.unwrap_err().to_string(), "FRAME_DEADLINE");
        drop(guard);
        drop(task);
        drop(connection);
        let snapshot = observer.snapshot();
        assert_eq!(snapshot.measurement_failures, 1);
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
            crate::ingress::SubmitDispatchContext {
                observation: Some(&task),
                public_proof_before_unowned_task: true,
                ..crate::ingress::SubmitDispatchContext::default()
            },
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
            crate::ingress::SubmitDispatchContext {
                observation: Some(&task),
                public_proof_before_unowned_task: true,
                ..crate::ingress::SubmitDispatchContext::default()
            },
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
            crate::ingress::SubmitDispatchContext {
                observation: Some(&task),
                public_proof_before_unowned_task: true,
                ..crate::ingress::SubmitDispatchContext::default()
            },
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
        for phase in &snapshot.records[1].submit_phases {
            let expected = matches!(
                phase.phase,
                SubmitPhase::Decode
                    | SubmitPhase::ContextOwnerWait
                    | SubmitPhase::Context
                    | SubmitPhase::Work
                    | SubmitPhase::AdmissionOwnerWait
                    | SubmitPhase::Admission
                    | SubmitPhase::SubmitResult
                    | SubmitPhase::AdmissionPrepare
                    | SubmitPhase::Execution
                    | SubmitPhase::CommitOwnerWait
                    | SubmitPhase::Commit
                    | SubmitPhase::RootCommitment
            );
            assert_eq!(phase.started, expected, "{:?}", phase.phase);
            assert_eq!(phase.completed, expected);
            assert_eq!(phase.accepted, expected.then_some(true));
            assert_eq!(phase.wall_ns.is_some(), expected);
            if expected {
                assert_eq!(
                    phase.ended_ns.unwrap() - phase.started_ns.unwrap(),
                    phase.wall_ns.unwrap()
                );
            }
        }
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
    fn registry_snapshot_does_not_omit_unrelated_accepted_connections() {
        let observer = PublicRequestObserver::new(2).unwrap();
        let first = observer.connection().unwrap();
        first.identity(1);
        let cell = first.cell.clone();
        drop(first);

        // Stop the live reader inside the first record. Its row lock proves
        // that it has entered the snapshot; scheduling a thread alone does not.
        let task_guard = cell.task.lock().unwrap();
        let reader = observer.clone();
        let snapshot_thread = thread::spawn(move || reader.snapshot());
        let deadline = Instant::now() + std::time::Duration::from_secs(5);
        let reader_entered = loop {
            match cell.row.try_lock() {
                Err(std::sync::TryLockError::WouldBlock) => break true,
                Err(std::sync::TryLockError::Poisoned(_)) => panic!("unexpected poisoned row"),
                Ok(guard) => drop(guard),
            }
            if Instant::now() >= deadline {
                break false;
            }
            thread::yield_now();
        };
        let second = observer.connection();
        let second_retained = second.is_some();
        if let Some(second) = second {
            second.identity(2);
            drop(second);
        }
        drop(task_guard);
        snapshot_thread.join().unwrap();

        assert!(
            reader_entered,
            "live snapshot did not enter the held record"
        );
        assert!(second_retained, "live snapshot omitted another connection");
        let closed = observer.snapshot();
        assert_eq!(closed.accepted_connections_seen, 2);
        assert_eq!(closed.records_not_retained, 0);
        assert_eq!(closed.measurement_failures, 0);
        assert!(!closed.counter_overflow);
        assert_eq!(closed.records.len(), 2);
        assert!(closed.records.iter().all(|row| row.complete));
        assert_eq!(closed.records[0].connection_id, Some(1));
        assert_eq!(closed.records[1].connection_id, Some(2));
        assert!(closed.coverage_complete());
    }

    #[test]
    fn registry_concurrent_connections_are_retained_once_within_capacity() {
        const THREADS: usize = 8;
        const PER_THREAD: usize = 256;
        const CAPACITY: usize = 512;
        let observer = PublicRequestObserver::new(CAPACITY).unwrap();
        let start = Arc::new(Barrier::new(THREADS));
        let workers: Vec<_> = (0..THREADS)
            .map(|worker| {
                let observer = observer.clone();
                let start = start.clone();
                thread::spawn(move || {
                    start.wait();
                    let mut retained = 0;
                    for offset in 0..PER_THREAD {
                        if let Some(connection) = observer.connection() {
                            connection.identity((worker * PER_THREAD + offset + 1) as u64);
                            retained += 1;
                        }
                    }
                    retained
                })
            })
            .collect();
        let retained: usize = workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .sum();
        let closed = observer.snapshot();
        assert_eq!(retained, CAPACITY);
        assert_eq!(
            closed.accepted_connections_seen,
            (THREADS * PER_THREAD) as u64
        );
        assert_eq!(closed.records.len(), CAPACITY);
        assert_eq!(
            closed.records_not_retained,
            (THREADS * PER_THREAD - CAPACITY) as u64
        );
        assert_eq!(closed.measurement_failures, 0);
        assert!(!closed.counter_overflow);
        assert!(closed.records.iter().all(|row| row.complete));
        let identities: std::collections::BTreeSet<_> = closed
            .records
            .iter()
            .map(|row| row.connection_id.unwrap())
            .collect();
        assert_eq!(identities.len(), CAPACITY);
        assert!(!closed.coverage_complete());
    }

    #[test]
    fn coverage_rejects_a_poisoned_record_even_when_retained_records_are_complete() {
        let observer = PublicRequestObserver::new(2).unwrap();
        let damaged = observer.connection().unwrap();
        let healthy = observer.connection().unwrap();
        healthy.identity(2);
        drop(healthy);
        let cell = damaged.cell.clone();
        let failed_writer = thread::spawn(move || {
            let _guard = cell.row.lock().unwrap();
            panic!("injected observation writer failure");
        });
        assert!(failed_writer.join().is_err());
        drop(damaged);

        let captured = observer.snapshot();
        assert_eq!(captured.accepted_connections_seen, 2);
        assert_eq!(captured.records.len(), 1);
        assert_eq!(captured.records_not_retained, 0);
        assert_eq!(captured.measurement_failures, 1);
        assert!(!captured.counter_overflow);
        assert_eq!(captured.records[0].connection_id, Some(2));
        assert!(captured.records[0].complete);
        assert!(!captured.records[0].observation_failed);
        assert!(!captured.coverage_complete());
    }

    #[test]
    fn bounded_records_and_saturating_counter_overflow_remain_explicit() {
        assert!(PublicRequestObserver::new(0).is_err());
        assert!(PublicRequestObserver::new(MAX_REQUEST_OBSERVATION_RECORDS).is_ok());
        assert!(PublicRequestObserver::new(MAX_REQUEST_OBSERVATION_RECORDS + 1).is_err());
        let observer = PublicRequestObserver::new(2).unwrap();
        let first = observer.connection().unwrap();
        first.identity(1);
        drop(first);
        let second = observer.connection().unwrap();
        second.identity(2);
        drop(second);
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
        assert_eq!(snapshot.records.len(), 2);
        assert_eq!(snapshot.records[0].connection_id, Some(1));
        assert_eq!(snapshot.records[1].connection_id, Some(2));
        assert!(!snapshot.coverage_complete());
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
