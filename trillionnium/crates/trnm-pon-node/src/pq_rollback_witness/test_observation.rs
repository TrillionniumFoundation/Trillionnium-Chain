//! Test-only bounded measurements. No request bytes, roots, keys, signatures or
//! error text enter a record; no measurement can authorize or refuse work.
use serde::Serialize;
use serde_json::{json, Value};
use std::{
    cell::{Cell, RefCell},
    fmt::{self, Write as _},
    io::{self, Read, Write},
    marker::PhantomData,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    rc::Rc,
    sync::{
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    thread::{self, ThreadId},
    time::Instant,
};
use trnm_crypto_primitives::pq_auth::PqNativeError;

/// Preserve the action-local question-mark and return boundary and its exact result.
pub(crate) fn invoke<T>(action: impl FnOnce() -> crate::Result<T>) -> crate::Result<T> {
    action()
}

pub(crate) const PREFIX: &str = "TRNM_PQ_PHASE_DIAGNOSTIC ";
pub(crate) const CHILD_FILE: &str = "witness-phase-diagnostic.jsonl";
pub(crate) const CHILD_PENDING: &str = "witness-phase-diagnostic.pending";
const MAX_RECORDS: usize = 8;
const MAX_LINE_BYTES: usize = 32 * 1024;
const MAX_PROCESS_LOG_BYTES: usize = 256 * 1024;
static LOG_REMAINING: AtomicUsize = AtomicUsize::new(MAX_PROCESS_LOG_BYTES);
static LOG_LIMIT_REPORTED: AtomicBool = AtomicBool::new(false);
thread_local! {
    static ACTIVE: RefCell<Option<Arc<Recorder>>> = const { RefCell::new(None) };
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Kind {
    ClientCurrent,
    ClientCas,
    ClientAdvance,
    ServiceCurrent,
    ServiceCas,
    ServiceUnknown,
    MutationBegin,
    MutationCommit,
    TcpRequest,
    FixtureTransport,
    WitnessConnection,
}
#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Phase {
    ClientEntry,
    ChallengeAndBody,
    RequestSignIncludingSelfVerify,
    BeforeSendHook,
    BeforeTransport,
    Transport,
    ReplyContext,
    ClientReplyVerify,
    ClientFinal,
    ServiceEntryAndStorage,
    ServiceRequestContext,
    ServiceRequestVerify,
    ServiceRead,
    ServiceCas,
    ServiceCommit,
    ServiceFinalStorage,
    ReplySignIncludingSelfVerify,
    ServiceFinal,
    MutationBegin,
    LocalCheckpoint,
    Current,
    ProtectedRoot,
    AdvanceCas,
    LocalCommit,
    FinalLiveCheck,
    TcpReadRequest,
    TcpHandle,
    TcpWriteFrame,
    FixtureServiceMutex,
    WitnessRead,
    WitnessHandle,
    WitnessWrite,
}
const PHASES: [Phase; 32] = [
    Phase::ClientEntry,
    Phase::ChallengeAndBody,
    Phase::RequestSignIncludingSelfVerify,
    Phase::BeforeSendHook,
    Phase::BeforeTransport,
    Phase::Transport,
    Phase::ReplyContext,
    Phase::ClientReplyVerify,
    Phase::ClientFinal,
    Phase::ServiceEntryAndStorage,
    Phase::ServiceRequestContext,
    Phase::ServiceRequestVerify,
    Phase::ServiceRead,
    Phase::ServiceCas,
    Phase::ServiceCommit,
    Phase::ServiceFinalStorage,
    Phase::ReplySignIncludingSelfVerify,
    Phase::ServiceFinal,
    Phase::MutationBegin,
    Phase::LocalCheckpoint,
    Phase::Current,
    Phase::ProtectedRoot,
    Phase::AdvanceCas,
    Phase::LocalCommit,
    Phase::FinalLiveCheck,
    Phase::TcpReadRequest,
    Phase::TcpHandle,
    Phase::TcpWriteFrame,
    Phase::FixtureServiceMutex,
    Phase::WitnessRead,
    Phase::WitnessHandle,
    Phase::WitnessWrite,
];
#[derive(Clone, Copy)]
pub(crate) enum Mark {
    TransportEntered,
    CasCommitAttempted,
    CasCommitted,
    LocalCommitAttempted,
    LocalCommitted,
    MatchingCasReceipt,
    FixtureDelayEntered,
}

#[derive(Clone, Copy, Debug, Serialize)]
pub(crate) struct SafeError {
    origin: &'static str,
    code: Option<&'static str>,
    io_kind: Option<&'static str>,
    raw_os_error: Option<i32>,
    sqlite_extended_code: Option<i32>,
}
impl SafeError {
    fn code(origin: &'static str, code: Option<&'static str>) -> Self {
        Self {
            origin,
            code,
            io_kind: None,
            raw_os_error: None,
            sqlite_extended_code: None,
        }
    }
}
pub(crate) trait DiagnosticError {
    fn diagnostic(&self) -> SafeError;
}
impl DiagnosticError for io::Error {
    fn diagnostic(&self) -> SafeError {
        let mut error = SafeError::code("io", None);
        error.io_kind = Some(match self.kind() {
            io::ErrorKind::NotFound => "not_found",
            io::ErrorKind::PermissionDenied => "permission_denied",
            io::ErrorKind::ConnectionRefused => "connection_refused",
            io::ErrorKind::ConnectionReset => "connection_reset",
            io::ErrorKind::ConnectionAborted => "connection_aborted",
            io::ErrorKind::BrokenPipe => "broken_pipe",
            io::ErrorKind::WouldBlock => "would_block",
            io::ErrorKind::TimedOut => "timed_out",
            io::ErrorKind::Interrupted => "interrupted",
            io::ErrorKind::UnexpectedEof => "unexpected_eof",
            io::ErrorKind::WriteZero => "write_zero",
            _ => "other",
        });
        error.raw_os_error = self.raw_os_error();
        error
    }
}
impl DiagnosticError for rusqlite::Error {
    fn diagnostic(&self) -> SafeError {
        let mut error = SafeError::code("sqlite", None);
        if let Self::SqliteFailure(code, _) = self {
            error.sqlite_extended_code = Some(code.extended_code);
        }
        error
    }
}
impl DiagnosticError for PqNativeError {
    fn diagnostic(&self) -> SafeError {
        use trnm_protocol::pq_frame::PqFrameError as Frame;
        // Cargo can enable the dependency's provider feature without enabling
        // the Node flag. Do not assume that those two feature sets coincide.
        let code = if let Self::Frame(frame) = self {
            match frame {
                Frame::FrameLength => "PQ_FRAME_LENGTH",
                Frame::HeaderVersionAlgorithm => "PQ_HEADER_VERSION_ALGORITHM",
                Frame::PurposeOrReserved => "PQ_PURPOSE_OR_RESERVED",
                Frame::ContextOrIdentity => "PQ_CONTEXT_OR_IDENTITY",
                Frame::LifetimeOrSequence => "PQ_LIFETIME_OR_SEQUENCE",
                Frame::Expired => "PQ_EXPIRED",
                Frame::PayloadSize => "PQ_PAYLOAD_SIZE",
                Frame::PayloadDigest => "PQ_PAYLOAD_DIGEST",
                Frame::SignatureLength => "PQ_SIGNATURE_LENGTH",
                Frame::PublicKeyDer => "PQ_PUBLIC_KEY_DER",
            }
        } else if matches!(self, Self::KeyAlgorithm) {
            "PQ_KEY_ALGORITHM"
        } else if matches!(self, Self::KeyPin) {
            "PQ_KEY_PIN"
        } else if matches!(self, Self::SignatureRejected) {
            "PQ_SIGNATURE_REJECTED"
        } else {
            "PQ_PROVIDER_OR_UNKNOWN"
        };
        SafeError::code("canonical_pq", Some(code))
    }
}
// Bounded formatting is only used to recognize exact existing static literals.
// Never export an unrecognized formatted message or infer control authority.
struct SmallText {
    bytes: [u8; 96],
    len: usize,
}
impl fmt::Write for SmallText {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        if value.len() > self.bytes.len() - self.len {
            return Err(fmt::Error);
        }
        self.bytes[self.len..self.len + value.len()].copy_from_slice(value.as_bytes());
        self.len += value.len();
        Ok(())
    }
}
fn exact_code(error: &crate::Error) -> Option<&'static str> {
    let mut text = SmallText {
        bytes: [0; 96],
        len: 0,
    };
    write!(&mut text, "{error}").ok()?;
    match std::str::from_utf8(&text.bytes[..text.len]).ok()? {
        "PQ_NETWORK_AUDIT_INTEGRITY" => Some("PQ_NETWORK_AUDIT_INTEGRITY"),
        "PQ_NETWORK_BACKEND" => Some("PQ_NETWORK_BACKEND"),
        "PQ_NETWORK_CLIENT_BUDGET" => Some("PQ_NETWORK_CLIENT_BUDGET"),
        "PQ_NETWORK_CLIENT_CONTEXT" => Some("PQ_NETWORK_CLIENT_CONTEXT"),
        "PQ_NETWORK_CONFLICTING_REPLAY" => Some("PQ_NETWORK_CONFLICTING_REPLAY"),
        "PQ_NETWORK_CONTEXT" => Some("PQ_NETWORK_CONTEXT"),
        "PQ_NETWORK_DUPLICATE_KEY" => Some("PQ_NETWORK_DUPLICATE_KEY"),
        "PQ_NETWORK_EPOCH" => Some("PQ_NETWORK_EPOCH"),
        "PQ_NETWORK_EXPIRED_UNCONFIRMED" => Some("PQ_NETWORK_EXPIRED_UNCONFIRMED"),
        "PQ_NETWORK_GENERATION" => Some("PQ_NETWORK_GENERATION"),
        "PQ_NETWORK_INGRESS_BUDGET" => Some("PQ_NETWORK_INGRESS_BUDGET"),
        "PQ_NETWORK_KEY" => Some("PQ_NETWORK_KEY"),
        "PQ_NETWORK_LEDGER_BUDGET" => Some("PQ_NETWORK_LEDGER_BUDGET"),
        "PQ_NETWORK_LIFETIME" => Some("PQ_NETWORK_LIFETIME"),
        "PQ_NETWORK_LOOPBACK_ONLY" => Some("PQ_NETWORK_LOOPBACK_ONLY"),
        "PQ_NETWORK_NONCANONICAL" => Some("PQ_NETWORK_NONCANONICAL"),
        "PQ_NETWORK_OWNER" => Some("PQ_NETWORK_OWNER"),
        "PQ_NETWORK_PEER_LIMIT" => Some("PQ_NETWORK_PEER_LIMIT"),
        "PQ_NETWORK_POLICY_RECORD" => Some("PQ_NETWORK_POLICY_RECORD"),
        "PQ_NETWORK_POLICY_REQUIRED" => Some("PQ_NETWORK_POLICY_REQUIRED"),
        "PQ_NETWORK_RESOURCE_STATE" => Some("PQ_NETWORK_RESOURCE_STATE"),
        "PQ_NETWORK_RESPONSE_CONTEXT" => Some("PQ_NETWORK_RESPONSE_CONTEXT"),
        "PQ_NETWORK_RESPONSE_INTEGRITY" => Some("PQ_NETWORK_RESPONSE_INTEGRITY"),
        "PQ_NETWORK_REVOKED" => Some("PQ_NETWORK_REVOKED"),
        "PQ_NETWORK_ROSTER_INTEGRITY" => Some("PQ_NETWORK_ROSTER_INTEGRITY"),
        "PQ_NETWORK_SEQUENCE" => Some("PQ_NETWORK_SEQUENCE"),
        "PQ_NETWORK_SEQUENCE_GAP" => Some("PQ_NETWORK_SEQUENCE_GAP"),
        "PQ_NETWORK_SEQUENCE_INTEGRITY" => Some("PQ_NETWORK_SEQUENCE_INTEGRITY"),
        "PQ_NETWORK_SERVER_BUDGET" => Some("PQ_NETWORK_SERVER_BUDGET"),
        "PQ_NETWORK_SERVER_KEY" => Some("PQ_NETWORK_SERVER_KEY"),
        "PQ_NETWORK_UNKNOWN_PEER" => Some("PQ_NETWORK_UNKNOWN_PEER"),
        "PQ_NETWORK_WIRE_LIMIT" => Some("PQ_NETWORK_WIRE_LIMIT"),
        "PQ_NETWORK_WIRE_VERSION" => Some("PQ_NETWORK_WIRE_VERSION"),
        "PQ_WITNESS_BINDING" => Some("PQ_WITNESS_BINDING"),
        "PQ_WITNESS_BUSY" => Some("PQ_WITNESS_BUSY"),
        "PQ_WITNESS_CAS" => Some("PQ_WITNESS_CAS"),
        "PQ_WITNESS_CHALLENGE" => Some("PQ_WITNESS_CHALLENGE"),
        "PQ_WITNESS_CHECKPOINT" => Some("PQ_WITNESS_CHECKPOINT"),
        "PQ_WITNESS_COMMIT_UNCERTAIN" => Some("PQ_WITNESS_COMMIT_UNCERTAIN"),
        "PQ_WITNESS_CURRENT_FIELDS" => Some("PQ_WITNESS_CURRENT_FIELDS"),
        "PQ_WITNESS_DEADLINE" => Some("PQ_WITNESS_DEADLINE"),
        "PQ_WITNESS_EOF" => Some("PQ_WITNESS_EOF"),
        "PQ_WITNESS_EXISTING_NODE_REQUIRED" => Some("PQ_WITNESS_EXISTING_NODE_REQUIRED"),
        "PQ_WITNESS_GENERATION" => Some("PQ_WITNESS_GENERATION"),
        "PQ_WITNESS_IDENTITY_SEPARATION" => Some("PQ_WITNESS_IDENTITY_SEPARATION"),
        "PQ_WITNESS_LOCAL_BUDGET" => Some("PQ_WITNESS_LOCAL_BUDGET"),
        "PQ_WITNESS_LOCAL_CHECKPOINT" => Some("PQ_WITNESS_LOCAL_CHECKPOINT"),
        "PQ_WITNESS_LOCAL_ROOT" => Some("PQ_WITNESS_LOCAL_ROOT"),
        "PQ_WITNESS_LOCAL_WIDTH" => Some("PQ_WITNESS_LOCAL_WIDTH"),
        "PQ_WITNESS_NEW_NODE_REQUIRED" => Some("PQ_WITNESS_NEW_NODE_REQUIRED"),
        "PQ_WITNESS_OBSERVATION_ROLLBACK" => Some("PQ_WITNESS_OBSERVATION_ROLLBACK"),
        "PQ_WITNESS_OPERATION" => Some("PQ_WITNESS_OPERATION"),
        "PQ_WITNESS_PARENT" => Some("PQ_WITNESS_PARENT"),
        "PQ_WITNESS_PATH" => Some("PQ_WITNESS_PATH"),
        "PQ_WITNESS_POLICY" => Some("PQ_WITNESS_POLICY"),
        "PQ_WITNESS_REGISTRATION_SEQUENCE" => Some("PQ_WITNESS_REGISTRATION_SEQUENCE"),
        "PQ_WITNESS_REPLY_CONTEXT" => Some("PQ_WITNESS_REPLY_CONTEXT"),
        "PQ_WITNESS_REQUEST_CONTEXT" => Some("PQ_WITNESS_REQUEST_CONTEXT"),
        "PQ_WITNESS_REQUEST_SIZE" => Some("PQ_WITNESS_REQUEST_SIZE"),
        "PQ_WITNESS_REQUIRED" => Some("PQ_WITNESS_REQUIRED"),
        "PQ_WITNESS_RETRY_CONFLICT" => Some("PQ_WITNESS_RETRY_CONFLICT"),
        "PQ_WITNESS_ROLLBACK" => Some("PQ_WITNESS_ROLLBACK"),
        "PQ_WITNESS_SCHEMA" => Some("PQ_WITNESS_SCHEMA"),
        "PQ_WITNESS_SEQUENCE" => Some("PQ_WITNESS_SEQUENCE"),
        "PQ_WITNESS_SERVICE_PIN" => Some("PQ_WITNESS_SERVICE_PIN"),
        "PQ_WITNESS_STATE" => Some("PQ_WITNESS_STATE"),
        "PQ_WITNESS_STATE_WIDTH" => Some("PQ_WITNESS_STATE_WIDTH"),
        "PQ_WITNESS_STORAGE_IDENTITY" => Some("PQ_WITNESS_STORAGE_IDENTITY"),
        "PQ_WITNESS_STORAGE_ROLLBACK" => Some("PQ_WITNESS_STORAGE_ROLLBACK"),
        "PQ_WITNESS_TRANSACTION" => Some("PQ_WITNESS_TRANSACTION"),
        "PQ_WITNESS_UNAVAILABLE" => Some("PQ_WITNESS_UNAVAILABLE"),
        "PQ_WITNESS_WRITER_PIN" => Some("PQ_WITNESS_WRITER_PIN"),
        "PQ_WITNESS_WRITE_ZERO" => Some("PQ_WITNESS_WRITE_ZERO"),
        "LIVE_DEADLINE" => Some("LIVE_DEADLINE"),
        "LIVE_CANCELLED" => Some("LIVE_CANCELLED"),
        "WITNESS_OUTAGE" => Some("WITNESS_OUTAGE"),
        "NO_OLD_REPLY" => Some("NO_OLD_REPLY"),
        "WITNESS_MISSING" => Some("WITNESS_MISSING"),
        "LOST_CAS_REPLY" => Some("LOST_CAS_REPLY"),
        _ => None,
    }
}
impl DiagnosticError for crate::Error {
    fn diagnostic(&self) -> SafeError {
        use std::error::Error as _;
        if let Some(code) = self.code() {
            return SafeError::code("typed_node", Some(code.as_str()));
        }
        if let Some(source) = self.source() {
            if let Some(error) = source.downcast_ref::<io::Error>() {
                return error.diagnostic();
            }
            if let Some(error) = source.downcast_ref::<rusqlite::Error>() {
                return error.diagnostic();
            }
        }
        if self.kind() == crate::ErrorKind::RemoteRefusal {
            return SafeError::code("remote", None);
        }
        SafeError::code("exact_diagnostic_string_or_unknown", exact_code(self))
    }
}

#[derive(Clone, Copy, Default, Debug, Serialize)]
struct Totals {
    started: u64,
    completed: u64,
    failed: u64,
    unfinished: u64,
    wall_ns: Option<u64>,
    thread_cpu_ns: Option<u64>,
    wall_unknown: u64,
    cpu_unknown: u64,
    last_error: Option<SafeError>,
}
fn add(total: Option<u64>, sample: Option<u64>, first: bool) -> Option<u64> {
    if first {
        sample
    } else {
        total.zip(sample).and_then(|(a, b)| a.checked_add(b))
    }
}
impl Totals {
    fn end(&mut self, wall: Option<u64>, cpu: Option<u64>, outcome: Option<Option<SafeError>>) {
        let first = self.completed == 0 && self.unfinished == 0;
        self.wall_ns = add(self.wall_ns, wall, first);
        self.thread_cpu_ns = add(self.thread_cpu_ns, cpu, first);
        self.wall_unknown = self.wall_unknown.saturating_add(u64::from(wall.is_none()));
        self.cpu_unknown = self.cpu_unknown.saturating_add(u64::from(cpu.is_none()));
        match outcome {
            Some(error) => {
                self.completed = self.completed.saturating_add(1);
                if error.is_some() {
                    self.failed = self.failed.saturating_add(1);
                    self.last_error = error;
                }
            }
            None => self.unfinished = self.unfinished.saturating_add(1),
        }
    }
}
#[derive(Clone, Copy)]
struct Row {
    id: u64,
    kind: Kind,
    closed: bool,
    accepted: Option<bool>,
    error: Option<SafeError>,
    wall_ns: Option<u64>,
    thread_cpu_ns: Option<u64>,
    original_remaining_ns: Option<u64>,
    effective_remaining_ns: Option<u64>,
    last_phase: Option<Phase>,
    marks: [bool; 7],
    phases: [Totals; 32],
}
#[derive(Clone, Copy, Serialize)]
struct Failure {
    id: u64,
    kind: Kind,
    phase: Option<Phase>,
    error: SafeError,
    wall_ns: Option<u64>,
    thread_cpu_ns: Option<u64>,
    marks: [bool; 7],
}
struct State {
    last_failure: Option<Failure>,
    last_service_failure: Option<Failure>,
    last_tcp_failure: Option<Failure>,
    started: u64,
    completed: u64,
    closed: u64,
    overwritten: u64,
    rows: [Option<Row>; MAX_RECORDS],
    totals: [Totals; 32],
}
enum Sink {
    Stderr,
    File(PathBuf),
    Quiet,
}
pub(crate) struct Recorder {
    state: Mutex<State>,
    failed: AtomicU64,
    emitted: AtomicBool,
    failure_saved: AtomicBool,
    sink: Sink,
}
impl Recorder {
    fn new(sink: Sink) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(State {
                last_failure: None,
                last_service_failure: None,
                last_tcp_failure: None,
                started: 0,
                completed: 0,
                closed: 0,
                overwritten: 0,
                rows: [None; MAX_RECORDS],
                totals: [Totals::default(); 32],
            }),
            failed: AtomicU64::new(0),
            emitted: AtomicBool::new(false),
            failure_saved: AtomicBool::new(false),
            sink,
        })
    }
    fn fail(&self) {
        let _ = self
            .failed
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                Some(n.saturating_add(1))
            });
    }
    fn update(&self, change: impl FnOnce(&mut State)) -> bool {
        match self.state.try_lock() {
            Ok(mut state) => {
                change(&mut state);
                true
            }
            Err(_) => {
                self.fail();
                false
            }
        }
    }
    fn row(state: &mut State, id: u64) -> Option<&mut Row> {
        state.rows[(id % MAX_RECORDS as u64) as usize]
            .as_mut()
            .filter(|row| row.id == id)
    }
    fn snapshot(&self) -> Value {
        let Ok(state) = self.state.try_lock() else {
            self.fail();
            return json!({"schema":"pon-pq-test-phase-observation-v1","measurement_unavailable":true});
        };
        let phases = |totals: &[Totals; 32]| {
            PHASES
                .iter()
                .zip(totals)
                .filter(|(_, v)| v.started > 0)
                .map(|(phase, total)| json!({"phase":phase,"samples":total}))
                .collect::<Vec<_>>()
        };
        let mut rows = state.rows.iter().flatten().copied().collect::<Vec<_>>();
        rows.sort_by_key(|row| row.id);
        let rows = rows.into_iter().map(|r| json!({"id":r.id,"kind":r.kind,"closed":r.closed,
            "accepted":r.accepted,"error":r.error,"wall_ns":r.wall_ns,"thread_cpu_ns":r.thread_cpu_ns,
            "original_remaining_ns":r.original_remaining_ns,"effective_remaining_ns":r.effective_remaining_ns,
            "last_phase":r.last_phase,"transport_entered":r.marks[0],"cas_commit_attempted":r.marks[1],
            "cas_committed":r.marks[2],"local_commit_attempted":r.marks[3],"local_committed":r.marks[4],
            "matching_cas_receipt":r.marks[5],"fixture_delay_entered":r.marks[6],"phases":phases(&r.phases)})).collect::<Vec<_>>();
        json!({"schema":"pon-pq-test-phase-observation-v1","process_id":std::process::id(),
            "operation_ids_are_process_local":true,"records_started":state.started,"records_completed":state.completed,"records_closed":state.closed,
            "record_capacity":MAX_RECORDS,"records_overwritten":state.overwritten,"records":rows,
            "last_failure":state.last_failure,"last_service_failure":state.last_service_failure,
            "last_tcp_failure":state.last_tcp_failure,"mark_order":["transport_entered","cas_commit_attempted","cas_committed","local_commit_attempted","local_committed","matching_cas_receipt","fixture_delay_entered"],
            "has_open_records":state.rows.iter().flatten().any(|row|!row.closed),
            "has_open_operations":state.closed<state.started,"scope_snapshot_is_final":self.emitted.load(Ordering::Acquire),
            "failure_checkpoint_saved":self.failure_saved.load(Ordering::Acquire),"snapshot_is_not_service_completion":true,
            "phase_totals":phases(&state.totals),"measurement_failures":self.failed.load(Ordering::Relaxed),
            "nested_intervals_are_not_additive":true,"cpu_is_calling_thread_only":true,
            "budgets_unchanged":true,"observation_has_authority":false})
    }
    fn emit(&self) {
        if self.emitted.swap(true, Ordering::AcqRel) || matches!(self.sink, Sink::Quiet) {
            return;
        }
        self.write_snapshot();
    }
    fn save_child_failure(&self, error: &crate::Error) {
        // EOF from an ordinary client close is not a failed service request.
        // This classification changes observation only, never the old result.
        if !matches!(self.sink, Sink::File(_)) || error.diagnostic().code == Some("PQ_WITNESS_EOF")
        {
            return;
        }
        if !self.failure_saved.swap(true, Ordering::AcqRel) {
            self.write_snapshot();
        }
    }
    fn write_snapshot(&self) {
        let value = self.snapshot();
        let mut bytes = BoundedBytes(Vec::with_capacity(4096));
        let encoded = bytes
            .write_all(PREFIX.as_bytes())
            .and_then(|_| serde_json::to_writer(&mut bytes, &value).map_err(io::Error::other))
            .and_then(|_| bytes.write_all(b"\n"));
        if encoded.is_err() {
            bytes.0.clear();
            let fallback = json!({"schema":"pon-pq-test-phase-observation-v1","encoding_truncated":true,
                "records_started":value.get("records_started"),"records_completed":value.get("records_completed"),
                "records_closed":value.get("records_closed"),"has_open_operations":value.get("has_open_operations"),
                "scope_snapshot_is_final":value.get("scope_snapshot_is_final"),"failure_checkpoint_saved":value.get("failure_checkpoint_saved"),
                "snapshot_is_not_service_completion":true,
                "record_capacity":MAX_RECORDS,"records_overwritten":value.get("records_overwritten"),
                "measurement_failures":value.get("measurement_failures"),"last_failure":value.get("last_failure"),
                "last_service_failure":value.get("last_service_failure"),"last_tcp_failure":value.get("last_tcp_failure"),
                "mark_order":value.get("mark_order"),
                "phase_totals":value.get("phase_totals"),
                "nested_intervals_are_not_additive":true,"observation_has_authority":false});
            if bytes
                .write_all(PREFIX.as_bytes())
                .and_then(|_| {
                    serde_json::to_writer(&mut bytes, &fallback).map_err(io::Error::other)
                })
                .and_then(|_| bytes.write_all(b"\n"))
                .is_err()
            {
                return;
            }
        }
        match &self.sink {
            Sink::Stderr => emit_line(&bytes.0),
            Sink::File(path) => {
                // A child with captured pipes must not block on a large stderr
                // write while its parent is waiting for exit. One bounded file
                // is read only after the child has stopped, outside all requests.
                let pending = path.with_file_name(CHILD_PENDING);
                if let Ok(mut file) = std::fs::OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .mode(0o600)
                    .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                    .open(&pending)
                {
                    if file.write_all(&bytes.0).and_then(|_| file.flush()).is_ok() {
                        let _ = std::fs::rename(&pending, path);
                    }
                }
            }
            Sink::Quiet => {}
        }
    }
}
struct BoundedBytes(Vec<u8>);
impl io::Write for BoundedBytes {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > MAX_LINE_BYTES - self.0.len() {
            return Err(io::Error::other("diagnostic capacity"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
fn emit_line(line: &[u8]) {
    if LOG_REMAINING
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
            n.checked_sub(line.len())
        })
        .is_err()
    {
        if !LOG_LIMIT_REPORTED.swap(true, Ordering::AcqRel) {
            eprintln!("{PREFIX}{{\"schema\":\"pon-pq-test-phase-observation-v1\",\"process_log_limit_reached\":true}}");
        }
        return;
    }
    // Use libtest capture so a diagnostic cannot split the exact-selector
    // `test ... ok` receipt. The existing --show-output retains this line.
    if let Ok(text) = std::str::from_utf8(line) {
        eprint!("{text}");
    }
}
pub(crate) fn forward_child(directory: &Path) {
    fn missing() {
        emit_line(concat!("TRNM_PQ_PHASE_DIAGNOSTIC ",
            "{\"schema\":\"pon-pq-test-phase-observation-v1\",\"child_snapshot_missing_or_invalid\":true}\n").as_bytes());
    }
    let Ok(file) = std::fs::File::open(directory.join(CHILD_FILE)) else {
        missing();
        return;
    };
    let mut bytes = Vec::new();
    if file
        .take((MAX_LINE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .is_err()
        || bytes.len() > MAX_LINE_BYTES
    {
        missing();
        return;
    }
    if bytes.starts_with(PREFIX.as_bytes())
        && bytes.last() == Some(&b'\n')
        && bytes[..bytes.len() - 1].iter().all(|&b| b != b'\n')
        && serde_json::from_slice::<Value>(&bytes[PREFIX.len()..]).is_ok_and(|value| {
            value.get("schema").and_then(Value::as_str) == Some("pon-pq-test-phase-observation-v1")
        })
    {
        emit_line(&bytes);
    } else {
        missing();
    }
}

pub(crate) struct Scope {
    recorder: Arc<Recorder>,
    previous: Option<Arc<Recorder>>,
    emit: bool,
    _same_thread: PhantomData<Rc<()>>,
}
impl Scope {
    pub(crate) fn new() -> Self {
        Self::install(Recorder::new(Sink::Stderr), true)
    }
    pub(crate) fn child(directory: &Path) -> Self {
        Self::install(Recorder::new(Sink::File(directory.join(CHILD_FILE))), true)
    }
    pub(crate) fn attach(recorder: Arc<Recorder>) -> Self {
        Self::install(recorder, false)
    }
    fn install(recorder: Arc<Recorder>, emit: bool) -> Self {
        let previous = ACTIVE.with(|active| active.replace(Some(recorder.clone())));
        Self {
            recorder,
            previous,
            emit,
            _same_thread: PhantomData,
        }
    }
    pub(crate) fn recorder(&self) -> Arc<Recorder> {
        self.recorder.clone()
    }
    pub(crate) fn save_child_failure(&self, error: &crate::Error) {
        self.recorder.save_child_failure(error);
    }
}
impl Drop for Scope {
    fn drop(&mut self) {
        let _ = ACTIVE.try_with(|active| {
            if let Ok(mut active) = active.try_borrow_mut() {
                if active
                    .as_ref()
                    .is_some_and(|r| Arc::ptr_eq(r, &self.recorder))
                {
                    *active = self.previous.take();
                } else {
                    self.recorder.fail();
                }
            } else {
                self.recorder.fail();
            }
        });
        if self.emit {
            self.recorder.emit();
        }
    }
}

struct CpuStamp {
    thread: ThreadId,
    ns: u64,
}
impl CpuStamp {
    fn start() -> Option<Self> {
        Some(Self {
            thread: thread::current().id(),
            ns: thread_cpu_ns()?,
        })
    }
    fn finish(self) -> Option<u64> {
        if self.thread != thread::current().id() {
            return None;
        }
        thread_cpu_ns()?.checked_sub(self.ns)
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
fn nanos(duration: std::time::Duration) -> Option<u64> {
    u64::try_from(duration.as_nanos()).ok()
}
struct Interval {
    wall: Instant,
    cpu: Option<CpuStamp>,
}
impl Interval {
    fn start() -> Self {
        Self {
            wall: Instant::now(),
            cpu: CpuStamp::start(),
        }
    }
    fn finish(self) -> (Option<u64>, Option<u64>) {
        (
            Instant::now()
                .checked_duration_since(self.wall)
                .and_then(nanos),
            self.cpu.and_then(CpuStamp::finish),
        )
    }
}
pub(crate) struct Operation {
    recorder: Arc<Recorder>,
    id: u64,
    kind: Kind,
    last_phase: Cell<Option<Phase>>,
    marks: Cell<[bool; 7]>,
    interval: Option<Interval>,
    outcome: Option<Option<SafeError>>,
}
pub(crate) fn start(kind: Kind) -> Option<Operation> {
    let recorder = ACTIVE
        .try_with(|active| active.try_borrow().ok().and_then(|v| v.clone()))
        .ok()??;
    // No enabled scope means no clock, allocation or logging above this line.
    let interval = Interval::start();
    let mut id = None;
    recorder.update(|state| {
        let Some(next) = state.started.checked_add(1) else {
            recorder.fail();
            return;
        };
        let slot = (next % MAX_RECORDS as u64) as usize;
        state.overwritten = state
            .overwritten
            .saturating_add(u64::from(state.rows[slot].is_some()));
        state.started = next;
        id = Some(next);
        state.rows[slot] = Some(Row {
            id: next,
            kind,
            closed: false,
            accepted: None,
            error: None,
            wall_ns: None,
            thread_cpu_ns: None,
            original_remaining_ns: None,
            effective_remaining_ns: None,
            last_phase: None,
            marks: [false; 7],
            phases: [Totals::default(); 32],
        });
    });
    Some(Operation {
        recorder,
        id: id?,
        kind,
        last_phase: Cell::new(None),
        marks: Cell::new([false; 7]),
        interval: Some(interval),
        outcome: None,
    })
}
impl Operation {
    pub(crate) fn phase(&self, phase: Phase) -> PhaseGuard {
        self.last_phase.set(Some(phase));
        let interval = Interval::start();
        let recorded = self.recorder.update(|state| {
            state.totals[phase as usize].started =
                state.totals[phase as usize].started.saturating_add(1);
            if let Some(row) = Recorder::row(state, self.id) {
                row.last_phase = Some(phase);
                row.phases[phase as usize].started =
                    row.phases[phase as usize].started.saturating_add(1);
            }
        });
        PhaseGuard {
            recorder: self.recorder.clone(),
            id: self.id,
            phase,
            interval: Some(interval),
            outcome: None,
            recorded,
        }
    }
    pub(crate) fn deadlines(&self, original: Option<Instant>, effective: Instant) {
        let now = Instant::now();
        self.recorder.update(|state| {
            if let Some(row) = Recorder::row(state, self.id) {
                row.original_remaining_ns =
                    original.and_then(|v| nanos(v.saturating_duration_since(now)));
                row.effective_remaining_ns = nanos(effective.saturating_duration_since(now));
            }
        });
    }
    pub(crate) fn mark(&self, mark: Mark) {
        let mut marks = self.marks.get();
        marks[mark as usize] = true;
        self.marks.set(marks);
        self.recorder.update(|state| {
            if let Some(row) = Recorder::row(state, self.id) {
                row.marks[mark as usize] = true;
            }
        });
    }
    pub(crate) fn finish<T, E: DiagnosticError>(mut self, result: &Result<T, E>) {
        self.outcome = Some(result.as_ref().err().map(DiagnosticError::diagnostic));
    }
}
impl Drop for Operation {
    fn drop(&mut self) {
        let (wall, cpu) = self
            .interval
            .take()
            .map(Interval::finish)
            .unwrap_or((None, None));
        self.recorder.update(|state| {
            state.completed = state
                .completed
                .saturating_add(u64::from(self.outcome.is_some()));
            state.closed = state.closed.saturating_add(1);
            if let Some(Some(error)) = self.outcome {
                let failure = Failure {
                    id: self.id,
                    kind: self.kind,
                    phase: self.last_phase.get(),
                    error,
                    wall_ns: wall,
                    thread_cpu_ns: cpu,
                    marks: self.marks.get(),
                };
                state.last_failure = Some(failure);
                if matches!(
                    self.kind,
                    Kind::ServiceCurrent | Kind::ServiceCas | Kind::ServiceUnknown
                ) {
                    state.last_service_failure = Some(failure);
                }
                if matches!(self.kind, Kind::TcpRequest) {
                    state.last_tcp_failure = Some(failure);
                }
            }
            if let Some(row) = Recorder::row(state, self.id) {
                row.closed = true;
                row.accepted = self.outcome.map(|error| error.is_none());
                row.error = self.outcome.flatten();
                row.wall_ns = wall;
                row.thread_cpu_ns = cpu;
            }
        });
    }
}
pub(crate) struct PhaseGuard {
    recorder: Arc<Recorder>,
    id: u64,
    phase: Phase,
    interval: Option<Interval>,
    outcome: Option<Option<SafeError>>,
    recorded: bool,
}
impl PhaseGuard {
    pub(crate) fn finish<T, E: DiagnosticError>(mut self, result: &Result<T, E>) {
        self.outcome = Some(result.as_ref().err().map(DiagnosticError::diagnostic));
    }
}
impl Drop for PhaseGuard {
    fn drop(&mut self) {
        if !self.recorded {
            return;
        }
        let (wall, cpu) = self
            .interval
            .take()
            .map(Interval::finish)
            .unwrap_or((None, None));
        self.recorder.update(|state| {
            state.totals[self.phase as usize].end(wall, cpu, self.outcome);
            if let Some(row) = Recorder::row(state, self.id) {
                row.phases[self.phase as usize].end(wall, cpu, self.outcome);
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn disabled_observation_and_failures_never_supply_authority_or_error_text() {
        assert!(start(Kind::ClientCurrent).is_none());
        let recorder = Recorder::new(Sink::Quiet);
        let _scope = Scope::install(recorder.clone(), false);
        let op = start(Kind::ClientCurrent).unwrap();
        let phase = op.phase(Phase::BeforeTransport);
        let error: crate::Result<()> = Err("PQ_WITNESS_DEADLINE".into());
        phase.finish(&error);
        op.finish(&error);
        let service = start(Kind::ServiceCas).unwrap();
        let service_error: crate::Result<()> = Err(io::Error::from_raw_os_error(libc::EIO).into());
        service.phase(Phase::ServiceCommit).finish(&service_error);
        service.finish(&service_error);
        let op = start(Kind::TcpRequest).unwrap();
        let private: crate::Result<()> = Err("unknown request payload must never escape".into());
        op.phase(Phase::TcpHandle).finish(&private);
        op.finish(&private);
        let value = recorder.snapshot();
        let encoded = serde_json::to_string(&value).unwrap();
        assert!(encoded.contains("PQ_WITNESS_DEADLINE"));
        assert!(!encoded.contains("unknown request payload"));
        assert_eq!(value["records_completed"], 3);
        assert_eq!(value["last_service_failure"]["phase"], "service_commit");
        assert_eq!(
            value["last_service_failure"]["error"]["raw_os_error"],
            libc::EIO
        );
        assert_eq!(value["last_tcp_failure"]["phase"], "tcp_handle");
        assert_eq!(value["observation_has_authority"], false);
        let reset = crate::Error::from(io::Error::from_raw_os_error(libc::ECONNRESET)).diagnostic();
        assert_eq!(reset.raw_os_error, Some(libc::ECONNRESET));
        assert_eq!(reset.io_kind, Some("connection_reset"));
    }
    #[test]
    fn abandoned_phases_and_overwritten_rows_remain_explicit_and_bounded() {
        let recorder = Recorder::new(Sink::Quiet);
        let _scope = Scope::install(recorder.clone(), false);
        {
            let op = start(Kind::ClientCas).unwrap();
            let _phase = op.phase(Phase::Transport);
        }
        let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let op = start(Kind::ClientCas).unwrap();
            let _phase = op.phase(Phase::Transport);
            panic!("synthetic observation unwind");
        }));
        assert!(unwind.is_err());
        for _ in 0..MAX_RECORDS {
            let op = start(Kind::ClientCurrent).unwrap();
            op.finish(&Ok::<_, crate::Error>(()));
        }
        let value = recorder.snapshot();
        assert_eq!(value["records"].as_array().unwrap().len(), MAX_RECORDS);
        assert_eq!(value["records_overwritten"], 2);
        let totals = value["phase_totals"].as_array().unwrap();
        assert_eq!(totals[0]["samples"]["unfinished"], 2);
        assert_eq!(value["records_completed"], MAX_RECORDS);
        assert_eq!(value["has_open_operations"], false);
        let open = start(Kind::MutationBegin).unwrap();
        for _ in 0..MAX_RECORDS {
            start(Kind::ClientCurrent)
                .unwrap()
                .finish(&Ok::<_, crate::Error>(()));
        }
        // An outer operation can outlive all eight retained rows. Eviction
        // cannot make the observer claim that all operations have returned.
        assert_eq!(recorder.snapshot()["has_open_operations"], true);
        drop(open);
        assert_eq!(recorder.snapshot()["has_open_operations"], false);
    }
}
