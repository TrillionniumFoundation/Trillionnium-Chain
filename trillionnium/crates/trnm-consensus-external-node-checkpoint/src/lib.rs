//! Cross-process external whole-node checkpoint CAS authority.
//!
//! This crate is intentionally a narrow adapter around the canonical
//! [`trnm_poco_node::ExternalNodeCheckpointStoreV0`] contract.  A daemon owns
//! an append-only, hash-chained journal and serves exact load/CAS requests over
//! a private Unix socket.  The client never opens the journal.  A malformed,
//! truncated, reordered, replayed, or checksum-modified journal fails closed
//! before the daemon accepts a request.
//!
//! This is not a signer, HSM/KMS, host-attestation service, SafetyRules/Core
//! authority, or production node integration.  The canonical node's
//! `EXTERNAL_NODE_CHECKPOINT_OPERATIONAL_INTEGRATION_V0` and production flags
//! remain false; callers must opt into this adapter explicitly.

#![cfg(unix)]
#![forbid(unsafe_code)]

use std::{
    collections::BTreeMap,
    error::Error,
    fmt,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::unix::{
        fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt},
        net::{UnixListener, UnixStream},
    },
    path::{Component, Path, PathBuf},
    process,
    time::Duration,
};

use fs2::FileExt;
use sha2::{Digest, Sha256};
use trnm_poco_node::{
    ExternalNodeCheckpointStoreErrorV0, ExternalNodeCheckpointStoreV0, ExternalNodeCheckpointV0,
    EXTERNAL_NODE_CHECKPOINT_RECORD_BYTES_V0,
};

/// This adapter is a cross-process CAS transport, not operational node
/// integration.  The canonical node gate remains independently false.
pub const EXTERNAL_NODE_CHECKPOINT_UNIX_ADAPTER_V0: bool = true;
pub const EXTERNAL_NODE_CHECKPOINT_PRIVATE_KEY_HANDLING_V0: bool = false;
pub const EXTERNAL_NODE_CHECKPOINT_CONSENSUS_RUNTIME_V0: bool = false;
pub const EXTERNAL_NODE_CHECKPOINT_CORE_ADMISSION_V0: bool = false;
pub const EXTERNAL_NODE_CHECKPOINT_SAFETY_RULES_V0: bool = false;
pub const EXTERNAL_NODE_CHECKPOINT_HOST_ATTESTATION_V0: bool = false;
pub const EXTERNAL_NODE_CHECKPOINT_PRODUCTION_ACTIVATION_V0: bool = false;

const PROTOCOL_VERSION_V0: u8 = 1;
const REQUEST_MAGIC_V0: &[u8; 4] = b"NCPR";
const RESPONSE_MAGIC_V0: &[u8; 4] = b"NCPS";
const LOG_MAGIC_V0: &[u8; 8] = b"TRNMNC01";
const ANCHOR_MAGIC_V0: &[u8; 8] = b"TRNMNCH1";
const LOG_DOMAIN_V0: &[u8] = b"trnm.external-node-checkpoint.log.v0\0";
const ANCHOR_DOMAIN_V0: &[u8] = b"trnm.external-node-checkpoint.anchor.v0\0";
const MAX_FRAME_BYTES_V0: usize = 4096;
const CHECKPOINT_BYTES_V0: usize = EXTERNAL_NODE_CHECKPOINT_RECORD_BYTES_V0;
// magic + version + operation + reserved + sequence + scope + expected flag
// + expected slot + target + predecessor hash + record hash
const LOG_RECORD_BYTES_V0: usize =
    8 + 1 + 1 + 2 + 8 + 32 + 1 + CHECKPOINT_BYTES_V0 + CHECKPOINT_BYTES_V0 + 32 + 32;
const ANCHOR_BODY_BYTES_V0: usize = 8 + 1 + 3 + 8 + 32;
const ANCHOR_BYTES_V0: usize = ANCHOR_BODY_BYTES_V0 + 32;

const OP_COMPARE_AND_ADVANCE_V0: u8 = 1;
const OP_LOAD_V0: u8 = 2;
const STATUS_VALUE_V0: u8 = 1;
const STATUS_NONE_V0: u8 = 2;
const STATUS_APPLIED_V0: u8 = 3;
const STATUS_COMPARE_FAILED_V0: u8 = 4;
const STATUS_INVALID_STATE_V0: u8 = 5;
const STATUS_UNAVAILABLE_V0: u8 = 6;
const STATUS_PROTOCOL_V0: u8 = 7;

/// Errors internal to the daemon/client transport.  The public trait maps
/// these into its deliberately small closed error enum.
#[derive(Debug)]
pub enum ExternalNodeCheckpointAuthorityErrorV0 {
    InvalidConfig(&'static str),
    InvalidLog(&'static str),
    Io {
        stage: &'static str,
        source: io::Error,
    },
    Protocol(&'static str),
    CompareFailed,
    Unavailable,
}

impl fmt::Display for ExternalNodeCheckpointAuthorityErrorV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig(reason) => {
                write!(formatter, "invalid node-checkpoint config: {reason}")
            }
            Self::InvalidLog(reason) => write!(formatter, "node-checkpoint log rejected: {reason}"),
            Self::Io { stage, source } => {
                write!(formatter, "node-checkpoint I/O at {stage}: {source}")
            }
            Self::Protocol(reason) => write!(formatter, "node-checkpoint protocol: {reason}"),
            Self::CompareFailed => {
                formatter.write_str("node-checkpoint compare-and-advance failed")
            }
            Self::Unavailable => formatter.write_str("node-checkpoint authority unavailable"),
        }
    }
}

impl Error for ExternalNodeCheckpointAuthorityErrorV0 {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

impl From<io::Error> for ExternalNodeCheckpointAuthorityErrorV0 {
    fn from(source: io::Error) -> Self {
        Self::Io {
            stage: "Unix transport",
            source,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct LogRecordV0 {
    sequence: u64,
    scope: [u8; 32],
    expected: Option<ExternalNodeCheckpointV0>,
    target: ExternalNodeCheckpointV0,
    previous_hash: [u8; 32],
    record_hash: [u8; 32],
}

/// One process-owned checkpoint authority.  The process lock prevents a
/// second daemon from serving the same namespace; clients only use the Unix
/// socket and cannot mutate the journal directly through this API.
pub struct ExternalNodeCheckpointAuthorityV0 {
    log_path: PathBuf,
    anchor_path: PathBuf,
    directory: File,
    log: File,
    _lock: File,
    current: BTreeMap<[u8; 32], ExternalNodeCheckpointV0>,
    head_hash: [u8; 32],
    record_count: u64,
    poisoned: bool,
}

impl ExternalNodeCheckpointAuthorityV0 {
    /// Open and authenticate the entire append-only journal.  No repair or
    /// truncation is attempted.  A partial tail, stale anchor, or hash-chain
    /// mismatch is a hard startup failure.
    pub fn open(
        log_path: impl AsRef<Path>,
    ) -> Result<Self, ExternalNodeCheckpointAuthorityErrorV0> {
        let (directory, log_path) = private_path_v0(log_path.as_ref())?;
        let lock_path = sidecar_path_v0(&log_path, "lock-v0")?;
        let anchor_path = sidecar_path_v0(&log_path, "head-v0")?;
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&lock_path)
            .map_err(|source| ExternalNodeCheckpointAuthorityErrorV0::Io {
                stage: "open authority lock",
                source,
            })?;
        validate_private_file_v0(&lock, "authority lock")?;
        lock.try_lock_exclusive()
            .map_err(|source| ExternalNodeCheckpointAuthorityErrorV0::Io {
                stage: "lock authority namespace",
                source,
            })?;

        let log = OpenOptions::new()
            .read(true)
            .create(true)
            .append(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&log_path)
            .map_err(|source| ExternalNodeCheckpointAuthorityErrorV0::Io {
                stage: "open checkpoint journal",
                source,
            })?;
        validate_private_file_v0(&log, "checkpoint journal")?;
        let mut authority = Self {
            log_path,
            anchor_path,
            directory,
            log,
            _lock: lock,
            current: BTreeMap::new(),
            head_hash: [0; 32],
            record_count: 0,
            poisoned: false,
        };
        authority.replay_log_v0()?;
        authority.reconcile_anchor_v0()?;
        Ok(authority)
    }

    pub fn log_path(&self) -> &Path {
        &self.log_path
    }

    pub fn load_checked(
        &self,
        scope: [u8; 32],
    ) -> Result<Option<ExternalNodeCheckpointV0>, ExternalNodeCheckpointAuthorityErrorV0> {
        if self.poisoned {
            return Err(ExternalNodeCheckpointAuthorityErrorV0::Unavailable);
        }
        if scope == [0; 32] {
            return Err(ExternalNodeCheckpointAuthorityErrorV0::InvalidConfig(
                "zero scope",
            ));
        }
        Ok(self.current.get(&scope).copied())
    }

    pub fn compare_and_advance_checked(
        &mut self,
        expected: Option<ExternalNodeCheckpointV0>,
        target: ExternalNodeCheckpointV0,
    ) -> Result<(), ExternalNodeCheckpointAuthorityErrorV0> {
        if self.poisoned {
            return Err(ExternalNodeCheckpointAuthorityErrorV0::Unavailable);
        }
        let scope = target.scope();
        if scope == [0; 32] || target.encode_canonical().iter().all(|byte| *byte == 0) {
            return Err(ExternalNodeCheckpointAuthorityErrorV0::InvalidConfig(
                "target is not a canonical checkpoint",
            ));
        }
        if expected.is_some_and(|value| value.scope() != scope) {
            return Err(ExternalNodeCheckpointAuthorityErrorV0::CompareFailed);
        }
        if !valid_successor_shape_v0(expected.as_ref(), &target) {
            return Err(ExternalNodeCheckpointAuthorityErrorV0::CompareFailed);
        }
        if self.current.get(&scope).copied() != expected {
            return Err(ExternalNodeCheckpointAuthorityErrorV0::CompareFailed);
        }
        let sequence = self.record_count.checked_add(1).ok_or(
            ExternalNodeCheckpointAuthorityErrorV0::InvalidLog("record count exhausted"),
        )?;
        let previous_hash = self.head_hash;
        let record_hash = digest_record_v0(sequence, scope, expected, target, previous_hash);
        let record = LogRecordV0 {
            sequence,
            scope,
            expected,
            target,
            previous_hash,
            record_hash,
        };
        if let Err(source) = self.log.write_all(&encode_log_record_v0(record)) {
            self.poisoned = true;
            return Err(ExternalNodeCheckpointAuthorityErrorV0::Io {
                stage: "append checkpoint record",
                source,
            });
        }
        if let Err(source) = self.log.sync_data() {
            self.poisoned = true;
            return Err(ExternalNodeCheckpointAuthorityErrorV0::Io {
                stage: "sync checkpoint record",
                source,
            });
        }
        if let Err(source) = self.directory.sync_data() {
            self.poisoned = true;
            return Err(ExternalNodeCheckpointAuthorityErrorV0::Io {
                stage: "sync checkpoint directory",
                source,
            });
        }
        self.current.insert(scope, target);
        self.record_count = sequence;
        self.head_hash = record_hash;
        if let Err(error) = self.persist_anchor_v0() {
            self.poisoned = true;
            return Err(error);
        }
        Ok(())
    }

    fn replay_log_v0(&mut self) -> Result<(), ExternalNodeCheckpointAuthorityErrorV0> {
        let mut reader =
            self.log
                .try_clone()
                .map_err(|source| ExternalNodeCheckpointAuthorityErrorV0::Io {
                    stage: "clone checkpoint journal",
                    source,
                })?;
        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes).map_err(|source| {
            ExternalNodeCheckpointAuthorityErrorV0::Io {
                stage: "read checkpoint journal",
                source,
            }
        })?;
        if bytes.len() % LOG_RECORD_BYTES_V0 != 0 {
            return Err(ExternalNodeCheckpointAuthorityErrorV0::InvalidLog(
                "trailing partial checkpoint record",
            ));
        }
        for chunk in bytes.chunks_exact(LOG_RECORD_BYTES_V0) {
            let record = decode_log_record_v0(chunk)?;
            if record.sequence != self.record_count.saturating_add(1)
                || record.previous_hash != self.head_hash
                || record.record_hash
                    != digest_record_v0(
                        record.sequence,
                        record.scope,
                        record.expected,
                        record.target,
                        record.previous_hash,
                    )
                || !valid_successor_shape_v0(record.expected.as_ref(), &record.target)
                || record.target.scope() != record.scope
                || self.current.get(&record.scope).copied() != record.expected
            {
                return Err(ExternalNodeCheckpointAuthorityErrorV0::InvalidLog(
                    "checkpoint CAS replay mismatch",
                ));
            }
            self.current.insert(record.scope, record.target);
            self.record_count = record.sequence;
            self.head_hash = record.record_hash;
        }
        Ok(())
    }

    fn reconcile_anchor_v0(&mut self) -> Result<(), ExternalNodeCheckpointAuthorityErrorV0> {
        validate_existing_sidecar_v0(&self.anchor_path, "checkpoint head")?;
        match fs::read(&self.anchor_path) {
            Ok(bytes) => {
                let (count, head) = decode_anchor_v0(&bytes)?;
                if count > self.record_count {
                    return Err(ExternalNodeCheckpointAuthorityErrorV0::InvalidLog(
                        "durable head is ahead of journal",
                    ));
                }
                if count == self.record_count && head != self.head_hash {
                    return Err(ExternalNodeCheckpointAuthorityErrorV0::InvalidLog(
                        "durable head differs from journal",
                    ));
                }
                if count < self.record_count {
                    // A crash after the journal fsync and before anchor rename
                    // leaves only a monotonic journal-ahead state; repair is
                    // safe because the complete chain has already replayed.
                    self.persist_anchor_v0()?;
                }
                Ok(())
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                if self.record_count != 0 {
                    return Err(ExternalNodeCheckpointAuthorityErrorV0::InvalidLog(
                        "non-empty journal has no durable head",
                    ));
                }
                self.persist_anchor_v0()
            }
            Err(source) => Err(ExternalNodeCheckpointAuthorityErrorV0::Io {
                stage: "read checkpoint head",
                source,
            }),
        }
    }

    fn persist_anchor_v0(&self) -> Result<(), ExternalNodeCheckpointAuthorityErrorV0> {
        let name = self
            .anchor_path
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or(ExternalNodeCheckpointAuthorityErrorV0::InvalidConfig(
                "checkpoint head filename",
            ))?;
        let temporary = self.anchor_path.with_file_name(format!(
            ".{name}.tmp-{}-{}",
            process::id(),
            self.record_count
        ));
        let bytes = encode_anchor_v0(self.record_count, self.head_hash);
        let result = (|| {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
                .open(&temporary)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            fs::rename(&temporary, &self.anchor_path)?;
            self.directory.sync_data()?;
            Ok::<(), io::Error>(())
        })();
        if let Err(source) = result {
            let _ = fs::remove_file(&temporary);
            return Err(ExternalNodeCheckpointAuthorityErrorV0::Io {
                stage: "persist checkpoint head",
                source,
            });
        }
        Ok(())
    }

    fn handle_connection_v0(
        &mut self,
        mut stream: UnixStream,
    ) -> Result<(), ExternalNodeCheckpointAuthorityErrorV0> {
        if self.poisoned {
            return Err(ExternalNodeCheckpointAuthorityErrorV0::Unavailable);
        }
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .map_err(|source| ExternalNodeCheckpointAuthorityErrorV0::Io {
                stage: "set request timeout",
                source,
            })?;
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .map_err(|source| ExternalNodeCheckpointAuthorityErrorV0::Io {
                stage: "set response timeout",
                source,
            })?;
        let request = match decode_request_v0(&read_frame_v0(&mut stream)?) {
            Ok(request) => request,
            Err(error) => {
                write_frame_v0(&mut stream, &encode_status_response_v0(STATUS_PROTOCOL_V0))?;
                return Err(error);
            }
        };
        match request {
            RequestV0::Load { scope } => match self.load_checked(scope) {
                Ok(Some(value)) => write_frame_v0(&mut stream, &encode_value_response_v0(value)),
                Ok(None) => write_frame_v0(&mut stream, &encode_status_response_v0(STATUS_NONE_V0)),
                Err(_) => write_frame_v0(
                    &mut stream,
                    &encode_status_response_v0(STATUS_INVALID_STATE_V0),
                ),
            },
            RequestV0::CompareAndAdvance(request) => {
                let expected = request.expected;
                let target = request.target;
                match self.compare_and_advance_checked(expected, target) {
                    Ok(()) => {
                        write_frame_v0(&mut stream, &encode_status_response_v0(STATUS_APPLIED_V0))
                    }
                    Err(ExternalNodeCheckpointAuthorityErrorV0::CompareFailed) => write_frame_v0(
                        &mut stream,
                        &encode_status_response_v0(STATUS_COMPARE_FAILED_V0),
                    ),
                    Err(ExternalNodeCheckpointAuthorityErrorV0::InvalidLog(_)) => {
                        let result = write_frame_v0(
                            &mut stream,
                            &encode_status_response_v0(STATUS_INVALID_STATE_V0),
                        );
                        self.poisoned = true;
                        result
                    }
                    Err(_) => write_frame_v0(
                        &mut stream,
                        &encode_status_response_v0(STATUS_UNAVAILABLE_V0),
                    ),
                }
            }
        }
    }

    /// Serve requests until the process is terminated.  A journal integrity
    /// error poisons and terminates the daemon; malformed client requests are
    /// isolated to their connection.
    pub fn serve_unix(
        mut self,
        socket_path: impl AsRef<Path>,
    ) -> Result<(), ExternalNodeCheckpointAuthorityErrorV0> {
        let socket_path = socket_path.as_ref();
        remove_stale_socket_v0(socket_path)?;
        let _parent = prepare_socket_parent_v0(socket_path)?;
        let listener = UnixListener::bind(socket_path).map_err(|source| {
            ExternalNodeCheckpointAuthorityErrorV0::Io {
                stage: "bind checkpoint socket",
                source,
            }
        })?;
        fs::set_permissions(socket_path, fs::Permissions::from_mode(0o600)).map_err(|source| {
            ExternalNodeCheckpointAuthorityErrorV0::Io {
                stage: "protect checkpoint socket",
                source,
            }
        })?;
        for stream in listener.incoming() {
            match stream {
                Ok(stream) => {
                    if let Err(error) = self.handle_connection_v0(stream) {
                        if matches!(error, ExternalNodeCheckpointAuthorityErrorV0::InvalidLog(_)) {
                            return Err(error);
                        }
                    }
                }
                Err(source) => {
                    return Err(ExternalNodeCheckpointAuthorityErrorV0::Io {
                        stage: "accept checkpoint connection",
                        source,
                    })
                }
            }
        }
        Ok(())
    }
}

/// Stateless Unix client implementing the canonical node checkpoint store
/// trait.  Each operation opens a fresh socket connection.
#[derive(Debug, Clone)]
pub struct UnixExternalNodeCheckpointStoreV0 {
    socket_path: PathBuf,
    timeout: Duration,
}

impl UnixExternalNodeCheckpointStoreV0 {
    pub fn new(
        socket_path: impl AsRef<Path>,
    ) -> Result<Self, ExternalNodeCheckpointAuthorityErrorV0> {
        let path = socket_path.as_ref();
        if !path.is_absolute() || path.file_name().is_none() {
            return Err(ExternalNodeCheckpointAuthorityErrorV0::InvalidConfig(
                "checkpoint socket must be an absolute path",
            ));
        }
        Ok(Self {
            socket_path: path.to_path_buf(),
            timeout: Duration::from_secs(5),
        })
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    pub fn load_checked(
        &self,
        scope: [u8; 32],
    ) -> Result<Option<ExternalNodeCheckpointV0>, ExternalNodeCheckpointAuthorityErrorV0> {
        match self.request_v0(RequestV0::Load { scope })? {
            ResponseV0::Value(value) => Ok(Some(*value)),
            ResponseV0::None => Ok(None),
            ResponseV0::Applied
            | ResponseV0::CompareFailed
            | ResponseV0::InvalidState
            | ResponseV0::Unavailable
            | ResponseV0::Protocol => Err(ExternalNodeCheckpointAuthorityErrorV0::Protocol(
                "unexpected load response",
            )),
        }
    }

    pub fn compare_and_advance_checked(
        &self,
        expected: Option<ExternalNodeCheckpointV0>,
        target: ExternalNodeCheckpointV0,
    ) -> Result<(), ExternalNodeCheckpointAuthorityErrorV0> {
        match self.request_v0(RequestV0::CompareAndAdvance(Box::new(CompareRequestV0 {
            expected,
            target,
        })))? {
            ResponseV0::Applied => Ok(()),
            ResponseV0::CompareFailed => Err(ExternalNodeCheckpointAuthorityErrorV0::CompareFailed),
            ResponseV0::InvalidState => Err(ExternalNodeCheckpointAuthorityErrorV0::InvalidLog(
                "remote checkpoint journal rejected",
            )),
            ResponseV0::Unavailable => Err(ExternalNodeCheckpointAuthorityErrorV0::Unavailable),
            ResponseV0::Protocol => Err(ExternalNodeCheckpointAuthorityErrorV0::Protocol(
                "remote protocol failure",
            )),
            ResponseV0::Value(_) | ResponseV0::None => Err(
                ExternalNodeCheckpointAuthorityErrorV0::Protocol("unexpected compare response"),
            ),
        }
    }

    fn request_v0(
        &self,
        request: RequestV0,
    ) -> Result<ResponseV0, ExternalNodeCheckpointAuthorityErrorV0> {
        let mut stream = UnixStream::connect(&self.socket_path).map_err(|source| {
            ExternalNodeCheckpointAuthorityErrorV0::Io {
                stage: "connect checkpoint socket",
                source,
            }
        })?;
        stream
            .set_read_timeout(Some(self.timeout))
            .map_err(|source| ExternalNodeCheckpointAuthorityErrorV0::Io {
                stage: "set client read timeout",
                source,
            })?;
        stream
            .set_write_timeout(Some(self.timeout))
            .map_err(|source| ExternalNodeCheckpointAuthorityErrorV0::Io {
                stage: "set client write timeout",
                source,
            })?;
        write_frame_v0(&mut stream, &encode_request_v0(request))?;
        decode_response_v0(&read_frame_v0(&mut stream)?)
    }
}

impl ExternalNodeCheckpointStoreV0 for UnixExternalNodeCheckpointStoreV0 {
    fn load(
        &mut self,
        scope: [u8; 32],
    ) -> Result<Option<ExternalNodeCheckpointV0>, ExternalNodeCheckpointStoreErrorV0> {
        self.load_checked(scope).map_err(map_store_error_v0)
    }

    fn compare_and_advance(
        &mut self,
        expected: Option<ExternalNodeCheckpointV0>,
        target: ExternalNodeCheckpointV0,
    ) -> Result<(), ExternalNodeCheckpointStoreErrorV0> {
        self.compare_and_advance_checked(expected, target)
            .map_err(map_store_error_v0)
    }
}

/// Start the standalone authority process loop.
pub fn run_daemon(
    socket_path: impl AsRef<Path>,
    log_path: impl AsRef<Path>,
) -> Result<(), ExternalNodeCheckpointAuthorityErrorV0> {
    ExternalNodeCheckpointAuthorityV0::open(log_path)?.serve_unix(socket_path)
}

fn map_store_error_v0(
    error: ExternalNodeCheckpointAuthorityErrorV0,
) -> ExternalNodeCheckpointStoreErrorV0 {
    match error {
        ExternalNodeCheckpointAuthorityErrorV0::CompareFailed => {
            ExternalNodeCheckpointStoreErrorV0::CompareFailed
        }
        ExternalNodeCheckpointAuthorityErrorV0::InvalidConfig(_)
        | ExternalNodeCheckpointAuthorityErrorV0::InvalidLog(_)
        | ExternalNodeCheckpointAuthorityErrorV0::Protocol(_) => {
            ExternalNodeCheckpointStoreErrorV0::InvalidPersistedState
        }
        ExternalNodeCheckpointAuthorityErrorV0::Io { .. }
        | ExternalNodeCheckpointAuthorityErrorV0::Unavailable => {
            ExternalNodeCheckpointStoreErrorV0::Unavailable
        }
    }
}

#[derive(Debug)]
enum RequestV0 {
    Load { scope: [u8; 32] },
    CompareAndAdvance(Box<CompareRequestV0>),
}

#[derive(Debug)]
struct CompareRequestV0 {
    expected: Option<ExternalNodeCheckpointV0>,
    target: ExternalNodeCheckpointV0,
}

#[derive(Debug)]
enum ResponseV0 {
    Value(Box<ExternalNodeCheckpointV0>),
    None,
    Applied,
    CompareFailed,
    InvalidState,
    Unavailable,
    Protocol,
}

fn valid_successor_shape_v0(
    expected: Option<&ExternalNodeCheckpointV0>,
    target: &ExternalNodeCheckpointV0,
) -> bool {
    match expected {
        None => target.generation() == 0 && target.predecessor_checksum() == [0; 32],
        Some(expected) => target.validate_successor_of(expected).is_ok(),
    }
}

fn encode_request_v0(request: RequestV0) -> Vec<u8> {
    let mut body = Vec::with_capacity(MAX_FRAME_BYTES_V0);
    body.extend_from_slice(REQUEST_MAGIC_V0);
    body.push(PROTOCOL_VERSION_V0);
    match request {
        RequestV0::Load { scope } => {
            body.push(OP_LOAD_V0);
            body.extend_from_slice(&[0, 0, 0]);
            body.extend_from_slice(&scope);
        }
        RequestV0::CompareAndAdvance(request) => {
            let expected = request.expected;
            let target = request.target;
            body.push(OP_COMPARE_AND_ADVANCE_V0);
            body.push(u8::from(expected.is_some()));
            body.extend_from_slice(&[0, 0]);
            body.extend_from_slice(&target.scope());
            if let Some(value) = expected {
                body.extend_from_slice(&value.encode_canonical());
            }
            body.extend_from_slice(&target.encode_canonical());
        }
    }
    body
}

fn decode_request_v0(body: &[u8]) -> Result<RequestV0, ExternalNodeCheckpointAuthorityErrorV0> {
    if body.len() < 9 || &body[..4] != REQUEST_MAGIC_V0 || body[4] != PROTOCOL_VERSION_V0 {
        return Err(ExternalNodeCheckpointAuthorityErrorV0::Protocol(
            "request header",
        ));
    }
    match body[5] {
        OP_LOAD_V0 if body.len() == 41 && body[6..9] == [0, 0, 0] => Ok(RequestV0::Load {
            scope: body[9..41].try_into().expect("fixed load scope"),
        }),
        OP_COMPARE_AND_ADVANCE_V0 if body[6] <= 1 && body[7..9] == [0, 0] => {
            let scope: [u8; 32] = body[9..41].try_into().expect("fixed compare scope");
            let expected_start = 41;
            let target_start = expected_start + if body[6] == 1 { CHECKPOINT_BYTES_V0 } else { 0 };
            if body.len() != target_start + CHECKPOINT_BYTES_V0 {
                return Err(ExternalNodeCheckpointAuthorityErrorV0::Protocol(
                    "compare request length",
                ));
            }
            let expected = if body[6] == 1 {
                Some(
                    ExternalNodeCheckpointV0::decode_canonical_exact(
                        &body[expected_start..target_start],
                    )
                    .map_err(|_| {
                        ExternalNodeCheckpointAuthorityErrorV0::Protocol("expected checkpoint")
                    })?,
                )
            } else {
                None
            };
            let target = ExternalNodeCheckpointV0::decode_canonical_exact(&body[target_start..])
                .map_err(|_| {
                    ExternalNodeCheckpointAuthorityErrorV0::Protocol("target checkpoint")
                })?;
            if target.scope() != scope || expected.is_some_and(|value| value.scope() != scope) {
                return Err(ExternalNodeCheckpointAuthorityErrorV0::Protocol(
                    "checkpoint scope mismatch",
                ));
            }
            Ok(RequestV0::CompareAndAdvance(Box::new(CompareRequestV0 {
                expected,
                target,
            })))
        }
        _ => Err(ExternalNodeCheckpointAuthorityErrorV0::Protocol(
            "unsupported checkpoint request",
        )),
    }
}

fn encode_status_response_v0(status: u8) -> Vec<u8> {
    let mut body = Vec::with_capacity(8);
    body.extend_from_slice(RESPONSE_MAGIC_V0);
    body.push(PROTOCOL_VERSION_V0);
    body.push(status);
    body.extend_from_slice(&[0, 0]);
    body
}

fn encode_value_response_v0(value: ExternalNodeCheckpointV0) -> Vec<u8> {
    let mut body = encode_status_response_v0(STATUS_VALUE_V0);
    body.extend_from_slice(&value.encode_canonical());
    body
}

fn decode_response_v0(body: &[u8]) -> Result<ResponseV0, ExternalNodeCheckpointAuthorityErrorV0> {
    if body.len() < 8 || &body[..4] != RESPONSE_MAGIC_V0 || body[4] != PROTOCOL_VERSION_V0 {
        return Err(ExternalNodeCheckpointAuthorityErrorV0::Protocol(
            "response header",
        ));
    }
    if body[6..8] != [0, 0] {
        return Err(ExternalNodeCheckpointAuthorityErrorV0::Protocol(
            "response flags",
        ));
    }
    match body[5] {
        STATUS_VALUE_V0 if body.len() == 8 + CHECKPOINT_BYTES_V0 => {
            Ok(ResponseV0::Value(Box::new(
                ExternalNodeCheckpointV0::decode_canonical_exact(&body[8..]).map_err(|_| {
                    ExternalNodeCheckpointAuthorityErrorV0::Protocol("response checkpoint")
                })?,
            )))
        }
        STATUS_NONE_V0 if body.len() == 8 => Ok(ResponseV0::None),
        STATUS_APPLIED_V0 if body.len() == 8 => Ok(ResponseV0::Applied),
        STATUS_COMPARE_FAILED_V0 if body.len() == 8 => Ok(ResponseV0::CompareFailed),
        STATUS_INVALID_STATE_V0 if body.len() == 8 => Ok(ResponseV0::InvalidState),
        STATUS_UNAVAILABLE_V0 if body.len() == 8 => Ok(ResponseV0::Unavailable),
        STATUS_PROTOCOL_V0 if body.len() == 8 => Ok(ResponseV0::Protocol),
        _ => Err(ExternalNodeCheckpointAuthorityErrorV0::Protocol(
            "response shape",
        )),
    }
}

fn read_frame_v0(
    stream: &mut UnixStream,
) -> Result<Vec<u8>, ExternalNodeCheckpointAuthorityErrorV0> {
    let mut header = [0u8; 4];
    stream.read_exact(&mut header).map_err(|source| {
        ExternalNodeCheckpointAuthorityErrorV0::Io {
            stage: "read frame length",
            source,
        }
    })?;
    let length = u32::from_be_bytes(header) as usize;
    if length == 0 || length > MAX_FRAME_BYTES_V0 {
        return Err(ExternalNodeCheckpointAuthorityErrorV0::Protocol(
            "frame length",
        ));
    }
    let mut body = vec![0u8; length];
    stream
        .read_exact(&mut body)
        .map_err(|source| ExternalNodeCheckpointAuthorityErrorV0::Io {
            stage: "read frame body",
            source,
        })?;
    Ok(body)
}

fn write_frame_v0(
    stream: &mut UnixStream,
    body: &[u8],
) -> Result<(), ExternalNodeCheckpointAuthorityErrorV0> {
    if body.is_empty() || body.len() > MAX_FRAME_BYTES_V0 {
        return Err(ExternalNodeCheckpointAuthorityErrorV0::Protocol(
            "frame body length",
        ));
    }
    stream
        .write_all(&(body.len() as u32).to_be_bytes())
        .and_then(|_| stream.write_all(body))
        .and_then(|_| stream.flush())
        .map_err(|source| ExternalNodeCheckpointAuthorityErrorV0::Io {
            stage: "write frame",
            source,
        })
}

fn digest_record_v0(
    sequence: u64,
    scope: [u8; 32],
    expected: Option<ExternalNodeCheckpointV0>,
    target: ExternalNodeCheckpointV0,
    previous_hash: [u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(LOG_DOMAIN_V0);
    hasher.update(PROTOCOL_VERSION_V0.to_be_bytes());
    hasher.update(OP_COMPARE_AND_ADVANCE_V0.to_be_bytes());
    hasher.update(sequence.to_be_bytes());
    hasher.update(scope);
    hasher.update([u8::from(expected.is_some())]);
    if let Some(value) = expected {
        hasher.update(value.encode_canonical());
    } else {
        hasher.update([0u8; CHECKPOINT_BYTES_V0]);
    }
    hasher.update(target.encode_canonical());
    hasher.update(previous_hash);
    hasher.finalize().into()
}

fn encode_log_record_v0(record: LogRecordV0) -> [u8; LOG_RECORD_BYTES_V0] {
    let mut bytes = [0u8; LOG_RECORD_BYTES_V0];
    let mut offset = 0;
    bytes[offset..offset + 8].copy_from_slice(LOG_MAGIC_V0);
    offset += 8;
    bytes[offset] = PROTOCOL_VERSION_V0;
    offset += 1;
    bytes[offset] = OP_COMPARE_AND_ADVANCE_V0;
    offset += 1;
    bytes[offset..offset + 2].copy_from_slice(&[0, 0]);
    offset += 2;
    bytes[offset..offset + 8].copy_from_slice(&record.sequence.to_be_bytes());
    offset += 8;
    bytes[offset..offset + 32].copy_from_slice(&record.scope);
    offset += 32;
    bytes[offset] = u8::from(record.expected.is_some());
    offset += 1;
    if let Some(expected) = record.expected {
        bytes[offset..offset + CHECKPOINT_BYTES_V0].copy_from_slice(&expected.encode_canonical());
    }
    offset += CHECKPOINT_BYTES_V0;
    bytes[offset..offset + CHECKPOINT_BYTES_V0].copy_from_slice(&record.target.encode_canonical());
    offset += CHECKPOINT_BYTES_V0;
    bytes[offset..offset + 32].copy_from_slice(&record.previous_hash);
    offset += 32;
    bytes[offset..offset + 32].copy_from_slice(&record.record_hash);
    bytes
}

fn decode_log_record_v0(
    bytes: &[u8],
) -> Result<LogRecordV0, ExternalNodeCheckpointAuthorityErrorV0> {
    if bytes.len() != LOG_RECORD_BYTES_V0
        || &bytes[..8] != LOG_MAGIC_V0
        || bytes[8] != PROTOCOL_VERSION_V0
        || bytes[9] != OP_COMPARE_AND_ADVANCE_V0
        || bytes[10..12] != [0, 0]
    {
        return Err(ExternalNodeCheckpointAuthorityErrorV0::InvalidLog(
            "record header",
        ));
    }
    let sequence = u64::from_be_bytes(bytes[12..20].try_into().expect("fixed sequence"));
    let scope: [u8; 32] = bytes[20..52].try_into().expect("fixed scope");
    let expected_present = bytes[52];
    if expected_present > 1 {
        return Err(ExternalNodeCheckpointAuthorityErrorV0::InvalidLog(
            "record expected marker",
        ));
    }
    let expected_start = 53;
    let target_start = expected_start + CHECKPOINT_BYTES_V0;
    let previous_start = target_start + CHECKPOINT_BYTES_V0;
    let hash_start = previous_start + 32;
    let expected = if expected_present == 1 {
        Some(
            ExternalNodeCheckpointV0::decode_canonical_exact(&bytes[expected_start..target_start])
                .map_err(|_| {
                    ExternalNodeCheckpointAuthorityErrorV0::InvalidLog("expected record")
                })?,
        )
    } else {
        if bytes[expected_start..target_start]
            .iter()
            .any(|byte| *byte != 0)
        {
            return Err(ExternalNodeCheckpointAuthorityErrorV0::InvalidLog(
                "absent expected record is nonzero",
            ));
        }
        None
    };
    let target =
        ExternalNodeCheckpointV0::decode_canonical_exact(&bytes[target_start..previous_start])
            .map_err(|_| ExternalNodeCheckpointAuthorityErrorV0::InvalidLog("target record"))?;
    let previous_hash: [u8; 32] = bytes[previous_start..hash_start]
        .try_into()
        .expect("fixed predecessor");
    let record_hash: [u8; 32] = bytes[hash_start..hash_start + 32]
        .try_into()
        .expect("fixed digest");
    Ok(LogRecordV0 {
        sequence,
        scope,
        expected,
        target,
        previous_hash,
        record_hash,
    })
}

fn encode_anchor_v0(record_count: u64, head_hash: [u8; 32]) -> [u8; ANCHOR_BYTES_V0] {
    let mut bytes = [0u8; ANCHOR_BYTES_V0];
    bytes[..8].copy_from_slice(ANCHOR_MAGIC_V0);
    bytes[8] = PROTOCOL_VERSION_V0;
    bytes[9..12].copy_from_slice(&[0, 0, 0]);
    bytes[12..20].copy_from_slice(&record_count.to_be_bytes());
    bytes[20..52].copy_from_slice(&head_hash);
    let checksum = digest_anchor_v0(&bytes[..ANCHOR_BODY_BYTES_V0]);
    bytes[ANCHOR_BODY_BYTES_V0..].copy_from_slice(&checksum);
    bytes
}

fn decode_anchor_v0(
    bytes: &[u8],
) -> Result<(u64, [u8; 32]), ExternalNodeCheckpointAuthorityErrorV0> {
    if bytes.len() != ANCHOR_BYTES_V0
        || &bytes[..8] != ANCHOR_MAGIC_V0
        || bytes[8] != PROTOCOL_VERSION_V0
        || bytes[9..12] != [0, 0, 0]
        || bytes[ANCHOR_BODY_BYTES_V0..] != digest_anchor_v0(&bytes[..ANCHOR_BODY_BYTES_V0])
    {
        return Err(ExternalNodeCheckpointAuthorityErrorV0::InvalidLog(
            "checkpoint head",
        ));
    }
    let count = u64::from_be_bytes(bytes[12..20].try_into().expect("fixed anchor count"));
    let head: [u8; 32] = bytes[20..52].try_into().expect("fixed anchor head");
    if (count == 0) != (head == [0; 32]) {
        return Err(ExternalNodeCheckpointAuthorityErrorV0::InvalidLog(
            "checkpoint head empty shape",
        ));
    }
    Ok((count, head))
}

fn digest_anchor_v0(body: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(ANCHOR_DOMAIN_V0);
    hasher.update((body.len() as u64).to_be_bytes());
    hasher.update(body);
    hasher.finalize().into()
}

fn private_path_v0(path: &Path) -> Result<(File, PathBuf), ExternalNodeCheckpointAuthorityErrorV0> {
    if !path.is_absolute()
        || path.file_name().is_none()
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(ExternalNodeCheckpointAuthorityErrorV0::InvalidConfig(
            "journal path must be absolute and normalized",
        ));
    }
    let parent = path
        .parent()
        .ok_or(ExternalNodeCheckpointAuthorityErrorV0::InvalidConfig(
            "journal parent",
        ))?;
    let canonical_parent =
        fs::canonicalize(parent).map_err(|source| ExternalNodeCheckpointAuthorityErrorV0::Io {
            stage: "canonicalize journal parent",
            source,
        })?;
    let metadata = fs::symlink_metadata(&canonical_parent).map_err(|source| {
        ExternalNodeCheckpointAuthorityErrorV0::Io {
            stage: "stat journal parent",
            source,
        }
    })?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.permissions().mode() & 0o077 != 0
        || canonical_parent != parent
    {
        return Err(ExternalNodeCheckpointAuthorityErrorV0::InvalidConfig(
            "journal parent must be a private canonical directory",
        ));
    }
    let name = path
        .file_name()
        .ok_or(ExternalNodeCheckpointAuthorityErrorV0::InvalidConfig(
            "journal filename",
        ))?;
    let normalized = canonical_parent.join(name);
    let directory = File::open(&canonical_parent).map_err(|source| {
        ExternalNodeCheckpointAuthorityErrorV0::Io {
            stage: "open journal parent",
            source,
        }
    })?;
    Ok((directory, normalized))
}

fn sidecar_path_v0(
    log_path: &Path,
    suffix: &str,
) -> Result<PathBuf, ExternalNodeCheckpointAuthorityErrorV0> {
    let name = log_path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or(ExternalNodeCheckpointAuthorityErrorV0::InvalidConfig(
            "sidecar filename",
        ))?;
    Ok(log_path.with_file_name(format!(".{name}.{suffix}")))
}

fn validate_private_file_v0(
    file: &File,
    what: &'static str,
) -> Result<(), ExternalNodeCheckpointAuthorityErrorV0> {
    let metadata =
        file.metadata()
            .map_err(|source| ExternalNodeCheckpointAuthorityErrorV0::Io {
                stage: "stat private file",
                source,
            })?;
    if !metadata.file_type().is_file()
        || metadata.nlink() != 1
        || metadata.permissions().mode() & 0o777 != 0o600
    {
        return Err(ExternalNodeCheckpointAuthorityErrorV0::InvalidConfig(what));
    }
    Ok(())
}

fn validate_existing_sidecar_v0(
    path: &Path,
    what: &'static str,
) -> Result<(), ExternalNodeCheckpointAuthorityErrorV0> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink()
                || !metadata.file_type().is_file()
                || metadata.nlink() != 1
                || metadata.permissions().mode() & 0o777 != 0o600
            {
                return Err(ExternalNodeCheckpointAuthorityErrorV0::InvalidLog(what));
            }
            Ok(())
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(ExternalNodeCheckpointAuthorityErrorV0::Io {
            stage: "inspect checkpoint sidecar",
            source,
        }),
    }
}

fn remove_stale_socket_v0(path: &Path) -> Result<(), ExternalNodeCheckpointAuthorityErrorV0> {
    if !path.is_absolute() || path.file_name().is_none() {
        return Err(ExternalNodeCheckpointAuthorityErrorV0::InvalidConfig(
            "socket path must be absolute",
        ));
    }
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_socket() => {
            fs::remove_file(path).map_err(|source| ExternalNodeCheckpointAuthorityErrorV0::Io {
                stage: "remove stale checkpoint socket",
                source,
            })
        }
        Ok(_) => Err(ExternalNodeCheckpointAuthorityErrorV0::InvalidConfig(
            "socket path is not a Unix socket",
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(ExternalNodeCheckpointAuthorityErrorV0::Io {
            stage: "inspect checkpoint socket",
            source,
        }),
    }
}

fn prepare_socket_parent_v0(
    socket_path: &Path,
) -> Result<PathBuf, ExternalNodeCheckpointAuthorityErrorV0> {
    let parent =
        socket_path
            .parent()
            .ok_or(ExternalNodeCheckpointAuthorityErrorV0::InvalidConfig(
                "socket parent",
            ))?;
    if !parent.is_absolute()
        || parent
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(ExternalNodeCheckpointAuthorityErrorV0::InvalidConfig(
            "socket parent must be absolute and normalized",
        ));
    }
    if !parent.exists() {
        fs::create_dir_all(parent).map_err(|source| {
            ExternalNodeCheckpointAuthorityErrorV0::Io {
                stage: "create socket parent",
                source,
            }
        })?;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).map_err(|source| {
            ExternalNodeCheckpointAuthorityErrorV0::Io {
                stage: "protect socket parent",
                source,
            }
        })?;
    }
    let canonical =
        fs::canonicalize(parent).map_err(|source| ExternalNodeCheckpointAuthorityErrorV0::Io {
            stage: "canonicalize socket parent",
            source,
        })?;
    let metadata = fs::symlink_metadata(&canonical).map_err(|source| {
        ExternalNodeCheckpointAuthorityErrorV0::Io {
            stage: "stat socket parent",
            source,
        }
    })?;
    if canonical != parent
        || metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(ExternalNodeCheckpointAuthorityErrorV0::InvalidConfig(
            "socket parent must be a private canonical directory",
        ));
    }
    Ok(canonical)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        sync::mpsc,
        thread,
        time::{Duration, Instant},
    };
    use tempfile::TempDir;
    use trnm_consensus_signer_journal::SignerWatermarkV0;
    use trnm_consensus_types::{BlockId, StateRoot};
    use trnm_poco_node::{ExternalNodeCheckpointFieldsV0, ExternalNodeCheckpointStoreV0};

    const _: () = {
        assert!(EXTERNAL_NODE_CHECKPOINT_UNIX_ADAPTER_V0);
        assert!(!EXTERNAL_NODE_CHECKPOINT_PRIVATE_KEY_HANDLING_V0);
        assert!(!EXTERNAL_NODE_CHECKPOINT_CONSENSUS_RUNTIME_V0);
        assert!(!EXTERNAL_NODE_CHECKPOINT_CORE_ADMISSION_V0);
        assert!(!EXTERNAL_NODE_CHECKPOINT_SAFETY_RULES_V0);
        assert!(!EXTERNAL_NODE_CHECKPOINT_HOST_ATTESTATION_V0);
        assert!(!EXTERNAL_NODE_CHECKPOINT_PRODUCTION_ACTIVATION_V0);
        assert!(!trnm_poco_node::EXTERNAL_NODE_CHECKPOINT_OPERATIONAL_INTEGRATION_V0);
        assert!(!trnm_poco_node::EXTERNAL_NODE_CHECKPOINT_PRODUCTION_ACTIVATION_V0);
    };

    fn checkpoint(generation: u64, predecessor_checksum: [u8; 32]) -> ExternalNodeCheckpointV0 {
        ExternalNodeCheckpointV0::new(ExternalNodeCheckpointFieldsV0 {
            scope: [1; 32],
            generation,
            predecessor_checksum,
            safety_journal_id: [2; 32],
            safety_verifier_profile_ref: [3; 32],
            safety_revision: generation + 1,
            safety_state_record_checksum: [4; 32],
            safety_record_chain_checksum: [5; 32],
            application_host_config_ref: [6; 32],
            application_projection_profile_ref: [7; 32],
            application_safety_binding_manifest_checksum: [8; 32],
            application_committed_head_row_checksum: [9; 32],
            application_recovery_closure_checksum: [10; 32],
            application_block_id: BlockId::new([11; 32]),
            application_height: generation + 1,
            application_state_root: StateRoot::new([12; 32]),
            application_view: generation + 1,
            application_timestamp_ms: 100 + generation,
            signer_journal_id: [13; 32],
            signer_profile_checksum: [14; 32],
            signer_exact_watermark: SignerWatermarkV0::from_persisted_parts(
                [1; 32], [13; 32], generation, [15; 32],
            )
            .unwrap(),
        })
        .unwrap()
    }

    fn private_tempdir() -> TempDir {
        let directory = TempDir::new().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        directory
    }

    #[test]
    fn authority_exact_cas_rejects_replay_and_reopens() {
        let directory = private_tempdir();
        let log = directory.path().join("checkpoint.log");
        let first = checkpoint(0, [0; 32]);
        let second = checkpoint(1, first.checkpoint_checksum());
        let mut authority = ExternalNodeCheckpointAuthorityV0::open(&log).unwrap();
        authority.compare_and_advance_checked(None, first).unwrap();
        assert_eq!(authority.load_checked([1; 32]).unwrap(), Some(first));
        assert!(matches!(
            authority.compare_and_advance_checked(None, first),
            Err(ExternalNodeCheckpointAuthorityErrorV0::CompareFailed)
        ));
        authority
            .compare_and_advance_checked(Some(first), second)
            .unwrap();
        drop(authority);
        let reopened = ExternalNodeCheckpointAuthorityV0::open(&log).unwrap();
        assert_eq!(reopened.load_checked([1; 32]).unwrap(), Some(second));
    }

    #[test]
    fn journal_truncation_and_byte_edit_fail_closed() {
        let directory = private_tempdir();
        let log = directory.path().join("checkpoint.log");
        let first = checkpoint(0, [0; 32]);
        let mut authority = ExternalNodeCheckpointAuthorityV0::open(&log).unwrap();
        authority.compare_and_advance_checked(None, first).unwrap();
        drop(authority);
        let original = fs::read(&log).unwrap();
        fs::write(&log, &original[..original.len() - 1]).unwrap();
        assert!(matches!(
            ExternalNodeCheckpointAuthorityV0::open(&log),
            Err(ExternalNodeCheckpointAuthorityErrorV0::InvalidLog(_))
        ));
        fs::write(&log, &original).unwrap();
        let mut edited = original;
        edited[100] ^= 0x80;
        fs::write(&log, edited).unwrap();
        assert!(matches!(
            ExternalNodeCheckpointAuthorityV0::open(&log),
            Err(ExternalNodeCheckpointAuthorityErrorV0::InvalidLog(_))
        ));
    }

    #[test]
    fn replayed_record_fails_closed() {
        let directory = private_tempdir();
        let log = directory.path().join("checkpoint.log");
        let first = checkpoint(0, [0; 32]);
        let second = checkpoint(1, first.checkpoint_checksum());
        let mut authority = ExternalNodeCheckpointAuthorityV0::open(&log).unwrap();
        authority.compare_and_advance_checked(None, first).unwrap();
        authority
            .compare_and_advance_checked(Some(first), second)
            .unwrap();
        drop(authority);
        let mut bytes = fs::read(&log).unwrap();
        let replay = bytes[..LOG_RECORD_BYTES_V0].to_vec();
        bytes.extend_from_slice(&replay);
        fs::write(&log, bytes).unwrap();
        assert!(matches!(
            ExternalNodeCheckpointAuthorityV0::open(&log),
            Err(ExternalNodeCheckpointAuthorityErrorV0::InvalidLog(_))
        ));
    }

    #[test]
    fn unix_client_round_trip_uses_separate_thread_authority() {
        let directory = private_tempdir();
        let log = directory.path().join("checkpoint.log");
        let socket = directory.path().join("checkpoint.sock");
        let (ready_tx, ready_rx) = mpsc::channel();
        let log_for_thread = log.clone();
        let socket_for_thread = socket.clone();
        thread::spawn(move || {
            let authority = ExternalNodeCheckpointAuthorityV0::open(log_for_thread).unwrap();
            ready_tx.send(()).unwrap();
            authority.serve_unix(socket_for_thread).unwrap();
        });
        ready_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        while !socket.exists() {
            assert!(Instant::now() < deadline, "daemon socket did not appear");
            thread::sleep(Duration::from_millis(5));
        }
        let mut client = UnixExternalNodeCheckpointStoreV0::new(&socket).unwrap();
        let first = checkpoint(0, [0; 32]);
        client.compare_and_advance(None, first).unwrap();
        assert_eq!(client.load([1; 32]).unwrap(), Some(first));
    }

    #[test]
    fn activation_and_key_boundaries_remain_closed() {
        let manifest = include_str!("../Cargo.toml");
        for required in [
            "append_only_hash_chain = true",
            "cross_process_cas = true",
            "strict_scope_expected_target_cas = true",
            "private_key_handling = false",
            "consensus_runtime = false",
            "core_admission = false",
            "safety_rules = false",
            "host_attestation = false",
            "validator_runtime = false",
            "production_signature_producer = false",
            "external_node_checkpoint_operational_integration = false",
            "external_node_checkpoint_production_activation = false",
            "production_activation = false",
            "production_candidate = false",
        ] {
            assert!(manifest.contains(required), "missing metadata {required}");
        }
    }
}
