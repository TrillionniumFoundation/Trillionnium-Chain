//! Cross-process monotonic signer fencing for the narrow P0 timeout path.
//!
//! This crate deliberately owns the *external* side of the signer boundary.
//! The local signer journal remains a separate SQLite namespace and the
//! authority process never receives a private key or arbitrary bytes to sign.
//! The authority log is a fixed-record append-only hash chain.  A restart
//! authenticates the complete chain before serving a request; a partial,
//! reordered, truncated, or checksum-modified record therefore fails closed.
//! Compare-and-advance is served over a length-delimited Unix socket so the
//! journal and authority are different processes and different failure
//! domains.

#![forbid(unsafe_code)]

use std::{
    collections::BTreeMap,
    error::Error,
    fmt,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::unix::{
        fs::{FileTypeExt, OpenOptionsExt, PermissionsExt},
        net::{UnixListener, UnixStream},
    },
    path::{Path, PathBuf},
    process,
    time::Duration,
};

use fs2::FileExt;
use sha2::{Digest, Sha256};
use trnm_consensus_signer_journal::{
    ExternalMonotonicWatermarkV0, ExternalWatermarkErrorV0, SignatureProducerV0,
    SignerJournalErrorV0, SignerWatermarkV0,
};
use trnm_consensus_types::{CanonicalSignIntentV0, CanonicalSignPreimageV0, SignatureBytes};

/// This slice is an external fencing authority, not a production signer.
pub const EXTERNAL_WATERMARK_AUTHORITY_V1: bool = true;
pub const EXTERNAL_WATERMARK_APPEND_ONLY_HASH_CHAIN_V1: bool = true;
pub const EXTERNAL_WATERMARK_CROSS_PROCESS_CAS_V1: bool = true;
pub const EXTERNAL_WATERMARK_PRIVATE_KEY_HANDLING_V1: bool = false;
pub const EXTERNAL_WATERMARK_CONSENSUS_RUNTIME_V1: bool = false;
pub const EXTERNAL_WATERMARK_CORE_ADMISSION_V1: bool = false;
pub const EXTERNAL_WATERMARK_SAFETY_RULES_V1: bool = false;
pub const EXTERNAL_WATERMARK_HOST_ATTESTATION_V1: bool = false;
pub const EXTERNAL_WATERMARK_VALIDATOR_RUNTIME_V1: bool = false;
pub const EXTERNAL_WATERMARK_PRODUCTION_SIGNATURE_PRODUCER_V1: bool = false;
pub const EXTERNAL_WATERMARK_PRODUCTION_ACTIVATION_V1: bool = false;

const LOG_MAGIC: &[u8; 8] = b"TRNMEW01";
const LOG_DOMAIN: &[u8] = b"trnm.consensus.external-watermark.log-record.v1\0";
const REQUEST_MAGIC: &[u8; 4] = b"EWM1";
const RESPONSE_MAGIC: &[u8; 4] = b"EWR1";
const PROTOCOL_VERSION: u8 = 1;
const OP_LOAD: u8 = 0;
const OP_COMPARE_AND_ADVANCE: u8 = 1;
const STATUS_NONE: u8 = 0;
const STATUS_VALUE: u8 = 1;
const STATUS_COMPARE_FAILED: u8 = 2;
const STATUS_INVALID_STATE: u8 = 3;
const STATUS_UNAVAILABLE: u8 = 4;
const STATUS_PROTOCOL: u8 = 5;
const WATERMARK_BYTES: usize = 32 + 32 + 8 + 32;
const RECORD_BYTES: usize = 8 + 1 + 1 + 2 + WATERMARK_BYTES + 32 + 32;
const ANCHOR_MAGIC: &[u8; 8] = b"TRNMEH01";
const ANCHOR_BODY_BYTES: usize = 8 + 1 + 3 + 8 + 32;
const ANCHOR_BYTES: usize = ANCHOR_BODY_BYTES + 32;
const MAX_FRAME_BYTES: usize = 512;

/// Public authority failure surface.  The Unix client maps these into the
/// deliberately small `ExternalWatermarkErrorV0` trait enum.
#[derive(Debug)]
pub enum ExternalWatermarkAuthorityError {
    InvalidConfig(&'static str),
    InvalidLog(&'static str),
    Io {
        stage: &'static str,
        source: io::Error,
    },
    Protocol(&'static str),
    ScopeConflict,
    CompareFailed,
    Unavailable,
}

impl fmt::Display for ExternalWatermarkAuthorityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig(reason) => write!(f, "invalid external watermark config: {reason}"),
            Self::InvalidLog(reason) => write!(f, "external watermark log rejected: {reason}"),
            Self::Io { stage, source } => write!(f, "external watermark I/O at {stage}: {source}"),
            Self::Protocol(reason) => write!(f, "external watermark protocol: {reason}"),
            Self::ScopeConflict => f.write_str("external watermark scope conflict"),
            Self::CompareFailed => f.write_str("external watermark compare-and-advance failed"),
            Self::Unavailable => f.write_str("external watermark authority unavailable"),
        }
    }
}

impl Error for ExternalWatermarkAuthorityError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct LogRecordV1 {
    value: SignerWatermarkV0,
    previous_record_hash: [u8; 32],
    record_hash: [u8; 32],
}

/// One process-owned append-only authority.  The process holds an exclusive
/// lock beside the log; another process cannot serve the same namespace.
pub struct ExternalWatermarkAuthority {
    log_path: PathBuf,
    anchor_path: PathBuf,
    directory: File,
    log: File,
    _lock: File,
    current: BTreeMap<[u8; 32], SignerWatermarkV0>,
    head_hash: [u8; 32],
    record_count: u64,
    poisoned: bool,
}

impl ExternalWatermarkAuthority {
    /// Opens and fully authenticates an existing hash chain, or creates an
    /// empty authority namespace.  No trailing partial record is tolerated.
    pub fn open(log_path: impl AsRef<Path>) -> Result<Self, ExternalWatermarkAuthorityError> {
        let (directory, log_path) = private_path(log_path.as_ref())?;
        let lock_path = lock_path_for(&log_path)?;
        let anchor_path = anchor_path_for(&log_path)?;
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&lock_path)
            .map_err(|source| ExternalWatermarkAuthorityError::Io {
                stage: "open lock",
                source,
            })?;
        if lock
            .metadata()
            .map_err(|source| ExternalWatermarkAuthorityError::Io {
                stage: "stat lock",
                source,
            })?
            .permissions()
            .mode()
            & 0o777
            != 0o600
        {
            return Err(ExternalWatermarkAuthorityError::InvalidConfig(
                "lock must have mode 0600",
            ));
        }
        lock.try_lock_exclusive()
            .map_err(|source| ExternalWatermarkAuthorityError::Io {
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
            .map_err(|source| ExternalWatermarkAuthorityError::Io {
                stage: "open append-only log",
                source,
            })?;
        let metadata = log
            .metadata()
            .map_err(|source| ExternalWatermarkAuthorityError::Io {
                stage: "stat append-only log",
                source,
            })?;
        if metadata.permissions().mode() & 0o777 != 0o600 || !metadata.is_file() {
            return Err(ExternalWatermarkAuthorityError::InvalidConfig(
                "log must be a private regular file",
            ));
        }
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
        authority.replay_log()?;
        authority.reconcile_anchor()?;
        Ok(authority)
    }

    pub fn log_path(&self) -> &Path {
        &self.log_path
    }

    pub fn load(
        &self,
        scope: [u8; 32],
    ) -> Result<Option<SignerWatermarkV0>, ExternalWatermarkAuthorityError> {
        if scope == [0; 32] {
            return Err(ExternalWatermarkAuthorityError::InvalidConfig("zero scope"));
        }
        Ok(self.current.get(&scope).copied())
    }

    pub fn compare_and_advance(
        &mut self,
        expected: Option<SignerWatermarkV0>,
        target: SignerWatermarkV0,
    ) -> Result<(), ExternalWatermarkAuthorityError> {
        if self.poisoned {
            return Err(ExternalWatermarkAuthorityError::Unavailable);
        }
        let scope = target.scope();
        if scope == [0; 32] || target.journal_id() == [0; 32] || target.chain_checksum() == [0; 32]
        {
            return Err(ExternalWatermarkAuthorityError::InvalidConfig(
                "target contains a zero identity/checksum",
            ));
        }
        let current = self.current.get(&scope).copied();
        if current != expected {
            return Err(ExternalWatermarkAuthorityError::CompareFailed);
        }
        match (current, expected) {
            (None, None) if target.sequence() == 0 => {}
            (Some(previous), Some(expected))
                if expected == previous
                    && previous.journal_id() == target.journal_id()
                    && previous.sequence().checked_add(1) == Some(target.sequence()) => {}
            _ => return Err(ExternalWatermarkAuthorityError::CompareFailed),
        }
        let previous_record_hash = self.head_hash;
        let record_hash = record_hash(target, previous_record_hash);
        let record = LogRecordV1 {
            value: target,
            previous_record_hash,
            record_hash,
        };
        let encoded = encode_record(record);
        self.log
            .write_all(&encoded)
            .map_err(|source| ExternalWatermarkAuthorityError::Io {
                stage: "append watermark record",
                source,
            })?;
        self.log
            .sync_data()
            .map_err(|source| ExternalWatermarkAuthorityError::Io {
                stage: "sync watermark record",
                source,
            })?;
        self.directory
            .sync_data()
            .map_err(|source| ExternalWatermarkAuthorityError::Io {
                stage: "sync authority directory after append",
                source,
            })?;
        self.current.insert(scope, target);
        self.record_count =
            self.record_count
                .checked_add(1)
                .ok_or(ExternalWatermarkAuthorityError::InvalidLog(
                    "record count exhausted",
                ))?;
        self.head_hash = record_hash;
        if let Err(error) = self.persist_anchor() {
            self.poisoned = true;
            return Err(error);
        }
        Ok(())
    }

    fn replay_log(&mut self) -> Result<(), ExternalWatermarkAuthorityError> {
        let mut bytes = Vec::new();
        let mut reader =
            self.log
                .try_clone()
                .map_err(|source| ExternalWatermarkAuthorityError::Io {
                    stage: "clone log for replay",
                    source,
                })?;
        reader
            .read_to_end(&mut bytes)
            .map_err(|source| ExternalWatermarkAuthorityError::Io {
                stage: "read append-only log",
                source,
            })?;
        if bytes.len() % RECORD_BYTES != 0 {
            return Err(ExternalWatermarkAuthorityError::InvalidLog(
                "trailing partial record",
            ));
        }
        for chunk in bytes.chunks_exact(RECORD_BYTES) {
            let record = decode_record(chunk)?;
            if record.previous_record_hash != self.head_hash {
                return Err(ExternalWatermarkAuthorityError::InvalidLog(
                    "hash chain predecessor mismatch",
                ));
            }
            if record.record_hash != record_hash(record.value, self.head_hash) {
                return Err(ExternalWatermarkAuthorityError::InvalidLog(
                    "record checksum mismatch",
                ));
            }
            let scope = record.value.scope();
            match self.current.get(&scope).copied() {
                None if record.value.sequence() == 0 => {}
                Some(previous)
                    if previous.journal_id() == record.value.journal_id()
                        && previous.sequence().checked_add(1) == Some(record.value.sequence()) => {}
                _ => {
                    return Err(ExternalWatermarkAuthorityError::InvalidLog(
                        "scope sequence/journal fork",
                    ))
                }
            }
            self.current.insert(scope, record.value);
            self.head_hash = record.record_hash;
            self.record_count = self.record_count.checked_add(1).ok_or(
                ExternalWatermarkAuthorityError::InvalidLog("record count exhausted"),
            )?;
        }
        Ok(())
    }

    fn reconcile_anchor(&mut self) -> Result<(), ExternalWatermarkAuthorityError> {
        let bytes = match fs::read(&self.anchor_path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                if self.record_count != 0 {
                    return Err(ExternalWatermarkAuthorityError::InvalidLog(
                        "non-empty log has no durable head anchor",
                    ));
                }
                self.persist_anchor()?;
                return Ok(());
            }
            Err(source) => {
                return Err(ExternalWatermarkAuthorityError::Io {
                    stage: "read durable head anchor",
                    source,
                })
            }
        };
        let (anchored_count, anchored_head) = decode_anchor(&bytes)?;
        if anchored_count > self.record_count {
            return Err(ExternalWatermarkAuthorityError::InvalidLog(
                "append-only log is shorter than durable head anchor",
            ));
        }
        if anchored_count == self.record_count && anchored_head != self.head_hash {
            return Err(ExternalWatermarkAuthorityError::InvalidLog(
                "durable head anchor differs from log head",
            ));
        }
        // A crash after the log fsync but before the anchor rename leaves the
        // log ahead. Replaying and advancing the anchor is monotonic and safe;
        // the inverse (anchor ahead of log) is always a hard failure above.
        if anchored_count < self.record_count {
            self.persist_anchor()?;
        }
        Ok(())
    }

    fn persist_anchor(&self) -> Result<(), ExternalWatermarkAuthorityError> {
        let name = self
            .anchor_path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or(ExternalWatermarkAuthorityError::InvalidConfig(
                "anchor filename",
            ))?;
        let temporary = self.anchor_path.with_file_name(format!(
            ".{name}.tmp-{}-{}",
            process::id(),
            self.record_count
        ));
        let bytes = encode_anchor(self.record_count, self.head_hash);
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
            return Err(ExternalWatermarkAuthorityError::Io {
                stage: "persist durable head anchor",
                source,
            });
        }
        Ok(())
    }

    fn handle_request(
        &mut self,
        mut stream: UnixStream,
    ) -> Result<(), ExternalWatermarkAuthorityError> {
        if self.poisoned {
            return Err(ExternalWatermarkAuthorityError::Unavailable);
        }
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .map_err(|source| ExternalWatermarkAuthorityError::Io {
                stage: "set request timeout",
                source,
            })?;
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .map_err(|source| ExternalWatermarkAuthorityError::Io {
                stage: "set response timeout",
                source,
            })?;
        let body = read_frame(&mut stream)?;
        let request = decode_request(&body)?;
        let response = match request {
            RequestV1::Load { scope } => match self.load(scope) {
                Ok(Some(value)) => encode_value_response(value),
                Ok(None) => encode_empty_response(STATUS_NONE),
                Err(_) => encode_empty_response(STATUS_INVALID_STATE),
            },
            RequestV1::CompareAndAdvance { expected, target } => {
                match self.compare_and_advance(expected, target) {
                    Ok(()) => encode_empty_response(STATUS_NONE),
                    Err(ExternalWatermarkAuthorityError::CompareFailed) => {
                        encode_empty_response(STATUS_COMPARE_FAILED)
                    }
                    Err(ExternalWatermarkAuthorityError::InvalidConfig(_)) => {
                        encode_empty_response(STATUS_INVALID_STATE)
                    }
                    Err(_) => encode_empty_response(STATUS_UNAVAILABLE),
                }
            }
        };
        write_frame(&mut stream, &response)
    }

    /// Runs the blocking daemon loop.  The caller owns process lifetime; a
    /// kill-9 leaves either a complete fsync'd record or a detectable partial
    /// record, never an accepted silent rollback.
    pub fn serve_unix(
        mut self,
        socket_path: impl AsRef<Path>,
    ) -> Result<(), ExternalWatermarkAuthorityError> {
        let socket_path = socket_path.as_ref();
        remove_stale_socket(socket_path)?;
        let listener = UnixListener::bind(socket_path).map_err(|source| {
            ExternalWatermarkAuthorityError::Io {
                stage: "bind authority socket",
                source,
            }
        })?;
        fs::set_permissions(socket_path, fs::Permissions::from_mode(0o600)).map_err(|source| {
            ExternalWatermarkAuthorityError::Io {
                stage: "protect authority socket",
                source,
            }
        })?;
        for stream in listener.incoming() {
            match stream {
                Ok(stream) => {
                    // A malformed client frame is rejected without taking the
                    // daemon down.  A durable-log error poisons this process;
                    // a supervisor must restart and revalidate the chain.
                    if let Err(error) = self.handle_request(stream) {
                        if matches!(error, ExternalWatermarkAuthorityError::InvalidLog(_)) {
                            return Err(error);
                        }
                    }
                }
                Err(source) => {
                    return Err(ExternalWatermarkAuthorityError::Io {
                        stage: "accept authority connection",
                        source,
                    })
                }
            }
        }
        Ok(())
    }
}

/// Unix client implementing the signer-journal external watermark trait.
#[derive(Debug, Clone)]
pub struct UnixWatermarkClient {
    socket_path: PathBuf,
    timeout: Duration,
}

impl UnixWatermarkClient {
    pub fn new(socket_path: impl AsRef<Path>) -> Result<Self, ExternalWatermarkAuthorityError> {
        let socket_path = socket_path.as_ref();
        if !socket_path.is_absolute() || socket_path.file_name().is_none() {
            return Err(ExternalWatermarkAuthorityError::InvalidConfig(
                "authority socket must be an absolute path",
            ));
        }
        Ok(Self {
            socket_path: socket_path.to_path_buf(),
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

    fn request(&self, request: RequestV1) -> Result<ResponseV1, ExternalWatermarkAuthorityError> {
        let mut stream = UnixStream::connect(&self.socket_path).map_err(|source| {
            ExternalWatermarkAuthorityError::Io {
                stage: "connect authority socket",
                source,
            }
        })?;
        stream
            .set_read_timeout(Some(self.timeout))
            .map_err(|source| ExternalWatermarkAuthorityError::Io {
                stage: "set client read timeout",
                source,
            })?;
        stream
            .set_write_timeout(Some(self.timeout))
            .map_err(|source| ExternalWatermarkAuthorityError::Io {
                stage: "set client write timeout",
                source,
            })?;
        write_frame(&mut stream, &encode_request(request))?;
        decode_response(&read_frame(&mut stream)?)
    }

    pub fn load_checked(
        &self,
        scope: [u8; 32],
    ) -> Result<Option<SignerWatermarkV0>, ExternalWatermarkAuthorityError> {
        match self.request(RequestV1::Load { scope })? {
            ResponseV1::None => Ok(None),
            ResponseV1::Value(value) => Ok(Some(value)),
            ResponseV1::CompareFailed => Err(ExternalWatermarkAuthorityError::CompareFailed),
            ResponseV1::InvalidState => Err(ExternalWatermarkAuthorityError::InvalidLog(
                "authority rejected persisted state",
            )),
            ResponseV1::Unavailable => Err(ExternalWatermarkAuthorityError::Unavailable),
        }
    }

    pub fn compare_and_advance_checked(
        &self,
        expected: Option<SignerWatermarkV0>,
        target: SignerWatermarkV0,
    ) -> Result<(), ExternalWatermarkAuthorityError> {
        match self.request(RequestV1::CompareAndAdvance { expected, target })? {
            ResponseV1::None => Ok(()),
            ResponseV1::CompareFailed => Err(ExternalWatermarkAuthorityError::CompareFailed),
            ResponseV1::InvalidState => Err(ExternalWatermarkAuthorityError::InvalidLog(
                "authority rejected persisted state",
            )),
            ResponseV1::Unavailable => Err(ExternalWatermarkAuthorityError::Unavailable),
            ResponseV1::Value(_) => Err(ExternalWatermarkAuthorityError::Protocol(
                "compare response unexpectedly carried a value",
            )),
        }
    }
}

impl ExternalMonotonicWatermarkV0 for UnixWatermarkClient {
    fn load(
        &mut self,
        scope: [u8; 32],
    ) -> Result<Option<SignerWatermarkV0>, ExternalWatermarkErrorV0> {
        self.load_checked(scope).map_err(map_client_error)
    }

    fn compare_and_advance(
        &mut self,
        expected: Option<SignerWatermarkV0>,
        target: SignerWatermarkV0,
    ) -> Result<(), ExternalWatermarkErrorV0> {
        self.compare_and_advance_checked(expected, target)
            .map_err(map_client_error)
    }
}

/// Timeout-only adapter around the existing append-only local signer journal.
/// It rejects Vote intents before the journal can reach a producer.  It is
/// intentionally generic over the external client and producer so tests can
/// prove ordering without introducing a production key implementation.
pub struct TimeoutOnlySignerAdapter<W, P> {
    journal: trnm_consensus_signer_journal::SqliteSignerJournalV0<W>,
    producer: P,
}

impl<W, P> TimeoutOnlySignerAdapter<W, P>
where
    W: ExternalMonotonicWatermarkV0,
    P: SignatureProducerV0,
{
    pub fn new(
        journal: trnm_consensus_signer_journal::SqliteSignerJournalV0<W>,
        producer: P,
    ) -> Self {
        Self { journal, producer }
    }

    pub fn sign_timeout_only(
        &mut self,
        intent: &CanonicalSignIntentV0,
    ) -> Result<SignatureBytes, SignerJournalErrorV0> {
        if !matches!(intent.preimage(), CanonicalSignPreimageV0::TimeoutVote(_)) {
            return Err(SignerJournalErrorV0::InvalidProfile(
                "timeout-only adapter rejects non-timeout intent",
            ));
        }
        self.journal.sign_exact_v0(intent, &mut self.producer)
    }

    pub fn journal(&self) -> &trnm_consensus_signer_journal::SqliteSignerJournalV0<W> {
        &self.journal
    }
}

#[derive(Debug, Clone, Copy)]
enum RequestV1 {
    Load {
        scope: [u8; 32],
    },
    CompareAndAdvance {
        expected: Option<SignerWatermarkV0>,
        target: SignerWatermarkV0,
    },
}

#[derive(Debug, Clone, Copy)]
enum ResponseV1 {
    None,
    Value(SignerWatermarkV0),
    CompareFailed,
    InvalidState,
    Unavailable,
}

fn map_client_error(error: ExternalWatermarkAuthorityError) -> ExternalWatermarkErrorV0 {
    match error {
        ExternalWatermarkAuthorityError::CompareFailed
        | ExternalWatermarkAuthorityError::ScopeConflict => ExternalWatermarkErrorV0::CompareFailed,
        ExternalWatermarkAuthorityError::InvalidLog(_)
        | ExternalWatermarkAuthorityError::InvalidConfig(_)
        | ExternalWatermarkAuthorityError::Protocol(_) => {
            ExternalWatermarkErrorV0::InvalidPersistedState
        }
        ExternalWatermarkAuthorityError::Io { .. }
        | ExternalWatermarkAuthorityError::Unavailable => ExternalWatermarkErrorV0::Unavailable,
    }
}

fn private_path(path: &Path) -> Result<(File, PathBuf), ExternalWatermarkAuthorityError> {
    if !path.is_absolute() || path.file_name().is_none() {
        return Err(ExternalWatermarkAuthorityError::InvalidConfig(
            "log path must be absolute",
        ));
    }
    let parent = path
        .parent()
        .ok_or(ExternalWatermarkAuthorityError::InvalidConfig("log parent"))?;
    let parent =
        fs::canonicalize(parent).map_err(|source| ExternalWatermarkAuthorityError::Io {
            stage: "canonicalize log parent",
            source,
        })?;
    let metadata =
        fs::symlink_metadata(&parent).map_err(|source| ExternalWatermarkAuthorityError::Io {
            stage: "stat log parent",
            source,
        })?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(ExternalWatermarkAuthorityError::InvalidConfig(
            "log parent must be a private directory",
        ));
    }
    let name = path
        .file_name()
        .ok_or(ExternalWatermarkAuthorityError::InvalidConfig(
            "log filename",
        ))?;
    let log_path = parent.join(name);
    let directory = File::open(&parent).map_err(|source| ExternalWatermarkAuthorityError::Io {
        stage: "open log parent",
        source,
    })?;
    Ok((directory, log_path))
}

fn lock_path_for(log_path: &Path) -> Result<PathBuf, ExternalWatermarkAuthorityError> {
    let name = log_path.file_name().and_then(|name| name.to_str()).ok_or(
        ExternalWatermarkAuthorityError::InvalidConfig("lock filename"),
    )?;
    Ok(log_path.with_file_name(format!(".{name}.lock-v1")))
}

fn anchor_path_for(log_path: &Path) -> Result<PathBuf, ExternalWatermarkAuthorityError> {
    let name = log_path.file_name().and_then(|name| name.to_str()).ok_or(
        ExternalWatermarkAuthorityError::InvalidConfig("anchor filename"),
    )?;
    Ok(log_path.with_file_name(format!(".{name}.head-v1")))
}

fn remove_stale_socket(path: &Path) -> Result<(), ExternalWatermarkAuthorityError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_socket() => {
            fs::remove_file(path).map_err(|source| ExternalWatermarkAuthorityError::Io {
                stage: "remove stale authority socket",
                source,
            })?;
        }
        Ok(_) => {
            return Err(ExternalWatermarkAuthorityError::InvalidConfig(
                "socket path is not a Unix socket",
            ))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(source) => {
            return Err(ExternalWatermarkAuthorityError::Io {
                stage: "inspect authority socket",
                source,
            })
        }
    }
    Ok(())
}

fn record_hash(value: SignerWatermarkV0, previous: [u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(LOG_DOMAIN);
    hasher.update(previous);
    hasher.update(value.scope());
    hasher.update(value.journal_id());
    hasher.update(value.sequence().to_be_bytes());
    hasher.update(value.chain_checksum());
    hasher.finalize().into()
}

fn encode_record(record: LogRecordV1) -> [u8; RECORD_BYTES] {
    let mut bytes = [0u8; RECORD_BYTES];
    let mut offset = 0;
    bytes[offset..offset + 8].copy_from_slice(LOG_MAGIC);
    offset += 8;
    bytes[offset] = PROTOCOL_VERSION;
    offset += 1;
    bytes[offset] = 1;
    offset += 1;
    offset += 2;
    bytes[offset..offset + 32].copy_from_slice(&record.value.scope());
    offset += 32;
    bytes[offset..offset + 32].copy_from_slice(&record.value.journal_id());
    offset += 32;
    bytes[offset..offset + 8].copy_from_slice(&record.value.sequence().to_be_bytes());
    offset += 8;
    bytes[offset..offset + 32].copy_from_slice(&record.value.chain_checksum());
    offset += 32;
    bytes[offset..offset + 32].copy_from_slice(&record.previous_record_hash);
    offset += 32;
    bytes[offset..offset + 32].copy_from_slice(&record.record_hash);
    bytes
}

fn decode_record(bytes: &[u8]) -> Result<LogRecordV1, ExternalWatermarkAuthorityError> {
    if bytes.len() != RECORD_BYTES
        || &bytes[..8] != LOG_MAGIC
        || bytes[8] != PROTOCOL_VERSION
        || bytes[9] != 1
        || bytes[10..12] != [0, 0]
    {
        return Err(ExternalWatermarkAuthorityError::InvalidLog("record header"));
    }
    let scope = bytes[12..44].try_into().expect("record scope");
    let journal_id = bytes[44..76].try_into().expect("record journal");
    let sequence = u64::from_be_bytes(bytes[76..84].try_into().expect("record sequence"));
    let chain_checksum = bytes[84..116].try_into().expect("record checksum");
    let previous_record_hash = bytes[116..148].try_into().expect("record predecessor");
    let record_hash = bytes[148..180].try_into().expect("record hash");
    let value =
        SignerWatermarkV0::from_persisted_parts(scope, journal_id, sequence, chain_checksum)
            .map_err(|_| ExternalWatermarkAuthorityError::InvalidLog("record watermark fields"))?;
    Ok(LogRecordV1 {
        value,
        previous_record_hash,
        record_hash,
    })
}

fn anchor_checksum(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(ANCHOR_MAGIC);
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
    hasher.finalize().into()
}

fn encode_anchor(record_count: u64, head_hash: [u8; 32]) -> [u8; ANCHOR_BYTES] {
    let mut bytes = [0u8; ANCHOR_BYTES];
    bytes[..8].copy_from_slice(ANCHOR_MAGIC);
    bytes[8] = PROTOCOL_VERSION;
    bytes[9..12].copy_from_slice(&[0, 0, 0]);
    bytes[12..20].copy_from_slice(&record_count.to_be_bytes());
    bytes[20..52].copy_from_slice(&head_hash);
    let checksum = anchor_checksum(&bytes[..ANCHOR_BODY_BYTES]);
    bytes[ANCHOR_BODY_BYTES..].copy_from_slice(&checksum);
    bytes
}

fn decode_anchor(bytes: &[u8]) -> Result<(u64, [u8; 32]), ExternalWatermarkAuthorityError> {
    if bytes.len() != ANCHOR_BYTES
        || &bytes[..8] != ANCHOR_MAGIC
        || bytes[8] != PROTOCOL_VERSION
        || bytes[9..12] != [0, 0, 0]
    {
        return Err(ExternalWatermarkAuthorityError::InvalidLog(
            "durable head anchor header",
        ));
    }
    if bytes[ANCHOR_BODY_BYTES..] != anchor_checksum(&bytes[..ANCHOR_BODY_BYTES]) {
        return Err(ExternalWatermarkAuthorityError::InvalidLog(
            "durable head anchor checksum",
        ));
    }
    let count = u64::from_be_bytes(bytes[12..20].try_into().expect("anchor count"));
    let head = bytes[20..52].try_into().expect("anchor head");
    if count == 0 && head != [0; 32] {
        return Err(ExternalWatermarkAuthorityError::InvalidLog(
            "empty durable head anchor is nonzero",
        ));
    }
    if count != 0 && head == [0; 32] {
        return Err(ExternalWatermarkAuthorityError::InvalidLog(
            "non-empty durable head anchor is zero",
        ));
    }
    Ok((count, head))
}

fn encode_watermark(value: SignerWatermarkV0, output: &mut Vec<u8>) {
    output.extend_from_slice(&value.scope());
    output.extend_from_slice(&value.journal_id());
    output.extend_from_slice(&value.sequence().to_be_bytes());
    output.extend_from_slice(&value.chain_checksum());
}

fn decode_watermark(bytes: &[u8]) -> Result<SignerWatermarkV0, ExternalWatermarkAuthorityError> {
    if bytes.len() < WATERMARK_BYTES {
        return Err(ExternalWatermarkAuthorityError::Protocol("short watermark"));
    }
    let scope = bytes[..32].try_into().expect("watermark scope");
    let journal_id = bytes[32..64].try_into().expect("watermark journal");
    let sequence = u64::from_be_bytes(bytes[64..72].try_into().expect("watermark sequence"));
    let checksum = bytes[72..104].try_into().expect("watermark checksum");
    SignerWatermarkV0::from_persisted_parts(scope, journal_id, sequence, checksum)
        .map_err(|_| ExternalWatermarkAuthorityError::Protocol("invalid watermark"))
}

fn encode_request(request: RequestV1) -> Vec<u8> {
    let mut body = Vec::with_capacity(MAX_FRAME_BYTES);
    body.extend_from_slice(REQUEST_MAGIC);
    body.push(PROTOCOL_VERSION);
    match request {
        RequestV1::Load { scope } => {
            body.push(OP_LOAD);
            body.push(0);
            body.extend_from_slice(&[0, 0]);
            body.extend_from_slice(&scope);
        }
        RequestV1::CompareAndAdvance { expected, target } => {
            body.push(OP_COMPARE_AND_ADVANCE);
            body.push(u8::from(expected.is_some()));
            body.extend_from_slice(&[0, 0]);
            body.extend_from_slice(&target.scope());
            if let Some(expected) = expected {
                encode_watermark(expected, &mut body);
            }
            encode_watermark(target, &mut body);
        }
    }
    body
}

fn decode_request(body: &[u8]) -> Result<RequestV1, ExternalWatermarkAuthorityError> {
    if body.len() < 9 || &body[..4] != REQUEST_MAGIC || body[4] != PROTOCOL_VERSION {
        return Err(ExternalWatermarkAuthorityError::Protocol("request header"));
    }
    let operation = body[5];
    let expected_present = body[6];
    if body[7..9] != [0, 0] || body.len() > MAX_FRAME_BYTES {
        return Err(ExternalWatermarkAuthorityError::Protocol("request flags"));
    }
    match operation {
        OP_LOAD if expected_present == 0 && body.len() == 41 => {
            let scope = body[9..41].try_into().expect("load scope");
            Ok(RequestV1::Load { scope })
        }
        OP_COMPARE_AND_ADVANCE if expected_present <= 1 => {
            let expected_len = if expected_present == 1 {
                WATERMARK_BYTES
            } else {
                0
            };
            let expected_start = 41;
            let target_start = expected_start + expected_len;
            if body.len() != target_start + WATERMARK_BYTES {
                return Err(ExternalWatermarkAuthorityError::Protocol(
                    "compare request length",
                ));
            }
            let scope: [u8; 32] = body[9..41].try_into().expect("compare scope");
            let expected = if expected_present == 1 {
                Some(decode_watermark(&body[expected_start..target_start])?)
            } else {
                None
            };
            let target = decode_watermark(&body[target_start..])?;
            if target.scope() != scope {
                return Err(ExternalWatermarkAuthorityError::Protocol(
                    "target scope differs",
                ));
            }
            Ok(RequestV1::CompareAndAdvance { expected, target })
        }
        _ => Err(ExternalWatermarkAuthorityError::Protocol(
            "unsupported request operation",
        )),
    }
}

fn encode_empty_response(status: u8) -> Vec<u8> {
    vec![
        RESPONSE_MAGIC[0],
        RESPONSE_MAGIC[1],
        RESPONSE_MAGIC[2],
        RESPONSE_MAGIC[3],
        PROTOCOL_VERSION,
        status,
        0,
        0,
    ]
}

fn encode_value_response(value: SignerWatermarkV0) -> Vec<u8> {
    let mut body = encode_empty_response(STATUS_VALUE);
    encode_watermark(value, &mut body);
    body
}

fn decode_response(body: &[u8]) -> Result<ResponseV1, ExternalWatermarkAuthorityError> {
    if body.len() < 8 || &body[..4] != RESPONSE_MAGIC || body[4] != PROTOCOL_VERSION {
        return Err(ExternalWatermarkAuthorityError::Protocol("response header"));
    }
    let status = body[5];
    if body[6..8] != [0, 0] {
        return Err(ExternalWatermarkAuthorityError::Protocol("response flags"));
    }
    match status {
        STATUS_NONE if body.len() == 8 => Ok(ResponseV1::None),
        STATUS_VALUE if body.len() == 8 + WATERMARK_BYTES => {
            Ok(ResponseV1::Value(decode_watermark(&body[8..])?))
        }
        STATUS_COMPARE_FAILED if body.len() == 8 => Ok(ResponseV1::CompareFailed),
        STATUS_INVALID_STATE if body.len() == 8 => Ok(ResponseV1::InvalidState),
        STATUS_UNAVAILABLE if body.len() == 8 => Ok(ResponseV1::Unavailable),
        STATUS_PROTOCOL if body.len() == 8 => Err(ExternalWatermarkAuthorityError::Protocol(
            "remote protocol failure",
        )),
        _ => Err(ExternalWatermarkAuthorityError::Protocol("response shape")),
    }
}

fn read_frame(stream: &mut UnixStream) -> Result<Vec<u8>, ExternalWatermarkAuthorityError> {
    let mut length = [0u8; 4];
    stream
        .read_exact(&mut length)
        .map_err(|source| ExternalWatermarkAuthorityError::Io {
            stage: "read frame length",
            source,
        })?;
    let length = u32::from_be_bytes(length) as usize;
    if length == 0 || length > MAX_FRAME_BYTES {
        return Err(ExternalWatermarkAuthorityError::Protocol("frame length"));
    }
    let mut body = vec![0u8; length];
    stream
        .read_exact(&mut body)
        .map_err(|source| ExternalWatermarkAuthorityError::Io {
            stage: "read frame body",
            source,
        })?;
    Ok(body)
}

fn write_frame(
    stream: &mut UnixStream,
    body: &[u8],
) -> Result<(), ExternalWatermarkAuthorityError> {
    if body.is_empty() || body.len() > MAX_FRAME_BYTES {
        return Err(ExternalWatermarkAuthorityError::Protocol(
            "frame body length",
        ));
    }
    stream
        .write_all(&(body.len() as u32).to_be_bytes())
        .and_then(|_| stream.write_all(body))
        .and_then(|_| stream.flush())
        .map_err(|source| ExternalWatermarkAuthorityError::Io {
            stage: "write frame",
            source,
        })
}

/// Handles one stream request for tests that embed the authority in a parent
/// process.  Production-like tests use the standalone binary instead.
pub fn serve_connection(
    authority: &mut ExternalWatermarkAuthority,
    stream: UnixStream,
) -> Result<(), ExternalWatermarkAuthorityError> {
    authority.handle_request(stream)
}

/// Runs the standalone authority daemon from a socket and append-only log.
pub fn run_daemon(
    socket_path: impl AsRef<Path>,
    log_path: impl AsRef<Path>,
) -> Result<(), ExternalWatermarkAuthorityError> {
    ExternalWatermarkAuthority::open(log_path)?.serve_unix(socket_path)
}

#[cfg(test)]
mod source_contract_tests {
    #[test]
    fn activation_and_key_boundaries_remain_closed() {
        let manifest = include_str!("../Cargo.toml");
        let source = include_str!("lib.rs");
        for required in [
            "append_only_hash_chain = true",
            "cross_process_cas = true",
            "private_key_handling = false",
            "consensus_runtime = false",
            "core_admission = false",
            "safety_rules = false",
            "host_attestation = false",
            "validator_runtime = false",
            "production_signature_producer = false",
            "production_activation = false",
        ] {
            assert!(manifest.contains(required), "missing metadata {required}");
        }
        for forbidden in [
            concat!("Signing", "Key"),
            concat!("Secret", "Key"),
            concat!("ed25519", "-dalek"),
            concat!("production_activation", " = true"),
        ] {
            assert!(
                !source.contains(forbidden),
                "forbidden authority token {forbidden}"
            );
        }
    }
}
