//! Bounded Unix transport and append-only CAS store for owner checkpoints.
//! No signer, host attestation, ledger runtime or activation is provided.
//! Use a fresh private V2 namespace and independently reconcile local roots.

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
use trnm_checkpoint_types::{
    ExternalCheckpointStoreErrorV2, ExternalCheckpointStoreV2, ExternalCheckpointV2,
    EXTERNAL_CHECKPOINT_RECORD_BYTES_V2,
};

/// This adapter is a cross-process CAS transport, not operational node
/// integration.  The canonical node gate remains independently false.
pub const EXTERNAL_CHECKPOINT_UNIX_ADAPTER_V2: bool = true;
pub const EXTERNAL_CHECKPOINT_PRIVATE_KEY_HANDLING_V2: bool = false;
pub const EXTERNAL_CHECKPOINT_CONSENSUS_RUNTIME_V2: bool = false;
pub const EXTERNAL_CHECKPOINT_CORE_ADMISSION_V2: bool = false;
pub const EXTERNAL_CHECKPOINT_SAFETY_RULES_V2: bool = false;
pub const EXTERNAL_CHECKPOINT_HOST_ATTESTATION_V2: bool = false;
pub const EXTERNAL_CHECKPOINT_PRODUCTION_ACTIVATION_V2: bool = false;

const PROTOCOL_VERSION_V2: u8 = 2;
const REQUEST_MAGIC_V2: &[u8; 4] = b"CP2R";
const RESPONSE_MAGIC_V2: &[u8; 4] = b"CP2S";
const LOG_MAGIC_V2: &[u8; 8] = b"TRNMCPJ2";
const ANCHOR_MAGIC_V2: &[u8; 8] = b"TRNMCPA2";
const LOG_DOMAIN_V2: &[u8] = b"trnm.external-node-checkpoint.log.v2\0";
const ANCHOR_DOMAIN_V2: &[u8] = b"trnm.external-node-checkpoint.anchor.v2\0";
const MAX_FRAME_BYTES_V2: usize = 4096;
const CHECKPOINT_BYTES_V2: usize = EXTERNAL_CHECKPOINT_RECORD_BYTES_V2;
// magic + version + operation + reserved + sequence + scope + expected flag
// + expected slot + target + predecessor hash + record hash
const LOG_RECORD_BYTES_V2: usize =
    8 + 1 + 1 + 2 + 8 + 32 + 1 + CHECKPOINT_BYTES_V2 + CHECKPOINT_BYTES_V2 + 32 + 32;
const ANCHOR_BODY_BYTES_V2: usize = 8 + 1 + 3 + 8 + 32;
const ANCHOR_BYTES_V2: usize = ANCHOR_BODY_BYTES_V2 + 32;

const OP_COMPARE_AND_ADVANCE_V2: u8 = 1;
const OP_LOAD_V2: u8 = 2;
const STATUS_VALUE_V2: u8 = 1;
const STATUS_NONE_V2: u8 = 2;
const STATUS_APPLIED_V2: u8 = 3;
const STATUS_COMPARE_FAILED_V2: u8 = 4;
const STATUS_INVALID_STATE_V2: u8 = 5;
const STATUS_UNAVAILABLE_V2: u8 = 6;
const STATUS_PROTOCOL_V2: u8 = 7;

/// Errors internal to the daemon/client transport.  The public trait maps
/// these into its deliberately small closed error enum.
#[derive(Debug)]
pub enum ExternalCheckpointAuthorityErrorV2 {
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

impl fmt::Display for ExternalCheckpointAuthorityErrorV2 {
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

impl Error for ExternalCheckpointAuthorityErrorV2 {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

impl From<io::Error> for ExternalCheckpointAuthorityErrorV2 {
    fn from(source: io::Error) -> Self {
        Self::Io {
            stage: "Unix transport",
            source,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct LogRecordV2 {
    sequence: u64,
    scope: [u8; 32],
    expected: Option<ExternalCheckpointV2>,
    target: ExternalCheckpointV2,
    previous_hash: [u8; 32],
    record_hash: [u8; 32],
}

/// Descriptor/path identity retained by the candidate checkpoint owner.
///
/// A valid hash chain does not protect an already-open owner from a same-UID
/// rename-and-replace of its log, lock, head, or parent directory.  Keep the
/// identity fence local to this Unix adapter so every request can fail closed
/// before it treats a pathname as the authority it originally opened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CheckpointPathIdentityV2 {
    device: u64,
    inode: u64,
    owner: u32,
    mode: u32,
    links: u64,
    kind: u8,
}

impl CheckpointPathIdentityV2 {
    fn from_metadata(metadata: &fs::Metadata) -> Self {
        let kind = if metadata.is_dir() {
            1
        } else if metadata.is_file() {
            2
        } else {
            0
        };
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            owner: metadata.uid(),
            mode: metadata.mode() & 0o7777,
            links: metadata.nlink(),
            kind,
        }
    }

    /// Compare the stable object identity fields.  Directory link counts are
    /// intentionally excluded: creating/removing a child directory changes a
    /// parent directory's `nlink` without replacing the directory itself.
    fn same_object(self, other: Self) -> bool {
        self.device == other.device
            && self.inode == other.inode
            && self.owner == other.owner
            && self.mode == other.mode
            && self.kind == other.kind
            && (self.kind == 1 || self.links == other.links)
    }
}

/// One process-owned checkpoint authority.  The process lock prevents a
/// second daemon from serving the same namespace; clients only use the Unix
/// socket and cannot mutate the journal directly through this API.
pub struct ExternalCheckpointAuthorityV2 {
    log_path: PathBuf,
    anchor_path: PathBuf,
    lock_path: PathBuf,
    directory_path: PathBuf,
    directory: File,
    directory_identity: CheckpointPathIdentityV2,
    log: File,
    log_identity: CheckpointPathIdentityV2,
    _lock: File,
    lock_identity: CheckpointPathIdentityV2,
    anchor_identity: Option<CheckpointPathIdentityV2>,
    current: BTreeMap<[u8; 32], ExternalCheckpointV2>,
    head_hash: [u8; 32],
    record_count: u64,
    poisoned: bool,
}

impl ExternalCheckpointAuthorityV2 {
    /// Open and authenticate the entire append-only journal.  No repair or
    /// truncation is attempted.  A partial tail, stale anchor, or hash-chain
    /// mismatch is a hard startup failure.
    pub fn open(log_path: impl AsRef<Path>) -> Result<Self, ExternalCheckpointAuthorityErrorV2> {
        let (directory, log_path) = private_path_v2(log_path.as_ref())?;
        let directory_path = log_path
            .parent()
            .ok_or(ExternalCheckpointAuthorityErrorV2::InvalidConfig(
                "checkpoint journal parent",
            ))?
            .to_path_buf();
        let directory_identity = checkpoint_path_identity_from_file_v2(&directory)?;
        verify_checkpoint_path_identity_v2(&directory_path, directory_identity, true)?;
        let lock_path = sidecar_path_v2(&log_path, "lock-v2")?;
        let anchor_path = sidecar_path_v2(&log_path, "head-v2")?;
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&lock_path)
            .map_err(|source| ExternalCheckpointAuthorityErrorV2::Io {
                stage: "open authority lock",
                source,
            })?;
        validate_private_file_v2(&lock, "authority lock")?;
        let lock_identity = checkpoint_path_identity_from_file_v2(&lock)?;
        verify_checkpoint_path_identity_v2(&lock_path, lock_identity, false)?;
        lock.try_lock_exclusive()
            .map_err(|source| ExternalCheckpointAuthorityErrorV2::Io {
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
            .map_err(|source| ExternalCheckpointAuthorityErrorV2::Io {
                stage: "open checkpoint journal",
                source,
            })?;
        validate_private_file_v2(&log, "checkpoint journal")?;
        let log_identity = checkpoint_path_identity_from_file_v2(&log)?;
        verify_checkpoint_path_identity_v2(&log_path, log_identity, false)?;
        let mut authority = Self {
            log_path,
            anchor_path,
            lock_path,
            directory_path,
            directory,
            directory_identity,
            log,
            log_identity,
            _lock: lock,
            lock_identity,
            anchor_identity: None,
            current: BTreeMap::new(),
            head_hash: [0; 32],
            record_count: 0,
            poisoned: false,
        };
        authority.replay_log_v2()?;
        authority.reconcile_anchor_v2()?;
        authority.revalidate_bound_endpoints_v2()?;
        Ok(authority)
    }

    pub fn log_path(&self) -> &Path {
        &self.log_path
    }

    /// Revalidate every descriptor and canonical pathname bound by this
    /// authority.  This is a candidate fail-closed fence for same-UID
    /// rename/replace races; it is not a whole-node external anti-rollback
    /// anchor and does not promote the adapter to production use.
    pub fn revalidate_bound_endpoints_v2(&self) -> Result<(), ExternalCheckpointAuthorityErrorV2> {
        self.revalidate_base_endpoints_v2()?;
        self.validate_anchor_endpoint_v2()?;
        Ok(())
    }

    fn revalidate_base_endpoints_v2(&self) -> Result<(), ExternalCheckpointAuthorityErrorV2> {
        self.validate_directory_identity_v2()?;
        self.validate_file_identity_v2(&self.log_path, &self.log, self.log_identity)?;
        self.validate_file_identity_v2(&self.lock_path, &self._lock, self.lock_identity)?;
        Ok(())
    }

    fn validate_anchor_endpoint_v2(&self) -> Result<(), ExternalCheckpointAuthorityErrorV2> {
        match self.anchor_identity {
            Some(identity) => {
                verify_checkpoint_path_identity_v2(&self.anchor_path, identity, false)
            }
            None => match fs::symlink_metadata(&self.anchor_path) {
                Ok(_) => Err(ExternalCheckpointAuthorityErrorV2::InvalidLog(
                    "checkpoint head appeared after it was bound absent",
                )),
                Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
                Err(_) => Err(ExternalCheckpointAuthorityErrorV2::InvalidLog(
                    "checkpoint head identity cannot be inspected",
                )),
            },
        }
    }

    pub fn load_checked(
        &self,
        scope: [u8; 32],
    ) -> Result<Option<ExternalCheckpointV2>, ExternalCheckpointAuthorityErrorV2> {
        if self.poisoned {
            return Err(ExternalCheckpointAuthorityErrorV2::Unavailable);
        }
        self.revalidate_bound_endpoints_v2()?;
        if scope == [0; 32] {
            return Err(ExternalCheckpointAuthorityErrorV2::InvalidConfig(
                "zero scope",
            ));
        }
        let value = self.current.get(&scope).copied();
        self.revalidate_bound_endpoints_v2()?;
        Ok(value)
    }

    pub fn compare_and_advance_checked(
        &mut self,
        expected: Option<ExternalCheckpointV2>,
        target: ExternalCheckpointV2,
    ) -> Result<(), ExternalCheckpointAuthorityErrorV2> {
        if self.poisoned {
            return Err(ExternalCheckpointAuthorityErrorV2::Unavailable);
        }
        self.revalidate_bound_endpoints_v2()?;
        let scope = target.scope();
        if scope == [0; 32] || target.encode_canonical().iter().all(|byte| *byte == 0) {
            return Err(ExternalCheckpointAuthorityErrorV2::InvalidConfig(
                "target is not a canonical checkpoint",
            ));
        }
        if expected.is_some_and(|value| value.scope() != scope) {
            return Err(ExternalCheckpointAuthorityErrorV2::CompareFailed);
        }
        if !valid_successor_shape_v2(expected.as_ref(), &target) {
            return Err(ExternalCheckpointAuthorityErrorV2::CompareFailed);
        }
        if self.current.get(&scope).copied() != expected {
            return Err(ExternalCheckpointAuthorityErrorV2::CompareFailed);
        }
        let sequence = self.record_count.checked_add(1).ok_or(
            ExternalCheckpointAuthorityErrorV2::InvalidLog("record count exhausted"),
        )?;
        let previous_hash = self.head_hash;
        let record_hash = digest_record_v2(sequence, scope, expected, target, previous_hash);
        let record = LogRecordV2 {
            sequence,
            scope,
            expected,
            target,
            previous_hash,
            record_hash,
        };
        if let Err(source) = self.log.write_all(&encode_log_record_v2(record)) {
            self.poisoned = true;
            return Err(ExternalCheckpointAuthorityErrorV2::Io {
                stage: "append checkpoint record",
                source,
            });
        }
        if let Err(source) = self.log.sync_data() {
            self.poisoned = true;
            return Err(ExternalCheckpointAuthorityErrorV2::Io {
                stage: "sync checkpoint record",
                source,
            });
        }
        if let Err(source) = self.directory.sync_data() {
            self.poisoned = true;
            return Err(ExternalCheckpointAuthorityErrorV2::Io {
                stage: "sync checkpoint directory",
                source,
            });
        }
        if let Err(error) = self.revalidate_bound_endpoints_v2() {
            self.poisoned = true;
            return Err(error);
        }
        self.current.insert(scope, target);
        self.record_count = sequence;
        self.head_hash = record_hash;
        if let Err(error) = self.persist_anchor_v2() {
            self.poisoned = true;
            return Err(error);
        }
        if let Err(error) = self.revalidate_bound_endpoints_v2() {
            self.poisoned = true;
            return Err(error);
        }
        Ok(())
    }

    fn validate_directory_identity_v2(&self) -> Result<(), ExternalCheckpointAuthorityErrorV2> {
        let descriptor =
            self.directory
                .metadata()
                .map_err(|source| ExternalCheckpointAuthorityErrorV2::Io {
                    stage: "stat checkpoint directory descriptor",
                    source,
                })?;
        let named = fs::symlink_metadata(&self.directory_path).map_err(|_| {
            ExternalCheckpointAuthorityErrorV2::InvalidLog("checkpoint directory identity changed")
        })?;
        if !descriptor.is_dir()
            || !named.is_dir()
            || descriptor.file_type().is_symlink()
            || named.file_type().is_symlink()
            || descriptor.permissions().mode() & 0o7777 != 0o700
            || named.permissions().mode() & 0o7777 != 0o700
            || !CheckpointPathIdentityV2::from_metadata(&descriptor)
                .same_object(self.directory_identity)
            || !CheckpointPathIdentityV2::from_metadata(&named).same_object(self.directory_identity)
            || fs::canonicalize(&self.directory_path).map_err(|_| {
                ExternalCheckpointAuthorityErrorV2::InvalidLog(
                    "checkpoint directory is no longer canonical",
                )
            })? != self.directory_path
        {
            return Err(ExternalCheckpointAuthorityErrorV2::InvalidLog(
                "checkpoint directory identity changed",
            ));
        }
        Ok(())
    }

    fn validate_file_identity_v2(
        &self,
        path: &Path,
        descriptor: &File,
        expected: CheckpointPathIdentityV2,
    ) -> Result<(), ExternalCheckpointAuthorityErrorV2> {
        let descriptor_metadata = descriptor.metadata().map_err(|_| {
            ExternalCheckpointAuthorityErrorV2::InvalidLog(
                "checkpoint endpoint descriptor identity changed",
            )
        })?;
        let named = fs::symlink_metadata(path).map_err(|_| {
            ExternalCheckpointAuthorityErrorV2::InvalidLog(
                "checkpoint endpoint pathname identity changed",
            )
        })?;
        if !descriptor_metadata.is_file()
            || !named.is_file()
            || descriptor_metadata.file_type().is_symlink()
            || named.file_type().is_symlink()
            || descriptor_metadata.permissions().mode() & 0o7777 != 0o600
            || named.permissions().mode() & 0o7777 != 0o600
            || descriptor_metadata.nlink() != 1
            || named.nlink() != 1
            || !CheckpointPathIdentityV2::from_metadata(&descriptor_metadata).same_object(expected)
            || !CheckpointPathIdentityV2::from_metadata(&named).same_object(expected)
            || fs::canonicalize(path).map_err(|_| {
                ExternalCheckpointAuthorityErrorV2::InvalidLog(
                    "checkpoint endpoint is no longer canonical",
                )
            })? != path
        {
            return Err(ExternalCheckpointAuthorityErrorV2::InvalidLog(
                "checkpoint endpoint identity changed",
            ));
        }
        Ok(())
    }

    fn replay_log_v2(&mut self) -> Result<(), ExternalCheckpointAuthorityErrorV2> {
        let mut reader =
            self.log
                .try_clone()
                .map_err(|source| ExternalCheckpointAuthorityErrorV2::Io {
                    stage: "clone checkpoint journal",
                    source,
                })?;
        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes).map_err(|source| {
            ExternalCheckpointAuthorityErrorV2::Io {
                stage: "read checkpoint journal",
                source,
            }
        })?;
        if bytes.len() % LOG_RECORD_BYTES_V2 != 0 {
            return Err(ExternalCheckpointAuthorityErrorV2::InvalidLog(
                "trailing partial checkpoint record",
            ));
        }
        for chunk in bytes.chunks_exact(LOG_RECORD_BYTES_V2) {
            let record = decode_log_record_v2(chunk)?;
            if record.sequence != self.record_count.saturating_add(1)
                || record.previous_hash != self.head_hash
                || record.record_hash
                    != digest_record_v2(
                        record.sequence,
                        record.scope,
                        record.expected,
                        record.target,
                        record.previous_hash,
                    )
                || !valid_successor_shape_v2(record.expected.as_ref(), &record.target)
                || record.target.scope() != record.scope
                || self.current.get(&record.scope).copied() != record.expected
            {
                return Err(ExternalCheckpointAuthorityErrorV2::InvalidLog(
                    "checkpoint CAS replay mismatch",
                ));
            }
            self.current.insert(record.scope, record.target);
            self.record_count = record.sequence;
            self.head_hash = record.record_hash;
        }
        Ok(())
    }

    fn reconcile_anchor_v2(&mut self) -> Result<(), ExternalCheckpointAuthorityErrorV2> {
        validate_existing_sidecar_v2(&self.anchor_path, "checkpoint head")?;
        match fs::symlink_metadata(&self.anchor_path) {
            Ok(_) => {
                let (bytes, identity) = read_anchor_v2(&self.anchor_path)?;
                self.anchor_identity = Some(identity);
                let (count, head) = decode_anchor_v2(&bytes)?;
                if count > self.record_count {
                    return Err(ExternalCheckpointAuthorityErrorV2::InvalidLog(
                        "durable head is ahead of journal",
                    ));
                }
                if count == self.record_count && head != self.head_hash {
                    return Err(ExternalCheckpointAuthorityErrorV2::InvalidLog(
                        "durable head differs from journal",
                    ));
                }
                if count < self.record_count {
                    // A crash after the journal fsync and before anchor rename
                    // leaves only a monotonic journal-ahead state; repair is
                    // safe because the complete chain has already replayed.
                    self.persist_anchor_v2()?;
                }
                Ok(())
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                self.anchor_identity = None;
                if self.record_count != 0 {
                    return Err(ExternalCheckpointAuthorityErrorV2::InvalidLog(
                        "non-empty journal has no durable head",
                    ));
                }
                self.persist_anchor_v2()
            }
            Err(source) => Err(ExternalCheckpointAuthorityErrorV2::Io {
                stage: "inspect checkpoint head",
                source,
            }),
        }
    }

    fn persist_anchor_v2(&mut self) -> Result<(), ExternalCheckpointAuthorityErrorV2> {
        self.revalidate_base_endpoints_v2()?;
        self.validate_anchor_endpoint_v2()?;
        let name = self
            .anchor_path
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or(ExternalCheckpointAuthorityErrorV2::InvalidConfig(
                "checkpoint head filename",
            ))?;
        let temporary = self.anchor_path.with_file_name(format!(
            ".{name}.tmp-{}-{}",
            process::id(),
            self.record_count
        ));
        let bytes = encode_anchor_v2(self.record_count, self.head_hash);
        let result = (|| -> Result<(), ExternalCheckpointAuthorityErrorV2> {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
                .open(&temporary)
                .map_err(|source| ExternalCheckpointAuthorityErrorV2::Io {
                    stage: "open temporary checkpoint head",
                    source,
                })?;
            file.write_all(&bytes)
                .map_err(|source| ExternalCheckpointAuthorityErrorV2::Io {
                    stage: "write temporary checkpoint head",
                    source,
                })?;
            file.sync_all()
                .map_err(|source| ExternalCheckpointAuthorityErrorV2::Io {
                    stage: "sync temporary checkpoint head",
                    source,
                })?;
            let temporary_identity = checkpoint_path_identity_from_file_v2(&file)?;
            self.revalidate_base_endpoints_v2()?;
            self.validate_anchor_endpoint_v2()?;
            verify_checkpoint_path_identity_v2(&temporary, temporary_identity, false)?;
            fs::rename(&temporary, &self.anchor_path).map_err(|source| {
                ExternalCheckpointAuthorityErrorV2::Io {
                    stage: "publish checkpoint head",
                    source,
                }
            })?;
            self.directory.sync_data().map_err(|source| {
                ExternalCheckpointAuthorityErrorV2::Io {
                    stage: "sync checkpoint head directory",
                    source,
                }
            })?;
            Ok(())
        })();
        if let Err(error) = result {
            let _ = fs::remove_file(&temporary);
            return Err(error);
        }
        let (_, identity) = read_anchor_v2(&self.anchor_path)?;
        self.anchor_identity = Some(identity);
        Ok(())
    }

    fn handle_connection_v2(
        &mut self,
        mut stream: UnixStream,
    ) -> Result<(), ExternalCheckpointAuthorityErrorV2> {
        if self.poisoned {
            return Err(ExternalCheckpointAuthorityErrorV2::Unavailable);
        }
        self.revalidate_bound_endpoints_v2()?;
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .map_err(|source| ExternalCheckpointAuthorityErrorV2::Io {
                stage: "set request timeout",
                source,
            })?;
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .map_err(|source| ExternalCheckpointAuthorityErrorV2::Io {
                stage: "set response timeout",
                source,
            })?;
        let request = match decode_request_v2(&read_frame_v2(&mut stream)?) {
            Ok(request) => request,
            Err(error) => {
                write_frame_v2(&mut stream, &encode_status_response_v2(STATUS_PROTOCOL_V2))?;
                return Err(error);
            }
        };
        match request {
            RequestV2::Load { scope } => match self.load_checked(scope) {
                Ok(Some(value)) => write_frame_v2(&mut stream, &encode_value_response_v2(value)),
                Ok(None) => write_frame_v2(&mut stream, &encode_status_response_v2(STATUS_NONE_V2)),
                Err(error) => {
                    let integrity_error =
                        matches!(error, ExternalCheckpointAuthorityErrorV2::InvalidLog(_));
                    let result = write_frame_v2(
                        &mut stream,
                        &encode_status_response_v2(STATUS_INVALID_STATE_V2),
                    );
                    if integrity_error {
                        self.poisoned = true;
                        result?;
                        Err(error)
                    } else {
                        result
                    }
                }
            },
            RequestV2::CompareAndAdvance(request) => {
                let expected = request.expected;
                let target = request.target;
                match self.compare_and_advance_checked(expected, target) {
                    Ok(()) => {
                        write_frame_v2(&mut stream, &encode_status_response_v2(STATUS_APPLIED_V2))
                    }
                    Err(ExternalCheckpointAuthorityErrorV2::CompareFailed) => write_frame_v2(
                        &mut stream,
                        &encode_status_response_v2(STATUS_COMPARE_FAILED_V2),
                    ),
                    Err(error @ ExternalCheckpointAuthorityErrorV2::InvalidLog(_)) => {
                        let result = write_frame_v2(
                            &mut stream,
                            &encode_status_response_v2(STATUS_INVALID_STATE_V2),
                        );
                        self.poisoned = true;
                        result?;
                        Err(error)
                    }
                    Err(_) => write_frame_v2(
                        &mut stream,
                        &encode_status_response_v2(STATUS_UNAVAILABLE_V2),
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
    ) -> Result<(), ExternalCheckpointAuthorityErrorV2> {
        let socket_path = socket_path.as_ref();
        remove_stale_socket_v2(socket_path)?;
        let _parent = prepare_socket_parent_v2(socket_path)?;
        let listener = UnixListener::bind(socket_path).map_err(|source| {
            ExternalCheckpointAuthorityErrorV2::Io {
                stage: "bind checkpoint socket",
                source,
            }
        })?;
        fs::set_permissions(socket_path, fs::Permissions::from_mode(0o600)).map_err(|source| {
            ExternalCheckpointAuthorityErrorV2::Io {
                stage: "protect checkpoint socket",
                source,
            }
        })?;
        for stream in listener.incoming() {
            match stream {
                Ok(stream) => {
                    if let Err(error) = self.handle_connection_v2(stream) {
                        if matches!(error, ExternalCheckpointAuthorityErrorV2::InvalidLog(_)) {
                            return Err(error);
                        }
                    }
                }
                Err(source) => {
                    return Err(ExternalCheckpointAuthorityErrorV2::Io {
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
pub struct UnixExternalCheckpointStoreV2 {
    socket_path: PathBuf,
    timeout: Duration,
}

impl UnixExternalCheckpointStoreV2 {
    pub fn new(socket_path: impl AsRef<Path>) -> Result<Self, ExternalCheckpointAuthorityErrorV2> {
        let path = socket_path.as_ref();
        if !path.is_absolute() || path.file_name().is_none() {
            return Err(ExternalCheckpointAuthorityErrorV2::InvalidConfig(
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
    ) -> Result<Option<ExternalCheckpointV2>, ExternalCheckpointAuthorityErrorV2> {
        match self.request_v2(RequestV2::Load { scope })? {
            ResponseV2::Value(value) => Ok(Some(*value)),
            ResponseV2::None => Ok(None),
            ResponseV2::Applied
            | ResponseV2::CompareFailed
            | ResponseV2::InvalidState
            | ResponseV2::Unavailable
            | ResponseV2::Protocol => Err(ExternalCheckpointAuthorityErrorV2::Protocol(
                "unexpected load response",
            )),
        }
    }

    pub fn compare_and_advance_checked(
        &self,
        expected: Option<ExternalCheckpointV2>,
        target: ExternalCheckpointV2,
    ) -> Result<(), ExternalCheckpointAuthorityErrorV2> {
        match self.request_v2(RequestV2::CompareAndAdvance(Box::new(CompareRequestV2 {
            expected,
            target,
        })))? {
            ResponseV2::Applied => Ok(()),
            ResponseV2::CompareFailed => Err(ExternalCheckpointAuthorityErrorV2::CompareFailed),
            ResponseV2::InvalidState => Err(ExternalCheckpointAuthorityErrorV2::InvalidLog(
                "remote checkpoint journal rejected",
            )),
            ResponseV2::Unavailable => Err(ExternalCheckpointAuthorityErrorV2::Unavailable),
            ResponseV2::Protocol => Err(ExternalCheckpointAuthorityErrorV2::Protocol(
                "remote protocol failure",
            )),
            ResponseV2::Value(_) | ResponseV2::None => Err(
                ExternalCheckpointAuthorityErrorV2::Protocol("unexpected compare response"),
            ),
        }
    }

    fn request_v2(
        &self,
        request: RequestV2,
    ) -> Result<ResponseV2, ExternalCheckpointAuthorityErrorV2> {
        let mut stream = UnixStream::connect(&self.socket_path).map_err(|source| {
            ExternalCheckpointAuthorityErrorV2::Io {
                stage: "connect checkpoint socket",
                source,
            }
        })?;
        stream
            .set_read_timeout(Some(self.timeout))
            .map_err(|source| ExternalCheckpointAuthorityErrorV2::Io {
                stage: "set client read timeout",
                source,
            })?;
        stream
            .set_write_timeout(Some(self.timeout))
            .map_err(|source| ExternalCheckpointAuthorityErrorV2::Io {
                stage: "set client write timeout",
                source,
            })?;
        write_frame_v2(&mut stream, &encode_request_v2(request))?;
        decode_response_v2(&read_frame_v2(&mut stream)?)
    }
}

impl ExternalCheckpointStoreV2 for UnixExternalCheckpointStoreV2 {
    fn load(
        &mut self,
        scope: [u8; 32],
    ) -> Result<Option<ExternalCheckpointV2>, ExternalCheckpointStoreErrorV2> {
        self.load_checked(scope).map_err(map_store_error_v2)
    }

    fn compare_and_advance(
        &mut self,
        expected: Option<ExternalCheckpointV2>,
        target: ExternalCheckpointV2,
    ) -> Result<(), ExternalCheckpointStoreErrorV2> {
        self.compare_and_advance_checked(expected, target)
            .map_err(map_store_error_v2)
    }
}

/// Start the standalone authority process loop.
pub fn run_daemon(
    socket_path: impl AsRef<Path>,
    log_path: impl AsRef<Path>,
) -> Result<(), ExternalCheckpointAuthorityErrorV2> {
    ExternalCheckpointAuthorityV2::open(log_path)?.serve_unix(socket_path)
}

fn map_store_error_v2(error: ExternalCheckpointAuthorityErrorV2) -> ExternalCheckpointStoreErrorV2 {
    match error {
        ExternalCheckpointAuthorityErrorV2::CompareFailed => {
            ExternalCheckpointStoreErrorV2::CompareFailed
        }
        ExternalCheckpointAuthorityErrorV2::InvalidConfig(_)
        | ExternalCheckpointAuthorityErrorV2::InvalidLog(_)
        | ExternalCheckpointAuthorityErrorV2::Protocol(_) => {
            ExternalCheckpointStoreErrorV2::InvalidPersistedState
        }
        ExternalCheckpointAuthorityErrorV2::Io { .. }
        | ExternalCheckpointAuthorityErrorV2::Unavailable => {
            ExternalCheckpointStoreErrorV2::Unavailable
        }
    }
}

#[derive(Debug)]
enum RequestV2 {
    Load { scope: [u8; 32] },
    CompareAndAdvance(Box<CompareRequestV2>),
}

#[derive(Debug)]
struct CompareRequestV2 {
    expected: Option<ExternalCheckpointV2>,
    target: ExternalCheckpointV2,
}

#[derive(Debug)]
enum ResponseV2 {
    Value(Box<ExternalCheckpointV2>),
    None,
    Applied,
    CompareFailed,
    InvalidState,
    Unavailable,
    Protocol,
}

fn valid_successor_shape_v2(
    expected: Option<&ExternalCheckpointV2>,
    target: &ExternalCheckpointV2,
) -> bool {
    match expected {
        None => target.generation() == 0 && target.predecessor_checksum() == [0; 32],
        Some(expected) => target.validate_successor_of(expected).is_ok(),
    }
}

fn encode_request_v2(request: RequestV2) -> Vec<u8> {
    let mut body = Vec::with_capacity(MAX_FRAME_BYTES_V2);
    body.extend_from_slice(REQUEST_MAGIC_V2);
    body.push(PROTOCOL_VERSION_V2);
    match request {
        RequestV2::Load { scope } => {
            body.push(OP_LOAD_V2);
            body.extend_from_slice(&[0, 0, 0]);
            body.extend_from_slice(&scope);
        }
        RequestV2::CompareAndAdvance(request) => {
            let expected = request.expected;
            let target = request.target;
            body.push(OP_COMPARE_AND_ADVANCE_V2);
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

fn decode_request_v2(body: &[u8]) -> Result<RequestV2, ExternalCheckpointAuthorityErrorV2> {
    if body.len() < 9 || &body[..4] != REQUEST_MAGIC_V2 || body[4] != PROTOCOL_VERSION_V2 {
        return Err(ExternalCheckpointAuthorityErrorV2::Protocol(
            "request header",
        ));
    }
    match body[5] {
        OP_LOAD_V2 if body.len() == 41 && body[6..9] == [0, 0, 0] => Ok(RequestV2::Load {
            scope: body[9..41].try_into().expect("fixed load scope"),
        }),
        OP_COMPARE_AND_ADVANCE_V2 if body[6] <= 1 && body[7..9] == [0, 0] => {
            let scope: [u8; 32] = body[9..41].try_into().expect("fixed compare scope");
            let expected_start = 41;
            let target_start = expected_start + if body[6] == 1 { CHECKPOINT_BYTES_V2 } else { 0 };
            if body.len() != target_start + CHECKPOINT_BYTES_V2 {
                return Err(ExternalCheckpointAuthorityErrorV2::Protocol(
                    "compare request length",
                ));
            }
            let expected = if body[6] == 1 {
                Some(
                    ExternalCheckpointV2::decode_canonical_exact(
                        &body[expected_start..target_start],
                    )
                    .map_err(|_| {
                        ExternalCheckpointAuthorityErrorV2::Protocol("expected checkpoint")
                    })?,
                )
            } else {
                None
            };
            let target = ExternalCheckpointV2::decode_canonical_exact(&body[target_start..])
                .map_err(|_| ExternalCheckpointAuthorityErrorV2::Protocol("target checkpoint"))?;
            if target.scope() != scope || expected.is_some_and(|value| value.scope() != scope) {
                return Err(ExternalCheckpointAuthorityErrorV2::Protocol(
                    "checkpoint scope mismatch",
                ));
            }
            Ok(RequestV2::CompareAndAdvance(Box::new(CompareRequestV2 {
                expected,
                target,
            })))
        }
        _ => Err(ExternalCheckpointAuthorityErrorV2::Protocol(
            "unsupported checkpoint request",
        )),
    }
}

fn encode_status_response_v2(status: u8) -> Vec<u8> {
    let mut body = Vec::with_capacity(8);
    body.extend_from_slice(RESPONSE_MAGIC_V2);
    body.push(PROTOCOL_VERSION_V2);
    body.push(status);
    body.extend_from_slice(&[0, 0]);
    body
}

fn encode_value_response_v2(value: ExternalCheckpointV2) -> Vec<u8> {
    let mut body = encode_status_response_v2(STATUS_VALUE_V2);
    body.extend_from_slice(&value.encode_canonical());
    body
}

fn decode_response_v2(body: &[u8]) -> Result<ResponseV2, ExternalCheckpointAuthorityErrorV2> {
    if body.len() < 8 || &body[..4] != RESPONSE_MAGIC_V2 || body[4] != PROTOCOL_VERSION_V2 {
        return Err(ExternalCheckpointAuthorityErrorV2::Protocol(
            "response header",
        ));
    }
    if body[6..8] != [0, 0] {
        return Err(ExternalCheckpointAuthorityErrorV2::Protocol(
            "response flags",
        ));
    }
    match body[5] {
        STATUS_VALUE_V2 if body.len() == 8 + CHECKPOINT_BYTES_V2 => {
            Ok(ResponseV2::Value(Box::new(
                ExternalCheckpointV2::decode_canonical_exact(&body[8..]).map_err(|_| {
                    ExternalCheckpointAuthorityErrorV2::Protocol("response checkpoint")
                })?,
            )))
        }
        STATUS_NONE_V2 if body.len() == 8 => Ok(ResponseV2::None),
        STATUS_APPLIED_V2 if body.len() == 8 => Ok(ResponseV2::Applied),
        STATUS_COMPARE_FAILED_V2 if body.len() == 8 => Ok(ResponseV2::CompareFailed),
        STATUS_INVALID_STATE_V2 if body.len() == 8 => Ok(ResponseV2::InvalidState),
        STATUS_UNAVAILABLE_V2 if body.len() == 8 => Ok(ResponseV2::Unavailable),
        STATUS_PROTOCOL_V2 if body.len() == 8 => Ok(ResponseV2::Protocol),
        _ => Err(ExternalCheckpointAuthorityErrorV2::Protocol(
            "response shape",
        )),
    }
}

fn read_frame_v2(stream: &mut UnixStream) -> Result<Vec<u8>, ExternalCheckpointAuthorityErrorV2> {
    let mut header = [0u8; 4];
    stream
        .read_exact(&mut header)
        .map_err(|source| ExternalCheckpointAuthorityErrorV2::Io {
            stage: "read frame length",
            source,
        })?;
    let length = u32::from_be_bytes(header) as usize;
    if length == 0 || length > MAX_FRAME_BYTES_V2 {
        return Err(ExternalCheckpointAuthorityErrorV2::Protocol("frame length"));
    }
    let mut body = vec![0u8; length];
    stream
        .read_exact(&mut body)
        .map_err(|source| ExternalCheckpointAuthorityErrorV2::Io {
            stage: "read frame body",
            source,
        })?;
    Ok(body)
}

fn write_frame_v2(
    stream: &mut UnixStream,
    body: &[u8],
) -> Result<(), ExternalCheckpointAuthorityErrorV2> {
    if body.is_empty() || body.len() > MAX_FRAME_BYTES_V2 {
        return Err(ExternalCheckpointAuthorityErrorV2::Protocol(
            "frame body length",
        ));
    }
    stream
        .write_all(&(body.len() as u32).to_be_bytes())
        .and_then(|_| stream.write_all(body))
        .and_then(|_| stream.flush())
        .map_err(|source| ExternalCheckpointAuthorityErrorV2::Io {
            stage: "write frame",
            source,
        })
}

fn digest_record_v2(
    sequence: u64,
    scope: [u8; 32],
    expected: Option<ExternalCheckpointV2>,
    target: ExternalCheckpointV2,
    previous_hash: [u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(LOG_DOMAIN_V2);
    hasher.update(PROTOCOL_VERSION_V2.to_be_bytes());
    hasher.update(OP_COMPARE_AND_ADVANCE_V2.to_be_bytes());
    hasher.update(sequence.to_be_bytes());
    hasher.update(scope);
    hasher.update([u8::from(expected.is_some())]);
    if let Some(value) = expected {
        hasher.update(value.encode_canonical());
    } else {
        hasher.update([0u8; CHECKPOINT_BYTES_V2]);
    }
    hasher.update(target.encode_canonical());
    hasher.update(previous_hash);
    hasher.finalize().into()
}

fn encode_log_record_v2(record: LogRecordV2) -> [u8; LOG_RECORD_BYTES_V2] {
    let mut bytes = [0u8; LOG_RECORD_BYTES_V2];
    let mut offset = 0;
    bytes[offset..offset + 8].copy_from_slice(LOG_MAGIC_V2);
    offset += 8;
    bytes[offset] = PROTOCOL_VERSION_V2;
    offset += 1;
    bytes[offset] = OP_COMPARE_AND_ADVANCE_V2;
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
        bytes[offset..offset + CHECKPOINT_BYTES_V2].copy_from_slice(&expected.encode_canonical());
    }
    offset += CHECKPOINT_BYTES_V2;
    bytes[offset..offset + CHECKPOINT_BYTES_V2].copy_from_slice(&record.target.encode_canonical());
    offset += CHECKPOINT_BYTES_V2;
    bytes[offset..offset + 32].copy_from_slice(&record.previous_hash);
    offset += 32;
    bytes[offset..offset + 32].copy_from_slice(&record.record_hash);
    bytes
}

fn decode_log_record_v2(bytes: &[u8]) -> Result<LogRecordV2, ExternalCheckpointAuthorityErrorV2> {
    if bytes.len() != LOG_RECORD_BYTES_V2
        || &bytes[..8] != LOG_MAGIC_V2
        || bytes[8] != PROTOCOL_VERSION_V2
        || bytes[9] != OP_COMPARE_AND_ADVANCE_V2
        || bytes[10..12] != [0, 0]
    {
        return Err(ExternalCheckpointAuthorityErrorV2::InvalidLog(
            "record header",
        ));
    }
    let sequence = u64::from_be_bytes(bytes[12..20].try_into().expect("fixed sequence"));
    let scope: [u8; 32] = bytes[20..52].try_into().expect("fixed scope");
    let expected_present = bytes[52];
    if expected_present > 1 {
        return Err(ExternalCheckpointAuthorityErrorV2::InvalidLog(
            "record expected marker",
        ));
    }
    let expected_start = 53;
    let target_start = expected_start + CHECKPOINT_BYTES_V2;
    let previous_start = target_start + CHECKPOINT_BYTES_V2;
    let hash_start = previous_start + 32;
    let expected = if expected_present == 1 {
        Some(
            ExternalCheckpointV2::decode_canonical_exact(&bytes[expected_start..target_start])
                .map_err(|_| ExternalCheckpointAuthorityErrorV2::InvalidLog("expected record"))?,
        )
    } else {
        if bytes[expected_start..target_start]
            .iter()
            .any(|byte| *byte != 0)
        {
            return Err(ExternalCheckpointAuthorityErrorV2::InvalidLog(
                "absent expected record is nonzero",
            ));
        }
        None
    };
    let target = ExternalCheckpointV2::decode_canonical_exact(&bytes[target_start..previous_start])
        .map_err(|_| ExternalCheckpointAuthorityErrorV2::InvalidLog("target record"))?;
    let previous_hash: [u8; 32] = bytes[previous_start..hash_start]
        .try_into()
        .expect("fixed predecessor");
    let record_hash: [u8; 32] = bytes[hash_start..hash_start + 32]
        .try_into()
        .expect("fixed digest");
    Ok(LogRecordV2 {
        sequence,
        scope,
        expected,
        target,
        previous_hash,
        record_hash,
    })
}

fn encode_anchor_v2(record_count: u64, head_hash: [u8; 32]) -> [u8; ANCHOR_BYTES_V2] {
    let mut bytes = [0u8; ANCHOR_BYTES_V2];
    bytes[..8].copy_from_slice(ANCHOR_MAGIC_V2);
    bytes[8] = PROTOCOL_VERSION_V2;
    bytes[9..12].copy_from_slice(&[0, 0, 0]);
    bytes[12..20].copy_from_slice(&record_count.to_be_bytes());
    bytes[20..52].copy_from_slice(&head_hash);
    let checksum = digest_anchor_v2(&bytes[..ANCHOR_BODY_BYTES_V2]);
    bytes[ANCHOR_BODY_BYTES_V2..].copy_from_slice(&checksum);
    bytes
}

fn decode_anchor_v2(bytes: &[u8]) -> Result<(u64, [u8; 32]), ExternalCheckpointAuthorityErrorV2> {
    if bytes.len() != ANCHOR_BYTES_V2
        || &bytes[..8] != ANCHOR_MAGIC_V2
        || bytes[8] != PROTOCOL_VERSION_V2
        || bytes[9..12] != [0, 0, 0]
        || bytes[ANCHOR_BODY_BYTES_V2..] != digest_anchor_v2(&bytes[..ANCHOR_BODY_BYTES_V2])
    {
        return Err(ExternalCheckpointAuthorityErrorV2::InvalidLog(
            "checkpoint head",
        ));
    }
    let count = u64::from_be_bytes(bytes[12..20].try_into().expect("fixed anchor count"));
    let head: [u8; 32] = bytes[20..52].try_into().expect("fixed anchor head");
    if (count == 0) != (head == [0; 32]) {
        return Err(ExternalCheckpointAuthorityErrorV2::InvalidLog(
            "checkpoint head empty shape",
        ));
    }
    Ok((count, head))
}

fn digest_anchor_v2(body: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(ANCHOR_DOMAIN_V2);
    hasher.update((body.len() as u64).to_be_bytes());
    hasher.update(body);
    hasher.finalize().into()
}

fn private_path_v2(path: &Path) -> Result<(File, PathBuf), ExternalCheckpointAuthorityErrorV2> {
    if !path.is_absolute()
        || path.file_name().is_none()
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(ExternalCheckpointAuthorityErrorV2::InvalidConfig(
            "journal path must be absolute and normalized",
        ));
    }
    let parent = path
        .parent()
        .ok_or(ExternalCheckpointAuthorityErrorV2::InvalidConfig(
            "journal parent",
        ))?;
    let canonical_parent =
        fs::canonicalize(parent).map_err(|source| ExternalCheckpointAuthorityErrorV2::Io {
            stage: "canonicalize journal parent",
            source,
        })?;
    let metadata = fs::symlink_metadata(&canonical_parent).map_err(|source| {
        ExternalCheckpointAuthorityErrorV2::Io {
            stage: "stat journal parent",
            source,
        }
    })?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.permissions().mode() & 0o077 != 0
        || canonical_parent != parent
    {
        return Err(ExternalCheckpointAuthorityErrorV2::InvalidConfig(
            "journal parent must be a private canonical directory",
        ));
    }
    let name = path
        .file_name()
        .ok_or(ExternalCheckpointAuthorityErrorV2::InvalidConfig(
            "journal filename",
        ))?;
    let normalized = canonical_parent.join(name);
    let directory =
        File::open(&canonical_parent).map_err(|source| ExternalCheckpointAuthorityErrorV2::Io {
            stage: "open journal parent",
            source,
        })?;
    Ok((directory, normalized))
}

fn sidecar_path_v2(
    log_path: &Path,
    suffix: &str,
) -> Result<PathBuf, ExternalCheckpointAuthorityErrorV2> {
    let name = log_path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or(ExternalCheckpointAuthorityErrorV2::InvalidConfig(
            "sidecar filename",
        ))?;
    Ok(log_path.with_file_name(format!(".{name}.{suffix}")))
}

fn validate_private_file_v2(
    file: &File,
    what: &'static str,
) -> Result<(), ExternalCheckpointAuthorityErrorV2> {
    let metadata = file
        .metadata()
        .map_err(|source| ExternalCheckpointAuthorityErrorV2::Io {
            stage: "stat private file",
            source,
        })?;
    if !metadata.file_type().is_file()
        || metadata.nlink() != 1
        || metadata.permissions().mode() & 0o777 != 0o600
    {
        return Err(ExternalCheckpointAuthorityErrorV2::InvalidConfig(what));
    }
    Ok(())
}

fn checkpoint_path_identity_from_file_v2(
    file: &File,
) -> Result<CheckpointPathIdentityV2, ExternalCheckpointAuthorityErrorV2> {
    let metadata = file
        .metadata()
        .map_err(|source| ExternalCheckpointAuthorityErrorV2::Io {
            stage: "stat checkpoint endpoint descriptor",
            source,
        })?;
    Ok(CheckpointPathIdentityV2::from_metadata(&metadata))
}

fn read_anchor_v2(
    path: &Path,
) -> Result<(Vec<u8>, CheckpointPathIdentityV2), ExternalCheckpointAuthorityErrorV2> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|source| ExternalCheckpointAuthorityErrorV2::Io {
            stage: "open checkpoint head",
            source,
        })?;
    validate_private_file_v2(&file, "checkpoint head").map_err(|error| match error {
        ExternalCheckpointAuthorityErrorV2::InvalidConfig(_) => {
            ExternalCheckpointAuthorityErrorV2::InvalidLog("checkpoint head")
        }
        other => other,
    })?;
    let identity = checkpoint_path_identity_from_file_v2(&file)?;
    verify_checkpoint_path_identity_v2(path, identity, false)?;
    let mut bytes = Vec::new();
    let mut reader = file;
    reader
        .read_to_end(&mut bytes)
        .map_err(|source| ExternalCheckpointAuthorityErrorV2::Io {
            stage: "read checkpoint head",
            source,
        })?;
    verify_checkpoint_path_identity_v2(path, identity, false)?;
    Ok((bytes, identity))
}

fn verify_checkpoint_path_identity_v2(
    path: &Path,
    expected: CheckpointPathIdentityV2,
    directory: bool,
) -> Result<(), ExternalCheckpointAuthorityErrorV2> {
    let metadata = fs::symlink_metadata(path).map_err(|_| {
        ExternalCheckpointAuthorityErrorV2::InvalidLog(
            "checkpoint endpoint pathname identity changed",
        )
    })?;
    let valid_shape = if directory {
        metadata.is_dir()
            && !metadata.file_type().is_symlink()
            && metadata.permissions().mode() & 0o7777 == 0o700
    } else {
        metadata.is_file()
            && !metadata.file_type().is_symlink()
            && metadata.permissions().mode() & 0o7777 == 0o600
            && metadata.nlink() == 1
    };
    let canonical = fs::canonicalize(path).map_err(|_| {
        ExternalCheckpointAuthorityErrorV2::InvalidLog(
            "checkpoint endpoint pathname identity changed",
        )
    })?;
    if !valid_shape
        || !CheckpointPathIdentityV2::from_metadata(&metadata).same_object(expected)
        || canonical != path
    {
        return Err(ExternalCheckpointAuthorityErrorV2::InvalidLog(
            "checkpoint endpoint pathname identity changed",
        ));
    }
    Ok(())
}

fn validate_existing_sidecar_v2(
    path: &Path,
    what: &'static str,
) -> Result<(), ExternalCheckpointAuthorityErrorV2> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink()
                || !metadata.file_type().is_file()
                || metadata.nlink() != 1
                || metadata.permissions().mode() & 0o777 != 0o600
            {
                return Err(ExternalCheckpointAuthorityErrorV2::InvalidLog(what));
            }
            Ok(())
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(ExternalCheckpointAuthorityErrorV2::Io {
            stage: "inspect checkpoint sidecar",
            source,
        }),
    }
}

fn remove_stale_socket_v2(path: &Path) -> Result<(), ExternalCheckpointAuthorityErrorV2> {
    if !path.is_absolute() || path.file_name().is_none() {
        return Err(ExternalCheckpointAuthorityErrorV2::InvalidConfig(
            "socket path must be absolute",
        ));
    }
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_socket() => {
            fs::remove_file(path).map_err(|source| ExternalCheckpointAuthorityErrorV2::Io {
                stage: "remove stale checkpoint socket",
                source,
            })
        }
        Ok(_) => Err(ExternalCheckpointAuthorityErrorV2::InvalidConfig(
            "socket path is not a Unix socket",
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(ExternalCheckpointAuthorityErrorV2::Io {
            stage: "inspect checkpoint socket",
            source,
        }),
    }
}

fn prepare_socket_parent_v2(
    socket_path: &Path,
) -> Result<PathBuf, ExternalCheckpointAuthorityErrorV2> {
    let parent = socket_path
        .parent()
        .ok_or(ExternalCheckpointAuthorityErrorV2::InvalidConfig(
            "socket parent",
        ))?;
    if !parent.is_absolute()
        || parent
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(ExternalCheckpointAuthorityErrorV2::InvalidConfig(
            "socket parent must be absolute and normalized",
        ));
    }
    if !parent.exists() {
        fs::create_dir_all(parent).map_err(|source| ExternalCheckpointAuthorityErrorV2::Io {
            stage: "create socket parent",
            source,
        })?;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).map_err(|source| {
            ExternalCheckpointAuthorityErrorV2::Io {
                stage: "protect socket parent",
                source,
            }
        })?;
    }
    let canonical =
        fs::canonicalize(parent).map_err(|source| ExternalCheckpointAuthorityErrorV2::Io {
            stage: "canonicalize socket parent",
            source,
        })?;
    let metadata = fs::symlink_metadata(&canonical).map_err(|source| {
        ExternalCheckpointAuthorityErrorV2::Io {
            stage: "stat socket parent",
            source,
        }
    })?;
    if canonical != parent
        || metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(ExternalCheckpointAuthorityErrorV2::InvalidConfig(
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
    use trnm_checkpoint_types::EffectWatermarkV2;
    use trnm_checkpoint_types::{BlockId, StateRoot};
    use trnm_checkpoint_types::{ExternalCheckpointFieldsV2, ExternalCheckpointStoreV2};

    const _: () = {
        assert!(EXTERNAL_CHECKPOINT_UNIX_ADAPTER_V2);
        assert!(!EXTERNAL_CHECKPOINT_PRIVATE_KEY_HANDLING_V2);
        assert!(!EXTERNAL_CHECKPOINT_CONSENSUS_RUNTIME_V2);
        assert!(!EXTERNAL_CHECKPOINT_CORE_ADMISSION_V2);
        assert!(!EXTERNAL_CHECKPOINT_SAFETY_RULES_V2);
        assert!(!EXTERNAL_CHECKPOINT_HOST_ATTESTATION_V2);
        assert!(!EXTERNAL_CHECKPOINT_PRODUCTION_ACTIVATION_V2);
    };

    fn checkpoint(generation: u64, predecessor_checksum: [u8; 32]) -> ExternalCheckpointV2 {
        ExternalCheckpointV2::new(ExternalCheckpointFieldsV2 {
            scope: [1; 32],
            generation,
            predecessor_checksum,
            authority_journal_id: [2; 32],
            authority_verifier_profile_ref: [3; 32],
            authority_revision: generation + 1,
            authority_state_record_checksum: [4; 32],
            authority_record_chain_checksum: [5; 32],
            application_host_config_ref: [6; 32],
            application_projection_profile_ref: [7; 32],
            application_authority_binding_manifest_checksum: [8; 32],
            application_committed_head_row_checksum: [9; 32],
            application_recovery_closure_checksum: [10; 32],
            application_block_id: BlockId::new([11; 32]),
            application_height: generation + 1,
            application_state_root: StateRoot::new([12; 32]),
            application_generation: generation + 1,
            application_timestamp_ms: 100 + generation,
            effect_journal_id: [13; 32],
            effect_profile_checksum: [14; 32],
            effect_exact_watermark: EffectWatermarkV2::from_persisted_parts(
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
        let mut authority = ExternalCheckpointAuthorityV2::open(&log).unwrap();
        authority.compare_and_advance_checked(None, first).unwrap();
        assert_eq!(authority.load_checked([1; 32]).unwrap(), Some(first));
        assert!(matches!(
            authority.compare_and_advance_checked(None, first),
            Err(ExternalCheckpointAuthorityErrorV2::CompareFailed)
        ));
        authority
            .compare_and_advance_checked(Some(first), second)
            .unwrap();
        drop(authority);
        let reopened = ExternalCheckpointAuthorityV2::open(&log).unwrap();
        assert_eq!(reopened.load_checked([1; 32]).unwrap(), Some(second));
    }

    #[test]
    fn journal_truncation_and_byte_edit_fail_closed() {
        let directory = private_tempdir();
        let log = directory.path().join("checkpoint.log");
        let first = checkpoint(0, [0; 32]);
        let mut authority = ExternalCheckpointAuthorityV2::open(&log).unwrap();
        authority.compare_and_advance_checked(None, first).unwrap();
        drop(authority);
        let original = fs::read(&log).unwrap();
        fs::write(&log, &original[..original.len() - 1]).unwrap();
        assert!(matches!(
            ExternalCheckpointAuthorityV2::open(&log),
            Err(ExternalCheckpointAuthorityErrorV2::InvalidLog(_))
        ));
        fs::write(&log, &original).unwrap();
        let mut edited = original;
        edited[100] ^= 0x80;
        fs::write(&log, edited).unwrap();
        assert!(matches!(
            ExternalCheckpointAuthorityV2::open(&log),
            Err(ExternalCheckpointAuthorityErrorV2::InvalidLog(_))
        ));
    }

    #[test]
    fn replayed_record_fails_closed() {
        let directory = private_tempdir();
        let log = directory.path().join("checkpoint.log");
        let first = checkpoint(0, [0; 32]);
        let second = checkpoint(1, first.checkpoint_checksum());
        let mut authority = ExternalCheckpointAuthorityV2::open(&log).unwrap();
        authority.compare_and_advance_checked(None, first).unwrap();
        authority
            .compare_and_advance_checked(Some(first), second)
            .unwrap();
        drop(authority);
        let mut bytes = fs::read(&log).unwrap();
        let replay = bytes[..LOG_RECORD_BYTES_V2].to_vec();
        bytes.extend_from_slice(&replay);
        fs::write(&log, bytes).unwrap();
        assert!(matches!(
            ExternalCheckpointAuthorityV2::open(&log),
            Err(ExternalCheckpointAuthorityErrorV2::InvalidLog(_))
        ));
    }

    #[test]
    fn bound_log_replacement_fails_closed_before_load() {
        let directory = private_tempdir();
        let log = directory.path().join("checkpoint.log");
        let displaced = directory.path().join("checkpoint.log.displaced");
        let first = checkpoint(0, [0; 32]);
        let mut authority = ExternalCheckpointAuthorityV2::open(&log).unwrap();
        authority.compare_and_advance_checked(None, first).unwrap();
        fs::rename(&log, &displaced).unwrap();
        fs::copy(&displaced, &log).unwrap();
        fs::set_permissions(&log, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(matches!(
            authority.load_checked([1; 32]),
            Err(ExternalCheckpointAuthorityErrorV2::InvalidLog(_))
        ));
    }

    #[test]
    fn bound_lock_replacement_fails_closed_before_load() {
        let directory = private_tempdir();
        let log = directory.path().join("checkpoint.log");
        let lock = directory.path().join(".checkpoint.log.lock-v2");
        let displaced = directory.path().join(".checkpoint.log.lock-v2.displaced");
        let authority = ExternalCheckpointAuthorityV2::open(&log).unwrap();
        fs::rename(&lock, &displaced).unwrap();
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&lock)
            .unwrap();
        assert!(matches!(
            authority.load_checked([1; 32]),
            Err(ExternalCheckpointAuthorityErrorV2::InvalidLog(_))
        ));
    }

    #[test]
    fn bound_anchor_replacement_fails_closed_before_load() {
        let directory = private_tempdir();
        let log = directory.path().join("checkpoint.log");
        let anchor = directory.path().join(".checkpoint.log.head-v2");
        let displaced = directory.path().join(".checkpoint.log.head-v2.displaced");
        let first = checkpoint(0, [0; 32]);
        let mut authority = ExternalCheckpointAuthorityV2::open(&log).unwrap();
        authority.compare_and_advance_checked(None, first).unwrap();
        fs::rename(&anchor, &displaced).unwrap();
        fs::copy(&displaced, &anchor).unwrap();
        fs::set_permissions(&anchor, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(matches!(
            authority.load_checked([1; 32]),
            Err(ExternalCheckpointAuthorityErrorV2::InvalidLog(_))
        ));
    }

    #[test]
    fn bound_parent_directory_replacement_fails_closed_before_load() {
        let directory = private_tempdir();
        let root = directory.path().to_path_buf();
        let displaced = root.with_file_name(format!(
            "{}-displaced-{}",
            root.file_name().unwrap().to_string_lossy(),
            process::id()
        ));
        let log = root.join("checkpoint.log");
        let authority = ExternalCheckpointAuthorityV2::open(&log).unwrap();
        fs::rename(&root, &displaced).unwrap();
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(matches!(
            authority.load_checked([1; 32]),
            Err(ExternalCheckpointAuthorityErrorV2::InvalidLog(_))
        ));
        fs::remove_dir(&root).unwrap();
        fs::rename(&displaced, &root).unwrap();
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
            let authority = ExternalCheckpointAuthorityV2::open(log_for_thread).unwrap();
            ready_tx.send(()).unwrap();
            authority.serve_unix(socket_for_thread).unwrap();
        });
        ready_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        while !socket.exists() {
            assert!(Instant::now() < deadline, "daemon socket did not appear");
            thread::sleep(Duration::from_millis(5));
        }
        let mut client = UnixExternalCheckpointStoreV2::new(&socket).unwrap();
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
            "authority_rules = false",
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
