//! Cross-process monotonic signer fencing for the narrow P0 timeout path.
//!
//! This crate deliberately owns the *external* side of the signer boundary.
//! The local signer journal remains a separate SQLite namespace and the
//! authority process never receives a private key or arbitrary bytes to sign.
//! The authority log and its optional semantic round sidecar are fixed-record
//! append-only hash chains. A restart authenticates both complete chains
//! before serving a request; a partial, reordered, truncated, or
//! checksum-modified record therefore fails closed.
//! Compare-and-advance is served over a length-delimited Unix socket so the
//! journal and authority are different processes and different failure
//! domains.

#![forbid(unsafe_code)]

use std::{
    collections::{BTreeMap, BTreeSet},
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
    SignatureRequestV0, SignerJournalErrorV0, SignerWatermarkV0,
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
const OP_COMPARE_AND_ADVANCE_SEMANTIC: u8 = 2;
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
const SEMANTIC_MAGIC: &[u8; 8] = b"TRNMES01";
const SEMANTIC_DOMAIN: &[u8] = b"trnm.consensus.external-watermark.semantic.v1\0";
const SEMANTIC_ANCHOR_MAGIC: &[u8; 8] = b"TRNMET01";
const SEMANTIC_RECORD_BYTES: usize = 8 + 1 + 1 + 2 + 8 + 32 + 32 + 32 + 8 + 8 + 8 + 32 + 32;
const SEMANTIC_ANCHOR_BODY_BYTES: usize = 8 + 1 + 3 + 8 + 32;
const SEMANTIC_ANCHOR_BYTES: usize = SEMANTIC_ANCHOR_BODY_BYTES + 32;

/// Semantic round facts carried by the narrow external timeout CAS.
///
/// These facts are persisted in an independent hash-chained sidecar and are
/// checked before a new watermark reservation. They do not represent a full
/// Core/SafetyRules state or authorize a vote.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExternalWatermarkSemanticFactsV1 {
    pub epoch: u64,
    pub view: u64,
    pub safety_revision: u64,
}

impl ExternalWatermarkSemanticFactsV1 {
    pub const fn new(epoch: u64, view: u64, safety_revision: u64) -> Option<Self> {
        if safety_revision == 0 {
            return None;
        }
        Some(Self {
            epoch,
            view,
            safety_revision,
        })
    }
}

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

#[derive(Debug, Clone, Copy)]
struct SemanticRecordV1 {
    value: SignerWatermarkV0,
    facts: ExternalWatermarkSemanticFactsV1,
    previous_record_hash: [u8; 32],
    record_hash: [u8; 32],
}

/// One process-owned append-only authority.  The process holds an exclusive
/// lock beside the log; another process cannot serve the same namespace.
pub struct ExternalWatermarkAuthority {
    log_path: PathBuf,
    anchor_path: PathBuf,
    semantic_anchor_path: PathBuf,
    directory: File,
    log: File,
    semantic_log: File,
    _lock: File,
    current: BTreeMap<[u8; 32], SignerWatermarkV0>,
    semantic_current: BTreeMap<[u8; 32], ExternalWatermarkSemanticFactsV1>,
    semantic_last_sequence: BTreeMap<[u8; 32], u64>,
    head_hash: [u8; 32],
    record_count: u64,
    semantic_head_hash: [u8; 32],
    semantic_record_count: u64,
    history: BTreeSet<([u8; 32], u64, [u8; 32])>,
    poisoned: bool,
}

impl ExternalWatermarkAuthority {
    /// Opens and fully authenticates an existing hash chain, or creates an
    /// empty authority namespace.  No trailing partial record is tolerated.
    pub fn open(log_path: impl AsRef<Path>) -> Result<Self, ExternalWatermarkAuthorityError> {
        let (directory, log_path) = private_path(log_path.as_ref())?;
        let lock_path = lock_path_for(&log_path)?;
        let anchor_path = anchor_path_for(&log_path)?;
        let semantic_log_path = semantic_log_path_for(&log_path)?;
        let semantic_anchor_path = semantic_anchor_path_for(&log_path)?;
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
        let semantic_log = OpenOptions::new()
            .read(true)
            .create(true)
            .append(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&semantic_log_path)
            .map_err(|source| ExternalWatermarkAuthorityError::Io {
                stage: "open semantic watermark log",
                source,
            })?;
        let semantic_metadata =
            semantic_log
                .metadata()
                .map_err(|source| ExternalWatermarkAuthorityError::Io {
                    stage: "stat semantic watermark log",
                    source,
                })?;
        if semantic_metadata.permissions().mode() & 0o777 != 0o600 || !semantic_metadata.is_file() {
            return Err(ExternalWatermarkAuthorityError::InvalidConfig(
                "semantic watermark log must be a private regular file",
            ));
        }
        let mut authority = Self {
            log_path,
            anchor_path,
            semantic_anchor_path,
            directory,
            log,
            semantic_log,
            _lock: lock,
            current: BTreeMap::new(),
            semantic_current: BTreeMap::new(),
            semantic_last_sequence: BTreeMap::new(),
            head_hash: [0; 32],
            record_count: 0,
            semantic_head_hash: [0; 32],
            semantic_record_count: 0,
            history: BTreeSet::new(),
            poisoned: false,
        };
        authority.replay_log()?;
        authority.reconcile_anchor()?;
        authority.replay_semantic_log()?;
        authority.reconcile_semantic_anchor()?;
        if authority.semantic_record_count != 0
            && authority.semantic_record_count != authority.record_count
        {
            return Err(ExternalWatermarkAuthorityError::InvalidLog(
                "semantic and watermark logs have different lengths",
            ));
        }
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
        if self.semantic_record_count != 0 {
            return Err(ExternalWatermarkAuthorityError::ScopeConflict);
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
        self.history
            .insert((scope, target.sequence(), target.chain_checksum()));
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

    /// Compare-and-advance variant that durably binds the semantic round and
    /// Safety revision outside the signer process. A legacy opaque CAS history
    /// cannot be upgraded implicitly; callers must provision a fresh semantic
    /// namespace instead of assuming that a checksum proves ordering.
    pub fn compare_and_advance_semantic(
        &mut self,
        expected: Option<SignerWatermarkV0>,
        target: SignerWatermarkV0,
        facts: ExternalWatermarkSemanticFactsV1,
    ) -> Result<(), ExternalWatermarkAuthorityError> {
        if self.poisoned {
            return Err(ExternalWatermarkAuthorityError::Unavailable);
        }
        if facts.safety_revision == 0 {
            return Err(ExternalWatermarkAuthorityError::InvalidConfig(
                "semantic Safety revision must be positive",
            ));
        }
        if self.record_count != self.semantic_record_count {
            return Err(ExternalWatermarkAuthorityError::InvalidLog(
                "semantic and watermark logs are not aligned",
            ));
        }
        if self.record_count != 0 && self.semantic_record_count == 0 {
            return Err(ExternalWatermarkAuthorityError::ScopeConflict);
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
        if let Some(previous_facts) = self.semantic_current.get(&scope).copied() {
            if facts.epoch < previous_facts.epoch
                || (facts.epoch == previous_facts.epoch && facts.view <= previous_facts.view)
                || facts.safety_revision <= previous_facts.safety_revision
            {
                return Err(ExternalWatermarkAuthorityError::CompareFailed);
            }
        } else if current.is_some() {
            return Err(ExternalWatermarkAuthorityError::InvalidLog(
                "semantic head is missing for an existing watermark",
            ));
        }

        let previous_record_hash = self.head_hash;
        let record_hash = record_hash(target, previous_record_hash);
        let record = LogRecordV1 {
            value: target,
            previous_record_hash,
            record_hash,
        };
        let previous_semantic_hash = self.semantic_head_hash;
        let semantic_hash = semantic_record_hash(target, facts, previous_semantic_hash);
        let semantic_record = SemanticRecordV1 {
            value: target,
            facts,
            previous_record_hash: previous_semantic_hash,
            record_hash: semantic_hash,
        };
        // The two records are deliberately separate failure domains. If a
        // process dies between either append, replay sees unequal lengths and
        // refuses the namespace; it never guesses which side was authoritative.
        self.log
            .write_all(&encode_record(record))
            .map_err(|source| ExternalWatermarkAuthorityError::Io {
                stage: "append semantic watermark record",
                source,
            })?;
        self.log
            .sync_data()
            .map_err(|source| ExternalWatermarkAuthorityError::Io {
                stage: "sync semantic watermark record",
                source,
            })?;
        self.semantic_log
            .write_all(&encode_semantic_record(semantic_record))
            .map_err(|source| ExternalWatermarkAuthorityError::Io {
                stage: "append semantic facts record",
                source,
            })?;
        self.semantic_log
            .sync_data()
            .map_err(|source| ExternalWatermarkAuthorityError::Io {
                stage: "sync semantic facts record",
                source,
            })?;
        self.directory
            .sync_data()
            .map_err(|source| ExternalWatermarkAuthorityError::Io {
                stage: "sync semantic authority directory",
                source,
            })?;
        self.current.insert(scope, target);
        self.semantic_current.insert(scope, facts);
        self.semantic_last_sequence.insert(scope, target.sequence());
        self.history
            .insert((scope, target.sequence(), target.chain_checksum()));
        self.record_count =
            self.record_count
                .checked_add(1)
                .ok_or(ExternalWatermarkAuthorityError::InvalidLog(
                    "record count exhausted",
                ))?;
        self.semantic_record_count = self.semantic_record_count.checked_add(1).ok_or(
            ExternalWatermarkAuthorityError::InvalidLog("semantic record count exhausted"),
        )?;
        self.head_hash = record_hash;
        self.semantic_head_hash = semantic_hash;
        if let Err(error) = self.persist_anchor() {
            self.poisoned = true;
            return Err(error);
        }
        if let Err(error) = self.persist_semantic_anchor() {
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
            self.history.insert((
                scope,
                record.value.sequence(),
                record.value.chain_checksum(),
            ));
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

    fn replay_semantic_log(&mut self) -> Result<(), ExternalWatermarkAuthorityError> {
        let mut bytes = Vec::new();
        let mut reader = self.semantic_log.try_clone().map_err(|source| {
            ExternalWatermarkAuthorityError::Io {
                stage: "clone semantic log for replay",
                source,
            }
        })?;
        reader
            .read_to_end(&mut bytes)
            .map_err(|source| ExternalWatermarkAuthorityError::Io {
                stage: "read semantic watermark log",
                source,
            })?;
        if bytes.len() % SEMANTIC_RECORD_BYTES != 0 {
            return Err(ExternalWatermarkAuthorityError::InvalidLog(
                "trailing partial semantic record",
            ));
        }
        for chunk in bytes.chunks_exact(SEMANTIC_RECORD_BYTES) {
            let record = decode_semantic_record(chunk)?;
            if record.previous_record_hash != self.semantic_head_hash {
                return Err(ExternalWatermarkAuthorityError::InvalidLog(
                    "semantic hash chain predecessor mismatch",
                ));
            }
            if record.record_hash
                != semantic_record_hash(record.value, record.facts, self.semantic_head_hash)
            {
                return Err(ExternalWatermarkAuthorityError::InvalidLog(
                    "semantic record checksum mismatch",
                ));
            }
            let scope = record.value.scope();
            if !self.history.contains(&(
                scope,
                record.value.sequence(),
                record.value.chain_checksum(),
            )) {
                return Err(ExternalWatermarkAuthorityError::InvalidLog(
                    "semantic record has no matching watermark record",
                ));
            }
            match self.semantic_current.get(&scope).copied() {
                None if record.value.sequence() == 0 => {}
                Some(previous)
                    if self.current.get(&scope).map(|value| value.journal_id())
                        == Some(record.value.journal_id())
                        && self
                            .semantic_last_sequence
                            .get(&scope)
                            .and_then(|sequence| sequence.checked_add(1))
                            == Some(record.value.sequence())
                        && (record.facts.epoch > previous.epoch
                            || (record.facts.epoch == previous.epoch
                                && record.facts.view > previous.view))
                        && record.facts.safety_revision > previous.safety_revision => {}
                _ => {
                    return Err(ExternalWatermarkAuthorityError::InvalidLog(
                        "semantic scope sequence/order fork",
                    ))
                }
            }
            self.semantic_current.insert(scope, record.facts);
            self.semantic_last_sequence
                .insert(scope, record.value.sequence());
            self.semantic_head_hash = record.record_hash;
            self.semantic_record_count = self.semantic_record_count.checked_add(1).ok_or(
                ExternalWatermarkAuthorityError::InvalidLog("semantic record count exhausted"),
            )?;
        }
        Ok(())
    }

    fn reconcile_semantic_anchor(&mut self) -> Result<(), ExternalWatermarkAuthorityError> {
        let bytes = match fs::read(&self.semantic_anchor_path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                if self.semantic_record_count != 0 {
                    return Err(ExternalWatermarkAuthorityError::InvalidLog(
                        "non-empty semantic log has no durable head anchor",
                    ));
                }
                self.persist_semantic_anchor()?;
                return Ok(());
            }
            Err(source) => {
                return Err(ExternalWatermarkAuthorityError::Io {
                    stage: "read semantic head anchor",
                    source,
                })
            }
        };
        let (anchored_count, anchored_head) = decode_semantic_anchor(&bytes)?;
        if anchored_count > self.semantic_record_count {
            return Err(ExternalWatermarkAuthorityError::InvalidLog(
                "semantic log is shorter than durable head anchor",
            ));
        }
        if anchored_count == self.semantic_record_count && anchored_head != self.semantic_head_hash
        {
            return Err(ExternalWatermarkAuthorityError::InvalidLog(
                "semantic durable head anchor differs from log head",
            ));
        }
        if anchored_count < self.semantic_record_count {
            self.persist_semantic_anchor()?;
        }
        Ok(())
    }

    fn persist_semantic_anchor(&self) -> Result<(), ExternalWatermarkAuthorityError> {
        let name = self
            .semantic_anchor_path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or(ExternalWatermarkAuthorityError::InvalidConfig(
                "semantic anchor filename",
            ))?;
        let temporary = self.semantic_anchor_path.with_file_name(format!(
            ".{name}.tmp-{}-{}",
            process::id(),
            self.semantic_record_count
        ));
        let bytes = encode_semantic_anchor(self.semantic_record_count, self.semantic_head_hash);
        let result = (|| {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
                .open(&temporary)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            fs::rename(&temporary, &self.semantic_anchor_path)?;
            self.directory.sync_data()?;
            Ok::<(), io::Error>(())
        })();
        if let Err(source) = result {
            let _ = fs::remove_file(&temporary);
            return Err(ExternalWatermarkAuthorityError::Io {
                stage: "persist semantic head anchor",
                source,
            });
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
            RequestV1::CompareAndAdvanceSemantic {
                expected,
                target,
                facts,
            } => match self.compare_and_advance_semantic(expected, target, facts) {
                Ok(()) => encode_empty_response(STATUS_NONE),
                Err(ExternalWatermarkAuthorityError::CompareFailed) => {
                    encode_empty_response(STATUS_COMPARE_FAILED)
                }
                Err(ExternalWatermarkAuthorityError::InvalidConfig(_))
                | Err(ExternalWatermarkAuthorityError::InvalidLog(_))
                | Err(ExternalWatermarkAuthorityError::ScopeConflict) => {
                    encode_empty_response(STATUS_INVALID_STATE)
                }
                Err(_) => encode_empty_response(STATUS_UNAVAILABLE),
            },
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

    pub fn compare_and_advance_semantic_checked(
        &self,
        expected: Option<SignerWatermarkV0>,
        target: SignerWatermarkV0,
        facts: ExternalWatermarkSemanticFactsV1,
    ) -> Result<(), ExternalWatermarkAuthorityError> {
        match self.request(RequestV1::CompareAndAdvanceSemantic {
            expected,
            target,
            facts,
        })? {
            ResponseV1::None => Ok(()),
            ResponseV1::CompareFailed => Err(ExternalWatermarkAuthorityError::CompareFailed),
            ResponseV1::InvalidState => Err(ExternalWatermarkAuthorityError::InvalidLog(
                "authority rejected semantic persisted state",
            )),
            ResponseV1::Unavailable => Err(ExternalWatermarkAuthorityError::Unavailable),
            ResponseV1::Value(_) => Err(ExternalWatermarkAuthorityError::Protocol(
                "semantic compare response unexpectedly carried a value",
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

    /// Builds the narrow timeout adapter with an independent durable response
    /// binding. The returned adapter still has no Core/SafetyRules authority;
    /// this constructor only closes the producer crash/replay window.
    pub fn with_durable_response_binding(
        journal: trnm_consensus_signer_journal::SqliteSignerJournalV0<W>,
        response_log_path: impl AsRef<Path>,
        producer: P,
    ) -> Result<TimeoutOnlySignerAdapter<W, ReplayBoundTimeoutProducer<P>>, ReplayBindingErrorV1>
    {
        Ok(TimeoutOnlySignerAdapter::new(
            journal,
            ReplayBoundTimeoutProducer::open(response_log_path, producer)?,
        ))
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

// The signer journal makes the local intent and signature events durable, but
// a process can still die after an injected producer returns and before the
// journal's signature event is committed.  A retry must therefore have a
// durable response binding outside the SQLite namespace.  This store is a
// deliberately small, append-only response cache for the timeout-only slice;
// it never accepts arbitrary bytes or owns a key.
const REPLAY_LOG_MAGIC: &[u8; 8] = b"TRNMSR01";
const REPLAY_LOG_DOMAIN: &[u8] = b"trnm.consensus.timeout-response-binding.v1\0";
const REPLAY_ANCHOR_MAGIC: &[u8; 8] = b"TRNMSH01";
const REPLAY_VERSION: u8 = 1;
const REPLAY_RECORD_BYTES: usize = 8 + 1 + 1 + 2 + 8 + 32 + 32 + 32 + 64 + 32 + 32;
const REPLAY_ANCHOR_BODY_BYTES: usize = 8 + 1 + 3 + 8 + 32;
const REPLAY_ANCHOR_BYTES: usize = REPLAY_ANCHOR_BODY_BYTES + 32;

#[derive(Debug)]
pub enum ReplayBindingErrorV1 {
    InvalidConfig(&'static str),
    InvalidLog(&'static str),
    Io {
        stage: &'static str,
        source: io::Error,
    },
    Conflict(&'static str),
    Poisoned,
}

impl fmt::Display for ReplayBindingErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig(reason) => {
                write!(formatter, "invalid response binding config: {reason}")
            }
            Self::InvalidLog(reason) => {
                write!(formatter, "response binding log rejected: {reason}")
            }
            Self::Io { stage, source } => {
                write!(formatter, "response binding I/O at {stage}: {source}")
            }
            Self::Conflict(reason) => write!(formatter, "response binding conflict: {reason}"),
            Self::Poisoned => formatter.write_str("response binding store is poisoned"),
        }
    }
}

impl Error for ReplayBindingErrorV1 {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct ReplayRecordV1 {
    sequence: u64,
    fingerprint: [u8; 32],
    signer_profile_ref: [u8; 32],
    signing_root: [u8; 32],
    signature: [u8; 64],
    previous_record_hash: [u8; 32],
    record_hash: [u8; 32],
}

/// The exact request identity carried by one response-binding record.
///
/// This deliberately contains no caller-supplied message bytes or private-key
/// material; it is only the tuple authenticated by the append-only response
/// log and used by the narrow external-signer bridge for replay lookup.
#[derive(Debug, Clone, Copy)]
struct ResponseBindingFactsV1 {
    fingerprint: [u8; 32],
    signer_profile_ref: [u8; 32],
    signing_root: [u8; 32],
}

#[derive(Debug, Clone, Copy)]
struct ReplayEntryV1 {
    signer_profile_ref: [u8; 32],
    signing_root: [u8; 32],
    signature: SignatureBytes,
}

/// Durable response binding for one timeout-only signer process.
///
/// The log is independent from the SQLite signer journal and is protected by
/// its own lifetime lock.  A complete hash-chain and a durable head anchor are
/// authenticated before a caller can use it.  This catches stale/rewound
/// response state, partial tails, and byte edits as a fail-stop condition.
pub struct ReplayBindingStoreV1 {
    log_path: PathBuf,
    anchor_path: PathBuf,
    directory: File,
    log: File,
    _lock: File,
    entries: BTreeMap<[u8; 32], ReplayEntryV1>,
    head_hash: [u8; 32],
    record_count: u64,
    poisoned: bool,
}

impl ReplayBindingStoreV1 {
    pub fn open(log_path: impl AsRef<Path>) -> Result<Self, ReplayBindingErrorV1> {
        let (directory, log_path) =
            private_path(log_path.as_ref()).map_err(map_replay_path_error)?;
        let lock_path = replay_lock_path_for(&log_path)?;
        let anchor_path = replay_anchor_path_for(&log_path)?;
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&lock_path)
            .map_err(|source| ReplayBindingErrorV1::Io {
                stage: "open response binding lock",
                source,
            })?;
        ensure_private_regular(&lock, "response binding lock")?;
        lock.try_lock_exclusive()
            .map_err(|source| ReplayBindingErrorV1::Io {
                stage: "lock response binding namespace",
                source,
            })?;

        let log = OpenOptions::new()
            .read(true)
            .create(true)
            .append(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&log_path)
            .map_err(|source| ReplayBindingErrorV1::Io {
                stage: "open response binding log",
                source,
            })?;
        ensure_private_regular(&log, "response binding log")?;
        let mut store = Self {
            log_path,
            anchor_path,
            directory,
            log,
            _lock: lock,
            entries: BTreeMap::new(),
            head_hash: [0; 32],
            record_count: 0,
            poisoned: false,
        };
        store.replay_log()?;
        store.reconcile_anchor()?;
        Ok(store)
    }

    pub fn log_path(&self) -> &Path {
        &self.log_path
    }

    /// Number of durably bound responses in this namespace.
    ///
    /// The count is diagnostic state, not signer authority.  The narrow
    /// remote-signer bridge uses it only to reconcile the external CAS head:
    /// an external reservation that has no corresponding response record is
    /// ambiguous after a crash and must fail closed.
    pub const fn record_count_v1(&self) -> u64 {
        self.record_count
    }

    /// Looks up a previously bound signature without constructing a
    /// signer-journal request object.
    ///
    /// This is intentionally limited to the exact tuple already authenticated
    /// by the response log.  It accepts no caller-selected message bytes and
    /// never invokes a producer or private key.
    pub fn lookup_signature_v1(
        &self,
        fingerprint: [u8; 32],
        signer_profile_ref: [u8; 32],
        signing_root: [u8; 32],
    ) -> Result<Option<SignatureBytes>, ReplayBindingErrorV1> {
        if fingerprint == [0; 32] || signer_profile_ref == [0; 32] || signing_root == [0; 32] {
            return Err(ReplayBindingErrorV1::Conflict(
                "response lookup identity contains zero bytes",
            ));
        }
        if self.poisoned {
            return Err(ReplayBindingErrorV1::Poisoned);
        }
        let Some(entry) = self.entries.get(&fingerprint).copied() else {
            return Ok(None);
        };
        if entry.signer_profile_ref != signer_profile_ref || entry.signing_root != signing_root {
            return Err(ReplayBindingErrorV1::Conflict(
                "fingerprint is bound to a different signer request",
            ));
        }
        Ok(Some(entry.signature))
    }

    /// Durably binds one exact response signature to its request identity.
    ///
    /// The response log remains independent from the local SQLite journal and
    /// is append-only/hash-chained.  A conflicting duplicate is rejected;
    /// exact idempotent repetition is accepted.
    pub fn record_signature_v1(
        &mut self,
        fingerprint: [u8; 32],
        signer_profile_ref: [u8; 32],
        signing_root: [u8; 32],
        signature: SignatureBytes,
    ) -> Result<(), ReplayBindingErrorV1> {
        let request = ResponseBindingFactsV1 {
            fingerprint,
            signer_profile_ref,
            signing_root,
        };
        self.record_facts_v1(request, signature)
    }

    fn lookup_request(
        &self,
        request: &SignatureRequestV0<'_>,
    ) -> Result<Option<SignatureBytes>, ReplayBindingErrorV1> {
        self.lookup_signature_v1(
            request.fingerprint().into_bytes(),
            request.signer_profile_ref(),
            request.signing_root().into_bytes(),
        )
    }

    fn record_request(
        &mut self,
        request: &SignatureRequestV0<'_>,
        signature: SignatureBytes,
    ) -> Result<(), ReplayBindingErrorV1> {
        self.record_facts_v1(
            ResponseBindingFactsV1 {
                fingerprint: request.fingerprint().into_bytes(),
                signer_profile_ref: request.signer_profile_ref(),
                signing_root: request.signing_root().into_bytes(),
            },
            signature,
        )
    }

    fn record_facts_v1(
        &mut self,
        request: ResponseBindingFactsV1,
        signature: SignatureBytes,
    ) -> Result<(), ReplayBindingErrorV1> {
        if self.poisoned {
            return Err(ReplayBindingErrorV1::Poisoned);
        }
        if request.fingerprint == [0; 32]
            || request.signer_profile_ref == [0; 32]
            || request.signing_root == [0; 32]
        {
            return Err(ReplayBindingErrorV1::Conflict(
                "response binding identity contains zero bytes",
            ));
        }
        if signature.as_bytes() == &[0; 64] {
            return Err(ReplayBindingErrorV1::Conflict(
                "zero response cannot be bound",
            ));
        }
        let fingerprint = request.fingerprint;
        let signer_profile_ref = request.signer_profile_ref;
        let signing_root = request.signing_root;
        if let Some(existing) = self.entries.get(&fingerprint).copied() {
            if existing.signer_profile_ref != signer_profile_ref
                || existing.signing_root != signing_root
                || existing.signature != signature
            {
                return Err(ReplayBindingErrorV1::Conflict(
                    "duplicate response differs from the original binding",
                ));
            }
            return Ok(());
        }
        let sequence = self
            .record_count
            .checked_add(1)
            .ok_or(ReplayBindingErrorV1::InvalidLog("record count exhausted"))?;
        let previous_record_hash = self.head_hash;
        let record_hash = replay_record_hash(
            sequence,
            fingerprint,
            signer_profile_ref,
            signing_root,
            *signature.as_bytes(),
            previous_record_hash,
        );
        let record = ReplayRecordV1 {
            sequence,
            fingerprint,
            signer_profile_ref,
            signing_root,
            signature: *signature.as_bytes(),
            previous_record_hash,
            record_hash,
        };
        self.log
            .write_all(&encode_replay_record(record))
            .map_err(|source| ReplayBindingErrorV1::Io {
                stage: "append response binding record",
                source,
            })?;
        self.log
            .sync_data()
            .map_err(|source| ReplayBindingErrorV1::Io {
                stage: "sync response binding record",
                source,
            })?;
        self.directory
            .sync_data()
            .map_err(|source| ReplayBindingErrorV1::Io {
                stage: "sync response binding directory",
                source,
            })?;
        self.entries.insert(
            fingerprint,
            ReplayEntryV1 {
                signer_profile_ref,
                signing_root,
                signature,
            },
        );
        self.record_count = sequence;
        self.head_hash = record_hash;
        if let Err(error) = self.persist_anchor() {
            self.poisoned = true;
            return Err(error);
        }
        Ok(())
    }

    fn replay_log(&mut self) -> Result<(), ReplayBindingErrorV1> {
        let mut bytes = Vec::new();
        let mut reader = self
            .log
            .try_clone()
            .map_err(|source| ReplayBindingErrorV1::Io {
                stage: "clone response binding log",
                source,
            })?;
        reader
            .read_to_end(&mut bytes)
            .map_err(|source| ReplayBindingErrorV1::Io {
                stage: "read response binding log",
                source,
            })?;
        if bytes.len() % REPLAY_RECORD_BYTES != 0 {
            return Err(ReplayBindingErrorV1::InvalidLog(
                "trailing partial response record",
            ));
        }
        for chunk in bytes.chunks_exact(REPLAY_RECORD_BYTES) {
            let record = decode_replay_record(chunk)?;
            let expected_sequence = self
                .record_count
                .checked_add(1)
                .ok_or(ReplayBindingErrorV1::InvalidLog("record count exhausted"))?;
            if record.sequence != expected_sequence {
                return Err(ReplayBindingErrorV1::InvalidLog(
                    "response sequence gap or rollback",
                ));
            }
            if record.previous_record_hash != self.head_hash
                || record.record_hash
                    != replay_record_hash(
                        record.sequence,
                        record.fingerprint,
                        record.signer_profile_ref,
                        record.signing_root,
                        record.signature,
                        self.head_hash,
                    )
            {
                return Err(ReplayBindingErrorV1::InvalidLog(
                    "response hash-chain mismatch",
                ));
            }
            if self.entries.contains_key(&record.fingerprint) {
                return Err(ReplayBindingErrorV1::InvalidLog(
                    "duplicate response fingerprint",
                ));
            }
            self.entries.insert(
                record.fingerprint,
                ReplayEntryV1 {
                    signer_profile_ref: record.signer_profile_ref,
                    signing_root: record.signing_root,
                    signature: SignatureBytes::from_array(record.signature),
                },
            );
            self.record_count = record.sequence;
            self.head_hash = record.record_hash;
        }
        Ok(())
    }

    fn reconcile_anchor(&mut self) -> Result<(), ReplayBindingErrorV1> {
        match fs::symlink_metadata(&self.anchor_path) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() || !metadata.is_file() {
                    return Err(ReplayBindingErrorV1::InvalidConfig(
                        "response binding anchor must be a regular file",
                    ));
                }
                if metadata.permissions().mode() & 0o777 != 0o600 {
                    return Err(ReplayBindingErrorV1::InvalidConfig(
                        "response binding anchor must have mode 0600",
                    ));
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                if self.record_count != 0 {
                    return Err(ReplayBindingErrorV1::InvalidLog(
                        "non-empty response log has no durable anchor",
                    ));
                }
                self.persist_anchor()?;
                return Ok(());
            }
            Err(source) => {
                return Err(ReplayBindingErrorV1::Io {
                    stage: "inspect response binding anchor",
                    source,
                })
            }
        }
        let bytes = fs::read(&self.anchor_path).map_err(|source| ReplayBindingErrorV1::Io {
            stage: "read response binding anchor",
            source,
        })?;
        let (anchored_count, anchored_head) = decode_replay_anchor(&bytes)?;
        if anchored_count > self.record_count {
            return Err(ReplayBindingErrorV1::InvalidLog(
                "response binding anchor is ahead of log",
            ));
        }
        if anchored_count == self.record_count && anchored_head != self.head_hash {
            return Err(ReplayBindingErrorV1::InvalidLog(
                "response binding anchor differs from log head",
            ));
        }
        if anchored_count < self.record_count {
            self.persist_anchor()?;
        }
        Ok(())
    }

    fn persist_anchor(&self) -> Result<(), ReplayBindingErrorV1> {
        let name = self
            .anchor_path
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or(ReplayBindingErrorV1::InvalidConfig(
                "response anchor filename",
            ))?;
        let temporary = self.anchor_path.with_file_name(format!(
            ".{name}.tmp-{}-{}",
            process::id(),
            self.record_count
        ));
        let bytes = encode_replay_anchor(self.record_count, self.head_hash);
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
            return Err(ReplayBindingErrorV1::Io {
                stage: "persist response binding anchor",
                source,
            });
        }
        Ok(())
    }
}

/// Producer wrapper that turns an injected timeout signer into an exact,
/// durable response-replay boundary.  A second call for the same canonical
/// request is served from the response log and never reaches the producer.
/// Proposal, vote, and epoch intents are rejected before any side effect.
pub struct ReplayBoundTimeoutProducer<P> {
    producer: P,
    store: ReplayBindingStoreV1,
}

impl<P> ReplayBoundTimeoutProducer<P> {
    pub fn open(
        response_log_path: impl AsRef<Path>,
        producer: P,
    ) -> Result<Self, ReplayBindingErrorV1> {
        Ok(Self {
            producer,
            store: ReplayBindingStoreV1::open(response_log_path)?,
        })
    }

    pub fn store(&self) -> &ReplayBindingStoreV1 {
        &self.store
    }

    pub fn into_inner(self) -> P {
        self.producer
    }
}

impl<P: SignatureProducerV0> SignatureProducerV0 for ReplayBoundTimeoutProducer<P> {
    fn sign(
        &mut self,
        request: SignatureRequestV0<'_>,
    ) -> Result<SignatureBytes, trnm_consensus_signer_journal::SignatureProducerErrorV0> {
        if !matches!(
            request.intent().preimage(),
            CanonicalSignPreimageV0::TimeoutVote(_)
        ) {
            return Err(trnm_consensus_signer_journal::SignatureProducerErrorV0::Rejected);
        }
        if let Some(signature) = self
            .store
            .lookup_request(&request)
            .map_err(|_| trnm_consensus_signer_journal::SignatureProducerErrorV0::Internal)?
        {
            return Ok(signature);
        }
        let signature = self.producer.sign(request)?;
        self.store
            .record_request(&request, signature)
            .map_err(|_| trnm_consensus_signer_journal::SignatureProducerErrorV0::Internal)?;
        Ok(signature)
    }
}

fn map_replay_path_error(error: ExternalWatermarkAuthorityError) -> ReplayBindingErrorV1 {
    match error {
        ExternalWatermarkAuthorityError::InvalidConfig(reason) => {
            ReplayBindingErrorV1::InvalidConfig(reason)
        }
        ExternalWatermarkAuthorityError::Io { stage, source } => {
            ReplayBindingErrorV1::Io { stage, source }
        }
        _ => ReplayBindingErrorV1::InvalidConfig("response binding path"),
    }
}

fn ensure_private_regular(file: &File, label: &'static str) -> Result<(), ReplayBindingErrorV1> {
    let metadata = file.metadata().map_err(|source| ReplayBindingErrorV1::Io {
        stage: "stat response binding file",
        source,
    })?;
    if !metadata.is_file() || metadata.permissions().mode() & 0o777 != 0o600 {
        return Err(ReplayBindingErrorV1::InvalidConfig(label));
    }
    Ok(())
}

fn replay_lock_path_for(path: &Path) -> Result<PathBuf, ReplayBindingErrorV1> {
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or(ReplayBindingErrorV1::InvalidConfig("response log filename"))?;
    Ok(path.with_file_name(format!(".{name}.response-lock-v1")))
}

fn replay_anchor_path_for(path: &Path) -> Result<PathBuf, ReplayBindingErrorV1> {
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or(ReplayBindingErrorV1::InvalidConfig("response log filename"))?;
    Ok(path.with_file_name(format!(".{name}.response-head-v1")))
}

fn replay_record_hash(
    sequence: u64,
    fingerprint: [u8; 32],
    signer_profile_ref: [u8; 32],
    signing_root: [u8; 32],
    signature: [u8; 64],
    previous_record_hash: [u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(REPLAY_LOG_DOMAIN);
    hasher.update(sequence.to_be_bytes());
    hasher.update(fingerprint);
    hasher.update(signer_profile_ref);
    hasher.update(signing_root);
    hasher.update(signature);
    hasher.update(previous_record_hash);
    hasher.finalize().into()
}

fn encode_replay_record(record: ReplayRecordV1) -> [u8; REPLAY_RECORD_BYTES] {
    let mut bytes = [0u8; REPLAY_RECORD_BYTES];
    let mut offset = 0;
    bytes[offset..offset + 8].copy_from_slice(REPLAY_LOG_MAGIC);
    offset += 8;
    bytes[offset] = REPLAY_VERSION;
    offset += 1;
    bytes[offset] = 1;
    offset += 1;
    offset += 2;
    bytes[offset..offset + 8].copy_from_slice(&record.sequence.to_be_bytes());
    offset += 8;
    bytes[offset..offset + 32].copy_from_slice(&record.fingerprint);
    offset += 32;
    bytes[offset..offset + 32].copy_from_slice(&record.signer_profile_ref);
    offset += 32;
    bytes[offset..offset + 32].copy_from_slice(&record.signing_root);
    offset += 32;
    bytes[offset..offset + 64].copy_from_slice(&record.signature);
    offset += 64;
    bytes[offset..offset + 32].copy_from_slice(&record.previous_record_hash);
    offset += 32;
    bytes[offset..offset + 32].copy_from_slice(&record.record_hash);
    bytes
}

fn decode_replay_record(bytes: &[u8]) -> Result<ReplayRecordV1, ReplayBindingErrorV1> {
    if bytes.len() != REPLAY_RECORD_BYTES
        || &bytes[..8] != REPLAY_LOG_MAGIC
        || bytes[8] != REPLAY_VERSION
        || bytes[9] != 1
        || bytes[10..12] != [0, 0]
    {
        return Err(ReplayBindingErrorV1::InvalidLog("response record header"));
    }
    let sequence = u64::from_be_bytes(bytes[12..20].try_into().expect("response sequence"));
    let fingerprint = bytes[20..52].try_into().expect("response fingerprint");
    let signer_profile_ref = bytes[52..84].try_into().expect("response profile");
    let signing_root = bytes[84..116].try_into().expect("response signing root");
    let signature = bytes[116..180].try_into().expect("response signature");
    let previous_record_hash = bytes[180..212].try_into().expect("response predecessor");
    let record_hash = bytes[212..244].try_into().expect("response hash");
    if fingerprint == [0; 32]
        || signer_profile_ref == [0; 32]
        || signing_root == [0; 32]
        || signature == [0; 64]
    {
        return Err(ReplayBindingErrorV1::InvalidLog(
            "zero response binding field",
        ));
    }
    Ok(ReplayRecordV1 {
        sequence,
        fingerprint,
        signer_profile_ref,
        signing_root,
        signature,
        previous_record_hash,
        record_hash,
    })
}

fn replay_anchor_checksum(body: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(REPLAY_ANCHOR_MAGIC);
    hasher.update((body.len() as u64).to_be_bytes());
    hasher.update(body);
    hasher.finalize().into()
}

fn encode_replay_anchor(record_count: u64, head_hash: [u8; 32]) -> [u8; REPLAY_ANCHOR_BYTES] {
    let mut bytes = [0u8; REPLAY_ANCHOR_BYTES];
    bytes[..8].copy_from_slice(REPLAY_ANCHOR_MAGIC);
    bytes[8] = REPLAY_VERSION;
    bytes[9..12].copy_from_slice(&[0, 0, 0]);
    bytes[12..20].copy_from_slice(&record_count.to_be_bytes());
    bytes[20..52].copy_from_slice(&head_hash);
    let checksum = replay_anchor_checksum(&bytes[..REPLAY_ANCHOR_BODY_BYTES]);
    bytes[REPLAY_ANCHOR_BODY_BYTES..].copy_from_slice(&checksum);
    bytes
}

fn decode_replay_anchor(bytes: &[u8]) -> Result<(u64, [u8; 32]), ReplayBindingErrorV1> {
    if bytes.len() != REPLAY_ANCHOR_BYTES
        || &bytes[..8] != REPLAY_ANCHOR_MAGIC
        || bytes[8] != REPLAY_VERSION
        || bytes[9..12] != [0, 0, 0]
    {
        return Err(ReplayBindingErrorV1::InvalidLog("response anchor header"));
    }
    if bytes[REPLAY_ANCHOR_BODY_BYTES..]
        != replay_anchor_checksum(&bytes[..REPLAY_ANCHOR_BODY_BYTES])
    {
        return Err(ReplayBindingErrorV1::InvalidLog("response anchor checksum"));
    }
    let count = u64::from_be_bytes(bytes[12..20].try_into().expect("response anchor count"));
    let head = bytes[20..52].try_into().expect("response anchor head");
    if (count == 0) != (head == [0; 32]) {
        return Err(ReplayBindingErrorV1::InvalidLog(
            "response anchor empty state",
        ));
    }
    Ok((count, head))
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
    CompareAndAdvanceSemantic {
        expected: Option<SignerWatermarkV0>,
        target: SignerWatermarkV0,
        facts: ExternalWatermarkSemanticFactsV1,
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

fn semantic_log_path_for(log_path: &Path) -> Result<PathBuf, ExternalWatermarkAuthorityError> {
    let name = log_path.file_name().and_then(|name| name.to_str()).ok_or(
        ExternalWatermarkAuthorityError::InvalidConfig("semantic log filename"),
    )?;
    Ok(log_path.with_file_name(format!(".{name}.semantic-v1")))
}

fn semantic_anchor_path_for(log_path: &Path) -> Result<PathBuf, ExternalWatermarkAuthorityError> {
    let name = log_path.file_name().and_then(|name| name.to_str()).ok_or(
        ExternalWatermarkAuthorityError::InvalidConfig("semantic anchor filename"),
    )?;
    Ok(log_path.with_file_name(format!(".{name}.semantic-head-v1")))
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

fn semantic_record_hash(
    value: SignerWatermarkV0,
    facts: ExternalWatermarkSemanticFactsV1,
    previous: [u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(SEMANTIC_DOMAIN);
    hasher.update(previous);
    hasher.update(value.scope());
    hasher.update(value.journal_id());
    hasher.update(value.sequence().to_be_bytes());
    hasher.update(value.chain_checksum());
    hasher.update(facts.epoch.to_be_bytes());
    hasher.update(facts.view.to_be_bytes());
    hasher.update(facts.safety_revision.to_be_bytes());
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

fn encode_semantic_record(record: SemanticRecordV1) -> [u8; SEMANTIC_RECORD_BYTES] {
    let mut bytes = [0u8; SEMANTIC_RECORD_BYTES];
    let mut offset = 0;
    bytes[offset..offset + 8].copy_from_slice(SEMANTIC_MAGIC);
    offset += 8;
    bytes[offset] = PROTOCOL_VERSION;
    offset += 1;
    bytes[offset] = 1;
    offset += 1;
    offset += 2;
    bytes[offset..offset + 8].copy_from_slice(&record.value.sequence().to_be_bytes());
    offset += 8;
    bytes[offset..offset + 32].copy_from_slice(&record.value.scope());
    offset += 32;
    bytes[offset..offset + 32].copy_from_slice(&record.value.journal_id());
    offset += 32;
    bytes[offset..offset + 32].copy_from_slice(&record.value.chain_checksum());
    offset += 32;
    bytes[offset..offset + 8].copy_from_slice(&record.facts.epoch.to_be_bytes());
    offset += 8;
    bytes[offset..offset + 8].copy_from_slice(&record.facts.view.to_be_bytes());
    offset += 8;
    bytes[offset..offset + 8].copy_from_slice(&record.facts.safety_revision.to_be_bytes());
    offset += 8;
    bytes[offset..offset + 32].copy_from_slice(&record.previous_record_hash);
    offset += 32;
    bytes[offset..offset + 32].copy_from_slice(&record.record_hash);
    bytes
}

fn decode_semantic_record(
    bytes: &[u8],
) -> Result<SemanticRecordV1, ExternalWatermarkAuthorityError> {
    if bytes.len() != SEMANTIC_RECORD_BYTES
        || &bytes[..8] != SEMANTIC_MAGIC
        || bytes[8] != PROTOCOL_VERSION
        || bytes[9] != 1
        || bytes[10..12] != [0, 0]
    {
        return Err(ExternalWatermarkAuthorityError::InvalidLog(
            "semantic record header",
        ));
    }
    let sequence = u64::from_be_bytes(bytes[12..20].try_into().expect("semantic sequence"));
    let scope = bytes[20..52].try_into().expect("semantic scope");
    let journal_id = bytes[52..84].try_into().expect("semantic journal");
    let chain_checksum = bytes[84..116].try_into().expect("semantic checksum");
    let epoch = u64::from_be_bytes(bytes[116..124].try_into().expect("semantic epoch"));
    let view = u64::from_be_bytes(bytes[124..132].try_into().expect("semantic view"));
    let safety_revision =
        u64::from_be_bytes(bytes[132..140].try_into().expect("semantic revision"));
    if safety_revision == 0 {
        return Err(ExternalWatermarkAuthorityError::InvalidLog(
            "semantic revision is zero",
        ));
    }
    // The journal identity and checksum are authenticated by the paired main
    // record. The semantic sidecar carries the scope/sequence and is joined
    // against that exact tuple during replay.
    let previous_record_hash = bytes[140..172].try_into().expect("semantic predecessor");
    let record_hash = bytes[172..204].try_into().expect("semantic hash");
    let value =
        SignerWatermarkV0::from_persisted_parts(scope, journal_id, sequence, chain_checksum)
            .map_err(|_| ExternalWatermarkAuthorityError::InvalidLog("semantic value fields"))?;
    Ok(SemanticRecordV1 {
        value,
        facts: ExternalWatermarkSemanticFactsV1 {
            epoch,
            view,
            safety_revision,
        },
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

fn semantic_anchor_checksum(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(SEMANTIC_ANCHOR_MAGIC);
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
    hasher.finalize().into()
}

fn encode_semantic_anchor(record_count: u64, head_hash: [u8; 32]) -> [u8; SEMANTIC_ANCHOR_BYTES] {
    let mut bytes = [0u8; SEMANTIC_ANCHOR_BYTES];
    bytes[..8].copy_from_slice(SEMANTIC_ANCHOR_MAGIC);
    bytes[8] = PROTOCOL_VERSION;
    bytes[9..12].copy_from_slice(&[0, 0, 0]);
    bytes[12..20].copy_from_slice(&record_count.to_be_bytes());
    bytes[20..52].copy_from_slice(&head_hash);
    let checksum = semantic_anchor_checksum(&bytes[..SEMANTIC_ANCHOR_BODY_BYTES]);
    bytes[SEMANTIC_ANCHOR_BODY_BYTES..].copy_from_slice(&checksum);
    bytes
}

fn decode_semantic_anchor(
    bytes: &[u8],
) -> Result<(u64, [u8; 32]), ExternalWatermarkAuthorityError> {
    if bytes.len() != SEMANTIC_ANCHOR_BYTES
        || &bytes[..8] != SEMANTIC_ANCHOR_MAGIC
        || bytes[8] != PROTOCOL_VERSION
        || bytes[9..12] != [0, 0, 0]
    {
        return Err(ExternalWatermarkAuthorityError::InvalidLog(
            "semantic anchor header",
        ));
    }
    if bytes[SEMANTIC_ANCHOR_BODY_BYTES..]
        != semantic_anchor_checksum(&bytes[..SEMANTIC_ANCHOR_BODY_BYTES])
    {
        return Err(ExternalWatermarkAuthorityError::InvalidLog(
            "semantic anchor checksum",
        ));
    }
    let count = u64::from_be_bytes(bytes[12..20].try_into().expect("semantic anchor count"));
    let head = bytes[20..52].try_into().expect("semantic anchor head");
    if (count == 0) != (head == [0; 32]) {
        return Err(ExternalWatermarkAuthorityError::InvalidLog(
            "semantic anchor empty state",
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
        RequestV1::CompareAndAdvanceSemantic {
            expected,
            target,
            facts,
        } => {
            body.push(OP_COMPARE_AND_ADVANCE_SEMANTIC);
            body.push(u8::from(expected.is_some()));
            body.extend_from_slice(&[0, 0]);
            body.extend_from_slice(&target.scope());
            if let Some(expected) = expected {
                encode_watermark(expected, &mut body);
            }
            encode_watermark(target, &mut body);
            body.extend_from_slice(&facts.epoch.to_be_bytes());
            body.extend_from_slice(&facts.view.to_be_bytes());
            body.extend_from_slice(&facts.safety_revision.to_be_bytes());
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
        OP_COMPARE_AND_ADVANCE_SEMANTIC if expected_present <= 1 => {
            let expected_len = if expected_present == 1 {
                WATERMARK_BYTES
            } else {
                0
            };
            let expected_start = 41;
            let target_start = expected_start + expected_len;
            if body.len() != target_start + WATERMARK_BYTES + 24 {
                return Err(ExternalWatermarkAuthorityError::Protocol(
                    "semantic compare request length",
                ));
            }
            let scope: [u8; 32] = body[9..41].try_into().expect("semantic compare scope");
            let expected = if expected_present == 1 {
                Some(decode_watermark(&body[expected_start..target_start])?)
            } else {
                None
            };
            let target = decode_watermark(&body[target_start..target_start + WATERMARK_BYTES])?;
            if target.scope() != scope {
                return Err(ExternalWatermarkAuthorityError::Protocol(
                    "semantic target scope differs",
                ));
            }
            let facts_start = target_start + WATERMARK_BYTES;
            let facts = ExternalWatermarkSemanticFactsV1 {
                epoch: u64::from_be_bytes(
                    body[facts_start..facts_start + 8]
                        .try_into()
                        .expect("semantic epoch"),
                ),
                view: u64::from_be_bytes(
                    body[facts_start + 8..facts_start + 16]
                        .try_into()
                        .expect("semantic view"),
                ),
                safety_revision: u64::from_be_bytes(
                    body[facts_start + 16..facts_start + 24]
                        .try_into()
                        .expect("semantic revision"),
                ),
            };
            Ok(RequestV1::CompareAndAdvanceSemantic {
                expected,
                target,
                facts,
            })
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
            "durable_response_replay_binding = true",
            "response_binding_append_only_hash_chain = true",
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
