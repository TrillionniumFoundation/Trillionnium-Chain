//! Narrow, runnable checkpoint/restart/state-sync boundary for PoCO-BFT v0.
//!
//! This crate is deliberately smaller than a validator runtime.  It accepts a
//! real, signature-verified weighted [`QuorumCertificate`], binds that
//! certificate to one native application head, and durably records the
//! resulting checkpoint before a process can report restart readiness.  The
//! log is an append-only hash chain with a compare-and-swap predecessor.  A
//! missing state snapshot yields `NeedsStateSync`; a malformed, truncated,
//! reordered, or modified record fails closed.
//!
//! The state-sync API is an application adapter boundary: the caller supplies
//! an independently authenticated snapshot digest for the committed state
//! root.  This crate does not implement JMT execution, Core transitions,
//! SafetyRules, networking, signing, host attestation, or epoch activation.
//! All of those flags remain false until a node owner wires and audits them.

#![forbid(unsafe_code)]

use std::{
    error::Error,
    fmt,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
};

use fs2::FileExt;
use sha2::{Digest, Sha256};
use trnm_consensus_types::{
    decode_ordinary_qc_v0_exact, QuorumCertificate, SignatureVerifier, ValidatorSet,
};
use trnm_native_application::ApplicationHeadV0;

/// The admission path verifies a real weighted QC before persistence.
pub const CORE_RESTART_QUORUM_CHECKPOINT_ADMISSION_V0: bool = true;
/// Checkpoint records are persisted in an append-only, hash-linked log.
pub const CORE_RESTART_DURABLE_CHECKPOINT_LOG_V0: bool = true;
/// A predecessor hash is checked before each append.
pub const CORE_RESTART_CHECKPOINT_CAS_V0: bool = true;
/// Reopening the store authenticates every record and the state snapshot.
pub const CORE_RESTART_RESTART_READBACK_V0: bool = true;
/// A missing snapshot is represented as a state-sync requirement, not guessed.
pub const CORE_RESTART_STATE_SYNC_IMPORT_V0: bool = true;
/// This crate does not issue a Core/SafetyRules permit.
pub const CORE_RESTART_CORE_SAFETY_AUTHORITY_V0: bool = false;
/// This crate does not own a signer or emit signatures.
pub const CORE_RESTART_SIGNER_AUTHORITY_V0: bool = false;
/// This crate does not open a validator runtime or consensus transport.
pub const CORE_RESTART_RUNTIME_ACTIVATION_V0: bool = false;
/// Production activation remains closed.
pub const CORE_RESTART_PRODUCTION_ACTIVATION_V0: bool = false;

const LOG_MAGIC: &[u8; 8] = b"TRNMCR01";
const LOG_SCHEMA: u16 = 1;
const LOG_DOMAIN: &[u8] = b"trnm.core-restart.checkpoint-record.v1\0";
const SNAPSHOT_DOMAIN: &[u8] = b"trnm.core-restart.state-snapshot.v1\0";
const MAX_CHAIN_ID_BYTES: usize = 128;
const MAX_QC_BYTES: usize = 8 * 1024 * 1024;
const MAX_SNAPSHOT_BYTES: usize = 16 * 1024 * 1024;
const MAX_LOG_BYTES: usize = 64 * 1024 * 1024;

#[derive(Debug)]
pub enum CoreRestartError {
    InvalidInput(&'static str),
    InvalidCertificate(String),
    InvalidLog(&'static str),
    CasConflict,
    MissingCheckpoint,
    StateSyncMismatch(&'static str),
    Io {
        stage: &'static str,
        source: io::Error,
    },
}

impl fmt::Display for CoreRestartError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInput(field) => write!(formatter, "invalid checkpoint input: {field}"),
            Self::InvalidCertificate(reason) => {
                write!(
                    formatter,
                    "quorum checkpoint certificate rejected: {reason}"
                )
            }
            Self::InvalidLog(reason) => write!(formatter, "checkpoint log rejected: {reason}"),
            Self::CasConflict => formatter.write_str("checkpoint predecessor CAS conflict"),
            Self::MissingCheckpoint => formatter.write_str("checkpoint is not installed"),
            Self::StateSyncMismatch(field) => {
                write!(formatter, "state-sync bundle does not match {field}")
            }
            Self::Io { stage, source } => write!(formatter, "checkpoint I/O at {stage}: {source}"),
        }
    }
}

impl Error for CoreRestartError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

type Result<T> = std::result::Result<T, CoreRestartError>;

fn io_error(stage: &'static str, source: io::Error) -> CoreRestartError {
    CoreRestartError::Io { stage, source }
}

fn digest(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
    hasher.finalize().into()
}

fn nonzero(bytes: &[u8; 32], field: &'static str) -> Result<()> {
    if *bytes == [0; 32] {
        Err(CoreRestartError::InvalidInput(field))
    } else {
        Ok(())
    }
}

/// A candidate checkpoint after complete QC and application-head validation,
/// but before it is assigned a durable generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckpointCandidateV0 {
    chain_id: String,
    epoch: u64,
    height: u64,
    validator_set_id: [u8; 32],
    block_id: [u8; 32],
    state_root: [u8; 32],
    application_commit_id: [u8; 32],
    quorum_certificate_id: [u8; 32],
    quorum_certificate_bytes: Vec<u8>,
    snapshot_digest: [u8; 32],
    snapshot_bytes: Vec<u8>,
}

impl CheckpointCandidateV0 {
    /// Verifies all QC signatures and weighted quorum using the caller's
    /// deterministic verifier, then binds the result to one application head.
    /// The verifier should be the project's strict Ed25519 implementation in
    /// a real node; this crate intentionally does not choose a verifier.
    pub fn admit_quorum_certificate<V: SignatureVerifier>(
        certificate: &QuorumCertificate,
        validator_set: &ValidatorSet,
        verifier: &V,
        application_head: &ApplicationHeadV0,
        snapshot_bytes: Vec<u8>,
    ) -> Result<Self> {
        certificate
            .verify(validator_set, verifier)
            .map_err(|error| CoreRestartError::InvalidCertificate(format!("{error:?}")))?;
        if certificate.height().get() != application_head.height().get()
            || certificate.block_id().as_bytes() != application_head.block_id().as_bytes()
            || certificate.epoch() != validator_set.epoch()
            || certificate.validator_set_id() != validator_set.id()
            || certificate.chain_id() != validator_set.chain_id()
        {
            return Err(CoreRestartError::InvalidCertificate(
                "QC/application head or validator-set binding differs".to_owned(),
            ));
        }
        if certificate.height().get() == 0 {
            return Err(CoreRestartError::InvalidCertificate(
                "checkpoint height must be positive".to_owned(),
            ));
        }
        if snapshot_bytes.is_empty() || snapshot_bytes.len() > MAX_SNAPSHOT_BYTES {
            return Err(CoreRestartError::InvalidInput("state snapshot size"));
        }
        let quorum_certificate_bytes = certificate
            .try_cev0_bytes()
            .map_err(|error| CoreRestartError::InvalidCertificate(format!("{error:?}")))?;
        if quorum_certificate_bytes.len() > MAX_QC_BYTES {
            return Err(CoreRestartError::InvalidInput("quorum certificate size"));
        }
        let snapshot_digest = digest(SNAPSHOT_DOMAIN, &snapshot_bytes);
        let validator_set_id = *certificate.validator_set_id().as_bytes();
        let block_id = *certificate.block_id().as_bytes();
        let state_root = *application_head.state_root().as_bytes();
        let application_commit_id = *application_head.commit_id().as_bytes();
        nonzero(&validator_set_id, "validator set id")?;
        nonzero(&block_id, "block id")?;
        nonzero(&state_root, "state root")?;
        nonzero(&application_commit_id, "application commit id")?;
        Ok(Self {
            chain_id: certificate.chain_id().as_str().to_owned(),
            epoch: certificate.epoch().get(),
            height: certificate.height().get(),
            validator_set_id,
            block_id,
            state_root,
            application_commit_id,
            quorum_certificate_id: *certificate.id().as_bytes(),
            quorum_certificate_bytes,
            snapshot_digest,
            snapshot_bytes,
        })
    }

    pub fn chain_id(&self) -> &str {
        &self.chain_id
    }

    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    pub const fn height(&self) -> u64 {
        self.height
    }

    pub const fn block_id(&self) -> [u8; 32] {
        self.block_id
    }

    pub const fn state_root(&self) -> [u8; 32] {
        self.state_root
    }

    pub const fn application_commit_id(&self) -> [u8; 32] {
        self.application_commit_id
    }

    pub const fn snapshot_digest(&self) -> [u8; 32] {
        self.snapshot_digest
    }
}

/// One durable, quorum-certified checkpoint record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckpointRecordV0 {
    generation: u64,
    epoch: u64,
    height: u64,
    chain_id: String,
    validator_set_id: [u8; 32],
    block_id: [u8; 32],
    state_root: [u8; 32],
    application_commit_id: [u8; 32],
    quorum_certificate_id: [u8; 32],
    quorum_certificate_bytes: Vec<u8>,
    snapshot_digest: [u8; 32],
    predecessor_hash: [u8; 32],
    record_hash: [u8; 32],
}

impl CheckpointRecordV0 {
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    pub const fn height(&self) -> u64 {
        self.height
    }

    pub fn chain_id(&self) -> &str {
        &self.chain_id
    }

    pub const fn validator_set_id(&self) -> [u8; 32] {
        self.validator_set_id
    }

    pub const fn block_id(&self) -> [u8; 32] {
        self.block_id
    }

    pub const fn state_root(&self) -> [u8; 32] {
        self.state_root
    }

    pub const fn application_commit_id(&self) -> [u8; 32] {
        self.application_commit_id
    }

    pub const fn quorum_certificate_id(&self) -> [u8; 32] {
        self.quorum_certificate_id
    }

    pub fn quorum_certificate_bytes(&self) -> &[u8] {
        &self.quorum_certificate_bytes
    }

    pub const fn snapshot_digest(&self) -> [u8; 32] {
        self.snapshot_digest
    }

    pub const fn predecessor_hash(&self) -> [u8; 32] {
        self.predecessor_hash
    }

    pub const fn record_hash(&self) -> [u8; 32] {
        self.record_hash
    }

    fn from_candidate(
        candidate: &CheckpointCandidateV0,
        generation: u64,
        predecessor_hash: [u8; 32],
    ) -> Self {
        let mut value = Self {
            generation,
            epoch: candidate.epoch,
            height: candidate.height,
            chain_id: candidate.chain_id.clone(),
            validator_set_id: candidate.validator_set_id,
            block_id: candidate.block_id,
            state_root: candidate.state_root,
            application_commit_id: candidate.application_commit_id,
            quorum_certificate_id: candidate.quorum_certificate_id,
            quorum_certificate_bytes: candidate.quorum_certificate_bytes.clone(),
            snapshot_digest: candidate.snapshot_digest,
            predecessor_hash,
            record_hash: [0; 32],
        };
        value.record_hash = value.compute_hash();
        value
    }

    fn body_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(512 + self.quorum_certificate_bytes.len());
        push_u16(&mut bytes, LOG_SCHEMA);
        push_u64(&mut bytes, self.generation);
        push_u64(&mut bytes, self.epoch);
        push_u64(&mut bytes, self.height);
        push_string(&mut bytes, &self.chain_id);
        bytes.extend_from_slice(&self.validator_set_id);
        bytes.extend_from_slice(&self.block_id);
        bytes.extend_from_slice(&self.state_root);
        bytes.extend_from_slice(&self.application_commit_id);
        bytes.extend_from_slice(&self.quorum_certificate_id);
        bytes.extend_from_slice(&self.snapshot_digest);
        push_u32(&mut bytes, self.quorum_certificate_bytes.len() as u32);
        bytes.extend_from_slice(&self.quorum_certificate_bytes);
        bytes.extend_from_slice(&self.predecessor_hash);
        bytes
    }

    fn compute_hash(&self) -> [u8; 32] {
        digest(LOG_DOMAIN, &self.body_bytes())
    }

    fn encode(&self) -> Vec<u8> {
        let body = self.body_bytes();
        let mut bytes = Vec::with_capacity(LOG_MAGIC.len() + body.len() + 32);
        bytes.extend_from_slice(LOG_MAGIC);
        bytes.extend_from_slice(&body);
        bytes.extend_from_slice(&self.record_hash);
        bytes
    }

    fn validate(&self, expected_predecessor: [u8; 32]) -> Result<()> {
        if self.chain_id.is_empty() || self.chain_id.len() > MAX_CHAIN_ID_BYTES {
            return Err(CoreRestartError::InvalidLog("chain id length"));
        }
        if trnm_consensus_types::ChainId::new(&self.chain_id).is_err() {
            return Err(CoreRestartError::InvalidLog("chain id canonical encoding"));
        }
        if self.height == 0 {
            return Err(CoreRestartError::InvalidLog("checkpoint height is zero"));
        }
        if self.predecessor_hash != expected_predecessor {
            return Err(CoreRestartError::InvalidLog("record predecessor hash"));
        }
        nonzero(&self.validator_set_id, "record validator set id")?;
        nonzero(&self.block_id, "record block id")?;
        nonzero(&self.state_root, "record state root")?;
        nonzero(&self.application_commit_id, "record application commit id")?;
        nonzero(&self.quorum_certificate_id, "record QC id")?;
        nonzero(&self.snapshot_digest, "record snapshot digest")?;
        if self.quorum_certificate_bytes.is_empty()
            || self.quorum_certificate_bytes.len() > MAX_QC_BYTES
        {
            return Err(CoreRestartError::InvalidLog("record QC bytes"));
        }
        if self.record_hash != self.compute_hash() {
            return Err(CoreRestartError::InvalidLog("record checksum"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckpointCommitOutcomeV0 {
    Committed,
    AlreadyCommitted,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RestartDispositionV0 {
    Empty,
    Ready(CheckpointRecordV0),
    NeedsStateSync(CheckpointRecordV0),
}

/// A state-sync payload tied to an already admitted checkpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateSyncBundleV0 {
    checkpoint_record_hash: [u8; 32],
    state_root: [u8; 32],
    snapshot_digest: [u8; 32],
    snapshot_bytes: Vec<u8>,
}

impl StateSyncBundleV0 {
    pub fn new(
        checkpoint_record_hash: [u8; 32],
        state_root: [u8; 32],
        snapshot_digest: [u8; 32],
        snapshot_bytes: Vec<u8>,
    ) -> Result<Self> {
        nonzero(&checkpoint_record_hash, "state-sync checkpoint hash")?;
        nonzero(&state_root, "state-sync state root")?;
        nonzero(&snapshot_digest, "state-sync snapshot digest")?;
        if snapshot_bytes.is_empty() || snapshot_bytes.len() > MAX_SNAPSHOT_BYTES {
            return Err(CoreRestartError::InvalidInput("state-sync snapshot size"));
        }
        if digest(SNAPSHOT_DOMAIN, &snapshot_bytes) != snapshot_digest {
            return Err(CoreRestartError::StateSyncMismatch("snapshot digest"));
        }
        Ok(Self {
            checkpoint_record_hash,
            state_root,
            snapshot_digest,
            snapshot_bytes,
        })
    }
}

/// Durable checkpoint log owner.  The exclusive lock makes the CAS boundary
/// cross-process for one path; every reopen replays and authenticates the full
/// log before exposing a record.
pub struct CheckpointStoreV0 {
    directory_path: PathBuf,
    directory: File,
    log: File,
    _lock: File,
    current: Option<CheckpointRecordV0>,
    poisoned: bool,
}

impl CheckpointStoreV0 {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let directory_path = path.as_ref().to_path_buf();
        fs::create_dir_all(&directory_path)
            .map_err(|source| io_error("create directory", source))?;
        let directory = OpenOptions::new()
            .read(true)
            .open(&directory_path)
            .map_err(|source| io_error("open directory", source))?;
        let lock_path = directory_path.join("checkpoint.lock");
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(lock_path)
            .map_err(|source| io_error("open checkpoint lock", source))?;
        lock.try_lock_exclusive()
            .map_err(|source| io_error("lock checkpoint namespace", source))?;
        let log_path = directory_path.join("checkpoint.log");
        let log = OpenOptions::new()
            .read(true)
            .append(true)
            .create(true)
            .open(log_path)
            .map_err(|source| io_error("open checkpoint log", source))?;
        let mut value = Self {
            directory_path,
            directory,
            log,
            _lock: lock,
            current: None,
            poisoned: false,
        };
        value.replay_log()?;
        Ok(value)
    }

    pub fn current(&self) -> Option<&CheckpointRecordV0> {
        self.current.as_ref()
    }

    pub fn restart_disposition(&self) -> Result<RestartDispositionV0> {
        self.ensure_healthy()?;
        let Some(checkpoint) = self.current.clone() else {
            return Ok(RestartDispositionV0::Empty);
        };
        let path = self.snapshot_path(checkpoint.generation);
        match fs::read(&path) {
            Ok(bytes) => {
                if digest(SNAPSHOT_DOMAIN, &bytes) != checkpoint.snapshot_digest {
                    return Err(CoreRestartError::InvalidLog("state snapshot checksum"));
                }
                Ok(RestartDispositionV0::Ready(checkpoint))
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                Ok(RestartDispositionV0::NeedsStateSync(checkpoint))
            }
            Err(source) => Err(io_error("read state snapshot", source)),
        }
    }

    /// Appends one successor after checking the expected predecessor hash.
    /// The snapshot is synced before the checkpoint record, so a crash cannot
    /// expose a checkpoint whose local state bytes were never durable.
    pub fn commit(
        &mut self,
        candidate: &CheckpointCandidateV0,
        expected_predecessor: Option<[u8; 32]>,
    ) -> Result<CheckpointCommitOutcomeV0> {
        self.ensure_healthy()?;
        let predecessor = self.current.as_ref().map(CheckpointRecordV0::record_hash);
        if expected_predecessor != predecessor {
            return Err(CoreRestartError::CasConflict);
        }
        if let Some(previous) = self.current.as_ref() {
            if candidate.chain_id == previous.chain_id
                && candidate.epoch == previous.epoch
                && candidate.height == previous.height
                && candidate.validator_set_id == previous.validator_set_id
                && candidate.block_id == previous.block_id
                && candidate.state_root == previous.state_root
                && candidate.application_commit_id == previous.application_commit_id
                && candidate.quorum_certificate_id == previous.quorum_certificate_id
                && candidate.snapshot_digest == previous.snapshot_digest
            {
                return Ok(CheckpointCommitOutcomeV0::AlreadyCommitted);
            }
            if candidate.chain_id != previous.chain_id
                || candidate.epoch < previous.epoch
                || candidate.height <= previous.height
            {
                return Err(CoreRestartError::InvalidInput(
                    "checkpoint successor geometry",
                ));
            }
            if candidate.epoch == previous.epoch
                && candidate.validator_set_id != previous.validator_set_id
            {
                return Err(CoreRestartError::InvalidInput(
                    "validator set changed inside an epoch",
                ));
            }
        }
        let generation = match self.current.as_ref() {
            None => 0,
            Some(record) => {
                record
                    .generation
                    .checked_add(1)
                    .ok_or(CoreRestartError::InvalidInput(
                        "checkpoint generation overflow",
                    ))?
            }
        };
        let snapshot_path = self.snapshot_path(generation);
        write_atomic(&self.directory, &snapshot_path, &candidate.snapshot_bytes)?;
        let record = CheckpointRecordV0::from_candidate(
            candidate,
            generation,
            predecessor.unwrap_or([0; 32]),
        );
        record.validate(predecessor.unwrap_or([0; 32]))?;
        if let Err(source) = self.log.write_all(&record.encode()) {
            self.poisoned = true;
            return Err(io_error("append checkpoint record", source));
        }
        if let Err(source) = self.log.sync_all() {
            self.poisoned = true;
            return Err(io_error("sync checkpoint record", source));
        }
        if let Err(source) = self.directory.sync_all() {
            self.poisoned = true;
            return Err(io_error("sync checkpoint directory", source));
        }
        self.current = Some(record);
        Ok(CheckpointCommitOutcomeV0::Committed)
    }

    /// Installs a missing snapshot only after matching the exact retained
    /// checkpoint.  This is a state-sync import, not a new consensus commit.
    pub fn install_state_sync(&mut self, bundle: StateSyncBundleV0) -> Result<()> {
        self.ensure_healthy()?;
        let checkpoint = self
            .current
            .as_ref()
            .ok_or(CoreRestartError::MissingCheckpoint)?;
        if bundle.checkpoint_record_hash != checkpoint.record_hash {
            return Err(CoreRestartError::StateSyncMismatch("checkpoint record"));
        }
        if bundle.state_root != checkpoint.state_root {
            return Err(CoreRestartError::StateSyncMismatch("state root"));
        }
        if bundle.snapshot_digest != checkpoint.snapshot_digest {
            return Err(CoreRestartError::StateSyncMismatch("snapshot digest"));
        }
        write_atomic(
            &self.directory,
            &self.snapshot_path(checkpoint.generation),
            &bundle.snapshot_bytes,
        )
    }

    /// Re-verifies the current checkpoint's QC against the live validator set
    /// after restart.  The stored CEV0 bytes are compared to the exact caller
    /// supplied certificate; no unauthenticated metadata is enough.
    pub fn verify_current_quorum_certificate<V: SignatureVerifier>(
        &self,
        certificate: &QuorumCertificate,
        validator_set: &ValidatorSet,
        verifier: &V,
    ) -> Result<()> {
        self.ensure_healthy()?;
        let checkpoint = self
            .current
            .as_ref()
            .ok_or(CoreRestartError::MissingCheckpoint)?;
        let decoded =
            decode_ordinary_qc_v0_exact(&checkpoint.quorum_certificate_bytes, validator_set)
                .map_err(|error| CoreRestartError::InvalidCertificate(format!("{error:?}")))?;
        if decoded != *certificate {
            return Err(CoreRestartError::InvalidCertificate(
                "decoded retained QC differs from supplied QC".to_owned(),
            ));
        }
        certificate
            .verify(validator_set, verifier)
            .map_err(|error| CoreRestartError::InvalidCertificate(format!("{error:?}")))?;
        let encoded = certificate
            .try_cev0_bytes()
            .map_err(|error| CoreRestartError::InvalidCertificate(format!("{error:?}")))?;
        if certificate.id().as_bytes() != &checkpoint.quorum_certificate_id
            || encoded != checkpoint.quorum_certificate_bytes
            || certificate.block_id().as_bytes() != &checkpoint.block_id
            || certificate.height().get() != checkpoint.height
            || certificate.epoch().get() != checkpoint.epoch
            || certificate.validator_set_id().as_bytes() != &checkpoint.validator_set_id
        {
            return Err(CoreRestartError::InvalidCertificate(
                "replayed QC differs from retained checkpoint".to_owned(),
            ));
        }
        Ok(())
    }

    fn snapshot_path(&self, generation: u64) -> PathBuf {
        self.directory_path
            .join(format!("state-{generation:020}.bin"))
    }

    fn ensure_healthy(&self) -> Result<()> {
        if self.poisoned {
            return Err(CoreRestartError::InvalidLog(
                "checkpoint store is poisoned after commit I/O failure",
            ));
        }
        Ok(())
    }

    fn replay_log(&mut self) -> Result<()> {
        let mut bytes = Vec::new();
        let mut reader = self
            .log
            .try_clone()
            .map_err(|source| io_error("clone checkpoint log", source))?;
        reader
            .read_to_end(&mut bytes)
            .map_err(|source| io_error("read checkpoint log", source))?;
        if bytes.len() > MAX_LOG_BYTES {
            return Err(CoreRestartError::InvalidLog("checkpoint log exceeds bound"));
        }
        let mut offset = 0usize;
        let mut expected_previous = [0; 32];
        let mut expected_generation = 0u64;
        let mut previous: Option<CheckpointRecordV0> = None;
        while offset < bytes.len() {
            let (record, next) = decode_record(&bytes, offset)?;
            if record.generation != expected_generation {
                return Err(CoreRestartError::InvalidLog(
                    "checkpoint generation is not contiguous",
                ));
            }
            record.validate(expected_previous)?;
            if let Some(ref prior) = previous {
                if record.chain_id != prior.chain_id
                    || record.height <= prior.height
                    || record.epoch < prior.epoch
                    || (record.epoch == prior.epoch
                        && record.validator_set_id != prior.validator_set_id)
                {
                    return Err(CoreRestartError::InvalidLog(
                        "checkpoint successor geometry",
                    ));
                }
            }
            expected_previous = record.record_hash;
            expected_generation =
                expected_generation
                    .checked_add(1)
                    .ok_or(CoreRestartError::InvalidLog(
                        "checkpoint generation overflow",
                    ))?;
            previous = Some(record);
            offset = next;
        }
        if offset != bytes.len() {
            return Err(CoreRestartError::InvalidLog(
                "checkpoint log trailing bytes",
            ));
        }
        self.current = previous;
        Ok(())
    }
}

fn write_atomic(directory: &File, path: &Path, bytes: &[u8]) -> Result<()> {
    if bytes.is_empty() || bytes.len() > MAX_SNAPSHOT_BYTES {
        return Err(CoreRestartError::InvalidInput("state snapshot size"));
    }
    let temp = path.with_extension(format!("tmp-{}", std::process::id()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp)
        .map_err(|source| io_error("create state snapshot temporary", source))?;
    if let Err(source) = file.write_all(bytes).and_then(|_| file.sync_all()) {
        let _ = fs::remove_file(&temp);
        return Err(io_error("sync state snapshot temporary", source));
    }
    fs::rename(&temp, path).map_err(|source| io_error("install state snapshot", source))?;
    directory
        .sync_all()
        .map_err(|source| io_error("sync state snapshot directory", source))
}

fn push_u16(bytes: &mut Vec<u8>, value: u16) {
    bytes.extend_from_slice(&value.to_be_bytes());
}

fn push_u32(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(&value.to_be_bytes());
}

fn push_u64(bytes: &mut Vec<u8>, value: u64) {
    bytes.extend_from_slice(&value.to_be_bytes());
}

fn push_string(bytes: &mut Vec<u8>, value: &str) {
    push_u16(bytes, value.len() as u16);
    bytes.extend_from_slice(value.as_bytes());
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, length: usize) -> Result<&'a [u8]> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(CoreRestartError::InvalidLog("checkpoint offset overflow"))?;
        if end > self.bytes.len() {
            return Err(CoreRestartError::InvalidLog("checkpoint record truncated"));
        }
        let value = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(value)
    }

    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(
            self.take(2)?.try_into().expect("fixed length"),
        ))
    }

    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(
            self.take(4)?.try_into().expect("fixed length"),
        ))
    }

    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(
            self.take(8)?.try_into().expect("fixed length"),
        ))
    }

    fn fixed32(&mut self) -> Result<[u8; 32]> {
        Ok(self.take(32)?.try_into().expect("fixed length"))
    }
}

fn decode_record(bytes: &[u8], offset: usize) -> Result<(CheckpointRecordV0, usize)> {
    let mut cursor = Cursor { bytes, offset };
    if cursor.take(LOG_MAGIC.len())? != LOG_MAGIC {
        return Err(CoreRestartError::InvalidLog("checkpoint log magic"));
    }
    if cursor.u16()? != LOG_SCHEMA {
        return Err(CoreRestartError::InvalidLog("checkpoint log schema"));
    }
    let generation = cursor.u64()?;
    let epoch = cursor.u64()?;
    let height = cursor.u64()?;
    let chain_len = usize::from(cursor.u16()?);
    if chain_len == 0 || chain_len > MAX_CHAIN_ID_BYTES {
        return Err(CoreRestartError::InvalidLog("checkpoint chain id length"));
    }
    let chain_id = std::str::from_utf8(cursor.take(chain_len)?)
        .map_err(|_| CoreRestartError::InvalidLog("checkpoint chain id encoding"))?
        .to_owned();
    let validator_set_id = cursor.fixed32()?;
    let block_id = cursor.fixed32()?;
    let state_root = cursor.fixed32()?;
    let application_commit_id = cursor.fixed32()?;
    let quorum_certificate_id = cursor.fixed32()?;
    let snapshot_digest = cursor.fixed32()?;
    let qc_len = usize::try_from(cursor.u32()?)
        .map_err(|_| CoreRestartError::InvalidLog("checkpoint QC length"))?;
    if qc_len == 0 || qc_len > MAX_QC_BYTES {
        return Err(CoreRestartError::InvalidLog("checkpoint QC length"));
    }
    let quorum_certificate_bytes = cursor.take(qc_len)?.to_vec();
    let predecessor_hash = cursor.fixed32()?;
    let record_hash = cursor.fixed32()?;
    let record = CheckpointRecordV0 {
        generation,
        epoch,
        height,
        chain_id,
        validator_set_id,
        block_id,
        state_root,
        application_commit_id,
        quorum_certificate_id,
        quorum_certificate_bytes,
        snapshot_digest,
        predecessor_hash,
        record_hash,
    };
    Ok((record, cursor.offset))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
    use tempfile::tempdir;
    use trnm_consensus_types::{
        BlockId, ChainId, ConsensusParametersHash, ConsensusPublicKey, Epoch, Height,
        ProtocolVersion, SignatureBytes, Validator, ValidatorId, ValidatorSet, View, Vote,
        VotingPower,
    };

    struct StrictTestVerifier;

    impl SignatureVerifier for StrictTestVerifier {
        fn verify(
            &self,
            validator: &Validator,
            root: &trnm_consensus_types::SigningRoot,
            signature: &SignatureBytes,
        ) -> bool {
            let Ok(key) = VerifyingKey::from_bytes(validator.consensus_key().as_bytes()) else {
                return false;
            };
            key.verify_strict(
                root.as_bytes(),
                &Signature::from_bytes(signature.as_bytes()),
            )
            .is_ok()
        }
    }

    fn fixture() -> (ValidatorSet, QuorumCertificate, ApplicationHeadV0) {
        let genesis = trnm_consensus_types::GenesisHash::new([7; 32]);
        let chain = ChainId::new("restart-test").expect("chain");
        let params_hash = ConsensusParametersHash::new([8; 32]);
        let mut keys = Vec::new();
        let mut validators = Vec::new();
        for index in 0..4u8 {
            let signing = SigningKey::from_bytes(&[index + 1; 32]);
            let key = signing.verifying_key();
            let id = ValidatorId::new([index + 1; 32]);
            keys.push(signing);
            validators.push(
                Validator::new(
                    id,
                    ConsensusPublicKey::new(key.to_bytes()),
                    VotingPower::new(1).expect("power"),
                )
                .expect("validator"),
            );
        }
        validators.sort_by_key(Validator::id);
        let set = ValidatorSet::new(
            genesis,
            chain,
            ProtocolVersion::V0,
            Epoch::new(0),
            params_hash,
            validators,
        )
        .expect("set");
        let block_id = BlockId::new([9; 32]);
        let height = Height::new(4);
        let view = View::new(1);
        let mut votes = Vec::new();
        for (index, signing) in keys[..3].iter().enumerate() {
            let id = ValidatorId::new([index as u8 + 1; 32]);
            let root = Vote::signing_root_for_set(&set, view, height, block_id).expect("root");
            let signature = SignatureBytes::from_array(signing.sign(root.as_bytes()).to_bytes());
            votes.push(
                Vote::new(
                    chain,
                    ProtocolVersion::V0,
                    Epoch::new(0),
                    view,
                    height,
                    block_id,
                    set.id(),
                    id,
                    signature,
                    &set,
                )
                .expect("vote"),
            );
        }
        votes.sort_by_key(Vote::author);
        let qc = QuorumCertificate::new(
            chain,
            ProtocolVersion::V0,
            Epoch::new(0),
            view,
            height,
            block_id,
            set.id(),
            votes,
            &set,
        )
        .expect("QC");
        let head = ApplicationHeadV0::new(
            trnm_native_application::HeightV0::new(4),
            trnm_native_application::BlockIdV0::new([9; 32]).expect("block"),
            trnm_native_application::StateRootV0::new([10; 32]).expect("root"),
            trnm_native_application::ApplicationCommitIdV0::new([11; 32]).expect("commit"),
        );
        (set, qc, head)
    }

    #[test]
    fn qc_admission_commit_restart_and_reverify_are_real() {
        let (set, qc, head) = fixture();
        let candidate = CheckpointCandidateV0::admit_quorum_certificate(
            &qc,
            &set,
            &StrictTestVerifier,
            &head,
            b"authenticated-state-v1".to_vec(),
        )
        .expect("admit");
        let directory = tempdir().expect("directory");
        let mut store = CheckpointStoreV0::open(directory.path()).expect("open");
        assert_eq!(
            store.commit(&candidate, None).expect("commit"),
            CheckpointCommitOutcomeV0::Committed
        );
        assert!(matches!(
            store.restart_disposition().expect("restart"),
            RestartDispositionV0::Ready(_)
        ));
        store
            .verify_current_quorum_certificate(&qc, &set, &StrictTestVerifier)
            .expect("reverify");
        drop(store);
        let reopened = CheckpointStoreV0::open(directory.path()).expect("reopen");
        assert!(matches!(
            reopened.restart_disposition().expect("restarted"),
            RestartDispositionV0::Ready(_)
        ));
    }

    #[test]
    fn missing_state_requires_exact_state_sync_and_wrong_bundle_fails() {
        let (set, qc, head) = fixture();
        let bytes = b"authenticated-state-v1".to_vec();
        let candidate = CheckpointCandidateV0::admit_quorum_certificate(
            &qc,
            &set,
            &StrictTestVerifier,
            &head,
            bytes.clone(),
        )
        .expect("admit");
        let directory = tempdir().expect("directory");
        let mut store = CheckpointStoreV0::open(directory.path()).expect("open");
        store.commit(&candidate, None).expect("commit");
        let record = store.current().expect("record").clone();
        fs::remove_file(store.snapshot_path(record.generation())).expect("remove snapshot");
        assert!(matches!(
            store.restart_disposition().expect("needs sync"),
            RestartDispositionV0::NeedsStateSync(_)
        ));
        let digest = digest(SNAPSHOT_DOMAIN, &bytes);
        let bundle =
            StateSyncBundleV0::new(record.record_hash(), record.state_root(), digest, bytes)
                .expect("bundle");
        store.install_state_sync(bundle).expect("install");
        assert!(matches!(
            store.restart_disposition().expect("ready"),
            RestartDispositionV0::Ready(_)
        ));
        let wrong = StateSyncBundleV0::new(
            record.record_hash(),
            [12; 32],
            digest,
            b"authenticated-state-v1".to_vec(),
        )
        .expect("well-formed but foreign state-sync bundle");
        assert!(matches!(
            store.install_state_sync(wrong),
            Err(CoreRestartError::StateSyncMismatch("state root"))
        ));
    }

    #[test]
    fn tampered_or_truncated_log_fails_closed_and_cas_rejects_stale_writer() {
        let (set, qc, head) = fixture();
        let candidate = CheckpointCandidateV0::admit_quorum_certificate(
            &qc,
            &set,
            &StrictTestVerifier,
            &head,
            b"state".to_vec(),
        )
        .expect("admit");
        let directory = tempdir().expect("directory");
        let mut store = CheckpointStoreV0::open(directory.path()).expect("open");
        store.commit(&candidate, None).expect("commit");
        let record = store.current().expect("record").clone();
        assert!(matches!(
            CheckpointStoreV0::open(directory.path()),
            Err(CoreRestartError::Io {
                stage: "lock checkpoint namespace",
                ..
            })
        ));
        assert!(matches!(
            store.commit(&candidate, Some([0; 32])),
            Err(CoreRestartError::CasConflict)
        ));
        let mut rollback = candidate.clone();
        rollback.height = 3;
        assert!(matches!(
            store.commit(&rollback, Some(record.record_hash())),
            Err(CoreRestartError::InvalidInput(
                "checkpoint successor geometry"
            ))
        ));
        drop(store);
        let log_path = directory.path().join("checkpoint.log");
        let mut bytes = fs::read(&log_path).expect("read");
        bytes.pop();
        fs::write(&log_path, &bytes).expect("truncate");
        assert!(CheckpointStoreV0::open(directory.path()).is_err());
        fs::write(&log_path, record.encode()).expect("restore");
        let mut bytes = fs::read(&log_path).expect("read");
        let index = bytes.len() - 1;
        bytes[index] ^= 0x01;
        fs::write(&log_path, bytes).expect("tamper");
        assert!(CheckpointStoreV0::open(directory.path()).is_err());
    }

    #[test]
    fn commit_io_poison_fences_same_process_follow_up_operations() {
        let (set, qc, head) = fixture();
        let candidate = CheckpointCandidateV0::admit_quorum_certificate(
            &qc,
            &set,
            &StrictTestVerifier,
            &head,
            b"state".to_vec(),
        )
        .expect("admit");
        let directory = tempdir().expect("directory");
        let mut store = CheckpointStoreV0::open(directory.path()).expect("open");
        store.poisoned = true;
        assert!(matches!(
            store.commit(&candidate, None),
            Err(CoreRestartError::InvalidLog(
                "checkpoint store is poisoned after commit I/O failure"
            ))
        ));
        assert!(matches!(
            store.restart_disposition(),
            Err(CoreRestartError::InvalidLog(
                "checkpoint store is poisoned after commit I/O failure"
            ))
        ));
        let bundle = StateSyncBundleV0::new(
            [1; 32],
            [2; 32],
            digest(SNAPSHOT_DOMAIN, b"state"),
            b"state".to_vec(),
        )
        .expect("bundle");
        assert!(matches!(
            store.install_state_sync(bundle),
            Err(CoreRestartError::InvalidLog(
                "checkpoint store is poisoned after commit I/O failure"
            ))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn actual_checkpoint_log_write_failure_enters_terminal_poison_state() {
        let (set, qc, head) = fixture();
        let candidate = CheckpointCandidateV0::admit_quorum_certificate(
            &qc,
            &set,
            &StrictTestVerifier,
            &head,
            b"state".to_vec(),
        )
        .expect("admit");
        let directory = tempdir().expect("directory");
        let mut store = CheckpointStoreV0::open(directory.path()).expect("open");
        let full = OpenOptions::new()
            .write(true)
            .open("/dev/full")
            .expect("Linux /dev/full");
        let _original_log = std::mem::replace(&mut store.log, full);
        assert!(matches!(
            store.commit(&candidate, None),
            Err(CoreRestartError::Io {
                stage: "append checkpoint record",
                ..
            })
        ));
        assert!(matches!(
            store.restart_disposition(),
            Err(CoreRestartError::InvalidLog(
                "checkpoint store is poisoned after commit I/O failure"
            ))
        ));
    }
}
