#![forbid(unsafe_code)]
//! Locked, hash-chained file adapters for PoCO-BFT v0 authority and state sync.
//!
//! These adapters implement process exclusion, exact record recovery,
//! write-before-return durability calls, immutable snapshot generations, and a
//! current-pointer compare-and-swap. They are production-shaped repository
//! code, but physical power-loss behavior, filesystem guarantees, deployment
//! topology, and device-backed signing remain external evidence requirements.

use fs2::FileExt;
use std::{
    error::Error,
    fmt,
    fs::{self, File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};
use trnm_node_boundary_v0::{
    AuthorityCommandV0, AuthorityCoordinatorV0, AuthorityReceiptV0, AuthorityStageV0,
    BoundaryErrorV0, Digest32V0 as NodeDigestV0, NodeIdentityV0, OperationBindingV0,
    RecoveryDispositionV0,
};
use trnm_state_sync_v0::{
    Digest32V0 as SyncDigestV0, InstallReceiptV0, NonDestructiveInstallTargetV0,
    SnapshotManifestV0, StagingIdentityV0,
};

pub const DURABLE_FILE_ADAPTER_VERSION_V0: u16 = 0;
const AUTHORITY_MAGIC_V0: &[u8; 8] = b"TRNMAU00";
const AUTHORITY_RECORD_BYTES_V0: usize = 289;
const POINTER_MAGIC_V0: &[u8; 8] = b"TRNMSP00";
const POINTER_BYTES_V0: usize = 120;

#[derive(Debug)]
pub enum DurableFileErrorV0 {
    Io(io::Error),
    LockBusy(PathBuf),
    Poisoned,
    CorruptAuthorityJournal(&'static str),
    InvalidAuthorityCommand(BoundaryErrorV0),
    ActiveStagingExists,
    UnknownStaging,
    StagingIdentityMismatch,
    InvalidSnapshotManifest,
    ChunkOutOfBounds,
    ChunkSubstitution,
    IncompleteSnapshot,
    SnapshotByteCountMismatch,
    CurrentRootCasMismatch,
    RecoveryRequired(PathBuf),
    CorruptCurrentPointer(&'static str),
    SequenceOverflow,
}

impl fmt::Display for DurableFileErrorV0 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "durable file I/O failed: {error}"),
            Self::LockBusy(path) => write!(f, "durable adapter lock is busy: {}", path.display()),
            Self::Poisoned => f.write_str("durable adapter is poisoned after an uncertain write"),
            Self::CorruptAuthorityJournal(reason) => {
                write!(f, "authority journal is corrupt: {reason}")
            }
            Self::InvalidAuthorityCommand(error) => {
                write!(f, "authority command rejected: {error}")
            }
            Self::ActiveStagingExists => {
                f.write_str("a snapshot staging generation is already active")
            }
            Self::UnknownStaging => f.write_str("snapshot staging generation is unknown"),
            Self::StagingIdentityMismatch => f.write_str("snapshot staging identity mismatch"),
            Self::InvalidSnapshotManifest => {
                f.write_str("invalid snapshot manifest for file target")
            }
            Self::ChunkOutOfBounds => f.write_str("snapshot chunk is outside declared bounds"),
            Self::ChunkSubstitution => {
                f.write_str("snapshot chunk index was supplied with different bytes")
            }
            Self::IncompleteSnapshot => f.write_str("snapshot staging generation is incomplete"),
            Self::SnapshotByteCountMismatch => {
                f.write_str("snapshot staged byte count differs from manifest")
            }
            Self::CurrentRootCasMismatch => {
                f.write_str("current state root changed before snapshot install")
            }
            Self::RecoveryRequired(path) => {
                write!(
                    f,
                    "orphaned durable state requires explicit recovery: {}",
                    path.display()
                )
            }
            Self::CorruptCurrentPointer(reason) => {
                write!(f, "snapshot current pointer is corrupt: {reason}")
            }
            Self::SequenceOverflow => f.write_str("durable generation or sequence overflow"),
        }
    }
}

impl Error for DurableFileErrorV0 {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::InvalidAuthorityCommand(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for DurableFileErrorV0 {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

fn acquire_exclusive_lock(path: &Path) -> Result<File, DurableFileErrorV0> {
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(path)?;
    match file.try_lock_exclusive() {
        Ok(()) => Ok(file),
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
            Err(DurableFileErrorV0::LockBusy(path.to_path_buf()))
        }
        Err(error) => Err(DurableFileErrorV0::Io(error)),
    }
}

fn sync_directory(path: &Path) -> io::Result<()> {
    File::open(path)?.sync_all()
}

fn take_array<const N: usize>(
    bytes: &[u8],
    offset: &mut usize,
    reason: &'static str,
) -> Result<[u8; N], DurableFileErrorV0> {
    let end = offset
        .checked_add(N)
        .ok_or(DurableFileErrorV0::CorruptAuthorityJournal(reason))?;
    let slice = bytes
        .get(*offset..end)
        .ok_or(DurableFileErrorV0::CorruptAuthorityJournal(reason))?;
    *offset = end;
    slice
        .try_into()
        .map_err(|_| DurableFileErrorV0::CorruptAuthorityJournal(reason))
}

fn node_stage_from_byte(value: u8) -> Result<AuthorityStageV0, DurableFileErrorV0> {
    match value {
        0 => Ok(AuthorityStageV0::Prepared),
        1 => Ok(AuthorityStageV0::ApplicationSealed),
        2 => Ok(AuthorityStageV0::SafetyPersisted),
        3 => Ok(AuthorityStageV0::SignIntentPersisted),
        4 => Ok(AuthorityStageV0::SignatureConfirmed),
        5 => Ok(AuthorityStageV0::FinalityApplied),
        6 => Ok(AuthorityStageV0::CheckpointConfirmed),
        7 => Ok(AuthorityStageV0::OutboundPublished),
        _ => Err(DurableFileErrorV0::CorruptAuthorityJournal(
            "unknown authority stage",
        )),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AuthorityRecordV0 {
    identity_digest: NodeDigestV0,
    binding: OperationBindingV0,
    stage: AuthorityStageV0,
    sequence: u64,
    facts_digest: NodeDigestV0,
    previous_record_digest: NodeDigestV0,
    record_digest: NodeDigestV0,
}

impl AuthorityRecordV0 {
    fn canonical_digest(
        identity_digest: NodeDigestV0,
        binding: OperationBindingV0,
        stage: AuthorityStageV0,
        sequence: u64,
        facts_digest: NodeDigestV0,
        previous_record_digest: NodeDigestV0,
    ) -> NodeDigestV0 {
        NodeDigestV0::hash(
            b"trnm.file-authority-record.v0",
            &[
                &identity_digest.0,
                &binding.operation_id.0,
                &binding.height.to_be_bytes(),
                &binding.view.to_be_bytes(),
                &binding.block_id.0,
                &binding.parent_id.0,
                &binding.proposal_digest.0,
                &[stage as u8],
                &sequence.to_be_bytes(),
                &facts_digest.0,
                &previous_record_digest.0,
            ],
        )
    }

    fn new(
        identity: NodeIdentityV0,
        binding: OperationBindingV0,
        stage: AuthorityStageV0,
        sequence: u64,
        facts_digest: NodeDigestV0,
        previous_record_digest: NodeDigestV0,
    ) -> Self {
        let identity_digest = identity.digest();
        let record_digest = Self::canonical_digest(
            identity_digest,
            binding,
            stage,
            sequence,
            facts_digest,
            previous_record_digest,
        );
        Self {
            identity_digest,
            binding,
            stage,
            sequence,
            facts_digest,
            previous_record_digest,
            record_digest,
        }
    }

    fn encode(self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(AUTHORITY_RECORD_BYTES_V0);
        bytes.extend_from_slice(AUTHORITY_MAGIC_V0);
        bytes.extend_from_slice(&self.identity_digest.0);
        bytes.extend_from_slice(&self.binding.operation_id.0);
        bytes.extend_from_slice(&self.binding.height.to_be_bytes());
        bytes.extend_from_slice(&self.binding.view.to_be_bytes());
        bytes.extend_from_slice(&self.binding.block_id.0);
        bytes.extend_from_slice(&self.binding.parent_id.0);
        bytes.extend_from_slice(&self.binding.proposal_digest.0);
        bytes.push(self.stage as u8);
        bytes.extend_from_slice(&self.sequence.to_be_bytes());
        bytes.extend_from_slice(&self.facts_digest.0);
        bytes.extend_from_slice(&self.previous_record_digest.0);
        bytes.extend_from_slice(&self.record_digest.0);
        debug_assert_eq!(bytes.len(), AUTHORITY_RECORD_BYTES_V0);
        bytes
    }

    fn decode(bytes: &[u8]) -> Result<Self, DurableFileErrorV0> {
        if bytes.len() != AUTHORITY_RECORD_BYTES_V0 {
            return Err(DurableFileErrorV0::CorruptAuthorityJournal(
                "record length mismatch",
            ));
        }
        let mut offset = 0;
        let magic = take_array::<8>(bytes, &mut offset, "missing authority magic")?;
        if &magic != AUTHORITY_MAGIC_V0 {
            return Err(DurableFileErrorV0::CorruptAuthorityJournal(
                "authority magic mismatch",
            ));
        }
        let identity_digest = NodeDigestV0(take_array::<32>(
            bytes,
            &mut offset,
            "missing identity digest",
        )?);
        let operation_id = NodeDigestV0(take_array::<32>(
            bytes,
            &mut offset,
            "missing operation id",
        )?);
        let height = u64::from_be_bytes(take_array::<8>(bytes, &mut offset, "missing height")?);
        let view = u64::from_be_bytes(take_array::<8>(bytes, &mut offset, "missing view")?);
        let block_id = NodeDigestV0(take_array::<32>(bytes, &mut offset, "missing block id")?);
        let parent_id = NodeDigestV0(take_array::<32>(bytes, &mut offset, "missing parent id")?);
        let proposal_digest = NodeDigestV0(take_array::<32>(
            bytes,
            &mut offset,
            "missing proposal digest",
        )?);
        let stage = node_stage_from_byte(*bytes.get(offset).ok_or(
            DurableFileErrorV0::CorruptAuthorityJournal("missing authority stage"),
        )?)?;
        offset += 1;
        let sequence = u64::from_be_bytes(take_array::<8>(
            bytes,
            &mut offset,
            "missing authority sequence",
        )?);
        let facts_digest = NodeDigestV0(take_array::<32>(
            bytes,
            &mut offset,
            "missing facts digest",
        )?);
        let previous_record_digest = NodeDigestV0(take_array::<32>(
            bytes,
            &mut offset,
            "missing previous record digest",
        )?);
        let record_digest = NodeDigestV0(take_array::<32>(
            bytes,
            &mut offset,
            "missing record digest",
        )?);
        if offset != bytes.len() {
            return Err(DurableFileErrorV0::CorruptAuthorityJournal(
                "authority record has trailing bytes",
            ));
        }
        Ok(Self {
            identity_digest,
            binding: OperationBindingV0 {
                operation_id,
                height,
                view,
                block_id,
                parent_id,
                proposal_digest,
            },
            stage,
            sequence,
            facts_digest,
            previous_record_digest,
            record_digest,
        })
    }

    fn receipt(self) -> AuthorityReceiptV0 {
        AuthorityReceiptV0 {
            binding: self.binding,
            durable_stage: self.stage,
            durable_sequence: self.sequence,
            facts_digest: self.facts_digest,
            record_digest: self.record_digest,
        }
    }
}

fn validate_authority_chain(
    identity: NodeIdentityV0,
    bytes: &[u8],
) -> Result<Option<AuthorityRecordV0>, DurableFileErrorV0> {
    if !bytes.len().is_multiple_of(AUTHORITY_RECORD_BYTES_V0) {
        return Err(DurableFileErrorV0::CorruptAuthorityJournal(
            "truncated authority record",
        ));
    }
    let expected_identity = identity.digest();
    let mut previous: Option<AuthorityRecordV0> = None;
    for encoded in bytes.chunks_exact(AUTHORITY_RECORD_BYTES_V0) {
        let record = AuthorityRecordV0::decode(encoded)?;
        if record.identity_digest != expected_identity {
            return Err(DurableFileErrorV0::CorruptAuthorityJournal(
                "node identity changed within journal",
            ));
        }
        let rebound = OperationBindingV0::derive(
            identity,
            record.binding.height,
            record.binding.view,
            record.binding.block_id,
            record.binding.parent_id,
            record.binding.proposal_digest,
        );
        if rebound.operation_id != record.binding.operation_id {
            return Err(DurableFileErrorV0::CorruptAuthorityJournal(
                "operation binding digest mismatch",
            ));
        }
        let expected_record_digest = AuthorityRecordV0::canonical_digest(
            record.identity_digest,
            record.binding,
            record.stage,
            record.sequence,
            record.facts_digest,
            record.previous_record_digest,
        );
        if expected_record_digest != record.record_digest {
            return Err(DurableFileErrorV0::CorruptAuthorityJournal(
                "record digest mismatch",
            ));
        }
        match previous {
            None => {
                if record.sequence != 0
                    || record.stage != AuthorityStageV0::Prepared
                    || record.previous_record_digest != NodeDigestV0([0; 32])
                {
                    return Err(DurableFileErrorV0::CorruptAuthorityJournal(
                        "invalid first authority record",
                    ));
                }
            }
            Some(prior) => {
                let expected_sequence = prior
                    .sequence
                    .checked_add(1)
                    .ok_or(DurableFileErrorV0::SequenceOverflow)?;
                if record.sequence != expected_sequence
                    || record.previous_record_digest != prior.record_digest
                {
                    return Err(DurableFileErrorV0::CorruptAuthorityJournal(
                        "authority sequence or hash-chain discontinuity",
                    ));
                }
                if record.binding.operation_id == prior.binding.operation_id {
                    if prior.stage.successor() != Some(record.stage)
                        || record.binding != prior.binding
                    {
                        return Err(DurableFileErrorV0::CorruptAuthorityJournal(
                            "invalid in-operation authority transition",
                        ));
                    }
                } else {
                    let expected_height = prior
                        .binding
                        .height
                        .checked_add(1)
                        .ok_or(DurableFileErrorV0::SequenceOverflow)?;
                    if prior.stage != AuthorityStageV0::OutboundPublished
                        || record.stage != AuthorityStageV0::Prepared
                        || record.binding.height != expected_height
                        || record.binding.parent_id != prior.binding.block_id
                    {
                        return Err(DurableFileErrorV0::CorruptAuthorityJournal(
                            "invalid next-height authority transition",
                        ));
                    }
                }
            }
        }
        previous = Some(record);
    }
    Ok(previous)
}

pub struct FileAuthorityCoordinatorV0 {
    identity: NodeIdentityV0,
    _lock_file: File,
    journal: File,
    current: Option<AuthorityRecordV0>,
    poisoned: bool,
}

impl FileAuthorityCoordinatorV0 {
    pub fn open(
        directory: impl AsRef<Path>,
        identity: NodeIdentityV0,
    ) -> Result<Self, DurableFileErrorV0> {
        let directory = directory.as_ref();
        fs::create_dir_all(directory)?;
        let lock_path = directory.join("authority.lock.v0");
        let lock_file = acquire_exclusive_lock(&lock_path)?;
        let journal_path = directory.join("authority.journal.v0");
        let mut journal = OpenOptions::new()
            .create(true)
            .read(true)
            .append(true)
            .open(&journal_path)?;
        journal.seek(SeekFrom::Start(0))?;
        let mut bytes = Vec::new();
        journal.read_to_end(&mut bytes)?;
        let current = validate_authority_chain(identity, &bytes)?;
        journal.seek(SeekFrom::End(0))?;
        Ok(Self {
            identity,
            _lock_file: lock_file,
            journal,
            current,
            poisoned: false,
        })
    }

    #[must_use]
    pub fn current_receipt(&self) -> Option<AuthorityReceiptV0> {
        self.current.map(AuthorityRecordV0::receipt)
    }

    fn append_record(
        &mut self,
        record: AuthorityRecordV0,
    ) -> Result<AuthorityReceiptV0, DurableFileErrorV0> {
        if self.poisoned {
            return Err(DurableFileErrorV0::Poisoned);
        }
        let encoded = record.encode();
        let persisted = self
            .journal
            .write_all(&encoded)
            .and_then(|()| self.journal.sync_data());
        if let Err(error) = persisted {
            self.poisoned = true;
            return Err(DurableFileErrorV0::Io(error));
        }
        self.current = Some(record);
        Ok(record.receipt())
    }

    fn next_sequence_and_previous(&self) -> Result<(u64, NodeDigestV0), DurableFileErrorV0> {
        match self.current {
            None => Ok((0, NodeDigestV0([0; 32]))),
            Some(current) => Ok((
                current
                    .sequence
                    .checked_add(1)
                    .ok_or(DurableFileErrorV0::SequenceOverflow)?,
                current.record_digest,
            )),
        }
    }
}

impl AuthorityCoordinatorV0 for FileAuthorityCoordinatorV0 {
    type Error = DurableFileErrorV0;

    fn identity(&self) -> NodeIdentityV0 {
        self.identity
    }

    fn recover(&mut self) -> Result<RecoveryDispositionV0, Self::Error> {
        if self.poisoned {
            return Err(DurableFileErrorV0::Poisoned);
        }
        Ok(match self.current {
            None => RecoveryDispositionV0::Clean,
            Some(record) => RecoveryDispositionV0::Resume {
                binding: record.binding,
                durable_stage: record.stage,
                durable_sequence: record.sequence,
            },
        })
    }

    fn apply(&mut self, command: AuthorityCommandV0) -> Result<AuthorityReceiptV0, Self::Error> {
        if self.poisoned {
            return Err(DurableFileErrorV0::Poisoned);
        }
        let (binding, stage, facts_digest) = match command {
            AuthorityCommandV0::Begin {
                binding,
                ingress_digest,
            } => {
                if let Some(current) = self.current {
                    if current.binding == binding && current.stage == AuthorityStageV0::Prepared {
                        return if current.facts_digest == ingress_digest {
                            Ok(current.receipt())
                        } else {
                            Err(DurableFileErrorV0::InvalidAuthorityCommand(
                                BoundaryErrorV0::ReceiptSubstitution,
                            ))
                        };
                    }
                    let expected_height = current
                        .binding
                        .height
                        .checked_add(1)
                        .ok_or(DurableFileErrorV0::SequenceOverflow)?;
                    if current.stage != AuthorityStageV0::OutboundPublished
                        || binding.height != expected_height
                        || binding.parent_id != current.binding.block_id
                        || binding.operation_id == current.binding.operation_id
                    {
                        return Err(DurableFileErrorV0::InvalidAuthorityCommand(
                            BoundaryErrorV0::InvalidStageTransition,
                        ));
                    }
                }
                (binding, AuthorityStageV0::Prepared, ingress_digest)
            }
            AuthorityCommandV0::Advance {
                binding,
                expected_stage,
                next_stage,
                facts_digest,
            } => {
                let current = self
                    .current
                    .ok_or(DurableFileErrorV0::InvalidAuthorityCommand(
                        BoundaryErrorV0::InvalidStageTransition,
                    ))?;
                if current.binding != binding {
                    return Err(DurableFileErrorV0::InvalidAuthorityCommand(
                        BoundaryErrorV0::OperationBindingMismatch,
                    ));
                }
                if current.stage == next_stage && expected_stage.successor() == Some(next_stage) {
                    return if current.facts_digest == facts_digest {
                        Ok(current.receipt())
                    } else {
                        Err(DurableFileErrorV0::InvalidAuthorityCommand(
                            BoundaryErrorV0::ReceiptSubstitution,
                        ))
                    };
                }
                if current.stage != expected_stage || expected_stage.successor() != Some(next_stage)
                {
                    return Err(DurableFileErrorV0::InvalidAuthorityCommand(
                        BoundaryErrorV0::InvalidStageTransition,
                    ));
                }
                (binding, next_stage, facts_digest)
            }
        };
        let (sequence, previous) = self.next_sequence_and_previous()?;
        let record = AuthorityRecordV0::new(
            self.identity,
            binding,
            stage,
            sequence,
            facts_digest,
            previous,
        );
        self.append_record(record)
    }
}

impl Drop for FileAuthorityCoordinatorV0 {
    fn drop(&mut self) {
        let _ = FileExt::unlock(&self._lock_file);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CurrentPointerV0 {
    generation: u64,
    height: u64,
    state_root: SyncDigestV0,
    manifest_digest: SyncDigestV0,
    checksum: SyncDigestV0,
}

impl CurrentPointerV0 {
    fn checksum(
        generation: u64,
        height: u64,
        state_root: SyncDigestV0,
        manifest_digest: SyncDigestV0,
    ) -> SyncDigestV0 {
        SyncDigestV0::hash(
            b"trnm.snapshot-current-pointer.v0",
            &[
                &generation.to_be_bytes(),
                &height.to_be_bytes(),
                &state_root.0,
                &manifest_digest.0,
            ],
        )
    }

    fn new(
        generation: u64,
        height: u64,
        state_root: SyncDigestV0,
        manifest_digest: SyncDigestV0,
    ) -> Self {
        Self {
            generation,
            height,
            state_root,
            manifest_digest,
            checksum: Self::checksum(generation, height, state_root, manifest_digest),
        }
    }

    fn encode(self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(POINTER_BYTES_V0);
        bytes.extend_from_slice(POINTER_MAGIC_V0);
        bytes.extend_from_slice(&self.generation.to_be_bytes());
        bytes.extend_from_slice(&self.height.to_be_bytes());
        bytes.extend_from_slice(&self.state_root.0);
        bytes.extend_from_slice(&self.manifest_digest.0);
        bytes.extend_from_slice(&self.checksum.0);
        debug_assert_eq!(bytes.len(), POINTER_BYTES_V0);
        bytes
    }

    fn decode(bytes: &[u8]) -> Result<Self, DurableFileErrorV0> {
        if bytes.len() != POINTER_BYTES_V0 {
            return Err(DurableFileErrorV0::CorruptCurrentPointer(
                "pointer length mismatch",
            ));
        }
        if bytes.get(0..8) != Some(POINTER_MAGIC_V0.as_slice()) {
            return Err(DurableFileErrorV0::CorruptCurrentPointer(
                "pointer magic mismatch",
            ));
        }
        let generation = u64::from_be_bytes(
            bytes[8..16]
                .try_into()
                .map_err(|_| DurableFileErrorV0::CorruptCurrentPointer("generation"))?,
        );
        let height = u64::from_be_bytes(
            bytes[16..24]
                .try_into()
                .map_err(|_| DurableFileErrorV0::CorruptCurrentPointer("height"))?,
        );
        let state_root = SyncDigestV0(
            bytes[24..56]
                .try_into()
                .map_err(|_| DurableFileErrorV0::CorruptCurrentPointer("state root"))?,
        );
        let manifest_digest = SyncDigestV0(
            bytes[56..88]
                .try_into()
                .map_err(|_| DurableFileErrorV0::CorruptCurrentPointer("manifest digest"))?,
        );
        let checksum = SyncDigestV0(
            bytes[88..120]
                .try_into()
                .map_err(|_| DurableFileErrorV0::CorruptCurrentPointer("checksum"))?,
        );
        if generation == 0
            || height == 0
            || state_root == SyncDigestV0([0; 32])
            || checksum != Self::checksum(generation, height, state_root, manifest_digest)
        {
            return Err(DurableFileErrorV0::CorruptCurrentPointer(
                "pointer fields or checksum invalid",
            ));
        }
        Ok(Self {
            generation,
            height,
            state_root,
            manifest_digest,
            checksum,
        })
    }
}

#[derive(Clone, Debug)]
struct ActiveStagingV0 {
    identity: StagingIdentityV0,
    path: PathBuf,
    chunk_count: u32,
    maximum_chunk_bytes: u32,
    total_bytes: u64,
    manifest_digest: SyncDigestV0,
    state_root: SyncDigestV0,
    height: u64,
}

pub struct AtomicSnapshotFileTargetV0 {
    root: PathBuf,
    _lock_file: File,
    current: CurrentPointerV0,
    active: Option<ActiveStagingV0>,
    post_commit_directory_sync_degraded: bool,
}

impl AtomicSnapshotFileTargetV0 {
    pub fn open_or_initialize(
        root: impl AsRef<Path>,
        initial_state_root: SyncDigestV0,
        initial_height: u64,
        initial_generation: u64,
    ) -> Result<Self, DurableFileErrorV0> {
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(&root)?;
        fs::create_dir_all(root.join("staging"))?;
        fs::create_dir_all(root.join("generations"))?;
        let lock_file = acquire_exclusive_lock(&root.join("snapshot.lock.v0"))?;
        let pointer_path = root.join("CURRENT.v0");
        let current = if pointer_path.exists() {
            let bytes = fs::read(&pointer_path)?;
            CurrentPointerV0::decode(&bytes)?
        } else {
            if initial_state_root == SyncDigestV0([0; 32])
                || initial_height == 0
                || initial_generation == 0
            {
                return Err(DurableFileErrorV0::InvalidSnapshotManifest);
            }
            let pointer = CurrentPointerV0::new(
                initial_generation,
                initial_height,
                initial_state_root,
                SyncDigestV0([0; 32]),
            );
            let temporary = root.join(format!(".CURRENT.v0.init-{initial_generation}"));
            let mut file = OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&temporary)?;
            file.write_all(&pointer.encode())?;
            file.sync_all()?;
            fs::rename(&temporary, &pointer_path)?;
            sync_directory(&root)?;
            pointer
        };
        Ok(Self {
            root,
            _lock_file: lock_file,
            current,
            active: None,
            post_commit_directory_sync_degraded: false,
        })
    }

    #[must_use]
    pub fn current_state_root(&self) -> SyncDigestV0 {
        self.current.state_root
    }

    #[must_use]
    pub fn current_height(&self) -> u64 {
        self.current.height
    }

    #[must_use]
    pub fn current_generation(&self) -> u64 {
        self.current.generation
    }

    #[must_use]
    pub fn post_commit_directory_sync_degraded(&self) -> bool {
        self.post_commit_directory_sync_degraded
    }

    pub fn recover_unreferenced_generations(&mut self) -> Result<(), DurableFileErrorV0> {
        if self.active.is_some() {
            return Err(DurableFileErrorV0::ActiveStagingExists);
        }
        let staging_root = self.root.join("staging");
        for entry in fs::read_dir(&staging_root)? {
            let path = entry?.path();
            if path.is_dir() {
                fs::remove_dir_all(path)?;
            } else {
                fs::remove_file(path)?;
            }
        }
        let generations_root = self.root.join("generations");
        for entry in fs::read_dir(&generations_root)? {
            let path = entry?.path();
            let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
                return Err(DurableFileErrorV0::RecoveryRequired(path));
            };
            let Some(raw_generation) = name.strip_prefix("generation-") else {
                return Err(DurableFileErrorV0::RecoveryRequired(path));
            };
            let generation = raw_generation
                .parse::<u64>()
                .map_err(|_| DurableFileErrorV0::RecoveryRequired(path.clone()))?;
            if generation > self.current.generation {
                fs::remove_dir_all(path)?;
            }
        }
        sync_directory(&staging_root)?;
        sync_directory(&generations_root)?;
        Ok(())
    }

    fn generation_path(&self, generation: u64) -> PathBuf {
        self.root
            .join("generations")
            .join(format!("generation-{generation}"))
    }

    fn staging_matches(
        active: &ActiveStagingV0,
        identity: StagingIdentityV0,
    ) -> Result<(), DurableFileErrorV0> {
        if active.identity != identity {
            return Err(DurableFileErrorV0::StagingIdentityMismatch);
        }
        Ok(())
    }

    fn write_manifest_record(
        directory: &Path,
        manifest: &SnapshotManifestV0,
    ) -> Result<(), DurableFileErrorV0> {
        let path = directory.join("MANIFEST.v0");
        let mut bytes = Vec::with_capacity(128);
        bytes.extend_from_slice(b"TRNMSM00");
        bytes.extend_from_slice(&manifest.manifest_digest.0);
        bytes.extend_from_slice(&manifest.state_root.0);
        bytes.extend_from_slice(&manifest.height.to_be_bytes());
        bytes.extend_from_slice(&manifest.chunk_count.to_be_bytes());
        bytes.extend_from_slice(&manifest.total_bytes.to_be_bytes());
        let checksum = SyncDigestV0::hash(b"trnm.snapshot-staging-manifest.v0", &[&bytes]);
        bytes.extend_from_slice(&checksum.0);
        let mut file = OpenOptions::new().create_new(true).write(true).open(path)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        sync_directory(directory)?;
        Ok(())
    }
}

impl NonDestructiveInstallTargetV0 for AtomicSnapshotFileTargetV0 {
    type Error = DurableFileErrorV0;

    fn begin_staging(
        &mut self,
        manifest: &SnapshotManifestV0,
    ) -> Result<StagingIdentityV0, Self::Error> {
        if self.active.is_some() {
            return Err(DurableFileErrorV0::ActiveStagingExists);
        }
        if manifest.manifest_digest == SyncDigestV0([0; 32])
            || manifest.state_root == SyncDigestV0([0; 32])
            || manifest.height <= self.current.height
            || manifest.chunk_count == 0
            || manifest.maximum_chunk_bytes == 0
            || manifest.total_bytes == 0
        {
            return Err(DurableFileErrorV0::InvalidSnapshotManifest);
        }
        let generation = self
            .current
            .generation
            .checked_add(1)
            .ok_or(DurableFileErrorV0::SequenceOverflow)?;
        let staging_digest = SyncDigestV0::hash(
            b"trnm.snapshot-staging-identity.v0",
            &[&manifest.manifest_digest.0, &generation.to_be_bytes()],
        );
        let identity = StagingIdentityV0 {
            generation,
            staging_digest,
        };
        let path = self
            .root
            .join("staging")
            .join(format!("generation-{generation}"));
        let generation_path = self.generation_path(generation);
        if path.exists() || generation_path.exists() {
            return Err(DurableFileErrorV0::RecoveryRequired(if path.exists() {
                path
            } else {
                generation_path
            }));
        }
        fs::create_dir(&path)?;
        Self::write_manifest_record(&path, manifest)?;
        self.active = Some(ActiveStagingV0 {
            identity,
            path,
            chunk_count: manifest.chunk_count,
            maximum_chunk_bytes: manifest.maximum_chunk_bytes,
            total_bytes: manifest.total_bytes,
            manifest_digest: manifest.manifest_digest,
            state_root: manifest.state_root,
            height: manifest.height,
        });
        Ok(identity)
    }

    fn write_chunk(
        &mut self,
        staging: StagingIdentityV0,
        index: u32,
        bytes: &[u8],
    ) -> Result<(), Self::Error> {
        let active = self
            .active
            .as_ref()
            .ok_or(DurableFileErrorV0::UnknownStaging)?;
        Self::staging_matches(active, staging)?;
        if index >= active.chunk_count
            || bytes.is_empty()
            || bytes.len() > active.maximum_chunk_bytes as usize
        {
            return Err(DurableFileErrorV0::ChunkOutOfBounds);
        }
        let destination = active.path.join(format!("chunk-{index:08}.bin"));
        if destination.exists() {
            return if fs::read(&destination)? == bytes {
                Ok(())
            } else {
                Err(DurableFileErrorV0::ChunkSubstitution)
            };
        }
        let temporary = active.path.join(format!(".chunk-{index:08}.tmp"));
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&temporary, &destination)?;
        sync_directory(&active.path)?;
        Ok(())
    }

    fn commit_staging_cas(
        &mut self,
        staging: StagingIdentityV0,
        expected_current_root: SyncDigestV0,
        manifest: &SnapshotManifestV0,
    ) -> Result<InstallReceiptV0, Self::Error> {
        let active = self
            .active
            .as_ref()
            .ok_or(DurableFileErrorV0::UnknownStaging)?
            .clone();
        Self::staging_matches(&active, staging)?;
        if self.current.state_root != expected_current_root {
            return Err(DurableFileErrorV0::CurrentRootCasMismatch);
        }
        if active.manifest_digest != manifest.manifest_digest
            || active.state_root != manifest.state_root
            || active.height != manifest.height
            || active.chunk_count != manifest.chunk_count
            || active.total_bytes != manifest.total_bytes
        {
            return Err(DurableFileErrorV0::InvalidSnapshotManifest);
        }

        // Fail closed on every staging namespace entry before the pointer
        // linearization point. Only the exact manifest plus the canonical,
        // contiguous chunk names declared by this staging owner are admissible.
        let mut manifest_seen = false;
        let mut chunk_entries = 0_u32;
        for entry in fs::read_dir(&active.path)? {
            let entry = entry?;
            let path = entry.path();
            if !entry.file_type()?.is_file() {
                return Err(DurableFileErrorV0::RecoveryRequired(path));
            }
            let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
                return Err(DurableFileErrorV0::RecoveryRequired(path));
            };
            if name == "MANIFEST.v0" {
                manifest_seen = true;
                continue;
            }
            let Some(raw_index) = name
                .strip_prefix("chunk-")
                .and_then(|name| name.strip_suffix(".bin"))
            else {
                return Err(DurableFileErrorV0::RecoveryRequired(path));
            };
            if raw_index.len() != 8 {
                return Err(DurableFileErrorV0::RecoveryRequired(path));
            }
            let index = raw_index
                .parse::<u32>()
                .map_err(|_| DurableFileErrorV0::RecoveryRequired(path.clone()))?;
            if index >= active.chunk_count || format!("{index:08}") != raw_index {
                return Err(DurableFileErrorV0::RecoveryRequired(path));
            }
            chunk_entries = chunk_entries
                .checked_add(1)
                .ok_or(DurableFileErrorV0::SequenceOverflow)?;
        }
        if !manifest_seen || chunk_entries != active.chunk_count {
            return Err(DurableFileErrorV0::RecoveryRequired(active.path.clone()));
        }

        let mut total_bytes = 0_u64;
        for index in 0..active.chunk_count {
            let path = active.path.join(format!("chunk-{index:08}.bin"));
            let metadata = fs::metadata(path).map_err(|error| {
                if error.kind() == io::ErrorKind::NotFound {
                    DurableFileErrorV0::IncompleteSnapshot
                } else {
                    DurableFileErrorV0::Io(error)
                }
            })?;
            total_bytes = total_bytes
                .checked_add(metadata.len())
                .ok_or(DurableFileErrorV0::SequenceOverflow)?;
        }
        if total_bytes != active.total_bytes {
            return Err(DurableFileErrorV0::SnapshotByteCountMismatch);
        }
        sync_directory(&active.path)?;
        let generation_path = self.generation_path(active.identity.generation);
        if generation_path.exists() {
            return Err(DurableFileErrorV0::RecoveryRequired(generation_path));
        }
        fs::rename(&active.path, &generation_path)?;
        sync_directory(&self.root.join("generations"))?;

        let next = CurrentPointerV0::new(
            active.identity.generation,
            active.height,
            active.state_root,
            active.manifest_digest,
        );
        let temporary_pointer = self.root.join(format!(
            ".CURRENT.v0.generation-{}",
            active.identity.generation
        ));
        let mut pointer_file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary_pointer)?;
        pointer_file.write_all(&next.encode())?;
        pointer_file.sync_all()?;
        fs::rename(&temporary_pointer, self.root.join("CURRENT.v0"))?;

        // The pointer rename is the linearization point. No error is returned
        // after it, because the caller must never destructively abort a
        // generation that may already be serving. A directory-sync failure is
        // retained as a degraded health signal for operator quarantine and
        // external power-loss qualification.
        if sync_directory(&self.root).is_err() {
            self.post_commit_directory_sync_degraded = true;
        }
        let previous_root = self.current.state_root;
        self.current = next;
        self.active = None;
        let durable_receipt_digest = SyncDigestV0::hash(
            b"trnm.snapshot-install-receipt.v0",
            &[
                &previous_root.0,
                &next.state_root.0,
                &next.height.to_be_bytes(),
                &next.generation.to_be_bytes(),
                &next.manifest_digest.0,
            ],
        );
        Ok(InstallReceiptV0 {
            previous_root,
            installed_root: next.state_root,
            installed_height: next.height,
            generation: next.generation,
            durable_receipt_digest,
        })
    }

    fn abort_staging(&mut self, staging: StagingIdentityV0) -> Result<(), Self::Error> {
        // Authenticate the caller against a retained owner snapshot before
        // mutating or consuming the live staging handle.
        let active = self
            .active
            .as_ref()
            .ok_or(DurableFileErrorV0::UnknownStaging)?
            .clone();
        Self::staging_matches(&active, staging)?;
        if active.identity.generation == self.current.generation {
            return Err(DurableFileErrorV0::StagingIdentityMismatch);
        }
        if active.path.exists() {
            fs::remove_dir_all(&active.path)?;
        }
        let generation_path = self.generation_path(active.identity.generation);
        if generation_path.exists() {
            fs::remove_dir_all(generation_path)?;
        }
        sync_directory(&self.root.join("staging"))?;
        sync_directory(&self.root.join("generations"))?;
        self.active = None;
        Ok(())
    }
}

impl Drop for AtomicSnapshotFileTargetV0 {
    fn drop(&mut self) {
        let _ = FileExt::unlock(&self._lock_file);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        sync::atomic::{AtomicU64, Ordering},
        time::{SystemTime, UNIX_EPOCH},
    };

    static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new(label: &str) -> Self {
            let timestamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let counter = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "trnm-{label}-{}-{timestamp}-{counter}",
                std::process::id()
            ));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn node_digest(byte: u8) -> NodeDigestV0 {
        NodeDigestV0([byte; 32])
    }

    fn node_identity() -> NodeIdentityV0 {
        NodeIdentityV0 {
            chain_id: node_digest(1),
            validator_id: node_digest(2),
            application_id: node_digest(3),
            generation: 1,
        }
    }

    fn binding(height: u64, block_id: NodeDigestV0, parent_id: NodeDigestV0) -> OperationBindingV0 {
        OperationBindingV0::derive(
            node_identity(),
            height,
            0,
            block_id,
            parent_id,
            node_digest(height as u8),
        )
    }

    #[test]
    fn authority_journal_recovers_exact_facts_and_next_height() {
        let directory = TestDirectory::new("authority-recovery");
        let first = binding(10, node_digest(10), node_digest(9));
        {
            let mut coordinator =
                FileAuthorityCoordinatorV0::open(&directory.0, node_identity()).unwrap();
            let prepared = coordinator
                .apply(AuthorityCommandV0::Begin {
                    binding: first,
                    ingress_digest: node_digest(20),
                })
                .unwrap();
            assert_eq!(prepared.durable_sequence, 0);
            assert_eq!(prepared.facts_digest, node_digest(20));
            assert_eq!(
                coordinator
                    .apply(AuthorityCommandV0::Begin {
                        binding: first,
                        ingress_digest: node_digest(21),
                    })
                    .unwrap_err()
                    .to_string(),
                DurableFileErrorV0::InvalidAuthorityCommand(BoundaryErrorV0::ReceiptSubstitution)
                    .to_string()
            );
            let mut stage = AuthorityStageV0::Prepared;
            while let Some(next) = stage.successor() {
                coordinator
                    .apply(AuthorityCommandV0::Advance {
                        binding: first,
                        expected_stage: stage,
                        next_stage: next,
                        facts_digest: node_digest(30 + next as u8),
                    })
                    .unwrap();
                stage = next;
            }
        }
        let mut restarted =
            FileAuthorityCoordinatorV0::open(&directory.0, node_identity()).unwrap();
        assert!(matches!(
            restarted.recover().unwrap(),
            RecoveryDispositionV0::Resume {
                durable_stage: AuthorityStageV0::OutboundPublished,
                durable_sequence: 7,
                ..
            }
        ));
        let second = binding(11, node_digest(11), first.block_id);
        let receipt = restarted
            .apply(AuthorityCommandV0::Begin {
                binding: second,
                ingress_digest: node_digest(50),
            })
            .unwrap();
        assert_eq!(receipt.durable_sequence, 8);
        assert_eq!(receipt.binding, second);
    }

    #[test]
    fn truncated_authority_tail_is_never_silently_discarded() {
        let directory = TestDirectory::new("authority-truncated");
        {
            let mut coordinator =
                FileAuthorityCoordinatorV0::open(&directory.0, node_identity()).unwrap();
            coordinator
                .apply(AuthorityCommandV0::Begin {
                    binding: binding(1, node_digest(4), node_digest(3)),
                    ingress_digest: node_digest(5),
                })
                .unwrap();
        }
        let journal_path = directory.0.join("authority.journal.v0");
        let mut journal = OpenOptions::new().append(true).open(journal_path).unwrap();
        journal.write_all(&[0xff]).unwrap();
        journal.sync_data().unwrap();
        assert!(matches!(
            FileAuthorityCoordinatorV0::open(&directory.0, node_identity()),
            Err(DurableFileErrorV0::CorruptAuthorityJournal(
                "truncated authority record"
            ))
        ));
    }

    fn sync_digest(byte: u8) -> SyncDigestV0 {
        SyncDigestV0([byte; 32])
    }

    fn manifest(height: u64, state_root: SyncDigestV0, total_bytes: u64) -> SnapshotManifestV0 {
        let mut manifest = SnapshotManifestV0 {
            chain_id: sync_digest(1),
            protocol_digest: sync_digest(2),
            height,
            epoch: 1,
            state_root,
            chunk_root: sync_digest(3),
            chunk_count: 2,
            maximum_chunk_bytes: 1024,
            total_bytes,
            schema_digest: sync_digest(4),
            checkpoint_digest: sync_digest(5),
            manifest_digest: sync_digest(0),
        };
        manifest.manifest_digest = manifest.canonical_digest();
        manifest
    }

    #[test]
    fn snapshot_target_installs_generation_with_current_root_cas() {
        let directory = TestDirectory::new("snapshot-install");
        let initial_root = sync_digest(10);
        let installed_root = sync_digest(11);
        {
            let mut target =
                AtomicSnapshotFileTargetV0::open_or_initialize(&directory.0, initial_root, 1, 1)
                    .unwrap();
            let manifest = manifest(2, installed_root, 2);
            let staging = target.begin_staging(&manifest).unwrap();
            target.write_chunk(staging, 0, b"a").unwrap();
            target.write_chunk(staging, 1, b"b").unwrap();
            let receipt = target
                .commit_staging_cas(staging, initial_root, &manifest)
                .unwrap();
            assert_eq!(receipt.previous_root, initial_root);
            assert_eq!(receipt.installed_root, installed_root);
            assert_eq!(target.current_state_root(), installed_root);
            assert_eq!(target.current_generation(), 2);
        }
        let reopened =
            AtomicSnapshotFileTargetV0::open_or_initialize(&directory.0, sync_digest(99), 99, 99)
                .unwrap();
        assert_eq!(reopened.current_state_root(), installed_root);
        assert_eq!(reopened.current_height(), 2);
        assert_eq!(reopened.current_generation(), 2);
    }

    #[test]
    fn snapshot_cas_failure_and_chunk_substitution_preserve_current_root() {
        let directory = TestDirectory::new("snapshot-cas");
        let initial_root = sync_digest(20);
        let mut target =
            AtomicSnapshotFileTargetV0::open_or_initialize(&directory.0, initial_root, 1, 1)
                .unwrap();
        let manifest = manifest(2, sync_digest(21), 2);
        let staging = target.begin_staging(&manifest).unwrap();
        target.write_chunk(staging, 0, b"a").unwrap();
        assert!(matches!(
            target.write_chunk(staging, 0, b"z"),
            Err(DurableFileErrorV0::ChunkSubstitution)
        ));
        target.write_chunk(staging, 1, b"b").unwrap();
        assert!(matches!(
            target.commit_staging_cas(staging, sync_digest(22), &manifest),
            Err(DurableFileErrorV0::CurrentRootCasMismatch)
        ));
        assert_eq!(target.current_state_root(), initial_root);
        target.abort_staging(staging).unwrap();
        assert_eq!(target.current_state_root(), initial_root);
    }
}
