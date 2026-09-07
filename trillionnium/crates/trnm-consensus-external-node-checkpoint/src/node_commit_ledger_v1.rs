#![forbid(unsafe_code)]

use std::{
    error::Error,
    fmt,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Component, Path, PathBuf},
    process,
};

use fs2::FileExt;
use sha2::{Digest, Sha256};
use trnm_poco_node::{ExternalNodeCheckpointV0, EXTERNAL_NODE_CHECKPOINT_RECORD_BYTES_V0};

const ANCHOR_MAGIC_V1: &[u8; 8] = b"TRNMNCLA";
const RECORD_MAGIC_V1: &[u8; 8] = b"TRNMNCLR";
const HEAD_MAGIC_V1: &[u8; 8] = b"TRNMNCLH";
const SCHEMA_V1: u16 = 1;
const ANCHOR_DOMAIN_V1: &[u8] = b"trnm.node-commit-ledger.anchor.v1\0";
const RECORD_DOMAIN_V1: &[u8] = b"trnm.node-commit-ledger.record.v1\0";
const ANCHOR_BYTES_V1: usize = 8 + 2 + 6 + EXTERNAL_NODE_CHECKPOINT_RECORD_BYTES_V0 + 32;
const RECORD_BYTES_V1: usize = 8
    + 2
    + 6
    + 8
    + 32
    + EXTERNAL_NODE_CHECKPOINT_RECORD_BYTES_V0
    + EXTERNAL_NODE_CHECKPOINT_RECORD_BYTES_V0
    + 32;
const HEAD_BYTES_V1: usize = 8 + 2 + 6 + 8 + 32;
const MAX_RECORDS_V1: u64 = 1_000_000;

pub(crate) const NODE_COMMIT_LEDGER_IMPLEMENTED_V1: bool = true;
pub(crate) const NODE_COMMIT_LEDGER_EXACT_SOURCE_OR_TARGET_V1: bool = true;
pub(crate) const NODE_COMMIT_LEDGER_PRODUCTION_ACTIVATION_V1: bool = false;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NodeCommitConvergenceV1 {
    Source,
    Target,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct NodeCommitLedgerHeadV1 {
    pub(crate) sequence: u64,
    pub(crate) checkpoint: ExternalNodeCheckpointV0,
    pub(crate) record_digest: [u8; 32],
}

#[derive(Debug)]
pub(crate) enum NodeCommitLedgerErrorV1 {
    InvalidPath(&'static str),
    InvalidState(&'static str),
    SourceMismatch,
    TargetNotSuccessor,
    ThirdState,
    Io {
        stage: &'static str,
        source: std::io::Error,
    },
}

impl fmt::Display for NodeCommitLedgerErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPath(detail) => {
                write!(formatter, "node commit ledger path rejected: {detail}")
            }
            Self::InvalidState(detail) => {
                write!(formatter, "node commit ledger state rejected: {detail}")
            }
            Self::SourceMismatch => {
                formatter.write_str("node commit ledger source differs from durable head")
            }
            Self::TargetNotSuccessor => {
                formatter.write_str("node commit ledger target is not the exact successor")
            }
            Self::ThirdState => formatter
                .write_str("node commit ledger observed neither exact source nor exact target"),
            Self::Io { stage, source } => {
                write!(formatter, "node commit ledger I/O at {stage}: {source}")
            }
        }
    }
}

impl Error for NodeCommitLedgerErrorV1 {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

type ResultV1<T> = Result<T, NodeCommitLedgerErrorV1>;

fn io_v1(stage: &'static str, source: std::io::Error) -> NodeCommitLedgerErrorV1 {
    NodeCommitLedgerErrorV1::Io { stage, source }
}

pub(crate) struct NodeCommitLedgerV1 {
    root: PathBuf,
    records: PathBuf,
    root_endpoint: BoundEndpointV1,
    records_endpoint: BoundEndpointV1,
    anchor_endpoint: BoundEndpointV1,
    anchor: ExternalNodeCheckpointV0,
    lock: File,
    lock_identity: EndpointIdentityV1,
    head: NodeCommitLedgerHeadV1,
    poisoned: bool,
}

impl NodeCommitLedgerV1 {
    pub(crate) fn initialize_new(
        root: impl AsRef<Path>,
        anchor: ExternalNodeCheckpointV0,
    ) -> ResultV1<Self> {
        let root = validate_new_root_v1(root.as_ref())?;
        fs::create_dir(&root).map_err(|source| io_v1("create root", source))?;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
            .map_err(|source| io_v1("protect root", source))?;
        let records = root.join("records");
        fs::create_dir(&records).map_err(|source| io_v1("create records", source))?;
        fs::set_permissions(&records, fs::Permissions::from_mode(0o700))
            .map_err(|source| io_v1("protect records", source))?;
        let lock = create_private_file_v1(&root.join("ledger.lock"))?;
        lock.try_lock_exclusive()
            .map_err(|source| io_v1("lock ledger", source))?;

        let anchor_bytes = encode_anchor_v1(anchor);
        write_new_synced_file_v1(&root.join("anchor.v1"), &anchor_bytes)?;
        let anchor_digest = anchor_digest_v1(&anchor.encode_canonical());
        write_new_synced_file_v1(&root.join("head.v1"), &encode_head_v1(0, anchor_digest))?;
        sync_directory_v1(&records)?;
        sync_directory_v1(&root)?;
        let mut ledger = Self {
            root_endpoint: BoundEndpointV1::open(&root, true)?,
            records_endpoint: BoundEndpointV1::open(&records, true)?,
            anchor_endpoint: BoundEndpointV1::open(&root.join("anchor.v1"), false)?,
            anchor,
            lock_identity: EndpointIdentityV1::from_file(&lock)?,
            root,
            records,
            lock,
            head: NodeCommitLedgerHeadV1 {
                sequence: 0,
                checkpoint: anchor,
                record_digest: anchor_digest,
            },
            poisoned: false,
        };
        ledger.recover_v1()?;
        Ok(ledger)
    }

    #[cfg(test)]
    pub(crate) fn open_existing(root: impl AsRef<Path>) -> ResultV1<Self> {
        Self::open_existing_inner(root.as_ref(), None)
    }

    /// Bind recovery to the caller's exact operation, before repair or cleanup.
    /// Caller-supplied checkpoints are not an independent anti-rollback anchor.
    pub(crate) fn open_existing_expected(
        root: impl AsRef<Path>,
        source: ExternalNodeCheckpointV0,
        target: ExternalNodeCheckpointV0,
    ) -> ResultV1<Self> {
        target
            .validate_successor_of(&source)
            .map_err(|_| NodeCommitLedgerErrorV1::TargetNotSuccessor)?;
        Self::open_existing_inner(root.as_ref(), Some((source, target)))
    }

    fn open_existing_inner(
        root: &Path,
        expected: Option<(ExternalNodeCheckpointV0, ExternalNodeCheckpointV0)>,
    ) -> ResultV1<Self> {
        let root = validate_existing_root_v1(root)?;
        let records = validate_existing_directory_v1(&root.join("records"), "records directory")?;
        let lock_path = root.join("ledger.lock");
        let lock = open_private_file_v1(&lock_path)?;
        lock.try_lock_exclusive()
            .map_err(|source| io_v1("lock ledger", source))?;
        let anchor = decode_anchor_v1(&read_exact_file_v1(
            &root.join("anchor.v1"),
            ANCHOR_BYTES_V1,
        )?)?;
        let anchor_digest = anchor_digest_v1(&anchor.encode_canonical());
        let mut ledger = Self {
            root_endpoint: BoundEndpointV1::open(&root, true)?,
            records_endpoint: BoundEndpointV1::open(&records, true)?,
            anchor_endpoint: BoundEndpointV1::open(&root.join("anchor.v1"), false)?,
            anchor,
            lock_identity: EndpointIdentityV1::from_file(&lock)?,
            root,
            records,
            lock,
            head: NodeCommitLedgerHeadV1 {
                sequence: 0,
                checkpoint: anchor,
                record_digest: anchor_digest,
            },
            poisoned: false,
        };
        ledger.recover_expected_v1(expected)?;
        Ok(ledger)
    }

    pub(crate) const fn head(&self) -> NodeCommitLedgerHeadV1 {
        self.head
    }

    pub(crate) fn append_exact_successor(
        &mut self,
        source: ExternalNodeCheckpointV0,
        target: ExternalNodeCheckpointV0,
    ) -> ResultV1<NodeCommitLedgerHeadV1> {
        target
            .validate_successor_of(&source)
            .map_err(|_| NodeCommitLedgerErrorV1::TargetNotSuccessor)?;
        self.recover_expected_v1(Some((source, target)))?;
        if self.head.checkpoint == target {
            return Ok(self.head);
        }
        if self.head.checkpoint != source {
            return Err(NodeCommitLedgerErrorV1::SourceMismatch);
        }
        let sequence = self
            .head
            .sequence
            .checked_add(1)
            .ok_or(NodeCommitLedgerErrorV1::InvalidState("sequence exhausted"))?;
        if sequence > MAX_RECORDS_V1 {
            return Err(NodeCommitLedgerErrorV1::InvalidState(
                "record bound exceeded",
            ));
        }
        let encoded = encode_record_v1(sequence, self.head.record_digest, source, target);
        let final_path = self.record_path_v1(sequence);
        if final_path.exists() {
            return Err(NodeCommitLedgerErrorV1::InvalidState(
                "successor record already exists",
            ));
        }
        let temporary = self
            .records
            .join(format!(".record-{sequence:020}.tmp-{}", process::id()));
        // A failed write/sync/readback fences this owner until it is reopened.
        self.poisoned = true;
        self.validate_bound_namespace_v1()?;
        write_new_synced_file_v1(&temporary, &encoded)?;
        fs::rename(&temporary, &final_path).map_err(|source| io_v1("publish record", source))?;
        sync_directory_v1(&self.records)?;

        let digest = record_digest_from_encoded_v1(&encoded)?;
        publish_head_v1(&self.root, sequence, digest)?;
        sync_directory_v1(&self.root)?;

        self.recover_inner_v1(Some((source, target)))?;
        if self.head.sequence != sequence
            || self.head.checkpoint != target
            || self.head.record_digest != digest
        {
            return Err(NodeCommitLedgerErrorV1::ThirdState);
        }
        self.poisoned = false;
        Ok(self.head)
    }

    pub(crate) fn resolve_exact_source_or_target(
        &mut self,
        source: ExternalNodeCheckpointV0,
        target: ExternalNodeCheckpointV0,
    ) -> ResultV1<NodeCommitConvergenceV1> {
        target
            .validate_successor_of(&source)
            .map_err(|_| NodeCommitLedgerErrorV1::TargetNotSuccessor)?;
        self.recover_expected_v1(Some((source, target)))?;
        if self.head.checkpoint == source {
            Ok(NodeCommitConvergenceV1::Source)
        } else if self.head.checkpoint == target {
            Ok(NodeCommitConvergenceV1::Target)
        } else {
            Err(NodeCommitLedgerErrorV1::ThirdState)
        }
    }

    fn recover_v1(&mut self) -> ResultV1<()> {
        self.recover_expected_v1(None)
    }

    fn recover_expected_v1(
        &mut self,
        expected: Option<(ExternalNodeCheckpointV0, ExternalNodeCheckpointV0)>,
    ) -> ResultV1<()> {
        if self.poisoned {
            return Err(NodeCommitLedgerErrorV1::InvalidState(
                "ledger owner is fenced",
            ));
        }
        self.poisoned = true;
        self.recover_inner_v1(expected)?;
        self.poisoned = false;
        Ok(())
    }

    fn validate_bound_namespace_v1(&self) -> ResultV1<()> {
        self.root_endpoint.validate(&self.root)?;
        self.records_endpoint.validate(&self.records)?;
        self.anchor_endpoint
            .validate(&self.root.join("anchor.v1"))?;
        validate_bound_endpoint_v1(
            &self.root.join("ledger.lock"),
            &self.lock,
            self.lock_identity,
        )
    }

    fn recover_inner_v1(
        &mut self,
        expected: Option<(ExternalNodeCheckpointV0, ExternalNodeCheckpointV0)>,
    ) -> ResultV1<()> {
        self.validate_bound_namespace_v1()?;
        validate_root_entries_v1(&self.root)?;

        let anchor = decode_anchor_v1(&read_exact_file_v1(
            &self.root.join("anchor.v1"),
            ANCHOR_BYTES_V1,
        )?)?;
        if anchor != self.anchor {
            return Err(NodeCommitLedgerErrorV1::InvalidState(
                "bound anchor changed",
            ));
        }
        let anchor_digest = anchor_digest_v1(&anchor.encode_canonical());
        let (published_sequence, published_digest) = decode_head_v1(&read_exact_file_v1(
            &self.root.join("head.v1"),
            HEAD_BYTES_V1,
        )?)?;
        if published_sequence > MAX_RECORDS_V1 {
            return Err(NodeCommitLedgerErrorV1::InvalidState(
                "published sequence exceeds bound",
            ));
        }

        let mut sequence = 0_u64;
        let mut checkpoint = anchor;
        let mut digest = anchor_digest;
        loop {
            let next = sequence
                .checked_add(1)
                .ok_or(NodeCommitLedgerErrorV1::InvalidState("sequence exhausted"))?;
            if next > MAX_RECORDS_V1 {
                break;
            }
            let path = self.record_path_v1(next);
            if !path.exists() {
                break;
            }
            let encoded = read_exact_file_v1(&path, RECORD_BYTES_V1)?;
            let record = decode_record_v1(&encoded)?;
            if record.sequence != next
                || record.previous_digest != digest
                || record.source != checkpoint
            {
                return Err(NodeCommitLedgerErrorV1::InvalidState(
                    "record chain differs",
                ));
            }
            record
                .target
                .validate_successor_of(&record.source)
                .map_err(|_| {
                    NodeCommitLedgerErrorV1::InvalidState("record target is not successor")
                })?;
            sequence = next;
            checkpoint = record.target;
            digest = record.record_digest;
            if sequence == self.head.sequence
                && (checkpoint != self.head.checkpoint || digest != self.head.record_digest)
            {
                return Err(NodeCommitLedgerErrorV1::InvalidState(
                    "observed ledger prefix changed",
                ));
            }
        }
        reject_unexpected_record_entries_v1(&self.records, sequence)?;

        if published_sequence > sequence {
            return Err(NodeCommitLedgerErrorV1::InvalidState(
                "published head is ahead of durable records",
            ));
        }
        let published_actual = if published_sequence == 0 {
            anchor_digest
        } else {
            let encoded =
                read_exact_file_v1(&self.record_path_v1(published_sequence), RECORD_BYTES_V1)?;
            record_digest_from_encoded_v1(&encoded)?
        };
        if published_actual != published_digest {
            return Err(NodeCommitLedgerErrorV1::InvalidState(
                "published head digest differs",
            ));
        }
        if sequence < self.head.sequence
            || (sequence == self.head.sequence
                && (checkpoint != self.head.checkpoint || digest != self.head.record_digest))
        {
            return Err(NodeCommitLedgerErrorV1::InvalidState(
                "observed ledger head regressed or changed",
            ));
        }
        if expected.is_some_and(|(source, target)| checkpoint != source && checkpoint != target) {
            return Err(NodeCommitLedgerErrorV1::ThirdState);
        }
        // No mutation precedes full history and operation-context validation.
        self.validate_bound_namespace_v1()?;
        cleanup_abandoned_temps_v1(&self.records)?;
        cleanup_abandoned_head_temp_v1(&self.root)?;
        if published_sequence < sequence {
            // The only repairable crash cut is a complete, fsynced record that
            // became visible before the atomic HEAD publication.  Publishing
            // the replayed terminal record converges that operation to target.
            publish_head_v1(&self.root, sequence, digest)?;
            sync_directory_v1(&self.root)?;
        }
        self.validate_bound_namespace_v1()?;
        self.head = NodeCommitLedgerHeadV1 {
            sequence,
            checkpoint,
            record_digest: digest,
        };
        Ok(())
    }

    fn record_path_v1(&self, sequence: u64) -> PathBuf {
        self.records.join(format!("record-{sequence:020}.v1"))
    }
}

impl Drop for NodeCommitLedgerV1 {
    fn drop(&mut self) {
        let _ = FileExt::unlock(&self.lock);
    }
}

#[derive(Debug, Clone, Copy)]
struct DecodedRecordV1 {
    sequence: u64,
    previous_digest: [u8; 32],
    source: ExternalNodeCheckpointV0,
    target: ExternalNodeCheckpointV0,
    record_digest: [u8; 32],
}

/// Live identity fences complement, and never replace, the full byte audit.
#[derive(Clone, Copy, PartialEq, Eq)]
struct EndpointIdentityV1 {
    device: u64,
    inode: u64,
    owner: u32,
    mode: u32,
    directory: bool,
}

impl EndpointIdentityV1 {
    fn from_metadata(metadata: &fs::Metadata) -> ResultV1<Self> {
        let directory = metadata.is_dir();
        if !(directory || metadata.is_file())
            || metadata.permissions().mode() & 0o7777 != if directory { 0o700 } else { 0o600 }
            || (!directory && metadata.nlink() != 1)
        {
            return Err(NodeCommitLedgerErrorV1::InvalidPath(
                "bound endpoint kind/mode/links",
            ));
        }
        Ok(Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            owner: metadata.uid(),
            mode: metadata.permissions().mode() & 0o7777,
            directory,
        })
    }

    fn from_file(file: &File) -> ResultV1<Self> {
        Self::from_metadata(
            &file
                .metadata()
                .map_err(|source| io_v1("stat bound endpoint", source))?,
        )
    }
}

struct BoundEndpointV1 {
    file: File,
    identity: EndpointIdentityV1,
}

impl BoundEndpointV1 {
    fn open(path: &Path, directory: bool) -> ResultV1<Self> {
        let flags =
            libc::O_CLOEXEC | libc::O_NOFOLLOW | if directory { libc::O_DIRECTORY } else { 0 };
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(flags)
            .open(path)
            .map_err(|source| io_v1("open bound endpoint", source))?;
        let identity = EndpointIdentityV1::from_file(&file)?;
        if identity.directory != directory {
            return Err(NodeCommitLedgerErrorV1::InvalidPath(
                "bound endpoint kind changed",
            ));
        }
        let bound = Self { file, identity };
        bound.validate(path)?;
        Ok(bound)
    }

    fn validate(&self, path: &Path) -> ResultV1<()> {
        validate_bound_endpoint_v1(path, &self.file, self.identity)
    }
}

fn validate_bound_endpoint_v1(
    path: &Path,
    file: &File,
    expected: EndpointIdentityV1,
) -> ResultV1<()> {
    let named = fs::symlink_metadata(path).map_err(|source| io_v1("inspect bound path", source))?;
    if EndpointIdentityV1::from_file(file)? != expected
        || EndpointIdentityV1::from_metadata(&named)? != expected
        || fs::canonicalize(path).map_err(|source| io_v1("canonicalize bound path", source))?
            != path
    {
        return Err(NodeCommitLedgerErrorV1::InvalidPath(
            "bound endpoint identity changed",
        ));
    }
    Ok(())
}

fn validate_new_root_v1(path: &Path) -> ResultV1<PathBuf> {
    if !path.is_absolute()
        || path.parent().is_none()
        || path.file_name().is_none()
        || path
            .components()
            .any(|part| matches!(part, Component::CurDir | Component::ParentDir))
        || path.exists()
    {
        return Err(NodeCommitLedgerErrorV1::InvalidPath(
            "new root must be absent canonical absolute path",
        ));
    }
    let parent = path
        .parent()
        .ok_or(NodeCommitLedgerErrorV1::InvalidPath("root parent missing"))?;
    let canonical_parent =
        fs::canonicalize(parent).map_err(|source| io_v1("canonicalize root parent", source))?;
    if canonical_parent != parent {
        return Err(NodeCommitLedgerErrorV1::InvalidPath(
            "root parent is not canonical",
        ));
    }
    Ok(path.to_path_buf())
}

fn validate_existing_root_v1(path: &Path) -> ResultV1<PathBuf> {
    let canonical = fs::canonicalize(path).map_err(|source| io_v1("canonicalize root", source))?;
    if !path.is_absolute() || canonical != path {
        return Err(NodeCommitLedgerErrorV1::InvalidPath(
            "root is not canonical absolute path",
        ));
    }
    validate_existing_directory_v1(path, "ledger root")?;
    Ok(path.to_path_buf())
}

fn validate_existing_directory_v1(path: &Path, label: &'static str) -> ResultV1<PathBuf> {
    let metadata =
        fs::symlink_metadata(path).map_err(|source| io_v1("inspect directory", source))?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.permissions().mode() & 0o7777 != 0o700
    {
        return Err(NodeCommitLedgerErrorV1::InvalidPath(label));
    }
    Ok(path.to_path_buf())
}

fn create_private_file_v1(path: &Path) -> ResultV1<File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|source| io_v1("create private file", source))
}

fn open_private_file_v1(path: &Path) -> ResultV1<File> {
    validate_private_file_path_v1(path, "private file")?;
    OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|source| io_v1("open private file", source))
}

fn validate_private_file_path_v1(path: &Path, label: &'static str) -> ResultV1<()> {
    let metadata =
        fs::symlink_metadata(path).map_err(|source| io_v1("inspect private file", source))?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.permissions().mode() & 0o7777 != 0o600
        || metadata.nlink() != 1
    {
        return Err(NodeCommitLedgerErrorV1::InvalidPath(label));
    }
    Ok(())
}

fn write_new_synced_file_v1(path: &Path, bytes: &[u8]) -> ResultV1<()> {
    let mut file = create_private_file_v1(path)?;
    file.write_all(bytes)
        .map_err(|source| io_v1("write file", source))?;
    file.sync_all().map_err(|source| io_v1("sync file", source))
}

fn read_exact_file_v1(path: &Path, exact: usize) -> ResultV1<Vec<u8>> {
    validate_private_file_path_v1(path, "ledger file")?;
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|source| io_v1("open ledger file", source))?;
    let metadata = file
        .metadata()
        .map_err(|source| io_v1("stat ledger file", source))?;
    let identity = EndpointIdentityV1::from_metadata(&metadata)?;
    validate_bound_endpoint_v1(path, &file, identity)?;
    if metadata.len() != exact as u64 {
        return Err(NodeCommitLedgerErrorV1::InvalidState(
            "ledger file length differs",
        ));
    }
    let mut bytes = vec![0_u8; exact];
    file.read_exact(&mut bytes)
        .map_err(|source| io_v1("read ledger file", source))?;
    if file
        .metadata()
        .map_err(|source| io_v1("restat ledger file", source))?
        .len()
        != exact as u64
    {
        return Err(NodeCommitLedgerErrorV1::InvalidState(
            "ledger file length changed",
        ));
    }
    validate_bound_endpoint_v1(path, &file, identity)?;
    Ok(bytes)
}

fn sync_directory_v1(path: &Path) -> ResultV1<()> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|source| io_v1("sync directory", source))
}

fn publish_head_v1(root: &Path, sequence: u64, digest: [u8; 32]) -> ResultV1<()> {
    let temporary = root.join(format!(".head.v1.tmp-{}-{sequence}", process::id()));
    let final_path = root.join("head.v1");
    if temporary.exists() {
        fs::remove_file(&temporary).map_err(|source| io_v1("remove stale head temp", source))?;
    }
    write_new_synced_file_v1(&temporary, &encode_head_v1(sequence, digest))?;
    fs::rename(&temporary, &final_path).map_err(|source| io_v1("publish head", source))?;
    sync_directory_v1(root)
}

fn cleanup_abandoned_temps_v1(records: &Path) -> ResultV1<()> {
    for entry in fs::read_dir(records).map_err(|source| io_v1("scan records", source))? {
        let entry = entry.map_err(|source| io_v1("read records entry", source))?;
        let name = entry.file_name();
        let text = name.to_string_lossy();
        if record_temp_name_v1(&text) {
            validate_private_file_path_v1(&entry.path(), "record temp")?;
            fs::remove_file(entry.path()).map_err(|source| io_v1("remove record temp", source))?;
        } else if record_sequence_v1(&text).is_none() {
            return Err(NodeCommitLedgerErrorV1::InvalidState(
                "unexpected record cleanup entry",
            ));
        }
    }
    sync_directory_v1(records)
}

fn cleanup_abandoned_head_temp_v1(root: &Path) -> ResultV1<()> {
    for entry in fs::read_dir(root).map_err(|source| io_v1("scan ledger root", source))? {
        let entry = entry.map_err(|source| io_v1("read ledger root entry", source))?;
        let text = entry.file_name().to_string_lossy().into_owned();
        if head_temp_name_v1(&text) {
            validate_private_file_path_v1(&entry.path(), "head temp")?;
            fs::remove_file(entry.path()).map_err(|source| io_v1("remove head temp", source))?;
        } else if !matches!(
            text.as_str(),
            "anchor.v1" | "head.v1" | "ledger.lock" | "records"
        ) {
            return Err(NodeCommitLedgerErrorV1::InvalidState(
                "unexpected root cleanup entry",
            ));
        }
    }
    sync_directory_v1(root)
}

fn reject_unexpected_record_entries_v1(records: &Path, maximum_sequence: u64) -> ResultV1<()> {
    let expected_count = usize::try_from(maximum_sequence)
        .map_err(|_| NodeCommitLedgerErrorV1::InvalidState("record count conversion failed"))?;
    let mut seen = 0_usize;
    for entry in fs::read_dir(records).map_err(|source| io_v1("scan final records", source))? {
        let entry = entry.map_err(|source| io_v1("read final record entry", source))?;
        let name = entry.file_name();
        let text = name.to_string_lossy();
        validate_private_file_path_v1(&entry.path(), "record inventory entry")?;
        if record_temp_name_v1(&text) {
            continue;
        }
        if record_sequence_v1(&text).is_none_or(|sequence| sequence > maximum_sequence) {
            return Err(NodeCommitLedgerErrorV1::InvalidState(
                "unexpected records directory entry",
            ));
        }
        seen = seen
            .checked_add(1)
            .ok_or(NodeCommitLedgerErrorV1::InvalidState(
                "record count overflow",
            ))?;
    }
    if seen != expected_count {
        return Err(NodeCommitLedgerErrorV1::InvalidState(
            "record sequence has a gap or extra entry",
        ));
    }
    Ok(())
}

fn record_sequence_v1(name: &str) -> Option<u64> {
    let digits = name.strip_prefix("record-")?.strip_suffix(".v1")?;
    if digits.len() != 20 || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let sequence = digits.parse::<u64>().ok()?;
    (sequence > 0 && sequence <= MAX_RECORDS_V1).then_some(sequence)
}

fn canonical_pid_v1(text: &str) -> bool {
    text.parse::<u32>()
        .is_ok_and(|pid| pid > 0 && pid.to_string() == text)
}

fn record_temp_name_v1(name: &str) -> bool {
    let Some((sequence, pid)) = name
        .strip_prefix(".record-")
        .and_then(|value| value.split_once(".tmp-"))
    else {
        return false;
    };
    record_sequence_v1(&format!("record-{sequence}.v1")).is_some() && canonical_pid_v1(pid)
}

fn head_temp_name_v1(name: &str) -> bool {
    let Some((pid, sequence)) = name
        .strip_prefix(".head.v1.tmp-")
        .and_then(|value| value.split_once('-'))
    else {
        return false;
    };
    canonical_pid_v1(pid)
        && sequence.parse::<u64>().is_ok_and(|value| {
            value > 0 && value <= MAX_RECORDS_V1 && value.to_string() == sequence
        })
}

fn validate_root_entries_v1(root: &Path) -> ResultV1<()> {
    for entry in fs::read_dir(root).map_err(|source| io_v1("scan root inventory", source))? {
        let entry = entry.map_err(|source| io_v1("read root inventory", source))?;
        let name = entry.file_name();
        let text = name.to_string_lossy();
        if text == "records" {
            validate_existing_directory_v1(&entry.path(), "records inventory")?;
        } else if matches!(text.as_ref(), "anchor.v1" | "head.v1" | "ledger.lock")
            || head_temp_name_v1(&text)
        {
            validate_private_file_path_v1(&entry.path(), "root inventory file")?;
        } else {
            return Err(NodeCommitLedgerErrorV1::InvalidState(
                "unexpected ledger root entry",
            ));
        }
    }
    Ok(())
}

fn encode_anchor_v1(anchor: ExternalNodeCheckpointV0) -> [u8; ANCHOR_BYTES_V1] {
    let checkpoint = anchor.encode_canonical();
    let digest = anchor_digest_v1(&checkpoint);
    let mut out = [0_u8; ANCHOR_BYTES_V1];
    out[..8].copy_from_slice(ANCHOR_MAGIC_V1);
    out[8..10].copy_from_slice(&SCHEMA_V1.to_le_bytes());
    out[16..16 + EXTERNAL_NODE_CHECKPOINT_RECORD_BYTES_V0].copy_from_slice(&checkpoint);
    out[16 + EXTERNAL_NODE_CHECKPOINT_RECORD_BYTES_V0..].copy_from_slice(&digest);
    out
}

fn decode_anchor_v1(raw: &[u8]) -> ResultV1<ExternalNodeCheckpointV0> {
    if raw.len() != ANCHOR_BYTES_V1
        || &raw[..8] != ANCHOR_MAGIC_V1
        || u16_at_v1(raw, 8)? != SCHEMA_V1
        || raw[10..16].iter().any(|byte| *byte != 0)
    {
        return Err(NodeCommitLedgerErrorV1::InvalidState(
            "anchor header differs",
        ));
    }
    let checkpoint_end = 16 + EXTERNAL_NODE_CHECKPOINT_RECORD_BYTES_V0;
    let checkpoint = ExternalNodeCheckpointV0::decode_canonical_exact(&raw[16..checkpoint_end])
        .map_err(|_| NodeCommitLedgerErrorV1::InvalidState("anchor checkpoint is not canonical"))?;
    let digest: [u8; 32] = raw[checkpoint_end..]
        .try_into()
        .map_err(|_| NodeCommitLedgerErrorV1::InvalidState("anchor digest length differs"))?;
    if digest != anchor_digest_v1(&checkpoint.encode_canonical()) {
        return Err(NodeCommitLedgerErrorV1::InvalidState(
            "anchor digest differs",
        ));
    }
    Ok(checkpoint)
}

fn encode_record_v1(
    sequence: u64,
    previous_digest: [u8; 32],
    source: ExternalNodeCheckpointV0,
    target: ExternalNodeCheckpointV0,
) -> [u8; RECORD_BYTES_V1] {
    let source_bytes = source.encode_canonical();
    let target_bytes = target.encode_canonical();
    let mut out = [0_u8; RECORD_BYTES_V1];
    out[..8].copy_from_slice(RECORD_MAGIC_V1);
    out[8..10].copy_from_slice(&SCHEMA_V1.to_le_bytes());
    out[16..24].copy_from_slice(&sequence.to_le_bytes());
    out[24..56].copy_from_slice(&previous_digest);
    let source_start = 56;
    let source_end = source_start + EXTERNAL_NODE_CHECKPOINT_RECORD_BYTES_V0;
    let target_end = source_end + EXTERNAL_NODE_CHECKPOINT_RECORD_BYTES_V0;
    out[source_start..source_end].copy_from_slice(&source_bytes);
    out[source_end..target_end].copy_from_slice(&target_bytes);
    let digest = record_digest_v1(sequence, previous_digest, &source_bytes, &target_bytes);
    out[target_end..].copy_from_slice(&digest);
    out
}

fn decode_record_v1(raw: &[u8]) -> ResultV1<DecodedRecordV1> {
    if raw.len() != RECORD_BYTES_V1
        || &raw[..8] != RECORD_MAGIC_V1
        || u16_at_v1(raw, 8)? != SCHEMA_V1
        || raw[10..16].iter().any(|byte| *byte != 0)
    {
        return Err(NodeCommitLedgerErrorV1::InvalidState(
            "record header differs",
        ));
    }
    let sequence = u64_at_v1(raw, 16)?;
    if sequence == 0 || sequence > MAX_RECORDS_V1 {
        return Err(NodeCommitLedgerErrorV1::InvalidState(
            "record sequence is invalid",
        ));
    }
    let previous_digest: [u8; 32] = raw[24..56]
        .try_into()
        .map_err(|_| NodeCommitLedgerErrorV1::InvalidState("predecessor digest length differs"))?;
    let source_start = 56;
    let source_end = source_start + EXTERNAL_NODE_CHECKPOINT_RECORD_BYTES_V0;
    let target_end = source_end + EXTERNAL_NODE_CHECKPOINT_RECORD_BYTES_V0;
    let source = ExternalNodeCheckpointV0::decode_canonical_exact(&raw[source_start..source_end])
        .map_err(|_| {
        NodeCommitLedgerErrorV1::InvalidState("source checkpoint is not canonical")
    })?;
    let target = ExternalNodeCheckpointV0::decode_canonical_exact(&raw[source_end..target_end])
        .map_err(|_| NodeCommitLedgerErrorV1::InvalidState("target checkpoint is not canonical"))?;
    let record_digest: [u8; 32] = raw[target_end..]
        .try_into()
        .map_err(|_| NodeCommitLedgerErrorV1::InvalidState("record digest length differs"))?;
    let expected = record_digest_v1(
        sequence,
        previous_digest,
        &source.encode_canonical(),
        &target.encode_canonical(),
    );
    if record_digest != expected {
        return Err(NodeCommitLedgerErrorV1::InvalidState(
            "record digest differs",
        ));
    }
    Ok(DecodedRecordV1 {
        sequence,
        previous_digest,
        source,
        target,
        record_digest,
    })
}

fn record_digest_from_encoded_v1(raw: &[u8]) -> ResultV1<[u8; 32]> {
    Ok(decode_record_v1(raw)?.record_digest)
}

fn encode_head_v1(sequence: u64, digest: [u8; 32]) -> [u8; HEAD_BYTES_V1] {
    let mut out = [0_u8; HEAD_BYTES_V1];
    out[..8].copy_from_slice(HEAD_MAGIC_V1);
    out[8..10].copy_from_slice(&SCHEMA_V1.to_le_bytes());
    out[16..24].copy_from_slice(&sequence.to_le_bytes());
    out[24..].copy_from_slice(&digest);
    out
}

fn decode_head_v1(raw: &[u8]) -> ResultV1<(u64, [u8; 32])> {
    if raw.len() != HEAD_BYTES_V1
        || &raw[..8] != HEAD_MAGIC_V1
        || u16_at_v1(raw, 8)? != SCHEMA_V1
        || raw[10..16].iter().any(|byte| *byte != 0)
    {
        return Err(NodeCommitLedgerErrorV1::InvalidState("head header differs"));
    }
    let sequence = u64_at_v1(raw, 16)?;
    let digest: [u8; 32] = raw[24..]
        .try_into()
        .map_err(|_| NodeCommitLedgerErrorV1::InvalidState("head digest length differs"))?;
    Ok((sequence, digest))
}

fn anchor_digest_v1(anchor: &[u8; EXTERNAL_NODE_CHECKPOINT_RECORD_BYTES_V0]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(ANCHOR_DOMAIN_V1);
    hasher.update(anchor);
    hasher.finalize().into()
}

fn record_digest_v1(
    sequence: u64,
    previous_digest: [u8; 32],
    source: &[u8; EXTERNAL_NODE_CHECKPOINT_RECORD_BYTES_V0],
    target: &[u8; EXTERNAL_NODE_CHECKPOINT_RECORD_BYTES_V0],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(RECORD_DOMAIN_V1);
    hasher.update(sequence.to_le_bytes());
    hasher.update(previous_digest);
    hasher.update(source);
    hasher.update(target);
    hasher.finalize().into()
}

fn u16_at_v1(raw: &[u8], offset: usize) -> ResultV1<u16> {
    let bytes: [u8; 2] = raw
        .get(offset..offset + 2)
        .ok_or(NodeCommitLedgerErrorV1::InvalidState("u16 field missing"))?
        .try_into()
        .map_err(|_| NodeCommitLedgerErrorV1::InvalidState("u16 field length differs"))?;
    Ok(u16::from_le_bytes(bytes))
}

fn u64_at_v1(raw: &[u8], offset: usize) -> ResultV1<u64> {
    let bytes: [u8; 8] = raw
        .get(offset..offset + 8)
        .ok_or(NodeCommitLedgerErrorV1::InvalidState("u64 field missing"))?
        .try_into()
        .map_err(|_| NodeCommitLedgerErrorV1::InvalidState("u64 field length differs"))?;
    Ok(u64::from_le_bytes(bytes))
}

pub(crate) fn read_checkpoint_file_v1(path: &Path) -> ResultV1<ExternalNodeCheckpointV0> {
    let mut file = File::open(path).map_err(|source| io_v1("open checkpoint input", source))?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|source| io_v1("read checkpoint input", source))?;
    if bytes.len() != EXTERNAL_NODE_CHECKPOINT_RECORD_BYTES_V0 {
        return Err(NodeCommitLedgerErrorV1::InvalidState(
            "checkpoint input length differs",
        ));
    }
    ExternalNodeCheckpointV0::decode_canonical_exact(&bytes)
        .map_err(|_| NodeCommitLedgerErrorV1::InvalidState("checkpoint input is not canonical"))
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;
    use trnm_consensus_signer_journal::SignerWatermarkV0;
    use trnm_consensus_types::{BlockId, StateRoot};
    use trnm_poco_node::ExternalNodeCheckpointFieldsV0;

    use super::*;

    fn checkpoint_v1(
        generation: u64,
        predecessor_checksum: [u8; 32],
        marker: u8,
    ) -> ExternalNodeCheckpointV0 {
        ExternalNodeCheckpointV0::new(ExternalNodeCheckpointFieldsV0 {
            scope: [1; 32],
            generation,
            predecessor_checksum,
            safety_journal_id: [2; 32],
            safety_verifier_profile_ref: [3; 32],
            safety_revision: generation,
            safety_state_record_checksum: [marker; 32],
            safety_record_chain_checksum: [marker.wrapping_add(1); 32],
            application_host_config_ref: [6; 32],
            application_projection_profile_ref: [7; 32],
            application_safety_binding_manifest_checksum: [8; 32],
            application_committed_head_row_checksum: [marker.wrapping_add(2); 32],
            application_recovery_closure_checksum: [marker.wrapping_add(3); 32],
            application_block_id: BlockId::new([marker.wrapping_add(4); 32]),
            application_height: generation,
            application_state_root: StateRoot::new([marker.wrapping_add(5); 32]),
            application_view: generation,
            application_timestamp_ms: generation,
            signer_journal_id: [19; 32],
            signer_profile_checksum: [18; 32],
            signer_exact_watermark: SignerWatermarkV0::from_persisted_parts(
                [1; 32], [19; 32], generation, [20; 32],
            )
            .expect("canonical watermark"),
        })
        .expect("canonical checkpoint")
    }

    fn successor_v1(source: ExternalNodeCheckpointV0, marker: u8) -> ExternalNodeCheckpointV0 {
        checkpoint_v1(
            source.generation() + 1,
            source.checkpoint_checksum(),
            marker,
        )
    }

    #[test]
    fn durable_successor_reopens_exactly() {
        let temp = TempDir::new().expect("temporary ledger parent");
        let parent = fs::canonicalize(temp.path()).expect("canonical temp parent");
        let root = parent.join("ledger");
        let source = checkpoint_v1(0, [0; 32], 21);
        let target = successor_v1(source, 31);
        let mut ledger =
            NodeCommitLedgerV1::initialize_new(&root, source).expect("initialize ledger");
        let head = ledger
            .append_exact_successor(source, target)
            .expect("append successor");
        assert_eq!(head.sequence, 1);
        assert_eq!(head.checkpoint, target);
        drop(ledger);
        let reopened = NodeCommitLedgerV1::open_existing(&root).expect("reopen ledger");
        assert_eq!(reopened.head().checkpoint, target);
    }

    #[test]
    fn journal_ahead_of_head_recovers_to_exact_target() {
        let temp = TempDir::new().expect("temporary ledger parent");
        let parent = fs::canonicalize(temp.path()).expect("canonical temp parent");
        let root = parent.join("ledger");
        let source = checkpoint_v1(0, [0; 32], 21);
        let target = successor_v1(source, 31);
        let ledger = NodeCommitLedgerV1::initialize_new(&root, source).expect("initialize ledger");
        let encoded = encode_record_v1(1, ledger.head().record_digest, source, target);
        let path = ledger.record_path_v1(1);
        write_new_synced_file_v1(&path, &encoded).expect("publish durable record fixture");
        sync_directory_v1(&ledger.records).expect("sync records fixture");
        drop(ledger);

        let mut reopened =
            NodeCommitLedgerV1::open_existing(&root).expect("recover journal-ahead cut");
        assert_eq!(
            reopened
                .resolve_exact_source_or_target(source, target)
                .expect("exact convergence"),
            NodeCommitConvergenceV1::Target
        );
        assert_eq!(reopened.head().checkpoint, target);
    }

    #[test]
    fn abandoned_partial_temp_converges_to_source() {
        let temp = TempDir::new().expect("temporary ledger parent");
        let parent = fs::canonicalize(temp.path()).expect("canonical temp parent");
        let root = parent.join("ledger");
        let source = checkpoint_v1(0, [0; 32], 21);
        let target = successor_v1(source, 31);
        let ledger = NodeCommitLedgerV1::initialize_new(&root, source).expect("initialize ledger");
        let temp_record = ledger.records.join(".record-00000000000000000001.tmp-999");
        write_new_synced_file_v1(&temp_record, b"partial").expect("write partial temp fixture");
        drop(ledger);
        let mut reopened =
            NodeCommitLedgerV1::open_existing(&root).expect("recover partial temp cut");
        assert_eq!(
            reopened
                .resolve_exact_source_or_target(source, target)
                .expect("exact convergence"),
            NodeCommitConvergenceV1::Source
        );
    }

    #[test]
    fn third_state_is_rejected() {
        let temp = TempDir::new().expect("temporary ledger parent");
        let parent = fs::canonicalize(temp.path()).expect("canonical temp parent");
        let root = parent.join("ledger");
        let source = checkpoint_v1(0, [0; 32], 21);
        let target = successor_v1(source, 31);
        let third = successor_v1(target, 41);
        let mut ledger =
            NodeCommitLedgerV1::initialize_new(&root, source).expect("initialize ledger");
        ledger
            .append_exact_successor(source, target)
            .expect("first successor");
        ledger
            .append_exact_successor(target, third)
            .expect("second successor");
        assert!(matches!(
            ledger.resolve_exact_source_or_target(source, target),
            Err(NodeCommitLedgerErrorV1::ThirdState)
        ));
    }

    fn fixture_v1() -> (
        TempDir,
        PathBuf,
        ExternalNodeCheckpointV0,
        ExternalNodeCheckpointV0,
        NodeCommitLedgerV1,
    ) {
        let temp = TempDir::new().expect("temporary ledger parent");
        let root = fs::canonicalize(temp.path())
            .expect("canonical parent")
            .join("ledger");
        let source = checkpoint_v1(0, [0; 32], 21);
        let target = successor_v1(source, 31);
        let ledger = NodeCommitLedgerV1::initialize_new(&root, source).expect("initialize ledger");
        (temp, root, source, target, ledger)
    }

    fn retained_temp_v1(root: &Path) -> PathBuf {
        let path = root.join("records/.record-00000000000000000003.tmp-999");
        write_new_synced_file_v1(&path, b"partial retained evidence").expect("write temp fixture");
        path
    }

    #[test]
    fn exact_target_retry_is_read_only_and_does_not_append_v1() {
        let (_temp, root, source, target, mut ledger) = fixture_v1();
        let first = ledger
            .append_exact_successor(source, target)
            .expect("first append");
        let head_bytes = fs::read(root.join("head.v1")).expect("head bytes");
        assert_eq!(
            ledger
                .append_exact_successor(source, target)
                .expect("exact retry"),
            first
        );
        assert_eq!(
            fs::read(root.join("head.v1")).expect("head bytes"),
            head_bytes
        );
        assert_eq!(
            fs::read_dir(root.join("records")).expect("records").count(),
            1
        );
        drop(ledger);
        let mut reopened = NodeCommitLedgerV1::open_existing_expected(&root, source, target)
            .expect("exact-context reopen");
        assert_eq!(
            reopened
                .append_exact_successor(source, target)
                .expect("reopened retry"),
            first
        );
    }

    #[test]
    fn corrupted_older_record_fences_owner_without_cleanup_v1() {
        let (_temp, root, source, target, mut ledger) = fixture_v1();
        let third = successor_v1(target, 41);
        ledger
            .append_exact_successor(source, target)
            .expect("first append");
        ledger
            .append_exact_successor(target, third)
            .expect("second append");
        let old_path = ledger.record_path_v1(1);
        let original = fs::read(&old_path).expect("old record");
        let mut corrupted = original.clone();
        corrupted[56] ^= 1;
        fs::write(&old_path, &corrupted).expect("corrupt old record in place");
        let retained = retained_temp_v1(&root);
        let head = fs::read(root.join("head.v1")).expect("head");
        assert!(ledger
            .resolve_exact_source_or_target(target, third)
            .is_err());
        assert!(
            retained.exists(),
            "failed validation must not clean evidence"
        );
        assert_eq!(fs::read(root.join("head.v1")).expect("head"), head);
        fs::write(&old_path, original).expect("restore record");
        assert!(matches!(
            ledger.resolve_exact_source_or_target(target, third),
            Err(NodeCommitLedgerErrorV1::InvalidState(
                "ledger owner is fenced"
            ))
        ));
    }

    #[test]
    fn missing_record_and_head_ahead_fail_before_repair_v1() {
        for missing in [1_u64, 2] {
            let (_temp, root, source, target, mut ledger) = fixture_v1();
            let third = successor_v1(target, 41);
            ledger
                .append_exact_successor(source, target)
                .expect("first append");
            ledger
                .append_exact_successor(target, third)
                .expect("second append");
            fs::remove_file(ledger.record_path_v1(missing)).expect("remove retained record");
            let retained = retained_temp_v1(&root);
            let head = fs::read(root.join("head.v1")).expect("head");
            drop(ledger);
            assert!(NodeCommitLedgerV1::open_existing_expected(&root, target, third).is_err());
            assert!(retained.exists());
            assert_eq!(fs::read(root.join("head.v1")).expect("head"), head);
        }
        let (_temp, root, source, target, ledger) = fixture_v1();
        publish_head_v1(&root, 1, [77; 32]).expect("head ahead fixture");
        let head = fs::read(root.join("head.v1")).expect("head");
        drop(ledger);
        assert!(NodeCommitLedgerV1::open_existing_expected(&root, source, target).is_err());
        assert_eq!(fs::read(root.join("head.v1")).expect("head"), head);
    }

    #[test]
    fn live_root_records_lock_and_anchor_replacements_fail_closed_v1() {
        for endpoint in ["root", "records", "ledger.lock", "anchor.v1"] {
            let (temp, root, source, target, mut ledger) = fixture_v1();
            ledger
                .append_exact_successor(source, target)
                .expect("append");
            let saved = temp.path().join("saved-endpoint");
            let path = if endpoint == "root" {
                root.clone()
            } else {
                root.join(endpoint)
            };
            fs::rename(&path, &saved).expect("move bound endpoint");
            if endpoint == "root" {
                fs::create_dir(&root).expect("replacement root");
                fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
                    .expect("private root");
                let records = root.join("records");
                fs::create_dir(&records).expect("replacement records");
                fs::set_permissions(&records, fs::Permissions::from_mode(0o700))
                    .expect("private records");
                for name in ["anchor.v1", "head.v1", "ledger.lock"] {
                    fs::copy(saved.join(name), root.join(name)).expect("copy root file");
                }
                fs::copy(
                    saved.join("records/record-00000000000000000001.v1"),
                    records.join("record-00000000000000000001.v1"),
                )
                .expect("copy record");
            } else if endpoint == "records" {
                fs::create_dir(&path).expect("replacement records");
                fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                    .expect("private records");
                fs::copy(
                    saved.join("record-00000000000000000001.v1"),
                    path.join("record-00000000000000000001.v1"),
                )
                .expect("copy record");
            } else {
                fs::copy(&saved, &path).expect("replace file with identical bytes");
            }
            let head = fs::read(root.join("head.v1")).expect("replacement head");
            let retained = retained_temp_v1(&root);
            assert!(
                ledger
                    .resolve_exact_source_or_target(source, target)
                    .is_err(),
                "replacement {endpoint} must reject"
            );
            assert!(
                retained.exists(),
                "replacement {endpoint} must not be cleaned"
            );
            assert_eq!(fs::read(root.join("head.v1")).expect("head"), head);
            assert!(ledger.poisoned);
            if endpoint == "ledger.lock" {
                let contender = open_private_file_v1(&saved).expect("original lock path");
                assert!(
                    contender.try_lock_exclusive().is_err(),
                    "owner must retain the original lock"
                );
            }
        }
    }

    #[test]
    fn live_coherent_anchor_rewrite_and_head_rollback_are_rejected_v1() {
        let (_temp, root, source, target, mut ledger) = fixture_v1();
        let replacement = checkpoint_v1(0, [0; 32], 61);
        fs::write(root.join("anchor.v1"), encode_anchor_v1(replacement))
            .expect("rewrite bound anchor inode");
        fs::write(
            root.join("head.v1"),
            encode_head_v1(0, anchor_digest_v1(&replacement.encode_canonical())),
        )
        .expect("rewrite matching head");
        assert!(matches!(
            ledger.resolve_exact_source_or_target(source, target),
            Err(NodeCommitLedgerErrorV1::InvalidState(
                "bound anchor changed"
            ))
        ));

        let (_temp, root, source, target, mut ledger) = fixture_v1();
        ledger
            .append_exact_successor(source, target)
            .expect("append");
        fs::remove_file(ledger.record_path_v1(1)).expect("roll back record inventory");
        fs::write(
            root.join("head.v1"),
            encode_head_v1(0, anchor_digest_v1(&source.encode_canonical())),
        )
        .expect("restore older coherent head");
        assert!(matches!(
            ledger.resolve_exact_source_or_target(source, target),
            Err(NodeCommitLedgerErrorV1::InvalidState(
                "observed ledger head regressed or changed"
            ))
        ));
    }

    #[test]
    fn expected_context_mismatch_preserves_journal_ahead_and_temp_evidence_v1() {
        let (_temp, root, source, target, ledger) = fixture_v1();
        let encoded = encode_record_v1(1, ledger.head().record_digest, source, target);
        write_new_synced_file_v1(&ledger.record_path_v1(1), &encoded)
            .expect("journal ahead fixture");
        let retained = retained_temp_v1(&root);
        let head = fs::read(root.join("head.v1")).expect("old head");
        drop(ledger);
        let foreign_source = checkpoint_v1(0, [0; 32], 71);
        let foreign_target = successor_v1(foreign_source, 81);
        assert!(matches!(
            NodeCommitLedgerV1::open_existing_expected(&root, foreign_source, foreign_target),
            Err(NodeCommitLedgerErrorV1::ThirdState)
        ));
        assert_eq!(
            fs::read(root.join("head.v1")).expect("unchanged old head"),
            head
        );
        assert!(retained.exists());
        let reopened = NodeCommitLedgerV1::open_existing_expected(&root, source, target)
            .expect("matching context may recover target");
        assert_eq!(reopened.head().checkpoint, target);
        assert!(!retained.exists());
    }

    #[test]
    fn cold_rollback_below_supplied_expected_source_is_rejected_v1() {
        let (_temp, root, source, target, ledger) = fixture_v1();
        let third = successor_v1(target, 41);
        drop(ledger);
        // A cold owner cannot invent a trusted watermark: the caller must retain
        // the expected operation outside this rollback image.
        assert!(matches!(
            NodeCommitLedgerV1::open_existing_expected(&root, target, third),
            Err(NodeCommitLedgerErrorV1::ThirdState)
        ));
        assert!(
            NodeCommitLedgerV1::open_existing_expected(&root, source, target).is_ok(),
            "a caller that also rolls back its expectation is outside the local guarantee"
        );
    }

    #[test]
    fn coherent_rewritten_prefix_with_higher_head_is_rejected_v1() {
        let (_temp, root, source, target, mut ledger) = fixture_v1();
        ledger
            .append_exact_successor(source, target)
            .expect("observe original prefix");
        let substituted = successor_v1(source, 61);
        let extended = successor_v1(substituted, 71);
        let first = encode_record_v1(
            1,
            anchor_digest_v1(&source.encode_canonical()),
            source,
            substituted,
        );
        fs::write(ledger.record_path_v1(1), first).expect("coherently rewrite same record inode");
        let second = encode_record_v1(
            2,
            record_digest_from_encoded_v1(&first).expect("first digest"),
            substituted,
            extended,
        );
        write_new_synced_file_v1(&ledger.record_path_v1(2), &second).expect("forged extension");
        publish_head_v1(
            &root,
            2,
            record_digest_from_encoded_v1(&second).expect("second digest"),
        )
        .expect("matching newer head");
        let head = fs::read(root.join("head.v1")).expect("head");
        let retained = retained_temp_v1(&root);
        assert!(matches!(
            ledger.resolve_exact_source_or_target(substituted, extended),
            Err(NodeCommitLedgerErrorV1::InvalidState(
                "observed ledger prefix changed"
            ))
        ));
        assert!(ledger.poisoned);
        assert!(retained.exists());
        assert_eq!(fs::read(root.join("head.v1")).expect("head"), head);
    }

    #[test]
    fn valid_extension_preserves_the_observed_live_prefix_v1() {
        let (_temp, root, source, target, mut ledger) = fixture_v1();
        let observed = ledger
            .append_exact_successor(source, target)
            .expect("observe prefix");
        let extended = successor_v1(target, 41);
        let encoded = encode_record_v1(2, observed.record_digest, target, extended);
        write_new_synced_file_v1(&ledger.record_path_v1(2), &encoded)
            .expect("durable valid extension");
        sync_directory_v1(&root.join("records")).expect("sync extension");
        assert_eq!(
            ledger
                .resolve_exact_source_or_target(target, extended)
                .expect("recover extension"),
            NodeCommitConvergenceV1::Target
        );
        assert_eq!(ledger.head().sequence, 2);
    }

    #[test]
    fn record_and_temp_links_are_rejected_without_deleting_targets_v1() {
        use std::os::unix::fs::symlink;
        for temporary in [false, true] {
            for hard_link in [false, true] {
                let (temp, root, source, target, mut ledger) = fixture_v1();
                ledger
                    .append_exact_successor(source, target)
                    .expect("append");
                let path = if temporary {
                    root.join("records/.record-00000000000000000002.tmp-999")
                } else {
                    ledger.record_path_v1(1)
                };
                let saved = temp.path().join("outside-target");
                let bytes = if temporary {
                    b"must remain untouched".to_vec()
                } else {
                    fs::read(&path).expect("record bytes")
                };
                if !temporary {
                    fs::remove_file(&path).expect("remove record");
                }
                write_new_synced_file_v1(&saved, &bytes).expect("outside target");
                if hard_link {
                    fs::hard_link(&saved, &path).expect("hard link");
                } else {
                    symlink(&saved, &path).expect("symlink");
                }
                assert!(ledger
                    .resolve_exact_source_or_target(source, target)
                    .is_err());
                assert!(
                    fs::symlink_metadata(&path).is_ok(),
                    "rejected link must not be cleaned"
                );
                assert_eq!(fs::read(&saved).expect("outside target intact"), bytes);
            }
        }
    }

    #[test]
    fn unknown_root_and_noncanonical_temp_names_are_retained_and_rejected_v1() {
        for relative in [
            "unregistered.v1",
            ".head.v1.tmp-999-not-a-sequence",
            "records/.record-not-a-sequence.tmp-999",
            "records/record-1.v1",
        ] {
            let (_temp, root, source, target, mut ledger) = fixture_v1();
            let path = root.join(relative);
            write_new_synced_file_v1(&path, b"untrusted inventory").expect("extra inventory");
            assert!(
                ledger
                    .resolve_exact_source_or_target(source, target)
                    .is_err(),
                "reject {relative}"
            );
            assert_eq!(
                fs::read(path).expect("unknown entry retained"),
                b"untrusted inventory"
            );
        }
    }
}
