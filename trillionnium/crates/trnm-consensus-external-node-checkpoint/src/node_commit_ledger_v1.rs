#![forbid(unsafe_code)]

use std::{
    error::Error,
    fmt,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
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
    lock: File,
    head: NodeCommitLedgerHeadV1,
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
            root,
            records,
            lock,
            head: NodeCommitLedgerHeadV1 {
                sequence: 0,
                checkpoint: anchor,
                record_digest: anchor_digest,
            },
        };
        ledger.recover_v1()?;
        Ok(ledger)
    }

    pub(crate) fn open_existing(root: impl AsRef<Path>) -> ResultV1<Self> {
        let root = validate_existing_root_v1(root.as_ref())?;
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
            root,
            records,
            lock,
            head: NodeCommitLedgerHeadV1 {
                sequence: 0,
                checkpoint: anchor,
                record_digest: anchor_digest,
            },
        };
        ledger.recover_v1()?;
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
        self.recover_v1()?;
        if self.head.checkpoint != source {
            return Err(NodeCommitLedgerErrorV1::SourceMismatch);
        }
        target
            .validate_successor_of(&source)
            .map_err(|_| NodeCommitLedgerErrorV1::TargetNotSuccessor)?;
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
        write_new_synced_file_v1(&temporary, &encoded)?;
        fs::rename(&temporary, &final_path).map_err(|source| io_v1("publish record", source))?;
        sync_directory_v1(&self.records)?;

        let digest = record_digest_from_encoded_v1(&encoded)?;
        publish_head_v1(&self.root, sequence, digest)?;
        sync_directory_v1(&self.root)?;

        self.recover_v1()?;
        if self.head.sequence != sequence
            || self.head.checkpoint != target
            || self.head.record_digest != digest
        {
            return Err(NodeCommitLedgerErrorV1::ThirdState);
        }
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
        self.recover_v1()?;
        if self.head.checkpoint == source {
            Ok(NodeCommitConvergenceV1::Source)
        } else if self.head.checkpoint == target {
            Ok(NodeCommitConvergenceV1::Target)
        } else {
            Err(NodeCommitLedgerErrorV1::ThirdState)
        }
    }

    fn recover_v1(&mut self) -> ResultV1<()> {
        validate_existing_directory_v1(&self.root, "ledger root")?;
        validate_existing_directory_v1(&self.records, "records directory")?;
        validate_private_file_path_v1(&self.root.join("ledger.lock"), "ledger lock")?;
        cleanup_abandoned_temps_v1(&self.records)?;
        cleanup_abandoned_head_temp_v1(&self.root)?;

        let anchor = decode_anchor_v1(&read_exact_file_v1(
            &self.root.join("anchor.v1"),
            ANCHOR_BYTES_V1,
        )?)?;
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
        if published_sequence < sequence {
            // The only repairable crash cut is a complete, fsynced record that
            // became visible before the atomic HEAD publication.  Publishing
            // the replayed terminal record converges that operation to target.
            publish_head_v1(&self.root, sequence, digest)?;
            sync_directory_v1(&self.root)?;
        }
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
    if metadata.len() != exact as u64 {
        return Err(NodeCommitLedgerErrorV1::InvalidState(
            "ledger file length differs",
        ));
    }
    let mut bytes = vec![0_u8; exact];
    file.read_exact(&mut bytes)
        .map_err(|source| io_v1("read ledger file", source))?;
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
        if text.starts_with(".record-") && text.contains(".tmp-") {
            let metadata = entry
                .metadata()
                .map_err(|source| io_v1("stat record temp", source))?;
            if !metadata.is_file() {
                return Err(NodeCommitLedgerErrorV1::InvalidState(
                    "record temp is not a file",
                ));
            }
            fs::remove_file(entry.path()).map_err(|source| io_v1("remove record temp", source))?;
        }
    }
    sync_directory_v1(records)
}

fn cleanup_abandoned_head_temp_v1(root: &Path) -> ResultV1<()> {
    for entry in fs::read_dir(root).map_err(|source| io_v1("scan ledger root", source))? {
        let entry = entry.map_err(|source| io_v1("read ledger root entry", source))?;
        let text = entry.file_name().to_string_lossy().into_owned();
        if text.starts_with(".head.v1.tmp-") {
            let metadata = entry
                .metadata()
                .map_err(|source| io_v1("stat head temp", source))?;
            if !metadata.is_file() {
                return Err(NodeCommitLedgerErrorV1::InvalidState(
                    "head temp is not a file",
                ));
            }
            fs::remove_file(entry.path()).map_err(|source| io_v1("remove head temp", source))?;
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
        if !text.starts_with("record-")
            || !text.ends_with(".v1")
            || entry
                .file_type()
                .map_err(|source| io_v1("stat final record", source))?
                .is_dir()
        {
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
}
