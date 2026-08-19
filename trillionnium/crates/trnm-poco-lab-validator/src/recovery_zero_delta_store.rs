//! Crash-safe private storage for one canonical zero-delta recovery cut.
//!
//! This module accepts only an already typed and direct7-validated
//! [`RecoveryZeroDeltaCutV1`].  The fixed artifact is joined to an externally
//! supplied SHA-256, the exact expected typed cut, a zero-delta recovery
//! context, and the validator set.  Publication is create-new and idempotent:
//! exact response-loss successors are reconciled, while partial, foreign, or
//! ambiguous filesystem states fail closed.  The returned non-Clone owner
//! retains open directory/file handles and repeats the complete identity,
//! content-address, exact-decode, context, and validator-set join on every
//! fresh revalidation.
//!
//! There is deliberately no signer, journal, scheduler, Ready/Start, network,
//! timer, catch-up, or activation API here.
//!
//! Held root/artifact handles detect stable replacement. Publication child
//! operations remain pathname-based rather than directory-fd-relative, so
//! this boundary does not claim to defeat a hostile same-UID concurrent
//! rename-and-swap-back race.

use std::{
    ffi::OsStr,
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    os::unix::{
        ffi::OsStrExt,
        fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::{Path, PathBuf},
    process,
    sync::atomic::{AtomicU64, Ordering},
};

use anyhow::{bail, ensure, Context, Result};
use sha2::{Digest, Sha256};
use trnm_consensus_types::{
    decode_recovery_zero_delta_cut_v1_exact, RecoveryContextV1, RecoveryModeV1,
    RecoveryZeroDeltaCutV1, ValidatorSet, MAX_RECOVERY_ZERO_DELTA_CUT_BYTES_V1,
};

const RECOVERY_ZERO_DELTA_CUT_FILE_V1: &str = "recovery-zero-delta-cut-v1.bin";
const RECOVERY_ZERO_DELTA_CUT_NEXT_V1: &str = "recovery-zero-delta-cut-v1.next";
const RECOVERY_ZERO_DELTA_CUT_SIDECARS_V1: [&str; 3] = [
    RECOVERY_ZERO_DELTA_CUT_NEXT_V1,
    "recovery-zero-delta-cut-v1.tmp",
    "recovery-zero-delta-cut-v1.lock",
];
const RECOVERY_ZERO_DELTA_CUT_WRITING_PREFIX_V1: &str = "recovery-zero-delta-cut-v1.writing.";
static RECOVERY_ZERO_DELTA_WRITING_ATTEMPT_V1: AtomicU64 = AtomicU64::new(0);

/// Non-Clone proof that one exact canonical zero-delta cut remains pinned at
/// its immutable private path and still joins the retained expected context.
#[must_use = "stored zero-delta cut ownership must be retained across recovery"]
pub(crate) struct StoredRecoveryZeroDeltaCutV1 {
    pinned: PinnedRecoveryZeroDeltaArtifactV1,
    value: RecoveryZeroDeltaCutV1,
    context: RecoveryContextV1,
    artifact_sha256: [u8; 32],
}

impl std::fmt::Debug for StoredRecoveryZeroDeltaCutV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("StoredRecoveryZeroDeltaCutV1")
            .field("path", &self.pinned.path)
            .field("artifact_sha256", &self.artifact_sha256)
            .field("fields", &self.value.fields())
            .field("context", &self.context)
            .finish_non_exhaustive()
    }
}

impl StoredRecoveryZeroDeltaCutV1 {
    pub(crate) const fn value_v1(&self) -> &RecoveryZeroDeltaCutV1 {
        &self.value
    }

    pub(crate) const fn context_v1(&self) -> &RecoveryContextV1 {
        &self.context
    }

    pub(crate) const fn artifact_sha256_v1(&self) -> [u8; 32] {
        self.artifact_sha256
    }

    pub(crate) fn path_v1(&self) -> &Path {
        &self.pinned.path
    }

    /// Repeats the complete typed and filesystem join without granting a raw
    /// file handle or any process authority.
    pub(crate) fn revalidate_fresh_v1(&self, validator_set: &ValidatorSet) -> Result<()> {
        validate_expected_join_v1(
            self.artifact_sha256,
            &self.value,
            &self.context,
            validator_set,
        )?;
        self.pinned.revalidate_held_v1()?;
        let (fresh, bytes, observed_sha256) = open_and_read_artifact_v1(&self.pinned.root_path)?;
        ensure!(
            fresh.same_identity_v1(&self.pinned),
            "zero-delta cut path or open-file identity was replaced"
        );
        ensure!(
            observed_sha256 == self.artifact_sha256,
            "zero-delta cut content address changed"
        );
        let decoded = decode_recovery_zero_delta_cut_v1_exact(&bytes, validator_set)
            .map_err(|error| anyhow::anyhow!("fresh-decode zero-delta cut: {error}"))?;
        ensure!(
            decoded == self.value,
            "fresh zero-delta cut differs from retained typed value"
        );
        validate_cut_context_join_v1(observed_sha256, &decoded, &self.context, validator_set)?;
        fresh.revalidate_held_v1()?;
        self.pinned.revalidate_held_v1()
    }
}

/// Persists one exact, caller-content-addressed zero-delta cut.  An existing
/// target is accepted only when it is byte-exact canonical input, making a
/// response-loss retry deterministic.
pub(crate) fn persist_recovery_zero_delta_cut_v1(
    private_root: &Path,
    expected_artifact_sha256: [u8; 32],
    value: RecoveryZeroDeltaCutV1,
    expected_context: &RecoveryContextV1,
    validator_set: &ValidatorSet,
) -> Result<StoredRecoveryZeroDeltaCutV1> {
    validate_expected_join_v1(
        expected_artifact_sha256,
        &value,
        expected_context,
        validator_set,
    )?;
    let bytes = value
        .try_cev1_bytes()
        .map_err(|error| anyhow::anyhow!("encode zero-delta cut: {error}"))?;
    validate_encoded_bound_v1(&bytes)?;
    ensure!(
        sha256_v1(&bytes) == expected_artifact_sha256,
        "canonical zero-delta cut differs from expected content address"
    );
    publish_create_new_v1(private_root, &bytes)?;
    let stored = load_recovery_zero_delta_cut_v1(
        private_root,
        expected_artifact_sha256,
        &value,
        expected_context,
        validator_set,
    )?;
    ensure!(
        stored.value == value,
        "stored zero-delta cut differs from verified input"
    );
    Ok(stored)
}

/// Reopens only the fixed artifact path and joins it to the independently
/// supplied content address, typed cut, recovery context, and validator set.
pub(crate) fn load_recovery_zero_delta_cut_v1(
    private_root: &Path,
    expected_artifact_sha256: [u8; 32],
    expected_value: &RecoveryZeroDeltaCutV1,
    expected_context: &RecoveryContextV1,
    validator_set: &ValidatorSet,
) -> Result<StoredRecoveryZeroDeltaCutV1> {
    validate_expected_join_v1(
        expected_artifact_sha256,
        expected_value,
        expected_context,
        validator_set,
    )?;
    let (pinned, bytes, observed_sha256) = open_and_read_artifact_v1(private_root)?;
    ensure!(
        observed_sha256 == expected_artifact_sha256,
        "zero-delta cut SHA-256 differs from expected content address"
    );
    let value = decode_recovery_zero_delta_cut_v1_exact(&bytes, validator_set)
        .map_err(|error| anyhow::anyhow!("decode stored zero-delta cut: {error}"))?;
    ensure!(
        value == *expected_value,
        "stored zero-delta cut differs from expected typed value"
    );
    validate_cut_context_join_v1(observed_sha256, &value, expected_context, validator_set)?;
    pinned.revalidate_held_v1()?;
    Ok(StoredRecoveryZeroDeltaCutV1 {
        pinned,
        value,
        context: *expected_context,
        artifact_sha256: observed_sha256,
    })
}

fn validate_expected_join_v1(
    expected_artifact_sha256: [u8; 32],
    expected_value: &RecoveryZeroDeltaCutV1,
    expected_context: &RecoveryContextV1,
    validator_set: &ValidatorSet,
) -> Result<()> {
    ensure!(
        expected_artifact_sha256 != [0; 32],
        "expected zero-delta cut SHA-256 is zero"
    );
    expected_value
        .validate_direct7(validator_set)
        .map_err(|error| anyhow::anyhow!("validate expected typed zero-delta cut: {error}"))?;
    expected_context
        .validate_direct7(validator_set)
        .map_err(|error| anyhow::anyhow!("validate expected recovery context: {error}"))?;
    validate_cut_context_join_v1(
        expected_artifact_sha256,
        expected_value,
        expected_context,
        validator_set,
    )?;
    let canonical = expected_value
        .try_cev1_bytes()
        .map_err(|error| anyhow::anyhow!("encode expected zero-delta cut: {error}"))?;
    validate_encoded_bound_v1(&canonical)?;
    ensure!(
        sha256_v1(&canonical) == expected_artifact_sha256,
        "expected typed zero-delta cut does not match expected content address"
    );
    Ok(())
}

fn validate_cut_context_join_v1(
    artifact_sha256: [u8; 32],
    cut: &RecoveryZeroDeltaCutV1,
    context: &RecoveryContextV1,
    validator_set: &ValidatorSet,
) -> Result<()> {
    cut.validate_direct7(validator_set)
        .map_err(|error| anyhow::anyhow!("validate zero-delta cut join: {error}"))?;
    context
        .validate_direct7(validator_set)
        .map_err(|error| anyhow::anyhow!("validate zero-delta context join: {error}"))?;
    ensure!(
        context.mode() == RecoveryModeV1::ZeroDelta,
        "zero-delta cut cannot join a nonzero recovery context"
    );
    let cut = cut.fields();
    let context = context.fields();
    ensure!(
        context.caught_up_cut_artifact_sha256 == artifact_sha256,
        "recovery context does not bind the exact zero-delta cut content address"
    );
    ensure!(
        (
            cut.campaign_context_sha256,
            cut.fleet_start_certificate_sha256,
            cut.validator_set_id,
            cut.validator_set_artifact_sha256,
            cut.restart_cut_artifact_sha256,
            cut.restart_park_artifact_sha256,
            cut.restart_parked_ack_artifact_sha256,
            cut.restart_parked_ack_admission_set_sha256,
            cut.target_validator,
            cut.process_instance,
            cut.recovery_nonce,
            cut.node_facts_sha256,
        ) == (
            context.campaign_context_sha256,
            context.fleet_start_certificate_sha256,
            context.validator_set_id,
            context.validator_set_artifact_sha256,
            context.restart_cut_artifact_sha256,
            context.restart_park_artifact_sha256,
            context.restart_parked_ack_artifact_sha256,
            context.restart_parked_ack_admission_set_sha256,
            context.target_validator,
            context.process_instance,
            context.recovery_nonce,
            context.node_facts_sha256,
        ),
        "zero-delta cut identity facts differ from the expected recovery context"
    );
    ensure!(
        (
            cut.source_epoch,
            cut.source_height,
            cut.source_block_id,
            cut.source_state_root,
            cut.source_finalized_chain_root,
        ) == (
            context.restart_cut_epoch,
            context.restart_cut_height,
            context.restart_cut_block_id,
            context.restart_cut_state_root,
            context.restart_cut_chain_root,
        ),
        "zero-delta source cut differs from the expected RestartCut context"
    );
    ensure!(
        (
            cut.terminal_epoch,
            cut.terminal_height,
            cut.terminal_block_id,
            cut.terminal_state_root,
            cut.terminal_finalized_chain_root,
        ) == (
            context.terminal_epoch,
            context.terminal_height,
            context.terminal_block_id,
            context.terminal_state_root,
            context.terminal_chain_root,
        ),
        "zero-delta terminal cut differs from the expected recovery context"
    );
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DirectoryIdentityV1 {
    device: u64,
    inode: u64,
    uid: u32,
    mode: u32,
}

impl DirectoryIdentityV1 {
    fn from_metadata_v1(metadata: &fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            uid: metadata.uid(),
            mode: metadata.permissions().mode() & 0o7777,
        }
    }

    fn matches_metadata_v1(self, metadata: &fs::Metadata) -> bool {
        metadata.is_dir()
            && self.device == metadata.dev()
            && self.inode == metadata.ino()
            && self.uid == metadata.uid()
            && self.mode == metadata.permissions().mode() & 0o7777
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ArtifactIdentityV1 {
    device: u64,
    inode: u64,
    uid: u32,
    mode: u32,
    links: u64,
    length: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

impl ArtifactIdentityV1 {
    fn from_metadata_v1(metadata: &fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            uid: metadata.uid(),
            mode: metadata.permissions().mode() & 0o7777,
            links: metadata.nlink(),
            length: metadata.len(),
            modified_seconds: metadata.mtime(),
            modified_nanoseconds: metadata.mtime_nsec(),
            changed_seconds: metadata.ctime(),
            changed_nanoseconds: metadata.ctime_nsec(),
        }
    }

    fn matches_metadata_v1(self, metadata: &fs::Metadata) -> bool {
        metadata.is_file()
            && self.device == metadata.dev()
            && self.inode == metadata.ino()
            && self.uid == metadata.uid()
            && self.mode == metadata.permissions().mode() & 0o7777
            && self.links == metadata.nlink()
            && self.length == metadata.len()
            && self.modified_seconds == metadata.mtime()
            && self.modified_nanoseconds == metadata.mtime_nsec()
            && self.changed_seconds == metadata.ctime()
            && self.changed_nanoseconds == metadata.ctime_nsec()
    }
}

struct PinnedRecoveryZeroDeltaArtifactV1 {
    root_path: PathBuf,
    path: PathBuf,
    root_file: File,
    artifact_file: File,
    root_identity: DirectoryIdentityV1,
    artifact_identity: ArtifactIdentityV1,
}

impl std::fmt::Debug for PinnedRecoveryZeroDeltaArtifactV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PinnedRecoveryZeroDeltaArtifactV1")
            .field("root_path", &self.root_path)
            .field("path", &self.path)
            .field("root_identity", &self.root_identity)
            .field("artifact_identity", &self.artifact_identity)
            .finish_non_exhaustive()
    }
}

impl PinnedRecoveryZeroDeltaArtifactV1 {
    fn same_identity_v1(&self, other: &Self) -> bool {
        self.root_path == other.root_path
            && self.path == other.path
            && self.root_identity == other.root_identity
            && self.artifact_identity == other.artifact_identity
    }

    fn revalidate_held_v1(&self) -> Result<()> {
        ensure_no_publication_sidecars_v1(&self.root_path)?;
        ensure!(
            self.path == self.root_path.join(RECOVERY_ZERO_DELTA_CUT_FILE_V1)
                && self.path.file_name() == Some(OsStr::new(RECOVERY_ZERO_DELTA_CUT_FILE_V1)),
            "pinned zero-delta artifact escaped its fixed private path"
        );

        let held_root = self
            .root_file
            .metadata()
            .context("inspect held zero-delta private root")?;
        validate_private_root_metadata_v1(&held_root)?;
        ensure!(
            self.root_identity.matches_metadata_v1(&held_root),
            "held zero-delta private root identity changed"
        );
        let (fresh_root_file, fresh_root_identity) = open_private_root_v1(&self.root_path)?;
        ensure!(
            fresh_root_identity == self.root_identity,
            "zero-delta private root path was replaced"
        );
        drop(fresh_root_file);

        let held_artifact = self
            .artifact_file
            .metadata()
            .context("inspect held zero-delta cut")?;
        validate_private_artifact_metadata_v1(&held_artifact)?;
        ensure!(
            self.artifact_identity.matches_metadata_v1(&held_artifact),
            "held zero-delta cut identity changed"
        );
        let path_metadata =
            fs::symlink_metadata(&self.path).context("reinspect pinned zero-delta cut path")?;
        ensure!(
            !path_metadata.file_type().is_symlink(),
            "pinned zero-delta cut path became a symlink"
        );
        validate_private_artifact_metadata_v1(&path_metadata)?;
        ensure!(
            self.artifact_identity.matches_metadata_v1(&path_metadata),
            "pinned zero-delta cut path was replaced or mutated"
        );
        Ok(())
    }
}

fn effective_uid_v1() -> u32 {
    rustix::process::geteuid().as_raw()
}

fn validate_encoded_bound_v1(bytes: &[u8]) -> Result<()> {
    ensure!(
        !bytes.is_empty() && bytes.len() <= MAX_RECOVERY_ZERO_DELTA_CUT_BYTES_V1,
        "zero-delta cut canonical bytes cross the durable bound"
    );
    Ok(())
}

fn sha256_v1(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn writing_file_name_v1(process_id: u32, attempt: u64) -> String {
    format!("{RECOVERY_ZERO_DELTA_CUT_WRITING_PREFIX_V1}{process_id:08x}.{attempt:016x}")
}

fn next_writing_file_name_v1() -> String {
    writing_file_name_v1(
        process::id(),
        RECOVERY_ZERO_DELTA_WRITING_ATTEMPT_V1.fetch_add(1, Ordering::Relaxed),
    )
}

fn is_lower_hex_digit_v1(byte: u8) -> bool {
    byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
}

fn writing_candidate_v1(name: &OsStr) -> Option<bool> {
    let name = name.as_bytes();
    let prefix = RECOVERY_ZERO_DELTA_CUT_WRITING_PREFIX_V1.as_bytes();
    if !name.starts_with(prefix) {
        return None;
    }
    let suffix = &name[prefix.len()..];
    Some(
        suffix.len() == 25
            && suffix[8] == b'.'
            && suffix[..8].iter().copied().all(is_lower_hex_digit_v1)
            && suffix[..8].iter().any(|byte| *byte != b'0')
            && suffix[9..].iter().copied().all(is_lower_hex_digit_v1),
    )
}

fn revalidate_publication_root_v1(
    private_root: &Path,
    root_file: &File,
    root_identity: DirectoryIdentityV1,
) -> Result<()> {
    let held_root = root_file
        .metadata()
        .context("reinspect held zero-delta publication root")?;
    validate_private_root_metadata_v1(&held_root)?;
    ensure!(
        root_identity.matches_metadata_v1(&held_root),
        "zero-delta private root changed during publication"
    );
    let path_root =
        fs::symlink_metadata(private_root).context("reinspect zero-delta publication root path")?;
    ensure!(
        !path_root.file_type().is_symlink() && root_identity.matches_metadata_v1(&path_root),
        "zero-delta private root path was replaced during publication"
    );
    Ok(())
}

fn cleanup_one_interrupted_writing_candidate_v1(
    private_root: &Path,
    root_file: &File,
    root_identity: DirectoryIdentityV1,
    expected_bytes: &[u8],
    writing: &Path,
    next: &Path,
) -> Result<()> {
    let before = fs::symlink_metadata(writing).with_context(|| {
        format!(
            "inspect interrupted zero-delta writing candidate {}",
            writing.display()
        )
    })?;
    let mode = before.permissions().mode() & 0o7777;
    ensure!(
        !before.file_type().is_symlink()
            && before.is_file()
            && before.uid() == effective_uid_v1()
            && mode & !0o600 == 0
            && matches!(before.nlink(), 1 | 2)
            && before.len() <= u64::try_from(expected_bytes.len()).unwrap_or(u64::MAX),
        "interrupted zero-delta writing candidate has foreign metadata"
    );
    let expected_identity = ArtifactIdentityV1::from_metadata_v1(&before);

    let observed = if before.len() == 0 {
        Vec::new()
    } else {
        ensure!(
            mode == 0o600,
            "nonempty interrupted zero-delta writing candidate has incomplete permissions"
        );
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(writing)
            .with_context(|| {
                format!(
                    "open interrupted zero-delta writing candidate {}",
                    writing.display()
                )
            })?;
        let opened = file
            .metadata()
            .context("inspect opened interrupted zero-delta writing candidate")?;
        ensure!(
            expected_identity.matches_metadata_v1(&opened),
            "interrupted zero-delta writing candidate changed while opening"
        );
        let mut observed = Vec::with_capacity(
            usize::try_from(before.len()).context("writing candidate length overflows")?,
        );
        Read::by_ref(&mut file)
            .take(u64::try_from(expected_bytes.len()).unwrap_or(u64::MAX) + 1)
            .read_to_end(&mut observed)
            .context("read interrupted zero-delta writing candidate")?;
        let after = file
            .metadata()
            .context("reinspect interrupted zero-delta writing candidate")?;
        ensure!(
            expected_identity.matches_metadata_v1(&after),
            "interrupted zero-delta writing candidate changed while reading"
        );
        observed
    };
    ensure!(
        expected_bytes.starts_with(&observed),
        "interrupted zero-delta writing candidate is not an exact canonical prefix"
    );

    let next_exists = path_exists_no_follow_v1(next, "zero-delta next candidate")?;
    match expected_identity.links {
        1 => ensure!(
            !next_exists,
            "unlinked zero-delta writing candidate coexists with a foreign fixed candidate"
        ),
        2 => {
            ensure!(
                next_exists && observed == expected_bytes,
                "linked zero-delta writing candidate is partial or lacks its exact fixed link"
            );
            let next_identity = validate_publication_candidate_v1(next, expected_bytes, 2)?;
            ensure!(
                next_identity == expected_identity,
                "linked zero-delta writing and fixed candidates are different inodes"
            );
        }
        _ => unreachable!("writing candidate link count was checked above"),
    }

    let path_after = fs::symlink_metadata(writing)
        .context("reinspect interrupted zero-delta writing candidate path")?;
    ensure!(
        expected_identity.matches_metadata_v1(&path_after),
        "interrupted zero-delta writing candidate path was replaced"
    );
    revalidate_publication_root_v1(private_root, root_file, root_identity)?;
    fs::remove_file(writing)
        .context("remove authenticated interrupted zero-delta writing candidate")?;
    root_file
        .sync_all()
        .context("fsync cleaned zero-delta writing candidate")?;
    revalidate_publication_root_v1(private_root, root_file, root_identity)?;
    if expected_identity.links == 2 {
        validate_publication_candidate_v1(next, expected_bytes, 1)?;
    }
    Ok(())
}

fn cleanup_interrupted_writing_candidates_v1(
    private_root: &Path,
    root_file: &File,
    root_identity: DirectoryIdentityV1,
    expected_bytes: &[u8],
    next: &Path,
) -> Result<()> {
    let mut writing = None;
    for entry in fs::read_dir(private_root)
        .context("scan zero-delta private root for interrupted writing candidates")?
    {
        let entry = entry.context("read zero-delta private-root writing candidate")?;
        let name = entry.file_name();
        ensure!(
            !RECOVERY_ZERO_DELTA_CUT_SIDECARS_V1[1..]
                .iter()
                .any(|reserved| name == OsStr::new(reserved)),
            "forbidden zero-delta publication sidecar is preserved: {}",
            entry.path().display()
        );
        let Some(canonical) = writing_candidate_v1(&name) else {
            continue;
        };
        let path = private_root.join(&name);
        ensure!(
            canonical,
            "malformed zero-delta writing candidate is preserved: {}",
            path.display()
        );
        ensure!(
            writing.replace(path).is_none(),
            "multiple zero-delta writing candidates are ambiguous and preserved"
        );
    }
    let Some(writing) = writing else {
        return Ok(());
    };
    let target = private_root.join(RECOVERY_ZERO_DELTA_CUT_FILE_V1);
    ensure!(
        !path_exists_no_follow_v1(&target, "zero-delta target")?,
        "zero-delta target coexists with an impossible writing candidate"
    );
    revalidate_publication_root_v1(private_root, root_file, root_identity)?;
    cleanup_one_interrupted_writing_candidate_v1(
        private_root,
        root_file,
        root_identity,
        expected_bytes,
        &writing,
        next,
    )
}

fn create_complete_writing_candidate_v1(private_root: &Path, bytes: &[u8]) -> Result<PathBuf> {
    let name = next_writing_file_name_v1();
    let writing = private_root.join(&name);
    ensure!(
        writing.parent() == Some(private_root)
            && writing.file_name() == Some(OsStr::new(&name))
            && writing_candidate_v1(OsStr::new(&name)) == Some(true),
        "zero-delta writing candidate escaped its unique private path"
    );
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(&writing)
        .context("create-new unique zero-delta writing candidate")?;
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .context("chmod unique zero-delta writing candidate")?;
    file.write_all(bytes)
        .context("write unique zero-delta writing candidate")?;
    file.sync_all()
        .context("fsync unique zero-delta writing candidate")?;
    drop(file);
    validate_publication_candidate_v1(&writing, bytes, 1)?;
    Ok(writing)
}

fn publish_complete_writing_candidate_v1(
    private_root: &Path,
    root_file: &File,
    root_identity: DirectoryIdentityV1,
    bytes: &[u8],
    writing: &Path,
    next: &Path,
) -> Result<()> {
    validate_publication_candidate_v1(writing, bytes, 1)?;
    match fs::hard_link(writing, next) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => {
            return Err(error).context("link complete zero-delta writing candidate no-replace")
        }
    }
    let writing_linked = validate_publication_candidate_v1(writing, bytes, 2)?;
    let next_metadata =
        fs::symlink_metadata(next).context("inspect linked fixed zero-delta candidate")?;
    ensure!(
        !next_metadata.file_type().is_symlink()
            && writing_linked.matches_metadata_v1(&next_metadata),
        "zero-delta writing candidate did not link to the exact fixed candidate inode"
    );
    root_file
        .sync_all()
        .context("fsync linked zero-delta writing candidate")?;
    revalidate_publication_root_v1(private_root, root_file, root_identity)?;
    fs::remove_file(writing).context("remove linked unique zero-delta writing candidate")?;
    root_file
        .sync_all()
        .context("fsync fixed zero-delta candidate publication")?;
    revalidate_publication_root_v1(private_root, root_file, root_identity)?;
    validate_publication_candidate_v1(next, bytes, 1)?;
    Ok(())
}

fn publish_create_new_v1(private_root: &Path, bytes: &[u8]) -> Result<()> {
    validate_encoded_bound_v1(bytes)?;
    let (root_file, root_identity) = open_private_root_v1(private_root)?;
    root_file
        .try_lock()
        .context("lock zero-delta private root publication lifetime")?;
    let target = private_root.join(RECOVERY_ZERO_DELTA_CUT_FILE_V1);
    let next = private_root.join(RECOVERY_ZERO_DELTA_CUT_NEXT_V1);
    ensure!(
        target.parent() == Some(private_root)
            && target.file_name() == Some(OsStr::new(RECOVERY_ZERO_DELTA_CUT_FILE_V1))
            && next.parent() == Some(private_root)
            && next.file_name() == Some(OsStr::new(RECOVERY_ZERO_DELTA_CUT_NEXT_V1)),
        "zero-delta artifact target escaped its fixed private path"
    );

    cleanup_interrupted_writing_candidates_v1(
        private_root,
        &root_file,
        root_identity,
        bytes,
        &next,
    )?;
    ensure_no_publication_sidecars_except_v1(private_root, Some(RECOVERY_ZERO_DELTA_CUT_NEXT_V1))?;

    let target_exists = path_exists_no_follow_v1(&target, "zero-delta target")?;
    let next_exists = path_exists_no_follow_v1(&next, "zero-delta next candidate")?;
    if target_exists && !next_exists {
        validate_publication_candidate_v1(&target, bytes, 1)?;
        revalidate_publication_root_v1(private_root, &root_file, root_identity)?;
        drop(root_file);
        return Ok(());
    }

    if !next_exists {
        let writing = create_complete_writing_candidate_v1(private_root, bytes)?;
        publish_complete_writing_candidate_v1(
            private_root,
            &root_file,
            root_identity,
            bytes,
            &writing,
            &next,
        )?;
    }

    let next_identity =
        validate_publication_candidate_v1(&next, bytes, if target_exists { 2 } else { 1 })?;
    if target_exists {
        let target_metadata =
            fs::symlink_metadata(&target).context("inspect zero-delta response-loss target")?;
        ensure!(
            !target_metadata.file_type().is_symlink()
                && next_identity.matches_metadata_v1(&target_metadata),
            "zero-delta target and publication candidate are not one exact response-loss inode"
        );
    } else {
        match fs::hard_link(&next, &target) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error).context("publish zero-delta cut without replacement"),
        }
        let next_after_link = validate_publication_candidate_v1(&next, bytes, 2)?;
        let target_metadata =
            fs::symlink_metadata(&target).context("inspect published zero-delta target")?;
        ensure!(
            !target_metadata.file_type().is_symlink()
                && next_after_link.matches_metadata_v1(&target_metadata),
            "zero-delta no-replace publication did not create one exact linked target"
        );
    }

    root_file
        .sync_all()
        .context("fsync zero-delta linked publication")?;
    fs::remove_file(&next).context("remove committed zero-delta publication candidate")?;
    root_file
        .sync_all()
        .context("fsync zero-delta final publication")?;
    revalidate_publication_root_v1(private_root, &root_file, root_identity)?;
    drop(root_file);
    ensure_no_publication_sidecars_v1(private_root)?;
    let (_, observed, _) = open_and_read_artifact_v1(private_root)?;
    ensure!(
        observed == bytes,
        "published zero-delta cut differs from exact canonical input"
    );
    Ok(())
}

fn path_exists_no_follow_v1(path: &Path, label: &str) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).with_context(|| format!("inspect {label} publication path")),
    }
}

fn validate_publication_candidate_v1(
    path: &Path,
    expected_bytes: &[u8],
    expected_links: u64,
) -> Result<ArtifactIdentityV1> {
    let before = fs::symlink_metadata(path).context("inspect zero-delta publication candidate")?;
    ensure!(
        !before.file_type().is_symlink()
            && before.is_file()
            && before.permissions().mode() & 0o7777 == 0o600
            && before.uid() == effective_uid_v1()
            && before.nlink() == expected_links
            && before.len() == u64::try_from(expected_bytes.len()).unwrap_or(u64::MAX)
            && before.len()
                <= u64::try_from(MAX_RECOVERY_ZERO_DELTA_CUT_BYTES_V1).unwrap_or(u64::MAX),
        "zero-delta publication candidate has invalid private metadata"
    );
    let expected_identity = ArtifactIdentityV1::from_metadata_v1(&before);
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .context("open zero-delta publication candidate")?;
    let opened = file
        .metadata()
        .context("inspect opened zero-delta publication candidate")?;
    ensure!(
        expected_identity.matches_metadata_v1(&opened),
        "zero-delta publication candidate changed while opening"
    );
    let mut observed = Vec::with_capacity(expected_bytes.len());
    Read::by_ref(&mut file)
        .take(u64::try_from(MAX_RECOVERY_ZERO_DELTA_CUT_BYTES_V1).unwrap_or(u64::MAX) + 1)
        .read_to_end(&mut observed)
        .context("read zero-delta publication candidate")?;
    let after = file
        .metadata()
        .context("reinspect zero-delta publication candidate")?;
    let path_after =
        fs::symlink_metadata(path).context("reinspect zero-delta publication candidate path")?;
    ensure!(
        observed == expected_bytes
            && expected_identity.matches_metadata_v1(&after)
            && expected_identity.matches_metadata_v1(&path_after),
        "zero-delta publication candidate is partial, mutated, or foreign"
    );
    Ok(expected_identity)
}

fn open_and_read_artifact_v1(
    private_root: &Path,
) -> Result<(PinnedRecoveryZeroDeltaArtifactV1, Vec<u8>, [u8; 32])> {
    let (root_file, root_identity) = open_private_root_v1(private_root)?;
    ensure_no_publication_sidecars_v1(private_root)?;
    let path = private_root.join(RECOVERY_ZERO_DELTA_CUT_FILE_V1);
    ensure!(
        path.parent() == Some(private_root)
            && path.file_name() == Some(OsStr::new(RECOVERY_ZERO_DELTA_CUT_FILE_V1)),
        "zero-delta artifact path escaped its fixed private root"
    );

    let before = fs::symlink_metadata(&path).context("inspect zero-delta cut path")?;
    ensure!(
        !before.file_type().is_symlink(),
        "zero-delta cut path is a symlink"
    );
    validate_private_artifact_metadata_v1(&before)?;
    let expected_identity = ArtifactIdentityV1::from_metadata_v1(&before);

    let mut artifact_file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(&path)
        .context("open zero-delta cut")?;
    let opened = artifact_file
        .metadata()
        .context("inspect opened zero-delta cut")?;
    validate_private_artifact_metadata_v1(&opened)?;
    ensure!(
        expected_identity.matches_metadata_v1(&opened),
        "zero-delta cut identity changed while opening"
    );

    artifact_file
        .seek(SeekFrom::Start(0))
        .context("seek zero-delta cut")?;
    let mut bytes = Vec::with_capacity(
        usize::try_from(opened.len()).context("zero-delta cut byte length overflows")?,
    );
    Read::by_ref(&mut artifact_file)
        .take(u64::try_from(MAX_RECOVERY_ZERO_DELTA_CUT_BYTES_V1).unwrap_or(u64::MAX) + 1)
        .read_to_end(&mut bytes)
        .context("read zero-delta cut")?;
    ensure!(
        bytes.len() == usize::try_from(opened.len()).unwrap_or(usize::MAX)
            && bytes.len() <= MAX_RECOVERY_ZERO_DELTA_CUT_BYTES_V1,
        "zero-delta cut byte length changed while reading"
    );
    let observed_sha256 = sha256_v1(&bytes);

    let after_handle = artifact_file
        .metadata()
        .context("reinspect opened zero-delta cut")?;
    let after_path = fs::symlink_metadata(&path).context("reinspect zero-delta cut path")?;
    ensure!(
        !after_path.file_type().is_symlink()
            && expected_identity.matches_metadata_v1(&after_handle)
            && expected_identity.matches_metadata_v1(&after_path),
        "zero-delta cut identity changed during stat/read/hash"
    );
    let root_after = root_file
        .metadata()
        .context("reinspect zero-delta private root after artifact read")?;
    ensure!(
        root_identity.matches_metadata_v1(&root_after),
        "zero-delta private root changed during artifact read"
    );
    ensure_no_publication_sidecars_v1(private_root)?;

    Ok((
        PinnedRecoveryZeroDeltaArtifactV1 {
            root_path: private_root.to_path_buf(),
            path,
            root_file,
            artifact_file,
            root_identity,
            artifact_identity: expected_identity,
        },
        bytes,
        observed_sha256,
    ))
}

fn open_private_root_v1(root: &Path) -> Result<(File, DirectoryIdentityV1)> {
    ensure!(
        root.is_absolute(),
        "zero-delta private root is not absolute"
    );
    let before = fs::symlink_metadata(root).context("inspect zero-delta private root")?;
    ensure!(
        !before.file_type().is_symlink(),
        "zero-delta private root is a symlink"
    );
    validate_private_root_metadata_v1(&before)?;
    let canonical = fs::canonicalize(root).context("canonicalize zero-delta private root")?;
    ensure!(
        canonical == root,
        "zero-delta private root has a symlink or non-canonical ancestor"
    );
    let expected = DirectoryIdentityV1::from_metadata_v1(&before);
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(root)
        .context("open zero-delta private root")?;
    let opened = file
        .metadata()
        .context("inspect opened zero-delta private root")?;
    validate_private_root_metadata_v1(&opened)?;
    let after = fs::symlink_metadata(root).context("reinspect zero-delta private root")?;
    ensure!(
        !after.file_type().is_symlink()
            && expected.matches_metadata_v1(&opened)
            && expected.matches_metadata_v1(&after),
        "zero-delta private root identity changed while opening"
    );
    Ok((file, expected))
}

fn validate_private_root_metadata_v1(metadata: &fs::Metadata) -> Result<()> {
    ensure!(
        metadata.is_dir()
            && metadata.uid() == effective_uid_v1()
            && metadata.permissions().mode() & 0o7777 == 0o700,
        "zero-delta private root is not one effective-user-owned 0700 directory"
    );
    Ok(())
}

fn validate_private_artifact_metadata_v1(metadata: &fs::Metadata) -> Result<()> {
    ensure!(
        metadata.is_file()
            && metadata.permissions().mode() & 0o7777 == 0o600
            && metadata.nlink() == 1
            && metadata.uid() == effective_uid_v1()
            && metadata.len() > 0
            && metadata.len()
                <= u64::try_from(MAX_RECOVERY_ZERO_DELTA_CUT_BYTES_V1).unwrap_or(u64::MAX),
        "zero-delta cut is not one exact effective-user-owned private regular file"
    );
    Ok(())
}

fn ensure_no_publication_sidecars_v1(root: &Path) -> Result<()> {
    ensure_no_publication_sidecars_except_v1(root, None)
}

fn ensure_no_publication_sidecars_except_v1(root: &Path, allowed: Option<&str>) -> Result<()> {
    for name in RECOVERY_ZERO_DELTA_CUT_SIDECARS_V1 {
        if allowed == Some(name) {
            continue;
        }
        let path = root.join(name);
        match fs::symlink_metadata(&path) {
            Ok(_) => bail!(
                "zero-delta publication sidecar unexpectedly exists: {}",
                path.display()
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("inspect zero-delta sidecar {}", path.display()))
            }
        }
    }
    for entry in fs::read_dir(root).context("scan zero-delta private root for writing sidecars")? {
        let entry = entry.context("read zero-delta private-root sidecar entry")?;
        if writing_candidate_v1(&entry.file_name()).is_some() {
            bail!(
                "zero-delta publication writing sidecar unexpectedly exists: {}",
                entry.path().display()
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        io::Write,
        os::unix::fs::{symlink, OpenOptionsExt, PermissionsExt},
        path::Path,
    };

    use ed25519_dalek::SigningKey;
    use tempfile::TempDir;
    use trnm_consensus_types::{
        BlockId, ChainId, ConsensusParametersHash, ConsensusPublicKey, Epoch, GenesisHash, Height,
        ProtocolVersion, RecoveryContextV1Fields, RecoveryZeroDeltaCutV1Fields, StateRoot,
        Validator, ValidatorId, VotingPower,
    };

    use super::*;

    struct Fixture {
        set: ValidatorSet,
        cut: RecoveryZeroDeltaCutV1,
        context: RecoveryContextV1,
        artifact_sha256: [u8; 32],
    }

    fn fixture() -> Fixture {
        let keys = (1u8..=7)
            .map(|byte| SigningKey::from_bytes(&[byte.wrapping_add(0x20); 32]))
            .collect::<Vec<_>>();
        let validators = keys
            .iter()
            .enumerate()
            .map(|(index, key)| {
                Validator::new(
                    ValidatorId::new([u8::try_from(index + 1).unwrap(); 32]),
                    ConsensusPublicKey::new(key.verifying_key().to_bytes()),
                    VotingPower::new(1).unwrap(),
                )
                .unwrap()
            })
            .collect();
        let set = ValidatorSet::new(
            GenesisHash::new([0x11; 32]),
            ChainId::from_static("trnm-zero-delta-store-test"),
            ProtocolVersion::V0,
            Epoch::new(4),
            ConsensusParametersHash::new([0x12; 32]),
            validators,
        )
        .unwrap();
        let cut = RecoveryZeroDeltaCutV1::new_direct7(zero_delta_cut_fields(&set), &set).unwrap();
        let artifact_sha256 = sha256_v1(&cut.try_cev1_bytes().unwrap());
        let context =
            RecoveryContextV1::new_direct7(zero_delta_context_fields(&cut, artifact_sha256), &set)
                .unwrap();
        Fixture {
            set,
            cut,
            context,
            artifact_sha256,
        }
    }

    fn zero_delta_cut_fields(set: &ValidatorSet) -> RecoveryZeroDeltaCutV1Fields {
        RecoveryZeroDeltaCutV1Fields {
            campaign_context_sha256: [0x31; 32],
            fleet_start_certificate_sha256: [0x32; 32],
            validator_set_id: set.id(),
            validator_set_artifact_sha256: [0x33; 32],
            restart_cut_artifact_sha256: [0x34; 32],
            restart_park_artifact_sha256: [0x38; 32],
            restart_parked_ack_artifact_sha256: [0x39; 32],
            restart_parked_ack_admission_set_sha256: [0x3a; 32],
            target_validator: set.validators()[0].id(),
            process_instance: 2,
            recovery_nonce: [0x35; 32],
            node_facts_sha256: [0x36; 32],
            signer_inventory_invariant_sha256: [0x37; 32],
            source_epoch: set.epoch(),
            source_height: Height::new(50),
            source_block_id: BlockId::new([0x41; 32]),
            source_state_root: StateRoot::new([0x42; 32]),
            source_finalized_chain_root: [0x43; 32],
            terminal_epoch: set.epoch(),
            terminal_height: Height::new(50),
            terminal_block_id: BlockId::new([0x41; 32]),
            terminal_state_root: StateRoot::new([0x42; 32]),
            terminal_finalized_chain_root: [0x43; 32],
            terminal_application_commit_sha256: [0x44; 32],
            terminal_checkpoint_canonical_sha256: [0x45; 32],
        }
    }

    fn zero_delta_context_fields(
        cut: &RecoveryZeroDeltaCutV1,
        artifact_sha256: [u8; 32],
    ) -> RecoveryContextV1Fields {
        let fields = cut.fields();
        RecoveryContextV1Fields {
            mode: RecoveryModeV1::ZeroDelta,
            campaign_context_sha256: fields.campaign_context_sha256,
            fleet_start_certificate_sha256: fields.fleet_start_certificate_sha256,
            validator_set_id: fields.validator_set_id,
            validator_set_artifact_sha256: fields.validator_set_artifact_sha256,
            restart_cut_artifact_sha256: fields.restart_cut_artifact_sha256,
            restart_park_artifact_sha256: fields.restart_park_artifact_sha256,
            restart_parked_ack_artifact_sha256: fields.restart_parked_ack_artifact_sha256,
            restart_parked_ack_admission_set_sha256: fields.restart_parked_ack_admission_set_sha256,
            caught_up_cut_artifact_sha256: artifact_sha256,
            target_validator: fields.target_validator,
            process_instance: fields.process_instance,
            recovery_nonce: fields.recovery_nonce,
            restart_cut_epoch: fields.source_epoch,
            restart_cut_height: fields.source_height,
            restart_cut_block_id: fields.source_block_id,
            restart_cut_state_root: fields.source_state_root,
            restart_cut_chain_root: fields.source_finalized_chain_root,
            terminal_epoch: fields.terminal_epoch,
            terminal_height: fields.terminal_height,
            terminal_block_id: fields.terminal_block_id,
            terminal_state_root: fields.terminal_state_root,
            terminal_chain_root: fields.terminal_finalized_chain_root,
            node_facts_sha256: fields.node_facts_sha256,
        }
    }

    fn nonzero_context(fixture: &Fixture) -> RecoveryContextV1 {
        let mut fields = fixture.context.fields();
        fields.mode = RecoveryModeV1::NonZeroDelta;
        fields.terminal_height = Height::new(fields.restart_cut_height.get() + 1);
        fields.terminal_block_id = BlockId::new([0x51; 32]);
        fields.terminal_state_root = StateRoot::new([0x52; 32]);
        fields.terminal_chain_root = [0x53; 32];
        RecoveryContextV1::new_direct7(fields, &fixture.set).unwrap()
    }

    fn private_root() -> TempDir {
        let temporary = TempDir::new().unwrap();
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(temporary.path().canonicalize().unwrap(), temporary.path());
        temporary
    }

    fn write_test_artifact(root: &Path, name: &str, bytes: &[u8]) {
        let path = root.join(name);
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .unwrap();
        file.write_all(bytes).unwrap();
        file.sync_all().unwrap();
        File::open(root).unwrap().sync_all().unwrap();
    }

    fn persist(fixture: &Fixture, root: &Path) -> StoredRecoveryZeroDeltaCutV1 {
        persist_recovery_zero_delta_cut_v1(
            root,
            fixture.artifact_sha256,
            fixture.cut,
            &fixture.context,
            &fixture.set,
        )
        .unwrap()
    }

    #[test]
    fn typed_cut_persists_loads_idempotently_and_fresh_revalidates() {
        let fixture = fixture();
        let root = private_root();
        let stored = persist(&fixture, root.path());
        assert_eq!(stored.value_v1(), &fixture.cut);
        assert_eq!(stored.context_v1(), &fixture.context);
        assert_eq!(stored.artifact_sha256_v1(), fixture.artifact_sha256);
        assert_eq!(
            stored.path_v1(),
            root.path().join(RECOVERY_ZERO_DELTA_CUT_FILE_V1)
        );
        stored.revalidate_fresh_v1(&fixture.set).unwrap();

        let loaded = load_recovery_zero_delta_cut_v1(
            root.path(),
            fixture.artifact_sha256,
            &fixture.cut,
            &fixture.context,
            &fixture.set,
        )
        .unwrap();
        loaded.revalidate_fresh_v1(&fixture.set).unwrap();
        let metadata = fs::symlink_metadata(stored.path_v1()).unwrap();
        assert_eq!(metadata.permissions().mode() & 0o7777, 0o600);
        assert_eq!(metadata.uid(), effective_uid_v1());
        assert_eq!(metadata.nlink(), 1);

        persist(&fixture, root.path())
            .revalidate_fresh_v1(&fixture.set)
            .unwrap();
    }

    #[test]
    fn expected_hash_typed_cut_context_mode_and_set_are_all_required() {
        let fixture = fixture();
        let root = private_root();
        let _stored = persist(&fixture, root.path());

        assert!(load_recovery_zero_delta_cut_v1(
            root.path(),
            [0xee; 32],
            &fixture.cut,
            &fixture.context,
            &fixture.set,
        )
        .is_err());

        let mut mutant_fields = fixture.cut.fields();
        mutant_fields.signer_inventory_invariant_sha256 = [0x81; 32];
        let mutant = RecoveryZeroDeltaCutV1::new_direct7(mutant_fields, &fixture.set).unwrap();
        assert!(load_recovery_zero_delta_cut_v1(
            root.path(),
            fixture.artifact_sha256,
            &mutant,
            &fixture.context,
            &fixture.set,
        )
        .is_err());

        let mut context_fields = fixture.context.fields();
        context_fields.caught_up_cut_artifact_sha256 = [0x82; 32];
        let wrong_context = RecoveryContextV1::new_direct7(context_fields, &fixture.set).unwrap();
        assert!(load_recovery_zero_delta_cut_v1(
            root.path(),
            fixture.artifact_sha256,
            &fixture.cut,
            &wrong_context,
            &fixture.set,
        )
        .is_err());

        let mut park_mismatch_fields = fixture.context.fields();
        park_mismatch_fields.restart_park_artifact_sha256 = [0x83; 32];
        let park_mismatch_context =
            RecoveryContextV1::new_direct7(park_mismatch_fields, &fixture.set).unwrap();
        assert!(load_recovery_zero_delta_cut_v1(
            root.path(),
            fixture.artifact_sha256,
            &fixture.cut,
            &park_mismatch_context,
            &fixture.set,
        )
        .is_err());

        let mut ack_mismatch_fields = fixture.context.fields();
        ack_mismatch_fields.restart_parked_ack_artifact_sha256 = [0x84; 32];
        let ack_mismatch_context =
            RecoveryContextV1::new_direct7(ack_mismatch_fields, &fixture.set).unwrap();
        assert!(load_recovery_zero_delta_cut_v1(
            root.path(),
            fixture.artifact_sha256,
            &fixture.cut,
            &ack_mismatch_context,
            &fixture.set,
        )
        .is_err());

        let mut ack_admission_mismatch_fields = fixture.context.fields();
        ack_admission_mismatch_fields.restart_parked_ack_admission_set_sha256 = [0x85; 32];
        let ack_admission_mismatch_context =
            RecoveryContextV1::new_direct7(ack_admission_mismatch_fields, &fixture.set).unwrap();
        assert!(load_recovery_zero_delta_cut_v1(
            root.path(),
            fixture.artifact_sha256,
            &fixture.cut,
            &ack_admission_mismatch_context,
            &fixture.set,
        )
        .is_err());
        assert!(load_recovery_zero_delta_cut_v1(
            root.path(),
            fixture.artifact_sha256,
            &fixture.cut,
            &nonzero_context(&fixture),
            &fixture.set,
        )
        .is_err());

        let other = self::fixture();
        let mut other_validators = other.set.validators().to_vec();
        other_validators[6] = Validator::new(
            ValidatorId::new([0x91; 32]),
            ConsensusPublicKey::new(
                SigningKey::from_bytes(&[0x92; 32])
                    .verifying_key()
                    .to_bytes(),
            ),
            VotingPower::new(1).unwrap(),
        )
        .unwrap();
        let other_set = ValidatorSet::new(
            other.set.genesis_hash(),
            other.set.chain_id(),
            other.set.protocol_version(),
            other.set.epoch(),
            other.set.consensus_parameters_hash(),
            other_validators,
        )
        .unwrap();
        assert!(load_recovery_zero_delta_cut_v1(
            root.path(),
            fixture.artifact_sha256,
            &fixture.cut,
            &fixture.context,
            &other_set,
        )
        .is_err());
    }

    #[test]
    fn publication_reconciles_exact_next_linked_and_writing_response_loss() {
        let fixture = fixture();
        let bytes = fixture.cut.try_cev1_bytes().unwrap();

        let next_only = private_root();
        write_test_artifact(next_only.path(), RECOVERY_ZERO_DELTA_CUT_NEXT_V1, &bytes);
        drop(persist(&fixture, next_only.path()));
        assert!(!next_only
            .path()
            .join(RECOVERY_ZERO_DELTA_CUT_NEXT_V1)
            .exists());
        assert_eq!(
            fs::read(next_only.path().join(RECOVERY_ZERO_DELTA_CUT_FILE_V1)).unwrap(),
            bytes
        );

        let linked = private_root();
        let target = persist(&fixture, linked.path()).path_v1().to_path_buf();
        let next = linked.path().join(RECOVERY_ZERO_DELTA_CUT_NEXT_V1);
        fs::hard_link(&target, &next).unwrap();
        File::open(linked.path()).unwrap().sync_all().unwrap();
        drop(persist(&fixture, linked.path()));
        assert!(!next.exists());
        assert_eq!(fs::metadata(target).unwrap().nlink(), 1);

        for (attempt, prefix_length, incomplete_mode) in [
            (1u64, 0usize, Some(0o000)),
            (2, 1, None),
            (3, bytes.len() - 1, None),
            (4, bytes.len(), None),
        ] {
            let root = private_root();
            let writing_name = writing_file_name_v1(0x71a1, attempt);
            let writing = root.path().join(&writing_name);
            write_test_artifact(root.path(), &writing_name, &bytes[..prefix_length]);
            if let Some(mode) = incomplete_mode {
                fs::set_permissions(&writing, fs::Permissions::from_mode(mode)).unwrap();
            }
            drop(persist(&fixture, root.path()));
            assert!(!writing.exists());
            assert_eq!(
                fs::read(root.path().join(RECOVERY_ZERO_DELTA_CUT_FILE_V1)).unwrap(),
                bytes
            );
        }

        let writing_linked = private_root();
        let writing_name = writing_file_name_v1(0x71a2, 9);
        let writing = writing_linked.path().join(&writing_name);
        let next = writing_linked.path().join(RECOVERY_ZERO_DELTA_CUT_NEXT_V1);
        write_test_artifact(writing_linked.path(), &writing_name, &bytes);
        fs::hard_link(&writing, &next).unwrap();
        File::open(writing_linked.path())
            .unwrap()
            .sync_all()
            .unwrap();
        drop(persist(&fixture, writing_linked.path()));
        assert!(!writing.exists());
        assert!(!next.exists());
    }

    #[test]
    fn partial_or_foreign_publication_states_are_preserved_and_fail_closed() {
        let fixture = fixture();
        let bytes = fixture.cut.try_cev1_bytes().unwrap();

        let partial_next = private_root();
        write_test_artifact(
            partial_next.path(),
            RECOVERY_ZERO_DELTA_CUT_NEXT_V1,
            &bytes[..bytes.len() - 1],
        );
        assert!(persist_recovery_zero_delta_cut_v1(
            partial_next.path(),
            fixture.artifact_sha256,
            fixture.cut,
            &fixture.context,
            &fixture.set,
        )
        .is_err());
        assert!(partial_next
            .path()
            .join(RECOVERY_ZERO_DELTA_CUT_NEXT_V1)
            .exists());

        let partial_target = private_root();
        write_test_artifact(
            partial_target.path(),
            RECOVERY_ZERO_DELTA_CUT_FILE_V1,
            &bytes[..bytes.len() - 1],
        );
        assert!(persist_recovery_zero_delta_cut_v1(
            partial_target.path(),
            fixture.artifact_sha256,
            fixture.cut,
            &fixture.context,
            &fixture.set,
        )
        .is_err());

        let mutant_writing = private_root();
        let name = writing_file_name_v1(0x71a3, 10);
        let path = mutant_writing.path().join(&name);
        let mut mutant = bytes[..bytes.len() - 1].to_vec();
        mutant[0] ^= 1;
        write_test_artifact(mutant_writing.path(), &name, &mutant);
        assert!(persist_recovery_zero_delta_cut_v1(
            mutant_writing.path(),
            fixture.artifact_sha256,
            fixture.cut,
            &fixture.context,
            &fixture.set,
        )
        .is_err());
        assert_eq!(fs::read(path).unwrap(), mutant);

        let separate = private_root();
        let name = writing_file_name_v1(0x71a4, 11);
        write_test_artifact(separate.path(), &name, &bytes);
        write_test_artifact(separate.path(), RECOVERY_ZERO_DELTA_CUT_NEXT_V1, &bytes);
        assert!(persist_recovery_zero_delta_cut_v1(
            separate.path(),
            fixture.artifact_sha256,
            fixture.cut,
            &fixture.context,
            &fixture.set,
        )
        .is_err());
        assert!(separate.path().join(name).exists());
        assert!(separate
            .path()
            .join(RECOVERY_ZERO_DELTA_CUT_NEXT_V1)
            .exists());

        let multiple = private_root();
        let first = writing_file_name_v1(0x71a5, 12);
        let second = writing_file_name_v1(0x71a6, 13);
        write_test_artifact(multiple.path(), &first, &bytes[..1]);
        write_test_artifact(multiple.path(), &second, &bytes[..2]);
        assert!(persist_recovery_zero_delta_cut_v1(
            multiple.path(),
            fixture.artifact_sha256,
            fixture.cut,
            &fixture.context,
            &fixture.set,
        )
        .is_err());
        assert!(multiple.path().join(first).exists());
        assert!(multiple.path().join(second).exists());

        let target_and_writing = private_root();
        let writing = writing_file_name_v1(0x71a7, 14);
        write_test_artifact(
            target_and_writing.path(),
            RECOVERY_ZERO_DELTA_CUT_FILE_V1,
            &bytes,
        );
        write_test_artifact(target_and_writing.path(), &writing, &bytes[..1]);
        assert!(persist_recovery_zero_delta_cut_v1(
            target_and_writing.path(),
            fixture.artifact_sha256,
            fixture.cut,
            &fixture.context,
            &fixture.set,
        )
        .is_err());
        assert!(target_and_writing
            .path()
            .join(RECOVERY_ZERO_DELTA_CUT_FILE_V1)
            .exists());
        assert!(target_and_writing.path().join(writing).exists());

        let valid_and_malformed = private_root();
        let valid = writing_file_name_v1(0x71a8, 15);
        let malformed = format!("{RECOVERY_ZERO_DELTA_CUT_WRITING_PREFIX_V1}malformed");
        write_test_artifact(valid_and_malformed.path(), &valid, &bytes[..1]);
        write_test_artifact(valid_and_malformed.path(), &malformed, &bytes[..1]);
        assert!(persist_recovery_zero_delta_cut_v1(
            valid_and_malformed.path(),
            fixture.artifact_sha256,
            fixture.cut,
            &fixture.context,
            &fixture.set,
        )
        .is_err());
        assert!(valid_and_malformed.path().join(valid).exists());
        assert!(valid_and_malformed.path().join(malformed).exists());

        let writing_and_forbidden = private_root();
        let writing = writing_file_name_v1(0x71a9, 16);
        write_test_artifact(writing_and_forbidden.path(), &writing, &bytes[..1]);
        write_test_artifact(
            writing_and_forbidden.path(),
            RECOVERY_ZERO_DELTA_CUT_SIDECARS_V1[1],
            b"foreign",
        );
        assert!(persist_recovery_zero_delta_cut_v1(
            writing_and_forbidden.path(),
            fixture.artifact_sha256,
            fixture.cut,
            &fixture.context,
            &fixture.set,
        )
        .is_err());
        assert!(writing_and_forbidden.path().join(writing).exists());
        assert!(writing_and_forbidden
            .path()
            .join(RECOVERY_ZERO_DELTA_CUT_SIDECARS_V1[1])
            .exists());
    }

    #[test]
    fn fresh_revalidation_rejects_mutation_and_same_byte_replacement() {
        let fixture = fixture();
        let mutation_root = private_root();
        let stored = persist(&fixture, mutation_root.path());
        let path = stored.path_v1().to_path_buf();
        let mut bytes = fs::read(&path).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        fs::write(&path, bytes).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(stored.revalidate_fresh_v1(&fixture.set).is_err());

        let replacement_root = private_root();
        let stored = persist(&fixture, replacement_root.path());
        let path = stored.path_v1().to_path_buf();
        let bytes = fs::read(&path).unwrap();
        fs::rename(&path, replacement_root.path().join("displaced-cut.bin")).unwrap();
        write_test_artifact(
            replacement_root.path(),
            RECOVERY_ZERO_DELTA_CUT_FILE_V1,
            &bytes,
        );
        assert!(stored.revalidate_fresh_v1(&fixture.set).is_err());

        let parent = TempDir::new().unwrap();
        let live_root = parent.path().join("live-root");
        let displaced_root = parent.path().join("displaced-root");
        fs::create_dir(&live_root).unwrap();
        fs::set_permissions(&live_root, fs::Permissions::from_mode(0o700)).unwrap();
        let stored = persist(&fixture, &live_root);
        let bytes = fixture.cut.try_cev1_bytes().unwrap();
        fs::rename(&live_root, &displaced_root).unwrap();
        fs::create_dir(&live_root).unwrap();
        fs::set_permissions(&live_root, fs::Permissions::from_mode(0o700)).unwrap();
        write_test_artifact(&live_root, RECOVERY_ZERO_DELTA_CUT_FILE_V1, &bytes);
        assert!(stored.revalidate_fresh_v1(&fixture.set).is_err());
    }

    #[test]
    fn filesystem_policy_rejects_symlink_hardlink_modes_sizes_and_sidecars() {
        let fixture = fixture();

        let symlink_root = private_root();
        symlink(
            "/dev/null",
            symlink_root.path().join(RECOVERY_ZERO_DELTA_CUT_FILE_V1),
        )
        .unwrap();
        assert!(load_recovery_zero_delta_cut_v1(
            symlink_root.path(),
            fixture.artifact_sha256,
            &fixture.cut,
            &fixture.context,
            &fixture.set,
        )
        .is_err());

        let hardlink_root = private_root();
        let stored = persist(&fixture, hardlink_root.path());
        fs::hard_link(
            stored.path_v1(),
            hardlink_root.path().join("foreign-hardlink.bin"),
        )
        .unwrap();
        assert!(stored.revalidate_fresh_v1(&fixture.set).is_err());

        let artifact_mode_root = private_root();
        let stored = persist(&fixture, artifact_mode_root.path());
        fs::set_permissions(stored.path_v1(), fs::Permissions::from_mode(0o640)).unwrap();
        assert!(stored.revalidate_fresh_v1(&fixture.set).is_err());

        let root_mode = private_root();
        fs::set_permissions(root_mode.path(), fs::Permissions::from_mode(0o750)).unwrap();
        assert!(persist_recovery_zero_delta_cut_v1(
            root_mode.path(),
            fixture.artifact_sha256,
            fixture.cut,
            &fixture.context,
            &fixture.set,
        )
        .is_err());

        let oversized = private_root();
        write_test_artifact(
            oversized.path(),
            RECOVERY_ZERO_DELTA_CUT_FILE_V1,
            &vec![0u8; MAX_RECOVERY_ZERO_DELTA_CUT_BYTES_V1 + 1],
        );
        assert!(load_recovery_zero_delta_cut_v1(
            oversized.path(),
            fixture.artifact_sha256,
            &fixture.cut,
            &fixture.context,
            &fixture.set,
        )
        .is_err());

        let sidecar_root = private_root();
        let stored = persist(&fixture, sidecar_root.path());
        symlink(
            RECOVERY_ZERO_DELTA_CUT_FILE_V1,
            sidecar_root
                .path()
                .join(RECOVERY_ZERO_DELTA_CUT_SIDECARS_V1[1]),
        )
        .unwrap();
        assert!(stored.revalidate_fresh_v1(&fixture.set).is_err());

        let root_symlink_parent = TempDir::new().unwrap();
        let real_parent = root_symlink_parent.path().join("real-parent");
        let real_root = real_parent.join("private-root");
        let alias_parent = root_symlink_parent.path().join("alias-parent");
        let alias_root = alias_parent.join("private-root");
        fs::create_dir(&real_parent).unwrap();
        fs::create_dir(&real_root).unwrap();
        fs::set_permissions(&real_root, fs::Permissions::from_mode(0o700)).unwrap();
        symlink(&real_parent, &alias_parent).unwrap();
        assert!(persist_recovery_zero_delta_cut_v1(
            &alias_root,
            fixture.artifact_sha256,
            fixture.cut,
            &fixture.context,
            &fixture.set,
        )
        .is_err());
    }

    #[test]
    fn exact_decode_rejects_trailing_bytes_even_with_matching_hash() {
        let fixture = fixture();
        let root = private_root();
        let mut trailing = fixture.cut.try_cev1_bytes().unwrap();
        trailing.push(0);
        write_test_artifact(root.path(), RECOVERY_ZERO_DELTA_CUT_FILE_V1, &trailing);
        let mut context_fields = fixture.context.fields();
        context_fields.caught_up_cut_artifact_sha256 = sha256_v1(&trailing);
        let context = RecoveryContextV1::new_direct7(context_fields, &fixture.set).unwrap();
        assert!(load_recovery_zero_delta_cut_v1(
            root.path(),
            sha256_v1(&trailing),
            &fixture.cut,
            &context,
            &fixture.set,
        )
        .is_err());
    }

    #[test]
    fn store_has_no_process_or_recovery_barrier_authority_surface() {
        let source = include_str!("recovery_zero_delta_store.rs");
        let normal = &source[..source.find("#[cfg(test)]").unwrap()];
        for forbidden in [
            "SigningKey",
            "fn activate",
            "fn arm",
            "RecoveryReadySetV1",
            "RecoveryStartCertificateV1",
            "TcpStream",
            "UdpSocket",
            "RuntimeEventJournal",
            "OpenOptions::new().truncate",
            "set_len(",
        ] {
            assert!(
                !normal.contains(forbidden),
                "normal zero-delta store contains forbidden authority token {forbidden}"
            );
        }
        assert!(!normal.contains("pub fn write"));
        assert!(!normal.contains("impl Clone for StoredRecoveryZeroDeltaCutV1"));
    }
}
