//! Durable storage for authenticated recovery ReadySet and Start artifacts.
//!
//! The store publishes only already verified typed values at two fixed private
//! paths.  It retains open directory/file handles and exact filesystem
//! identities, and every load or fresh revalidation repeats strict Ed25519
//! decoding against a caller-supplied expected content address and recovery
//! context.  This module has no signing, journal, network, timer, process, or
//! activation API.

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
use trnm_consensus_crypto::StrictEd25519Verifier;
use trnm_consensus_types::{
    decode_recovery_ready_set_v1_exact, decode_recovery_start_certificate_v1_exact,
    RecoveryContextV1, RecoveryReadySetV1, RecoveryStartCertificateV1, ValidatorSet,
    MAX_RECOVERY_READY_SET_BYTES_V1, MAX_RECOVERY_START_CERTIFICATE_BYTES_V1,
};

const RECOVERY_READY_SET_FILE_V1: &str = "recovery-ready-set-v1.bin";
const RECOVERY_START_CERTIFICATE_FILE_V1: &str = "recovery-start-certificate-v1.bin";
const RECOVERY_READY_SET_SIDECARS_V1: [&str; 3] = [
    "recovery-ready-set-v1.next",
    "recovery-ready-set-v1.tmp",
    "recovery-ready-set-v1.lock",
];
const RECOVERY_START_CERTIFICATE_SIDECARS_V1: [&str; 3] = [
    "recovery-start-certificate-v1.next",
    "recovery-start-certificate-v1.tmp",
    "recovery-start-certificate-v1.lock",
];
const RECOVERY_READY_SET_WRITING_PREFIX_V1: &str = "recovery-ready-set-v1.writing.";
const RECOVERY_START_CERTIFICATE_WRITING_PREFIX_V1: &str = "recovery-start-certificate-v1.writing.";
static RECOVERY_WRITING_ATTEMPT_V1: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RecoveryArtifactKindV1 {
    ReadySet,
    StartCertificate,
}

impl RecoveryArtifactKindV1 {
    const fn file_name(self) -> &'static str {
        match self {
            Self::ReadySet => RECOVERY_READY_SET_FILE_V1,
            Self::StartCertificate => RECOVERY_START_CERTIFICATE_FILE_V1,
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::ReadySet => "recovery ReadySet",
            Self::StartCertificate => "recovery Start certificate",
        }
    }

    const fn next_file_name(self) -> &'static str {
        match self {
            Self::ReadySet => "recovery-ready-set-v1.next",
            Self::StartCertificate => "recovery-start-certificate-v1.next",
        }
    }

    const fn writing_prefix(self) -> &'static str {
        match self {
            Self::ReadySet => RECOVERY_READY_SET_WRITING_PREFIX_V1,
            Self::StartCertificate => RECOVERY_START_CERTIFICATE_WRITING_PREFIX_V1,
        }
    }

    const fn maximum_bytes(self) -> usize {
        match self {
            Self::ReadySet => MAX_RECOVERY_READY_SET_BYTES_V1,
            Self::StartCertificate => MAX_RECOVERY_START_CERTIFICATE_BYTES_V1,
        }
    }
}

/// Non-Clone proof that one exact ReadySet remains pinned at its immutable
/// private path and has survived strict canonical fresh readback.
#[must_use = "stored recovery ReadySet ownership must be retained across the barrier"]
pub(crate) struct StoredRecoveryReadySetV1 {
    pinned: PinnedRecoveryArtifactV1,
    value: RecoveryReadySetV1,
    artifact_sha256: [u8; 32],
}

impl std::fmt::Debug for StoredRecoveryReadySetV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("StoredRecoveryReadySetV1")
            .field("path", &self.pinned.path)
            .field("artifact_sha256", &self.artifact_sha256)
            .field("context", self.value.context())
            .finish_non_exhaustive()
    }
}

impl StoredRecoveryReadySetV1 {
    pub(crate) const fn value_v1(&self) -> &RecoveryReadySetV1 {
        &self.value
    }

    pub(crate) const fn context_v1(&self) -> &RecoveryContextV1 {
        self.value.context()
    }

    pub(crate) const fn artifact_sha256_v1(&self) -> [u8; 32] {
        self.artifact_sha256
    }

    pub(crate) fn path_v1(&self) -> &Path {
        &self.pinned.path
    }

    pub(crate) fn revalidate_fresh_v1(&self, validator_set: &ValidatorSet) -> Result<()> {
        self.value
            .context()
            .validate_direct7(validator_set)
            .map_err(|error| {
                anyhow::anyhow!("validate stored recovery ReadySet context: {error}")
            })?;
        self.value
            .verify(validator_set, &StrictEd25519Verifier)
            .map_err(|error| anyhow::anyhow!("verify retained recovery ReadySet: {error}"))?;
        self.pinned.revalidate_held_v1()?;
        let (fresh, bytes, observed_sha256) =
            open_and_read_artifact_v1(&self.pinned.root_path, RecoveryArtifactKindV1::ReadySet)?;
        ensure!(
            fresh.same_identity_v1(&self.pinned),
            "recovery ReadySet path or open-file identity was replaced"
        );
        ensure!(
            observed_sha256 == self.artifact_sha256,
            "recovery ReadySet content address changed"
        );
        let decoded =
            decode_recovery_ready_set_v1_exact(&bytes, validator_set, &StrictEd25519Verifier)
                .map_err(|error| anyhow::anyhow!("fresh-decode recovery ReadySet: {error}"))?;
        ensure!(
            decoded.context() == self.value.context() && decoded == self.value,
            "fresh recovery ReadySet differs from retained typed value"
        );
        fresh.revalidate_held_v1()?;
        self.pinned.revalidate_held_v1()
    }
}

/// Non-Clone proof that one exact Start certificate, including its complete
/// ReadySet, remains pinned and strictly revalidatable.
#[must_use = "stored recovery Start ownership must be retained across the barrier"]
pub(crate) struct StoredRecoveryStartCertificateV1 {
    ready: StoredRecoveryReadySetV1,
    pinned: PinnedRecoveryArtifactV1,
    value: RecoveryStartCertificateV1,
    artifact_sha256: [u8; 32],
}

impl std::fmt::Debug for StoredRecoveryStartCertificateV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("StoredRecoveryStartCertificateV1")
            .field("path", &self.pinned.path)
            .field("artifact_sha256", &self.artifact_sha256)
            .field(
                "ready_set_artifact_sha256",
                &self.ready.artifact_sha256_v1(),
            )
            .field("context", self.value.context())
            .finish_non_exhaustive()
    }
}

impl StoredRecoveryStartCertificateV1 {
    pub(crate) const fn value_v1(&self) -> &RecoveryStartCertificateV1 {
        &self.value
    }

    pub(crate) const fn context_v1(&self) -> &RecoveryContextV1 {
        self.value.context()
    }

    pub(crate) const fn artifact_sha256_v1(&self) -> [u8; 32] {
        self.artifact_sha256
    }

    pub(crate) const fn ready_set_artifact_sha256_v1(&self) -> [u8; 32] {
        self.ready.artifact_sha256_v1()
    }

    pub(crate) const fn ready_set_v1(&self) -> &RecoveryReadySetV1 {
        self.ready.value_v1()
    }

    pub(crate) fn path_v1(&self) -> &Path {
        &self.pinned.path
    }

    pub(crate) fn revalidate_fresh_v1(&self, validator_set: &ValidatorSet) -> Result<()> {
        self.ready
            .revalidate_fresh_v1(validator_set)
            .context("revalidate durable ReadySet before recovery Start")?;
        self.value
            .context()
            .validate_direct7(validator_set)
            .map_err(|error| anyhow::anyhow!("validate stored recovery Start context: {error}"))?;
        self.value
            .verify(validator_set, &StrictEd25519Verifier)
            .map_err(|error| anyhow::anyhow!("verify retained recovery Start: {error}"))?;
        self.pinned.revalidate_held_v1()?;
        let (fresh, bytes, observed_sha256) = open_and_read_artifact_v1(
            &self.pinned.root_path,
            RecoveryArtifactKindV1::StartCertificate,
        )?;
        ensure!(
            fresh.same_identity_v1(&self.pinned),
            "recovery Start path or open-file identity was replaced"
        );
        ensure!(
            observed_sha256 == self.artifact_sha256,
            "recovery Start content address changed"
        );
        let decoded = decode_recovery_start_certificate_v1_exact(
            &bytes,
            validator_set,
            &StrictEd25519Verifier,
        )
        .map_err(|error| anyhow::anyhow!("fresh-decode recovery Start: {error}"))?;
        ensure!(
            decoded.context() == self.value.context()
                && decoded == self.value
                && decoded.ready_set() == self.ready.value_v1(),
            "fresh recovery Start differs from retained typed value"
        );
        fresh.revalidate_held_v1()?;
        self.pinned.revalidate_held_v1()?;
        self.ready
            .revalidate_fresh_v1(validator_set)
            .context("revalidate durable ReadySet after recovery Start")
    }
}

/// Strictly verifies and create-new persists one typed ReadySet.
pub(crate) fn persist_recovery_ready_set_v1(
    private_root: &Path,
    value: RecoveryReadySetV1,
    validator_set: &ValidatorSet,
) -> Result<StoredRecoveryReadySetV1> {
    value
        .verify(validator_set, &StrictEd25519Verifier)
        .map_err(|error| anyhow::anyhow!("verify recovery ReadySet before persistence: {error}"))?;
    let expected_context = *value.context();
    let bytes = value
        .try_cev1_bytes()
        .map_err(|error| anyhow::anyhow!("encode recovery ReadySet: {error}"))?;
    validate_encoded_bound_v1(
        &bytes,
        RecoveryArtifactKindV1::ReadySet.maximum_bytes(),
        RecoveryArtifactKindV1::ReadySet.label(),
    )?;
    let expected_sha256 = sha256_v1(&bytes);
    publish_create_new_v1(private_root, RecoveryArtifactKindV1::ReadySet, &bytes)?;
    let stored = load_recovery_ready_set_v1(
        private_root,
        expected_sha256,
        &expected_context,
        validator_set,
    )?;
    ensure!(
        stored.value == value,
        "stored recovery ReadySet differs from verified input"
    );
    Ok(stored)
}

/// Reopens only the fixed ReadySet path and joins it to caller-authenticated
/// expected content address, context, validator set, and strict verifier.
pub(crate) fn load_recovery_ready_set_v1(
    private_root: &Path,
    expected_artifact_sha256: [u8; 32],
    expected_context: &RecoveryContextV1,
    validator_set: &ValidatorSet,
) -> Result<StoredRecoveryReadySetV1> {
    validate_expected_v1(expected_artifact_sha256, expected_context, validator_set)?;
    let (pinned, bytes, observed_sha256) =
        open_and_read_artifact_v1(private_root, RecoveryArtifactKindV1::ReadySet)?;
    ensure!(
        observed_sha256 == expected_artifact_sha256,
        "recovery ReadySet SHA-256 differs from expected content address"
    );
    let value = decode_recovery_ready_set_v1_exact(&bytes, validator_set, &StrictEd25519Verifier)
        .map_err(|error| anyhow::anyhow!("decode stored recovery ReadySet: {error}"))?;
    ensure!(
        value.context() == expected_context,
        "stored recovery ReadySet context differs from expected context"
    );
    pinned.revalidate_held_v1()?;
    Ok(StoredRecoveryReadySetV1 {
        pinned,
        value,
        artifact_sha256: observed_sha256,
    })
}

/// Strictly verifies and create-new persists one typed Start certificate.
pub(crate) fn persist_recovery_start_certificate_v1(
    private_root: &Path,
    value: RecoveryStartCertificateV1,
    ready: StoredRecoveryReadySetV1,
    validator_set: &ValidatorSet,
) -> Result<StoredRecoveryStartCertificateV1> {
    ready
        .revalidate_fresh_v1(validator_set)
        .context("revalidate durable ReadySet before Start persistence")?;
    value
        .verify(validator_set, &StrictEd25519Verifier)
        .map_err(|error| anyhow::anyhow!("verify recovery Start before persistence: {error}"))?;
    ensure!(
        value.ready_set() == ready.value_v1(),
        "recovery Start does not embed the exact durable ReadySet"
    );
    let expected_context = *value.context();
    let bytes = value
        .try_cev1_bytes()
        .map_err(|error| anyhow::anyhow!("encode recovery Start: {error}"))?;
    validate_encoded_bound_v1(
        &bytes,
        RecoveryArtifactKindV1::StartCertificate.maximum_bytes(),
        RecoveryArtifactKindV1::StartCertificate.label(),
    )?;
    let expected_sha256 = sha256_v1(&bytes);
    publish_create_new_v1(
        private_root,
        RecoveryArtifactKindV1::StartCertificate,
        &bytes,
    )?;
    let stored = load_recovery_start_certificate_with_ready_v1(
        private_root,
        expected_sha256,
        &expected_context,
        ready,
        validator_set,
    )?;
    ensure!(
        stored.value == value,
        "stored recovery Start differs from verified input"
    );
    Ok(stored)
}

/// Reopens only the fixed Start path and retains the complete decoded
/// ReadySet inside the returned non-Clone owner.
pub(crate) fn load_recovery_start_certificate_v1(
    private_root: &Path,
    expected_artifact_sha256: [u8; 32],
    expected_ready_set_artifact_sha256: [u8; 32],
    expected_context: &RecoveryContextV1,
    validator_set: &ValidatorSet,
) -> Result<StoredRecoveryStartCertificateV1> {
    let ready = load_recovery_ready_set_v1(
        private_root,
        expected_ready_set_artifact_sha256,
        expected_context,
        validator_set,
    )
    .context("load exact durable ReadySet before recovery Start")?;
    load_recovery_start_certificate_with_ready_v1(
        private_root,
        expected_artifact_sha256,
        expected_context,
        ready,
        validator_set,
    )
}

fn load_recovery_start_certificate_with_ready_v1(
    private_root: &Path,
    expected_artifact_sha256: [u8; 32],
    expected_context: &RecoveryContextV1,
    ready: StoredRecoveryReadySetV1,
    validator_set: &ValidatorSet,
) -> Result<StoredRecoveryStartCertificateV1> {
    validate_expected_v1(expected_artifact_sha256, expected_context, validator_set)?;
    ready
        .revalidate_fresh_v1(validator_set)
        .context("revalidate durable ReadySet while loading recovery Start")?;
    ensure!(
        ready.context_v1() == expected_context,
        "durable ReadySet context differs from expected recovery Start context"
    );
    let (pinned, bytes, observed_sha256) =
        open_and_read_artifact_v1(private_root, RecoveryArtifactKindV1::StartCertificate)?;
    ensure!(
        observed_sha256 == expected_artifact_sha256,
        "recovery Start SHA-256 differs from expected content address"
    );
    let value =
        decode_recovery_start_certificate_v1_exact(&bytes, validator_set, &StrictEd25519Verifier)
            .map_err(|error| anyhow::anyhow!("decode stored recovery Start: {error}"))?;
    ensure!(
        value.context() == expected_context && value.ready_set() == ready.value_v1(),
        "stored recovery Start differs from expected context or durable ReadySet"
    );
    pinned.revalidate_held_v1()?;
    ready
        .revalidate_fresh_v1(validator_set)
        .context("revalidate durable ReadySet after loading recovery Start")?;
    Ok(StoredRecoveryStartCertificateV1 {
        ready,
        pinned,
        value,
        artifact_sha256: observed_sha256,
    })
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
            mode: metadata.permissions().mode() & 0o777,
        }
    }

    fn matches_metadata_v1(self, metadata: &fs::Metadata) -> bool {
        metadata.is_dir()
            && self.device == metadata.dev()
            && self.inode == metadata.ino()
            && self.uid == metadata.uid()
            && self.mode == metadata.permissions().mode() & 0o777
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
}

impl ArtifactIdentityV1 {
    fn from_metadata_v1(metadata: &fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            uid: metadata.uid(),
            mode: metadata.permissions().mode() & 0o777,
            links: metadata.nlink(),
            length: metadata.len(),
            modified_seconds: metadata.mtime(),
            modified_nanoseconds: metadata.mtime_nsec(),
        }
    }

    fn matches_metadata_v1(self, metadata: &fs::Metadata) -> bool {
        metadata.is_file()
            && self.device == metadata.dev()
            && self.inode == metadata.ino()
            && self.uid == metadata.uid()
            && self.mode == metadata.permissions().mode() & 0o777
            && self.links == metadata.nlink()
            && self.length == metadata.len()
            && self.modified_seconds == metadata.mtime()
            && self.modified_nanoseconds == metadata.mtime_nsec()
    }
}

struct PinnedRecoveryArtifactV1 {
    kind: RecoveryArtifactKindV1,
    root_path: PathBuf,
    path: PathBuf,
    root_file: File,
    artifact_file: File,
    root_identity: DirectoryIdentityV1,
    artifact_identity: ArtifactIdentityV1,
}

impl std::fmt::Debug for PinnedRecoveryArtifactV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PinnedRecoveryArtifactV1")
            .field("kind", &self.kind)
            .field("root_path", &self.root_path)
            .field("path", &self.path)
            .field("root_identity", &self.root_identity)
            .field("artifact_identity", &self.artifact_identity)
            .finish_non_exhaustive()
    }
}

impl PinnedRecoveryArtifactV1 {
    fn same_identity_v1(&self, other: &Self) -> bool {
        self.kind == other.kind
            && self.root_path == other.root_path
            && self.path == other.path
            && self.root_identity == other.root_identity
            && self.artifact_identity == other.artifact_identity
    }

    fn revalidate_held_v1(&self) -> Result<()> {
        ensure_no_publication_sidecars_v1(&self.root_path)?;
        ensure!(
            self.path == self.root_path.join(self.kind.file_name())
                && self.path.file_name() == Some(OsStr::new(self.kind.file_name())),
            "pinned recovery artifact escaped its fixed private path"
        );

        let held_root = self
            .root_file
            .metadata()
            .context("inspect held recovery private root")?;
        validate_private_root_metadata_v1(&held_root)?;
        ensure!(
            self.root_identity.matches_metadata_v1(&held_root),
            "held recovery private root identity changed"
        );
        let (fresh_root_file, fresh_root_identity) = open_private_root_v1(&self.root_path)?;
        ensure!(
            fresh_root_identity == self.root_identity,
            "recovery private root path was replaced"
        );
        drop(fresh_root_file);

        let held_artifact = self
            .artifact_file
            .metadata()
            .context("inspect held recovery artifact")?;
        validate_private_artifact_metadata_v1(
            &held_artifact,
            self.root_identity.uid,
            self.kind.maximum_bytes(),
            self.kind.label(),
        )?;
        ensure!(
            self.artifact_identity.matches_metadata_v1(&held_artifact),
            "held recovery artifact identity changed"
        );
        let path_metadata = fs::symlink_metadata(&self.path)
            .with_context(|| format!("reinspect pinned {} path", self.kind.label()))?;
        ensure!(
            !path_metadata.file_type().is_symlink(),
            "pinned {} path became a symlink",
            self.kind.label()
        );
        validate_private_artifact_metadata_v1(
            &path_metadata,
            self.root_identity.uid,
            self.kind.maximum_bytes(),
            self.kind.label(),
        )?;
        ensure!(
            self.artifact_identity.matches_metadata_v1(&path_metadata),
            "pinned {} path was replaced or mutated",
            self.kind.label()
        );
        Ok(())
    }
}

fn validate_expected_v1(
    expected_artifact_sha256: [u8; 32],
    expected_context: &RecoveryContextV1,
    validator_set: &ValidatorSet,
) -> Result<()> {
    ensure!(
        expected_artifact_sha256 != [0; 32],
        "expected recovery artifact SHA-256 is zero"
    );
    expected_context
        .validate_direct7(validator_set)
        .map_err(|error| anyhow::anyhow!("validate expected recovery context: {error}"))
}

fn validate_encoded_bound_v1(bytes: &[u8], maximum: usize, label: &str) -> Result<()> {
    ensure!(
        !bytes.is_empty() && bytes.len() <= maximum,
        "{label} canonical bytes cross the durable bound"
    );
    Ok(())
}

fn sha256_v1(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn writing_file_name_v1(kind: RecoveryArtifactKindV1, process_id: u32, attempt: u64) -> String {
    format!(
        "{}{:08x}.{:016x}",
        kind.writing_prefix(),
        process_id,
        attempt
    )
}

fn next_writing_file_name_v1(kind: RecoveryArtifactKindV1) -> String {
    writing_file_name_v1(
        kind,
        process::id(),
        RECOVERY_WRITING_ATTEMPT_V1.fetch_add(1, Ordering::Relaxed),
    )
}

fn is_lower_hex_digit_v1(byte: u8) -> bool {
    byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
}

fn writing_candidate_kind_v1(name: &OsStr) -> Option<(RecoveryArtifactKindV1, bool)> {
    let name = name.as_bytes();
    for kind in [
        RecoveryArtifactKindV1::ReadySet,
        RecoveryArtifactKindV1::StartCertificate,
    ] {
        let prefix = kind.writing_prefix().as_bytes();
        if !name.starts_with(prefix) {
            continue;
        }
        let suffix = &name[prefix.len()..];
        let canonical = suffix.len() == 25
            && suffix[8] == b'.'
            && suffix[..8].iter().copied().all(is_lower_hex_digit_v1)
            && suffix[..8].iter().any(|byte| *byte != b'0')
            && suffix[9..].iter().copied().all(is_lower_hex_digit_v1);
        return Some((kind, canonical));
    }
    None
}

fn revalidate_publication_root_v1(
    private_root: &Path,
    root_file: &File,
    root_identity: DirectoryIdentityV1,
) -> Result<()> {
    let held_root = root_file
        .metadata()
        .context("reinspect held recovery publication root")?;
    ensure!(
        root_identity.matches_metadata_v1(&held_root),
        "recovery private root changed during publication"
    );
    let path_root =
        fs::symlink_metadata(private_root).context("reinspect recovery publication root path")?;
    ensure!(
        !path_root.file_type().is_symlink() && root_identity.matches_metadata_v1(&path_root),
        "recovery private root path was replaced during publication"
    );
    Ok(())
}

fn cleanup_one_interrupted_writing_candidate_v1(
    private_root: &Path,
    root_file: &File,
    root_identity: DirectoryIdentityV1,
    kind: RecoveryArtifactKindV1,
    expected_bytes: &[u8],
    writing: &Path,
    next: &Path,
) -> Result<()> {
    let before = fs::symlink_metadata(writing).with_context(|| {
        format!(
            "inspect interrupted {} writing candidate {}",
            kind.label(),
            writing.display()
        )
    })?;
    let mode = before.permissions().mode() & 0o777;
    ensure!(
        !before.file_type().is_symlink()
            && before.is_file()
            && before.uid() == root_identity.uid
            && mode & !0o600 == 0
            && matches!(before.nlink(), 1 | 2)
            && before.len() <= u64::try_from(expected_bytes.len()).unwrap_or(u64::MAX),
        "interrupted {} writing candidate has foreign metadata",
        kind.label()
    );
    let expected_identity = ArtifactIdentityV1::from_metadata_v1(&before);

    let observed = if before.len() == 0 {
        Vec::new()
    } else {
        ensure!(
            mode == 0o600,
            "nonempty interrupted {} writing candidate has incomplete permissions",
            kind.label()
        );
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(writing)
            .with_context(|| {
                format!(
                    "open interrupted {} writing candidate {}",
                    kind.label(),
                    writing.display()
                )
            })?;
        let opened = file.metadata().with_context(|| {
            format!(
                "inspect opened interrupted {} writing candidate",
                kind.label()
            )
        })?;
        ensure!(
            expected_identity.matches_metadata_v1(&opened),
            "interrupted {} writing candidate changed while opening",
            kind.label()
        );
        let mut observed = Vec::with_capacity(
            usize::try_from(before.len()).context("writing candidate length overflows")?,
        );
        Read::by_ref(&mut file)
            .take(u64::try_from(expected_bytes.len()).unwrap_or(u64::MAX) + 1)
            .read_to_end(&mut observed)
            .with_context(|| format!("read interrupted {} writing candidate", kind.label()))?;
        let after = file.metadata().with_context(|| {
            format!(
                "reinspect opened interrupted {} writing candidate",
                kind.label()
            )
        })?;
        ensure!(
            expected_identity.matches_metadata_v1(&after),
            "interrupted {} writing candidate changed while reading",
            kind.label()
        );
        observed
    };
    ensure!(
        expected_bytes.starts_with(&observed),
        "interrupted {} writing candidate is not an exact canonical prefix",
        kind.label()
    );

    let next_exists = path_exists_no_follow_v1(next, kind.label())?;
    match expected_identity.links {
        1 => ensure!(
            !next_exists,
            "unlinked {} writing candidate coexists with a foreign fixed candidate",
            kind.label()
        ),
        2 => {
            ensure!(
                next_exists && observed == expected_bytes,
                "linked {} writing candidate is partial or lacks its exact fixed link",
                kind.label()
            );
            let next_identity = validate_publication_candidate_v1(
                next,
                root_identity.uid,
                kind,
                expected_bytes,
                2,
            )?;
            ensure!(
                next_identity == expected_identity,
                "linked {} writing candidate and fixed candidate are different inodes",
                kind.label()
            );
        }
        _ => unreachable!("writing candidate link count was checked above"),
    }

    let path_after = fs::symlink_metadata(writing).with_context(|| {
        format!(
            "reinspect interrupted {} writing candidate path",
            kind.label()
        )
    })?;
    ensure!(
        expected_identity.matches_metadata_v1(&path_after),
        "interrupted {} writing candidate path was replaced",
        kind.label()
    );
    revalidate_publication_root_v1(private_root, root_file, root_identity)?;
    fs::remove_file(writing).with_context(|| {
        format!(
            "remove authenticated interrupted {} writing candidate",
            kind.label()
        )
    })?;
    root_file
        .sync_all()
        .with_context(|| format!("fsync cleaned {} writing candidate", kind.label()))?;
    revalidate_publication_root_v1(private_root, root_file, root_identity)?;
    if expected_identity.links == 2 {
        validate_publication_candidate_v1(next, root_identity.uid, kind, expected_bytes, 1)?;
    }
    Ok(())
}

fn cleanup_interrupted_writing_candidates_v1(
    private_root: &Path,
    root_file: &File,
    root_identity: DirectoryIdentityV1,
    kind: RecoveryArtifactKindV1,
    expected_bytes: &[u8],
    next: &Path,
) -> Result<()> {
    let mut names = fs::read_dir(private_root)
        .context("scan recovery private root for interrupted writing candidates")?
        .map(|entry| entry.map(|entry| entry.file_name()))
        .collect::<std::io::Result<Vec<_>>>()
        .context("read recovery private-root writing candidate names")?;
    names.sort();
    for name in names {
        let Some((observed_kind, canonical)) = writing_candidate_kind_v1(&name) else {
            continue;
        };
        let writing = private_root.join(&name);
        ensure!(
            canonical,
            "malformed recovery writing candidate is preserved: {}",
            writing.display()
        );
        ensure!(
            observed_kind == kind,
            "foreign recovery writing candidate is preserved: {}",
            writing.display()
        );
        cleanup_one_interrupted_writing_candidate_v1(
            private_root,
            root_file,
            root_identity,
            kind,
            expected_bytes,
            &writing,
            next,
        )?;
    }
    Ok(())
}

fn create_complete_writing_candidate_v1(
    private_root: &Path,
    expected_uid: u32,
    kind: RecoveryArtifactKindV1,
    bytes: &[u8],
) -> Result<PathBuf> {
    let name = next_writing_file_name_v1(kind);
    let writing = private_root.join(&name);
    ensure!(
        writing.parent() == Some(private_root)
            && writing.file_name() == Some(OsStr::new(&name))
            && writing_candidate_kind_v1(OsStr::new(&name)) == Some((kind, true)),
        "{} writing candidate escaped its unique private path",
        kind.label()
    );
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(&writing)
        .with_context(|| format!("create-new unique {} writing candidate", kind.label()))?;
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .with_context(|| format!("chmod unique {} writing candidate", kind.label()))?;
    file.write_all(bytes)
        .with_context(|| format!("write unique {} writing candidate", kind.label()))?;
    file.sync_all()
        .with_context(|| format!("fsync unique {} writing candidate", kind.label()))?;
    drop(file);
    validate_publication_candidate_v1(&writing, expected_uid, kind, bytes, 1)?;
    Ok(writing)
}

fn publish_complete_writing_candidate_v1(
    private_root: &Path,
    root_file: &File,
    root_identity: DirectoryIdentityV1,
    kind: RecoveryArtifactKindV1,
    bytes: &[u8],
    writing: &Path,
    next: &Path,
) -> Result<()> {
    validate_publication_candidate_v1(writing, root_identity.uid, kind, bytes, 1)?;
    match fs::hard_link(writing, next) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "link complete {} writing candidate no-replace",
                    kind.label()
                )
            })
        }
    }
    let writing_linked =
        validate_publication_candidate_v1(writing, root_identity.uid, kind, bytes, 2)?;
    let next_metadata = fs::symlink_metadata(next)
        .with_context(|| format!("inspect linked fixed {} candidate", kind.label()))?;
    ensure!(
        !next_metadata.file_type().is_symlink()
            && writing_linked.matches_metadata_v1(&next_metadata),
        "{} writing candidate did not link to the exact fixed candidate inode",
        kind.label()
    );
    root_file
        .sync_all()
        .with_context(|| format!("fsync linked {} writing candidate", kind.label()))?;
    let writing_before_unlink =
        validate_publication_candidate_v1(writing, root_identity.uid, kind, bytes, 2)?;
    let next_before_unlink =
        validate_publication_candidate_v1(next, root_identity.uid, kind, bytes, 2)?;
    ensure!(
        writing_before_unlink == next_before_unlink,
        "{} writing and fixed candidates diverged before unlink",
        kind.label()
    );
    revalidate_publication_root_v1(private_root, root_file, root_identity)?;
    fs::remove_file(writing)
        .with_context(|| format!("remove linked unique {} writing candidate", kind.label()))?;
    root_file
        .sync_all()
        .with_context(|| format!("fsync fixed {} candidate publication", kind.label()))?;
    revalidate_publication_root_v1(private_root, root_file, root_identity)?;
    validate_publication_candidate_v1(next, root_identity.uid, kind, bytes, 1)?;
    Ok(())
}

fn publish_create_new_v1(
    private_root: &Path,
    kind: RecoveryArtifactKindV1,
    bytes: &[u8],
) -> Result<()> {
    validate_encoded_bound_v1(bytes, kind.maximum_bytes(), kind.label())?;
    let (root_file, root_identity) = open_private_root_v1(private_root)?;
    root_file
        .try_lock()
        .context("lock recovery private root publication lifetime")?;
    let target = private_root.join(kind.file_name());
    let next = private_root.join(kind.next_file_name());
    ensure!(
        target.parent() == Some(private_root)
            && target.file_name() == Some(OsStr::new(kind.file_name()))
            && next.parent() == Some(private_root)
            && next.file_name() == Some(OsStr::new(kind.next_file_name())),
        "recovery artifact target escaped its fixed private path"
    );
    cleanup_interrupted_writing_candidates_v1(
        private_root,
        &root_file,
        root_identity,
        kind,
        bytes,
        &next,
    )?;
    ensure_no_publication_sidecars_except_v1(private_root, Some(kind.next_file_name()))?;

    let target_exists = path_exists_no_follow_v1(&target, kind.label())?;
    let next_exists = path_exists_no_follow_v1(&next, kind.label())?;
    if target_exists && !next_exists {
        drop(root_file);
        let (_, observed, _) = open_and_read_artifact_v1(private_root, kind)?;
        ensure!(
            observed == bytes,
            "existing {} differs from the exact idempotent input",
            kind.label()
        );
        return Ok(());
    }

    if !next_exists {
        let writing =
            create_complete_writing_candidate_v1(private_root, root_identity.uid, kind, bytes)?;
        publish_complete_writing_candidate_v1(
            private_root,
            &root_file,
            root_identity,
            kind,
            bytes,
            &writing,
            &next,
        )?;
    }

    let next_identity = validate_publication_candidate_v1(
        &next,
        root_identity.uid,
        kind,
        bytes,
        if target_exists { 2 } else { 1 },
    )?;

    if target_exists {
        let target_metadata = fs::symlink_metadata(&target)
            .with_context(|| format!("inspect {} response-loss target", kind.label()))?;
        ensure!(
            !target_metadata.file_type().is_symlink()
                && next_identity.matches_metadata_v1(&target_metadata),
            "{} target and publication candidate are not one exact response-loss inode",
            kind.label()
        );
    } else {
        match fs::hard_link(&next, &target) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("publish {} without replacement", kind.label()))
            }
        }
        let next_after_link =
            validate_publication_candidate_v1(&next, root_identity.uid, kind, bytes, 2)?;
        let target_metadata = fs::symlink_metadata(&target)
            .with_context(|| format!("inspect published {} target", kind.label()))?;
        ensure!(
            !target_metadata.file_type().is_symlink()
                && next_after_link.matches_metadata_v1(&target_metadata),
            "{} no-replace publication did not create one exact linked target",
            kind.label()
        );
    }

    root_file
        .sync_all()
        .with_context(|| format!("fsync {} linked publication", kind.label()))?;
    fs::remove_file(&next)
        .with_context(|| format!("remove committed {} publication candidate", kind.label()))?;
    root_file
        .sync_all()
        .with_context(|| format!("fsync {} final publication", kind.label()))?;
    revalidate_publication_root_v1(private_root, &root_file, root_identity)?;
    drop(root_file);
    ensure_no_publication_sidecars_v1(private_root)?;
    let (_, observed, _) = open_and_read_artifact_v1(private_root, kind)?;
    ensure!(
        observed == bytes,
        "published {} differs from exact canonical input",
        kind.label()
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
    expected_uid: u32,
    kind: RecoveryArtifactKindV1,
    expected_bytes: &[u8],
    expected_links: u64,
) -> Result<ArtifactIdentityV1> {
    let before = fs::symlink_metadata(path)
        .with_context(|| format!("inspect {} publication candidate", kind.label()))?;
    ensure!(
        !before.file_type().is_symlink()
            && before.is_file()
            && before.permissions().mode() & 0o777 == 0o600
            && before.uid() == expected_uid
            && before.nlink() == expected_links
            && before.len() == u64::try_from(expected_bytes.len()).unwrap_or(u64::MAX)
            && before.len() <= u64::try_from(kind.maximum_bytes()).unwrap_or(u64::MAX),
        "{} publication candidate has invalid private metadata",
        kind.label()
    );
    let expected_identity = ArtifactIdentityV1::from_metadata_v1(&before);
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .with_context(|| format!("open {} publication candidate", kind.label()))?;
    let opened = file
        .metadata()
        .with_context(|| format!("inspect opened {} publication candidate", kind.label()))?;
    ensure!(
        expected_identity.matches_metadata_v1(&opened),
        "{} publication candidate changed while opening",
        kind.label()
    );
    let mut observed = Vec::with_capacity(expected_bytes.len());
    Read::by_ref(&mut file)
        .take(u64::try_from(kind.maximum_bytes()).unwrap_or(u64::MAX) + 1)
        .read_to_end(&mut observed)
        .with_context(|| format!("read {} publication candidate", kind.label()))?;
    let after = file
        .metadata()
        .with_context(|| format!("reinspect {} publication candidate", kind.label()))?;
    let path_after = fs::symlink_metadata(path)
        .with_context(|| format!("reinspect {} candidate path", kind.label()))?;
    ensure!(
        observed == expected_bytes
            && expected_identity.matches_metadata_v1(&after)
            && expected_identity.matches_metadata_v1(&path_after),
        "{} publication candidate is partial, mutated, or foreign",
        kind.label()
    );
    Ok(expected_identity)
}

fn open_and_read_artifact_v1(
    private_root: &Path,
    kind: RecoveryArtifactKindV1,
) -> Result<(PinnedRecoveryArtifactV1, Vec<u8>, [u8; 32])> {
    let (root_file, root_identity) = open_private_root_v1(private_root)?;
    ensure_no_publication_sidecars_v1(private_root)?;
    let path = private_root.join(kind.file_name());
    ensure!(
        path.parent() == Some(private_root)
            && path.file_name() == Some(OsStr::new(kind.file_name())),
        "recovery artifact path escaped its fixed private root"
    );

    let before =
        fs::symlink_metadata(&path).with_context(|| format!("inspect {} path", kind.label()))?;
    ensure!(
        !before.file_type().is_symlink(),
        "{} path is a symlink",
        kind.label()
    );
    validate_private_artifact_metadata_v1(
        &before,
        root_identity.uid,
        kind.maximum_bytes(),
        kind.label(),
    )?;
    let expected_identity = ArtifactIdentityV1::from_metadata_v1(&before);

    let mut artifact_file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(&path)
        .with_context(|| format!("open {}", kind.label()))?;
    let opened = artifact_file
        .metadata()
        .with_context(|| format!("inspect opened {}", kind.label()))?;
    validate_private_artifact_metadata_v1(
        &opened,
        root_identity.uid,
        kind.maximum_bytes(),
        kind.label(),
    )?;
    ensure!(
        expected_identity.matches_metadata_v1(&opened),
        "{} identity changed while opening",
        kind.label()
    );

    artifact_file
        .seek(SeekFrom::Start(0))
        .with_context(|| format!("seek {}", kind.label()))?;
    let mut bytes = Vec::with_capacity(
        usize::try_from(opened.len()).context("recovery artifact byte length overflows")?,
    );
    Read::by_ref(&mut artifact_file)
        .take(u64::try_from(kind.maximum_bytes()).unwrap_or(u64::MAX) + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("read {}", kind.label()))?;
    ensure!(
        bytes.len() == usize::try_from(opened.len()).unwrap_or(usize::MAX)
            && bytes.len() <= kind.maximum_bytes(),
        "{} byte length changed while reading",
        kind.label()
    );
    let observed_sha256 = sha256_v1(&bytes);

    let after_handle = artifact_file
        .metadata()
        .with_context(|| format!("reinspect opened {}", kind.label()))?;
    let after_path =
        fs::symlink_metadata(&path).with_context(|| format!("reinspect {} path", kind.label()))?;
    ensure!(
        !after_path.file_type().is_symlink()
            && expected_identity.matches_metadata_v1(&after_handle)
            && expected_identity.matches_metadata_v1(&after_path),
        "{} identity changed during stat/read/hash",
        kind.label()
    );
    let root_after = root_file
        .metadata()
        .context("reinspect recovery private root after artifact read")?;
    ensure!(
        root_identity.matches_metadata_v1(&root_after),
        "recovery private root changed during artifact read"
    );
    ensure_no_publication_sidecars_v1(private_root)?;

    Ok((
        PinnedRecoveryArtifactV1 {
            kind,
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
    ensure!(root.is_absolute(), "recovery private root is not absolute");
    let before = fs::symlink_metadata(root).context("inspect recovery private root")?;
    ensure!(
        !before.file_type().is_symlink(),
        "recovery private root is a symlink"
    );
    validate_private_root_metadata_v1(&before)?;
    let canonical = fs::canonicalize(root).context("canonicalize recovery private root")?;
    ensure!(
        canonical == root,
        "recovery private root has a symlink or non-canonical ancestor"
    );
    let expected = DirectoryIdentityV1::from_metadata_v1(&before);
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(root)
        .context("open recovery private root")?;
    let opened = file
        .metadata()
        .context("inspect opened recovery private root")?;
    validate_private_root_metadata_v1(&opened)?;
    let after = fs::symlink_metadata(root).context("reinspect recovery private root")?;
    ensure!(
        !after.file_type().is_symlink()
            && expected.matches_metadata_v1(&opened)
            && expected.matches_metadata_v1(&after),
        "recovery private root identity changed while opening"
    );
    Ok((file, expected))
}

fn validate_private_root_metadata_v1(metadata: &fs::Metadata) -> Result<()> {
    ensure!(
        metadata.is_dir() && metadata.permissions().mode() & 0o777 == 0o700,
        "recovery private root is not one exact 0700 directory"
    );
    Ok(())
}

fn validate_private_artifact_metadata_v1(
    metadata: &fs::Metadata,
    expected_uid: u32,
    maximum_bytes: usize,
    label: &str,
) -> Result<()> {
    ensure!(
        metadata.is_file()
            && metadata.permissions().mode() & 0o777 == 0o600
            && metadata.nlink() == 1
            && metadata.uid() == expected_uid
            && metadata.len() > 0
            && metadata.len() <= u64::try_from(maximum_bytes).unwrap_or(u64::MAX),
        "{label} is not one exact private regular file"
    );
    Ok(())
}

fn ensure_no_publication_sidecars_v1(root: &Path) -> Result<()> {
    ensure_no_publication_sidecars_except_v1(root, None)
}

fn ensure_no_publication_sidecars_except_v1(root: &Path, allowed: Option<&str>) -> Result<()> {
    for name in RECOVERY_READY_SET_SIDECARS_V1
        .into_iter()
        .chain(RECOVERY_START_CERTIFICATE_SIDECARS_V1)
    {
        if allowed == Some(name) {
            continue;
        }
        let path = root.join(name);
        match fs::symlink_metadata(&path) {
            Ok(_) => bail!(
                "recovery publication sidecar unexpectedly exists: {}",
                path.display()
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("inspect recovery sidecar {}", path.display()))
            }
        }
    }
    for entry in fs::read_dir(root).context("scan recovery private root for writing sidecars")? {
        let entry = entry.context("read recovery private-root sidecar entry")?;
        if writing_candidate_kind_v1(&entry.file_name()).is_some() {
            bail!(
                "recovery publication writing sidecar unexpectedly exists: {}",
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

    use ed25519_dalek::{Signer, SigningKey};
    use sha2::{Digest, Sha256};
    use tempfile::TempDir;
    use trnm_consensus_crypto::StrictEd25519Verifier;
    use trnm_consensus_types::{
        BlockId, ChainId, ConsensusParametersHash, ConsensusPublicKey, Epoch, GenesisHash, Height,
        ProtocolVersion, RecoveryContextV1, RecoveryContextV1Fields, RecoveryModeV1,
        RecoveryReadySetV1, RecoveryStartCertificateV1, Signature64, SignedRecoveryReadyV1,
        SignedRecoveryStartV1, StateRoot, Validator, ValidatorId, ValidatorSet, VotingPower,
    };

    use super::*;

    struct Fixture {
        set: ValidatorSet,
        context: RecoveryContextV1,
        ready_set: RecoveryReadySetV1,
        start: RecoveryStartCertificateV1,
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
            ChainId::from_static("trnm-recovery-store-test"),
            ProtocolVersion::V0,
            Epoch::new(4),
            ConsensusParametersHash::new([0x12; 32]),
            validators,
        )
        .unwrap();
        let context = RecoveryContextV1::new_direct7(zero_delta_fields(&set), &set).unwrap();
        let ready_statements = set
            .validators()
            .iter()
            .zip(&keys)
            .map(|(validator, key)| {
                let root = SignedRecoveryReadyV1::signing_root_for(&context, validator.id());
                let signature = Signature64::from_array(key.sign(root.as_bytes()).to_bytes());
                SignedRecoveryReadyV1::from_signature(
                    context,
                    validator.id(),
                    signature,
                    &set,
                    &StrictEd25519Verifier,
                )
                .unwrap()
            })
            .collect();
        let ready_set =
            RecoveryReadySetV1::new(context, ready_statements, &set, &StrictEd25519Verifier)
                .unwrap();
        let starts = set
            .validators()
            .iter()
            .zip(&keys)
            .map(|(validator, key)| {
                let root = SignedRecoveryStartV1::signing_root_for(&ready_set, validator.id());
                let signature = Signature64::from_array(key.sign(root.as_bytes()).to_bytes());
                SignedRecoveryStartV1::from_signature(
                    &ready_set,
                    validator.id(),
                    signature,
                    &set,
                    &StrictEd25519Verifier,
                )
                .unwrap()
            })
            .collect();
        let start = RecoveryStartCertificateV1::new(
            ready_set.clone(),
            starts,
            &set,
            &StrictEd25519Verifier,
        )
        .unwrap();
        Fixture {
            set,
            context,
            ready_set,
            start,
        }
    }

    fn zero_delta_fields(set: &ValidatorSet) -> RecoveryContextV1Fields {
        RecoveryContextV1Fields {
            mode: RecoveryModeV1::ZeroDelta,
            campaign_context_sha256: [0x31; 32],
            fleet_start_certificate_sha256: [0x32; 32],
            validator_set_id: set.id(),
            validator_set_artifact_sha256: [0x33; 32],
            restart_cut_artifact_sha256: [0x34; 32],
            restart_park_artifact_sha256: [0x46; 32],
            restart_parked_ack_artifact_sha256: [0x47; 32],
            restart_parked_ack_admission_set_sha256: [0x48; 32],
            caught_up_cut_artifact_sha256: [0x45; 32],
            target_validator: set.validators()[0].id(),
            process_instance: 2,
            recovery_nonce: [0x35; 32],
            restart_cut_epoch: Epoch::new(4),
            restart_cut_height: Height::new(50),
            restart_cut_block_id: BlockId::new([0x41; 32]),
            restart_cut_state_root: StateRoot::new([0x42; 32]),
            restart_cut_chain_root: [0x43; 32],
            terminal_epoch: Epoch::new(4),
            terminal_height: Height::new(50),
            terminal_block_id: BlockId::new([0x41; 32]),
            terminal_state_root: StateRoot::new([0x42; 32]),
            terminal_chain_root: [0x43; 32],
            node_facts_sha256: [0x44; 32],
        }
    }

    fn nonzero_context(set: &ValidatorSet) -> RecoveryContextV1 {
        let mut fields = zero_delta_fields(set);
        fields.mode = RecoveryModeV1::NonZeroDelta;
        fields.terminal_height = Height::new(51);
        fields.terminal_block_id = BlockId::new([0x51; 32]);
        fields.terminal_state_root = StateRoot::new([0x52; 32]);
        fields.terminal_chain_root = [0x53; 32];
        RecoveryContextV1::new_direct7(fields, set).unwrap()
    }

    fn private_root() -> TempDir {
        let temporary = TempDir::new().unwrap();
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(temporary.path().canonicalize().unwrap(), temporary.path());
        temporary
    }

    fn sha256(bytes: &[u8]) -> [u8; 32] {
        Sha256::digest(bytes).into()
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

    #[test]
    fn typed_ready_and_start_persist_load_and_fresh_revalidate() {
        let fixture = fixture();
        let root = private_root();
        let ready_bytes = fixture.ready_set.try_cev1_bytes().unwrap();
        let ready_sha256 = sha256(&ready_bytes);
        let stored_ready =
            persist_recovery_ready_set_v1(root.path(), fixture.ready_set.clone(), &fixture.set)
                .unwrap();
        assert_eq!(stored_ready.value_v1(), &fixture.ready_set);
        assert_eq!(stored_ready.context_v1(), &fixture.context);
        assert_eq!(stored_ready.artifact_sha256_v1(), ready_sha256);
        assert_eq!(
            stored_ready.path_v1(),
            root.path().join(RECOVERY_READY_SET_FILE_V1)
        );
        stored_ready.revalidate_fresh_v1(&fixture.set).unwrap();

        let loaded_ready =
            load_recovery_ready_set_v1(root.path(), ready_sha256, &fixture.context, &fixture.set)
                .unwrap();
        loaded_ready.revalidate_fresh_v1(&fixture.set).unwrap();

        let start_bytes = fixture.start.try_cev1_bytes().unwrap();
        let start_sha256 = sha256(&start_bytes);
        let ready_for_start =
            load_recovery_ready_set_v1(root.path(), ready_sha256, &fixture.context, &fixture.set)
                .unwrap();
        let stored_start = persist_recovery_start_certificate_v1(
            root.path(),
            fixture.start.clone(),
            ready_for_start,
            &fixture.set,
        )
        .unwrap();
        assert_eq!(stored_start.value_v1(), &fixture.start);
        assert_eq!(stored_start.context_v1(), &fixture.context);
        assert_eq!(stored_start.artifact_sha256_v1(), start_sha256);
        assert_eq!(stored_start.ready_set_artifact_sha256_v1(), ready_sha256);
        assert_eq!(stored_start.ready_set_v1(), &fixture.ready_set);
        assert_eq!(
            stored_start.path_v1(),
            root.path().join(RECOVERY_START_CERTIFICATE_FILE_V1)
        );
        stored_start.revalidate_fresh_v1(&fixture.set).unwrap();
        stored_ready.revalidate_fresh_v1(&fixture.set).unwrap();

        let loaded_start = load_recovery_start_certificate_v1(
            root.path(),
            start_sha256,
            ready_sha256,
            &fixture.context,
            &fixture.set,
        )
        .unwrap();
        loaded_start.revalidate_fresh_v1(&fixture.set).unwrap();

        let ready_metadata = fs::symlink_metadata(stored_ready.path_v1()).unwrap();
        let start_metadata = fs::symlink_metadata(stored_start.path_v1()).unwrap();
        assert_eq!(ready_metadata.permissions().mode() & 0o777, 0o600);
        assert_eq!(start_metadata.permissions().mode() & 0o777, 0o600);
        assert_eq!(ready_metadata.nlink(), 1);
        assert_eq!(start_metadata.nlink(), 1);
        persist_recovery_ready_set_v1(root.path(), fixture.ready_set, &fixture.set)
            .unwrap()
            .revalidate_fresh_v1(&fixture.set)
            .unwrap();
        persist_recovery_start_certificate_v1(
            root.path(),
            fixture.start,
            load_recovery_ready_set_v1(root.path(), ready_sha256, &fixture.context, &fixture.set)
                .unwrap(),
            &fixture.set,
        )
        .unwrap()
        .revalidate_fresh_v1(&fixture.set)
        .unwrap();
    }

    #[test]
    fn publication_reconciles_exact_temp_and_linked_response_loss_but_rejects_partial() {
        let fixture = fixture();
        let bytes = fixture.ready_set.try_cev1_bytes().unwrap();

        let temp_only = private_root();
        write_test_artifact(
            temp_only.path(),
            RecoveryArtifactKindV1::ReadySet.next_file_name(),
            &bytes,
        );
        drop(
            persist_recovery_ready_set_v1(
                temp_only.path(),
                fixture.ready_set.clone(),
                &fixture.set,
            )
            .unwrap(),
        );
        assert!(!temp_only
            .path()
            .join(RecoveryArtifactKindV1::ReadySet.next_file_name())
            .exists());

        let linked = private_root();
        let stored =
            persist_recovery_ready_set_v1(linked.path(), fixture.ready_set.clone(), &fixture.set)
                .unwrap();
        let target = stored.path_v1().to_path_buf();
        drop(stored);
        let next = linked
            .path()
            .join(RecoveryArtifactKindV1::ReadySet.next_file_name());
        fs::hard_link(&target, &next).unwrap();
        File::open(linked.path()).unwrap().sync_all().unwrap();
        drop(
            persist_recovery_ready_set_v1(linked.path(), fixture.ready_set.clone(), &fixture.set)
                .unwrap(),
        );
        assert!(!next.exists());
        assert_eq!(fs::metadata(&target).unwrap().nlink(), 1);

        let partial_temp = private_root();
        write_test_artifact(
            partial_temp.path(),
            RecoveryArtifactKindV1::ReadySet.next_file_name(),
            &bytes[..bytes.len() - 1],
        );
        assert!(persist_recovery_ready_set_v1(
            partial_temp.path(),
            fixture.ready_set.clone(),
            &fixture.set,
        )
        .is_err());
        assert!(!partial_temp
            .path()
            .join(RECOVERY_READY_SET_FILE_V1)
            .exists());

        let partial_target = private_root();
        write_test_artifact(
            partial_target.path(),
            RECOVERY_READY_SET_FILE_V1,
            &bytes[..bytes.len() - 1],
        );
        assert!(persist_recovery_ready_set_v1(
            partial_target.path(),
            fixture.ready_set,
            &fixture.set,
        )
        .is_err());
    }

    #[test]
    fn publication_recovers_authenticated_writing_kill_windows() {
        let fixture = fixture();
        let bytes = fixture.ready_set.try_cev1_bytes().unwrap();
        for (attempt, prefix_length, incomplete_mode) in [
            (1u64, 0usize, Some(0o000)),
            (2, 1, None),
            (3, bytes.len() - 1, None),
            (4, bytes.len(), None),
        ] {
            let root = private_root();
            let writing_name =
                writing_file_name_v1(RecoveryArtifactKindV1::ReadySet, 0x71a1, attempt);
            let writing = root.path().join(&writing_name);
            write_test_artifact(root.path(), &writing_name, &bytes[..prefix_length]);
            if let Some(mode) = incomplete_mode {
                fs::set_permissions(&writing, fs::Permissions::from_mode(mode)).unwrap();
            }

            drop(
                persist_recovery_ready_set_v1(root.path(), fixture.ready_set.clone(), &fixture.set)
                    .unwrap(),
            );
            assert!(!writing.exists());
            assert_eq!(
                fs::read(root.path().join(RECOVERY_READY_SET_FILE_V1)).unwrap(),
                bytes
            );
            assert!(!root
                .path()
                .join(RecoveryArtifactKindV1::ReadySet.next_file_name())
                .exists());
            assert!(fs::read_dir(root.path())
                .unwrap()
                .all(|entry| { writing_candidate_kind_v1(&entry.unwrap().file_name()).is_none() }));
        }
    }

    #[test]
    fn publication_recovers_exact_writing_to_next_response_loss() {
        let fixture = fixture();
        let bytes = fixture.ready_set.try_cev1_bytes().unwrap();
        let root = private_root();
        let writing_name = writing_file_name_v1(RecoveryArtifactKindV1::ReadySet, 0x71a2, 9);
        let writing = root.path().join(&writing_name);
        let next = root
            .path()
            .join(RecoveryArtifactKindV1::ReadySet.next_file_name());
        write_test_artifact(root.path(), &writing_name, &bytes);
        fs::hard_link(&writing, &next).unwrap();
        File::open(root.path()).unwrap().sync_all().unwrap();

        drop(
            persist_recovery_ready_set_v1(root.path(), fixture.ready_set.clone(), &fixture.set)
                .unwrap(),
        );
        let target = root.path().join(RECOVERY_READY_SET_FILE_V1);
        assert!(!writing.exists());
        assert!(!next.exists());
        assert_eq!(fs::read(&target).unwrap(), bytes);
        assert_eq!(fs::metadata(target).unwrap().nlink(), 1);
    }

    #[test]
    fn publication_preserves_foreign_writing_mutants_fail_closed() {
        let fixture = fixture();
        let bytes = fixture.ready_set.try_cev1_bytes().unwrap();

        let mismatched = private_root();
        let mismatched_name = writing_file_name_v1(RecoveryArtifactKindV1::ReadySet, 0x71a3, 10);
        let mismatched_path = mismatched.path().join(&mismatched_name);
        let mut mismatched_bytes = bytes[..bytes.len() - 1].to_vec();
        mismatched_bytes[0] ^= 1;
        write_test_artifact(mismatched.path(), &mismatched_name, &mismatched_bytes);
        assert!(persist_recovery_ready_set_v1(
            mismatched.path(),
            fixture.ready_set.clone(),
            &fixture.set,
        )
        .is_err());
        assert_eq!(fs::read(&mismatched_path).unwrap(), mismatched_bytes);
        assert!(!mismatched.path().join(RECOVERY_READY_SET_FILE_V1).exists());

        let third_link = private_root();
        let third_link_name = writing_file_name_v1(RecoveryArtifactKindV1::ReadySet, 0x71a4, 11);
        let third_link_path = third_link.path().join(&third_link_name);
        let foreign_link = third_link.path().join("foreign-writing-link.bin");
        write_test_artifact(third_link.path(), &third_link_name, &bytes);
        fs::hard_link(&third_link_path, &foreign_link).unwrap();
        File::open(third_link.path()).unwrap().sync_all().unwrap();
        assert!(persist_recovery_ready_set_v1(
            third_link.path(),
            fixture.ready_set.clone(),
            &fixture.set,
        )
        .is_err());
        assert!(third_link_path.exists());
        assert!(foreign_link.exists());
        assert_eq!(fs::metadata(&third_link_path).unwrap().nlink(), 2);
        assert!(!third_link.path().join(RECOVERY_READY_SET_FILE_V1).exists());

        let separate_next = private_root();
        let separate_name = writing_file_name_v1(RecoveryArtifactKindV1::ReadySet, 0x71a5, 12);
        let separate_path = separate_next.path().join(&separate_name);
        let next = separate_next
            .path()
            .join(RecoveryArtifactKindV1::ReadySet.next_file_name());
        write_test_artifact(separate_next.path(), &separate_name, &bytes);
        write_test_artifact(
            separate_next.path(),
            RecoveryArtifactKindV1::ReadySet.next_file_name(),
            &bytes,
        );
        assert!(persist_recovery_ready_set_v1(
            separate_next.path(),
            fixture.ready_set.clone(),
            &fixture.set,
        )
        .is_err());
        assert!(separate_path.exists());
        assert!(next.exists());
        assert_eq!(fs::metadata(&separate_path).unwrap().nlink(), 1);
        assert_eq!(fs::metadata(&next).unwrap().nlink(), 1);

        let mutated_response_loss = private_root();
        let mutated_name = writing_file_name_v1(RecoveryArtifactKindV1::ReadySet, 0x71a6, 13);
        let mutated_path = mutated_response_loss.path().join(&mutated_name);
        let mutated_next = mutated_response_loss
            .path()
            .join(RecoveryArtifactKindV1::ReadySet.next_file_name());
        let mut mutated_bytes = bytes.clone();
        let last = mutated_bytes.len() - 1;
        mutated_bytes[last] ^= 1;
        write_test_artifact(mutated_response_loss.path(), &mutated_name, &mutated_bytes);
        fs::hard_link(&mutated_path, &mutated_next).unwrap();
        File::open(mutated_response_loss.path())
            .unwrap()
            .sync_all()
            .unwrap();
        assert!(persist_recovery_ready_set_v1(
            mutated_response_loss.path(),
            fixture.ready_set.clone(),
            &fixture.set,
        )
        .is_err());
        assert_eq!(fs::read(&mutated_path).unwrap(), mutated_bytes);
        assert!(mutated_next.exists());
        assert_eq!(fs::metadata(&mutated_path).unwrap().nlink(), 2);

        let malformed = private_root();
        let malformed_name = format!(
            "{}foreign",
            RecoveryArtifactKindV1::ReadySet.writing_prefix()
        );
        let malformed_path = malformed.path().join(&malformed_name);
        write_test_artifact(malformed.path(), &malformed_name, &bytes[..1]);
        assert!(
            persist_recovery_ready_set_v1(malformed.path(), fixture.ready_set, &fixture.set,)
                .is_err()
        );
        assert_eq!(fs::read(&malformed_path).unwrap(), &bytes[..1]);
        assert!(!malformed.path().join(RECOVERY_READY_SET_FILE_V1).exists());
    }

    #[test]
    fn load_requires_exact_expected_hash_context_park_ack_and_mode() {
        let fixture = fixture();
        let root = private_root();
        let bytes = fixture.ready_set.try_cev1_bytes().unwrap();
        let expected_sha256 = sha256(&bytes);
        let _stored =
            persist_recovery_ready_set_v1(root.path(), fixture.ready_set.clone(), &fixture.set)
                .unwrap();
        let start_sha256 = sha256(&fixture.start.try_cev1_bytes().unwrap());
        let ready_for_start = load_recovery_ready_set_v1(
            root.path(),
            expected_sha256,
            &fixture.context,
            &fixture.set,
        )
        .unwrap();
        let _stored_start = persist_recovery_start_certificate_v1(
            root.path(),
            fixture.start.clone(),
            ready_for_start,
            &fixture.set,
        )
        .unwrap();

        assert!(load_recovery_ready_set_v1(
            root.path(),
            [0xee; 32],
            &fixture.context,
            &fixture.set,
        )
        .is_err());
        let mut fields = fixture.context.fields();
        fields.restart_park_artifact_sha256 = [0x92; 32];
        let wrong_context = RecoveryContextV1::new_direct7(fields, &fixture.set).unwrap();
        assert!(load_recovery_ready_set_v1(
            root.path(),
            expected_sha256,
            &wrong_context,
            &fixture.set,
        )
        .is_err());
        for (field, wrong_context) in [
            {
                let mut fields = fixture.context.fields();
                fields.restart_parked_ack_artifact_sha256 = [0x93; 32];
                (
                    "restart ParkedAck artifact SHA-256",
                    RecoveryContextV1::new_direct7(fields, &fixture.set).unwrap(),
                )
            },
            {
                let mut fields = fixture.context.fields();
                fields.restart_parked_ack_admission_set_sha256 = [0x94; 32];
                (
                    "restart ParkedAck admission-set SHA-256",
                    RecoveryContextV1::new_direct7(fields, &fixture.set).unwrap(),
                )
            },
        ] {
            assert!(
                load_recovery_ready_set_v1(
                    root.path(),
                    expected_sha256,
                    &wrong_context,
                    &fixture.set,
                )
                .is_err(),
                "ReadySet reopen must reject a changed {field}"
            );
            assert!(
                load_recovery_start_certificate_v1(
                    root.path(),
                    start_sha256,
                    expected_sha256,
                    &wrong_context,
                    &fixture.set,
                )
                .is_err(),
                "Start reopen must reject a changed {field}"
            );
        }
        assert!(load_recovery_ready_set_v1(
            root.path(),
            expected_sha256,
            &nonzero_context(&fixture.set),
            &fixture.set,
        )
        .is_err());
    }

    #[test]
    fn fresh_revalidate_rejects_mutation_and_same_byte_replacement() {
        let fixture = fixture();
        let mutation_root = private_root();
        let stored = persist_recovery_ready_set_v1(
            mutation_root.path(),
            fixture.ready_set.clone(),
            &fixture.set,
        )
        .unwrap();
        let path = stored.path_v1().to_path_buf();
        let mut mutated = fs::read(&path).unwrap();
        let last = mutated.len() - 1;
        mutated[last] ^= 1;
        fs::write(&path, mutated).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(stored.revalidate_fresh_v1(&fixture.set).is_err());

        let replacement_root = private_root();
        let stored = persist_recovery_ready_set_v1(
            replacement_root.path(),
            fixture.ready_set.clone(),
            &fixture.set,
        )
        .unwrap();
        let path = stored.path_v1().to_path_buf();
        let bytes = fs::read(&path).unwrap();
        let displaced = replacement_root.path().join("displaced-ready-set.bin");
        fs::rename(&path, &displaced).unwrap();
        write_test_artifact(replacement_root.path(), RECOVERY_READY_SET_FILE_V1, &bytes);
        assert!(stored.revalidate_fresh_v1(&fixture.set).is_err());
    }

    #[test]
    fn store_rejects_symlink_nonregular_hardlink_and_publication_sidecar() {
        let fixture = fixture();
        let expected_sha256 = sha256(&fixture.ready_set.try_cev1_bytes().unwrap());

        let symlink_root = private_root();
        symlink(
            "/dev/null",
            symlink_root.path().join(RECOVERY_READY_SET_FILE_V1),
        )
        .unwrap();
        assert!(load_recovery_ready_set_v1(
            symlink_root.path(),
            expected_sha256,
            &fixture.context,
            &fixture.set,
        )
        .is_err());

        let nonregular_root = private_root();
        fs::create_dir(nonregular_root.path().join(RECOVERY_READY_SET_FILE_V1)).unwrap();
        assert!(load_recovery_ready_set_v1(
            nonregular_root.path(),
            expected_sha256,
            &fixture.context,
            &fixture.set,
        )
        .is_err());

        let hardlink_root = private_root();
        let stored = persist_recovery_ready_set_v1(
            hardlink_root.path(),
            fixture.ready_set.clone(),
            &fixture.set,
        )
        .unwrap();
        fs::hard_link(
            stored.path_v1(),
            hardlink_root.path().join("foreign-hardlink.bin"),
        )
        .unwrap();
        assert!(stored.revalidate_fresh_v1(&fixture.set).is_err());

        let sidecar_root = private_root();
        let stored =
            persist_recovery_ready_set_v1(sidecar_root.path(), fixture.ready_set, &fixture.set)
                .unwrap();
        symlink(
            RECOVERY_READY_SET_FILE_V1,
            sidecar_root.path().join(RECOVERY_READY_SET_SIDECARS_V1[0]),
        )
        .unwrap();
        assert!(stored.revalidate_fresh_v1(&fixture.set).is_err());
        assert!(load_recovery_ready_set_v1(
            sidecar_root.path(),
            expected_sha256,
            &fixture.context,
            &fixture.set,
        )
        .is_err());
    }

    #[test]
    fn exact_load_rejects_trailing_bytes_and_invalid_signature_with_matching_hash() {
        let fixture = fixture();

        let trailing_root = private_root();
        let mut trailing = fixture.ready_set.try_cev1_bytes().unwrap();
        trailing.push(0);
        write_test_artifact(trailing_root.path(), RECOVERY_READY_SET_FILE_V1, &trailing);
        assert!(load_recovery_ready_set_v1(
            trailing_root.path(),
            sha256(&trailing),
            &fixture.context,
            &fixture.set,
        )
        .is_err());

        let invalid_signature_root = private_root();
        let mut invalid_signature = fixture.ready_set.try_cev1_bytes().unwrap();
        let last = invalid_signature.len() - 1;
        invalid_signature[last] ^= 1;
        write_test_artifact(
            invalid_signature_root.path(),
            RECOVERY_READY_SET_FILE_V1,
            &invalid_signature,
        );
        assert!(load_recovery_ready_set_v1(
            invalid_signature_root.path(),
            sha256(&invalid_signature),
            &fixture.context,
            &fixture.set,
        )
        .is_err());
    }

    #[test]
    fn ready_and_start_fixed_paths_reject_cross_substitution() {
        let fixture = fixture();
        let ready_bytes = fixture.ready_set.try_cev1_bytes().unwrap();
        let start_bytes = fixture.start.try_cev1_bytes().unwrap();

        let start_at_ready = private_root();
        write_test_artifact(
            start_at_ready.path(),
            RECOVERY_READY_SET_FILE_V1,
            &start_bytes,
        );
        assert!(load_recovery_ready_set_v1(
            start_at_ready.path(),
            sha256(&start_bytes),
            &fixture.context,
            &fixture.set,
        )
        .is_err());

        let ready_at_start = private_root();
        write_test_artifact(
            ready_at_start.path(),
            RECOVERY_START_CERTIFICATE_FILE_V1,
            &ready_bytes,
        );
        assert!(load_recovery_start_certificate_v1(
            ready_at_start.path(),
            sha256(&ready_bytes),
            sha256(&ready_bytes),
            &fixture.context,
            &fixture.set,
        )
        .is_err());
    }

    #[test]
    fn store_has_no_runtime_or_scalar_authority_surface() {
        let source = include_str!("recovery_barrier_store.rs");
        let normal = &source[..source.find("#[cfg(test)]").unwrap()];
        for forbidden in [
            "SigningKey,",
            "fn activate",
            "fn arm",
            "TcpStream",
            "UdpSocket",
            "RuntimeEventJournal",
            "OpenOptions::new().truncate",
            "set_len(",
        ] {
            assert!(
                !normal.contains(forbidden),
                "normal store surface contains forbidden authority token {forbidden}"
            );
        }
        assert!(!normal.contains("pub fn write"));
    }
}
