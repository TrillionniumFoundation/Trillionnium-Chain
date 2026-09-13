//! Crash-safe private storage for one canonical direct-seven restart-park certificate.
//!
//! A caller supplies a nonzero expected SHA-256 over the raw canonical
//! artifact independently of the typed value. The value is joined to the exact
//! expected RestartCut body, FleetStart certificate, validator set, and local
//! validator/config statement before publication or load. Publication is
//! create-new and idempotent: exact response-loss successors are reconciled,
//! while partial, foreign, or ambiguous filesystem states fail closed.
//!
//! The returned non-Clone owner pins the private root and artifact identities.
//! Every fresh revalidation repeats the complete stat/read/hash/exact-decode
//! and semantic join. The park wire binds the RestartCut body digest, not the
//! separately stored RestartCut artifact SHA-256; a later composite must also
//! retain the corresponding StoredRestartCutCertificateV1.
//!
//! This module exposes no signer, journal, network, Ready/Start barrier,
//! timer, process-control, recovery, or activation authority.
//!
//! Root and artifact handles detect stable replacement, but publication child
//! operations are still pathname-based rather than directory-fd-relative.
//! A hostile same-UID concurrent rename-and-swap-back race is therefore not
//! claimed closed by this inert boundary.

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
use trnm_consensus_types::{ValidatorId, ValidatorSet};

use crate::{
    fleet_barrier::FleetStartCertificateV1,
    restart_cut::{
        RestartCutBodyV1, RestartParkCertificateV1, SignedLocalRestartParkV1,
        MAX_RESTART_PARK_CERTIFICATE_BYTES_V1,
    },
};

const RESTART_PARK_CERTIFICATE_FILE_V1: &str = "restart-park-certificate-v1.bin";
const RESTART_PARK_CERTIFICATE_NEXT_V1: &str = "restart-park-certificate-v1.next";
const RESTART_PARK_CERTIFICATE_SIDECARS_V1: [&str; 3] = [
    RESTART_PARK_CERTIFICATE_NEXT_V1,
    "restart-park-certificate-v1.tmp",
    "restart-park-certificate-v1.lock",
];
const RESTART_PARK_CERTIFICATE_WRITING_PREFIX_V1: &str = "restart-park-certificate-v1.writing.";
static RESTART_PARK_WRITING_ATTEMPT_V1: AtomicU64 = AtomicU64::new(0);

#[must_use = "stored restart-park ownership must be retained across the later composite join"]
pub(crate) struct StoredRestartParkCertificateV1 {
    pinned: PinnedRestartParkArtifactV1,
    value: RestartParkCertificateV1,
    expected_body: RestartCutBodyV1,
    local_validator: ValidatorId,
    local_config_sha256: [u8; 32],
    local_statement: SignedLocalRestartParkV1,
    artifact_sha256: [u8; 32],
}

impl std::fmt::Debug for StoredRestartParkCertificateV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("StoredRestartParkCertificateV1")
            .field("path", &self.pinned.path)
            .field("artifact_sha256", &self.artifact_sha256)
            .field("body_sha256", &self.expected_body.digest())
            .field("local_validator", &self.local_validator)
            .field("local_config_sha256", &self.local_config_sha256)
            .finish_non_exhaustive()
    }
}

impl StoredRestartParkCertificateV1 {
    pub(crate) const fn value_v1(&self) -> &RestartParkCertificateV1 {
        &self.value
    }

    pub(crate) const fn body_v1(&self) -> &RestartCutBodyV1 {
        &self.expected_body
    }

    pub(crate) const fn local_validator_v1(&self) -> ValidatorId {
        self.local_validator
    }

    pub(crate) const fn local_config_sha256_v1(&self) -> [u8; 32] {
        self.local_config_sha256
    }

    pub(crate) const fn local_statement_v1(&self) -> &SignedLocalRestartParkV1 {
        &self.local_statement
    }

    pub(crate) const fn artifact_sha256_v1(&self) -> [u8; 32] {
        self.artifact_sha256
    }

    pub(crate) fn path_v1(&self) -> &Path {
        &self.pinned.path
    }

    pub(crate) fn revalidate_fresh_v1(
        &self,
        fleet_start_certificate: &FleetStartCertificateV1,
        validator_set: &ValidatorSet,
    ) -> Result<()> {
        validate_expected_join_v1(
            self.artifact_sha256,
            &self.value,
            &self.expected_body,
            self.local_validator,
            self.local_config_sha256,
            fleet_start_certificate,
            validator_set,
        )?;
        ensure!(
            self.value.statement(self.local_validator) == Some(&self.local_statement),
            "retained restart-park local statement differs from retained certificate"
        );
        self.pinned.revalidate_held_v1()?;
        let (fresh, bytes, observed_sha256) = open_and_read_artifact_v1(&self.pinned.root_path)?;
        ensure!(
            fresh.same_identity_v1(&self.pinned),
            "restart-park path or open-file identity was replaced"
        );
        ensure!(
            observed_sha256 == self.artifact_sha256,
            "restart-park content address changed"
        );
        let decoded =
            RestartParkCertificateV1::decode(&bytes, fleet_start_certificate, validator_set)
                .map_err(|error| {
                    anyhow::anyhow!("fresh-decode restart-park certificate: {error}")
                })?;
        ensure!(
            decoded == self.value,
            "fresh restart-park certificate differs from retained typed value"
        );
        ensure!(
            decoded.statement(self.local_validator) == Some(&self.local_statement),
            "fresh restart-park local statement differs from retained exact statement"
        );
        validate_certificate_join_v1(
            observed_sha256,
            &decoded,
            &self.expected_body,
            self.local_validator,
            self.local_config_sha256,
            fleet_start_certificate,
            validator_set,
        )?;
        fresh.revalidate_held_v1()?;
        self.pinned.revalidate_held_v1()
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn persist_restart_park_certificate_v1(
    private_root: &Path,
    expected_artifact_sha256: [u8; 32],
    value: RestartParkCertificateV1,
    expected_body: &RestartCutBodyV1,
    local_validator: ValidatorId,
    local_config_sha256: [u8; 32],
    fleet_start_certificate: &FleetStartCertificateV1,
    validator_set: &ValidatorSet,
) -> Result<StoredRestartParkCertificateV1> {
    validate_expected_join_v1(
        expected_artifact_sha256,
        &value,
        expected_body,
        local_validator,
        local_config_sha256,
        fleet_start_certificate,
        validator_set,
    )?;
    let bytes = value.encode();
    validate_encoded_bound_v1(&bytes)?;
    ensure!(
        sha256_v1(&bytes) == expected_artifact_sha256,
        "canonical restart-park certificate differs from expected content address"
    );
    publish_create_new_v1(private_root, &bytes)?;
    let stored = load_restart_park_certificate_v1(
        private_root,
        expected_artifact_sha256,
        expected_body,
        local_validator,
        local_config_sha256,
        fleet_start_certificate,
        validator_set,
    )?;
    ensure!(
        stored.value == value,
        "stored restart-park certificate differs from verified input"
    );
    Ok(stored)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn load_restart_park_certificate_v1(
    private_root: &Path,
    expected_artifact_sha256: [u8; 32],
    expected_body: &RestartCutBodyV1,
    local_validator: ValidatorId,
    local_config_sha256: [u8; 32],
    fleet_start_certificate: &FleetStartCertificateV1,
    validator_set: &ValidatorSet,
) -> Result<StoredRestartParkCertificateV1> {
    ensure!(
        expected_artifact_sha256 != [0; 32],
        "expected restart-park certificate SHA-256 is zero"
    );
    let (pinned, bytes, observed_sha256) = open_and_read_artifact_v1(private_root)?;
    ensure!(
        observed_sha256 == expected_artifact_sha256,
        "restart-park SHA-256 differs from expected content address"
    );
    let value = RestartParkCertificateV1::decode(&bytes, fleet_start_certificate, validator_set)
        .map_err(|error| anyhow::anyhow!("decode stored restart-park certificate: {error}"))?;
    validate_certificate_join_v1(
        observed_sha256,
        &value,
        expected_body,
        local_validator,
        local_config_sha256,
        fleet_start_certificate,
        validator_set,
    )?;
    let local_statement = value
        .statement(local_validator)
        .cloned()
        .context("stored restart-park certificate lacks exact local statement")?;
    pinned.revalidate_held_v1()?;
    Ok(StoredRestartParkCertificateV1 {
        pinned,
        value,
        expected_body: expected_body.clone(),
        local_validator,
        local_config_sha256,
        local_statement,
        artifact_sha256: observed_sha256,
    })
}

#[allow(clippy::too_many_arguments)]
fn validate_expected_join_v1(
    expected_artifact_sha256: [u8; 32],
    expected_value: &RestartParkCertificateV1,
    expected_body: &RestartCutBodyV1,
    local_validator: ValidatorId,
    local_config_sha256: [u8; 32],
    fleet_start_certificate: &FleetStartCertificateV1,
    validator_set: &ValidatorSet,
) -> Result<()> {
    ensure!(
        expected_artifact_sha256 != [0; 32],
        "expected restart-park certificate SHA-256 is zero"
    );
    validate_certificate_join_v1(
        expected_artifact_sha256,
        expected_value,
        expected_body,
        local_validator,
        local_config_sha256,
        fleet_start_certificate,
        validator_set,
    )?;
    let canonical = expected_value.encode();
    validate_encoded_bound_v1(&canonical)?;
    ensure!(
        sha256_v1(&canonical) == expected_artifact_sha256,
        "expected typed restart-park certificate does not match expected content address"
    );
    let decoded =
        RestartParkCertificateV1::decode(&canonical, fleet_start_certificate, validator_set)
            .map_err(|error| {
                anyhow::anyhow!("exact-decode expected restart-park certificate: {error}")
            })?;
    ensure!(
        decoded == *expected_value,
        "expected restart-park certificate is not exact canonical wire"
    );
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn validate_certificate_join_v1(
    artifact_sha256: [u8; 32],
    certificate: &RestartParkCertificateV1,
    expected_body: &RestartCutBodyV1,
    local_validator: ValidatorId,
    local_config_sha256: [u8; 32],
    fleet_start_certificate: &FleetStartCertificateV1,
    validator_set: &ValidatorSet,
) -> Result<()> {
    ensure!(
        artifact_sha256 != [0; 32],
        "restart-park certificate content address is zero"
    );
    certificate
        .verify(fleet_start_certificate, validator_set)
        .map_err(|error| anyhow::anyhow!("validate restart-park certificate join: {error}"))?;
    ensure!(
        certificate.body() == expected_body,
        "restart-park certificate body differs from exact expected RestartCut body"
    );
    ensure!(
        expected_body.process_instance() == 1,
        "restart-park certificate is not bound to process 1"
    );
    ensure!(
        validator_set.validator(local_validator).is_some(),
        "restart-park local validator is absent from the exact validator set"
    );
    ensure!(
        local_config_sha256 != [0; 32],
        "restart-park local config SHA-256 is zero"
    );
    ensure!(
        expected_body.fleet_start_certificate_sha256()
            == sha256_v1(&fleet_start_certificate.encode()),
        "expected RestartCut body differs from exact raw FleetStart certificate"
    );
    let local_ready = fleet_start_certificate
        .ready_set()
        .statement(local_validator)
        .context("FleetStart certificate lacks the local Ready statement")?;
    ensure!(
        local_ready.local_cut().config_sha256() == local_config_sha256,
        "FleetStart local config differs from expected restart-park binding"
    );
    let local_statement = certificate
        .statement(local_validator)
        .context("restart-park certificate lacks exact local signed statement")?;
    local_statement
        .verify(expected_body, fleet_start_certificate, validator_set)
        .map_err(|error| anyhow::anyhow!("validate exact local restart-park statement: {error}"))?;
    let local_park = local_statement.local_park();
    ensure!(
        local_statement.origin() == local_validator
            && local_park.local_validator() == local_validator
            && local_park.local_config_sha256() == local_config_sha256
            && local_park.process_instance() == 1
            && local_statement.restart_cut_body_sha256() == expected_body.digest()
            && local_park.restart_cut_body_sha256() == expected_body.digest(),
        "restart-park certificate local statement differs from exact local/body binding"
    );
    Ok(())
}

fn validate_encoded_bound_v1(bytes: &[u8]) -> Result<()> {
    ensure!(
        !bytes.is_empty() && bytes.len() <= MAX_RESTART_PARK_CERTIFICATE_BYTES_V1,
        "restart-park certificate canonical bytes cross the durable bound"
    );
    Ok(())
}

fn sha256_v1(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
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

struct PinnedRestartParkArtifactV1 {
    root_path: PathBuf,
    path: PathBuf,
    root_file: File,
    artifact_file: File,
    root_identity: DirectoryIdentityV1,
    artifact_identity: ArtifactIdentityV1,
}

impl std::fmt::Debug for PinnedRestartParkArtifactV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PinnedRestartParkArtifactV1")
            .field("root_path", &self.root_path)
            .field("path", &self.path)
            .field("root_identity", &self.root_identity)
            .field("artifact_identity", &self.artifact_identity)
            .finish_non_exhaustive()
    }
}

impl PinnedRestartParkArtifactV1 {
    fn same_identity_v1(&self, other: &Self) -> bool {
        self.root_path == other.root_path
            && self.path == other.path
            && self.root_identity == other.root_identity
            && self.artifact_identity == other.artifact_identity
    }

    fn revalidate_held_v1(&self) -> Result<()> {
        ensure_no_publication_sidecars_v1(&self.root_path)?;
        ensure!(
            self.path == self.root_path.join(RESTART_PARK_CERTIFICATE_FILE_V1)
                && self.path.file_name() == Some(OsStr::new(RESTART_PARK_CERTIFICATE_FILE_V1)),
            "pinned restart park artifact escaped its fixed private path"
        );

        let held_root = self
            .root_file
            .metadata()
            .context("inspect held restart park private root")?;
        validate_private_root_metadata_v1(&held_root)?;
        ensure!(
            self.root_identity.matches_metadata_v1(&held_root),
            "held restart park private root identity changed"
        );
        let (fresh_root_file, fresh_root_identity) = open_private_root_v1(&self.root_path)?;
        ensure!(
            fresh_root_identity == self.root_identity,
            "restart park private root path was replaced"
        );
        drop(fresh_root_file);

        let held_artifact = self
            .artifact_file
            .metadata()
            .context("inspect held restart park cut")?;
        validate_private_artifact_metadata_v1(&held_artifact)?;
        ensure!(
            self.artifact_identity.matches_metadata_v1(&held_artifact),
            "held restart park cut identity changed"
        );
        let path_metadata =
            fs::symlink_metadata(&self.path).context("reinspect pinned restart park cut path")?;
        ensure!(
            !path_metadata.file_type().is_symlink(),
            "pinned restart park cut path became a symlink"
        );
        validate_private_artifact_metadata_v1(&path_metadata)?;
        ensure!(
            self.artifact_identity.matches_metadata_v1(&path_metadata),
            "pinned restart park cut path was replaced or mutated"
        );
        Ok(())
    }
}

fn effective_uid_v1() -> u32 {
    rustix::process::geteuid().as_raw()
}

fn writing_file_name_v1(process_id: u32, attempt: u64) -> String {
    format!("{RESTART_PARK_CERTIFICATE_WRITING_PREFIX_V1}{process_id:08x}.{attempt:016x}")
}

fn next_writing_file_name_v1() -> String {
    writing_file_name_v1(
        process::id(),
        RESTART_PARK_WRITING_ATTEMPT_V1.fetch_add(1, Ordering::Relaxed),
    )
}

fn is_lower_hex_digit_v1(byte: u8) -> bool {
    byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
}

fn writing_candidate_v1(name: &OsStr) -> Option<bool> {
    let name = name.as_bytes();
    let prefix = RESTART_PARK_CERTIFICATE_WRITING_PREFIX_V1.as_bytes();
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
        .context("reinspect held restart park publication root")?;
    validate_private_root_metadata_v1(&held_root)?;
    ensure!(
        root_identity.matches_metadata_v1(&held_root),
        "restart park private root changed during publication"
    );
    let path_root = fs::symlink_metadata(private_root)
        .context("reinspect restart park publication root path")?;
    ensure!(
        !path_root.file_type().is_symlink() && root_identity.matches_metadata_v1(&path_root),
        "restart park private root path was replaced during publication"
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
            "inspect interrupted restart park writing candidate {}",
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
        "interrupted restart park writing candidate has foreign metadata"
    );
    let expected_identity = ArtifactIdentityV1::from_metadata_v1(&before);

    let observed = if before.len() == 0 {
        Vec::new()
    } else {
        ensure!(
            mode == 0o600,
            "nonempty interrupted restart park writing candidate has incomplete permissions"
        );
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(writing)
            .with_context(|| {
                format!(
                    "open interrupted restart park writing candidate {}",
                    writing.display()
                )
            })?;
        let opened = file
            .metadata()
            .context("inspect opened interrupted restart park writing candidate")?;
        ensure!(
            expected_identity.matches_metadata_v1(&opened),
            "interrupted restart park writing candidate changed while opening"
        );
        let mut observed = Vec::with_capacity(
            usize::try_from(before.len()).context("writing candidate length overflows")?,
        );
        Read::by_ref(&mut file)
            .take(u64::try_from(expected_bytes.len()).unwrap_or(u64::MAX) + 1)
            .read_to_end(&mut observed)
            .context("read interrupted restart park writing candidate")?;
        let after = file
            .metadata()
            .context("reinspect interrupted restart park writing candidate")?;
        ensure!(
            expected_identity.matches_metadata_v1(&after),
            "interrupted restart park writing candidate changed while reading"
        );
        observed
    };
    ensure!(
        expected_bytes.starts_with(&observed),
        "interrupted restart park writing candidate is not an exact canonical prefix"
    );

    let next_exists = path_exists_no_follow_v1(next, "restart park next candidate")?;
    match expected_identity.links {
        1 => ensure!(
            !next_exists,
            "unlinked restart park writing candidate coexists with a foreign fixed candidate"
        ),
        2 => {
            ensure!(
                next_exists && observed == expected_bytes,
                "linked restart park writing candidate is partial or lacks its exact fixed link"
            );
            let next_identity = validate_publication_candidate_v1(next, expected_bytes, 2)?;
            ensure!(
                next_identity == expected_identity,
                "linked restart park writing and fixed candidates are different inodes"
            );
        }
        _ => unreachable!("writing candidate link count was checked above"),
    }

    let path_after = fs::symlink_metadata(writing)
        .context("reinspect interrupted restart park writing candidate path")?;
    ensure!(
        expected_identity.matches_metadata_v1(&path_after),
        "interrupted restart park writing candidate path was replaced"
    );
    revalidate_publication_root_v1(private_root, root_file, root_identity)?;
    fs::remove_file(writing)
        .context("remove authenticated interrupted restart park writing candidate")?;
    root_file
        .sync_all()
        .context("fsync cleaned restart park writing candidate")?;
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
        .context("scan restart park private root for interrupted writing candidates")?
    {
        let entry = entry.context("read restart park private-root writing candidate")?;
        let name = entry.file_name();
        ensure!(
            !RESTART_PARK_CERTIFICATE_SIDECARS_V1[1..]
                .iter()
                .any(|reserved| name == OsStr::new(reserved)),
            "forbidden restart park publication sidecar is preserved: {}",
            entry.path().display()
        );
        let Some(canonical) = writing_candidate_v1(&name) else {
            continue;
        };
        let path = private_root.join(&name);
        ensure!(
            canonical,
            "malformed restart park writing candidate is preserved: {}",
            path.display()
        );
        ensure!(
            writing.replace(path).is_none(),
            "multiple restart park writing candidates are ambiguous and preserved"
        );
    }
    let Some(writing) = writing else {
        return Ok(());
    };
    let target = private_root.join(RESTART_PARK_CERTIFICATE_FILE_V1);
    ensure!(
        !path_exists_no_follow_v1(&target, "restart park target")?,
        "restart park target coexists with an impossible writing candidate"
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
        "restart park writing candidate escaped its unique private path"
    );
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(&writing)
        .context("create-new unique restart park writing candidate")?;
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .context("chmod unique restart park writing candidate")?;
    file.write_all(bytes)
        .context("write unique restart park writing candidate")?;
    file.sync_all()
        .context("fsync unique restart park writing candidate")?;
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
            return Err(error).context("link complete restart park writing candidate no-replace")
        }
    }
    let writing_linked = validate_publication_candidate_v1(writing, bytes, 2)?;
    let next_metadata =
        fs::symlink_metadata(next).context("inspect linked fixed restart park candidate")?;
    ensure!(
        !next_metadata.file_type().is_symlink()
            && writing_linked.matches_metadata_v1(&next_metadata),
        "restart park writing candidate did not link to the exact fixed candidate inode"
    );
    root_file
        .sync_all()
        .context("fsync linked restart park writing candidate")?;
    revalidate_publication_root_v1(private_root, root_file, root_identity)?;
    fs::remove_file(writing).context("remove linked unique restart park writing candidate")?;
    root_file
        .sync_all()
        .context("fsync fixed restart park candidate publication")?;
    revalidate_publication_root_v1(private_root, root_file, root_identity)?;
    validate_publication_candidate_v1(next, bytes, 1)?;
    Ok(())
}

fn publish_create_new_v1(private_root: &Path, bytes: &[u8]) -> Result<()> {
    validate_encoded_bound_v1(bytes)?;
    let (root_file, root_identity) = open_private_root_v1(private_root)?;
    root_file
        .try_lock()
        .context("lock restart park private root publication lifetime")?;
    let target = private_root.join(RESTART_PARK_CERTIFICATE_FILE_V1);
    let next = private_root.join(RESTART_PARK_CERTIFICATE_NEXT_V1);
    ensure!(
        target.parent() == Some(private_root)
            && target.file_name() == Some(OsStr::new(RESTART_PARK_CERTIFICATE_FILE_V1))
            && next.parent() == Some(private_root)
            && next.file_name() == Some(OsStr::new(RESTART_PARK_CERTIFICATE_NEXT_V1)),
        "restart park artifact target escaped its fixed private path"
    );

    cleanup_interrupted_writing_candidates_v1(
        private_root,
        &root_file,
        root_identity,
        bytes,
        &next,
    )?;
    ensure_no_publication_sidecars_except_v1(private_root, Some(RESTART_PARK_CERTIFICATE_NEXT_V1))?;

    let target_exists = path_exists_no_follow_v1(&target, "restart park target")?;
    let next_exists = path_exists_no_follow_v1(&next, "restart park next candidate")?;
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
            fs::symlink_metadata(&target).context("inspect restart park response-loss target")?;
        ensure!(
            !target_metadata.file_type().is_symlink()
                && next_identity.matches_metadata_v1(&target_metadata),
            "restart park target and publication candidate are not one exact response-loss inode"
        );
    } else {
        match fs::hard_link(&next, &target) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => {
                return Err(error).context("publish restart park cut without replacement")
            }
        }
        let next_after_link = validate_publication_candidate_v1(&next, bytes, 2)?;
        let target_metadata =
            fs::symlink_metadata(&target).context("inspect published restart park target")?;
        ensure!(
            !target_metadata.file_type().is_symlink()
                && next_after_link.matches_metadata_v1(&target_metadata),
            "restart park no-replace publication did not create one exact linked target"
        );
    }

    root_file
        .sync_all()
        .context("fsync restart park linked publication")?;
    fs::remove_file(&next).context("remove committed restart park publication candidate")?;
    root_file
        .sync_all()
        .context("fsync restart park final publication")?;
    revalidate_publication_root_v1(private_root, &root_file, root_identity)?;
    drop(root_file);
    ensure_no_publication_sidecars_v1(private_root)?;
    let (_, observed, _) = open_and_read_artifact_v1(private_root)?;
    ensure!(
        observed == bytes,
        "published restart park cut differs from exact canonical input"
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
    let before =
        fs::symlink_metadata(path).context("inspect restart park publication candidate")?;
    ensure!(
        !before.file_type().is_symlink()
            && before.is_file()
            && before.permissions().mode() & 0o7777 == 0o600
            && before.uid() == effective_uid_v1()
            && before.nlink() == expected_links
            && before.len() == u64::try_from(expected_bytes.len()).unwrap_or(u64::MAX)
            && before.len()
                <= u64::try_from(MAX_RESTART_PARK_CERTIFICATE_BYTES_V1).unwrap_or(u64::MAX),
        "restart park publication candidate has invalid private metadata"
    );
    let expected_identity = ArtifactIdentityV1::from_metadata_v1(&before);
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .context("open restart park publication candidate")?;
    let opened = file
        .metadata()
        .context("inspect opened restart park publication candidate")?;
    ensure!(
        expected_identity.matches_metadata_v1(&opened),
        "restart park publication candidate changed while opening"
    );
    let mut observed = Vec::with_capacity(expected_bytes.len());
    Read::by_ref(&mut file)
        .take(u64::try_from(MAX_RESTART_PARK_CERTIFICATE_BYTES_V1).unwrap_or(u64::MAX) + 1)
        .read_to_end(&mut observed)
        .context("read restart park publication candidate")?;
    let after = file
        .metadata()
        .context("reinspect restart park publication candidate")?;
    let path_after =
        fs::symlink_metadata(path).context("reinspect restart park publication candidate path")?;
    ensure!(
        observed == expected_bytes
            && expected_identity.matches_metadata_v1(&after)
            && expected_identity.matches_metadata_v1(&path_after),
        "restart park publication candidate is partial, mutated, or foreign"
    );
    Ok(expected_identity)
}

fn open_and_read_artifact_v1(
    private_root: &Path,
) -> Result<(PinnedRestartParkArtifactV1, Vec<u8>, [u8; 32])> {
    let (root_file, root_identity) = open_private_root_v1(private_root)?;
    ensure_no_publication_sidecars_v1(private_root)?;
    let path = private_root.join(RESTART_PARK_CERTIFICATE_FILE_V1);
    ensure!(
        path.parent() == Some(private_root)
            && path.file_name() == Some(OsStr::new(RESTART_PARK_CERTIFICATE_FILE_V1)),
        "restart park artifact path escaped its fixed private root"
    );

    let before = fs::symlink_metadata(&path).context("inspect restart park cut path")?;
    ensure!(
        !before.file_type().is_symlink(),
        "restart park cut path is a symlink"
    );
    validate_private_artifact_metadata_v1(&before)?;
    let expected_identity = ArtifactIdentityV1::from_metadata_v1(&before);

    let mut artifact_file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(&path)
        .context("open restart park cut")?;
    let opened = artifact_file
        .metadata()
        .context("inspect opened restart park cut")?;
    validate_private_artifact_metadata_v1(&opened)?;
    ensure!(
        expected_identity.matches_metadata_v1(&opened),
        "restart park cut identity changed while opening"
    );

    artifact_file
        .seek(SeekFrom::Start(0))
        .context("seek restart park cut")?;
    let mut bytes = Vec::with_capacity(
        usize::try_from(opened.len()).context("restart park cut byte length overflows")?,
    );
    Read::by_ref(&mut artifact_file)
        .take(u64::try_from(MAX_RESTART_PARK_CERTIFICATE_BYTES_V1).unwrap_or(u64::MAX) + 1)
        .read_to_end(&mut bytes)
        .context("read restart park cut")?;
    ensure!(
        bytes.len() == usize::try_from(opened.len()).unwrap_or(usize::MAX)
            && bytes.len() <= MAX_RESTART_PARK_CERTIFICATE_BYTES_V1,
        "restart park cut byte length changed while reading"
    );
    let observed_sha256 = sha256_v1(&bytes);

    let after_handle = artifact_file
        .metadata()
        .context("reinspect opened restart park cut")?;
    let after_path = fs::symlink_metadata(&path).context("reinspect restart park cut path")?;
    ensure!(
        !after_path.file_type().is_symlink()
            && expected_identity.matches_metadata_v1(&after_handle)
            && expected_identity.matches_metadata_v1(&after_path),
        "restart park cut identity changed during stat/read/hash"
    );
    let root_after = root_file
        .metadata()
        .context("reinspect restart park private root after artifact read")?;
    ensure!(
        root_identity.matches_metadata_v1(&root_after),
        "restart park private root changed during artifact read"
    );
    ensure_no_publication_sidecars_v1(private_root)?;

    Ok((
        PinnedRestartParkArtifactV1 {
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
        "restart park private root is not absolute"
    );
    let before = fs::symlink_metadata(root).context("inspect restart park private root")?;
    ensure!(
        !before.file_type().is_symlink(),
        "restart park private root is a symlink"
    );
    validate_private_root_metadata_v1(&before)?;
    let canonical = fs::canonicalize(root).context("canonicalize restart park private root")?;
    ensure!(
        canonical == root,
        "restart park private root has a symlink or non-canonical ancestor"
    );
    let expected = DirectoryIdentityV1::from_metadata_v1(&before);
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(root)
        .context("open restart park private root")?;
    let opened = file
        .metadata()
        .context("inspect opened restart park private root")?;
    validate_private_root_metadata_v1(&opened)?;
    let after = fs::symlink_metadata(root).context("reinspect restart park private root")?;
    ensure!(
        !after.file_type().is_symlink()
            && expected.matches_metadata_v1(&opened)
            && expected.matches_metadata_v1(&after),
        "restart park private root identity changed while opening"
    );
    Ok((file, expected))
}

fn validate_private_root_metadata_v1(metadata: &fs::Metadata) -> Result<()> {
    ensure!(
        metadata.is_dir()
            && metadata.uid() == effective_uid_v1()
            && metadata.permissions().mode() & 0o7777 == 0o700,
        "restart park private root is not one effective-user-owned 0700 directory"
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
                <= u64::try_from(MAX_RESTART_PARK_CERTIFICATE_BYTES_V1).unwrap_or(u64::MAX),
        "restart park cut is not one exact effective-user-owned private regular file"
    );
    Ok(())
}

fn ensure_no_publication_sidecars_v1(root: &Path) -> Result<()> {
    ensure_no_publication_sidecars_except_v1(root, None)
}

fn ensure_no_publication_sidecars_except_v1(root: &Path, allowed: Option<&str>) -> Result<()> {
    for name in RESTART_PARK_CERTIFICATE_SIDECARS_V1 {
        if allowed == Some(name) {
            continue;
        }
        let path = root.join(name);
        match fs::symlink_metadata(&path) {
            Ok(_) => bail!(
                "restart park publication sidecar unexpectedly exists: {}",
                path.display()
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("inspect restart park sidecar {}", path.display()))
            }
        }
    }
    for entry in
        fs::read_dir(root).context("scan restart park private root for writing sidecars")?
    {
        let entry = entry.context("read restart park private-root sidecar entry")?;
        if writing_candidate_v1(&entry.file_name()).is_some() {
            bail!(
                "restart park publication writing sidecar unexpectedly exists: {}",
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
        os::unix::fs::{symlink, MetadataExt, OpenOptionsExt, PermissionsExt},
        path::Path,
    };

    use ed25519_dalek::{Signer, SigningKey};
    use tempfile::TempDir;
    use trnm_consensus_signer_journal::SignerWatermarkV0;
    use trnm_consensus_types::{
        BlockId, CertificateId, ChainId, ConsensusParametersV0, ConsensusPublicKey, Epoch,
        GenesisHash, Height, ProtocolVersion, QcRef, StateRoot, Validator, ValidatorId,
        ValidatorSet, View, VotingPower,
    };

    use crate::{
        fleet_barrier::{
            CommonCampaignContextV1, CommonChainCutV1, FleetBarrierTransportV1,
            FleetCampaignCapacitiesV1, FleetCampaignIdentityV1, FleetCampaignRequestV1,
            FleetMeshSessionDirectionV1, FleetMeshSessionSetV1, FleetMeshSessionV1,
            FleetReadySetV1, FleetStartCertificateV1, LocalReadyCutV1, SignedFleetReadyV1,
            SignedFleetStartV1,
        },
        restart_cut::{
            LocalRestartParkV1, RestartCutBodyV1, RestartCutStateV1, RestartParkCertificateV1,
            RestartParkRoleV1, SignedLocalRestartParkV1,
        },
    };

    use super::*;

    fn validator_fixture() -> (ValidatorSet, Vec<SigningKey>) {
        let keys = (0..7)
            .map(|index| SigningKey::from_bytes(&[0x31 + index; 32]))
            .collect::<Vec<_>>();
        let parameters = ConsensusParametersV0::reference_shadow_v0();
        let validators = keys
            .iter()
            .enumerate()
            .map(|(index, key)| {
                Validator::new(
                    ValidatorId::new([0x11 + u8::try_from(index).unwrap(); 32]),
                    ConsensusPublicKey::new(key.verifying_key().to_bytes()),
                    VotingPower::new(1).unwrap(),
                )
                .unwrap()
            })
            .collect();
        let set = ValidatorSet::new(
            GenesisHash::new([0x21; 32]),
            ChainId::new("trnm-poco-g3-restart-cut-test").unwrap(),
            ProtocolVersion::V0,
            Epoch::new(0),
            parameters.hash(),
            validators,
        )
        .unwrap();
        (set, keys)
    }

    fn campaign(set: &ValidatorSet) -> CommonCampaignContextV1 {
        CommonCampaignContextV1::new(
            FleetCampaignIdentityV1::new(
                "poco-g3-7-20260814T000000Z-89abcdef".to_owned(),
                set.chain_id(),
                *set.genesis_hash().as_bytes(),
                *set.id().as_bytes(),
                [0x41; 32],
                [0x42; 32],
                [0x43; 32],
                [0x44; 32],
                [0x45; 32],
                [0x46; 32],
                [0x47; 32],
                u32::try_from(set.validators().len()).unwrap(),
            )
            .unwrap(),
            FleetCampaignRequestV1::new(
                1,
                4,
                60,
                2,
                30,
                30,
                100,
                103,
                FleetBarrierTransportV1::Direct,
            )
            .unwrap(),
            FleetCampaignCapacitiesV1::new(4_096, 60, 163, 160, 60, 220, 8_192, 160, 161, 321, 108)
                .unwrap(),
            CommonChainCutV1::new(
                3, 4, 0, [0x50; 32], 3, 3, [0x51; 32], 1, [0x52; 32], 3, [0x53; 32], 3, [0x53; 32],
                [0x54; 32], 5, 2, 5,
            )
            .unwrap(),
        )
        .unwrap()
    }

    fn mesh_and_local_cut(
        set: &ValidatorSet,
        index: usize,
    ) -> (FleetMeshSessionSetV1, LocalReadyCutV1) {
        let local = set.validators()[index].id();
        let mut sessions = Vec::new();
        for (remote_index, remote) in set.validators().iter().enumerate() {
            if remote.id() == local {
                continue;
            }
            sessions.push(
                FleetMeshSessionV1::new(
                    FleetMeshSessionDirectionV1::Incoming,
                    remote.id(),
                    [0x20 + u8::try_from(remote_index * set.validators().len() + index).unwrap();
                        32],
                )
                .unwrap(),
            );
            sessions.push(
                FleetMeshSessionV1::new(
                    FleetMeshSessionDirectionV1::Outgoing,
                    remote.id(),
                    [0x20 + u8::try_from(index * set.validators().len() + remote_index).unwrap();
                        32],
                )
                .unwrap(),
            );
        }
        let mesh = FleetMeshSessionSetV1::new(local, sessions, set).unwrap();
        let local_cut = LocalReadyCutV1::new(
            local,
            [0x61 + u8::try_from(index).unwrap(); 32],
            1,
            10 + u64::try_from(index).unwrap(),
            [0x71 + u8::try_from(index).unwrap(); 32],
            &mesh,
            [0x91 + u8::try_from(index).unwrap(); 32],
            [0xa1 + u8::try_from(index).unwrap(); 32],
            [0xb1 + u8::try_from(index).unwrap(); 32],
            [0xc1 + u8::try_from(index).unwrap(); 32],
        )
        .unwrap();
        (mesh, local_cut)
    }

    fn fleet_start_certificate(
        set: &ValidatorSet,
        keys: &[SigningKey],
        campaign: &CommonCampaignContextV1,
        event_salt: u8,
    ) -> FleetStartCertificateV1 {
        let ready = keys
            .iter()
            .enumerate()
            .map(|(index, key)| {
                let (mesh, local_cut) = mesh_and_local_cut(set, index);
                SignedFleetReadyV1::new(campaign.clone(), local_cut, mesh, set, key).unwrap()
            })
            .collect::<Vec<_>>();
        let ready_set = FleetReadySetV1::new(campaign.clone(), ready.clone(), set).unwrap();
        let starts = ready
            .iter()
            .zip(keys)
            .enumerate()
            .map(|(index, (ready, key))| {
                SignedFleetStartV1::new(
                    ready,
                    &ready_set,
                    ready.local_cut().pre_ready_journal_sequence() + 1,
                    [event_salt + u8::try_from(index).unwrap(); 32],
                    set,
                    key,
                )
                .unwrap()
            })
            .collect();
        FleetStartCertificateV1::new(ready_set, starts, set).unwrap()
    }

    fn restart_state(set: &ValidatorSet) -> RestartCutStateV1 {
        RestartCutStateV1 {
            epoch: Epoch::new(0),
            current_view: View::new(10),
            direct_high_qc: QcRef::new(
                CertificateId::new([0x81; 32]),
                Epoch::new(0),
                View::new(9),
                Height::new(8),
                BlockId::new([0x82; 32]),
                set.id(),
            ),
            proposal_parent_height: Height::new(8),
            proposal_parent_block_id: BlockId::new([0x82; 32]),
            finalized_height: Height::new(6),
            finalized_block_id: BlockId::new([0x83; 32]),
            finalized_chain_root: [0x8f; 32],
            application_height: Height::new(6),
            application_block_id: BlockId::new([0x83; 32]),
            application_state_root: StateRoot::new([0x84; 32]),
            external_checkpoint_generation: 12,
            external_checkpoint_checksum: [0x85; 32],
            safety_revision: 13,
            safety_state_record_checksum: [0x8c; 32],
            safety_record_chain_checksum: [0x8d; 32],
            signer_watermark: SignerWatermarkV0::from_persisted_parts(
                [0x89; 32], [0x8a; 32], 6, [0x8b; 32],
            )
            .unwrap(),
            signer_durable_vote_intent_count: 2,
            signer_durable_timeout_intent_count: 1,
            signer_signed_vote_intent_count: 2,
            signer_signed_timeout_intent_count: 1,
            signer_inventory_digest: [0x8e; 32],
            pending_sign: None,
            replay_archive_context_sha256: [0x86; 32],
            replay_archive_head_sequence: 4,
            replay_archive_head_sha256: [0x87; 32],
            runtime_journal_head_sequence: 20,
            runtime_journal_head_sha256: [0x88; 32],
        }
    }

    fn restart_target_config_sha256(
        set: &ValidatorSet,
        start: &FleetStartCertificateV1,
    ) -> [u8; 32] {
        restart_local_config_sha256(set, start, 2)
    }

    fn restart_local_config_sha256(
        set: &ValidatorSet,
        start: &FleetStartCertificateV1,
        index: usize,
    ) -> [u8; 32] {
        start
            .ready_set()
            .statement(set.validators()[index].id())
            .expect("local Ready statement exists")
            .local_cut()
            .config_sha256()
    }

    fn restart_body(
        set: &ValidatorSet,
        campaign: &CommonCampaignContextV1,
        start: &FleetStartCertificateV1,
    ) -> RestartCutBodyV1 {
        RestartCutBodyV1::new(
            campaign.clone(),
            set.validators()[2].id(),
            restart_target_config_sha256(set, start),
            1,
            restart_state(set),
            start,
            set,
        )
        .unwrap()
    }

    fn peer_restart_state(set: &ValidatorSet, salt: u8) -> RestartCutStateV1 {
        let mut state = restart_state(set);
        state.external_checkpoint_checksum = [salt; 32];
        state.safety_revision += 1;
        state.safety_state_record_checksum = [salt.wrapping_add(1); 32];
        state.safety_record_chain_checksum = [salt.wrapping_add(2); 32];
        state.signer_watermark = SignerWatermarkV0::from_persisted_parts(
            [salt.wrapping_add(3); 32],
            [salt.wrapping_add(4); 32],
            6,
            [salt.wrapping_add(5); 32],
        )
        .unwrap();
        state.signer_inventory_digest = [salt.wrapping_add(6); 32];
        state.replay_archive_context_sha256 = [salt.wrapping_add(7); 32];
        state.replay_archive_head_sha256 = [salt.wrapping_add(8); 32];
        state.runtime_journal_head_sha256 = [salt.wrapping_add(9); 32];
        state
    }

    fn target_restart_park(
        set: &ValidatorSet,
        start: &FleetStartCertificateV1,
        body: &RestartCutBodyV1,
    ) -> LocalRestartParkV1 {
        LocalRestartParkV1::new(
            RestartParkRoleV1::Target,
            body.target_validator(),
            body.target_config_sha256(),
            body.process_instance(),
            body,
            body.state(),
            start,
            set,
        )
        .unwrap()
    }

    fn peer_restart_park(
        set: &ValidatorSet,
        start: &FleetStartCertificateV1,
        body: &RestartCutBodyV1,
        index: usize,
    ) -> LocalRestartParkV1 {
        assert_ne!(set.validators()[index].id(), body.target_validator());
        LocalRestartParkV1::new(
            RestartParkRoleV1::Peer,
            set.validators()[index].id(),
            restart_local_config_sha256(set, start, index),
            body.process_instance(),
            body,
            peer_restart_state(set, 0xa0 + u8::try_from(index).unwrap()),
            start,
            set,
        )
        .unwrap()
    }

    fn signed_park_statement(
        set: &ValidatorSet,
        keys: &[SigningKey],
        start: &FleetStartCertificateV1,
        body: &RestartCutBodyV1,
        park: LocalRestartParkV1,
    ) -> SignedLocalRestartParkV1 {
        let index = set
            .validators()
            .iter()
            .position(|validator| validator.id() == park.local_validator())
            .expect("park origin exists");
        let digest = SignedLocalRestartParkV1::signing_digest_for_parts(
            park.local_validator(),
            body,
            &park,
            start,
            set,
        )
        .unwrap();
        SignedLocalRestartParkV1::from_parts(
            park.local_validator(),
            body,
            park,
            keys[index].sign(&digest).to_bytes(),
            start,
            set,
        )
        .unwrap()
    }

    fn park_statements(
        set: &ValidatorSet,
        keys: &[SigningKey],
        start: &FleetStartCertificateV1,
        body: &RestartCutBodyV1,
    ) -> Vec<SignedLocalRestartParkV1> {
        set.validators()
            .iter()
            .enumerate()
            .map(|(index, validator)| {
                let park = if validator.id() == body.target_validator() {
                    target_restart_park(set, start, body)
                } else {
                    peer_restart_park(set, start, body, index)
                };
                signed_park_statement(set, keys, start, body, park)
            })
            .collect()
    }

    struct Fixture {
        set: ValidatorSet,
        keys: Vec<SigningKey>,
        fleet_start: FleetStartCertificateV1,
        body: RestartCutBodyV1,
        certificate: RestartParkCertificateV1,
        artifact_sha256: [u8; 32],
        local_validator: ValidatorId,
        local_config_sha256: [u8; 32],
    }

    fn fixture_with_start_salt(start_salt: u8) -> Fixture {
        let (set, keys) = validator_fixture();
        let campaign = campaign(&set);
        let fleet_start = fleet_start_certificate(&set, &keys, &campaign, start_salt);
        let body = restart_body(&set, &campaign, &fleet_start);
        let statements = park_statements(&set, &keys, &fleet_start, &body);
        let certificate =
            RestartParkCertificateV1::new(body.clone(), statements, &fleet_start, &set).unwrap();
        let artifact_sha256 = sha256_v1(&certificate.encode());
        let local_validator = body.target_validator();
        let local_config_sha256 = body.target_config_sha256();
        Fixture {
            set,
            keys,
            fleet_start,
            body,
            certificate,
            artifact_sha256,
            local_validator,
            local_config_sha256,
        }
    }

    fn fixture() -> Fixture {
        fixture_with_start_salt(0xd0)
    }

    fn alternate_body_and_certificate(
        fixture: &Fixture,
    ) -> (RestartCutBodyV1, RestartParkCertificateV1) {
        let mut state = restart_state(&fixture.set);
        state.runtime_journal_head_sha256 = [0xe1; 32];
        let body = RestartCutBodyV1::new(
            fixture.body.campaign().clone(),
            fixture.body.target_validator(),
            fixture.body.target_config_sha256(),
            1,
            state,
            &fixture.fleet_start,
            &fixture.set,
        )
        .unwrap();
        let statements = park_statements(&fixture.set, &fixture.keys, &fixture.fleet_start, &body);
        let certificate = RestartParkCertificateV1::new(
            body.clone(),
            statements,
            &fixture.fleet_start,
            &fixture.set,
        )
        .unwrap();
        (body, certificate)
    }

    fn other_validator_set(fixture: &Fixture) -> ValidatorSet {
        let mut validators = fixture.set.validators().to_vec();
        validators[6] = Validator::new(
            ValidatorId::new([0xf1; 32]),
            ConsensusPublicKey::new(
                SigningKey::from_bytes(&[0xf2; 32])
                    .verifying_key()
                    .to_bytes(),
            ),
            VotingPower::new(1).unwrap(),
        )
        .unwrap();
        ValidatorSet::new(
            fixture.set.genesis_hash(),
            fixture.set.chain_id(),
            fixture.set.protocol_version(),
            fixture.set.epoch(),
            fixture.set.consensus_parameters_hash(),
            validators,
        )
        .unwrap()
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

    fn persist_result(
        fixture: &Fixture,
        root: &Path,
    ) -> anyhow::Result<StoredRestartParkCertificateV1> {
        persist_restart_park_certificate_v1(
            root,
            fixture.artifact_sha256,
            fixture.certificate.clone(),
            &fixture.body,
            fixture.local_validator,
            fixture.local_config_sha256,
            &fixture.fleet_start,
            &fixture.set,
        )
    }

    fn persist(fixture: &Fixture, root: &Path) -> StoredRestartParkCertificateV1 {
        persist_result(fixture, root).unwrap()
    }

    #[test]
    fn certificate_persists_loads_idempotently_and_fresh_revalidates() {
        let fixture = fixture();
        let root = private_root();
        let stored = persist(&fixture, root.path());
        assert_eq!(stored.value_v1(), &fixture.certificate);
        assert_eq!(stored.body_v1(), &fixture.body);
        assert_eq!(stored.local_validator_v1(), fixture.local_validator);
        assert_eq!(stored.local_config_sha256_v1(), fixture.local_config_sha256);
        assert_eq!(
            stored.local_statement_v1(),
            fixture
                .certificate
                .statement(fixture.local_validator)
                .unwrap()
        );
        assert_eq!(stored.artifact_sha256_v1(), fixture.artifact_sha256);
        assert_eq!(
            stored.path_v1(),
            root.path().join(RESTART_PARK_CERTIFICATE_FILE_V1)
        );
        assert_eq!(stored.body_v1().process_instance(), 1);
        stored
            .revalidate_fresh_v1(&fixture.fleet_start, &fixture.set)
            .unwrap();

        let loaded = load_restart_park_certificate_v1(
            root.path(),
            fixture.artifact_sha256,
            &fixture.body,
            fixture.local_validator,
            fixture.local_config_sha256,
            &fixture.fleet_start,
            &fixture.set,
        )
        .unwrap();
        loaded
            .revalidate_fresh_v1(&fixture.fleet_start, &fixture.set)
            .unwrap();
        let metadata = fs::symlink_metadata(stored.path_v1()).unwrap();
        assert_eq!(metadata.permissions().mode() & 0o7777, 0o600);
        assert_eq!(metadata.uid(), effective_uid_v1());
        assert_eq!(metadata.nlink(), 1);

        persist(&fixture, root.path())
            .revalidate_fresh_v1(&fixture.fleet_start, &fixture.set)
            .unwrap();

        let peer = fixture
            .set
            .validators()
            .iter()
            .map(|validator| validator.id())
            .find(|validator| *validator != fixture.body.target_validator())
            .unwrap();
        let peer_config = fixture
            .certificate
            .statement(peer)
            .unwrap()
            .local_park()
            .local_config_sha256();
        let peer_root = private_root();
        let peer_stored = persist_restart_park_certificate_v1(
            peer_root.path(),
            fixture.artifact_sha256,
            fixture.certificate.clone(),
            &fixture.body,
            peer,
            peer_config,
            &fixture.fleet_start,
            &fixture.set,
        )
        .unwrap();
        assert_eq!(peer_stored.local_validator_v1(), peer);
        assert_eq!(peer_stored.local_config_sha256_v1(), peer_config);
        assert_eq!(
            peer_stored.local_statement_v1(),
            fixture.certificate.statement(peer).unwrap()
        );
        peer_stored
            .revalidate_fresh_v1(&fixture.fleet_start, &fixture.set)
            .unwrap();
    }

    #[test]
    fn expected_sha_fleet_set_body_and_local_binding_are_required() {
        let fixture = fixture();
        let root = private_root();
        drop(persist(&fixture, root.path()));

        for wrong_sha in [[0; 32], [0xee; 32]] {
            assert!(load_restart_park_certificate_v1(
                root.path(),
                wrong_sha,
                &fixture.body,
                fixture.local_validator,
                fixture.local_config_sha256,
                &fixture.fleet_start,
                &fixture.set,
            )
            .is_err());
        }

        let (alternate_body, _alternate_certificate) = alternate_body_and_certificate(&fixture);
        assert!(load_restart_park_certificate_v1(
            root.path(),
            fixture.artifact_sha256,
            &alternate_body,
            fixture.local_validator,
            fixture.local_config_sha256,
            &fixture.fleet_start,
            &fixture.set,
        )
        .is_err());
        let wrong_start = fixture_with_start_salt(0xe0);
        assert!(load_restart_park_certificate_v1(
            root.path(),
            fixture.artifact_sha256,
            &fixture.body,
            fixture.local_validator,
            fixture.local_config_sha256,
            &wrong_start.fleet_start,
            &fixture.set,
        )
        .is_err());
        assert!(load_restart_park_certificate_v1(
            root.path(),
            fixture.artifact_sha256,
            &fixture.body,
            fixture.local_validator,
            fixture.local_config_sha256,
            &fixture.fleet_start,
            &other_validator_set(&fixture),
        )
        .is_err());
        assert!(load_restart_park_certificate_v1(
            root.path(),
            fixture.artifact_sha256,
            &fixture.body,
            fixture.local_validator,
            [0xef; 32],
            &fixture.fleet_start,
            &fixture.set,
        )
        .is_err());
        assert!(load_restart_park_certificate_v1(
            root.path(),
            fixture.artifact_sha256,
            &fixture.body,
            ValidatorId::new([0xfe; 32]),
            fixture.local_config_sha256,
            &fixture.fleet_start,
            &fixture.set,
        )
        .is_err());
    }

    #[test]
    fn publication_reconciles_exact_next_linked_and_writing_response_loss() {
        let fixture = fixture();
        let bytes = fixture.certificate.encode();

        let next_only = private_root();
        write_test_artifact(next_only.path(), RESTART_PARK_CERTIFICATE_NEXT_V1, &bytes);
        drop(persist(&fixture, next_only.path()));
        assert!(!next_only
            .path()
            .join(RESTART_PARK_CERTIFICATE_NEXT_V1)
            .exists());
        assert_eq!(
            fs::read(next_only.path().join(RESTART_PARK_CERTIFICATE_FILE_V1)).unwrap(),
            bytes
        );

        let linked = private_root();
        let target = persist(&fixture, linked.path()).path_v1().to_path_buf();
        let next = linked.path().join(RESTART_PARK_CERTIFICATE_NEXT_V1);
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
                fs::read(root.path().join(RESTART_PARK_CERTIFICATE_FILE_V1)).unwrap(),
                bytes
            );
        }

        let root = private_root();
        let writing_name = writing_file_name_v1(0x71a2, 9);
        let writing = root.path().join(&writing_name);
        let next = root.path().join(RESTART_PARK_CERTIFICATE_NEXT_V1);
        write_test_artifact(root.path(), &writing_name, &bytes);
        fs::hard_link(&writing, &next).unwrap();
        File::open(root.path()).unwrap().sync_all().unwrap();
        drop(persist(&fixture, root.path()));
        assert!(!writing.exists());
        assert!(!next.exists());
    }

    #[test]
    fn partial_foreign_and_ambiguous_publication_states_fail_closed() {
        let fixture = fixture();
        let bytes = fixture.certificate.encode();

        let partial_next = private_root();
        write_test_artifact(
            partial_next.path(),
            RESTART_PARK_CERTIFICATE_NEXT_V1,
            &bytes[..bytes.len() - 1],
        );
        assert!(persist_restart_park_certificate_v1(
            partial_next.path(),
            fixture.artifact_sha256,
            fixture.certificate.clone(),
            &fixture.body,
            fixture.local_validator,
            fixture.local_config_sha256,
            &fixture.fleet_start,
            &fixture.set,
        )
        .is_err());
        assert!(partial_next
            .path()
            .join(RESTART_PARK_CERTIFICATE_NEXT_V1)
            .exists());

        let partial_target = private_root();
        write_test_artifact(
            partial_target.path(),
            RESTART_PARK_CERTIFICATE_FILE_V1,
            &bytes[..bytes.len() - 1],
        );
        assert!(persist_restart_park_certificate_v1(
            partial_target.path(),
            fixture.artifact_sha256,
            fixture.certificate.clone(),
            &fixture.body,
            fixture.local_validator,
            fixture.local_config_sha256,
            &fixture.fleet_start,
            &fixture.set,
        )
        .is_err());

        let mutant_writing = private_root();
        let name = writing_file_name_v1(0x71a3, 10);
        let path = mutant_writing.path().join(&name);
        let mut mutant = bytes[..bytes.len() - 1].to_vec();
        mutant[0] ^= 1;
        write_test_artifact(mutant_writing.path(), &name, &mutant);
        assert!(persist_restart_park_certificate_v1(
            mutant_writing.path(),
            fixture.artifact_sha256,
            fixture.certificate.clone(),
            &fixture.body,
            fixture.local_validator,
            fixture.local_config_sha256,
            &fixture.fleet_start,
            &fixture.set,
        )
        .is_err());
        assert_eq!(fs::read(path).unwrap(), mutant);

        let separate = private_root();
        let name = writing_file_name_v1(0x71a4, 11);
        write_test_artifact(separate.path(), &name, &bytes);
        write_test_artifact(separate.path(), RESTART_PARK_CERTIFICATE_NEXT_V1, &bytes);
        assert!(persist_restart_park_certificate_v1(
            separate.path(),
            fixture.artifact_sha256,
            fixture.certificate.clone(),
            &fixture.body,
            fixture.local_validator,
            fixture.local_config_sha256,
            &fixture.fleet_start,
            &fixture.set,
        )
        .is_err());
        assert!(separate.path().join(name).exists());
        assert!(separate
            .path()
            .join(RESTART_PARK_CERTIFICATE_NEXT_V1)
            .exists());

        let multiple = private_root();
        let first = writing_file_name_v1(0x71a5, 12);
        let second = writing_file_name_v1(0x71a6, 13);
        write_test_artifact(multiple.path(), &first, &bytes[..1]);
        write_test_artifact(multiple.path(), &second, &bytes[..2]);
        assert!(persist_result(&fixture, multiple.path()).is_err());
        assert!(multiple.path().join(first).exists());
        assert!(multiple.path().join(second).exists());

        let target_and_writing = private_root();
        let writing = writing_file_name_v1(0x71a7, 14);
        write_test_artifact(
            target_and_writing.path(),
            RESTART_PARK_CERTIFICATE_FILE_V1,
            &bytes,
        );
        write_test_artifact(target_and_writing.path(), &writing, &bytes[..1]);
        assert!(persist_result(&fixture, target_and_writing.path()).is_err());
        assert!(target_and_writing
            .path()
            .join(RESTART_PARK_CERTIFICATE_FILE_V1)
            .exists());
        assert!(target_and_writing.path().join(writing).exists());

        let valid_and_malformed = private_root();
        let valid = writing_file_name_v1(0x71a8, 15);
        let malformed = format!("{RESTART_PARK_CERTIFICATE_WRITING_PREFIX_V1}malformed");
        write_test_artifact(valid_and_malformed.path(), &valid, &bytes[..1]);
        write_test_artifact(valid_and_malformed.path(), &malformed, &bytes[..1]);
        assert!(persist_result(&fixture, valid_and_malformed.path()).is_err());
        assert!(valid_and_malformed.path().join(valid).exists());
        assert!(valid_and_malformed.path().join(malformed).exists());

        let writing_and_forbidden = private_root();
        let writing = writing_file_name_v1(0x71a9, 16);
        write_test_artifact(writing_and_forbidden.path(), &writing, &bytes[..1]);
        write_test_artifact(
            writing_and_forbidden.path(),
            RESTART_PARK_CERTIFICATE_SIDECARS_V1[1],
            b"foreign",
        );
        assert!(persist_result(&fixture, writing_and_forbidden.path()).is_err());
        assert!(writing_and_forbidden.path().join(writing).exists());
        assert!(writing_and_forbidden
            .path()
            .join(RESTART_PARK_CERTIFICATE_SIDECARS_V1[1])
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
        assert!(stored
            .revalidate_fresh_v1(&fixture.fleet_start, &fixture.set)
            .is_err());

        let replacement_root = private_root();
        let stored = persist(&fixture, replacement_root.path());
        let path = stored.path_v1().to_path_buf();
        let bytes = fs::read(&path).unwrap();
        fs::rename(&path, replacement_root.path().join("displaced-park.bin")).unwrap();
        write_test_artifact(
            replacement_root.path(),
            RESTART_PARK_CERTIFICATE_FILE_V1,
            &bytes,
        );
        assert!(stored
            .revalidate_fresh_v1(&fixture.fleet_start, &fixture.set)
            .is_err());

        let parent = TempDir::new().unwrap();
        let live_root = parent.path().join("live-root");
        let displaced_root = parent.path().join("displaced-root");
        fs::create_dir(&live_root).unwrap();
        fs::set_permissions(&live_root, fs::Permissions::from_mode(0o700)).unwrap();
        let stored = persist(&fixture, &live_root);
        let bytes = fixture.certificate.encode();
        fs::rename(&live_root, &displaced_root).unwrap();
        fs::create_dir(&live_root).unwrap();
        fs::set_permissions(&live_root, fs::Permissions::from_mode(0o700)).unwrap();
        write_test_artifact(&live_root, RESTART_PARK_CERTIFICATE_FILE_V1, &bytes);
        assert!(stored
            .revalidate_fresh_v1(&fixture.fleet_start, &fixture.set)
            .is_err());
    }

    #[test]
    fn filesystem_policy_rejects_symlink_nonregular_hardlink_modes_sizes_sidecars_and_ancestry() {
        let fixture = fixture();

        let symlink_root = private_root();
        symlink(
            "/dev/null",
            symlink_root.path().join(RESTART_PARK_CERTIFICATE_FILE_V1),
        )
        .unwrap();
        assert!(load_restart_park_certificate_v1(
            symlink_root.path(),
            fixture.artifact_sha256,
            &fixture.body,
            fixture.local_validator,
            fixture.local_config_sha256,
            &fixture.fleet_start,
            &fixture.set,
        )
        .is_err());

        let nonregular_root = private_root();
        fs::create_dir(
            nonregular_root
                .path()
                .join(RESTART_PARK_CERTIFICATE_FILE_V1),
        )
        .unwrap();
        assert!(load_restart_park_certificate_v1(
            nonregular_root.path(),
            fixture.artifact_sha256,
            &fixture.body,
            fixture.local_validator,
            fixture.local_config_sha256,
            &fixture.fleet_start,
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
        assert!(stored
            .revalidate_fresh_v1(&fixture.fleet_start, &fixture.set)
            .is_err());

        let artifact_mode_root = private_root();
        let stored = persist(&fixture, artifact_mode_root.path());
        fs::set_permissions(stored.path_v1(), fs::Permissions::from_mode(0o640)).unwrap();
        assert!(stored
            .revalidate_fresh_v1(&fixture.fleet_start, &fixture.set)
            .is_err());

        let root_mode = private_root();
        fs::set_permissions(root_mode.path(), fs::Permissions::from_mode(0o750)).unwrap();
        assert!(persist_restart_park_certificate_v1(
            root_mode.path(),
            fixture.artifact_sha256,
            fixture.certificate.clone(),
            &fixture.body,
            fixture.local_validator,
            fixture.local_config_sha256,
            &fixture.fleet_start,
            &fixture.set,
        )
        .is_err());

        let oversized = private_root();
        write_test_artifact(
            oversized.path(),
            RESTART_PARK_CERTIFICATE_FILE_V1,
            &vec![0u8; MAX_RESTART_PARK_CERTIFICATE_BYTES_V1 + 1],
        );
        assert!(load_restart_park_certificate_v1(
            oversized.path(),
            fixture.artifact_sha256,
            &fixture.body,
            fixture.local_validator,
            fixture.local_config_sha256,
            &fixture.fleet_start,
            &fixture.set,
        )
        .is_err());

        let sidecar_root = private_root();
        let stored = persist(&fixture, sidecar_root.path());
        symlink(
            RESTART_PARK_CERTIFICATE_FILE_V1,
            sidecar_root
                .path()
                .join(RESTART_PARK_CERTIFICATE_SIDECARS_V1[1]),
        )
        .unwrap();
        assert!(stored
            .revalidate_fresh_v1(&fixture.fleet_start, &fixture.set)
            .is_err());

        let root_symlink_parent = TempDir::new().unwrap();
        let real_parent = root_symlink_parent.path().join("real-parent");
        let real_root = real_parent.join("private-root");
        let alias_parent = root_symlink_parent.path().join("alias-parent");
        let alias_root = alias_parent.join("private-root");
        fs::create_dir(&real_parent).unwrap();
        fs::create_dir(&real_root).unwrap();
        fs::set_permissions(&real_root, fs::Permissions::from_mode(0o700)).unwrap();
        symlink(&real_parent, &alias_parent).unwrap();
        assert!(persist_restart_park_certificate_v1(
            &alias_root,
            fixture.artifact_sha256,
            fixture.certificate.clone(),
            &fixture.body,
            fixture.local_validator,
            fixture.local_config_sha256,
            &fixture.fleet_start,
            &fixture.set,
        )
        .is_err());
    }

    #[test]
    fn exact_decode_and_store_reject_trailing_bytes_even_with_matching_raw_sha() {
        let fixture = fixture();
        let root = private_root();
        let mut trailing = fixture.certificate.encode();
        trailing.push(0);
        assert!(
            RestartParkCertificateV1::decode(&trailing, &fixture.fleet_start, &fixture.set,)
                .is_err()
        );
        write_test_artifact(root.path(), RESTART_PARK_CERTIFICATE_FILE_V1, &trailing);
        assert!(load_restart_park_certificate_v1(
            root.path(),
            sha256_v1(&trailing),
            &fixture.body,
            fixture.local_validator,
            fixture.local_config_sha256,
            &fixture.fleet_start,
            &fixture.set,
        )
        .is_err());
    }

    #[test]
    fn store_has_no_signer_journal_network_barrier_or_process_authority_surface() {
        let source = include_str!("restart_park_store.rs");
        let normal = &source[..source.find("#[cfg(test)]").unwrap()];
        for forbidden in [
            "SigningKey",
            "TcpStream",
            "UdpSocket",
            "RuntimeEventJournalV1",
            "RuntimeControl",
            "ProcessHost",
            "RecoveryReadySetV1",
            "RecoveryStartCertificateV1",
            "fn activate",
            "fn arm",
            "fn append",
            "fn sign",
            "Command::new",
            "kill(",
            "set_len(",
            "OpenOptions::new().truncate",
        ] {
            assert!(
                !normal.contains(forbidden),
                "normal restart-park store contains forbidden authority token {forbidden}"
            );
        }
        assert!(!normal.contains("pub fn "));
        assert!(!normal.contains("impl Clone for StoredRestartParkCertificateV1"));
    }
}
