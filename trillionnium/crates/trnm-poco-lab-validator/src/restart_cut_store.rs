//! Durable, content-addressed storage for one local N/N RestartCut artifact.
//!
//! This module owns only a private file publication/readback boundary. It
//! cannot form a certificate, append the runtime journal, stop a process,
//! recover a Node authority, activate a signer, or arm a timer.
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
use trnm_consensus_types::{ValidatorId, ValidatorSet};

use crate::{
    config::LoadedValidatorConfig,
    fleet_barrier::{FleetStartCertificateV1, MAX_FLEET_START_CERTIFICATE_BYTES_V1},
    restart_cut::{
        RestartCutBodyV1, RestartCutCertificateV1, SignedRestartCutV1,
        VerifiedRestartCutCertificateV1, MAX_RESTART_CUT_CERTIFICATE_BYTES_V1,
    },
};

const FLEET_START_CERTIFICATE_FILE_V1: &str = "fleet-start-certificate.bin";
const RESTART_CUT_CERTIFICATE_FILE_V1: &str = "restart-cut-certificate.bin";
const RESTART_CUT_CERTIFICATE_NEXT_FILE_V1: &str = "restart-cut-certificate.next";
const RESTART_CUT_CERTIFICATE_SIDECARS_V1: [&str; 3] = [
    RESTART_CUT_CERTIFICATE_NEXT_FILE_V1,
    "restart-cut-certificate.tmp",
    "restart-cut-certificate.lock",
];
const RESTART_CUT_CERTIFICATE_WRITING_PREFIX_V1: &str = "restart-cut-certificate.writing.";
static RESTART_CUT_WRITING_ATTEMPT_V1: AtomicU64 = AtomicU64::new(0);

/// Non-Clone proof that the exact verified N/N certificate is durably visible
/// at the local private run root and survived a canonical fresh readback.
#[must_use = "a stored RestartCut is required by the later journal/startup join"]
pub(crate) struct StoredRestartCutCertificateV1 {
    verified: VerifiedRestartCutCertificateV1,
    pinned: PinnedRestartCutArtifactV1,
    fleet_start: FleetStartCertificateV1,
    validator_set: ValidatorSet,
    local_validator: ValidatorId,
    local_config_sha256: [u8; 32],
}

impl std::fmt::Debug for StoredRestartCutCertificateV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("StoredRestartCutCertificateV1")
            .field("path", &self.pinned.path)
            .field("target_validator", &self.verified.body().target_validator())
            .field("artifact_sha256", &self.verified.artifact_sha256())
            .finish_non_exhaustive()
    }
}

impl StoredRestartCutCertificateV1 {
    /// Borrows the exact authenticated certificate without splitting the
    /// non-Clone durable owner. Later composite stores use this only to
    /// reverify cross-artifact identities.
    pub(crate) const fn certificate_v1(&self) -> &RestartCutCertificateV1 {
        self.verified.certificate()
    }

    pub(crate) const fn body_v1(&self) -> &RestartCutBodyV1 {
        self.verified.body()
    }

    pub(crate) const fn artifact_sha256_v1(&self) -> [u8; 32] {
        self.verified.artifact_sha256()
    }

    pub(crate) const fn statement_count_v1(&self) -> usize {
        self.verified.certificate().statement_count()
    }

    /// Borrowed signed data only.  This does not split or transfer the
    /// durable owner; the composite Cut/Park boundary uses it to rederive
    /// canonical phase message identities after a fresh readback.
    pub(crate) fn statement_v1(&self, origin: ValidatorId) -> Option<&SignedRestartCutV1> {
        self.verified.certificate().statement(origin)
    }

    pub(crate) fn contains_exact_target_prepare_v1(
        &self,
        target_prepare: &SignedRestartCutV1,
    ) -> bool {
        target_prepare.origin() == self.verified.body().target_validator()
            && target_prepare.body() == self.verified.body()
            && self
                .verified
                .certificate()
                .statement(target_prepare.origin())
                == Some(target_prepare)
    }

    /// Reasserts that the authenticated target declaration is present in the
    /// exact N/N carrier. This keeps process-2 startup from treating the body
    /// projection alone as restart authority.
    pub(crate) fn has_exact_target_prepare_v1(&self) -> bool {
        self.verified
            .certificate()
            .statement(self.verified.body().target_validator())
            .is_some_and(|target_prepare| self.contains_exact_target_prepare_v1(target_prepare))
    }

    /// Reopens the final artifact and repeats the complete held-identity,
    /// canonical-decode, N/N authentication, FleetStart, validator-set, local
    /// membership/config, content-address, and exact-byte join.
    pub(crate) fn revalidate_fresh_readback_v1(&self) -> Result<()> {
        validate_local_binding_v1(
            &self.verified,
            self.local_validator,
            self.local_config_sha256,
            &self.validator_set,
            &self.fleet_start,
        )?;
        self.fleet_start
            .verify(&self.validator_set)
            .map_err(|error| anyhow::anyhow!("reverify retained FleetStartCertificate: {error}"))?;
        self.pinned.revalidate_held_v1()?;
        let (fresh, bytes, artifact_sha256) =
            open_and_read_restart_cut_artifact_v1(&self.pinned.root_path)?;
        ensure!(
            fresh.same_identity_v1(&self.pinned),
            "stored RestartCut path or open-file identity was replaced"
        );
        ensure!(
            bytes == self.verified.certificate().encode()
                && artifact_sha256 == self.verified.artifact_sha256(),
            "stored RestartCut fresh readback differs from authenticated carrier"
        );
        let fresh_verified = RestartCutCertificateV1::decode_verified(
            &bytes,
            &self.fleet_start,
            &self.validator_set,
        )
        .map_err(|error| anyhow::anyhow!("fresh-verify stored RestartCut certificate: {error}"))?;
        validate_local_binding_v1(
            &fresh_verified,
            self.local_validator,
            self.local_config_sha256,
            &self.validator_set,
            &self.fleet_start,
        )?;
        ensure!(
            fresh_verified.certificate() == self.verified.certificate()
                && fresh_verified.artifact_sha256() == self.verified.artifact_sha256()
                && fresh_verified.certificate().encode() == bytes,
            "stored RestartCut fresh authentication differs from retained carrier"
        );
        fresh.revalidate_held_v1()?;
        self.pinned.revalidate_held_v1()
    }

    pub(crate) fn path_v1(&self) -> &Path {
        &self.pinned.path
    }

    pub(crate) fn into_verified_v1(self) -> VerifiedRestartCutCertificateV1 {
        self.verified
    }
}

/// Consumes one already verified N/N certificate, publishes it without
/// replacement, fsyncs it, and reconstructs the verified carrier from the
/// bytes freshly read through the final path. An existing byte-identical
/// artifact is the only accepted retry.
pub(crate) fn persist_local_restart_cut_certificate_v1(
    config: &LoadedValidatorConfig,
    verified: VerifiedRestartCutCertificateV1,
) -> Result<StoredRestartCutCertificateV1> {
    let fleet_start = load_fleet_start_certificate_v1(config.run_root(), config.validator_set())?;
    persist_at_root_v1(
        config.run_root(),
        config.local_validator(),
        config.config_sha256(),
        config.validator_set(),
        &fleet_start,
        verified,
    )
}

/// Reopens an already published artifact. This is comparison authority only;
/// the later process-journal predecessor join must consume it before any
/// process-2 event may be appended.
pub(crate) fn load_local_restart_cut_certificate_v1(
    config: &LoadedValidatorConfig,
) -> Result<StoredRestartCutCertificateV1> {
    let fleet_start = load_fleet_start_certificate_v1(config.run_root(), config.validator_set())?;
    load_at_root_v1(
        config.run_root(),
        config.local_validator(),
        config.config_sha256(),
        config.validator_set(),
        &fleet_start,
    )
}

fn persist_at_root_v1(
    root: &Path,
    local_validator: ValidatorId,
    local_config_sha256: [u8; 32],
    validator_set: &ValidatorSet,
    fleet_start: &FleetStartCertificateV1,
    verified: VerifiedRestartCutCertificateV1,
) -> Result<StoredRestartCutCertificateV1> {
    validate_local_binding_v1(
        &verified,
        local_validator,
        local_config_sha256,
        validator_set,
        fleet_start,
    )?;
    let bytes = verified.certificate().encode();
    ensure!(
        !bytes.is_empty() && bytes.len() <= MAX_RESTART_CUT_CERTIFICATE_BYTES_V1,
        "RestartCut certificate crosses its durable bound"
    );
    let expected_sha256: [u8; 32] = Sha256::digest(&bytes).into();
    ensure!(
        expected_sha256 == verified.artifact_sha256(),
        "verified RestartCut content address differs"
    );
    let freshly_verified = RestartCutCertificateV1::decode_verified(
        &bytes,
        fleet_start,
        validator_set,
    )
    .map_err(|error| {
        anyhow::anyhow!("pre-publication RestartCut differs from supplied FleetStart/set: {error}")
    })?;
    validate_local_binding_v1(
        &freshly_verified,
        local_validator,
        local_config_sha256,
        validator_set,
        fleet_start,
    )?;
    ensure!(
        freshly_verified.certificate() == verified.certificate()
            && freshly_verified.artifact_sha256() == verified.artifact_sha256(),
        "pre-publication RestartCut fresh authentication differs from supplied carrier"
    );

    publish_create_new_v1(root, &bytes)?;

    let stored = load_at_root_v1(
        root,
        local_validator,
        local_config_sha256,
        validator_set,
        fleet_start,
    )?;
    ensure!(
        stored.artifact_sha256_v1() == expected_sha256 && stored.body_v1() == verified.body(),
        "stored RestartCut fresh readback differs from verified input"
    );
    Ok(stored)
}

fn load_at_root_v1(
    root: &Path,
    local_validator: ValidatorId,
    local_config_sha256: [u8; 32],
    validator_set: &ValidatorSet,
    fleet_start: &FleetStartCertificateV1,
) -> Result<StoredRestartCutCertificateV1> {
    let (pinned, bytes, observed_sha256) = open_and_read_restart_cut_artifact_v1(root)?;
    let verified = RestartCutCertificateV1::decode_verified(&bytes, fleet_start, validator_set)
        .map_err(|error| anyhow::anyhow!("verify stored RestartCut certificate: {error}"))?;
    ensure!(
        observed_sha256 == verified.artifact_sha256() && verified.certificate().encode() == bytes,
        "stored RestartCut content address or canonical bytes differ"
    );
    validate_local_binding_v1(
        &verified,
        local_validator,
        local_config_sha256,
        validator_set,
        fleet_start,
    )?;
    pinned.revalidate_held_v1()?;
    Ok(StoredRestartCutCertificateV1 {
        verified,
        pinned,
        fleet_start: fleet_start.clone(),
        validator_set: validator_set.clone(),
        local_validator,
        local_config_sha256,
    })
}

pub(crate) fn load_fleet_start_certificate_v1(
    root: &Path,
    validator_set: &ValidatorSet,
) -> Result<FleetStartCertificateV1> {
    let bytes = read_private_file_v1(
        root,
        FLEET_START_CERTIFICATE_FILE_V1,
        MAX_FLEET_START_CERTIFICATE_BYTES_V1,
    )?;
    let certificate = FleetStartCertificateV1::decode(&bytes, validator_set)
        .map_err(|error| anyhow::anyhow!("verify stored FleetStartCertificate: {error}"))?;
    certificate
        .verify(validator_set)
        .map_err(|error| anyhow::anyhow!("verify stored FleetStartCertificate: {error}"))?;
    ensure!(
        certificate.encode() == bytes,
        "stored FleetStartCertificate is non-canonical"
    );
    Ok(certificate)
}

fn validate_local_binding_v1(
    verified: &VerifiedRestartCutCertificateV1,
    local_validator: ValidatorId,
    local_config_sha256: [u8; 32],
    validator_set: &ValidatorSet,
    fleet_start: &FleetStartCertificateV1,
) -> Result<()> {
    let body = verified.body();
    fleet_start
        .verify(validator_set)
        .map_err(|error| anyhow::anyhow!("verify local RestartCut FleetStart: {error}"))?;
    let local_ready = fleet_start
        .ready_set()
        .statement(local_validator)
        .context("RestartCut FleetStart lacks the local Ready statement")?;
    ensure!(
        validator_set.validator(local_validator).is_some()
            && local_config_sha256 != [0; 32]
            && local_ready.local_cut().config_sha256() == local_config_sha256
            && verified.certificate().statement(local_validator).is_some()
            && body.process_instance() == 1
            && (body.target_validator() != local_validator
                || body.target_config_sha256() == local_config_sha256),
        "RestartCut artifact is not the exact local-member process-1 cut"
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

struct PinnedRestartCutArtifactV1 {
    root_path: PathBuf,
    path: PathBuf,
    root_file: File,
    artifact_file: File,
    root_identity: DirectoryIdentityV1,
    artifact_identity: ArtifactIdentityV1,
}

impl std::fmt::Debug for PinnedRestartCutArtifactV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PinnedRestartCutArtifactV1")
            .field("root_path", &self.root_path)
            .field("path", &self.path)
            .field("root_identity", &self.root_identity)
            .field("artifact_identity", &self.artifact_identity)
            .finish_non_exhaustive()
    }
}

impl PinnedRestartCutArtifactV1 {
    fn same_identity_v1(&self, other: &Self) -> bool {
        self.root_path == other.root_path
            && self.path == other.path
            && self.root_identity == other.root_identity
            && self.artifact_identity == other.artifact_identity
    }

    fn revalidate_held_v1(&self) -> Result<()> {
        ensure_no_publication_sidecars_v1(&self.root_path)?;
        ensure!(
            self.path == self.root_path.join(RESTART_CUT_CERTIFICATE_FILE_V1)
                && self.path.file_name() == Some(OsStr::new(RESTART_CUT_CERTIFICATE_FILE_V1)),
            "pinned RestartCut artifact escaped its fixed private path"
        );

        let held_root = self
            .root_file
            .metadata()
            .context("inspect held RestartCut private root")?;
        validate_private_root_metadata_v1(&held_root)?;
        ensure!(
            self.root_identity.matches_metadata_v1(&held_root),
            "held RestartCut private root identity changed"
        );
        let (fresh_root_file, fresh_root_identity) = open_private_root_v1(&self.root_path)?;
        ensure!(
            fresh_root_identity == self.root_identity,
            "RestartCut private root path was replaced"
        );
        drop(fresh_root_file);

        let held_artifact = self
            .artifact_file
            .metadata()
            .context("inspect held RestartCut artifact")?;
        validate_private_artifact_metadata_v1(
            &held_artifact,
            MAX_RESTART_CUT_CERTIFICATE_BYTES_V1,
        )?;
        ensure!(
            self.artifact_identity.matches_metadata_v1(&held_artifact),
            "held RestartCut artifact identity changed"
        );
        let path_metadata =
            fs::symlink_metadata(&self.path).context("reinspect pinned RestartCut path")?;
        ensure!(
            !path_metadata.file_type().is_symlink(),
            "pinned RestartCut path became a symlink"
        );
        validate_private_artifact_metadata_v1(
            &path_metadata,
            MAX_RESTART_CUT_CERTIFICATE_BYTES_V1,
        )?;
        ensure!(
            self.artifact_identity.matches_metadata_v1(&path_metadata),
            "pinned RestartCut path was replaced or mutated"
        );
        Ok(())
    }
}

fn effective_uid_v1() -> u32 {
    rustix::process::geteuid().as_raw()
}

fn validate_encoded_bound_v1(bytes: &[u8]) -> Result<()> {
    ensure!(
        !bytes.is_empty() && bytes.len() <= MAX_RESTART_CUT_CERTIFICATE_BYTES_V1,
        "RestartCut canonical bytes cross the durable bound"
    );
    Ok(())
}

fn sha256_v1(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn writing_file_name_v1(process_id: u32, attempt: u64) -> String {
    format!("{RESTART_CUT_CERTIFICATE_WRITING_PREFIX_V1}{process_id:08x}.{attempt:016x}")
}

fn next_writing_file_name_v1() -> String {
    writing_file_name_v1(
        process::id(),
        RESTART_CUT_WRITING_ATTEMPT_V1.fetch_add(1, Ordering::Relaxed),
    )
}

fn is_lower_hex_digit_v1(byte: u8) -> bool {
    byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
}

fn writing_candidate_v1(name: &OsStr) -> Option<bool> {
    let name = name.as_bytes();
    let prefix = RESTART_CUT_CERTIFICATE_WRITING_PREFIX_V1.as_bytes();
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
        .context("reinspect held RestartCut publication root")?;
    validate_private_root_metadata_v1(&held_root)?;
    ensure!(
        root_identity.matches_metadata_v1(&held_root),
        "RestartCut private root changed during publication"
    );
    let path_root =
        fs::symlink_metadata(private_root).context("reinspect RestartCut publication root path")?;
    ensure!(
        !path_root.file_type().is_symlink() && root_identity.matches_metadata_v1(&path_root),
        "RestartCut private root path was replaced during publication"
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
            "inspect interrupted RestartCut writing candidate {}",
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
        "interrupted RestartCut writing candidate has foreign metadata"
    );
    let expected_identity = ArtifactIdentityV1::from_metadata_v1(&before);

    let observed = if before.len() == 0 {
        Vec::new()
    } else {
        ensure!(
            mode == 0o600,
            "nonempty interrupted RestartCut writing candidate has incomplete permissions"
        );
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(writing)
            .with_context(|| {
                format!(
                    "open interrupted RestartCut writing candidate {}",
                    writing.display()
                )
            })?;
        let opened = file
            .metadata()
            .context("inspect opened interrupted RestartCut writing candidate")?;
        ensure!(
            expected_identity.matches_metadata_v1(&opened),
            "interrupted RestartCut writing candidate changed while opening"
        );
        let mut observed = Vec::with_capacity(
            usize::try_from(before.len()).context("writing candidate length overflows")?,
        );
        Read::by_ref(&mut file)
            .take(u64::try_from(expected_bytes.len()).unwrap_or(u64::MAX) + 1)
            .read_to_end(&mut observed)
            .context("read interrupted RestartCut writing candidate")?;
        let after = file
            .metadata()
            .context("reinspect interrupted RestartCut writing candidate")?;
        ensure!(
            expected_identity.matches_metadata_v1(&after),
            "interrupted RestartCut writing candidate changed while reading"
        );
        observed
    };
    ensure!(
        expected_bytes.starts_with(&observed),
        "interrupted RestartCut writing candidate is not an exact canonical prefix"
    );

    let next_exists = path_exists_no_follow_v1(next, "RestartCut next candidate")?;
    match expected_identity.links {
        1 => ensure!(
            !next_exists,
            "unlinked RestartCut writing candidate coexists with a foreign fixed candidate"
        ),
        2 => {
            ensure!(
                next_exists && observed == expected_bytes,
                "linked RestartCut writing candidate is partial or lacks its exact fixed link"
            );
            let next_identity = validate_publication_candidate_v1(next, expected_bytes, 2)?;
            ensure!(
                next_identity == expected_identity,
                "linked RestartCut writing and fixed candidates are different inodes"
            );
        }
        _ => unreachable!("writing candidate link count was checked above"),
    }

    let path_after = fs::symlink_metadata(writing)
        .context("reinspect interrupted RestartCut writing candidate path")?;
    ensure!(
        expected_identity.matches_metadata_v1(&path_after),
        "interrupted RestartCut writing candidate path was replaced"
    );
    revalidate_publication_root_v1(private_root, root_file, root_identity)?;
    fs::remove_file(writing)
        .context("remove authenticated interrupted RestartCut writing candidate")?;
    root_file
        .sync_all()
        .context("fsync cleaned RestartCut writing candidate")?;
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
        .context("scan RestartCut private root for interrupted writing candidates")?
    {
        let entry = entry.context("read RestartCut private-root writing candidate")?;
        let name = entry.file_name();
        ensure!(
            !RESTART_CUT_CERTIFICATE_SIDECARS_V1[1..]
                .iter()
                .any(|reserved| name == OsStr::new(reserved)),
            "forbidden RestartCut publication sidecar is preserved: {}",
            entry.path().display()
        );
        let Some(canonical) = writing_candidate_v1(&name) else {
            continue;
        };
        let path = private_root.join(&name);
        ensure!(
            canonical,
            "malformed RestartCut writing candidate is preserved: {}",
            path.display()
        );
        ensure!(
            writing.replace(path).is_none(),
            "multiple RestartCut writing candidates are ambiguous and preserved"
        );
    }
    let Some(writing) = writing else {
        return Ok(());
    };
    let target = private_root.join(RESTART_CUT_CERTIFICATE_FILE_V1);
    ensure!(
        !path_exists_no_follow_v1(&target, "RestartCut target")?,
        "RestartCut target coexists with an impossible writing candidate"
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
        "RestartCut writing candidate escaped its unique private path"
    );
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(&writing)
        .context("create-new unique RestartCut writing candidate")?;
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .context("chmod unique RestartCut writing candidate")?;
    file.write_all(bytes)
        .context("write unique RestartCut writing candidate")?;
    file.sync_all()
        .context("fsync unique RestartCut writing candidate")?;
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
            return Err(error).context("link complete RestartCut writing candidate no-replace")
        }
    }
    let writing_linked = validate_publication_candidate_v1(writing, bytes, 2)?;
    let next_metadata =
        fs::symlink_metadata(next).context("inspect linked fixed RestartCut candidate")?;
    ensure!(
        !next_metadata.file_type().is_symlink()
            && writing_linked.matches_metadata_v1(&next_metadata),
        "RestartCut writing candidate did not link to the exact fixed candidate inode"
    );
    root_file
        .sync_all()
        .context("fsync linked RestartCut writing candidate")?;
    revalidate_publication_root_v1(private_root, root_file, root_identity)?;
    fs::remove_file(writing).context("remove linked unique RestartCut writing candidate")?;
    root_file
        .sync_all()
        .context("fsync fixed RestartCut candidate publication")?;
    revalidate_publication_root_v1(private_root, root_file, root_identity)?;
    validate_publication_candidate_v1(next, bytes, 1)?;
    Ok(())
}

fn publish_create_new_v1(private_root: &Path, bytes: &[u8]) -> Result<()> {
    validate_encoded_bound_v1(bytes)?;
    let (root_file, root_identity) = open_private_root_v1(private_root)?;
    root_file
        .try_lock()
        .context("lock RestartCut private root publication lifetime")?;
    let target = private_root.join(RESTART_CUT_CERTIFICATE_FILE_V1);
    let next = private_root.join(RESTART_CUT_CERTIFICATE_NEXT_FILE_V1);
    ensure!(
        target.parent() == Some(private_root)
            && target.file_name() == Some(OsStr::new(RESTART_CUT_CERTIFICATE_FILE_V1))
            && next.parent() == Some(private_root)
            && next.file_name() == Some(OsStr::new(RESTART_CUT_CERTIFICATE_NEXT_FILE_V1)),
        "RestartCut artifact target escaped its fixed private path"
    );

    cleanup_interrupted_writing_candidates_v1(
        private_root,
        &root_file,
        root_identity,
        bytes,
        &next,
    )?;
    ensure_no_publication_sidecars_except_v1(
        private_root,
        Some(RESTART_CUT_CERTIFICATE_NEXT_FILE_V1),
    )?;

    let target_exists = path_exists_no_follow_v1(&target, "RestartCut target")?;
    let next_exists = path_exists_no_follow_v1(&next, "RestartCut next candidate")?;
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
            fs::symlink_metadata(&target).context("inspect RestartCut response-loss target")?;
        ensure!(
            !target_metadata.file_type().is_symlink()
                && next_identity.matches_metadata_v1(&target_metadata),
            "RestartCut target and publication candidate are not one exact response-loss inode"
        );
    } else {
        match fs::hard_link(&next, &target) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error).context("publish RestartCut without replacement"),
        }
        let next_after_link = validate_publication_candidate_v1(&next, bytes, 2)?;
        let target_metadata =
            fs::symlink_metadata(&target).context("inspect published RestartCut target")?;
        ensure!(
            !target_metadata.file_type().is_symlink()
                && next_after_link.matches_metadata_v1(&target_metadata),
            "RestartCut no-replace publication did not create one exact linked target"
        );
    }

    root_file
        .sync_all()
        .context("fsync RestartCut linked publication")?;
    fs::remove_file(&next).context("remove committed RestartCut publication candidate")?;
    root_file
        .sync_all()
        .context("fsync RestartCut final publication")?;
    revalidate_publication_root_v1(private_root, &root_file, root_identity)?;
    drop(root_file);
    ensure_no_publication_sidecars_v1(private_root)?;
    let (_, observed, _) = open_and_read_restart_cut_artifact_v1(private_root)?;
    ensure!(
        observed == bytes,
        "published RestartCut differs from exact canonical input"
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
    let before = fs::symlink_metadata(path).context("inspect RestartCut publication candidate")?;
    ensure!(
        !before.file_type().is_symlink()
            && before.is_file()
            && before.permissions().mode() & 0o7777 == 0o600
            && before.uid() == effective_uid_v1()
            && before.nlink() == expected_links
            && before.len() == u64::try_from(expected_bytes.len()).unwrap_or(u64::MAX)
            && before.len()
                <= u64::try_from(MAX_RESTART_CUT_CERTIFICATE_BYTES_V1).unwrap_or(u64::MAX),
        "RestartCut publication candidate has invalid private metadata"
    );
    let expected_identity = ArtifactIdentityV1::from_metadata_v1(&before);
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .context("open RestartCut publication candidate")?;
    let opened = file
        .metadata()
        .context("inspect opened RestartCut publication candidate")?;
    ensure!(
        expected_identity.matches_metadata_v1(&opened),
        "RestartCut publication candidate changed while opening"
    );
    let mut observed = Vec::with_capacity(expected_bytes.len());
    Read::by_ref(&mut file)
        .take(u64::try_from(MAX_RESTART_CUT_CERTIFICATE_BYTES_V1).unwrap_or(u64::MAX) + 1)
        .read_to_end(&mut observed)
        .context("read RestartCut publication candidate")?;
    let after = file
        .metadata()
        .context("reinspect RestartCut publication candidate")?;
    let path_after =
        fs::symlink_metadata(path).context("reinspect RestartCut publication candidate path")?;
    ensure!(
        observed == expected_bytes
            && expected_identity.matches_metadata_v1(&after)
            && expected_identity.matches_metadata_v1(&path_after),
        "RestartCut publication candidate is partial, mutated, or foreign"
    );
    Ok(expected_identity)
}

fn open_and_read_restart_cut_artifact_v1(
    private_root: &Path,
) -> Result<(PinnedRestartCutArtifactV1, Vec<u8>, [u8; 32])> {
    let (root_file, root_identity) = open_private_root_v1(private_root)?;
    ensure_no_publication_sidecars_v1(private_root)?;
    let path = private_root.join(RESTART_CUT_CERTIFICATE_FILE_V1);
    ensure!(
        path.parent() == Some(private_root)
            && path.file_name() == Some(OsStr::new(RESTART_CUT_CERTIFICATE_FILE_V1)),
        "RestartCut artifact path escaped its fixed private root"
    );

    let before = fs::symlink_metadata(&path).context("inspect RestartCut artifact path")?;
    ensure!(
        !before.file_type().is_symlink(),
        "RestartCut artifact path is a symlink"
    );
    validate_private_artifact_metadata_v1(&before, MAX_RESTART_CUT_CERTIFICATE_BYTES_V1)?;
    let expected_identity = ArtifactIdentityV1::from_metadata_v1(&before);

    let mut artifact_file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(&path)
        .context("open RestartCut artifact")?;
    let opened = artifact_file
        .metadata()
        .context("inspect opened RestartCut artifact")?;
    validate_private_artifact_metadata_v1(&opened, MAX_RESTART_CUT_CERTIFICATE_BYTES_V1)?;
    ensure!(
        expected_identity.matches_metadata_v1(&opened),
        "RestartCut artifact identity changed while opening"
    );

    artifact_file
        .seek(SeekFrom::Start(0))
        .context("seek RestartCut artifact")?;
    let mut bytes = Vec::with_capacity(
        usize::try_from(opened.len()).context("RestartCut artifact byte length overflows")?,
    );
    Read::by_ref(&mut artifact_file)
        .take(u64::try_from(MAX_RESTART_CUT_CERTIFICATE_BYTES_V1).unwrap_or(u64::MAX) + 1)
        .read_to_end(&mut bytes)
        .context("read RestartCut artifact")?;
    ensure!(
        bytes.len() == usize::try_from(opened.len()).unwrap_or(usize::MAX)
            && bytes.len() <= MAX_RESTART_CUT_CERTIFICATE_BYTES_V1,
        "RestartCut artifact byte length changed while reading"
    );
    let observed_sha256 = sha256_v1(&bytes);

    let after_handle = artifact_file
        .metadata()
        .context("reinspect opened RestartCut artifact")?;
    let after_path = fs::symlink_metadata(&path).context("reinspect RestartCut artifact path")?;
    ensure!(
        !after_path.file_type().is_symlink()
            && expected_identity.matches_metadata_v1(&after_handle)
            && expected_identity.matches_metadata_v1(&after_path),
        "RestartCut artifact identity changed during stat/read/hash"
    );
    let root_after = root_file
        .metadata()
        .context("reinspect RestartCut private root after artifact read")?;
    ensure!(
        root_identity.matches_metadata_v1(&root_after),
        "RestartCut private root changed during artifact read"
    );
    ensure_no_publication_sidecars_v1(private_root)?;

    Ok((
        PinnedRestartCutArtifactV1 {
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
        "RestartCut private root is not absolute"
    );
    let before = fs::symlink_metadata(root).context("inspect RestartCut private root")?;
    ensure!(
        !before.file_type().is_symlink(),
        "RestartCut private root is a symlink"
    );
    validate_private_root_metadata_v1(&before)?;
    let canonical = fs::canonicalize(root).context("canonicalize RestartCut private root")?;
    ensure!(
        canonical == root,
        "RestartCut private root has a symlink or non-canonical ancestor"
    );
    let expected = DirectoryIdentityV1::from_metadata_v1(&before);
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(root)
        .context("open RestartCut private root")?;
    let opened = file
        .metadata()
        .context("inspect opened RestartCut private root")?;
    validate_private_root_metadata_v1(&opened)?;
    let after = fs::symlink_metadata(root).context("reinspect RestartCut private root")?;
    ensure!(
        !after.file_type().is_symlink()
            && expected.matches_metadata_v1(&opened)
            && expected.matches_metadata_v1(&after),
        "RestartCut private root identity changed while opening"
    );
    Ok((file, expected))
}

fn validate_private_root_metadata_v1(metadata: &fs::Metadata) -> Result<()> {
    ensure!(
        metadata.is_dir()
            && metadata.uid() == effective_uid_v1()
            && metadata.permissions().mode() & 0o7777 == 0o700,
        "RestartCut private root is not one effective-user-owned 0700 directory"
    );
    Ok(())
}

fn validate_private_artifact_metadata_v1(
    metadata: &fs::Metadata,
    maximum_bytes: usize,
) -> Result<()> {
    ensure!(
        metadata.is_file()
            && metadata.permissions().mode() & 0o7777 == 0o600
            && metadata.nlink() == 1
            && metadata.uid() == effective_uid_v1()
            && metadata.len() > 0
            && metadata.len() <= u64::try_from(maximum_bytes).unwrap_or(u64::MAX),
        "private artifact is not one exact effective-user-owned private regular file"
    );
    Ok(())
}

fn ensure_no_publication_sidecars_v1(root: &Path) -> Result<()> {
    ensure_no_publication_sidecars_except_v1(root, None)
}

fn ensure_no_publication_sidecars_except_v1(root: &Path, allowed: Option<&str>) -> Result<()> {
    for name in RESTART_CUT_CERTIFICATE_SIDECARS_V1 {
        if allowed == Some(name) {
            continue;
        }
        let path = root.join(name);
        match fs::symlink_metadata(&path) {
            Ok(_) => bail!(
                "RestartCut publication sidecar unexpectedly exists: {}",
                path.display()
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("inspect RestartCut sidecar {}", path.display()))
            }
        }
    }
    for entry in fs::read_dir(root).context("scan RestartCut private root for writing sidecars")? {
        let entry = entry.context("read RestartCut private-root sidecar entry")?;
        if writing_candidate_v1(&entry.file_name()).is_some() {
            bail!(
                "RestartCut publication writing sidecar unexpectedly exists: {}",
                entry.path().display()
            );
        }
    }
    Ok(())
}

fn read_private_file_v1(root: &Path, name: &str, maximum_bytes: usize) -> Result<Vec<u8>> {
    let (root_file, root_identity) = open_private_root_v1(root)?;
    let path = root.join(name);
    ensure!(
        path.parent() == Some(root) && path.file_name() == Some(OsStr::new(name)),
        "private artifact escaped its exact root"
    );
    let before = fs::symlink_metadata(&path)
        .with_context(|| format!("inspect private artifact {}", path.display()))?;
    ensure!(
        !before.file_type().is_symlink(),
        "private artifact is a symlink: {}",
        path.display()
    );
    validate_private_artifact_metadata_v1(&before, maximum_bytes)?;
    let expected_identity = ArtifactIdentityV1::from_metadata_v1(&before);
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(&path)
        .with_context(|| format!("open private artifact {}", path.display()))?;
    let opened = file
        .metadata()
        .with_context(|| format!("inspect opened artifact {}", path.display()))?;
    validate_private_artifact_metadata_v1(&opened, maximum_bytes)?;
    ensure!(
        expected_identity.matches_metadata_v1(&opened),
        "private artifact changed during open: {}",
        path.display()
    );
    let mut bytes = Vec::with_capacity(
        usize::try_from(opened.len()).context("private artifact length overflows")?,
    );
    Read::by_ref(&mut file)
        .take(u64::try_from(maximum_bytes).unwrap_or(u64::MAX) + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("read private artifact {}", path.display()))?;
    let after = file
        .metadata()
        .with_context(|| format!("reinspect private artifact {}", path.display()))?;
    let path_after = fs::symlink_metadata(&path)
        .with_context(|| format!("reinspect private artifact path {}", path.display()))?;
    let root_after = root_file
        .metadata()
        .context("reinspect private root after artifact read")?;
    ensure!(
        bytes.len() == usize::try_from(opened.len()).unwrap_or(usize::MAX)
            && bytes.len() <= maximum_bytes
            && expected_identity.matches_metadata_v1(&after)
            && expected_identity.matches_metadata_v1(&path_after)
            && root_identity.matches_metadata_v1(&root_after),
        "private artifact changed during read: {}",
        path.display()
    );
    Ok(bytes)
}

#[cfg(test)]
pub(crate) fn persist_restart_cut_at_test_root_v1(
    root: &Path,
    local_validator: ValidatorId,
    local_config_sha256: [u8; 32],
    validator_set: &ValidatorSet,
    fleet_start: &FleetStartCertificateV1,
    verified: VerifiedRestartCutCertificateV1,
) -> Result<StoredRestartCutCertificateV1> {
    persist_at_root_v1(
        root,
        local_validator,
        local_config_sha256,
        validator_set,
        fleet_start,
        verified,
    )
}

#[cfg(test)]
pub(crate) fn load_restart_cut_at_test_root_v1(
    root: &Path,
    local_validator: ValidatorId,
    local_config_sha256: [u8; 32],
    validator_set: &ValidatorSet,
    fleet_start: &FleetStartCertificateV1,
) -> Result<StoredRestartCutCertificateV1> {
    load_at_root_v1(
        root,
        local_validator,
        local_config_sha256,
        validator_set,
        fleet_start,
    )
}
