//! Durable intent fence for the cross-store finalization boundary.
//!
//! The native application commit and the Core/Safety/checkpoint acknowledgements
//! are deliberately separate durable stores.  A process death between those
//! stores must not leave an operator guessing whether a finalization should be
//! retried.  This small, feature-gated WAL records the complete finalization
//! tuple before the application commit.  It is not a commit protocol by itself:
//! recovery still has to revalidate the Core queue and all stores.  Its purpose
//! is to make an interrupted operation fail closed (or be retried exactly) rather
//! than silently becoming a different operation.

#![cfg(feature = "lab-validator-runtime")]

use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

use sha2::{Digest, Sha256};
use trnm_consensus_core::DurableFinalizationV0;

const MAGIC_V0: &[u8; 8] = b"TRNMFIN0";
const DOMAIN_V0: &[u8] = b"trnm.poco-node.finalization-intent.v0\0";
const MARKER_SUFFIX_V0: &str = ".finalization.pending.v0";
const TEMP_SUFFIX_V0: &str = ".finalization.pending.v0.tmp";
const FIXED_BYTES_V0: usize = 8 + (6 * 8) + (11 * 32) + 32;

/// Stable identity of one filesystem object admitted by the marker owner.
///
/// Marker paths are derived from a SQLite path, but a path is not an
/// authority: a same-UID process can replace a parent directory or the store
/// file between two operations.  Keeping the device/inode pair lets every
/// path-based operation reject that replacement before accepting a marker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PathIdentityV0 {
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
}

#[cfg(unix)]
impl PathIdentityV0 {
    fn from_metadata(metadata: &fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        }
    }
}

#[cfg(not(unix))]
impl PathIdentityV0 {
    fn from_metadata(_metadata: &fs::Metadata) -> Self {
        Self {}
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FinalizationIntentMarkerV0 {
    pub(crate) scope: [u8; 32],
    pub(crate) owner_id: [u8; 32],
    pub(crate) proof_id: [u8; 32],
    pub(crate) target_block_id: [u8; 32],
    pub(crate) parent_block_id: [u8; 32],
    pub(crate) target_state_root: [u8; 32],
    pub(crate) target_receipts_root: [u8; 32],
    pub(crate) parent_state_root: [u8; 32],
    pub(crate) parent_commit_id: [u8; 32],
    pub(crate) target_overlay_checksum: [u8; 32],
    pub(crate) source_artifact_checksum: [u8; 32],
    pub(crate) target_height: u64,
    pub(crate) target_view: u64,
    pub(crate) target_timestamp_ms: u64,
    pub(crate) parent_height: u64,
    pub(crate) parent_view: u64,
    pub(crate) parent_timestamp_ms: u64,
}

impl FinalizationIntentMarkerV0 {
    pub(crate) fn from_finalization(
        finalization: &DurableFinalizationV0,
        scope: [u8; 32],
        owner_id: [u8; 32],
        source_artifact_checksum: [u8; 32],
        parent_state_root: [u8; 32],
        parent_commit_id: [u8; 32],
    ) -> Result<Self, &'static str> {
        if scope == [0; 32]
            || owner_id == [0; 32]
            || source_artifact_checksum == [0; 32]
            || parent_state_root == [0; 32]
            || parent_commit_id == [0; 32]
        {
            return Err("finalization intent namespace/checksum is zero");
        }
        let header = finalization.proof().finalized_block().header();
        let overlay = finalization.target_overlay_ref();
        let parent = finalization.authenticated_parent();
        if header.id().as_bytes() != overlay.block_id().as_bytes()
            || header.parent_id().as_bytes() != overlay.parent_block_id().as_bytes()
            || header.height().get() == 0
            || header.id().is_zero()
            || header.parent_id().is_zero()
            || overlay.overlay_checksum() == [0; 32]
        {
            return Err("finalization intent geometry is not canonical");
        }
        Ok(Self {
            scope,
            owner_id,
            proof_id: finalization.proof_id().into_bytes(),
            target_block_id: *header.id().as_bytes(),
            parent_block_id: *header.parent_id().as_bytes(),
            target_state_root: *header.state_root().as_bytes(),
            target_receipts_root: *header.receipts_root().as_bytes(),
            parent_state_root,
            parent_commit_id,
            target_overlay_checksum: overlay.overlay_checksum(),
            source_artifact_checksum,
            target_height: header.height().get(),
            target_view: header.view().get(),
            target_timestamp_ms: header.timestamp_ms(),
            parent_height: parent.height().get(),
            parent_view: parent.view().get(),
            parent_timestamp_ms: parent.timestamp_ms(),
        })
    }

    pub(crate) fn matches_finalization(
        &self,
        finalization: &DurableFinalizationV0,
        scope: [u8; 32],
        owner_id: [u8; 32],
        source_artifact_checksum: [u8; 32],
        parent_state_root: [u8; 32],
        parent_commit_id: [u8; 32],
    ) -> bool {
        Self::from_finalization(
            finalization,
            scope,
            owner_id,
            source_artifact_checksum,
            parent_state_root,
            parent_commit_id,
        )
        .is_ok_and(|expected| *self == expected)
    }

    pub(crate) fn encode(self) -> [u8; FIXED_BYTES_V0] {
        let mut bytes = [0_u8; FIXED_BYTES_V0];
        let mut offset = 0;
        bytes[offset..offset + 8].copy_from_slice(MAGIC_V0);
        offset += 8;
        for value in [
            self.target_height,
            self.target_view,
            self.target_timestamp_ms,
            self.parent_height,
            self.parent_view,
            self.parent_timestamp_ms,
        ] {
            bytes[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
            offset += 8;
        }
        for value in [
            self.scope,
            self.owner_id,
            self.proof_id,
            self.target_block_id,
            self.parent_block_id,
            self.target_state_root,
            self.target_receipts_root,
            self.parent_state_root,
            self.parent_commit_id,
            self.target_overlay_checksum,
            self.source_artifact_checksum,
        ] {
            bytes[offset..offset + 32].copy_from_slice(&value);
            offset += 32;
        }
        let checksum = checksum_v0(&bytes[..offset]);
        bytes[offset..].copy_from_slice(&checksum);
        bytes
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() != FIXED_BYTES_V0 || &bytes[..8] != MAGIC_V0 {
            return Err("finalization intent marker length or magic mismatch");
        }
        let checksum_offset = FIXED_BYTES_V0 - 32;
        if bytes[checksum_offset..] != checksum_v0(&bytes[..checksum_offset]) {
            return Err("finalization intent marker checksum mismatch");
        }
        let mut offset = 8;
        let read_u64 = |bytes: &[u8], offset: &mut usize| {
            let mut raw = [0_u8; 8];
            raw.copy_from_slice(&bytes[*offset..*offset + 8]);
            *offset += 8;
            u64::from_be_bytes(raw)
        };
        let target_height = read_u64(bytes, &mut offset);
        let target_view = read_u64(bytes, &mut offset);
        let target_timestamp_ms = read_u64(bytes, &mut offset);
        let parent_height = read_u64(bytes, &mut offset);
        let parent_view = read_u64(bytes, &mut offset);
        let parent_timestamp_ms = read_u64(bytes, &mut offset);
        let read_fixed = |bytes: &[u8], offset: &mut usize| {
            let mut raw = [0_u8; 32];
            raw.copy_from_slice(&bytes[*offset..*offset + 32]);
            *offset += 32;
            raw
        };
        let marker = Self {
            scope: read_fixed(bytes, &mut offset),
            owner_id: read_fixed(bytes, &mut offset),
            proof_id: read_fixed(bytes, &mut offset),
            target_block_id: read_fixed(bytes, &mut offset),
            parent_block_id: read_fixed(bytes, &mut offset),
            target_state_root: read_fixed(bytes, &mut offset),
            target_receipts_root: read_fixed(bytes, &mut offset),
            parent_state_root: read_fixed(bytes, &mut offset),
            parent_commit_id: read_fixed(bytes, &mut offset),
            target_overlay_checksum: read_fixed(bytes, &mut offset),
            source_artifact_checksum: read_fixed(bytes, &mut offset),
            target_height,
            target_view,
            target_timestamp_ms,
            parent_height,
            parent_view,
            parent_timestamp_ms,
        };
        if offset != checksum_offset
            || marker.scope == [0; 32]
            || marker.owner_id == [0; 32]
            || marker.proof_id == [0; 32]
            || marker.target_block_id == [0; 32]
            || marker.parent_block_id == [0; 32]
            || marker.target_state_root == [0; 32]
            || marker.target_receipts_root == [0; 32]
            || marker.parent_state_root == [0; 32]
            || marker.parent_commit_id == [0; 32]
            || marker.target_overlay_checksum == [0; 32]
            || marker.source_artifact_checksum == [0; 32]
            || marker.target_height == 0
        {
            return Err("finalization intent marker contains zero identity");
        }
        Ok(marker)
    }
}

fn checksum_v0(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN_V0);
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
    hasher.finalize().into()
}

pub(crate) fn marker_path_v0(store_path: &Path) -> PathBuf {
    let mut value = store_path.as_os_str().to_os_string();
    value.push(MARKER_SUFFIX_V0);
    PathBuf::from(value)
}

fn marker_temp_path_v0(store_path: &Path) -> PathBuf {
    let mut value = store_path.as_os_str().to_os_string();
    value.push(TEMP_SUFFIX_V0);
    PathBuf::from(value)
}

fn validate_parent_path_v0(path: &Path) -> Result<&Path, &'static str> {
    let parent = path.parent().ok_or("finalization intent has no parent")?;
    if !path.is_absolute() || path.file_name().is_none() {
        return Err("finalization intent path is not absolute");
    }
    let metadata =
        fs::symlink_metadata(parent).map_err(|_| "finalization intent parent lookup failed")?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err("finalization intent parent is not a directory");
    }
    // Reject an indirect symlink or an unresolved `..` in the parent.  The
    // descriptor/identity checks below then refer to exactly this directory,
    // rather than an arbitrary directory reached through the textual path.
    if fs::canonicalize(parent).map_err(|_| "finalization intent parent canonicalize failed")?
        != parent
    {
        return Err("finalization intent parent is not canonical");
    }
    Ok(parent)
}

fn open_parent_v0(path: &Path) -> Result<(File, PathIdentityV0), &'static str> {
    let parent = validate_parent_path_v0(path)?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW);
    let directory = options
        .open(parent)
        .map_err(|_| "finalization intent parent open failed")?;
    let metadata = directory
        .metadata()
        .map_err(|_| "finalization intent parent metadata failed")?;
    if !metadata.is_dir() {
        return Err("finalization intent parent is not a directory");
    }
    Ok((directory, PathIdentityV0::from_metadata(&metadata)))
}

fn ensure_parent_identity_v0(path: &Path, expected: PathIdentityV0) -> Result<(), &'static str> {
    let (_directory, observed) = open_parent_v0(path)?;
    if observed != expected {
        return Err("finalization intent parent directory was replaced");
    }
    Ok(())
}

fn sync_parent_v0(path: &Path, expected: PathIdentityV0) -> Result<(), &'static str> {
    let (directory, observed) = open_parent_v0(path)?;
    if observed != expected {
        return Err("finalization intent parent directory was replaced");
    }
    directory
        .sync_all()
        .map_err(|_| "finalization intent parent fsync failed")?;
    ensure_parent_identity_v0(path, expected)
}

fn open_read_v0(path: &Path) -> Result<File, &'static str> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK);
    options
        .open(path)
        .map_err(|_| "finalization intent marker open failed")
}

fn validate_store_v0(store_path: &Path) -> Result<(PathIdentityV0, PathIdentityV0), &'static str> {
    let (_parent_file, parent_identity) = open_parent_v0(store_path)?;
    let metadata =
        fs::symlink_metadata(store_path).map_err(|_| "finalization intent store lookup failed")?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err("finalization intent store is not a regular file");
    }
    #[cfg(unix)]
    if metadata.nlink() != 1 {
        return Err("finalization intent store has unexpected hard links");
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    let store = options
        .open(store_path)
        .map_err(|_| "finalization intent store open failed")?;
    let observed = store
        .metadata()
        .map_err(|_| "finalization intent store metadata failed")?;
    if !observed.is_file() {
        return Err("finalization intent store is not a regular file");
    }
    #[cfg(unix)]
    if observed.nlink() != 1 {
        return Err("finalization intent store has unexpected hard links");
    }
    let store_identity = PathIdentityV0::from_metadata(&observed);
    if PathIdentityV0::from_metadata(&metadata) != store_identity {
        return Err("finalization intent store was replaced during open");
    }
    ensure_store_identity_v0(store_path, store_identity, parent_identity)?;
    Ok((store_identity, parent_identity))
}

fn ensure_store_identity_v0(
    store_path: &Path,
    expected_store: PathIdentityV0,
    expected_parent: PathIdentityV0,
) -> Result<(), &'static str> {
    ensure_parent_identity_v0(store_path, expected_parent)?;
    let metadata =
        fs::symlink_metadata(store_path).map_err(|_| "finalization intent store lookup failed")?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err("finalization intent store is not a regular file");
    }
    #[cfg(unix)]
    if metadata.nlink() != 1 {
        return Err("finalization intent store has unexpected hard links");
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    let store = options
        .open(store_path)
        .map_err(|_| "finalization intent store open failed")?;
    let observed = store
        .metadata()
        .map_err(|_| "finalization intent store metadata failed")?;
    if !observed.is_file() {
        return Err("finalization intent store is not a regular file");
    }
    #[cfg(unix)]
    if observed.nlink() != 1 {
        return Err("finalization intent store has unexpected hard links");
    }
    if PathIdentityV0::from_metadata(&metadata) != expected_store
        || PathIdentityV0::from_metadata(&observed) != expected_store
    {
        return Err("finalization intent store was replaced");
    }
    ensure_parent_identity_v0(store_path, expected_parent)
}

fn validate_path_identity_v0(
    path: &Path,
    expected: PathIdentityV0,
    label: &'static str,
) -> Result<(), &'static str> {
    let metadata = fs::symlink_metadata(path).map_err(|_| label)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(label);
    }
    if PathIdentityV0::from_metadata(&metadata) != expected {
        return Err(label);
    }
    Ok(())
}

fn validate_file_v0(file: &File, path: &Path) -> Result<(), &'static str> {
    let metadata = file
        .metadata()
        .map_err(|_| "finalization intent marker metadata failed")?;
    if !metadata.is_file() || metadata.len() != FIXED_BYTES_V0 as u64 || !path.is_absolute() {
        return Err("finalization intent marker file shape invalid");
    }
    #[cfg(unix)]
    if metadata.mode() & 0o077 != 0 || metadata.nlink() != 1 {
        return Err("finalization intent marker permissions/links invalid");
    }
    Ok(())
}

pub(crate) fn load_marker_v0(
    store_path: &Path,
) -> Result<Option<FinalizationIntentMarkerV0>, &'static str> {
    let (store_identity, parent_identity) = validate_store_v0(store_path)?;
    let path = marker_path_v0(store_path);
    let temp = marker_temp_path_v0(store_path);
    ensure_store_identity_v0(store_path, store_identity, parent_identity)?;
    ensure_parent_identity_v0(&path, parent_identity)?;
    match fs::symlink_metadata(&temp) {
        Ok(_) => return Err("finalization intent temporary marker exists"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err("finalization intent temporary marker lookup failed"),
    }
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err("finalization intent marker lookup failed"),
    };
    if !metadata.file_type().is_file() {
        return Err("finalization intent marker is not a regular file");
    }
    let mut file = open_read_v0(&path)?;
    validate_file_v0(&file, &path)?;
    let marker_identity = PathIdentityV0::from_metadata(
        &file
            .metadata()
            .map_err(|_| "finalization intent marker metadata failed")?,
    );
    validate_path_identity_v0(
        &path,
        marker_identity,
        "finalization intent marker was replaced during open",
    )?;
    let mut bytes = Vec::with_capacity(FIXED_BYTES_V0);
    file.read_to_end(&mut bytes)
        .map_err(|_| "finalization intent marker read failed")?;
    ensure_store_identity_v0(store_path, store_identity, parent_identity)?;
    ensure_parent_identity_v0(&path, parent_identity)?;
    Ok(Some(FinalizationIntentMarkerV0::decode(&bytes)?))
}

pub(crate) fn write_marker_v0(
    store_path: &Path,
    marker: FinalizationIntentMarkerV0,
) -> Result<(), &'static str> {
    let (store_identity, parent_identity) = validate_store_v0(store_path)?;
    ensure_store_identity_v0(store_path, store_identity, parent_identity)?;
    if let Some(existing) = load_marker_v0(store_path)? {
        ensure_store_identity_v0(store_path, store_identity, parent_identity)?;
        return if existing == marker {
            Ok(())
        } else {
            Err("finalization intent marker conflicts with an existing operation")
        };
    }
    let path = marker_path_v0(store_path);
    let temp = marker_temp_path_v0(store_path);
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(true);
    #[cfg(unix)]
    options
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    let mut file = options
        .open(&temp)
        .map_err(|_| "finalization intent temporary marker create failed")?;
    let temp_identity = PathIdentityV0::from_metadata(
        &file
            .metadata()
            .map_err(|_| "finalization intent temporary marker metadata failed")?,
    );
    file.write_all(&marker.encode())
        .and_then(|()| file.sync_all())
        .map_err(|_| "finalization intent temporary marker fsync failed")?;
    drop(file);
    ensure_store_identity_v0(store_path, store_identity, parent_identity)?;
    ensure_parent_identity_v0(&path, parent_identity)?;
    validate_path_identity_v0(
        &temp,
        temp_identity,
        "finalization intent temporary marker was replaced before publish",
    )?;
    fs::hard_link(&temp, &path)
        .map_err(|_| "finalization intent marker publish raced or failed")?;
    ensure_parent_identity_v0(&path, parent_identity)?;
    validate_path_identity_v0(
        &path,
        temp_identity,
        "finalization intent marker publish identity mismatch",
    )?;
    sync_parent_v0(&path, parent_identity)?;
    ensure_store_identity_v0(store_path, store_identity, parent_identity)?;
    validate_path_identity_v0(
        &temp,
        temp_identity,
        "finalization intent temporary marker was replaced before cleanup",
    )?;
    fs::remove_file(&temp).map_err(|_| "finalization intent temporary marker cleanup failed")?;
    ensure_store_identity_v0(store_path, store_identity, parent_identity)?;
    ensure_parent_identity_v0(&path, parent_identity)?;
    sync_parent_v0(&path, parent_identity)
}

pub(crate) fn clear_marker_v0(
    store_path: &Path,
    expected: FinalizationIntentMarkerV0,
) -> Result<(), &'static str> {
    let (store_identity, parent_identity) = validate_store_v0(store_path)?;
    ensure_store_identity_v0(store_path, store_identity, parent_identity)?;
    let path = marker_path_v0(store_path);
    if load_marker_v0(store_path)? != Some(expected) {
        return Err("finalization intent marker is absent or differs on clear");
    }
    ensure_store_identity_v0(store_path, store_identity, parent_identity)?;
    let marker_file = open_read_v0(&path)?;
    validate_file_v0(&marker_file, &path)?;
    let marker_identity = PathIdentityV0::from_metadata(
        &marker_file
            .metadata()
            .map_err(|_| "finalization intent marker metadata failed")?,
    );
    validate_path_identity_v0(
        &path,
        marker_identity,
        "finalization intent marker was replaced before clear",
    )?;
    ensure_parent_identity_v0(&path, parent_identity)?;
    fs::remove_file(&path).map_err(|_| "finalization intent marker remove failed")?;
    ensure_store_identity_v0(store_path, store_identity, parent_identity)?;
    ensure_parent_identity_v0(&path, parent_identity)?;
    if fs::symlink_metadata(&path).is_ok() {
        return Err("finalization intent marker reappeared during clear");
    }
    sync_parent_v0(&path, parent_identity)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    // The marker codec tests do not need a real cryptographic proof.  The
    // constructor test below uses a hand-built shape through a helper in the
    // core test surface; all on-disk tests use a synthetic marker so malformed
    // bytes and namespace fencing remain independently testable.
    fn marker(seed: u8) -> FinalizationIntentMarkerV0 {
        FinalizationIntentMarkerV0 {
            scope: [seed; 32],
            owner_id: [seed.wrapping_add(1); 32],
            proof_id: [seed.wrapping_add(2); 32],
            target_block_id: [seed.wrapping_add(3); 32],
            parent_block_id: [seed.wrapping_add(4); 32],
            target_state_root: [seed.wrapping_add(5); 32],
            target_receipts_root: [seed.wrapping_add(6); 32],
            parent_state_root: [seed.wrapping_add(7); 32],
            parent_commit_id: [seed.wrapping_add(8); 32],
            target_overlay_checksum: [seed.wrapping_add(9); 32],
            source_artifact_checksum: [seed.wrapping_add(10); 32],
            target_height: 7,
            target_view: 8,
            target_timestamp_ms: 9,
            parent_height: 6,
            parent_view: 7,
            parent_timestamp_ms: 8,
        }
    }

    #[test]
    fn marker_roundtrip_and_exact_clear_v0() {
        let directory = tempdir().expect("tempdir");
        let store = directory.path().join("proposal.sqlite");
        File::create(&store).expect("create store identity");
        let expected = marker(1);
        write_marker_v0(&store, expected).expect("publish marker");
        assert_eq!(load_marker_v0(&store).expect("load marker"), Some(expected));
        write_marker_v0(&store, expected).expect("idempotent replay");
        clear_marker_v0(&store, expected).expect("clear marker");
        assert_eq!(load_marker_v0(&store).expect("load clear"), None);
    }

    #[test]
    fn marker_conflict_tamper_and_temp_are_fail_closed_v0() {
        let directory = tempdir().expect("tempdir");
        let store = directory.path().join("proposal.sqlite");
        File::create(&store).expect("create store identity");
        let expected = marker(11);
        write_marker_v0(&store, expected).expect("publish marker");
        assert!(write_marker_v0(&store, marker(12)).is_err());
        let path = marker_path_v0(&store);
        let mut bytes = fs::read(&path).expect("read marker");
        bytes[17] ^= 1;
        fs::write(&path, bytes).expect("tamper marker");
        assert!(load_marker_v0(&store).is_err());
        fs::remove_file(&path).expect("remove tampered marker");
        let temp = marker_temp_path_v0(&store);
        fs::write(&temp, expected.encode()).expect("write orphan temp");
        assert!(load_marker_v0(&store).is_err());
    }

    #[test]
    fn marker_clear_rejects_foreign_expected_tuple_v0() {
        let directory = tempdir().expect("tempdir");
        let store = directory.path().join("proposal.sqlite");
        File::create(&store).expect("create store identity");
        let expected = marker(21);
        write_marker_v0(&store, expected).expect("publish marker");
        assert!(clear_marker_v0(&store, marker(22)).is_err());
        assert_eq!(load_marker_v0(&store).expect("load marker"), Some(expected));
    }

    #[cfg(unix)]
    #[test]
    fn marker_rejects_parent_or_store_path_replacement_v0() {
        use std::os::unix::fs::symlink;

        let directory = tempdir().expect("tempdir");
        let parent = directory.path().join("node");
        fs::create_dir(&parent).expect("create canonical parent");
        let store = parent.join("proposal.sqlite");
        File::create(&store).expect("create store identity");
        let expected = marker(31);
        write_marker_v0(&store, expected).expect("publish marker");

        // A replaced parent must not redirect a marker read to a different
        // directory, even when the replacement is a symlink to the old one.
        let moved_parent = directory.path().join("moved-node");
        fs::rename(&parent, &moved_parent).expect("move original parent");
        symlink(&moved_parent, &parent).expect("replace parent with symlink");
        assert!(load_marker_v0(&store).is_err());

        // Restore the canonical parent and then replace the store path itself
        // with a symlink.  Marker authority is tied to the exact regular store
        // object, not merely to a textual filename.
        fs::remove_file(&parent).expect("remove parent symlink");
        fs::rename(&moved_parent, &parent).expect("restore original parent");
        let moved_store = parent.join("proposal.moved.sqlite");
        fs::rename(&store, &moved_store).expect("move original store");
        symlink(&moved_store, &store).expect("replace store with symlink");
        assert!(load_marker_v0(&store).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn marker_rejects_store_or_marker_aliases_v0() {
        use std::fs::hard_link;

        let directory = tempdir().expect("tempdir");
        let store = directory.path().join("proposal.sqlite");
        File::create(&store).expect("create store identity");
        let store_alias = directory.path().join("proposal.alias.sqlite");
        hard_link(&store, &store_alias).expect("create store alias");
        assert!(load_marker_v0(&store).is_err());
        fs::remove_file(&store_alias).expect("remove store alias");

        let expected = marker(41);
        write_marker_v0(&store, expected).expect("publish marker");
        let marker_alias = directory.path().join("marker.alias");
        hard_link(marker_path_v0(&store), &marker_alias).expect("create marker alias");
        assert!(load_marker_v0(&store).is_err());
    }
}
