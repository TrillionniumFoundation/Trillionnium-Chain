//! Storage-local snapshot v1 integrity. No new consensus wire bytes or trust root.
//!
//! The selected generation is verified in bounded reads against its exact full
//! manifest. Legacy lossy manifest records are rejected, never rewritten. The
//! Linux opens reject final-component links, special files and aliases. Pinned
//! namespace identities detect observed replacement; owner-controlled ancestors
//! and exclusion of a continuously malicious same-UID writer remain assumptions.

use super::{DurableFileErrorV0, SnapshotManifestV0, SyncDigestV0};
use fs2::FileExt;
use std::{
    fs::{self, File},
    io::{self, Read},
    path::{Path, PathBuf},
};
use trnm_state_sync_v0::{chunk_merkle_root_v0, SnapshotChunkV0};

const MAGIC: &[u8; 8] = b"TRNMSM01";
const MANIFEST_BYTES: usize = 296;
const DOMAIN: &[u8] = b"trnm.snapshot-staging-manifest.v1";
type Result<T> = std::result::Result<T, DurableFileErrorV0>;

#[cfg(target_os = "linux")]
fn open_path(path: &Path, directory: bool, create: bool) -> Result<File> {
    use rustix::fs::{openat, Mode, OFlags, CWD};
    let mut flags = OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
    flags |= if directory {
        OFlags::DIRECTORY | OFlags::RDONLY
    } else if create {
        OFlags::RDWR | OFlags::CREATE | OFlags::EXCL
    } else {
        OFlags::RDONLY
    };
    let file: File = openat(CWD, path, flags, Mode::from_raw_mode(0o600))
        .map_err(|error| DurableFileErrorV0::Io(error.into()))?
        .into();
    validate_file(&file, path, directory)?;
    Ok(file)
}

#[cfg(not(target_os = "linux"))]
fn open_path(_path: &Path, _directory: bool, _create: bool) -> Result<File> {
    Err(DurableFileErrorV0::Io(io::Error::new(
        io::ErrorKind::Unsupported,
        "snapshot v1 requires Linux no-follow file admission",
    )))
}

#[cfg(target_os = "linux")]
fn validate_file(file: &File, path: &Path, directory: bool) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let metadata = file.metadata()?;
    if metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o022 != 0
        || (directory && !metadata.is_dir())
        || (!directory && (!metadata.is_file() || metadata.nlink() != 1))
    {
        return Err(DurableFileErrorV0::RecoveryRequired(path.to_owned()));
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn validate_file(_file: &File, path: &Path, _directory: bool) -> Result<()> {
    Err(DurableFileErrorV0::RecoveryRequired(path.to_owned()))
}

#[cfg(target_os = "linux")]
fn same_file(left: &File, right: &File) -> Result<bool> {
    use std::os::unix::fs::MetadataExt;
    let a = left.metadata()?;
    let b = right.metadata()?;
    Ok(a.dev() == b.dev() && a.ino() == b.ino())
}

#[cfg(not(target_os = "linux"))]
fn same_file(_left: &File, _right: &File) -> Result<bool> {
    Ok(false)
}

/// Create a new private file. Existing names, including dangling links, are
/// never truncated or treated as successful idempotent writes.
pub(super) fn create_snapshot_file_v1(path: &Path) -> Result<File> {
    open_path(path, false, true)
}

#[cfg(target_os = "linux")]
pub(super) fn create_snapshot_directory_v1(path: &Path) -> Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    fs::DirBuilder::new().mode(0o700).create(path)?;
    validate_directory_v1(path)
}

#[cfg(not(target_os = "linux"))]
pub(super) fn create_snapshot_directory_v1(path: &Path) -> Result<()> {
    Err(DurableFileErrorV0::RecoveryRequired(path.to_owned()))
}

pub(super) fn validate_directory_v1(path: &Path) -> Result<()> {
    open_path(path, true, false).map(|_| ())
}

pub(super) fn open_snapshot_lock_v1(path: &Path) -> Result<File> {
    let create = match fs::symlink_metadata(path) {
        Ok(_) => false,
        Err(error) if error.kind() == io::ErrorKind::NotFound => true,
        Err(error) => return Err(error.into()),
    };
    if create
        && path
            .parent()
            .is_some_and(|parent| parent.join("CURRENT.v0").exists())
    {
        return Err(DurableFileErrorV0::RecoveryRequired(path.to_owned()));
    }
    let file = open_path(path, false, create)?;
    if let Err(error) = FileExt::try_lock_exclusive(&file) {
        return if error.kind() == io::ErrorKind::WouldBlock {
            Err(DurableFileErrorV0::LockBusy(path.to_owned()))
        } else {
            Err(error.into())
        };
    }
    file.sync_all()?;
    Ok(file)
}

pub(super) struct SnapshotNamespaceV1 {
    directories: Vec<(PathBuf, File)>,
}
impl SnapshotNamespaceV1 {
    pub(super) fn pin(root: &Path, lock: &File) -> Result<Self> {
        let mut directories = Vec::new();
        for path in [
            root.to_owned(),
            root.join("staging"),
            root.join("generations"),
        ] {
            let file = open_path(&path, true, false)?;
            directories.push((path, file));
        }
        let value = Self { directories };
        value.check(root, lock)?;
        Ok(value)
    }

    pub(super) fn check(&self, root: &Path, lock: &File) -> Result<()> {
        for (path, retained) in &self.directories {
            validate_file(retained, path, true)?;
            let named = open_path(path, true, false)?;
            if !same_file(retained, &named)? {
                return Err(DurableFileErrorV0::RecoveryRequired(path.clone()));
            }
        }
        let path = root.join("snapshot.lock.v0");
        validate_file(lock, &path, false)?;
        if !same_file(lock, &open_path(&path, false, false)?)? {
            return Err(DurableFileErrorV0::RecoveryRequired(path));
        }
        Ok(())
    }
}

pub(super) fn read_bounded_v1(path: &Path, maximum: usize) -> Result<Vec<u8>> {
    let mut file = open_path(path, false, false)?;
    let size = file.metadata()?.len();
    if size > maximum as u64 {
        return Err(DurableFileErrorV0::RecoveryRequired(path.to_owned()));
    }
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(size as usize).map_err(|_| {
        DurableFileErrorV0::Io(io::Error::other("bounded snapshot allocation failed"))
    })?;
    (&mut file)
        .take(maximum as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 != size || file.metadata()?.len() != size {
        return Err(DurableFileErrorV0::RecoveryRequired(path.to_owned()));
    }
    validate_file(&file, path, false)?;
    if !same_file(&file, &open_path(path, false, false)?)? {
        return Err(DurableFileErrorV0::RecoveryRequired(path.to_owned()));
    }
    Ok(bytes)
}

pub(super) fn encode_manifest_v1(manifest: &SnapshotManifestV0) -> Result<Vec<u8>> {
    manifest
        .validate_shape()
        .map_err(|_| DurableFileErrorV0::InvalidSnapshotManifest)?;
    let mut bytes = Vec::with_capacity(MANIFEST_BYTES);
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&manifest.chain_id.0);
    bytes.extend_from_slice(&manifest.protocol_digest.0);
    bytes.extend_from_slice(&manifest.height.to_be_bytes());
    bytes.extend_from_slice(&manifest.epoch.to_be_bytes());
    bytes.extend_from_slice(&manifest.state_root.0);
    bytes.extend_from_slice(&manifest.chunk_root.0);
    bytes.extend_from_slice(&manifest.chunk_count.to_be_bytes());
    bytes.extend_from_slice(&manifest.maximum_chunk_bytes.to_be_bytes());
    bytes.extend_from_slice(&manifest.total_bytes.to_be_bytes());
    bytes.extend_from_slice(&manifest.schema_digest.0);
    bytes.extend_from_slice(&manifest.checkpoint_digest.0);
    bytes.extend_from_slice(&manifest.manifest_digest.0);
    let checksum = SyncDigestV0::hash(DOMAIN, &[&bytes]);
    bytes.extend_from_slice(&checksum.0);
    Ok(bytes)
}

fn take<const N: usize>(bytes: &[u8], offset: &mut usize) -> Result<[u8; N]> {
    let end = offset
        .checked_add(N)
        .ok_or(DurableFileErrorV0::InvalidSnapshotManifest)?;
    let value = bytes
        .get(*offset..end)
        .and_then(|slice| slice.try_into().ok())
        .ok_or(DurableFileErrorV0::InvalidSnapshotManifest)?;
    *offset = end;
    Ok(value)
}

pub(super) fn decode_manifest_v1(bytes: &[u8]) -> Result<SnapshotManifestV0> {
    if bytes.len() != MANIFEST_BYTES || bytes.get(..8) != Some(MAGIC.as_slice()) {
        return Err(DurableFileErrorV0::InvalidSnapshotManifest);
    }
    let mut p = 8;
    let manifest = SnapshotManifestV0 {
        chain_id: SyncDigestV0(take(bytes, &mut p)?),
        protocol_digest: SyncDigestV0(take(bytes, &mut p)?),
        height: u64::from_be_bytes(take(bytes, &mut p)?),
        epoch: u64::from_be_bytes(take(bytes, &mut p)?),
        state_root: SyncDigestV0(take(bytes, &mut p)?),
        chunk_root: SyncDigestV0(take(bytes, &mut p)?),
        chunk_count: u32::from_be_bytes(take(bytes, &mut p)?),
        maximum_chunk_bytes: u32::from_be_bytes(take(bytes, &mut p)?),
        total_bytes: u64::from_be_bytes(take(bytes, &mut p)?),
        schema_digest: SyncDigestV0(take(bytes, &mut p)?),
        checkpoint_digest: SyncDigestV0(take(bytes, &mut p)?),
        manifest_digest: SyncDigestV0(take(bytes, &mut p)?),
    };
    let checksum = SyncDigestV0::hash(DOMAIN, &[&bytes[..p]]);
    if checksum.0 != take::<32>(bytes, &mut p)? || p != bytes.len() {
        return Err(DurableFileErrorV0::InvalidSnapshotManifest);
    }
    manifest
        .validate_shape()
        .map_err(|_| DurableFileErrorV0::InvalidSnapshotManifest)?;
    Ok(manifest)
}

pub(super) fn read_manifest_v1(directory: &Path) -> Result<SnapshotManifestV0> {
    validate_directory_v1(directory)?;
    decode_manifest_v1(&read_bounded_v1(
        &directory.join("MANIFEST.v0"),
        MANIFEST_BYTES,
    )?)
}

pub(super) fn validate_staging_inventory_v1(
    directory: &Path,
    manifest: &SnapshotManifestV0,
) -> Result<()> {
    inspect_inventory(directory, manifest, true).map(|_| ())
}

fn inspect_inventory(
    directory: &Path,
    manifest: &SnapshotManifestV0,
    allow_temporary: bool,
) -> Result<u32> {
    if read_manifest_v1(directory)? != *manifest {
        return Err(DurableFileErrorV0::InvalidSnapshotManifest);
    }
    let mut chunks = 0_u32;
    let mut temporary_seen = false;
    for (count, entry) in fs::read_dir(directory)?.enumerate() {
        let path = entry?.path();
        if count > manifest.chunk_count as usize + 1 {
            return Err(DurableFileErrorV0::RecoveryRequired(directory.to_owned()));
        }
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            return Err(DurableFileErrorV0::RecoveryRequired(path));
        };
        if name == "MANIFEST.v0" {
            continue;
        }
        let (raw_index, temporary) = if let Some(value) = name
            .strip_prefix("chunk-")
            .and_then(|s| s.strip_suffix(".bin"))
        {
            (value, false)
        } else if let Some(value) = name
            .strip_prefix(".chunk-")
            .and_then(|s| s.strip_suffix(".tmp"))
        {
            (value, true)
        } else {
            return Err(DurableFileErrorV0::RecoveryRequired(path));
        };
        let index = raw_index
            .parse::<u32>()
            .ok()
            .filter(|index| *index < manifest.chunk_count && raw_index == format!("{index:08}"))
            .ok_or_else(|| DurableFileErrorV0::RecoveryRequired(path.clone()))?;
        let _ = index;
        let file = open_path(&path, false, false)?;
        let size = file.metadata()?.len();
        if size > u64::from(manifest.maximum_chunk_bytes) || (!temporary && size == 0) {
            return Err(DurableFileErrorV0::RecoveryRequired(path));
        }
        if temporary {
            if !allow_temporary || temporary_seen {
                return Err(DurableFileErrorV0::RecoveryRequired(path));
            }
            temporary_seen = true;
        } else {
            chunks += 1;
        }
    }
    Ok(chunks)
}

pub(super) fn verify_generation_v1(directory: &Path, manifest: &SnapshotManifestV0) -> Result<()> {
    manifest
        .validate_shape()
        .map_err(|_| DurableFileErrorV0::InvalidSnapshotManifest)?;
    if inspect_inventory(directory, manifest, false)? != manifest.chunk_count {
        return Err(DurableFileErrorV0::IncompleteSnapshot);
    }
    let binding = manifest.chunk_binding_digest();
    let mut hashes = Vec::with_capacity(manifest.chunk_count as usize);
    let mut total = 0_u64;
    for index in 0..manifest.chunk_count {
        let bytes = read_bounded_v1(
            &directory.join(format!("chunk-{index:08}.bin")),
            manifest.maximum_chunk_bytes as usize,
        )?;
        total = total
            .checked_add(bytes.len() as u64)
            .ok_or(DurableFileErrorV0::SequenceOverflow)?;
        if total > manifest.total_bytes {
            return Err(DurableFileErrorV0::SnapshotByteCountMismatch);
        }
        hashes.push(SnapshotChunkV0::canonical_digest(binding, index, &bytes));
    }
    if total != manifest.total_bytes {
        return Err(DurableFileErrorV0::SnapshotByteCountMismatch);
    }
    if chunk_merkle_root_v0(&hashes) != manifest.chunk_root {
        return Err(DurableFileErrorV0::ChunkSubstitution);
    }
    if read_manifest_v1(directory)? != *manifest {
        return Err(DurableFileErrorV0::InvalidSnapshotManifest);
    }
    Ok(())
}
