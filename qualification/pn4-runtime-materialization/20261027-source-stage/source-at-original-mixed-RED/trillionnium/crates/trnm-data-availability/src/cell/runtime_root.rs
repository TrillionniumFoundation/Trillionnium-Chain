//! Explicit runtime byte roles, separate from the eleven-object model profile.
//! This is a disposable-cache consumer, not provider-retention or model authority.
//! The existing cache's cooperative single-owner namespace contract applies.

use super::{
    network::{fetch_cell_in_session, RequestContext, ResponseBudget},
    require, CellContextV1, CellDigestV1, CellErrorV1, CellManifestV1, CellPeerLimitsV1,
    CellResultV1, CellStoreV1, MAX_CHUNK_BYTES,
};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    net::SocketAddr,
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Component, Path},
    sync::atomic::{AtomicU64, Ordering},
    time::Instant,
};

const HOST_CAP: u64 = 2 * 1024 * 1024 * 1024;
const META_CAP: u64 = 64 * 1024 * 1024;
const CACHE_CAP: u64 = 512 * 1024 * 1024;
const MAX_FILES: usize = 32_768;

/// Canonical portable runtime roles; none is a ninth model-base member.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CellRuntimeRoleV1 {
    Interpreter,
    StandardLibrary,
    SitePackage,
    Native,
    Wheel,
    Distribution,
    Source,
    Launcher,
    LauncherSource,
    LauncherRecipe,
    Provenance,
}
impl CellRuntimeRoleV1 {
    pub fn name(self) -> &'static str {
        match self {
            Self::Interpreter => "interpreter",
            Self::StandardLibrary => "stdlib",
            Self::SitePackage => "site",
            Self::Native => "native",
            Self::Wheel => "wheel",
            Self::Distribution => "distribution",
            Self::Source => "source",
            Self::Launcher => "launcher",
            Self::LauncherSource => "launcher-source",
            Self::LauncherRecipe => "launcher-recipe",
            Self::Provenance => "provenance",
        }
    }
}

/// Ordered original-byte segments, each a complete authority-pinned TCM1.
/// Whole-file SHA is mandatory even when every individual segment verifies.
#[derive(Clone, Debug)]
pub struct CellRuntimeFileV1 {
    pub path: String,
    pub role: CellRuntimeRoleV1,
    pub bytes: u64,
    pub sha256: CellDigestV1,
    pub segments: Vec<CellManifestV1>,
}

/// One original reservation; no per-file deadline, connection or byte reset.
#[derive(Clone, Copy, Debug)]
pub struct CellRuntimeLimitsV1 {
    pub peer: CellPeerLimitsV1,
    pub deadline: Instant,
    pub host_bytes: u64,
    pub metadata_bytes: u64,
    /// Full owner's not-visible-in-census held/unlinked/old+new/partial costs.
    /// None means unknown, and refuses before any cache write or provider call.
    pub outstanding_owned_bytes: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CellRuntimeMaterializationV1 {
    pub files_root: CellDigestV1,
    pub file_count: usize,
    pub reconstructed_bytes: u64,
    pub reserved_host_bytes: u64,
    /// Failure or success never refunds this original network reservation.
    pub reserved_response_bytes: u64,
    pub received_response_bytes: u64,
    pub connection_attempts: u64,
}

pub fn runtime_files_root_v1(files: &[CellRuntimeFileV1]) -> CellResultV1<CellDigestV1> {
    require(
        !files.is_empty() && files.len() <= MAX_FILES,
        "runtime file count",
    )?;
    let mut hash = Sha256::new();
    hash.update(b"hepta.smollm-runtime-files.v1\0");
    let mut previous: Option<&str> = None;
    for file in files {
        runtime_path(&file.path)?;
        require(
            previous.is_none_or(|value| value < file.path.as_str()),
            "runtime sorted unique paths",
        )?;
        previous = Some(&file.path);
        for value in [file.path.as_bytes(), file.role.name().as_bytes()] {
            hash.update((value.len() as u64).to_be_bytes());
            hash.update(value);
        }
        hash.update(file.bytes.to_be_bytes());
        hash.update(file.sha256);
    }
    Ok(hash.finalize().into())
}

fn runtime_path(path: &str) -> CellResultV1<()> {
    require(
        !path.is_empty()
            && path.len() <= 1024
            && path.is_ascii()
            && path
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"/_+.-".contains(&b))
            && Path::new(path)
                .components()
                .all(|part| matches!(part, Component::Normal(_)))
            && !path
                .split('/')
                .any(|part| part.is_empty() || part == "." || part == ".."),
        "runtime relative path",
    )
}

/// Validate the complete known plan before opening a peer. Empty original files
/// have no Cells and the mandatory SHA256(empty); executable roles cannot be empty.
fn validate_files(
    files: &[CellRuntimeFileV1],
    context: &CellContextV1,
    deadline: Instant,
    metadata_cap: u64,
) -> CellResultV1<(u64, u64)> {
    runtime_files_root_v1(files)?;
    let mut payload = 0u64;
    let mut metadata = 0u64;
    let names: BTreeSet<_> = files.iter().map(|file| file.path.as_str()).collect();
    for file in files {
        require(Instant::now() <= deadline, "runtime plan deadline")?;
        for ancestor in Path::new(&file.path)
            .ancestors()
            .skip(1)
            .filter_map(Path::to_str)
        {
            require(
                !names.contains(ancestor),
                "runtime file/directory collision",
            )?;
        }
        payload = payload
            .checked_add(file.bytes)
            .ok_or(CellErrorV1::Invalid("runtime payload overflow"))?;
        metadata = metadata
            .checked_add(file.path.len() as u64 + 128)
            .ok_or(CellErrorV1::Invalid("runtime metadata overflow"))?;
        require(file.bytes <= HOST_CAP, "runtime individual file bound")?;
        let mut size = 0u64;
        require(
            metadata <= metadata_cap && payload <= HOST_CAP,
            "runtime bounded plan",
        )?;
        for segment in &file.segments {
            require(Instant::now() <= deadline, "runtime plan deadline")?;
            segment.validate()?;
            require(
                segment.context() == context
                    && segment.size() <= u64::from(MAX_CHUNK_BYTES)
                    && segment.chunks().len() == 1,
                "runtime bounded segment/context",
            )?;
            size = size
                .checked_add(segment.size())
                .ok_or(CellErrorV1::Invalid("runtime segment overflow"))?;
            metadata = metadata
                .checked_add(segment.encode().len() as u64)
                .ok_or(CellErrorV1::Invalid("runtime metadata overflow"))?;
            require(metadata <= metadata_cap, "runtime metadata cap")?;
        }
        require(size == file.bytes, "runtime segment coverage")?;
        if file.bytes == 0 {
            require(
                file.segments.is_empty()
                    && file.sha256 == <[u8; 32]>::from(Sha256::digest([]))
                    && !matches!(
                        file.role,
                        CellRuntimeRoleV1::Interpreter
                            | CellRuntimeRoleV1::Launcher
                            | CellRuntimeRoleV1::Native
                    ),
                "runtime empty file",
            )?;
        }
    }
    Ok((payload, metadata))
}

/// Enumerate the entire same-owner scope, including existing CURRENT versions,
/// DB, WAL, SHM, locks, staging and partials. Count allocated extents as well as
/// logical lengths. This admission is not a filesystem quota against other writers.
fn census(path: &Path, uid: u32, entries: &mut u64, deadline: Instant) -> CellResultV1<u64> {
    require(Instant::now() <= deadline, "runtime census deadline")?;
    *entries += 1;
    require(*entries <= 131_072, "runtime scope entry bound")?;
    let value = fs::symlink_metadata(path)?;
    require(
        value.uid() == uid && !value.file_type().is_symlink(),
        "runtime scope owner/link",
    )?;
    let mut bytes = value.len().max(
        value
            .blocks()
            .checked_mul(512)
            .ok_or(CellErrorV1::Invalid("runtime extent overflow"))?,
    );
    if value.is_dir() {
        require(
            value.permissions().mode() & 0o077 == 0,
            "runtime private scope directory",
        )?;
        for entry in fs::read_dir(path)? {
            bytes = bytes
                .checked_add(census(&entry?.path(), uid, entries, deadline)?)
                .ok_or(CellErrorV1::Invalid("runtime scope overflow"))?;
        }
    } else {
        require(
            value.is_file() && value.nlink() == 1,
            "runtime scope regular exclusive file",
        )?;
    }
    Ok(bytes)
}

/// Real streaming materialization through the existing TCM1 downloader. The
/// caller must supply the original private complete host scope and an exclusive
/// cache in it. This cooperative byte owner is not an immutable executable
/// root, a physical filesystem quota, a release issuer or a runtime loader.
/// The durable create-only reservation remains after EVERY outcome;
/// an unknown or failed attempt is never made cheap by calling this API again.
/// Caller reconciliation of that record is deliberately not a refund API.
pub fn materialize_runtime_root_v1(
    store: &mut CellStoreV1,
    scope: &Path,
    output_name: &str,
    files: &[CellRuntimeFileV1],
    expected_files_root: CellDigestV1,
    context: &CellContextV1,
    peers: &[SocketAddr],
    limits: CellRuntimeLimitsV1,
) -> CellResultV1<CellRuntimeMaterializationV1> {
    limits.peer.validate()?;
    context.validate()?;
    runtime_path(output_name)?;
    require(!output_name.contains('/'), "runtime output basename")?;
    require(
        (1..=HOST_CAP).contains(&limits.host_bytes)
            && (1..=META_CAP).contains(&limits.metadata_bytes),
        "runtime original host/metadata caps",
    )?;
    let outstanding = limits
        .outstanding_owned_bytes
        .ok_or(CellErrorV1::Invalid("runtime unresolved owned cost"))?;
    let deadline = limits
        .deadline
        .min(Instant::now() + limits.peer.overall_timeout);
    require(
        Instant::now() <= deadline
            && peers.len() <= 8
            && peers.iter().collect::<BTreeSet<_>>().len() == peers.len(),
        "runtime peer/deadline",
    )?;
    let files_root = runtime_files_root_v1(files)?;
    require(
        files_root == expected_files_root,
        "runtime owner-pinned files root",
    )?;
    let (payload, metadata) = validate_files(files, context, deadline, limits.metadata_bytes)?;
    require(metadata <= limits.metadata_bytes, "runtime metadata cap")?;
    require(
        !fs::symlink_metadata(scope)?.file_type().is_symlink(),
        "runtime scope symlink",
    )?;
    let scope = scope.canonicalize()?;
    let scope_meta = fs::symlink_metadata(&scope)?;
    require(
        scope_meta.is_dir() && scope_meta.permissions().mode() & 0o077 == 0,
        "runtime private scope",
    )?;
    require(
        store.path.starts_with(&scope)
            && store.config.max_database_bytes <= CACHE_CAP
            && store.config.max_logical_bytes <= CACHE_CAP,
        "runtime cache same scope/original cap",
    )?;
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(scope.join("runtime-owner-v1.lock"))?;
    lock.try_lock()
        .map_err(|_| CellErrorV1::Invalid("runtime scope owner busy"))?;
    let baseline = census(&scope, scope_meta.uid(), &mut 0, deadline)?;
    let cache = store
        .config
        .max_database_bytes
        .checked_add(store.config.max_wal_bytes()?)
        .and_then(|n| n.checked_add(store.config.max_shm_bytes().ok()?))
        .ok_or(CellErrorV1::Invalid("runtime cache reservation overflow"))?;
    // Include complete destination, all metadata, and a full bounded DB/WAL/SHM
    // reservation. Existing cache bytes are also in baseline: conservative,
    // never subtract an unverified refund. Directory allocation needs reservation.
    let granularity = fs2::allocation_granularity(&scope)?;
    require(
        granularity > 0 && granularity <= META_CAP,
        "runtime filesystem allocation unit",
    )?;
    let round = |bytes: u64| {
        bytes
            .div_ceil(granularity)
            .checked_mul(granularity)
            .ok_or(CellErrorV1::Invalid("runtime allocation overflow"))
    };
    let allocated_payload = files.iter().try_fold(0u64, |sum, file| {
        sum.checked_add(round(file.bytes)?)
            .ok_or(CellErrorV1::Invalid("runtime allocation overflow"))
    })?;
    let directories = files
        .iter()
        .map(|file| Path::new(&file.path).ancestors().count() as u64)
        .sum::<u64>();
    let directory_reserve = (directories + 3)
        .checked_mul(granularity)
        .ok_or(CellErrorV1::Invalid("runtime allocation overflow"))?;
    let reserved = baseline
        .checked_add(outstanding)
        .and_then(|n| n.checked_add(allocated_payload))
        .and_then(|n| n.checked_add(limits.metadata_bytes))
        .and_then(|n| n.checked_add(cache))
        .and_then(|n| n.checked_add(directory_reserve))
        .ok_or(CellErrorV1::Invalid("runtime host reservation overflow"))?;
    require(
        reserved <= limits.host_bytes,
        "runtime same-owner peak admission",
    )?;
    let output = scope.join(output_name);
    require(
        fs::symlink_metadata(&output)
            .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound),
        "runtime destination already exists",
    )?;
    let mut reservation = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(scope.join("runtime-reservation-v1"))?;
    reservation.write_all(b"TRRV1\0")?;
    reservation.write_all(&files_root)?;
    reservation.write_all(&reserved.to_be_bytes())?;
    reservation.write_all(&limits.peer.max_response_bytes.to_be_bytes())?;
    reservation.sync_all()?;
    File::open(&scope)?.sync_all()?;
    let staging = scope.join(format!("{output_name}.partial-runtime-v1"));
    fs::DirBuilder::new().mode(0o700).create(&staging)?;
    File::open(&scope)?.sync_all()?;
    let requests_left = AtomicU64::new(limits.peer.max_connections);
    let responses = ResponseBudget::new(limits.peer.max_response_bytes);
    let transport = RequestContext {
        timeout: limits.peer.request_timeout,
        overall: deadline,
        requests_left: &requests_left,
        responses: &responses,
    };
    for file in files {
        require(Instant::now() <= deadline, "runtime file deadline")?;
        let target = staging.join(&file.path);
        let parent = target
            .parent()
            .ok_or(CellErrorV1::Invalid("runtime parent"))?;
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(parent)?;
        let mut destination = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&target)?;
        // Make every newly created file/directory entry durable BEFORE a
        // disposable-cache row can be retired. A durable data inode without a
        // durable parent dirent is not a successful responsibility transfer.
        for ancestor in parent
            .ancestors()
            .take_while(|path| path.starts_with(&scope))
        {
            File::open(ancestor)?.sync_all()?;
        }
        let mut full = Sha256::new();
        let mut actual = 0u64;
        for segment in &file.segments {
            // Store the already owner-pinned manifest, then reuse the original
            // single transport for EVERY file/segment/retry. No full release is
            // accumulated in the 512-MiB disposable cache.
            store.put_manifest(segment.id(), &segment.encode())?;
            let (fetched, _) =
                fetch_cell_in_session(store, segment.id(), peers, limits.peer, &transport, None)?;
            require(fetched == *segment, "runtime pinned segment")?;
            for expected in segment.chunks() {
                let bytes = store
                    .chunk(expected.sha256)?
                    .ok_or(CellErrorV1::Unavailable)?;
                require(bytes.len() as u32 == expected.size, "runtime chunk length")?;
                destination.write_all(&bytes)?;
                full.update(&bytes);
                actual += bytes.len() as u64;
            }
            destination.sync_all()?;
            store.retire_consumed_runtime_segment(segment)?;
            require(
                Instant::now() <= deadline,
                "runtime materialization deadline",
            )?;
        }
        require(
            actual == file.bytes && <[u8; 32]>::from(full.finalize()) == file.sha256,
            "runtime whole-file digest",
        )?;
        destination.sync_all()?;
        // Re-read the actual file, not the prior receive buffer, before output.
        let mut observed = Sha256::new();
        let mut read = File::open(&target)?.take(file.bytes + 1);
        let mut buffer = [0u8; 65536];
        let mut read_bytes = 0u64;
        loop {
            require(Instant::now() <= deadline, "runtime readback deadline")?;
            let n = read.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            observed.update(&buffer[..n]);
            read_bytes += n as u64;
        }
        require(
            read_bytes == file.bytes && <[u8; 32]>::from(observed.finalize()) == file.sha256,
            "runtime file readback",
        )?;
    }
    File::open(&staging)?.sync_all()?;
    require(
        census(&scope, scope_meta.uid(), &mut 0, deadline)?
            .checked_add(outstanding)
            .is_some_and(|n| n <= limits.host_bytes),
        "runtime actual same-owner cap",
    )?;
    require(Instant::now() <= deadline, "runtime publication deadline")?;
    // Private same-owner namespace and held owner lock exclude supported races.
    // No chmod/mount/immutable flag is silently performed by this byte owner.
    fs::rename(&staging, &output)?;
    File::open(&scope)?.sync_all()?;
    Ok(CellRuntimeMaterializationV1 {
        files_root,
        file_count: files.len(),
        reconstructed_bytes: payload,
        reserved_host_bytes: reserved,
        reserved_response_bytes: limits.peer.max_response_bytes,
        received_response_bytes: responses.received()?,
        connection_attempts: limits.peer.max_connections - requests_left.load(Ordering::Relaxed),
    })
}

#[cfg(test)]
#[path = "runtime_root_tests.rs"]
mod tests;
