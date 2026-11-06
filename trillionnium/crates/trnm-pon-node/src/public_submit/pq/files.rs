//! Private Linux descriptor-bound storage for one bounded recovery campaign.
//! Blob names are content addresses, never authority. Unreferenced blobs remain
//! inert; this local owner is not an independent whole-directory rollback oracle.
use crate::{ensure, Result};
use fs2::FileExt;
use rustix::fs::{self as rfs, Mode, OFlags, RenameFlags};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::{File, Metadata, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use trnm_protocol::pon_wire::{hash, Hash};

pub(super) const MAX_METADATA: usize = 128 * 1024;
pub(super) const MAX_BLOB: usize = trnm_protocol::pq_legacy_profile::MAX_WIRE;
const CURRENT: &str = "journal";
const PREPARED: &str = "prepared";
const LOCK: &str = "lock";

type LoadedSnapshots = (Option<Vec<u8>>, Option<Vec<u8>>);
#[cfg(test)]
type FaultCallback = Box<dyn FnMut(Point, &Path) -> Result<()>>;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Blob {
    pub digest: Hash,
    pub bytes: u32,
}
impl Blob {
    fn of(bytes: &[u8]) -> Self {
        Self {
            digest: hash(b"pq-parent-blob-v1", &[bytes]),
            bytes: bytes.len() as u32,
        }
    }
    fn name(&self) -> String {
        format!("blob-{}", hex::encode(self.digest))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Identity {
    device: u64,
    inode: u64,
    size: u64,
    mode: u32,
    links: u64,
    uid: u32,
    modified: (i64, i64),
    changed: (i64, i64),
}
fn identity(m: &Metadata) -> Identity {
    Identity {
        device: m.dev(),
        inode: m.ino(),
        size: m.len(),
        mode: m.mode(),
        links: m.nlink(),
        uid: m.uid(),
        modified: (m.mtime(), m.mtime_nsec()),
        changed: (m.ctime(), m.ctime_nsec()),
    }
}
fn same_renamed_object(a: &Identity, b: &Identity) -> bool {
    let mut before = a.clone();
    // rename may update ctime; byte digest and every other identity field stay bound.
    before.changed = b.changed;
    before == *b
}
fn regular(m: &Metadata) -> Result<()> {
    ensure(
        m.is_file()
            && m.mode() & 0o7777 == 0o600
            && m.nlink() == 1
            && m.uid() == rustix::process::geteuid().as_raw(),
        "PQ_RECOVERY_FILE_OWNER",
    )
}
fn name_ok(name: &str) -> Result<()> {
    ensure(
        !name.is_empty()
            && name.len() <= 80
            && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'),
        "PQ_RECOVERY_FILE_NAME",
    )
}
fn io(error: rustix::io::Errno) -> std::io::Error {
    error.into()
}
fn digest(raw: &[u8]) -> Hash {
    hash(b"pq-parent-journal-bytes-v1", &[raw])
}

#[derive(Clone)]
struct Observed {
    identity: Identity,
    digest: Hash,
}
struct Synced {
    file: File,
    observed: Observed,
}
pub(super) struct Files {
    path: PathBuf,
    root: File,
    parent: File,
    parent_path: PathBuf,
    parent_identity: (u64, u64),
    lock: File,
    root_identity: (u64, u64),
    lock_identity: Identity,
    current: Option<Observed>,
    prepared: Option<Observed>,
    prepared_file: Option<File>,
    pinned: BTreeMap<String, (File, Observed)>,
    fenced: bool,
    #[cfg(test)]
    pub fail_at: Option<Point>,
    #[cfg(test)]
    pub callback: Option<FaultCallback>,
}
#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Point {
    BlobReady,
    Prepared,
    Published,
    WriteSynced,
    ParentSynced,
}

impl Files {
    pub fn acquire(path: &Path, create: bool) -> Result<Self> {
        let mut owner = Self::acquire_raw(path, create)?;
        owner.finish_acquire()?;
        Ok(owner)
    }
    #[cfg(test)]
    pub fn acquire_with_fault(path: &Path, create: bool, callback: FaultCallback) -> Result<Self> {
        let mut owner = Self::acquire_raw(path, create)?;
        owner.callback = Some(callback);
        owner.finish_acquire()?;
        Ok(owner)
    }
    fn acquire_raw(path: &Path, create: bool) -> Result<Self> {
        ensure(path.is_absolute(), "PQ_RECOVERY_DIRECTORY_PATH")?;
        let parent_path = path
            .parent()
            .ok_or("PQ_RECOVERY_DIRECTORY_PATH")?
            .to_path_buf();
        let name = path.file_name().ok_or("PQ_RECOVERY_DIRECTORY_PATH")?;
        let parent = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(&parent_path)?;
        let parent_metadata = parent.metadata()?;
        let parent_identity = (parent_metadata.dev(), parent_metadata.ino());
        if create {
            rfs::mkdirat(&parent, name, Mode::from_raw_mode(0o700)).map_err(io)?;
        }
        let root = File::from(
            rfs::openat(
                &parent,
                name,
                OFlags::RDONLY
                    | OFlags::DIRECTORY
                    | OFlags::NOFOLLOW
                    | OFlags::CLOEXEC
                    | OFlags::NONBLOCK,
                Mode::empty(),
            )
            .map_err(io)?,
        );
        let m = root.metadata()?;
        ensure(
            m.is_dir()
                && m.mode() & 0o7777 == 0o700
                && m.uid() == rustix::process::geteuid().as_raw(),
            "PQ_RECOVERY_DIRECTORY_OWNER",
        )?;
        let mut flags = OFlags::RDWR | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
        if create {
            flags |= OFlags::CREATE | OFlags::EXCL;
        }
        let lock =
            File::from(rfs::openat(&root, LOCK, flags, Mode::from_raw_mode(0o600)).map_err(io)?);
        regular(&lock.metadata()?)?;
        ensure(lock.metadata()?.len() == 0, "PQ_RECOVERY_LOCK_BYTES")?;
        FileExt::try_lock_exclusive(&lock)?;
        if create {
            lock.sync_all()?;
            root.sync_all()?;
        }
        let lock_identity = identity(&lock.metadata()?);
        let owner = Self {
            path: path.to_path_buf(),
            root,
            parent,
            parent_path,
            parent_identity,
            lock,
            root_identity: (m.dev(), m.ino()),
            lock_identity,
            current: None,
            prepared: None,
            prepared_file: None,
            pinned: BTreeMap::new(),
            fenced: false,
            #[cfg(test)]
            fail_at: None,
            #[cfg(test)]
            callback: None,
        };
        owner.check_owner()?;
        Ok(owner)
    }
    fn finish_acquire(&mut self) -> Result<()> {
        self.check_owner()?;
        self.root.sync_all()?;
        // The new root's entry lives in the actual held parent directory.
        // Synchronizing the child directory alone cannot make that entry durable.
        self.parent.sync_all()?;
        #[cfg(test)]
        self.cut(Point::ParentSynced)?;
        self.check_owner()
    }
    pub fn is_fenced(&self) -> bool {
        self.fenced
    }
    fn guarded<T>(&mut self, action: impl FnOnce(&mut Self) -> Result<T>) -> Result<T> {
        ensure(!self.fenced, "PQ_RECOVERY_FENCED")?;
        let result = action(self);
        if result.is_err() {
            self.fenced = true;
        }
        result
    }
    fn open(&self, name: &str) -> Result<Option<File>> {
        name_ok(name)?;
        match rfs::openat(
            &self.root,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(fd) => Ok(Some(File::from(fd))),
            Err(rustix::io::Errno::NOENT) => Ok(None),
            Err(error) => Err(io(error).into()),
        }
    }
    fn check_owner(&self) -> Result<()> {
        let held_parent = self.parent.metadata()?;
        let named_parent = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(&self.parent_path)?
            .metadata()?;
        ensure(
            (held_parent.dev(), held_parent.ino()) == self.parent_identity
                && (named_parent.dev(), named_parent.ino()) == self.parent_identity,
            "PQ_RECOVERY_PARENT_CHANGED",
        )?;
        let name = self.path.file_name().ok_or("PQ_RECOVERY_DIRECTORY_PATH")?;
        let parent_child = File::from(
            rfs::openat(
                &self.parent,
                name,
                OFlags::RDONLY
                    | OFlags::DIRECTORY
                    | OFlags::NOFOLLOW
                    | OFlags::NONBLOCK
                    | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(io)?,
        )
        .metadata()?;
        ensure(
            (parent_child.dev(), parent_child.ino()) == self.root_identity,
            "PQ_RECOVERY_DIRECTORY_CHANGED",
        )?;
        let m = self.root.metadata()?;
        ensure(
            m.is_dir()
                && m.mode() & 0o7777 == 0o700
                && m.uid() == rustix::process::geteuid().as_raw()
                && (m.dev(), m.ino()) == self.root_identity,
            "PQ_RECOVERY_DIRECTORY_CHANGED",
        )?;
        let named = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(&self.path)?
            .metadata()?;
        ensure(
            (named.dev(), named.ino()) == self.root_identity,
            "PQ_RECOVERY_DIRECTORY_CHANGED",
        )?;
        let held = self.lock.metadata()?;
        regular(&held)?;
        let named = self
            .open(LOCK)?
            .ok_or("PQ_RECOVERY_LOCK_MISSING")?
            .metadata()?;
        regular(&named)?;
        ensure(
            identity(&held) == self.lock_identity && identity(&named) == self.lock_identity,
            "PQ_RECOVERY_LOCK_CHANGED",
        )?;
        for (name, (file, expected)) in &self.pinned {
            let held = file.metadata()?;
            let named = self
                .open(name)?
                .ok_or("PQ_RECOVERY_BLOB_MISSING")?
                .metadata()?;
            regular(&held)?;
            regular(&named)?;
            ensure(
                identity(&held) == expected.identity && identity(&named) == expected.identity,
                "PQ_RECOVERY_BLOB_CHANGED",
            )?;
        }
        Ok(())
    }
    fn pin(&mut self, name: String, observed: Observed) -> Result<()> {
        let file = self.open(&name)?.ok_or("PQ_RECOVERY_BLOB_MISSING")?;
        ensure(
            identity(&file.metadata()?) == observed.identity,
            "PQ_RECOVERY_BLOB_CHANGED",
        )?;
        if let Some((_, prior)) = self.pinned.get(&name) {
            ensure(
                prior.identity == observed.identity && prior.digest == observed.digest,
                "PQ_RECOVERY_BLOB_CHANGED",
            )?;
        } else {
            self.pinned.insert(name, (file, observed));
        }
        self.check_owner()
    }
    fn read(&self, name: &str, limit: usize) -> Result<Option<(Vec<u8>, Observed)>> {
        self.check_owner()?;
        let Some(mut file) = self.open(name)? else {
            return Ok(None);
        };
        let before = file.metadata()?;
        regular(&before)?;
        ensure(before.len() <= limit as u64, "PQ_RECOVERY_FILE_LIMIT")?;
        let mut raw = Vec::new();
        Read::by_ref(&mut file)
            .take(limit as u64 + 1)
            .read_to_end(&mut raw)?;
        ensure(raw.len() <= limit, "PQ_RECOVERY_FILE_LIMIT")?;
        let after = file.metadata()?;
        let named = self
            .open(name)?
            .ok_or("PQ_RECOVERY_FILE_MISSING")?
            .metadata()?;
        regular(&after)?;
        regular(&named)?;
        ensure(
            identity(&before) == identity(&after)
                && identity(&after) == identity(&named)
                && raw.len() as u64 == after.len(),
            "PQ_RECOVERY_FILE_CHANGED",
        )?;
        self.check_owner()?;
        let observed = Observed {
            identity: identity(&after),
            digest: digest(&raw),
        };
        Ok(Some((raw, observed)))
    }
    fn check_slot(&self, name: &str, expected: &Option<Observed>) -> Result<()> {
        let actual = self.read(name, MAX_METADATA)?;
        ensure(
            match (expected, actual) {
                (None, None) => true,
                (Some(old), Some((_, new))) => {
                    old.identity == new.identity && old.digest == new.digest
                }
                _ => false,
            },
            "PQ_RECOVERY_SNAPSHOT_CHANGED",
        )
    }
    fn recheck_inner(&self) -> Result<()> {
        self.check_owner()?;
        self.check_slot(CURRENT, &self.current)?;
        self.check_slot(PREPARED, &self.prepared)?;
        ensure(
            match (&self.prepared, &self.prepared_file) {
                (None, None) => true,
                (Some(expected), Some(file)) => identity(&file.metadata()?) == expected.identity,
                _ => false,
            },
            "PQ_RECOVERY_PREPARED_CHANGED",
        )?;
        self.check_owner()
    }
    pub fn recheck(&mut self) -> Result<()> {
        self.guarded(|s| s.recheck_inner())
    }
    pub fn load(&mut self) -> Result<LoadedSnapshots> {
        self.guarded(|s| {
            let current = s.read(CURRENT, MAX_METADATA)?;
            let prepared = s.read(PREPARED, MAX_METADATA)?;
            s.current = current.as_ref().map(|v| v.1.clone());
            s.prepared = prepared.as_ref().map(|v| v.1.clone());
            s.prepared_file = if s.prepared.is_some() {
                s.open(PREPARED)?
            } else {
                None
            };
            s.recheck_inner()?;
            Ok((current.map(|v| v.0), prepared.map(|v| v.0)))
        })
    }
    fn synchronized(&mut self, name: &str, file: File, expected: Observed) -> Result<Synced> {
        ensure(
            identity(&file.metadata()?) == expected.identity,
            "PQ_RECOVERY_WRITE_CHANGED",
        )?;
        file.sync_all()?;
        self.root.sync_all()?;
        #[cfg(test)]
        self.cut(Point::WriteSynced)?;
        let held = file.metadata()?;
        let named = self
            .open(name)?
            .ok_or("PQ_RECOVERY_WRITE_MISSING")?
            .metadata()?;
        regular(&held)?;
        regular(&named)?;
        ensure(
            identity(&held) == expected.identity && identity(&named) == expected.identity,
            "PQ_RECOVERY_WRITE_CHANGED",
        )?;
        self.check_owner()?;
        Ok(Synced {
            file,
            observed: expected,
        })
    }
    fn write_new(&mut self, name: &str, raw: &[u8]) -> Result<Synced> {
        name_ok(name)?;
        let fd = rfs::openat(
            &self.root,
            name,
            OFlags::WRONLY
                | OFlags::CREATE
                | OFlags::EXCL
                | OFlags::NOFOLLOW
                | OFlags::NONBLOCK
                | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )
        .map_err(io)?;
        let mut file = File::from(fd);
        regular(&file.metadata()?)?;
        file.write_all(raw)?;
        let metadata = file.metadata()?;
        ensure(
            metadata.len() == raw.len() as u64,
            "PQ_RECOVERY_WRITE_CHANGED",
        )?;
        self.synchronized(
            name,
            file,
            Observed {
                identity: identity(&metadata),
                digest: digest(raw),
            },
        )
    }
    pub fn get(&mut self, blob: &Blob) -> Result<Vec<u8>> {
        self.guarded(|s| {
            ensure(blob.bytes as usize <= MAX_BLOB, "PQ_RECOVERY_BLOB_LIMIT")?;
            let (raw, observed) = s
                .read(&blob.name(), MAX_BLOB)?
                .ok_or("PQ_RECOVERY_BLOB_MISSING")?;
            ensure(Blob::of(&raw) == *blob, "PQ_RECOVERY_BLOB_DIGEST")?;
            s.pin(blob.name(), observed)?;
            Ok(raw)
        })
    }
    pub fn put(&mut self, raw: &[u8]) -> Result<Blob> {
        self.guarded(|s| {
            ensure(raw.len() <= MAX_BLOB, "PQ_RECOVERY_BLOB_LIMIT")?;
            s.recheck_inner()?;
            let blob = Blob::of(raw);
            let name = blob.name();
            if let Some((existing, observed)) = s.read(&name, MAX_BLOB)? {
                ensure(existing == raw, "PQ_RECOVERY_BLOB_DIGEST")?;
                s.pin(name.clone(), observed)?;
                s.pinned
                    .get(&name)
                    .ok_or("PQ_RECOVERY_BLOB_MISSING")?
                    .0
                    .sync_all()?;
                s.root.sync_all()?;
                s.recheck_inner()?;
                return Ok(blob);
            }
            let candidate = format!("{}-pending", name);
            let synced = if let Some((existing, observed)) = s.read(&candidate, MAX_BLOB)? {
                ensure(existing == raw, "PQ_RECOVERY_BLOB_DIGEST")?;
                let file = s.open(&candidate)?.ok_or("PQ_RECOVERY_BLOB_MISSING")?;
                s.synchronized(&candidate, file, observed)?
            } else {
                s.write_new(&candidate, raw)?
            };
            let (prepared, readback) = s
                .read(&candidate, MAX_BLOB)?
                .ok_or("PQ_RECOVERY_BLOB_MISSING")?;
            ensure(
                prepared == raw
                    && readback.identity == synced.observed.identity
                    && readback.digest == synced.observed.digest,
                "PQ_RECOVERY_BLOB_CHANGED",
            )?;
            s.recheck_inner()?;
            rfs::renameat_with(
                &s.root,
                candidate.as_str(),
                &s.root,
                name.as_str(),
                RenameFlags::NOREPLACE,
            )
            .map_err(io)?;
            s.root.sync_all()?;
            let (published, observed) =
                s.read(&name, MAX_BLOB)?.ok_or("PQ_RECOVERY_BLOB_MISSING")?;
            ensure(
                published == raw
                    && identity(&synced.file.metadata()?) == observed.identity
                    && same_renamed_object(&synced.observed.identity, &observed.identity),
                "PQ_RECOVERY_BLOB_CHANGED",
            )?;
            s.pin(name, observed)?;
            s.recheck_inner()?;
            #[cfg(test)]
            s.cut(Point::BlobReady)?;
            s.recheck_inner()?;
            Ok(blob)
        })
    }
    pub fn prepare(&mut self, raw: &[u8]) -> Result<()> {
        self.guarded(|s| {
            ensure(
                raw.len() <= MAX_METADATA && s.prepared.is_none(),
                "PQ_RECOVERY_PREPARED",
            )?;
            s.recheck_inner()?;
            let synced = s.write_new(PREPARED, raw)?;
            let (observed, readback) = s
                .read(PREPARED, MAX_METADATA)?
                .ok_or("PQ_RECOVERY_PREPARED")?;
            ensure(
                observed == raw
                    && readback.identity == synced.observed.identity
                    && readback.digest == synced.observed.digest,
                "PQ_RECOVERY_PREPARED_CHANGED",
            )?;
            s.prepared_file = Some(synced.file);
            s.prepared = Some(readback);
            s.recheck_inner()?;
            #[cfg(test)]
            s.cut(Point::Prepared)?;
            Ok(())
        })
    }
    // The caller has fully audited every referenced blob and the exact bounded
    // state transition. This publishes metadata only; it never sends a request.
    pub fn publish(&mut self) -> Result<()> {
        self.guarded(|s| {
            let expected = s.prepared.clone().ok_or("PQ_RECOVERY_PREPARED")?;
            s.recheck_inner()?;
            s.prepared_file
                .as_ref()
                .ok_or("PQ_RECOVERY_PREPARED")?
                .sync_all()?;
            s.root.sync_all()?;
            s.recheck_inner()?;
            if s.current.is_none() {
                rfs::renameat_with(&s.root, PREPARED, &s.root, CURRENT, RenameFlags::NOREPLACE)
                    .map_err(io)?;
            } else {
                rfs::renameat(&s.root, PREPARED, &s.root, CURRENT).map_err(io)?;
            }
            s.root.sync_all()?;
            #[cfg(test)]
            s.cut(Point::Published)?;
            let (_, current) = s
                .read(CURRENT, MAX_METADATA)?
                .ok_or("PQ_RECOVERY_SNAPSHOT_MISSING")?;
            let held = s
                .prepared_file
                .as_ref()
                .ok_or("PQ_RECOVERY_PREPARED")?
                .metadata()?;
            ensure(
                identity(&held) == current.identity
                    && same_renamed_object(&expected.identity, &current.identity)
                    && current.digest == expected.digest
                    && s.read(PREPARED, MAX_METADATA)?.is_none(),
                "PQ_RECOVERY_PUBLISH_UNKNOWN",
            )?;
            s.check_owner()?;
            s.current = Some(current);
            s.prepared = None;
            s.prepared_file = None;
            s.recheck_inner()
        })
    }
    #[cfg(test)]
    fn cut(&mut self, point: Point) -> Result<()> {
        if let Some(callback) = self.callback.as_mut() {
            callback(point, &self.path)?;
        }
        if self.fail_at == Some(point) {
            self.fail_at = None;
            return Err(std::io::Error::other("injected post-fsync publication cut").into());
        }
        Ok(())
    }
}
