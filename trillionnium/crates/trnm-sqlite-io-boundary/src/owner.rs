use crate::ledger::{Code, Identity, Ledger, RootReceipt};
use crate::{BoundaryError, Result, DOMAIN, FILE_BYTES, OBJECTS_PER_ROOT, ROOT_COUNT};
use rusqlite::ffi;
use std::ffi::{CStr, CString, OsStr, OsString};
use std::fs::File;
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};
use std::ptr;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicPtr, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

static OWNER_CLAIMED: AtomicBool = AtomicBool::new(false);

pub(crate) struct Root {
    pub index: usize,
    pub directory: File,
    pub identity: Identity,
    pub pid: u32,
    pub uid: u32,
    pub prefix: CString,
    pub ledger: Mutex<Ledger>,
    pub reentrant_fault: AtomicBool,
    pub callback_panic_fault: AtomicBool,
    // Failure-only fixed ownership slots. Atomic publication permits a
    // same-thread rejected xClose to transfer actual state without waiting on
    // a mutex already held by the outer SQLite callback. Never dereferenced by
    // the receipt reader, automatically freed, retried or refunded.
    quarantined: [QuarantineSlot; OBJECTS_PER_ROOT * 32],
    pub cleanup_fault: AtomicBool,
}

struct QuarantineSlot {
    pointer: AtomicPtr<Mutex<crate::vfs::FileState>>,
    code: AtomicI32,
}

pub struct NativeIoOwner {
    roots: [Arc<Root>; ROOT_COUNT],
}

#[derive(Clone)]
pub struct NativeIoLease {
    pub(crate) registration: Arc<crate::vfs::Registration>,
}

impl NativeIoOwner {
    /// Create exactly seven fresh private roots. Existing directories are
    /// rejected; cold reopen uses a clone of this owner's existing lease.
    /// Ancestors are walked with O_DIRECTORY|O_NOFOLLOW and held throughout
    /// mkdir/open, so replacement of an absolute ancestor cannot redirect I/O.
    pub fn create(paths: [PathBuf; ROOT_COUNT]) -> Result<Self> {
        Self::create_roots(
            paths
                .into_iter()
                .enumerate()
                .map(|(index, path)| Root::create(&path, index)),
        )
    }
    /// Create seven fresh roots relative to consumed parent directory handles.
    /// Each name must be one nonempty basename, never a path. No parent path is
    /// recovered, canonicalized or reopened; rename of a parent cannot redirect
    /// the mkdir/open away from its held inode. The caller supplies the original
    /// capabilities and owns their provenance and all phase ancestor creation.
    /// Existing entries still fail. Cold reopen must retain the original lease.
    /// Both constructors consume the same one-owner claim, including on failure.
    pub fn create_at(parents: [(File, OsString); ROOT_COUNT]) -> Result<Self> {
        Self::create_roots(
            parents
                .into_iter()
                .enumerate()
                .map(|(index, (parent, name))| Root::create_at(parent, &name, index)),
        )
    }
    fn create_roots(pending: impl IntoIterator<Item = Result<Root>>) -> Result<Self> {
        // This is the seven-Node partition of one owned campaign process,
        // not an unlimited allocator of independent 336-MiB domains. A failed
        // claim also stays consumed; another campaign requires a fresh process.
        if OWNER_CLAIMED
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(BoundaryError(
                "one native I/O owner per process; claim already consumed".into(),
            ));
        }
        let mut roots = Vec::with_capacity(ROOT_COUNT);
        for pending_root in pending {
            let root = Arc::new(pending_root?);
            if roots
                .iter()
                .any(|old: &Arc<Root>| old.identity == root.identity)
            {
                return Err(BoundaryError("duplicate root inode".into()));
            }
            roots.push(root);
        }
        let roots = roots
            .try_into()
            .map_err(|_| BoundaryError("root count".into()))?;
        Ok(Self { roots })
    }
    pub fn lease(&self, index: usize) -> Result<NativeIoLease> {
        let root = self
            .roots
            .get(index)
            .ok_or_else(|| BoundaryError("root index".into()))?;
        root.check().map_err(code_error)?;
        Ok(NativeIoLease {
            registration: crate::vfs::Registration::new(root.clone())?,
        })
    }
    pub fn receipts(&self) -> Result<Vec<RootReceipt>> {
        self.roots.iter().map(|r| r.receipt()).collect()
    }
}

impl NativeIoLease {
    /// Registered name with process-lifetime storage, including after the last
    /// owner/lease is dropped. The name is not a security secret or capability.
    pub fn vfs_name(&self) -> &str {
        self.registration.name()
    }
    pub fn directory(&self) -> PathBuf {
        PathBuf::from(std::ffi::OsStr::from_bytes(
            self.registration.root.prefix.to_bytes(),
        ))
    }
    pub fn identity(&self) -> (u64, u64) {
        let id = self.registration.root.identity;
        (id.dev, id.ino)
    }
    pub fn receipt(&self) -> Result<RootReceipt> {
        self.registration.root.receipt()
    }
    pub fn check(&self) -> Result<()> {
        self.registration.root.check().map_err(code_error)
    }
    pub(crate) fn connection_admission(&self) -> Result<()> {
        let mut ledger = self.registration.root.lock().map_err(code_error)?;
        ledger.admission().map_err(code_error)
    }
}

pub(crate) fn code_error(code: i32) -> BoundaryError {
    BoundaryError(format!("SQLite boundary error {code}"))
}

impl Root {
    fn create(path: &Path, index: usize) -> Result<Self> {
        if !path.is_absolute() {
            return Err(BoundaryError("absolute fresh root required".into()));
        }
        let parent = path
            .parent()
            .ok_or_else(|| BoundaryError("root parent".into()))?;
        let leaf = path
            .file_name()
            .ok_or_else(|| BoundaryError("root basename".into()))?;
        let parent_fd = walk_directory(parent)?;
        Self::create_at(parent_fd, leaf, index)
    }
    fn create_at(parent_fd: File, leaf: &OsStr, index: usize) -> Result<Self> {
        // Inspect the actual consumed handle before any namespace mutation.
        // Holding this File, rather than its former pathname, anchors both
        // operations to the same directory even after a rename/replacement.
        let parent_stat = stat_fd(parent_fd.as_raw_fd()).map_err(code_error)?;
        if parent_stat.st_mode & libc::S_IFMT != libc::S_IFDIR {
            return Err(BoundaryError("held root parent is not a directory".into()));
        }
        let bytes = leaf.as_bytes();
        if bytes.is_empty()
            || bytes == b"."
            || bytes == b".."
            || bytes.contains(&b'/')
            || bytes.contains(&0)
        {
            return Err(BoundaryError("one normal root basename required".into()));
        }
        let name = CString::new(bytes).map_err(|_| BoundaryError("root NUL".into()))?;
        // SAFETY: owned directory and NUL-terminated one-component name.
        if unsafe { libc::mkdirat(parent_fd.as_raw_fd(), name.as_ptr(), 0o700) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        // Do not remove a successfully created earlier root on later failure:
        // its existence is retained evidence, and a failed owner is not reused.
        let fd = unsafe {
            libc::openat(
                parent_fd.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let directory = unsafe { File::from_raw_fd(fd) };
        let parent_after = stat_fd(parent_fd.as_raw_fd()).map_err(code_error)?;
        if identity(&parent_after) != identity(&parent_stat)
            || parent_after.st_mode & libc::S_IFMT != libc::S_IFDIR
        {
            return Err(BoundaryError("held root parent identity changed".into()));
        }
        let stat = stat_fd(fd).map_err(code_error)?;
        let uid = unsafe { libc::geteuid() };
        if stat.st_mode & libc::S_IFMT != libc::S_IFDIR
            || stat.st_uid != uid
            || stat.st_mode & 0o077 != 0
        {
            return Err(BoundaryError("fresh root ownership/mode".into()));
        }
        Ok(Self {
            index,
            directory,
            identity: identity(&stat),
            pid: std::process::id(),
            uid,
            prefix: CString::new(format!("/proc/self/fd/{fd}")).expect("numeric path"),
            ledger: Mutex::new(Ledger::new()),
            reentrant_fault: AtomicBool::new(false),
            callback_panic_fault: AtomicBool::new(false),
            quarantined: std::array::from_fn(|_| QuarantineSlot {
                pointer: AtomicPtr::new(ptr::null_mut()),
                code: AtomicI32::new(0),
            }),
            cleanup_fault: AtomicBool::new(false),
        })
    }
    pub fn check(&self) -> Code<()> {
        if std::process::id() != self.pid {
            return Err(ffi::SQLITE_IOERR);
        }
        let stat = stat_fd(self.directory.as_raw_fd())?;
        if identity(&stat) != self.identity
            || stat.st_uid != self.uid
            || stat.st_mode & libc::S_IFMT != libc::S_IFDIR
            || stat.st_mode & 0o077 != 0
        {
            return Err(ffi::SQLITE_IOERR);
        }
        Ok(())
    }
    pub fn lock(&self) -> Code<MutexGuard<'_, Ledger>> {
        let mut guard = self.cleanup_lock()?;
        if let Err(code) = self.check() {
            return guard.fail("held root identity/ownership/fstat fence", code);
        }
        Ok(guard)
    }
    pub fn cleanup_lock(&self) -> Code<MutexGuard<'_, Ledger>> {
        if std::process::id() != self.pid {
            return Err(ffi::SQLITE_IOERR);
        }
        // Independent connections may legitimately close while another one
        // writes. Wait for the owner gate; never discard their actual close
        // because try_lock happened to report contention. TLS at the ABI
        // boundary rejects same-thread callback reentrancy before this point.
        let mut guard = match self.ledger.lock() {
            Ok(guard) => guard,
            Err(poison) => {
                let mut guard = poison.into_inner();
                let _: Code<()> =
                    guard.fail("owner callback panic poisoned ledger", ffi::SQLITE_IOERR);
                guard
            }
        };
        if self.cleanup_fault.load(Ordering::Acquire) {
            let _: Code<()> = guard.fail(
                "actual lower state quarantined; owned process terminal required",
                ffi::SQLITE_IOERR_CLOSE,
            );
        }
        if self.reentrant_fault.load(Ordering::Acquire) {
            let _: Code<()> = guard.fail(
                "same-thread VFS callback reentrancy refused",
                ffi::SQLITE_IOERR,
            );
        }
        if self.callback_panic_fault.load(Ordering::Acquire) {
            let _: Code<()> =
                guard.fail("VFS callback panic caught at C boundary", ffi::SQLITE_IOERR);
        }
        if let Err(code) = self.check() {
            let _: Code<()> = guard.fail("cleanup retained after held root failure", code);
        }
        Ok(guard)
    }
    pub fn path(&self, leaf: &str) -> Code<CString> {
        if leaf.is_empty()
            || leaf.len() > 96
            || leaf.contains('/')
            || leaf.contains('\0')
            || leaf == "."
            || leaf == ".."
        {
            return Err(ffi::SQLITE_CANTOPEN);
        }
        CString::new(format!("{}/{leaf}", self.prefix.to_string_lossy()))
            .map_err(|_| ffi::SQLITE_CANTOPEN)
    }
    pub fn leaf<'a>(&self, path: &'a CStr) -> Code<&'a str> {
        let path = path.to_str().map_err(|_| ffi::SQLITE_CANTOPEN)?;
        let prefix = self.prefix.to_str().map_err(|_| ffi::SQLITE_CANTOPEN)?;
        let leaf = path
            .strip_prefix(prefix)
            .and_then(|x| x.strip_prefix('/'))
            .ok_or(ffi::SQLITE_CANTOPEN)?;
        self.path(leaf)?;
        if leaf.contains('?') || leaf.contains('#') || leaf.starts_with("file:") {
            return Err(ffi::SQLITE_CANTOPEN);
        }
        Ok(leaf)
    }
    pub fn stat_name(&self, name: &str) -> Code<Option<libc::stat>> {
        let name = CString::new(name).map_err(|_| ffi::SQLITE_CANTOPEN)?;
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        let rc = unsafe {
            libc::fstatat(
                self.directory.as_raw_fd(),
                name.as_ptr(),
                stat.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if rc != 0 {
            return if std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
                Ok(None)
            } else {
                Err(ffi::SQLITE_IOERR_FSTAT)
            };
        }
        let stat = unsafe { stat.assume_init() };
        validate_regular(self, &stat)?;
        Ok(Some(stat))
    }
    pub fn bind_fd(&self, ledger: &mut Ledger, slot: usize, fd: RawFd) -> Code<()> {
        let stat = stat_fd(fd)?;
        validate_regular(self, &stat)?;
        let name = ledger.slots[slot]
            .as_ref()
            .ok_or(ffi::SQLITE_IOERR)?
            .receipt
            .basename
            .clone();
        let linked = stat.st_nlink != 0;
        if linked {
            let named = self.stat_name(&name)?.ok_or(ffi::SQLITE_IOERR)?;
            if identity(&named) != identity(&stat) {
                return ledger.fail("actual fd/held root inode mismatch", ffi::SQLITE_IOERR);
            }
        }
        ledger.bind(
            slot,
            identity(&stat),
            u64::try_from(stat.st_size).map_err(|_| ffi::SQLITE_IOERR_FSTAT)?,
            u64::try_from(stat.st_blocks).map_err(|_| ffi::SQLITE_IOERR_FSTAT)?,
            linked,
        )
    }
    pub fn receipt(&self) -> Result<RootReceipt> {
        let ledger = self.cleanup_lock().map_err(code_error)?;
        let mut quarantined = 0;
        let mut quarantined_sqlite_codes = Vec::new();
        let mut quarantine_entries_complete = true;
        for slot in &self.quarantined {
            let pointer = slot.pointer.load(Ordering::Acquire);
            if pointer.is_null() {
                continue;
            }
            quarantined += 1;
            if pointer as usize == 1 {
                quarantine_entries_complete = false;
                quarantined_sqlite_codes.push(ffi::SQLITE_IOERR_CLOSE);
            } else {
                quarantined_sqlite_codes.push(slot.code.load(Ordering::Acquire));
            }
        }
        Ok(RootReceipt {
            schema: DOMAIN,
            owner_pid: self.pid,
            root_device: self.identity.dev,
            root_inode: self.identity.ino,
            logical_bytes_limit: FILE_BYTES * OBJECTS_PER_ROOT as u64,
            retained_object_limit: OBJECTS_PER_ROOT,
            high_water_sum: ledger
                .slots
                .iter()
                .flatten()
                .map(|o| o.receipt.high_water_bytes)
                .sum(),
            retained_logical_bytes_peak: ledger.retained_logical_bytes_peak,
            retained_objects_peak: ledger.retained_objects_peak,
            objects: ledger
                .slots
                .iter()
                .flatten()
                .map(|o| o.receipt.clone())
                .collect(),
            failed: ledger.failed.is_some(),
            first_failure: ledger.failed.clone(),
            first_failure_sqlite_code: ledger.first_failure_code,
            secondary_failures: ledger.secondary_failures.clone(),
            secondary_failures_complete: ledger.secondary_failures_complete,
            callback_operations: ledger.operations,
            denied_operations: ledger.denied,
            allocated_blocks_hard_cap_implemented: false,
            lifecycle: ledger.lifecycle.clone(),
            cleanup_lifecycle: ledger.cleanup.clone(),
            lifecycle_complete: ledger.lifecycle_complete,
            lifecycle_serialized_bytes: ledger.lifecycle_bytes,
            lifecycle_serialized_bytes_cap: (1024 + 256) * 512,
            quarantined_actual_states: quarantined,
            quarantined_sqlite_codes,
            quarantine_entries_complete,
        })
    }
    pub fn quarantine(
        &self,
        state: Box<Mutex<crate::vfs::FileState>>,
        code: i32,
        ledger: &mut Ledger,
    ) {
        let pointer = Box::into_raw(state);
        if !unsafe { self.quarantine_raw(pointer, code) } {
            ledger.lifecycle_complete = false;
            let _: Code<()> = ledger.fail(
                "quarantine ownership invariant violated; no qualification possible",
                ffi::SQLITE_IOERR_CLOSE,
            );
            // No unconfirmed lower allocation is freed or refunded. The
            // admitted actual+pending open count makes this branch unreachable.
        }
    }
    /// Transfer one unique Box allocation; caller must relinquish ownership and
    /// must not close/free it after successful publication. A fixed reservation
    /// marker is never dereferenced; unknown/pending publication is NO_GO.
    pub unsafe fn quarantine_raw(
        &self,
        state: *mut Mutex<crate::vfs::FileState>,
        code: i32,
    ) -> bool {
        self.cleanup_fault.store(true, Ordering::Release);
        if state.is_null() {
            return false;
        }
        let reserved = ptr::without_provenance_mut(1);
        for slot in &self.quarantined {
            if slot
                .pointer
                .compare_exchange(
                    ptr::null_mut(),
                    reserved,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
            {
                slot.code.store(code, Ordering::Relaxed);
                slot.pointer.store(state, Ordering::Release);
                return true;
            }
        }
        false
    }
}

fn walk_directory(path: &Path) -> Result<File> {
    let start = CString::new("/").expect("constant");
    let fd = unsafe {
        libc::open(
            start.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let mut held = unsafe { File::from_raw_fd(fd) };
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(name) => {
                let name = CString::new(name.as_bytes())
                    .map_err(|_| BoundaryError("ancestor NUL".into()))?;
                let fd = unsafe {
                    libc::openat(
                        held.as_raw_fd(),
                        name.as_ptr(),
                        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                    )
                };
                if fd < 0 {
                    return Err(std::io::Error::last_os_error().into());
                }
                held = unsafe { File::from_raw_fd(fd) };
            }
            _ => return Err(BoundaryError("non-normal ancestor".into())),
        }
    }
    Ok(held)
}
pub(crate) fn stat_fd(fd: RawFd) -> Code<libc::stat> {
    let mut stat = std::mem::MaybeUninit::uninit();
    if fd < 0 || unsafe { libc::fstat(fd, stat.as_mut_ptr()) } != 0 {
        return Err(ffi::SQLITE_IOERR_FSTAT);
    }
    Ok(unsafe { stat.assume_init() })
}
pub(crate) fn identity(stat: &libc::stat) -> Identity {
    Identity {
        dev: stat.st_dev,
        ino: stat.st_ino,
    }
}
fn validate_regular(root: &Root, stat: &libc::stat) -> Code<()> {
    if stat.st_mode & libc::S_IFMT != libc::S_IFREG
        || stat.st_uid != root.uid
        || stat.st_nlink > 1
        || stat.st_size < 0
    {
        return Err(ffi::SQLITE_IOERR_FSTAT);
    }
    Ok(())
}
