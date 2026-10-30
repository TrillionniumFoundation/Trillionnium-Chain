//! C callbacks are confined to this crate. No callback unwinds into SQLite.
use crate::ledger::{Code, Ledger, RootReceipt};
use crate::owner::Root;
use crate::{unix_abi, BoundaryError, Result, FILE_BYTES, ROOT_COUNT};
use rusqlite::ffi;
use std::cell::{Cell, UnsafeCell};
use std::ffi::{c_char, c_int, c_void, CStr, CString};
use std::mem::size_of;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;
use std::sync::atomic::{AtomicI32, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

// A safe foreign SQLite memory connection can retain pVfs without opening any
// wrapped file. Therefore registration/root/name lifetime is process-wide,
// independently of every lease and file Arc. Exactly seven fixed owner roots
// exist; no successful, failed or partly published slot is ever cleared.
static REGISTRATIONS: [Mutex<Option<Arc<Registration>>>; ROOT_COUNT] =
    [const { Mutex::new(None) }; ROOT_COUNT];
// Read before taking a possibly fork-inherited mutex. A child process cannot
// snapshot/reuse its parent's registration even when the public name is known.
static REGISTRATION_OWNER_PID: AtomicU32 = AtomicU32::new(0);
thread_local! {
    static IN_CALLBACK: Cell<bool> = const { Cell::new(false) };
    static ACTIVE_ROOT: Cell<*const Root> = const { Cell::new(ptr::null()) };
}

pub(crate) struct Registration {
    pub root: Arc<Root>,
    base: *mut ffi::sqlite3_vfs,
    name: CString,
    vfs: UnsafeCell<ffi::sqlite3_vfs>,
    registration_code: AtomicI32,
}
// The VFS shape is immutable after registration. Its process-owned Root mutex
// serializes all delegated I/O and ledger mutations. Foreign VFS mutation is
// explicitly outside this factory's admitted trusted-host contract.
unsafe impl Send for Registration {}
unsafe impl Sync for Registration {}

impl Registration {
    pub fn new(root: Arc<Root>) -> Result<Arc<Self>> {
        root.check().map_err(crate::owner::code_error)?;
        match REGISTRATION_OWNER_PID.compare_exchange(
            0,
            root.pid,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => {}
            Err(pid) if pid == root.pid => {}
            Err(_) => {
                return Err(BoundaryError(
                    "registration owner PID cannot be rebound".into(),
                ))
            }
        }
        let slot = REGISTRATIONS
            .get(root.index)
            .ok_or_else(|| BoundaryError("permanent registration root index".into()))?;
        let mut slot = slot.lock().map_err(|_| {
            BoundaryError("permanent registration publication poisoned; no retry".into())
        })?;
        if let Some(existing) = slot.as_ref() {
            if !Arc::ptr_eq(&existing.root, &root) {
                return Err(BoundaryError(
                    "permanent root registration cannot be rebound".into(),
                ));
            }
            let code = existing.registration_code.load(Ordering::Acquire);
            if code != ffi::SQLITE_OK {
                return Err(BoundaryError(format!("earlier VFS publication failed or remained uncertain ({code}); permanent object retained, no retry")));
            }
            return Ok(existing.clone());
        }
        root.check().map_err(crate::owner::code_error)?;
        let base = unsafe { ffi::sqlite3_vfs_find(c"unix".as_ptr()) };
        unix_abi::validate_base(base).map_err(BoundaryError)?;
        let version = root
            .lock()
            .map_err(crate::owner::code_error)?
            .policy()
            .vfs_version();
        let name = CString::new(format!(
            "trnm-pn1-owned-inode-{}-{}-{}",
            version,
            root.pid,
            root.index + 1,
        ))
        .expect("numeric name");
        // Copy only to construct the wrapper. Every delegated callback receives
        // the ORIGINAL base pointer, never this copy's replacement pAppData.
        let mut shape = unsafe { *base };
        shape.szOsFile = c_int::try_from(size_of::<Outer>())
            .map_err(|_| BoundaryError("outer ABI size".into()))?;
        shape.mxPathname = 512;
        shape.pNext = ptr::null_mut();
        shape.zName = name.as_ptr();
        shape.xOpen = Some(open);
        shape.xDelete = Some(delete);
        shape.xAccess = Some(access);
        shape.xFullPathname = Some(full_pathname);
        shape.xDlOpen = Some(dl_open);
        shape.xDlError = Some(dl_error);
        shape.xDlSym = None;
        shape.xDlClose = None;
        shape.xRandomness = Some(randomness);
        shape.xSleep = Some(sleep);
        shape.xCurrentTime = Some(current_time);
        shape.xGetLastError = Some(last_error);
        shape.xCurrentTimeInt64 = Some(current_time_int64);
        // No system-call replacement or introspection of the global Unix table.
        shape.xSetSystemCall = None;
        shape.xGetSystemCall = None;
        shape.xNextSystemCall = None;
        let registration = Arc::new(Self {
            root,
            base,
            name,
            vfs: UnsafeCell::new(shape),
            registration_code: AtomicI32::new(-1),
        });
        unsafe {
            (*registration.vfs.get()).pAppData = Arc::as_ptr(&registration).cast_mut().cast();
        }
        // Install the permanent real Arc BEFORE the first C publication. Even
        // a concurrent safe foreign memory open or a partial/error publication
        // cannot observe an object whose final lease later frees its pVfs.
        *slot = Some(registration.clone());
        let rc = unsafe { ffi::sqlite3_vfs_register(registration.vfs.get(), 0) };
        registration.registration_code.store(rc, Ordering::Release);
        if rc != ffi::SQLITE_OK {
            return Err(BoundaryError(format!("VFS registration {rc}")));
        }
        Ok(registration)
    }
    pub fn name(&self) -> &str {
        self.name.to_str().expect("ASCII VFS name")
    }
}
/// Owned snapshot of the exact permanently registered domain. This does not
/// create a lease, publish/register anything, reset a failure, or change quota.
pub fn registered_receipt(vfs_name: &str) -> Result<RootReceipt> {
    if vfs_name.is_empty() || vfs_name.len() > 128 {
        return Err(BoundaryError("registered VFS name length".into()));
    }
    if REGISTRATION_OWNER_PID.load(Ordering::Acquire) != std::process::id() {
        return Err(BoundaryError("registered VFS owner PID/absence".into()));
    }
    for slot in &REGISTRATIONS {
        let selected = {
            let slot = slot
                .lock()
                .map_err(|_| BoundaryError("permanent registration publication poisoned".into()))?;
            slot.as_ref().filter(|r| r.name() == vfs_name).cloned()
        };
        if let Some(registration) = selected {
            if registration.root.pid != std::process::id()
                || registration.registration_code.load(Ordering::Acquire) != ffi::SQLITE_OK
            {
                return Err(BoundaryError(
                    "registered VFS is not ready in this PID".into(),
                ));
            }
            return registration.root.receipt();
        }
    }
    Err(BoundaryError("unknown registered VFS name".into()))
}

// No unregister/drop cleanup for a published registration: SQLite's safe
// foreign memory connections do not participate in this crate's Arc ownership.
// REGISTRATIONS retains at most seven real VFS/root allocations until process
// termination, within the existing seven-root/held-directory partition.

#[repr(C)]
struct Outer {
    public: ffi::sqlite3_file,
    state: *mut Mutex<FileState>,
    root: *const Root,
}
pub(crate) struct FileState {
    registration: Arc<Registration>,
    inner: *mut ffi::sqlite3_file,
    filename_owner: ffi::sqlite3_filename,
    slot: usize,
    main: bool,
    shm_slot: Option<usize>,
}
unsafe impl Send for FileState {}

fn boundary(body: impl FnOnce() -> Code<c_int>) -> c_int {
    IN_CALLBACK.with(|cell| {
        if cell.replace(true) {
            ACTIVE_ROOT.with(|active| {
                let root = active.get();
                if !root.is_null() {
                    unsafe {
                        (*root).reentrant_fault.store(true, Ordering::Release);
                    }
                }
            });
            return ffi::SQLITE_IOERR;
        }
        struct Reset<'a>(&'a Cell<bool>);
        impl Drop for Reset<'_> {
            fn drop(&mut self) {
                ACTIVE_ROOT.with(|active| active.set(ptr::null()));
                self.0.set(false);
            }
        }
        let _reset = Reset(cell);
        match catch_unwind(AssertUnwindSafe(body)) {
            Ok(Ok(code)) => code,
            Ok(Err(code)) => code,
            Err(_) => {
                ACTIVE_ROOT.with(|active| {
                    let root = active.get();
                    if !root.is_null() {
                        unsafe {
                            (*root).callback_panic_fault.store(true, Ordering::Release);
                        }
                    }
                });
                ffi::SQLITE_IOERR
            }
        }
    })
}
unsafe fn latch_vfs(vfs: *mut ffi::sqlite3_vfs, code: c_int, expected: &[c_int]) -> c_int {
    if code == ffi::SQLITE_OK || expected.contains(&code) {
        return code;
    }
    // A rejected nested callback is already latched through ACTIVE_ROOT's
    // atomic flag. Waiting on its outer callback's ledger would deadlock.
    if IN_CALLBACK.with(Cell::get) {
        return code;
    }
    // The VFS registration is kept alive by the opening connection/lease.
    // Do not call registration(), which itself may be the failed fence.
    if !vfs.is_null() {
        let context = unsafe { (*vfs).pAppData.cast::<Registration>() };
        if !context.is_null() {
            let root = unsafe { &(*context).root };
            if let Ok(mut ledger) = root.cleanup_lock() {
                let _: Code<()> =
                    ledger.fail("VFS callback failed; exact original code retained", code);
            }
        }
    }
    code
}
unsafe fn quarantine_close(
    outer: *mut Outer,
    state: *mut Mutex<FileState>,
    root: &Root,
    ledger: &mut Ledger,
    why: &str,
    code: c_int,
) -> Code<c_int> {
    let _: Code<()> = ledger.fail(why, code);
    // SQLite may free Outer after ANY xClose result. Transfer actual ownership
    // out of Outer before returning; no later SQLite retry is assumed.
    unsafe {
        (*outer).state = ptr::null_mut();
        (*outer).public.pMethods = ptr::null();
    }
    root.quarantine(unsafe { Box::from_raw(state) }, code, ledger);
    Err(code)
}
unsafe fn dispose_unpublished(
    registration: Arc<Registration>,
    inner: *mut ffi::sqlite3_file,
    filename: ffi::sqlite3_filename,
    slot: usize,
    main: bool,
    ledger: &mut Ledger,
) {
    let pending = ledger.slots[slot]
        .as_ref()
        .is_some_and(|o| o.receipt.pending_opens != 0);
    let rc = match unsafe { methods(inner) } {
        Ok(table) => match table.xClose {
            Some(close) => unsafe { close(inner) },
            None => ffi::SQLITE_IOERR_CLOSE,
        },
        Err(code) => code,
    };
    if rc == ffi::SQLITE_OK {
        if pending {
            ledger.release_pending(slot, "unpublished-actual-close");
        } else {
            ledger.close_handle(slot);
        }
        unsafe {
            ffi::sqlite3_free(inner.cast());
            ffi::sqlite3_free_filename(filename);
        }
    } else {
        let _: Code<()> = ledger.fail(
            "unpublished lower close unconfirmed; actual allocation retained",
            rc,
        );
        let root = registration.root.clone();
        root.quarantine(
            Box::new(Mutex::new(FileState {
                registration,
                inner,
                filename_owner: filename,
                slot,
                main,
                shm_slot: None,
            })),
            rc,
            ledger,
        );
    }
}
unsafe fn registration<'a>(vfs: *mut ffi::sqlite3_vfs) -> Code<&'a Registration> {
    if vfs.is_null() {
        return Err(ffi::SQLITE_IOERR);
    }
    let context = unsafe { (*vfs).pAppData.cast::<Registration>() };
    if context.is_null() {
        return Err(ffi::SQLITE_IOERR);
    }
    let context = unsafe { &*context };
    ACTIVE_ROOT.with(|active| active.set(Arc::as_ptr(&context.root)));
    context.root.check()?;
    unix_abi::validate_base(context.base).map_err(|_| ffi::SQLITE_IOERR)?;
    Ok(context)
}
unsafe fn clone_registration(vfs: *mut ffi::sqlite3_vfs) -> Code<Arc<Registration>> {
    let reference = unsafe { registration(vfs)? };
    let pointer = reference as *const Registration;
    unsafe {
        Arc::increment_strong_count(pointer);
    }
    Ok(unsafe { Arc::from_raw(pointer) })
}
unsafe fn methods(inner: *mut ffi::sqlite3_file) -> Code<&'static ffi::sqlite3_io_methods> {
    if inner.is_null() {
        return Err(ffi::SQLITE_IOERR);
    }
    let pointer = unsafe { (*inner).pMethods };
    if pointer.is_null() {
        return Err(ffi::SQLITE_IOERR);
    }
    Ok(unsafe { &*pointer })
}
unsafe fn with_file(
    file: *mut ffi::sqlite3_file,
    body: impl FnOnce(&mut FileState, &mut Ledger) -> Code<c_int>,
) -> Code<c_int> {
    if file.is_null() {
        return Err(ffi::SQLITE_IOERR);
    }
    let state = unsafe { (*file.cast::<Outer>()).state };
    if state.is_null() {
        return Err(ffi::SQLITE_IOERR);
    }
    let (mut state, poisoned) = match unsafe { &*state }.lock() {
        Ok(guard) => (guard, false),
        Err(poison) => (poison.into_inner(), true),
    };
    let root = state.registration.root.clone();
    ACTIVE_ROOT.with(|active| active.set(Arc::as_ptr(&root)));
    let mut ledger = root.lock()?;
    if poisoned {
        let _: Code<()> = ledger.fail("file callback panic poisoned state", ffi::SQLITE_IOERR);
    }
    if unix_abi::validate_base(state.registration.base).is_err() {
        return ledger.fail("actual base VFS qualification changed", ffi::SQLITE_IOERR);
    }
    let outcome = body(&mut state, &mut ledger);
    if root.reentrant_fault.load(Ordering::Acquire)
        || root.callback_panic_fault.load(Ordering::Acquire)
    {
        let _: Code<()> = ledger.fail("nested callback/panic fault latched", ffi::SQLITE_IOERR);
        if let Err(code) = outcome {
            ledger.observe_secondary("nested callback/panic fault", ffi::SQLITE_IOERR);
            return Err(code);
        }
        return Err(ffi::SQLITE_IOERR);
    }
    match outcome {
        Ok(code) => Ok(code),
        Err(code) => ledger.fail("wrapper callback refused; original code retained", code),
    }
}
fn endpoint(amount: c_int, offset: i64) -> Code<u64> {
    let amount = u64::try_from(amount).map_err(|_| ffi::SQLITE_IOERR_WRITE)?;
    let offset = u64::try_from(offset).map_err(|_| ffi::SQLITE_IOERR_WRITE)?;
    offset.checked_add(amount).ok_or(ffi::SQLITE_FULL)
}
fn recognized(name: &str) -> bool {
    matches!(
        name,
        "native.sqlite" | "native.sqlite-journal" | "native.sqlite-wal" | "native.sqlite-shm"
    ) || name.starts_with("trnm-temp-")
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}
fn kind(flags: c_int) -> c_int {
    flags
        & (ffi::SQLITE_OPEN_MAIN_DB
            | ffi::SQLITE_OPEN_MAIN_JOURNAL
            | ffi::SQLITE_OPEN_WAL
            | ffi::SQLITE_OPEN_TEMP_DB
            | ffi::SQLITE_OPEN_TEMP_JOURNAL
            | ffi::SQLITE_OPEN_SUBJOURNAL
            | ffi::SQLITE_OPEN_TRANSIENT_DB
            | ffi::SQLITE_OPEN_SUPER_JOURNAL)
}

unsafe extern "C" fn open(
    vfs: *mut ffi::sqlite3_vfs,
    supplied: ffi::sqlite3_filename,
    output: *mut ffi::sqlite3_file,
    flags: c_int,
    out_flags: *mut c_int,
) -> c_int {
    if output.is_null() {
        return ffi::SQLITE_CANTOPEN;
    }
    unsafe {
        ptr::write(
            output.cast::<Outer>(),
            Outer {
                public: ffi::sqlite3_file {
                    pMethods: ptr::null(),
                },
                state: ptr::null_mut(),
                root: ptr::null(),
            },
        );
    }
    let code = boundary(|| unsafe {
        let registration = clone_registration(vfs)?;
        let root = registration.root.clone();
        let mut ledger = root.lock()?;
        let file_kind = kind(flags);
        if flags
            & (ffi::SQLITE_OPEN_AUTOPROXY | ffi::SQLITE_OPEN_MEMORY | ffi::SQLITE_OPEN_SHAREDCACHE)
            != 0
            || !matches!(
                file_kind,
                ffi::SQLITE_OPEN_MAIN_DB
                    | ffi::SQLITE_OPEN_MAIN_JOURNAL
                    | ffi::SQLITE_OPEN_WAL
                    | ffi::SQLITE_OPEN_TEMP_DB
                    | ffi::SQLITE_OPEN_TEMP_JOURNAL
                    | ffi::SQLITE_OPEN_SUBJOURNAL
                    | ffi::SQLITE_OPEN_TRANSIENT_DB
            )
        {
            return ledger.fail("unsupported SQLite open flags/kind", ffi::SQLITE_CANTOPEN);
        }
        let main = file_kind == ffi::SQLITE_OPEN_MAIN_DB;
        let leaf = if supplied.is_null() {
            if main
                || flags
                    & (ffi::SQLITE_OPEN_DELETEONCLOSE
                        | ffi::SQLITE_OPEN_CREATE
                        | ffi::SQLITE_OPEN_EXCLUSIVE)
                    != ffi::SQLITE_OPEN_DELETEONCLOSE
                        | ffi::SQLITE_OPEN_CREATE
                        | ffi::SQLITE_OPEN_EXCLUSIVE
            {
                return ledger.fail(
                    "NULL file without original exclusive temporary lifecycle",
                    ffi::SQLITE_CANTOPEN,
                );
            }
            ledger.next_temp = ledger.next_temp.checked_add(1).ok_or(ffi::SQLITE_FULL)?;
            format!("trnm-temp-{}-{}", root.pid, ledger.next_temp)
        } else {
            root.leaf(CStr::from_ptr(supplied))?.to_owned()
        };
        let paired = (main && leaf == "native.sqlite")
            || (file_kind == ffi::SQLITE_OPEN_MAIN_JOURNAL && leaf == "native.sqlite-journal")
            || (file_kind == ffi::SQLITE_OPEN_WAL && leaf == "native.sqlite-wal")
            || (!main
                && file_kind != ffi::SQLITE_OPEN_MAIN_JOURNAL
                && file_kind != ffi::SQLITE_OPEN_WAL
                && leaf.starts_with("trnm-temp-"));
        if !paired || !recognized(&leaf) {
            return ledger.fail("file kind/name mismatch", ffi::SQLITE_CANTOPEN);
        }
        let slot = ledger.reserve_open(&leaf, main)?;
        if let Some(stat) = root.stat_name(&leaf)? {
            ledger.observe_existing_before_io(
                slot,
                crate::owner::identity(&stat),
                u64::try_from(stat.st_size).map_err(|_| ffi::SQLITE_IOERR_FSTAT)?,
                u64::try_from(stat.st_blocks).map_err(|_| ffi::SQLITE_IOERR_FSTAT)?,
                true,
            )?;
        }
        // SQLite's filename helpers require their own extended allocation,
        // not a temporary CString masquerading as sqlite3_filename.
        let db = root.path(
            if main
                || file_kind == ffi::SQLITE_OPEN_MAIN_JOURNAL
                || file_kind == ffi::SQLITE_OPEN_WAL
            {
                "native.sqlite"
            } else {
                &leaf
            },
        )?;
        let journal = root.path(if file_kind == ffi::SQLITE_OPEN_MAIN_JOURNAL {
            &leaf
        } else {
            "native.sqlite-journal"
        })?;
        let wal = root.path("native.sqlite-wal")?;
        let filename = ffi::sqlite3_create_filename(
            db.as_ptr(),
            journal.as_ptr(),
            wal.as_ptr(),
            0,
            ptr::null_mut(),
        );
        if filename.is_null() {
            return ledger.fail("filename allocation", ffi::SQLITE_NOMEM);
        }
        let selected = if file_kind == ffi::SQLITE_OPEN_MAIN_JOURNAL {
            ffi::sqlite3_filename_journal(filename)
        } else if file_kind == ffi::SQLITE_OPEN_WAL {
            ffi::sqlite3_filename_wal(filename)
        } else {
            filename
        };
        let inner = ffi::sqlite3_malloc64(
            u64::try_from((*registration.base).szOsFile).map_err(|_| ffi::SQLITE_NOMEM)?,
        )
        .cast::<ffi::sqlite3_file>();
        if inner.is_null() {
            ffi::sqlite3_free_filename(filename);
            return ledger.fail("inner allocation", ffi::SQLITE_NOMEM);
        }
        ptr::write_bytes(
            inner.cast::<u8>(),
            0,
            (*registration.base).szOsFile as usize,
        );
        if let Err(code) = ledger.reserve_handle(slot) {
            ffi::sqlite3_free(inner.cast());
            ffi::sqlite3_free_filename(filename);
            return Err(code);
        }
        let rc = (*registration.base).xOpen.ok_or(ffi::SQLITE_CANTOPEN)?(
            registration.base,
            selected,
            inner,
            flags,
            out_flags,
        );
        if rc != ffi::SQLITE_OK {
            let _: Code<()> = ledger.fail("base xOpen failed; pending reservation retained", rc);
            if (*inner).pMethods.is_null() {
                // The SQLite xOpen contract says no xClose is required in this
                // case; retain uncertain inode reservation, release only the
                // uncreated handle reservation, and free non-file allocations.
                ledger.release_pending(slot, "failed-open-no-methods");
                ffi::sqlite3_free(inner.cast());
                ffi::sqlite3_free_filename(filename);
            } else {
                dispose_unpublished(
                    registration.clone(),
                    inner,
                    filename,
                    slot,
                    main,
                    &mut ledger,
                );
            }
            return Err(rc);
        }
        let initialized = (|| {
            if methods(inner)?.iVersion < 3 {
                return Err(ffi::SQLITE_IOERR);
            }
            let fd = unix_abi::main_fd(inner, registration.base)?;
            root.bind_fd(&mut ledger, slot, fd)?;
            ledger.opened(slot)?;
            Ok(())
        })();
        if let Err(code) = initialized {
            let _: Code<()> = ledger.fail("actual opened fd identity/ABI admission failed", code);
            dispose_unpublished(
                registration.clone(),
                inner,
                filename,
                slot,
                main,
                &mut ledger,
            );
            return Err(code);
        }
        let state = Box::new(Mutex::new(FileState {
            registration,
            inner,
            filename_owner: filename,
            slot,
            main,
            shm_slot: None,
        }));
        (*output.cast::<Outer>()).root = Arc::as_ptr(&root);
        (*output.cast::<Outer>()).state = Box::into_raw(state);
        (*output).pMethods = &IO_METHODS;
        Ok(ffi::SQLITE_OK)
    });
    unsafe { latch_vfs(vfs, code, &[]) }
}

unsafe extern "C" fn close(file: *mut ffi::sqlite3_file) -> c_int {
    if IN_CALLBACK.with(Cell::get) {
        ACTIVE_ROOT.with(|active| {
            let root = active.get();
            if !root.is_null() {
                unsafe {
                    (*root).reentrant_fault.store(true, Ordering::Release);
                }
            }
        });
        // SQLite may free this outer allocation after the refused close.
        // Transfer the actual Box to a fixed atomic owner without acquiring
        // either the file or root mutex held by the outer callback.
        if !file.is_null() {
            unsafe {
                let outer = file.cast::<Outer>();
                let root = (*outer).root;
                if !root.is_null() {
                    (*root).reentrant_fault.store(true, Ordering::Release);
                    let state = ptr::replace(ptr::addr_of_mut!((*outer).state), ptr::null_mut());
                    (*file).pMethods = ptr::null();
                    if !state.is_null() {
                        (*root).quarantine_raw(state, ffi::SQLITE_IOERR_CLOSE);
                    }
                }
            }
        }
        return ffi::SQLITE_IOERR_CLOSE;
    }
    boundary(|| unsafe {
        if file.is_null() {
            return Err(ffi::SQLITE_IOERR_CLOSE);
        }
        let outer = file.cast::<Outer>();
        if (*outer).state.is_null() {
            return Err(ffi::SQLITE_IOERR_CLOSE);
        }
        let state_pointer = (*outer).state;
        let mut state = match (&*state_pointer).lock() {
            Ok(guard) => guard,
            Err(poison) => poison.into_inner(),
        };
        let root = state.registration.root.clone();
        ACTIVE_ROOT.with(|active| active.set(Arc::as_ptr(&root)));
        let mut ledger = root.cleanup_lock()?;
        if unix_abi::validate_base(state.registration.base).is_err() {
            return quarantine_close(
                outer,
                state_pointer,
                &root,
                &mut ledger,
                "close cannot delegate changed base; actual state retained until owner exit",
                ffi::SQLITE_IOERR_CLOSE,
            );
        }
        let inner_methods = match methods(state.inner) {
            Ok(methods) => methods,
            Err(code) => {
                return quarantine_close(
                    outer,
                    state_pointer,
                    &root,
                    &mut ledger,
                    "close has no valid underlying method table; quarantined",
                    code,
                )
            }
        };
        let underlying_close = match inner_methods.xClose {
            Some(close) => close,
            None => {
                return quarantine_close(
                    outer,
                    state_pointer,
                    &root,
                    &mut ledger,
                    "close method missing; actual handle quarantined",
                    ffi::SQLITE_IOERR_CLOSE,
                )
            }
        };
        let underlying_unmap = if state.shm_slot.is_some() {
            match inner_methods.xShmUnmap {
                Some(unmap) => Some(unmap),
                None => {
                    return quarantine_close(
                        outer,
                        state_pointer,
                        &root,
                        &mut ledger,
                        "SHM cleanup method missing; actual handle quarantined",
                        ffi::SQLITE_IOERR_SHMOPEN,
                    )
                }
            }
        } else {
            None
        };
        // Only after owning both guards and a valid actual close operation do
        // we detach the outer state. No ordinary contention loses a handle.
        (*outer).state = ptr::null_mut();
        (*outer).public.pMethods = ptr::null();
        let mut bookkeeping_error = None;
        if let Some(unmap) = underlying_unmap {
            let rc = unmap(state.inner, 0);
            if rc != ffi::SQLITE_OK {
                // The pinned Unix function returns OK, including no-op. An
                // unknown failure cannot safely be followed by unixClose's
                // pShm==NULL precondition. Retain the entire actual state and
                // charged handles until this owned process exits.
                return quarantine_close(
                    outer,
                    state_pointer,
                    &root,
                    &mut ledger,
                    "cleanup SHM unmap failed; actual state retained until owner exit",
                    rc,
                );
            }
            if let Err(code) = release_shm(&mut state, &mut ledger) {
                bookkeeping_error = Some(code);
            }
        }
        let rc = underlying_close(state.inner);
        if rc != ffi::SQLITE_OK {
            return quarantine_close(
                outer,
                state_pointer,
                &root,
                &mut ledger,
                "underlying close failed; actual state retained until owner exit",
                rc,
            );
        }
        ledger.close_handle(state.slot);
        // Filename borrow and inner allocation end AFTER the actual xClose.
        ffi::sqlite3_free(state.inner.cast());
        ffi::sqlite3_free_filename(state.filename_owner);
        drop(ledger);
        drop(state);
        drop(Box::from_raw(state_pointer));
        Ok(bookkeeping_error.unwrap_or(rc))
    })
}

unsafe extern "C" fn read(
    file: *mut ffi::sqlite3_file,
    output: *mut c_void,
    amount: c_int,
    offset: i64,
) -> c_int {
    boundary(|| unsafe {
        with_file(file, |state, ledger| {
            endpoint(amount, offset)?;
            let rc = methods(state.inner)?.xRead.ok_or(ffi::SQLITE_IOERR_READ)?(
                state.inner,
                output,
                amount,
                offset,
            );
            if rc != ffi::SQLITE_OK && rc != ffi::SQLITE_IOERR_SHORT_READ {
                return ledger.fail("base read failed", rc);
            }
            Ok(rc)
        })
    })
}
unsafe extern "C" fn write(
    file: *mut ffi::sqlite3_file,
    input: *const c_void,
    amount: c_int,
    offset: i64,
) -> c_int {
    boundary(|| unsafe {
        with_file(file, |state, ledger| {
            let end = endpoint(amount, offset)?;
            let root = &state.registration.root;
            root.bind_fd(
                ledger,
                state.slot,
                unix_abi::main_fd(state.inner, state.registration.base)?,
            )?;
            ledger.reserve_growth(state.slot, end)?;
            let rc = methods(state.inner)?
                .xWrite
                .ok_or(ffi::SQLITE_IOERR_WRITE)?(
                state.inner, input, amount, offset
            );
            if rc != ffi::SQLITE_OK {
                let _: Code<()> =
                    ledger.fail("base write failed; pre-growth reservation retained", rc);
            }
            let observed = unix_abi::main_fd(state.inner, state.registration.base)
                .and_then(|fd| root.bind_fd(ledger, state.slot, fd));
            if let Err(post) = observed {
                if rc != ffi::SQLITE_OK {
                    ledger.observe_secondary("post-write identity observation", post);
                    return Err(rc);
                }
                return ledger.fail("post-write identity observation failed", post);
            }
            if rc != ffi::SQLITE_OK {
                return Err(rc);
            }
            Ok(rc)
        })
    })
}
unsafe extern "C" fn truncate(file: *mut ffi::sqlite3_file, size: i64) -> c_int {
    boundary(|| unsafe {
        with_file(file, |state, ledger| {
            let size = u64::try_from(size).map_err(|_| ffi::SQLITE_IOERR_TRUNCATE)?;
            state.registration.root.bind_fd(
                ledger,
                state.slot,
                unix_abi::main_fd(state.inner, state.registration.base)?,
            )?;
            ledger.reserve_growth(state.slot, size)?;
            // CHUNK_SIZE is never delegated, so stock truncate cannot round beyond
            // the already reserved endpoint.
            let rc = methods(state.inner)?
                .xTruncate
                .ok_or(ffi::SQLITE_IOERR_TRUNCATE)?(state.inner, size as i64);
            if rc != ffi::SQLITE_OK {
                let _: Code<()> = ledger.fail("base truncate failed; reservation retained", rc);
            }
            let observed = unix_abi::main_fd(state.inner, state.registration.base)
                .and_then(|fd| state.registration.root.bind_fd(ledger, state.slot, fd));
            if let Err(post) = observed {
                if rc != ffi::SQLITE_OK {
                    ledger.observe_secondary("post-truncate identity observation", post);
                    return Err(rc);
                }
                return ledger.fail("post-truncate identity observation failed", post);
            }
            if rc != ffi::SQLITE_OK {
                return Err(rc);
            }
            Ok(rc)
        })
    })
}

macro_rules! forward_file {
    ($name:ident, $member:ident, ($($argument:ident : $kind:ty),*), $error:expr, [$($expected:expr),*]) => {
        unsafe extern "C" fn $name(file: *mut ffi::sqlite3_file, $($argument: $kind),*) -> c_int {
            boundary(|| unsafe { with_file(file, |state, ledger| {
                let rc = methods(state.inner)?.$member.ok_or($error)?(state.inner, $($argument),*);
                if rc != ffi::SQLITE_OK $( && rc != $expected )* {
                    return ledger.fail(concat!("base ", stringify!($member), " failed"), rc);
                }
                Ok(rc)
            }) })
        }
    };
}
forward_file!(sync, xSync, (flags: c_int), ffi::SQLITE_IOERR_FSYNC, []);
forward_file!(file_size, xFileSize, (size: *mut i64), ffi::SQLITE_IOERR_FSTAT, []);
forward_file!(lock, xLock, (level: c_int), ffi::SQLITE_IOERR_LOCK, [ffi::SQLITE_BUSY]);
forward_file!(unlock, xUnlock, (level: c_int), ffi::SQLITE_IOERR_UNLOCK, []);
forward_file!(reserved, xCheckReservedLock, (answer: *mut c_int), ffi::SQLITE_IOERR_CHECKRESERVEDLOCK, []);
forward_file!(shm_lock, xShmLock, (offset: c_int, count: c_int, flags: c_int), ffi::SQLITE_IOERR_SHMLOCK, [ffi::SQLITE_BUSY]);

unsafe extern "C" fn file_control(
    file: *mut ffi::sqlite3_file,
    operation: c_int,
    argument: *mut c_void,
) -> c_int {
    boundary(|| unsafe {
        with_file(file, |state, ledger| {
            // Closed whitelist: no unknown controls reach unixFileControl. In
            // particular SIZE_HINT/CHUNK_SIZE cannot preallocate behind xWrite,
            // and pointer/atomic/VFS/filename controls do not expose the inner file.
            let admitted = match operation {
                ffi::SQLITE_FCNTL_LOCKSTATE
                | ffi::SQLITE_FCNTL_LAST_ERRNO
                | ffi::SQLITE_FCNTL_HAS_MOVED
                | ffi::SQLITE_FCNTL_EXTERNAL_READER => true,
                ffi::SQLITE_FCNTL_PERSIST_WAL | ffi::SQLITE_FCNTL_POWERSAFE_OVERWRITE => {
                    !argument.is_null() && *argument.cast::<c_int>() < 0
                }
                ffi::SQLITE_FCNTL_MMAP_SIZE => {
                    if argument.is_null() {
                        return Err(ffi::SQLITE_IOERR);
                    }
                    *argument.cast::<i64>() = 0;
                    return Ok(ffi::SQLITE_OK);
                }
                _ => false,
            };
            if !admitted {
                return Ok(ffi::SQLITE_NOTFOUND);
            }
            if argument.is_null() {
                return Err(ffi::SQLITE_IOERR);
            }
            let rc = methods(state.inner)?
                .xFileControl
                .ok_or(ffi::SQLITE_NOTFOUND)?(state.inner, operation, argument);
            if rc != ffi::SQLITE_OK && rc != ffi::SQLITE_NOTFOUND {
                return ledger.fail("base file-control query failed", rc);
            }
            Ok(rc)
        })
    })
}
unsafe extern "C" fn sector_size(file: *mut ffi::sqlite3_file) -> c_int {
    let mut result = 0;
    let rc = boundary(|| unsafe {
        with_file(file, |state, _| {
            result = methods(state.inner)?.xSectorSize.ok_or(ffi::SQLITE_IOERR)?(state.inner);
            Ok(ffi::SQLITE_OK)
        })
    });
    if rc == ffi::SQLITE_OK {
        result
    } else {
        0
    }
}
unsafe extern "C" fn characteristics(file: *mut ffi::sqlite3_file) -> c_int {
    let mut result = 0;
    let rc = boundary(|| unsafe {
        with_file(file, |state, _| {
            result = methods(state.inner)?
                .xDeviceCharacteristics
                .ok_or(ffi::SQLITE_IOERR)?(state.inner)
                & !ffi::SQLITE_IOCAP_BATCH_ATOMIC;
            Ok(ffi::SQLITE_OK)
        })
    });
    if rc == ffi::SQLITE_OK {
        result
    } else {
        0
    }
}

unsafe extern "C" fn shm_map(
    file: *mut ffi::sqlite3_file,
    region: c_int,
    region_bytes: c_int,
    extend: c_int,
    output: *mut *mut c_void,
) -> c_int {
    if output.is_null() {
        return ffi::SQLITE_IOERR_SHMMAP;
    }
    unsafe {
        *output = ptr::null_mut();
    }
    boundary(|| unsafe {
        with_file(file, |state, ledger| {
            if !state.main || region < 0 || region_bytes != 32768 || ![0, 1, 2].contains(&extend) {
                return ledger.fail(
                    "unsupported shared-memory map request",
                    ffi::SQLITE_IOERR_SHMMAP,
                );
            }
            let page = libc::sysconf(libc::_SC_PAGESIZE);
            if page <= 0 || !(page as u64).is_power_of_two() {
                return ledger.fail("unknown host page size", ffi::SQLITE_IOERR_SHMMAP);
            }
            let per_map = (page as u64 / 32768).max(1);
            let regions = (region as u64)
                .checked_add(per_map)
                .ok_or(ffi::SQLITE_FULL)?
                / per_map
                * per_map;
            let bytes = regions.checked_mul(32768).ok_or(ffi::SQLITE_FULL)?;
            if bytes > FILE_BYTES || bytes > c_int::MAX as u64 {
                return ledger.fail("rounded SHM object exceeds cap", ffi::SQLITE_FULL);
            }
            let slot = match state.shm_slot {
                Some(slot) => slot,
                None => ledger.reserve_open("native.sqlite-shm", false)?,
            };
            // unixOpenSharedMemory may open/truncate to three bytes even when
            // bExtend=0. Every first map reserves a real object BEFORE delegation.
            if let Some(stat) = state.registration.root.stat_name("native.sqlite-shm")? {
                ledger.observe_existing_before_io(
                    slot,
                    crate::owner::identity(&stat),
                    u64::try_from(stat.st_size).map_err(|_| ffi::SQLITE_IOERR_FSTAT)?,
                    u64::try_from(stat.st_blocks).map_err(|_| ffi::SQLITE_IOERR_FSTAT)?,
                    true,
                )?;
            }
            // Exact pinned SQLite 3.51 WAL recovery also passes writeLock=2.
            // Both admitted nonzero values extend in unixShmMap. Reserve the
            // complete rounded length before either call; unknown values were
            // refused above and no byte/object/event allowance is increased.
            ledger.reserve_growth(slot, if extend != 0 { bytes.max(3) } else { 3 })?;
            if state.shm_slot.is_none() {
                // Own a pending SHM reference BEFORE the delegated operation.
                // An error after Unix creates pShm must still route through its
                // real xShmUnmap before unixClose (which requires pShm == NULL).
                ledger.add_shm(slot)?;
                state.shm_slot = Some(slot);
            }
            let rc = methods(state.inner)?
                .xShmMap
                .ok_or(ffi::SQLITE_IOERR_SHMMAP)?(
                state.inner,
                region,
                region_bytes,
                extend,
                output,
            );
            if rc != ffi::SQLITE_OK {
                let _: Code<()> =
                    ledger.fail("base SHM map failed; pending reservation retained", rc);
            }
            // Even a failing map can have opened/grown a SHM object. Inspect the
            // actual borrowed descriptor; never open/close a checking sentinel.
            // Latch the earlier lower result before this fallible observation.
            let observed = match unix_abi::shm_fd(state.inner, state.registration.base) {
                Ok(Some(fd)) => state.registration.root.bind_fd(ledger, slot, fd),
                Ok(None) if rc == ffi::SQLITE_OK => ledger.fail(
                    "successful map has no real SHM object",
                    ffi::SQLITE_IOERR_SHMOPEN,
                ),
                Ok(None) => Ok(()),
                Err(code) => Err(code),
            };
            if let Err(post) = observed {
                if rc != ffi::SQLITE_OK {
                    ledger.observe_secondary("post-SHM-map identity observation", post);
                    return Err(rc);
                }
                return ledger.fail("post-SHM-map identity observation failed", post);
            }
            if rc != ffi::SQLITE_OK {
                return Err(rc);
            }
            Ok(rc)
        })
    })
}
fn release_shm(state: &mut FileState, ledger: &mut Ledger) -> Code<()> {
    let mut issue = None;
    if let Some(slot) = state.shm_slot.take() {
        match state.registration.root.stat_name("native.sqlite-shm") {
            Ok(None) => ledger.unlinked(slot),
            Ok(Some(_)) => {}
            Err(code) => {
                let _: Code<()> = ledger.fail(
                    "post-unmap identity observation failed; linked slot conservatively retained",
                    code,
                );
                issue = Some(code);
            }
        }
        ledger.close_shm(slot);
    }
    issue.map_or(Ok(()), Err)
}
unsafe extern "C" fn shm_unmap(file: *mut ffi::sqlite3_file, delete_flag: c_int) -> c_int {
    boundary(|| unsafe {
        with_file(file, |state, ledger| {
            if ![0, 1].contains(&delete_flag) {
                return Err(ffi::SQLITE_IOERR_SHMMAP);
            }
            let rc = methods(state.inner)?
                .xShmUnmap
                .ok_or(ffi::SQLITE_IOERR_SHMMAP)?(state.inner, delete_flag);
            if rc != ffi::SQLITE_OK {
                return ledger.fail("base SHM unmap failed; reference retained", rc);
            }
            // Underlying unmap has released this actual unixShm reference; other
            // wrappers' references keep the same object charged until last purge.
            release_shm(state, ledger)?;
            Ok(rc)
        })
    })
}
unsafe extern "C" fn shm_barrier(file: *mut ffi::sqlite3_file) {
    let _ = boundary(|| unsafe {
        with_file(file, |state, _| {
            methods(state.inner)?
                .xShmBarrier
                .ok_or(ffi::SQLITE_IOERR_SHMLOCK)?(state.inner);
            Ok(ffi::SQLITE_OK)
        })
    });
}
unsafe extern "C" fn fetch(
    file: *mut ffi::sqlite3_file,
    offset: i64,
    amount: c_int,
    output: *mut *mut c_void,
) -> c_int {
    if output.is_null() {
        return ffi::SQLITE_IOERR_MMAP;
    }
    unsafe {
        *output = ptr::null_mut();
    }
    boundary(|| unsafe {
        with_file(file, |_state, _| {
            endpoint(amount, offset)?;
            // Explicitly unsupported mmap. NULL is SQLite's documented fallback
            // to xRead, not an alleged mapped reference or unaccounted allocation.
            Ok(ffi::SQLITE_OK)
        })
    })
}
unsafe extern "C" fn unfetch(
    file: *mut ffi::sqlite3_file,
    _offset: i64,
    mapping: *mut c_void,
) -> c_int {
    boundary(|| unsafe {
        with_file(file, |_state, ledger| {
            if !mapping.is_null() {
                return ledger.fail(
                    "foreign mapping passed to unmapped VFS",
                    ffi::SQLITE_IOERR_MMAP,
                );
            }
            Ok(ffi::SQLITE_OK)
        })
    })
}

unsafe extern "C" fn delete(
    vfs: *mut ffi::sqlite3_vfs,
    name: *const c_char,
    directory_sync: c_int,
) -> c_int {
    let code = boundary(|| unsafe {
        let registration = registration(vfs)?;
        let mut ledger = registration.root.lock()?;
        ledger.admission()?;
        if name.is_null() {
            return Err(ffi::SQLITE_IOERR_DELETE);
        }
        let leaf = registration.root.leaf(CStr::from_ptr(name))?;
        if !recognized(leaf) || leaf == "native.sqlite" {
            return ledger.fail("unsupported file deletion", ffi::SQLITE_IOERR_DELETE);
        }
        let slot = if let Some(stat) = registration.root.stat_name(leaf)? {
            let slot = ledger.reserve_open(leaf, false)?;
            ledger.observe_existing_before_io(
                slot,
                crate::owner::identity(&stat),
                u64::try_from(stat.st_size).map_err(|_| ffi::SQLITE_IOERR_FSTAT)?,
                u64::try_from(stat.st_blocks).map_err(|_| ffi::SQLITE_IOERR_FSTAT)?,
                true,
            )?;
            Some(slot)
        } else {
            ledger.named(leaf)
        };
        let stable = registration.root.path(leaf)?;
        let rc = (*registration.base)
            .xDelete
            .ok_or(ffi::SQLITE_IOERR_DELETE)?(
            registration.base, stable.as_ptr(), directory_sync
        );
        if rc == ffi::SQLITE_OK {
            if let Some(slot) = slot {
                ledger.unlinked(slot);
            }
        } else if rc != ffi::SQLITE_IOERR_DELETE_NOENT {
            return ledger.fail("base delete failed; original error and charge retained", rc);
        }
        Ok(rc)
    });
    unsafe { latch_vfs(vfs, code, &[ffi::SQLITE_IOERR_DELETE_NOENT]) }
}
unsafe extern "C" fn access(
    vfs: *mut ffi::sqlite3_vfs,
    name: *const c_char,
    flags: c_int,
    output: *mut c_int,
) -> c_int {
    if output.is_null() {
        return ffi::SQLITE_IOERR_ACCESS;
    }
    unsafe {
        *output = 0;
    }
    let code = boundary(|| unsafe {
        let registration = registration(vfs)?;
        let _ledger = registration.root.lock()?;
        if name.is_null() {
            return Err(ffi::SQLITE_IOERR_ACCESS);
        }
        let leaf = registration.root.leaf(CStr::from_ptr(name))?;
        if !recognized(leaf) {
            return Err(ffi::SQLITE_IOERR_ACCESS);
        }
        registration.root.stat_name(leaf)?;
        let stable = registration.root.path(leaf)?;
        Ok((*registration.base)
            .xAccess
            .ok_or(ffi::SQLITE_IOERR_ACCESS)?(
            registration.base,
            stable.as_ptr(),
            flags,
            output,
        ))
    });
    unsafe { latch_vfs(vfs, code, &[]) }
}
unsafe extern "C" fn full_pathname(
    vfs: *mut ffi::sqlite3_vfs,
    name: *const c_char,
    capacity: c_int,
    output: *mut c_char,
) -> c_int {
    let code = boundary(|| unsafe {
        let registration = registration(vfs)?;
        if name.is_null() || output.is_null() || capacity <= 0 {
            return Err(ffi::SQLITE_CANTOPEN);
        }
        let source = CStr::from_ptr(name);
        let leaf = registration.root.leaf(source)?;
        if !recognized(leaf) {
            return Err(ffi::SQLITE_CANTOPEN);
        }
        let bytes = source.to_bytes_with_nul();
        if bytes.len() > capacity as usize {
            return Err(ffi::SQLITE_CANTOPEN);
        }
        // Do not invoke Unix realpath: it would resolve /proc/self/fd back to
        // a replaceable ancestor and destroy the held-directory contract.
        ptr::copy_nonoverlapping(bytes.as_ptr().cast::<c_char>(), output, bytes.len());
        Ok(ffi::SQLITE_OK)
    });
    unsafe { latch_vfs(vfs, code, &[]) }
}
unsafe extern "C" fn dl_open(_vfs: *mut ffi::sqlite3_vfs, _name: *const c_char) -> *mut c_void {
    ptr::null_mut()
}
unsafe extern "C" fn dl_error(_vfs: *mut ffi::sqlite3_vfs, capacity: c_int, output: *mut c_char) {
    if !output.is_null() && capacity > 0 {
        let text = b"owned SQLite domain does not support extensions\0";
        let n = text.len().min(capacity as usize);
        unsafe {
            ptr::copy_nonoverlapping(text.as_ptr().cast::<c_char>(), output, n);
            *output.add(n - 1) = 0;
        }
    }
}
unsafe extern "C" fn randomness(
    vfs: *mut ffi::sqlite3_vfs,
    bytes: c_int,
    output: *mut c_char,
) -> c_int {
    let mut written = 0;
    let code = boundary(|| unsafe {
        let r = registration(vfs)?;
        written = (*r.base).xRandomness.ok_or(ffi::SQLITE_IOERR)?(r.base, bytes, output);
        Ok(ffi::SQLITE_OK)
    });
    unsafe {
        latch_vfs(vfs, code, &[]);
    }
    written
}
unsafe extern "C" fn sleep(vfs: *mut ffi::sqlite3_vfs, microseconds: c_int) -> c_int {
    let mut elapsed = 0;
    let code = boundary(|| unsafe {
        let r = registration(vfs)?;
        elapsed = (*r.base).xSleep.ok_or(ffi::SQLITE_IOERR)?(r.base, microseconds);
        Ok(ffi::SQLITE_OK)
    });
    unsafe {
        latch_vfs(vfs, code, &[]);
    }
    elapsed
}
unsafe extern "C" fn current_time(vfs: *mut ffi::sqlite3_vfs, output: *mut f64) -> c_int {
    let code = boundary(|| unsafe {
        let r = registration(vfs)?;
        Ok((*r.base).xCurrentTime.ok_or(ffi::SQLITE_IOERR)?(
            r.base, output,
        ))
    });
    unsafe { latch_vfs(vfs, code, &[]) }
}
unsafe extern "C" fn current_time_int64(vfs: *mut ffi::sqlite3_vfs, output: *mut i64) -> c_int {
    let code = boundary(|| unsafe {
        let r = registration(vfs)?;
        Ok((*r.base).xCurrentTimeInt64.ok_or(ffi::SQLITE_IOERR)?(
            r.base, output,
        ))
    });
    unsafe { latch_vfs(vfs, code, &[]) }
}
unsafe extern "C" fn last_error(
    vfs: *mut ffi::sqlite3_vfs,
    capacity: c_int,
    output: *mut c_char,
) -> c_int {
    let mut observed = 0;
    let code = boundary(|| unsafe {
        let r = registration(vfs)?;
        observed = (*r.base).xGetLastError.ok_or(ffi::SQLITE_IOERR)?(r.base, capacity, output);
        Ok(ffi::SQLITE_OK)
    });
    if code == ffi::SQLITE_OK {
        observed
    } else {
        unsafe { latch_vfs(vfs, code, &[]) }
    }
}

static IO_METHODS: ffi::sqlite3_io_methods = ffi::sqlite3_io_methods {
    iVersion: 3,
    xClose: Some(close),
    xRead: Some(read),
    xWrite: Some(write),
    xTruncate: Some(truncate),
    xSync: Some(sync),
    xFileSize: Some(file_size),
    xLock: Some(lock),
    xUnlock: Some(unlock),
    xCheckReservedLock: Some(reserved),
    xFileControl: Some(file_control),
    xSectorSize: Some(sector_size),
    xDeviceCharacteristics: Some(characteristics),
    xShmMap: Some(shm_map),
    xShmLock: Some(shm_lock),
    xShmBarrier: Some(shm_barrier),
    xShmUnmap: Some(shm_unmap),
    xFetch: Some(fetch),
    xUnfetch: Some(unfetch),
};
