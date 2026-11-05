//! Read-only access to a reviewed private SQLite Unix ABI, never a public ABI.
//!
//! See `unix-abi-source-proof.md` in the candidate handoff. A controlled build
//! must compile the pinned source layout witness; runtime layout/options/base
//! mismatches fail before any private prefix is inspected. This candidate has
//! not yet been built or qualified and does not attest hostile native code.

use libsqlite3_sys as ffi;
#[cfg(trnm_sqlite_layout_witness)]
use std::ffi::CStr;
use std::ffi::{c_char, c_int, c_uchar, c_ushort, c_void};
use std::mem::align_of;
#[cfg(trnm_sqlite_layout_witness)]
use std::mem::{offset_of, size_of};
use std::ptr;
#[cfg(trnm_sqlite_layout_witness)]
use std::sync::OnceLock;

#[cfg(unix)]
use std::os::fd::RawFd;
#[cfg(not(unix))]
type RawFd = c_int;

#[cfg(trnm_sqlite_layout_witness)]
const SOURCE_ID: &[u8] =
    b"2026-03-13 10:38:09 737ae4a34738ffa0c3ff7f9bb18df914dd1cad163f28fd6b6e114a344fe6d618";
#[cfg(trnm_sqlite_layout_witness)]
const UNIX_FILE_BYTES: c_int = 120;
#[cfg(trnm_sqlite_layout_witness)]
const UNIX_VFS_NAME: &[u8] = b"unix\0";
#[cfg(trnm_sqlite_layout_witness)]
const BUILD_FENCE: &str = "sqlite-3.51.3-normal-native-linux-layout-v3";
#[cfg(trnm_sqlite_layout_witness)]
const AMALGAMATION_SHA256: &str =
    "9512509b1bccb7461f79bea8aad6280ae4699e925fa4804381b71f59e7efb0c5";

#[cfg(trnm_sqlite_layout_witness)]
unsafe extern "C" {
    fn trnm_io_witness_layout(key: c_int) -> u64;
    fn trnm_io_witness_compileoption(index: c_int) -> *const c_char;
    fn trnm_io_witness_version() -> c_int;
    fn trnm_io_witness_source_id() -> *const c_char;
}

// sqlite3.c:39459-39469. All members through p_shm are unconditional. No
// shared Rust reference to this prefix is ever constructed: individual raw
// fields are read so that unrelated mutable C members are not borrowed.
#[repr(C)]
struct UnixFilePrefix {
    p_method: *const ffi::sqlite3_io_methods,
    p_vfs: *mut ffi::sqlite3_vfs,
    p_inode: *mut c_void,
    h: c_int,
    e_file_lock: c_uchar,
    ctrl_flags: c_ushort,
    last_errno: c_int,
    locking_context: *mut c_void,
    p_preallocated_unused: *mut c_void,
    z_path: *const c_char,
    p_shm: *mut UnixShmPrefix,
}

// sqlite3.c:43791-43792. Only the immutable first pointer is represented.
#[repr(C)]
struct UnixShmPrefix {
    p_shm_node: *mut UnixShmNodePrefix,
}

// sqlite3.c:43757-43761. The first three fields establish h_shm's offset;
// they are not read. In particular, no n_ref, lock array, region count or
// other concurrently mutable node member is read.
#[repr(C)]
struct UnixShmNodePrefix {
    p_inode: *mut c_void,
    p_shm_mutex: *mut ffi::sqlite3_mutex,
    z_filename: *mut c_char,
    h_shm: c_int,
}

#[derive(Clone, Copy, Eq, PartialEq)]
#[cfg(trnm_sqlite_layout_witness)]
struct BaseIdentity([usize; 25]);

#[cfg(trnm_sqlite_layout_witness)]
static BASE_IDENTITY: OnceLock<BaseIdentity> = OnceLock::new();
#[cfg(trnm_sqlite_layout_witness)]
static ABI_COMPATIBILITY: OnceLock<Result<(), String>> = OnceLock::new();

#[cfg(trnm_sqlite_layout_witness)]
fn supported_target_and_layout() -> bool {
    cfg!(all(
        target_os = "linux",
        target_pointer_width = "64",
        target_endian = "little",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )) && size_of::<c_int>() == 4
        && size_of::<c_ushort>() == 2
        && size_of::<*mut c_void>() == 8
        && align_of::<*mut c_void>() == 8
        && size_of::<ffi::sqlite3_file>() == 8
        && size_of::<ffi::sqlite3_vfs>() == 168
        && size_of::<ffi::sqlite3_io_methods>() == 152
        && size_of::<UnixFilePrefix>() == 72
        && align_of::<UnixFilePrefix>() == 8
        && offset_of!(UnixFilePrefix, p_vfs) == 8
        && offset_of!(UnixFilePrefix, h) == 24
        && offset_of!(UnixFilePrefix, p_shm) == 64
        && size_of::<UnixShmPrefix>() == 8
        && offset_of!(UnixShmPrefix, p_shm_node) == 0
        && size_of::<UnixShmNodePrefix>() == 32
        && align_of::<UnixShmNodePrefix>() == 8
        && offset_of!(UnixShmNodePrefix, h_shm) == 24
}

#[cfg(trnm_sqlite_layout_witness)]
fn checked_c_layout() -> bool {
    // Values are obtained from the actual included upstream C types, never
    // copied C structs. Full sizes precede all private-prefix access. Exact
    // normal-build sizes also reject unsupported tail/conditional layouts.
    let expected = [
        size_of::<*mut c_void>() as u64,
        size_of::<c_int>() as u64,
        size_of::<c_ushort>() as u64,
        align_of::<*mut c_void>() as u64,
        size_of::<ffi::sqlite3_file>() as u64,
        size_of::<ffi::sqlite3_vfs>() as u64,
        size_of::<ffi::sqlite3_io_methods>() as u64,
        UNIX_FILE_BYTES as u64,
        align_of::<UnixFilePrefix>() as u64,
        offset_of!(UnixFilePrefix, p_method) as u64,
        offset_of!(UnixFilePrefix, p_vfs) as u64,
        offset_of!(UnixFilePrefix, h) as u64,
        offset_of!(UnixFilePrefix, p_shm) as u64,
        24,
        align_of::<UnixShmPrefix>() as u64,
        offset_of!(UnixShmPrefix, p_shm_node) as u64,
        96,
        align_of::<UnixShmNodePrefix>() as u64,
        offset_of!(UnixShmNodePrefix, h_shm) as u64,
    ];
    expected.iter().enumerate().all(|(index, expected)| {
        // The witness is pure compile-time data: no second SQLite instance
        // is initialized and no database or VFS callback is ever executed.
        unsafe { trnm_io_witness_layout(index as c_int) == *expected }
    })
}

#[cfg(trnm_sqlite_layout_witness)]
fn compile_options_match() -> bool {
    for index in 0..512 {
        // Both APIs read their immutable compile-option table only. This
        // deliberately compares the complete ordered tables, not a partial
        // set of compileoption_used predicates that omits some private flags.
        let runtime = unsafe { ffi::sqlite3_compileoption_get(index) };
        let witness = unsafe { trnm_io_witness_compileoption(index) };
        if runtime.is_null() || witness.is_null() {
            return runtime.is_null() && witness.is_null();
        }
        if unsafe { CStr::from_ptr(runtime) != CStr::from_ptr(witness) } {
            return false;
        }
    }
    false
}

fn aligned<T>(value: *const T) -> bool {
    !value.is_null() && (value as usize).is_multiple_of(align_of::<T>())
}

#[cfg(trnm_sqlite_layout_witness)]
fn verify_abi_compatibility() -> Result<(), String> {
    if option_env!("TRNM_SQLITE3_BUILD_FENCE") != Some(BUILD_FENCE)
        || option_env!("TRNM_SQLITE3_AMALGAMATION_SHA256") != Some(AMALGAMATION_SHA256)
    {
        return Err("PRIVATE_ABI_UNSUPPORTED: missing controlled exact bundled build fence".into());
    }
    if !supported_target_and_layout() || !checked_c_layout() {
        return Err("PRIVATE_ABI_UNSUPPORTED: expected witnessed Linux little-endian LP64 x86_64/aarch64 ABI".into());
    }
    // These are public API/compile-time witness reads, not VFS callbacks.
    // The owner establishes the source/build and in-process trust boundary.
    unsafe {
        if ffi::sqlite3_libversion_number() != 3_051_003 || trnm_io_witness_version() != 3_051_003 {
            return Err("PRIVATE_ABI_UNSUPPORTED: SQLite version must be exactly 3.51.3".into());
        }
        let source_id = ffi::sqlite3_sourceid();
        let witnessed_source_id = trnm_io_witness_source_id();
        if source_id.is_null()
            || witnessed_source_id.is_null()
            || CStr::from_ptr(source_id).to_bytes() != SOURCE_ID
            || CStr::from_ptr(witnessed_source_id).to_bytes() != SOURCE_ID
        {
            return Err("PRIVATE_ABI_UNSUPPORTED: SQLite source ID mismatch".into());
        }
        if ffi::sqlite3_threadsafe() != 1 || !compile_options_match() {
            return Err("PRIVATE_ABI_UNSUPPORTED: runtime compile options differ from the exact normal bundled witness".into());
        }
    }
    Ok(())
}

/// Refuse an unsupported or changed base before any private-prefix read.
///
/// Runtime comparisons rely on the controlled build's pinned dependency,
/// mirrored normal flags, fresh-build/environment fence, and C layout witness.
/// They are not attestation against a malicious library or hostile native code.
/// The owner must prohibit registration/replacement, unregister, system-call
/// overrides, and mutation of this registered VFS for its whole lifetime.
#[cfg(trnm_sqlite_layout_witness)]
pub(crate) fn validate_base(base: *mut ffi::sqlite3_vfs) -> Result<(), String> {
    // Source/build layout and compile-option tables are immutable under the
    // admitted ownership model. Check once rather than scan the full table
    // on every SQLite write. Base identity/callbacks are still checked below.
    ABI_COMPATIBILITY
        .get_or_init(verify_abi_compatibility)
        .as_ref()
        .map_err(Clone::clone)?;
    unsafe {
        let registered = ffi::sqlite3_vfs_find(UNIX_VFS_NAME.as_ptr().cast());
        // Reject arbitrary caller pointers before dereferencing a VFS. The
        // registered pointer is trusted only under the ownership condition.
        if !aligned(registered) || base != registered {
            return Err(
                "PRIVATE_ABI_UNSUPPORTED: base must be the owned registered unix VFS".into(),
            );
        }
        if ffi::sqlite3_vfs_find(ptr::null()) != registered {
            return Err(
                "PRIVATE_ABI_UNSUPPORTED: the registered unix VFS is not the default".into(),
            );
        }
        let vfs = &*registered;
        if vfs.iVersion != 3
            || vfs.szOsFile != UNIX_FILE_BYTES
            || vfs.szOsFile < size_of::<UnixFilePrefix>() as c_int
            || vfs.mxPathname != 512
            || vfs.zName.is_null()
            || CStr::from_ptr(vfs.zName).to_bytes() != b"unix"
            || vfs.pAppData.is_null()
            || vfs.xOpen.is_none()
            || vfs.xDelete.is_none()
            || vfs.xAccess.is_none()
            || vfs.xFullPathname.is_none()
        {
            return Err("PRIVATE_ABI_UNSUPPORTED: unix VFS public shape mismatch".into());
        }
        let identity = BaseIdentity([
            registered as usize,
            vfs.iVersion as usize,
            vfs.szOsFile as usize,
            vfs.mxPathname as usize,
            vfs.zName as usize,
            vfs.pAppData as usize,
            vfs.xOpen.map_or(0, |f| f as usize),
            vfs.xDelete.map_or(0, |f| f as usize),
            vfs.xAccess.map_or(0, |f| f as usize),
            vfs.xFullPathname.map_or(0, |f| f as usize),
            vfs.xDlOpen.map_or(0, |f| f as usize),
            vfs.xDlError.map_or(0, |f| f as usize),
            vfs.xDlSym.map_or(0, |f| f as usize),
            vfs.xDlClose.map_or(0, |f| f as usize),
            vfs.xRandomness.map_or(0, |f| f as usize),
            vfs.xSleep.map_or(0, |f| f as usize),
            vfs.xCurrentTime.map_or(0, |f| f as usize),
            vfs.xGetLastError.map_or(0, |f| f as usize),
            vfs.xCurrentTimeInt64.map_or(0, |f| f as usize),
            vfs.xSetSystemCall.map_or(0, |f| f as usize),
            vfs.xGetSystemCall.map_or(0, |f| f as usize),
            vfs.xNextSystemCall.map_or(0, |f| f as usize),
            size_of::<UnixFilePrefix>(),
            offset_of!(UnixFilePrefix, p_shm),
            offset_of!(UnixShmNodePrefix, h_shm),
        ]);
        if BASE_IDENTITY.get_or_init(|| identity) != &identity {
            return Err(
                "PRIVATE_ABI_UNSUPPORTED: owned base VFS identity or callbacks changed".into(),
            );
        }
    }
    Ok(())
}

/// An unqualified target/build leaves ordinary Node APIs buildable, but it
/// cannot open the bounded API and never substitutes an ordinary/default VFS.
#[cfg(not(trnm_sqlite_layout_witness))]
pub(crate) fn validate_base(_base: *mut ffi::sqlite3_vfs) -> Result<(), String> {
    Err(format!(
        "PRIVATE_ABI_UNSUPPORTED: {}",
        option_env!("TRNM_SQLITE3_UNQUALIFIED_REASON")
            .unwrap_or("no exact C layout witness was compiled for this target/build")
    ))
}

/// Check the base and allocation bounds before reading a private prefix.
///
/// # Safety
/// `inner` must point to the live, aligned, at-least-120-byte allocation that
/// this exact owned base VFS successfully initialized. It must not be an
/// outer wrapper, foreign VFS object, fabricated allocation, or closed file.
/// The owner must serialize this file's callbacks and keep the allocation
/// alive. Alignment and size checks cannot establish allocation provenance.
unsafe fn checked_prefix(
    inner: *mut ffi::sqlite3_file,
    base: *mut ffi::sqlite3_vfs,
) -> Result<*const UnixFilePrefix, i32> {
    validate_base(base).map_err(|_| ffi::SQLITE_IOERR_FSTAT)?;
    if !aligned(inner.cast::<UnixFilePrefix>()) {
        return Err(ffi::SQLITE_IOERR_FSTAT);
    }
    let prefix = inner.cast::<UnixFilePrefix>();
    // validate_base established exact szOsFile BEFORE either private read.
    // Allocation provenance is the explicit unsafe precondition above.
    let creator = unsafe { ptr::read(ptr::addr_of!((*prefix).p_vfs)) };
    let methods = unsafe { ptr::read(ptr::addr_of!((*prefix).p_method)) };
    if creator != base || !aligned(methods) {
        return Err(ffi::SQLITE_IOERR_FSTAT);
    }
    Ok(prefix)
}

/// Borrow SQLite's actual database/journal/temp descriptor; never owns it.
///
/// # Safety
/// All `checked_prefix` preconditions apply. The caller may use the returned
/// descriptor only while this file remains live and exclusively serialized.
/// Never close it, convert it to `OwnedFd`/`File`, duplicate it as a sentinel,
/// change its flags, or retain it across the owning callback/close.
pub(crate) unsafe fn main_fd(
    inner: *mut ffi::sqlite3_file,
    base: *mut ffi::sqlite3_vfs,
) -> Result<RawFd, i32> {
    let prefix = unsafe { checked_prefix(inner, base)? };
    let descriptor = unsafe { ptr::read(ptr::addr_of!((*prefix).h)) };
    if descriptor < 3 {
        return Err(ffi::SQLITE_IOERR_FSTAT);
    }
    Ok(descriptor)
}

/// Borrow the actual shared-memory descriptor, if this file has opened SHM.
///
/// # Safety
/// All `checked_prefix` preconditions apply. In addition, this must be the
/// actual live base-created `unixFile`; `pShm` cannot be caller-controlled.
/// The file's callbacks must not run concurrently or re-enter. Its live
/// `unixShm` reference keeps the shared node alive while other connections
/// operate. After creation `unixShm.pShmNode` and node `hShm` are immutable;
/// no mutable shared fields are inspected. A pointer's non-null/aligned value
/// alone does not prove provenance. Never call this for unknown inner data.
pub(crate) unsafe fn shm_fd(
    inner: *mut ffi::sqlite3_file,
    base: *mut ffi::sqlite3_vfs,
) -> Result<Option<RawFd>, i32> {
    let prefix = unsafe { checked_prefix(inner, base)? };
    let shm = unsafe { ptr::read(ptr::addr_of!((*prefix).p_shm)) };
    if shm.is_null() {
        return Ok(None);
    }
    if !aligned(shm) {
        return Err(ffi::SQLITE_IOERR_SHMOPEN);
    }
    // Do not dereference an unknown pointer merely to discover its layout.
    // This read is valid only with the actual allocation provenance proved
    // by the unsafe preconditions, in addition to build/layout validation.
    let node = unsafe { ptr::read(ptr::addr_of!((*shm).p_shm_node)) };
    if !aligned(node) {
        return Err(ffi::SQLITE_IOERR_SHMOPEN);
    }
    let descriptor = unsafe { ptr::read(ptr::addr_of!((*node).h_shm)) };
    if descriptor < 3 {
        // Heap-simulated SHM (unix-excl), destroyed nodes and unknown states
        // are unsupported, not a successful 'no SHM' observation.
        return Err(ffi::SQLITE_IOERR_SHMOPEN);
    }
    Ok(Some(descriptor))
}
