use crate::NativeIoLease;
#[cfg(target_os = "linux")]
use crate::{BoundaryError, Result};
use rusqlite::Connection;
#[cfg(target_os = "linux")]
use rusqlite::{config::DbConfig, ffi, OpenFlags, MAIN_DB};
#[cfg(target_os = "linux")]
use std::ffi::{c_char, c_int, c_void, CStr};
use std::ops::Deref;
#[cfg(target_os = "linux")]
use std::path::Path;

/// Connection drops before its registration/root lease. A bare Connection is
/// never returned from the bounded factory, including the in-memory DDL probe.
///
/// The safe API must not allow a connection to be detached from that lease.
/// This checks the specific mutable-dereference escape (E0596), rather than a
/// missing private constructor or an unrelated dependency error.
///
/// ```compile_fail,E0596
/// use rusqlite::Connection;
/// use trnm_sqlite_io_boundary::OwnedConnection;
/// fn detach(mut owned: OwnedConnection) -> Connection {
///     std::mem::replace(&mut *owned, Connection::open_in_memory().unwrap())
/// }
/// ```
pub struct OwnedConnection {
    connection: Connection,
    _lease: Option<NativeIoLease>,
}
impl OwnedConnection {
    /// Preserve the legacy constructor's exact behavior on the default path.
    pub fn legacy(connection: Connection) -> Self {
        Self {
            connection,
            _lease: None,
        }
    }
    // Never expose &mut Connection: safe mem::replace would detach an in-memory
    // connection from the registration it may need for a later temp spill.
    // These proxies borrow this wrapper for the returned transaction lifetime.
    pub fn transaction(&mut self) -> rusqlite::Result<rusqlite::Transaction<'_>> {
        self.connection.transaction()
    }
    pub fn transaction_with_behavior(
        &mut self,
        behavior: rusqlite::TransactionBehavior,
    ) -> rusqlite::Result<rusqlite::Transaction<'_>> {
        self.connection.transaction_with_behavior(behavior)
    }
    pub fn savepoint(&mut self) -> rusqlite::Result<rusqlite::Savepoint<'_>> {
        self.connection.savepoint()
    }
    pub fn savepoint_with_name<T: Into<String>>(
        &mut self,
        name: T,
    ) -> rusqlite::Result<rusqlite::Savepoint<'_>> {
        self.connection.savepoint_with_name(name)
    }
}
impl Deref for OwnedConnection {
    type Target = Connection;
    fn deref(&self) -> &Connection {
        &self.connection
    }
}
#[cfg(target_os = "linux")]
impl NativeIoLease {
    pub fn open(&self, path: &Path, flags: OpenFlags) -> Result<OwnedConnection> {
        self.connection_admission()?;
        if path != self.directory().join("native.sqlite")
            || flags.contains(OpenFlags::SQLITE_OPEN_MEMORY)
        {
            return Err(BoundaryError(
                "only the held native.sqlite is admitted".into(),
            ));
        }
        let connection = Connection::open_with_flags_and_vfs(path, flags, self.registration.name())
            .map_err(|e| BoundaryError(e.to_string()))?;
        self.finish(connection)
    }
    pub fn open_in_memory(&self) -> Result<OwnedConnection> {
        self.connection_admission()?;
        let connection = Connection::open_in_memory_with_flags_and_vfs(
            OpenFlags::default(),
            self.registration.name(),
        )
        .map_err(|e| BoundaryError(e.to_string()))?;
        self.finish(connection)
    }
    fn finish(&self, connection: Connection) -> Result<OwnedConnection> {
        // A last read-only WAL connection cannot acquire the write lock used
        // by SQLite's optional close-time checkpoint. Configure this before
        // any schema/read access; writer checkpoint and FULL sync stay intact.
        if connection
            .is_readonly(MAIN_DB)
            .map_err(|e| BoundaryError(e.to_string()))?
        {
            let configured = connection
                .set_db_config(DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE, true)
                .map_err(|e| BoundaryError(e.to_string()))?;
            let observed = connection
                .db_config(DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE)
                .map_err(|e| BoundaryError(e.to_string()))?;
            if !configured || !observed {
                return Err(BoundaryError(
                    "read-only close checkpoint configuration was not retained".into(),
                ));
            }
        }
        // SAFETY: this live owned handle is not exposed or concurrently used.
        // The callback has static lifetime and owns no borrowed user data.
        let rc = unsafe {
            ffi::sqlite3_set_authorizer(connection.handle(), Some(authorize), std::ptr::null_mut())
        };
        if rc != ffi::SQLITE_OK {
            return Err(BoundaryError(format!("authorizer install {rc}")));
        }
        // Extension loading is also rejected at the VFS xDlOpen boundary.
        let rc = unsafe { ffi::sqlite3_enable_load_extension(connection.handle(), 0) };
        if rc != ffi::SQLITE_OK {
            return Err(BoundaryError(format!("extension disable {rc}")));
        }
        // A memory-only open may not invoke xOpen. This second admission is
        // the factory's completion linearization point: a concurrent owner
        // failure must not be hidden by a nominally successful new connection.
        self.connection_admission()?;
        Ok(OwnedConnection {
            connection,
            _lease: Some(self.clone()),
        })
    }
}

#[cfg(target_os = "linux")]
unsafe extern "C" fn authorize(
    _user: *mut c_void,
    action: c_int,
    first: *const c_char,
    second: *const c_char,
    _database: *const c_char,
    _trigger: *const c_char,
) -> c_int {
    // No allocation, callbacks into SQLite, locks or unwind across this ABI.
    // SQLITE_ATTACH also rejects VACUUM INTO's internally generated ATTACH.
    if action == ffi::SQLITE_ATTACH || action == ffi::SQLITE_DETACH {
        return ffi::SQLITE_DENY;
    }
    let eq = |pointer: *const c_char, expected: &[u8]| {
        !pointer.is_null()
            && unsafe { CStr::from_ptr(pointer) }
                .to_bytes()
                .eq_ignore_ascii_case(expected)
    };
    if action == ffi::SQLITE_FUNCTION && eq(second, b"load_extension") {
        return ffi::SQLITE_DENY;
    }
    if action == ffi::SQLITE_PRAGMA
        && (eq(first, b"temp_store_directory")
            || eq(first, b"data_store_directory")
            || eq(first, b"mmap_size")
            || eq(first, b"locking_mode")
            || eq(first, b"wal_checkpoint") && !second.is_null() && !eq(second, b"PASSIVE"))
    {
        return ffi::SQLITE_DENY;
    }
    ffi::SQLITE_OK
}
