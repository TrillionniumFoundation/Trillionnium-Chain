//! Connection-local observation of executed explicit transaction controls.
//!
//! This is a read-result fence, not a commit veto or an undo mechanism. A
//! control that fails after it starts also invalidates the scope. Implicit
//! SQLite transactions are not assigned identities by this interface.
use crate::{BoundaryError, Result};
use rusqlite::{ffi, Connection};
use std::ffi::{c_int, c_uint, c_void, CStr};
use std::ptr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

const KEY: &[u8] = b"trnm.native-io.executed-transaction-scope.v1\0";

struct Observer {
    connection: *mut ffi::sqlite3,
    pid: u32,
    controls: AtomicU64,
    writes: AtomicU64,
    statements: AtomicU64,
    failed: AtomicBool,
}

/// Opaque, connection-borrowed observation. It cannot be supplied with another
/// connection at verification, detached from that connection, or reset by a
/// later capture. Nested scopes share one connection-owned monotone observer.
pub struct TransactionScope<'db> {
    connection: &'db Connection,
    observer: *mut Observer,
    controls: u64,
    writes: u64,
}

impl<'db> TransactionScope<'db> {
    /// Capture after the caller's own BEGIN, before invoking untrusted work.
    /// A legacy codec fixture receives the same observer, never native-I/O
    /// qualification. The held factory installs it before returning its DB.
    pub fn capture(connection: &'db Connection) -> Result<Self> {
        install(connection)?;
        let observer = observer(connection)?;
        probe(connection, observer)?;
        // SAFETY: client data is owned by this borrowed live connection. The
        // private key is not exposed through SQL. See install/destroy below.
        let controls = unsafe { &*observer }.controls.load(Ordering::SeqCst);
        let writes = unsafe { &*observer }.writes.load(Ordering::SeqCst);
        Ok(Self {
            connection,
            observer,
            controls,
            writes,
        })
    }

    /// Refuse a result after ANY explicit transaction-control execution began
    /// on this connection, including an ABA back to the same autocommit state.
    /// A different connection has its own observer and does not affect this.
    pub fn unchanged(&self) -> Result<()> {
        if observer(self.connection)? != self.observer {
            return Err(error("transaction observer replaced"));
        }
        probe(self.connection, self.observer)?;
        // SAFETY: lookup above verifies the original connection-owned pointer
        // before dereference; the shared Connection borrow excludes safe close.
        let state = unsafe { &*self.observer };
        if state.failed.load(Ordering::SeqCst)
            || state.controls.load(Ordering::SeqCst) != self.controls
        {
            return Err(error("executed transaction control crossed read scope"));
        }
        Ok(())
    }

    /// A narrow observation inside the same actual main WRITE transaction.
    /// False means some potentially writing SQL executed since capture, even
    /// a failed/no-row statement or DDL later reversed. Transaction/observer
    /// replacement is an error, never an ordinary cache miss. Existing users of
    /// `unchanged` retain their original transaction-control-only contract.
    ///
    /// This is not a general SQLite or filesystem immutability certificate:
    /// readonly connection controls, prepare-time PRAGMA effects, non-SQL Blob
    /// writes/backup APIs and indirect UDF/virtual-table effects still require
    /// the caller's closed SQL graph, fresh namespace/schema checks and original
    /// owner/storage fences. Node's admitted graph does not use Blob/backup APIs.
    pub fn same_write_snapshot(&self, expected: &Connection) -> Result<bool> {
        if !std::ptr::eq(self.connection, expected) {
            return Err(error("write snapshot belongs to another connection"));
        }
        self.unchanged()?;
        // SAFETY: this is the same borrowed live handle checked by unchanged;
        // the main schema name is a static nul-terminated C string.
        let handle = unsafe { self.connection.handle() };
        if unsafe { ffi::sqlite3_get_autocommit(handle) } != 0
            || unsafe { ffi::sqlite3_txn_state(handle, c"main".as_ptr()) } != ffi::SQLITE_TXN_WRITE
        {
            return Err(error("original main write transaction is not active"));
        }
        // SAFETY: unchanged checked the original connection-owned observer.
        Ok(unsafe { &*self.observer }.writes.load(Ordering::SeqCst) == self.writes)
    }
}

fn error(message: &str) -> BoundaryError {
    BoundaryError(message.into())
}

fn observer(connection: &Connection) -> Result<*mut Observer> {
    // SAFETY: rusqlite owns a live handle for this shared borrow. Safe callers
    // cannot replace this private client data or close the borrowed connection.
    let handle = unsafe { connection.handle() };
    let pointer: *mut Observer =
        unsafe { ffi::sqlite3_get_clientdata(handle, KEY.as_ptr().cast()) }.cast();
    if pointer.is_null() {
        return Err(error("transaction observer missing"));
    }
    // SAFETY: only install below writes this private key in the admitted graph.
    let state: &Observer = unsafe { &*pointer };
    if state.connection != handle
        || state.pid != std::process::id()
        || state.failed.load(Ordering::SeqCst)
    {
        return Err(error("transaction observer connection/process/fault"));
    }
    Ok(pointer)
}

pub(crate) fn install(connection: &Connection) -> Result<()> {
    // SAFETY: this live Connection borrow is not concurrently used. Replacing
    // the private client data requires unsafe FFI. A trace-hook replacement,
    // including through a safe feature-gated API, is detected by the live probe.
    let handle = unsafe { connection.handle() };
    let existing = unsafe { ffi::sqlite3_get_clientdata(handle, KEY.as_ptr().cast()) };
    if !existing.is_null() {
        observer(connection)?;
        return Ok(());
    }
    let state = Box::into_raw(Box::new(Observer {
        connection: handle,
        pid: std::process::id(),
        controls: AtomicU64::new(0),
        writes: AtomicU64::new(0),
        statements: AtomicU64::new(0),
        failed: AtomicBool::new(false),
    }));
    // SQLite3.51.3 destroys this Box exactly once on OOM, replacement, or close.
    // Do not free it again on a failed set_clientdata. No SQL function exposes
    // the key or pointer. The stable Box survives Connection/OwnedConnection moves.
    let rc = unsafe {
        ffi::sqlite3_set_clientdata(handle, KEY.as_ptr().cast(), state.cast(), Some(destroy))
    };
    if rc != ffi::SQLITE_OK {
        return Err(error("transaction observer client data install failed"));
    }
    let rc = unsafe {
        ffi::sqlite3_trace_v2(
            handle,
            ffi::SQLITE_TRACE_STMT as c_uint,
            Some(trace),
            state.cast(),
        )
    };
    if rc != ffi::SQLITE_OK {
        // Mark the retained owner invalid; do not reset an observer/epoch or
        // report success with no hook. Connection close owns final cleanup.
        unsafe { &*state }.failed.store(true, Ordering::SeqCst);
        return Err(error("transaction observer trace install failed"));
    }
    Ok(())
}

fn probe(connection: &Connection, pointer: *mut Observer) -> Result<()> {
    // A real executed SELECT checks that another tracer did not leave this
    // observer installed but disconnected. No boolean self-attestation is used.
    let state = unsafe { &*pointer };
    let before = state.statements.load(Ordering::SeqCst);
    if connection
        .query_row("SELECT 0", [], |row| row.get::<_, i64>(0))
        .is_err()
    {
        state.failed.store(true, Ordering::SeqCst);
        return Err(error("transaction observer execution probe failed"));
    }
    if state.failed.load(Ordering::SeqCst) || state.statements.load(Ordering::SeqCst) <= before {
        state.failed.store(true, Ordering::SeqCst);
        return Err(error("transaction observer trace inactive/overflow"));
    }
    Ok(())
}

unsafe extern "C" fn destroy(pointer: *mut c_void) {
    // SQLite3.51.3 sqlite3Close invokes client destructors while the handle is
    // live, before setting ZOMBIE. Clear the callback before freeing its context,
    // including close_v2 with outstanding statements. No Rust Drop can panic.
    let state = unsafe { Box::from_raw(pointer.cast::<Observer>()) };
    unsafe { ffi::sqlite3_trace_v2(state.connection, 0, None, ptr::null_mut()) };
}

fn increment(counter: &AtomicU64, failed: &AtomicBool) {
    if counter
        .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |old| old.checked_add(1))
        .is_err()
    {
        // Sticky overflow: never wrap into an old valid epoch.
        failed.store(true, Ordering::SeqCst);
    }
}

unsafe extern "C" fn trace(
    event: c_uint,
    context: *mut c_void,
    statement: *mut c_void,
    _text: *mut c_void,
) -> c_int {
    // No allocation, locks, SQL execution, user closures, indexing panic or
    // unwind across this ABI. SQLite owns the actual statement during callback.
    if event != ffi::SQLITE_TRACE_STMT as c_uint || context.is_null() {
        return 0;
    }
    let state = unsafe { &*context.cast::<Observer>() };
    let statement = statement.cast::<ffi::sqlite3_stmt>();
    if statement.is_null()
        || state.pid != std::process::id()
        || unsafe { ffi::sqlite3_db_handle(statement) } != state.connection
    {
        state.failed.store(true, Ordering::SeqCst);
        return 0;
    }
    increment(&state.statements, &state.failed);
    // EXPLAIN compiles transaction opcodes but does not execute those controls.
    if unsafe { ffi::sqlite3_stmt_isexplain(statement) } != 0 {
        return 0;
    }
    // Count attempted execution, not prepare-time authorization or row counts.
    // DDL, no-row writes and later rollback may leave total_changes unchanged.
    // Transaction controls with readonly=true are still tracked independently
    // below. A write-count overflow is the original sticky observer failure.
    if unsafe { ffi::sqlite3_stmt_readonly(statement) } == 0 {
        increment(&state.writes, &state.failed);
    }
    let sql = unsafe { ffi::sqlite3_sql(statement) };
    if sql.is_null() {
        state.failed.store(true, Ordering::SeqCst);
    } else if transaction_control(unsafe { CStr::from_ptr(sql) }.to_bytes()) {
        increment(&state.controls, &state.failed);
    }
    0
}

fn transaction_control(mut sql: &[u8]) -> bool {
    // SQLite3.51.3 ASCII tokenizer: whitespace/comments/BOM are TK_SPACE;
    // empty leading commands are allowed. Read sqlite3_sql(P), not the trace X
    // string, which can be a synthetic trigger/reentrant comment.
    loop {
        if sql.first() == Some(&b';') {
            sql = &sql[1..];
        } else if matches!(sql.first(), Some(b' ' | b'\t' | b'\n' | b'\r' | b'\x0c')) {
            // aiClass rejects a leading VT, but sqlite3Isspace consumes VT
            // inside a whitespace token that started with one of these five.
            let length = sql
                .iter()
                .take_while(|byte| {
                    matches!(**byte, b' ' | b'\t' | b'\n' | b'\r' | b'\x0b' | b'\x0c')
                })
                .count();
            sql = &sql[length..];
        } else if sql.starts_with(b"\xef\xbb\xbf") {
            sql = &sql[3..];
        } else if sql.starts_with(b"--") {
            sql = match sql.iter().position(|byte| *byte == b'\n') {
                Some(end) => &sql[end + 1..],
                None => return false,
            };
        } else if sql.starts_with(b"/*") {
            sql = match sql.windows(2).position(|pair| pair == b"*/") {
                Some(end) => &sql[end + 2..],
                None => return false,
            };
        } else {
            break;
        }
    }
    // Non-ASCII bytes and '$'/'_' are identifier continuations in the pinned
    // ASCII tokenizer; BEGINx or BEGINé must not be mistaken for BEGIN.
    let length = sql
        .iter()
        .take_while(|byte| {
            byte.is_ascii_alphanumeric() || **byte == b'_' || **byte == b'$' || **byte >= 0x80
        })
        .count();
    let word = &sql[..length];
    [
        b"BEGIN".as_slice(),
        b"COMMIT",
        b"END",
        b"ROLLBACK",
        b"SAVEPOINT",
        b"RELEASE",
    ]
    .iter()
    .any(|control| word.eq_ignore_ascii_case(control))
}

#[cfg(test)]
#[path = "transaction_scope_tests.rs"]
mod tests;
