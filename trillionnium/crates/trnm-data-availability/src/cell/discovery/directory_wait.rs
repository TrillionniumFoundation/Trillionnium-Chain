//! Keep local directory contention inside the caller's original request budget.
//! SQLite and filesystem work remain cooperative; this is not kernel preemption.

use super::{check_deadline, CellErrorV1, CellResultV1};
use rusqlite::Connection;
use std::{
    sync::{Mutex, MutexGuard, TryLockError},
    thread,
    time::{Duration, Instant},
};

pub(super) fn lock_before<T>(
    owner: &Mutex<T>,
    deadline: Instant,
) -> CellResultV1<MutexGuard<'_, T>> {
    loop {
        check_deadline(deadline)?;
        match owner.try_lock() {
            Ok(guard) => {
                // Acquiring the owner at the deadline cannot start new SQL work.
                check_deadline(deadline)?;
                return Ok(guard);
            }
            Err(TryLockError::WouldBlock) => thread::sleep(
                Duration::from_millis(1).min(deadline.saturating_duration_since(Instant::now())),
            ),
            Err(TryLockError::Poisoned(_)) => {
                return Err(CellErrorV1::Invalid("discovery owner poisoned"));
            }
        }
    }
}

pub(super) struct SqliteDeadline {
    deadline: Instant,
    original_busy: Duration,
}

impl SqliteDeadline {
    /// Refresh before BEGIN, COMMIT and a fresh readback. Waiting in an earlier
    /// stage never renews the time available for a later SQLite lock.
    pub(super) fn before_sql(&self, db: &Connection) -> CellResultV1<()> {
        check_deadline(self.deadline)?;
        db.busy_timeout(
            self.original_busy
                .min(self.deadline.saturating_duration_since(Instant::now())),
        )?;
        check_deadline(self.deadline)
    }
}

pub(super) fn with_sqlite_deadline<T>(
    db: &mut Connection,
    deadline: Instant,
    operation: impl FnOnce(&mut Connection, &SqliteDeadline) -> CellResultV1<T>,
) -> CellResultV1<T> {
    check_deadline(deadline)?;
    let original_ms: u64 = db.pragma_query_value(None, "busy_timeout", |row| row.get(0))?;
    let wait = SqliteDeadline {
        deadline,
        original_busy: Duration::from_millis(original_ms),
    };
    let result = wait.before_sql(db).and_then(|()| operation(db, &wait));
    // Restore on both success and refusal. A timed-out call must not shorten
    // the next request's policy. Restoration grants no time to this request.
    let restored = db.busy_timeout(wait.original_busy);
    match result {
        Ok(value) => {
            restored?;
            check_deadline(deadline)?;
            Ok(value)
        }
        Err(error) => Err(error),
    }
}
