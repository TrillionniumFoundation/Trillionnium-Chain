//! Fixed-schema SQLite under a held private directory and exclusive file lease.
//!
//! Concurrent filesystem administration by the private directory's owner UID
//! is trusted. SQLite reopens the basename and does not expose its main-file fd;
//! the surrounding path checks detect persistent replacement but cannot attest
//! inode continuity against a same-UID swap-and-restore race during that open.
use super::{
    map_error, rejected, require, JournalHeadV3, OwnerBudgetV3, RootOwnerResultV3,
    MAX_ENROLLMENT_BYTES, MAX_ENVELOPE_BYTES, MAX_JOURNAL_EVENTS_V3, MAX_RETAINED_BYTES,
    MAX_STATE_BYTES,
};
use fs2::FileExt;
use rusqlite::{
    params, Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior,
};
use rustix::fs::{openat, Mode, OFlags};
use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

const MAX_DATABASE_BYTES: u64 = 64 * 1024 * 1024;
const APPLICATION_ID: u32 = 0x5252_5633;
const DDL: [&str; 4] = [
    "CREATE TABLE enrollment(singleton INTEGER PRIMARY KEY CHECK(singleton=1),wire BLOB NOT NULL,initial_state BLOB NOT NULL,initial_root BLOB NOT NULL)",
    "CREATE TABLE current(singleton INTEGER PRIMARY KEY CHECK(singleton=1),version INTEGER NOT NULL,root BLOB NOT NULL,state BLOB NOT NULL)",
    "CREATE TABLE events(version INTEGER PRIMARY KEY,previous_version INTEGER NOT NULL,previous_root BLOB NOT NULL,root BLOB NOT NULL,observed_at INTEGER NOT NULL,envelope BLOB NOT NULL,state BLOB NOT NULL)",
    "CREATE TABLE pending(singleton INTEGER PRIMARY KEY CHECK(singleton=1),version INTEGER NOT NULL,previous_version INTEGER NOT NULL,previous_root BLOB NOT NULL,root BLOB NOT NULL,observed_at INTEGER NOT NULL,envelope BLOB NOT NULL,state BLOB NOT NULL)",
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct RetainedEventV3 {
    pub previous: JournalHeadV3,
    pub head: JournalHeadV3,
    pub observed_at_unix: u64,
    pub envelope: Vec<u8>,
    pub state: Vec<u8>,
}
pub(super) struct RetainedRowsV3 {
    pub enrollment: Vec<u8>,
    pub initial_state: Vec<u8>,
    pub initial_head: JournalHeadV3,
    pub current_state: Vec<u8>,
    pub current_head: JournalHeadV3,
    pub events: Vec<RetainedEventV3>,
    pub pending: Option<RetainedEventV3>,
}

pub(super) struct StoreV3 {
    // Close SQLite before releasing the exclusive lock and held directory.
    db: Connection,
    file: File,
    directory: File,
    path: PathBuf,
    parent: PathBuf,
    process: u32,
}

fn identity(meta: &fs::Metadata) -> (u64, u64) {
    (meta.dev(), meta.ino())
}
fn private_file(file: &File) -> RootOwnerResultV3<()> {
    let meta = file.metadata()?;
    require(
        meta.is_file()
            && meta.nlink() == 1
            && meta.uid() == rustix::process::geteuid().as_raw()
            && meta.mode() & 0o7777 == 0o600
            && meta.len() <= MAX_DATABASE_BYTES,
        "ROOT_OWNER_PRIVATE_DATABASE_IDENTITY",
    )
}
fn private_directory(file: &File) -> RootOwnerResultV3<()> {
    let meta = file.metadata()?;
    require(
        meta.is_dir()
            && meta.uid() == rustix::process::geteuid().as_raw()
            && meta.mode() & 0o7777 == 0o700,
        "ROOT_OWNER_PRIVATE_DIRECTORY_IDENTITY",
    )
}

struct ProgressReset<'a>(&'a Connection);
impl Drop for ProgressReset<'_> {
    fn drop(&mut self) {
        // A failed reset leaves the original cancellation/deadline handler in
        // place, so it cannot widen the next operation's admitted resources.
        let _ = self.0.progress_handler(0, None::<fn() -> bool>);
    }
}

impl StoreV3 {
    fn bind(path: &Path, create: bool, budget: &OwnerBudgetV3) -> RootOwnerResultV3<Self> {
        budget.check()?;
        require(path.is_absolute(), "ROOT_OWNER_ABSOLUTE_DATABASE_PATH")?;
        let parent = path
            .parent()
            .ok_or_else(|| rejected("ROOT_OWNER_DATABASE_PATH"))?;
        require(
            parent.canonicalize()? == parent,
            "ROOT_OWNER_CANONICAL_PARENT",
        )?;
        let name = path
            .file_name()
            .ok_or_else(|| rejected("ROOT_OWNER_DATABASE_PATH"))?;
        let mut components = Path::new(name).components();
        require(
            matches!(components.next(), Some(Component::Normal(value)) if value == name)
                && components.next().is_none(),
            "ROOT_OWNER_DATABASE_BASENAME",
        )?;
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY | libc::O_CLOEXEC)
            .open(parent)?;
        private_directory(&directory)?;
        let mut flags = OFlags::RDWR | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
        if create {
            flags |= OFlags::CREATE | OFlags::EXCL;
        }
        let file = File::from(openat(&directory, name, flags, Mode::RUSR | Mode::WUSR)?);
        private_file(&file)?;
        file.try_lock_exclusive()
            .map_err(|_| rejected("ROOT_OWNER_BUSY"))?;
        if !create {
            // Refuse a legacy/foreign database before opening any writable
            // SQLite connection or changing its journal mode. The fixed header
            // identity is additional routing, not the signed enrollment pin.
            let mut header = [0; 100];
            file.try_clone()?.read_exact(&mut header)?;
            require(
                &header[..16] == b"SQLite format 3\0"
                    && header[18] == 1
                    && header[19] == 1
                    && u32::from_be_bytes(header[60..64].try_into().unwrap()) == 3
                    && u32::from_be_bytes(header[68..72].try_into().unwrap()) == APPLICATION_ID,
                "ROOT_OWNER_DATABASE_NAMESPACE",
            )?;
        }
        // SQLite's NOFOLLOW rejects /proc/self/fd paths as symlinks. Open the
        // independently checked canonical name with NOFOLLOW retained. The
        // held directory/file lease and surrounding identity checks do not
        // eliminate the trusted same-UID administration boundary above.
        let db = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .map_err(map_error)?;
        db.busy_timeout(Duration::ZERO).map_err(map_error)?;
        db.execute_batch("PRAGMA trusted_schema=OFF; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON; PRAGMA temp_store=MEMORY; PRAGMA mmap_size=0;").map_err(map_error)?;
        let journal: String = db
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))
            .map_err(map_error)?;
        require(journal == "delete", "ROOT_OWNER_DATABASE_JOURNAL_MODE")?;
        let page_size: u64 = db
            .query_row("PRAGMA page_size", [], |row| row.get(0))
            .map_err(map_error)?;
        require(page_size == 4096, "ROOT_OWNER_DATABASE_PAGE_SIZE")?;
        db.pragma_update(None, "max_page_count", MAX_DATABASE_BYTES / page_size)
            .map_err(map_error)?;
        let value = Self {
            db,
            file,
            directory,
            path: path.to_path_buf(),
            parent: parent.to_path_buf(),
            process: std::process::id(),
        };
        value.check_identity()?;
        budget.check()?;
        Ok(value)
    }
    pub fn create(
        path: &Path,
        enrollment: &[u8],
        head: JournalHeadV3,
        state: &[u8],
        budget: &mut OwnerBudgetV3,
    ) -> RootOwnerResultV3<Self> {
        require(
            head.version == 0
                && enrollment.len() <= MAX_ENROLLMENT_BYTES
                && state.len() <= MAX_STATE_BYTES,
            "ROOT_OWNER_INITIAL_STATE_BOUND",
        )?;
        head.validate()?;
        let value = Self::bind(path, true, budget)?;
        value.with_write(budget, |db, _| {
            for ddl in DDL {
                db.execute_batch(ddl).map_err(map_error)?;
            }
            db.execute_batch("PRAGMA user_version=3")
                .map_err(map_error)?;
            db.pragma_update(None, "application_id", APPLICATION_ID)
                .map_err(map_error)?;
            db.execute(
                "INSERT INTO enrollment VALUES(1,?,?,?)",
                params![enrollment, state, head.root.as_slice()],
            )
            .map_err(map_error)?;
            db.execute(
                "INSERT INTO current VALUES(1,0,?,?)",
                params![head.root.as_slice(), state],
            )
            .map_err(map_error)?;
            Ok(())
        })?;
        value.directory.sync_all()?;
        Ok(value)
    }
    pub fn open(path: &Path, budget: &mut OwnerBudgetV3) -> RootOwnerResultV3<Self> {
        Self::bind(path, false, budget)
    }
    pub fn check_identity(&self) -> RootOwnerResultV3<()> {
        require(
            self.process == std::process::id(),
            "ROOT_OWNER_PROCESS_CHANGED",
        )?;
        private_file(&self.file)?;
        private_directory(&self.directory)?;
        require(
            self.parent.canonicalize()? == self.parent,
            "ROOT_OWNER_PARENT_REPLACED",
        )?;
        let named_parent = fs::symlink_metadata(&self.parent)?;
        require(
            named_parent.is_dir()
                && identity(&named_parent) == identity(&self.directory.metadata()?),
            "ROOT_OWNER_PARENT_REPLACED",
        )?;
        let name = self
            .path
            .file_name()
            .ok_or_else(|| rejected("ROOT_OWNER_DATABASE_PATH"))?;
        let named = File::from(openat(
            &self.directory,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )?);
        private_file(&named)?;
        require(
            identity(&named.metadata()?) == identity(&self.file.metadata()?),
            "ROOT_OWNER_DATABASE_REPLACED",
        )
    }
    fn progress<'a>(&'a self, budget: &OwnerBudgetV3) -> RootOwnerResultV3<ProgressReset<'a>> {
        let deadline = budget.deadline;
        let cancelled = budget.cancelled.clone();
        self.db
            .progress_handler(
                100,
                Some(move || cancelled.load(Ordering::Acquire) || Instant::now() >= deadline),
            )
            .map_err(map_error)?;
        Ok(ProgressReset(&self.db))
    }
    pub fn with_read<T>(
        &self,
        budget: &mut OwnerBudgetV3,
        operation: impl FnOnce(&Connection, &mut OwnerBudgetV3) -> RootOwnerResultV3<T>,
    ) -> RootOwnerResultV3<T> {
        self.with_transaction(TransactionBehavior::Deferred, budget, operation)
    }
    pub fn with_write<T>(
        &self,
        budget: &mut OwnerBudgetV3,
        operation: impl FnOnce(&Connection, &mut OwnerBudgetV3) -> RootOwnerResultV3<T>,
    ) -> RootOwnerResultV3<T> {
        self.with_transaction(TransactionBehavior::Immediate, budget, operation)
    }
    fn with_transaction<T>(
        &self,
        behavior: TransactionBehavior,
        budget: &mut OwnerBudgetV3,
        operation: impl FnOnce(&Connection, &mut OwnerBudgetV3) -> RootOwnerResultV3<T>,
    ) -> RootOwnerResultV3<T> {
        budget.check()?;
        self.check_identity()?;
        let _reset = self.progress(budget)?;
        let tx = Transaction::new_unchecked(&self.db, behavior).map_err(map_error)?;
        let result = operation(&tx, budget)?;
        self.check_identity()?;
        budget.check()?;
        tx.commit().map_err(map_error)?;
        self.file.sync_all()?;
        self.directory.sync_all()?;
        self.check_identity()?;
        budget.check()?;
        Ok(result)
    }

    fn validate_schema(db: &Connection) -> RootOwnerResultV3<()> {
        let version: u64 = db
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .map_err(map_error)?;
        let application: u32 = db
            .query_row("PRAGMA application_id", [], |row| row.get(0))
            .map_err(map_error)?;
        let count: usize = db
            .query_row("SELECT COUNT(*) FROM sqlite_master", [], |row| row.get(0))
            .map_err(map_error)?;
        require(
            version == 3 && application == APPLICATION_ID && count == DDL.len(),
            "ROOT_OWNER_SCHEMA",
        )?;
        for (name, ddl) in ["enrollment", "current", "events", "pending"]
            .into_iter()
            .zip(DDL)
        {
            let valid: bool = db.query_row("SELECT COALESCE(typeof(type)='text' AND type='table' AND typeof(name)='text' AND name=? AND typeof(tbl_name)='text' AND tbl_name=? AND typeof(sql)='text' AND length(CAST(sql AS BLOB))=? AND sql=?,0) FROM sqlite_master WHERE name=?", params![name, name, ddl.len(), ddl, name], |row| row.get(0)).map_err(map_error)?;
            require(valid, "ROOT_OWNER_SCHEMA")?;
        }
        Ok(())
    }

    pub fn read_bounded(db: &Connection) -> RootOwnerResultV3<RetainedRowsV3> {
        Self::validate_schema(db)?;
        let (enrollments, current, pending, events): (usize, usize, usize, usize) = db.query_row("SELECT (SELECT COUNT(*) FROM enrollment),(SELECT COUNT(*) FROM current),(SELECT COUNT(*) FROM pending),(SELECT COUNT(*) FROM events)", [], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?))).map_err(map_error)?;
        require(
            enrollments == 1 && current == 1 && pending <= 1 && events <= MAX_JOURNAL_EVENTS_V3,
            "ROOT_OWNER_ROW_COUNT",
        )?;
        let enrollment_valid: bool = db.query_row("SELECT COALESCE(typeof(singleton)='integer' AND singleton=1 AND typeof(wire)='blob' AND length(wire)>0 AND length(wire)<=? AND typeof(initial_state)='blob' AND length(initial_state)>0 AND length(initial_state)<=? AND typeof(initial_root)='blob' AND length(initial_root)=64,0) FROM enrollment", params![MAX_ENROLLMENT_BYTES, MAX_STATE_BYTES], |row| row.get(0)).map_err(map_error)?;
        let current_valid: bool = db.query_row("SELECT COALESCE(typeof(singleton)='integer' AND singleton=1 AND typeof(version)='integer' AND version>=0 AND version<=? AND typeof(root)='blob' AND length(root)=64 AND typeof(state)='blob' AND length(state)>0 AND length(state)<=?,0) FROM current", params![MAX_JOURNAL_EVENTS_V3, MAX_STATE_BYTES], |row| row.get(0)).map_err(map_error)?;
        require(enrollment_valid && current_valid, "ROOT_OWNER_ROW_WIDTH")?;
        let mut retained_bytes = 0usize;
        for table in ["events", "pending"] {
            let sql = format!("SELECT COUNT(*) FROM {table} WHERE NOT COALESCE(typeof(version)='integer' AND version>0 AND version<=? AND typeof(previous_version)='integer' AND previous_version>=0 AND previous_version=version-1 AND typeof(previous_root)='blob' AND length(previous_root)=64 AND typeof(root)='blob' AND length(root)=64 AND typeof(observed_at)='integer' AND observed_at>=0 AND typeof(envelope)='blob' AND length(envelope)>0 AND length(envelope)<=? AND typeof(state)='blob' AND length(state)>0 AND length(state)<=?,0)");
            let invalid: usize = db
                .query_row(
                    &sql,
                    params![MAX_JOURNAL_EVENTS_V3, MAX_ENVELOPE_BYTES, MAX_STATE_BYTES],
                    |row| row.get(0),
                )
                .map_err(map_error)?;
            require(invalid == 0, "ROOT_OWNER_EVENT_WIDTH")?;
            let bytes: usize = db
                .query_row(
                    &format!("SELECT COALESCE(SUM(length(envelope)+length(state)),0) FROM {table}"),
                    [],
                    |row| row.get(0),
                )
                .map_err(map_error)?;
            retained_bytes = retained_bytes
                .checked_add(bytes)
                .ok_or_else(|| rejected("ROOT_OWNER_BYTE_BUDGET"))?;
        }
        require(
            retained_bytes <= MAX_RETAINED_BYTES,
            "ROOT_OWNER_BYTE_BUDGET",
        )?;
        if pending == 1 {
            let valid: bool = db
                .query_row(
                    "SELECT typeof(singleton)='integer' AND singleton=1 FROM pending",
                    [],
                    |row| row.get(0),
                )
                .map_err(map_error)?;
            require(valid, "ROOT_OWNER_PENDING_SINGLETON")?;
        }
        let (enrollment, initial_state, initial_root): (Vec<u8>, Vec<u8>, Vec<u8>) = db
            .query_row(
                "SELECT wire,initial_state,initial_root FROM enrollment",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .map_err(map_error)?;
        let (version, root, current_state): (u64, Vec<u8>, Vec<u8>) = db
            .query_row("SELECT version,root,state FROM current", [], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            })
            .map_err(map_error)?;
        let mut statement = db.prepare("SELECT version,previous_version,previous_root,root,observed_at,envelope,state FROM events ORDER BY version").map_err(map_error)?;
        let event_rows = statement.query_map([], event_row).map_err(map_error)?;
        let mut retained = Vec::with_capacity(events);
        for row in event_rows {
            retained.push(decode_event(row.map_err(map_error)?)?);
        }
        let pending = db.query_row("SELECT version,previous_version,previous_root,root,observed_at,envelope,state FROM pending", [], event_row).optional().map_err(map_error)?.map(decode_event).transpose()?;
        Ok(RetainedRowsV3 {
            enrollment,
            initial_state,
            initial_head: JournalHeadV3 {
                version: 0,
                root: initial_root
                    .try_into()
                    .map_err(|_| rejected("ROOT_OWNER_INITIAL_ROOT"))?,
            },
            current_state,
            current_head: JournalHeadV3 {
                version,
                root: root
                    .try_into()
                    .map_err(|_| rejected("ROOT_OWNER_CURRENT_ROOT"))?,
            },
            events: retained,
            pending,
        })
    }

    pub fn stage(db: &Connection, event: &RetainedEventV3) -> RootOwnerResultV3<()> {
        let used: usize = db
            .query_row(
                "SELECT COALESCE(SUM(length(envelope)+length(state)),0) FROM events",
                [],
                |row| row.get(0),
            )
            .map_err(map_error)?;
        require(
            event.envelope.len() <= MAX_ENVELOPE_BYTES
                && event.state.len() <= MAX_STATE_BYTES
                && used
                    .checked_add(event.envelope.len())
                    .and_then(|n| n.checked_add(event.state.len()))
                    .is_some_and(|n| n <= MAX_RETAINED_BYTES),
            "ROOT_OWNER_BYTE_BUDGET",
        )?;
        db.execute(
            "INSERT INTO pending VALUES(1,?,?,?,?,?,?,?)",
            params![
                event.head.version,
                event.previous.version,
                event.previous.root.as_slice(),
                event.head.root.as_slice(),
                event.observed_at_unix,
                &event.envelope,
                &event.state
            ],
        )
        .map_err(map_error)?;
        Ok(())
    }
    pub fn finish(db: &Connection, event: &RetainedEventV3) -> RootOwnerResultV3<()> {
        let inserted = db.execute("INSERT INTO events SELECT version,previous_version,previous_root,root,observed_at,envelope,state FROM pending WHERE singleton=1", []).map_err(map_error)?;
        let updated = db.execute("UPDATE current SET version=?,root=?,state=? WHERE singleton=1 AND version=? AND root=?", params![event.head.version, event.head.root.as_slice(), &event.state, event.previous.version, event.previous.root.as_slice()]).map_err(map_error)?;
        let removed = db
            .execute("DELETE FROM pending WHERE singleton=1", [])
            .map_err(map_error)?;
        require(
            inserted == 1 && updated == 1 && removed == 1,
            "ROOT_OWNER_FINISH_CONFLICT",
        )
    }
}

type EventRowV3 = (u64, u64, Vec<u8>, Vec<u8>, u64, Vec<u8>, Vec<u8>);
fn event_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<EventRowV3> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
        row.get(6)?,
    ))
}
fn decode_event(row: EventRowV3) -> RootOwnerResultV3<RetainedEventV3> {
    let previous = JournalHeadV3 {
        version: row.1,
        root: row
            .2
            .try_into()
            .map_err(|_| rejected("ROOT_OWNER_EVENT_ROOT"))?,
    };
    let head = JournalHeadV3 {
        version: row.0,
        root: row
            .3
            .try_into()
            .map_err(|_| rejected("ROOT_OWNER_EVENT_ROOT"))?,
    };
    previous.validate()?;
    head.validate()?;
    Ok(RetainedEventV3 {
        previous,
        head,
        observed_at_unix: row.4,
        envelope: row.5,
        state: row.6,
    })
}
