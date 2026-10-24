//! Serialize supported cache writers before checkpoint admission. A checkpoint
//! policy alone is not a quota: no new transaction starts until TRUNCATE has
//! completed and the actual WAL is empty. Readers may force a pre-write refusal.
//! The owner-controlled namespace must not be unlinked/replaced while in use;
//! arbitrary SQLite clients and filesystem attackers are outside this contract.
use std::{
    fs::{self, File, OpenOptions, TryLockError},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use rusqlite::{config::DbConfig, Connection};

use super::{require, CellCacheConfigV4, CellErrorV1, CellResultV1};

pub(super) const WRITER_BUDGET: Duration = Duration::from_secs(5);

pub(super) fn sidecar(path: &Path, suffix: &str) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(suffix);
    value.into()
}

pub(super) fn writer_identity(path: &Path) -> CellResultV1<(PathBuf, File)> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
        .canonicalize()?;
    let path = parent.join(
        path.file_name()
            .ok_or(CellErrorV1::Invalid("cache database path"))?,
    );
    check_path(&path)?;
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(sidecar(&path, "-writer-lock-v4"))?;
    let metadata = file.metadata()?;
    require(
        metadata.is_file() && metadata.len() == 0,
        "cache writer lock",
    )?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        require(metadata.nlink() == 1, "cache writer lock links")?;
    }
    Ok((path, file))
}

pub(super) fn check_path(path: &Path) -> CellResultV1<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            require(metadata.is_file(), "cache database file")?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                require(metadata.nlink() == 1, "cache database links")?;
            }
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}

pub(super) struct WriterPermit<'a>(&'a File);
impl Drop for WriterPermit<'_> {
    fn drop(&mut self) {
        let _ = self.0.unlock();
    }
}

pub(super) fn acquire(file: &File, deadline: Instant) -> CellResultV1<WriterPermit<'_>> {
    loop {
        match file.try_lock() {
            Ok(()) => return Ok(WriterPermit(file)),
            Err(TryLockError::Error(e)) => return Err(e.into()),
            Err(TryLockError::WouldBlock) => {
                // This consumes the original SQLite five-second contention
                // allowance. SQL receives only the remainder, never another 5s.
                let left = remaining(deadline)?;
                std::thread::sleep(left.min(Duration::from_millis(1)));
            }
        }
    }
}

pub(super) fn remaining(deadline: Instant) -> CellResultV1<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|d| !d.is_zero())
        .ok_or(CellErrorV1::CacheWriterBusy)
}

pub(super) fn configure(connection: &Connection) -> CellResultV1<()> {
    // The frame/padding bound is qualified against this exact locked backend;
    // an upgraded or substituted pager requires a new source qualification.
    require(
        rusqlite::version_number() == 3_046_000,
        "cache WAL backend version",
    )?;
    require(
        connection.set_db_config(DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE, true)?,
        "cache close checkpoint policy",
    )?;
    connection.pragma_update(None, "cache_spill", false)?;
    connection.pragma_update(None, "wal_autocheckpoint", 0)?;
    connection.pragma_update(None, "synchronous", "FULL")?;
    let spill: u64 = connection.pragma_query_value(None, "cache_spill", |r| r.get(0))?;
    let automatic: u64 = connection.pragma_query_value(None, "wal_autocheckpoint", |r| r.get(0))?;
    let synchronous: u64 = connection.pragma_query_value(None, "synchronous", |r| r.get(0))?;
    require(
        spill == 0 && automatic == 0 && synchronous == 2,
        "cache writer pager policy",
    )
}

pub(super) fn check_sidecars(path: &Path, config: CellCacheConfigV4) -> CellResultV1<()> {
    for (suffix, cap, reason) in [
        ("-wal", config.max_wal_bytes()?, "cache WAL physical bound"),
        ("-shm", config.max_shm_bytes()?, "cache SHM physical bound"),
    ] {
        match fs::symlink_metadata(sidecar(path, suffix)) {
            Ok(metadata) => {
                require(metadata.is_file() && metadata.len() <= cap, reason)?;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

pub(super) fn checkpoint_zero(connection: &Connection, path: &Path) -> CellResultV1<()> {
    // A held read snapshot refuses immediately; no extra busy wait is added.
    connection.busy_timeout(Duration::ZERO)?;
    let mode: String = connection.pragma_query_value(None, "journal_mode", |r| r.get(0))?;
    require(mode == "wal", "cache journal mode")?;
    let result: (i64, i64, i64) =
        connection.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?))
        })?;
    if result != (0, 0, 0) {
        return Err(CellErrorV1::CacheWriterBusy);
    }
    match fs::metadata(sidecar(path, "-wal")) {
        Ok(metadata) if metadata.len() != 0 => Err(CellErrorV1::CacheWriterBusy),
        Ok(_) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}
