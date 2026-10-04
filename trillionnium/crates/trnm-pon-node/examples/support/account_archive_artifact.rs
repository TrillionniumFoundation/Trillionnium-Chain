//! Consistent SQLite exports for research fixtures, never a production archive hook.
use rusqlite::{Connection, OpenFlags};
use serde::Serialize;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

#[derive(Debug, Serialize)]
pub struct FileObservation {
    pub exists: Option<bool>,
    pub bytes: Option<u64>,
    pub error: Option<String>,
}

impl FileObservation {
    fn read(path: &Path) -> Self {
        match std::fs::metadata(path) {
            Ok(metadata) => Self {
                exists: Some(true),
                bytes: Some(metadata.len()),
                error: None,
            },
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Self {
                exists: Some(false),
                bytes: None,
                error: None,
            },
            Err(error) => Self {
                exists: None,
                bytes: None,
                error: Some(error.to_string()),
            },
        }
    }

    fn sidecar(path: &Path, suffix: &str) -> Self {
        let mut name = path.as_os_str().to_os_string();
        name.push(suffix);
        Self::read(Path::new(&name))
    }

    fn is_missing(&self) -> bool {
        self.exists == Some(false) && self.bytes.is_none() && self.error.is_none()
    }
}

#[derive(Debug, Serialize)]
pub struct CheckpointObservation {
    pub busy: i64,
    pub log_frames: i64,
    pub checkpointed_frames: i64,
}

#[derive(Debug, Serialize)]
pub struct StepObservation {
    pub result: &'static str,
    pub error: Option<String>,
}

impl StepObservation {
    fn skipped() -> Self {
        Self {
            result: "NOT_ATTEMPTED",
            error: None,
        }
    }

    fn ok() -> Self {
        Self {
            result: "OK",
            error: None,
        }
    }

    fn error(error: impl ToString) -> Self {
        Self {
            result: "ERROR",
            error: Some(error.to_string()),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct SourceObservation {
    pub connection_path: Option<String>,
    pub path_matches: bool,
    pub synchronous: Option<i64>,
    pub page_count: Option<u64>,
    pub page_size: Option<u64>,
    pub query_errors: Vec<String>,
    pub autocommit_before_checkpoint: bool,
    pub checkpoint: Option<CheckpointObservation>,
    pub checkpoint_error: Option<String>,
    pub close: StepObservation,
    pub wal_before_checkpoint: FileObservation,
    pub wal_after_checkpoint: FileObservation,
    pub wal_after_close: FileObservation,
}

#[derive(Debug, Serialize)]
pub struct ExportObservation {
    pub destination_before: FileObservation,
    pub vacuum_into: StepObservation,
    pub open: StepObservation,
    pub journal_mode: Option<String>,
    pub page_count: Option<u64>,
    pub page_size: Option<u64>,
    pub query_errors: Vec<String>,
    pub close: StepObservation,
    pub header_prefix_hex: Option<String>,
    pub header_error: Option<String>,
    pub file_after_close: FileObservation,
    pub wal_after_close: FileObservation,
    pub shm_after_close: FileObservation,
    pub journal_after_close: FileObservation,
}

#[derive(Debug, Serialize)]
pub struct ArtifactFinalization {
    pub schema: &'static str,
    pub result: &'static str,
    pub sqlite_version: String,
    pub method: &'static str,
    pub source_database: PathBuf,
    pub export_database: PathBuf,
    pub source: SourceObservation,
    pub export: ExportObservation,
}

/// Keep live SQLite files outside the independent checker's export directory.
pub fn create_working_archive_path(output: &Path) -> Result<PathBuf, String> {
    let mut name = output
        .file_name()
        .ok_or("an export directory name is required")?
        .to_os_string();
    name.push("-working");
    let working = output.with_file_name(name);
    std::fs::create_dir(&working)
        .map_err(|error| format!("fresh working directory {}: {error}", working.display()))?;
    Ok(working.join("archive.sqlite"))
}

fn observed_query<T>(
    result: rusqlite::Result<T>,
    name: &str,
    errors: &mut Vec<String>,
) -> Option<T> {
    match result {
        Ok(value) => Some(value),
        Err(error) => {
            errors.push(format!("{name}: {error}"));
            None
        }
    }
}

fn close_connection(db: Connection) -> StepObservation {
    match db.close() {
        Ok(()) => StepObservation::ok(),
        Err((_connection, error)) => StepObservation::error(error),
    }
}

/// Also exercised directly with committed, uncheckpointed WAL in a native test.
pub(super) fn vacuum_into(db: &Connection, export: &Path) -> StepObservation {
    if !FileObservation::read(export).is_missing() {
        return StepObservation::error("export target must not already exist");
    }
    let Some(filename) = export.to_str() else {
        return StepObservation::error("export target must be a UTF-8 SQLite filename");
    };
    match db.execute("VACUUM main INTO ?1", [filename]) {
        Ok(_) => StepObservation::ok(),
        Err(error) => StepObservation::error(error),
    }
}

/// Export from the still-open source connection into a separate SQLite snapshot.
///
/// This is SQLite's logical snapshot operation, not a copy of the main file. A
/// source checkpoint that returns busy still rejects. Source sidecar observations
/// are retained without claiming that their paths stay stable after source close.
/// The export must independently be a closed DELETE-mode database with header
/// versions 1/1 and no WAL, SHM or rollback journal. Observed SQLite and inspection
/// failures are written before deciding acceptance; receipt I/O failures also
/// return an error and may leave a partial receipt. There is no retry, fallback,
/// manual cleanup or activation.
pub fn finish_archive_artifact(
    db: Connection,
    path: &Path,
    output: &Path,
) -> Result<ArtifactFinalization, String> {
    let export_path = output.join("archive.sqlite");
    let mut source_errors = Vec::new();
    let connection_path: Option<String> = observed_query(
        db.query_row(
            "SELECT file FROM pragma_database_list WHERE name='main'",
            [],
            |row| row.get(0),
        ),
        "main database path",
        &mut source_errors,
    );
    let path_matches = connection_path.as_ref().is_some_and(|actual| {
        match (std::fs::canonicalize(actual), std::fs::canonicalize(path)) {
            (Ok(actual), Ok(expected)) => actual == expected,
            _ => false,
        }
    });
    let synchronous: Option<i64> = observed_query(
        db.query_row("PRAGMA synchronous", [], |row| row.get(0)),
        "synchronous",
        &mut source_errors,
    );
    let source_page_count: Option<u64> = observed_query(
        db.query_row("PRAGMA page_count", [], |row| row.get(0)),
        "page_count",
        &mut source_errors,
    );
    let source_page_size: Option<u64> = observed_query(
        db.query_row("PRAGMA page_size", [], |row| row.get(0)),
        "page_size",
        &mut source_errors,
    );
    let autocommit_before_checkpoint = db.is_autocommit();
    let wal_before_checkpoint = FileObservation::sidecar(path, "-wal");
    let checkpoint_result = db.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| {
        Ok(CheckpointObservation {
            busy: row.get(0)?,
            log_frames: row.get(1)?,
            checkpointed_frames: row.get(2)?,
        })
    });
    let (checkpoint, checkpoint_error) = match checkpoint_result {
        Ok(observed) => (Some(observed), None),
        Err(error) => (None, Some(error.to_string())),
    };
    let wal_after_checkpoint = FileObservation::sidecar(path, "-wal");
    let source_qualified = path_matches
        && source_errors.is_empty()
        && autocommit_before_checkpoint
        && checkpoint.as_ref().is_some_and(|observed| {
            observed.busy == 0 && observed.log_frames == 0 && observed.checkpointed_frames == 0
        });
    let destination_before = FileObservation::read(&export_path);
    let vacuum = if source_qualified && destination_before.is_missing() {
        vacuum_into(&db, &export_path)
    } else {
        StepObservation::skipped()
    };
    let source_close = close_connection(db);
    let wal_after_close = FileObservation::sidecar(path, "-wal");

    let mut export_open = StepObservation::skipped();
    let mut journal_mode: Option<String> = None;
    let mut page_count: Option<u64> = None;
    let mut page_size: Option<u64> = None;
    let mut export_errors = Vec::new();
    let mut export_close = StepObservation::skipped();
    let mut header_prefix_hex = None;
    let mut header_error = None;
    let mut header_valid = false;
    if vacuum.result == "OK" {
        match Connection::open_with_flags(&export_path, OpenFlags::SQLITE_OPEN_READ_ONLY) {
            Ok(reader) => {
                export_open = StepObservation::ok();
                journal_mode = observed_query(
                    reader.query_row("PRAGMA journal_mode", [], |row| row.get(0)),
                    "journal_mode",
                    &mut export_errors,
                );
                page_count = observed_query(
                    reader.query_row("PRAGMA page_count", [], |row| row.get(0)),
                    "page_count",
                    &mut export_errors,
                );
                page_size = observed_query(
                    reader.query_row("PRAGMA page_size", [], |row| row.get(0)),
                    "page_size",
                    &mut export_errors,
                );
                export_close = close_connection(reader);
            }
            Err(error) => export_open = StepObservation::error(error),
        }
        let read_header = (|| -> std::io::Result<[u8; 20]> {
            let mut file = std::fs::File::open(&export_path)?;
            let mut header = [0; 20];
            file.read_exact(&mut header)?;
            Ok(header)
        })();
        match read_header {
            Ok(header) => {
                header_valid =
                    &header[..16] == b"SQLite format 3\0" && header[18] == 1 && header[19] == 1;
                header_prefix_hex = Some(hex::encode(header));
            }
            Err(error) => header_error = Some(error.to_string()),
        }
    }
    let file_after_close = FileObservation::read(&export_path);
    let export_wal = FileObservation::sidecar(&export_path, "-wal");
    let export_shm = FileObservation::sidecar(&export_path, "-shm");
    let export_journal = FileObservation::sidecar(&export_path, "-journal");
    let geometry_matches = match (page_count, page_size) {
        (Some(count), Some(size)) if count > 0 && size > 0 => count
            .checked_mul(size)
            .is_some_and(|bytes| file_after_close.bytes == Some(bytes)),
        _ => false,
    };
    let accepted = source_qualified
        && source_close.result == "OK"
        && destination_before.is_missing()
        && vacuum.result == "OK"
        && export_open.result == "OK"
        && journal_mode.as_deref() == Some("delete")
        && export_errors.is_empty()
        && export_close.result == "OK"
        && header_valid
        && geometry_matches
        && file_after_close.error.is_none()
        && export_wal.is_missing()
        && export_shm.is_missing()
        && export_journal.is_missing();
    let receipt = ArtifactFinalization {
        schema: "pon-account-archive-snapshot-finalization-v1",
        result: if accepted { "PASS" } else { "FAIL" },
        sqlite_version: rusqlite::version().into(),
        method: "VACUUM main INTO ?1",
        source_database: path.to_path_buf(),
        export_database: export_path,
        source: SourceObservation {
            connection_path,
            path_matches,
            synchronous,
            page_count: source_page_count,
            page_size: source_page_size,
            query_errors: source_errors,
            autocommit_before_checkpoint,
            checkpoint,
            checkpoint_error,
            close: source_close,
            wal_before_checkpoint,
            wal_after_checkpoint,
            wal_after_close,
        },
        export: ExportObservation {
            destination_before,
            vacuum_into: vacuum,
            open: export_open,
            journal_mode,
            page_count,
            page_size,
            query_errors: export_errors,
            close: export_close,
            header_prefix_hex,
            header_error,
            file_after_close,
            wal_after_close: export_wal,
            shm_after_close: export_shm,
            journal_after_close: export_journal,
        },
    };
    let bytes = serde_json::to_vec(&receipt).map_err(|error| error.to_string())?;
    let receipt_path = output.join("finalization.json");
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&receipt_path)
        .map_err(|error| format!("write {}: {error}", receipt_path.display()))?;
    file.write_all(&bytes).map_err(|error| error.to_string())?;
    file.sync_all().map_err(|error| error.to_string())?;
    if accepted {
        Ok(receipt)
    } else {
        Err(format!(
            "archive snapshot export failed; actual receipt: {}",
            receipt_path.display()
        ))
    }
}
