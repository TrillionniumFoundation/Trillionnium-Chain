//! Finalization for retained research fixtures, never a production archive hook.
use rusqlite::Connection;
use serde::Serialize;
use std::io::Write;
use std::path::Path;

#[derive(Debug, Serialize)]
pub struct WalObservation {
    pub exists: Option<bool>,
    pub bytes: Option<u64>,
    pub error: Option<String>,
}

impl WalObservation {
    fn read(path: &Path) -> Self {
        let mut wal = path.as_os_str().to_os_string();
        wal.push("-wal");
        match std::fs::metadata(wal) {
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

    fn is_empty(&self) -> bool {
        self.error.is_none()
            && matches!(
                (self.exists, self.bytes),
                (Some(false), None) | (Some(true), Some(0))
            )
    }
}

#[derive(Debug, Serialize)]
pub struct CheckpointObservation {
    pub busy: i64,
    pub log_frames: i64,
    pub checkpointed_frames: i64,
}

#[derive(Debug, Serialize)]
pub struct CloseObservation {
    pub result: &'static str,
    pub error: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ArtifactFinalization {
    pub schema: &'static str,
    pub result: &'static str,
    pub sqlite_version: String,
    pub autocommit_before_checkpoint: bool,
    pub checkpoint: Option<CheckpointObservation>,
    pub checkpoint_error: Option<String>,
    pub control_connection_close: CloseObservation,
    pub wal_before_checkpoint: WalObservation,
    pub wal_after_checkpoint: WalObservation,
    pub wal_after_close: WalObservation,
}

/// Consume the final control connection after all archive handles leave scope.
///
/// PRAGMA execution can succeed while its returned `busy` column reports failure.
/// A successful explicit close also does not certify that SQLite removed its WAL.
/// Preserve the actual observations before rejecting either condition. This helper
/// never removes or truncates a file itself, and never retries a failed checkpoint.
pub fn finish_archive_artifact(
    db: Connection,
    path: &Path,
    output: &Path,
) -> Result<ArtifactFinalization, String> {
    let autocommit_before_checkpoint = db.is_autocommit();
    let wal_before_checkpoint = WalObservation::read(path);
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
    let wal_after_checkpoint = WalObservation::read(path);
    let control_connection_close = match db.close() {
        Ok(()) => CloseObservation {
            result: "OK",
            error: None,
        },
        Err((_connection, error)) => CloseObservation {
            result: "ERROR",
            error: Some(error.to_string()),
        },
    };
    let wal_after_close = WalObservation::read(path);
    let accepted = autocommit_before_checkpoint
        && checkpoint.as_ref().is_some_and(|observed| {
            observed.busy == 0 && observed.log_frames == 0 && observed.checkpointed_frames == 0
        })
        && control_connection_close.result == "OK"
        && wal_before_checkpoint.error.is_none()
        && wal_after_checkpoint.is_empty()
        && wal_after_close.is_empty();
    let receipt = ArtifactFinalization {
        schema: "pon-account-archive-finalization-v1",
        result: if accepted { "PASS" } else { "FAIL" },
        sqlite_version: rusqlite::version().into(),
        autocommit_before_checkpoint,
        checkpoint,
        checkpoint_error,
        control_connection_close,
        wal_before_checkpoint,
        wal_after_checkpoint,
        wal_after_close,
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
            "archive artifact finalization failed; actual receipt: {}",
            receipt_path.display()
        ))
    }
}
