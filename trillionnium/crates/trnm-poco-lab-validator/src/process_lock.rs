//! Process-local exclusivity for one validator runtime namespace.
//!
//! A deployment root is an identity boundary: starting two validator
//! processes against the same root would otherwise let them race on the
//! signer journal, replay archive, runtime event journal, and TCP listener.
//! The lock is advisory at the OS level but is acquired before any runtime
//! effect and held for the complete process lifetime.  `flock` releases it
//! automatically when a process dies, so a crashed validator can be restarted
//! without deleting or trusting a stale marker file.

use std::{
    fs::{File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

use anyhow::{Context, Result};
use fs2::FileExt;

/// The lock file name is deliberately stable and excluded from signed
/// evidence inventories.  Its contents are diagnostic only; authority comes
/// from the kernel lock, not from this text.
pub const VALIDATOR_PROCESS_LOCK_FILE_V1: &str = "validator-process.lock";

#[derive(Debug)]
pub struct ValidatorProcessLockV1 {
    file: File,
    path: PathBuf,
}

impl ValidatorProcessLockV1 {
    /// Acquire the exclusive lock for one validator run root.
    pub fn acquire(run_root: &Path, run_id: &str, validator_id: &str) -> Result<Self> {
        let path = run_root.join(VALIDATOR_PROCESS_LOCK_FILE_V1);
        let mut options = OpenOptions::new();
        options.create(true).read(true).write(true);
        #[cfg(unix)]
        options.mode(0o600).custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
        let file = options
            .open(&path)
            .with_context(|| format!("open validator process lock {}", path.display()))?;
        file.try_lock_exclusive().with_context(|| {
            format!(
                "validator process lock is already held for {} (run_id={run_id}, validator_id={validator_id})",
                run_root.display()
            )
        })?;

        // Keep only bounded, non-authoritative diagnostics.  Writing happens
        // after the lock is held, and sync makes the marker useful when
        // investigating a crash without turning it into an activation fact.
        file.set_len(0).context("truncate validator process lock marker")?;
        let mut marker = format!(
            "schema=trnm.validator-process-lock.v1\nrun_id={run_id}\nvalidator_id={validator_id}\npid={}\n",
            std::process::id()
        );
        marker.truncate(1024);
        (&file)
            .write_all(marker.as_bytes())
            .context("write validator process lock marker")?;
        file.sync_all()
            .context("sync validator process lock marker")?;
        Ok(Self { file, path })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for ValidatorProcessLockV1 {
    fn drop(&mut self) {
        // Explicit unlock gives deterministic handoff in tests and normal
        // shutdown.  Kernel process teardown remains the crash-safety backstop.
        let _ = self.file.unlock();
    }
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::*;

    #[test]
    fn lock_excludes_second_process_owner_and_reopens_after_drop() {
        let directory = tempdir().expect("temporary run root");
        let first = ValidatorProcessLockV1::acquire(directory.path(), "run-a", "validator-a")
            .expect("first owner acquires lock");
        assert!(
            ValidatorProcessLockV1::acquire(directory.path(), "run-a", "validator-a").is_err(),
            "one runtime root must not have two owners"
        );
        drop(first);
        ValidatorProcessLockV1::acquire(directory.path(), "run-a", "validator-a")
            .expect("lock is released on clean owner shutdown");
    }
}
