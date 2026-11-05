//! Private, crash-consistent owner record for automatic commit/reveal salts.
//!
//! New automatic submissions use an OS CSPRNG salt; the existing on-chain
//! commit/reveal hash and historical records are unchanged. The full private
//! record must be synced before any adapter can consume it. All decisions are
//! local to the original worker owner and never grant chain or model authority.
use crate::{commitment, now_ms, SubmissionRecord};
use anyhow::{ensure, Context, Result};
use rustix::fs::{flock, openat, FlockOperation, Mode, OFlags, CWD};
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::sync::{Mutex, OnceLock};

const MAX_LOG_BYTES: u64 = 64 * 1024 * 1024;

// One process-local owner for BOTH manual and automatic submissions. The
// inode flock separately coordinates independent processes using this path.
static LOCAL_OWNER: OnceLock<Mutex<()>> = OnceLock::new();

pub(crate) fn append_private_manual_submission(path: &Path, line: &str) -> Result<()> {
    ensure!(
        !line.contains('\n') && !line.contains('\r'),
        "manual submission requires one complete JSON line"
    );
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let _local_lock = LOCAL_OWNER
        .get_or_init(|| Mutex::new(()))
        .lock()
        .map_err(|_| anyhow::anyhow!("submission owner lock poisoned"))?;
    let descriptor = openat(
        CWD,
        path,
        OFlags::RDWR | OFlags::APPEND | OFlags::CREATE | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::RUSR | Mode::WUSR,
    )?;
    let mut file = File::from(descriptor);
    flock(&file, FlockOperation::LockExclusive)?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file()
            && metadata.nlink() == 1
            && metadata.uid() == rustix::process::geteuid().as_raw()
            && metadata.mode() & 0o077 == 0
            && metadata.mode() & 0o200 != 0,
        "private manual submission journal required"
    );
    let appended = u64::try_from(line.len())?
        .checked_add(1)
        .ok_or_else(|| anyhow::anyhow!("manual submission length overflow"))?;
    ensure!(
        metadata
            .len()
            .checked_add(appended)
            .is_some_and(|total| total <= MAX_LOG_BYTES),
        "manual submission journal capacity"
    );
    if metadata.len() != 0 {
        file.seek(SeekFrom::End(-1))?;
        let mut last = [0_u8; 1];
        file.read_exact(&mut last)?;
        ensure!(last[0] == b'\n', "incomplete manual submission log");
    }
    file.seek(SeekFrom::End(0))?;
    file.write_all(line.as_bytes())?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    let named = fs::symlink_metadata(path)?;
    ensure!(
        named.dev() == metadata.dev() && named.ino() == metadata.ino(),
        "manual submission journal replaced during append"
    );
    if let Some(parent) = path.parent() {
        File::open(parent)?.sync_all()?;
    }
    Ok(())
}

pub(crate) fn journal_automatic_submission(
    path: &Path,
    task_id: u64,
    worker: &str,
    result_hash: &str,
    proposed_salt: &str,
) -> Result<String> {
    ensure!(
        worker.len() <= 4096 && !worker.is_empty(),
        "invalid worker identity"
    );
    ensure!(
        result_hash.len() == 64 && result_hash.bytes().all(|x| x.is_ascii_hexdigit()),
        "invalid result digest"
    );
    ensure!(
        proposed_salt.len() == 64 && proposed_salt.bytes().all(|x| x.is_ascii_hexdigit()),
        "invalid proposed salt"
    );
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    // POSIX record locks may be owned by the process rather than the FD.
    // Serialize same-process threads as well as independent processes.
    let _local_lock = LOCAL_OWNER
        .get_or_init(|| Mutex::new(()))
        .lock()
        .map_err(|_| anyhow::anyhow!("submission owner lock poisoned"))?;
    // One retained inode is both the local journal and the kernel lock. Locks
    // release on process death, unlike stale PID/lock marker files. NOFOLLOW
    // forbids swapping a last-component link onto somebody else's journal.
    let descriptor = openat(
        CWD,
        path,
        OFlags::RDWR | OFlags::APPEND | OFlags::CREATE | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::RUSR | Mode::WUSR,
    )?;
    let mut file = File::from(descriptor);
    flock(&file, FlockOperation::LockExclusive)?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file()
            && metadata.nlink() == 1
            && metadata.uid() == rustix::process::geteuid().as_raw()
            && metadata.mode() & 0o077 == 0
            && metadata.mode() & 0o200 != 0,
        "private automatic submission journal required"
    );
    ensure!(metadata.len() <= MAX_LOG_BYTES, "submission log capacity");
    file.seek(SeekFrom::Start(0))?;
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(MAX_LOG_BYTES + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= MAX_LOG_BYTES,
        "submission log capacity"
    );
    ensure!(
        bytes.is_empty() || bytes.ends_with(b"\n"),
        "incomplete submission log; refuse replay"
    );
    let contents = std::str::from_utf8(&bytes)?;
    let mut prior: Option<SubmissionRecord> = None;
    for line in contents.lines() {
        ensure!(!line.is_empty(), "empty submission log row");
        let existing: SubmissionRecord =
            serde_json::from_str(line).context("invalid submission log row")?;
        if existing.task_id != task_id {
            continue;
        }
        ensure!(
            existing.worker == worker && existing.result_hash == result_hash,
            "conflicting task submission identity"
        );
        ensure!(
            existing.commit_cmd
                == crate::workflow_ops::commit_template(
                    task_id,
                    worker,
                    &existing.commit_hash,
                    task_id,
                )
                && existing.reveal_cmd
                    == crate::workflow_ops::reveal_template(
                        task_id,
                        result_hash,
                        &existing.salt_hex,
                    )
                && existing.nonce == Some(task_id)
                && existing.salt_hex.len() == 64
                && existing.salt_hex.bytes().all(|c| c.is_ascii_hexdigit())
                && existing.commit_hash
                    == commitment(task_id, result_hash, &existing.salt_hex, worker),
            "tampered retained commitment"
        );
        match &prior {
            None => prior = Some(existing),
            Some(old) => ensure!(
                old.salt_hex == existing.salt_hex && old.commit_hash == existing.commit_hash,
                "conflicting duplicate submission records"
            ),
        }
    }
    if let Some(retained) = prior {
        // Reopen/resume must still address the same private retained inode.
        // A renamed or swapped journal cannot silently select a new identity.
        let named = fs::symlink_metadata(path)?;
        ensure!(
            named.dev() == metadata.dev() && named.ino() == metadata.ino(),
            "retained submission journal replaced during replay"
        );
        return Ok(retained.salt_hex);
    }
    let commit_hash = commitment(task_id, result_hash, proposed_salt, worker);
    let record = SubmissionRecord {
        ts_unix_ms: now_ms(),
        task_id,
        worker: worker.into(),
        nonce: Some(task_id),
        commit_hash: commit_hash.clone(),
        result_hash: result_hash.into(),
        salt_hex: proposed_salt.into(),
        commit_cmd: crate::workflow_ops::commit_template(task_id, worker, &commit_hash, task_id),
        reveal_cmd: crate::workflow_ops::reveal_template(task_id, result_hash, proposed_salt),
    };
    let encoded = serde_json::to_vec(&record)?;
    ensure!(
        metadata
            .len()
            .checked_add(encoded.len() as u64 + 1)
            .is_some_and(|length| length <= MAX_LOG_BYTES),
        "submission log capacity"
    );
    file.seek(SeekFrom::End(0))?;
    file.write_all(&encoded)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    let path_metadata = fs::symlink_metadata(path)?;
    ensure!(
        path_metadata.dev() == metadata.dev() && path_metadata.ino() == metadata.ino(),
        "submission journal replaced during commit"
    );
    if let Some(parent) = path.parent() {
        File::open(parent)?.sync_all()?;
    }
    Ok(proposed_salt.to_string())
}
