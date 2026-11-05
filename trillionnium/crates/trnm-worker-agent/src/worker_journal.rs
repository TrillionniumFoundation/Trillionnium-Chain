//! Bounded, durable local worker journals. Invalid history is never an empty log.
//! Locks retain one inode and release on process death; lock paths are never unlinked.
use anyhow::{anyhow, ensure, Context, Result};
use serde::{de::DeserializeOwned, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

pub(crate) const MAX_LOG_BYTES: u64 = 64 * 1024 * 1024;
pub(crate) const MAX_LOG_RECORDS: usize = 100_000;

fn parent(path: &Path) -> &Path {
    path.parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

fn open_regular(path: &Path, writable: bool, create: bool) -> Result<File> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(writable)
        .create(create)
        .truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(
            (rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32,
        );
    }
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    ensure!(metadata.is_file(), "worker journal requires a regular file");
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        ensure!(
            metadata.nlink() == 1
                && metadata.uid() == rustix::process::geteuid().as_raw()
                && metadata.mode() & 0o022 == 0,
            "worker journal must be owned locally and not writable by other users"
        );
    }
    Ok(file)
}

fn try_lock(file: &File, exclusive: bool) -> Result<bool> {
    #[cfg(unix)]
    {
        use rustix::fs::{flock, FlockOperation};
        let operation = if exclusive {
            FlockOperation::NonBlockingLockExclusive
        } else {
            FlockOperation::NonBlockingLockShared
        };
        match flock(file, operation) {
            Ok(()) => Ok(true),
            Err(rustix::io::Errno::AGAIN) => Ok(false),
            Err(error) => Err(error.into()),
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (file, exclusive);
        anyhow::bail!("durable worker journal locking is unavailable on this platform")
    }
}

fn lock_for_io(file: &File, exclusive: bool) -> Result<()> {
    // A concurrent append or the short fork/exec descriptor lifetime may
    // retain a lock. Wait within one fixed deadline, never reset it on retry.
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(500);
    loop {
        if try_lock(file, exclusive)? {
            return Ok(());
        }
        ensure!(
            std::time::Instant::now() < deadline,
            "worker journal lock deadline"
        );
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
}

fn check_named_file(path: &Path, file: &File) -> Result<()> {
    let named = fs::symlink_metadata(path)?;
    let opened = file.metadata()?;
    ensure!(named.is_file(), "worker journal path was replaced");
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        ensure!(
            named.dev() == opened.dev() && named.ino() == opened.ino(),
            "worker journal inode was replaced"
        );
    }
    #[cfg(not(unix))]
    let _ = opened;
    Ok(())
}

pub(crate) fn try_lock_path(path: &Path) -> Result<Option<File>> {
    fs::create_dir_all(parent(path))?;
    let file = open_regular(path, true, true)?;
    if !try_lock(&file, true)? {
        return Ok(None);
    }
    check_named_file(path, &file)?;
    Ok(Some(file))
}

fn read_locked(file: &mut File) -> Result<Vec<u8>> {
    ensure!(
        file.metadata()?.len() <= MAX_LOG_BYTES,
        "worker journal byte capacity"
    );
    file.seek(SeekFrom::Start(0))?;
    let mut bytes = Vec::new();
    Read::by_ref(file)
        .take(MAX_LOG_BYTES + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= MAX_LOG_BYTES,
        "worker journal byte capacity"
    );
    ensure!(
        bytes.is_empty() || bytes.ends_with(b"\n"),
        "incomplete worker journal record"
    );
    let raw = std::str::from_utf8(&bytes)?;
    ensure!(
        raw.lines()
            .filter(|line| !line.trim().is_empty())
            .take(MAX_LOG_RECORDS + 1)
            .count()
            <= MAX_LOG_RECORDS,
        "worker journal record capacity"
    );
    Ok(bytes)
}

pub(crate) fn read_raw(path: &Path) -> Result<Vec<u8>> {
    let mut file = match open_regular(path, false, false) {
        Ok(file) => file,
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|io| io.kind() == std::io::ErrorKind::NotFound) =>
        {
            return Ok(Vec::new())
        }
        Err(error) => return Err(error),
    };
    lock_for_io(&file, false)?;
    check_named_file(path, &file)?;
    let bytes = read_locked(&mut file)?;
    check_named_file(path, &file)?;
    Ok(bytes)
}

pub(crate) fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<Vec<T>> {
    std::str::from_utf8(bytes)?
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).context("invalid worker journal record"))
        .collect()
}

pub(crate) fn read<T: DeserializeOwned>(path: &Path) -> Result<Vec<T>> {
    decode(&read_raw(path)?)
}

pub(crate) fn append(path: &Path, line: &str) -> Result<()> {
    ensure!(
        !line.contains(['\n', '\r']),
        "one complete JSON record is required"
    );
    let _: serde_json::Value = serde_json::from_str(line)?;
    fs::create_dir_all(parent(path))?;
    let mut file = open_regular(path, true, true)?;
    lock_for_io(&file, true)?;
    check_named_file(path, &file)?;
    let bytes = read_locked(&mut file)?;
    let records: Vec<serde_json::Value> = decode(&bytes)?;
    ensure!(
        records.len() < MAX_LOG_RECORDS,
        "worker journal record capacity"
    );
    let total = bytes
        .len()
        .checked_add(line.len())
        .and_then(|n| n.checked_add(1))
        .ok_or_else(|| anyhow!("worker journal length overflow"))?;
    ensure!(
        total as u64 <= MAX_LOG_BYTES,
        "worker journal byte capacity"
    );
    file.seek(SeekFrom::End(0))?;
    file.write_all(line.as_bytes())?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    check_named_file(path, &file)?;
    File::open(parent(path))?.sync_all()?;
    Ok(())
}

fn encode<T: Serialize>(records: &[T]) -> Result<Vec<u8>> {
    ensure!(
        records.len() <= MAX_LOG_RECORDS,
        "worker journal record capacity"
    );
    let mut bytes = Vec::new();
    for record in records {
        let encoded = serde_json::to_vec(record)?;
        let total = bytes
            .len()
            .checked_add(encoded.len())
            .and_then(|n| n.checked_add(1))
            .ok_or_else(|| anyhow!("worker journal length overflow"))?;
        ensure!(
            total as u64 <= MAX_LOG_BYTES,
            "worker journal byte capacity"
        );
        bytes.extend_from_slice(&encoded);
        bytes.push(b'\n');
    }
    Ok(bytes)
}

/// Atomically replace an ingress snapshot after its original read digest agrees.
pub(crate) fn replace<T: Serialize>(
    path: &Path,
    records: &[T],
    expected_digest: [u8; 32],
) -> Result<()> {
    use sha2::{Digest, Sha256};
    let bytes = encode(records)?;
    let _guard = lock_snapshot(path)?;
    let current: [u8; 32] = Sha256::digest(read_raw(path)?).into();
    ensure!(
        current == expected_digest,
        "ingress snapshot changed; reload before retry"
    );
    atomic_write(path, &bytes)
}

fn lock_snapshot(path: &Path) -> Result<File> {
    let base = path
        .file_name()
        .ok_or_else(|| anyhow!("journal filename required"))?;
    let mut lock_name = std::ffi::OsString::from(".");
    lock_name.push(base);
    lock_name.push(".snapshot.lock");
    let lock_path = parent(path).join(lock_name);
    fs::create_dir_all(parent(path))?;
    let guard = open_regular(&lock_path, true, true)?;
    lock_for_io(&guard, true)?;
    check_named_file(&lock_path, &guard)?;
    Ok(guard)
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let base = path
        .file_name()
        .ok_or_else(|| anyhow!("journal filename required"))?;
    let mut random = [0_u8; 16];
    getrandom::fill(&mut random).map_err(|error| anyhow!("snapshot entropy: {error}"))?;
    let mut temporary_name = std::ffi::OsString::from(".");
    temporary_name.push(base);
    temporary_name.push(format!(".{}.tmp", hex::encode(random)));
    let temporary = parent(path).join(temporary_name);
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32);
    }
    let mut file = options.open(&temporary)?;
    let result = (|| -> Result<()> {
        file.write_all(bytes)?;
        file.sync_all()?;
        check_named_file(&temporary, &file)?;
        fs::rename(&temporary, path)?;
        check_named_file(path, &file)?;
        File::open(parent(path))?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

pub(crate) fn next_task_id(path: &Path) -> Result<u64> {
    let _guard = lock_snapshot(path)?;
    let mut state = match open_regular(path, false, false) {
        Ok(mut file) => {
            ensure!(
                file.metadata()?.len() <= 4096,
                "worker task state byte capacity"
            );
            let mut bytes = Vec::new();
            Read::by_ref(&mut file).take(4097).read_to_end(&mut bytes)?;
            ensure!(bytes.len() <= 4096, "worker task state byte capacity");
            check_named_file(path, &file)?;
            serde_json::from_slice::<crate::WorkerState>(&bytes)?
        }
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|io| io.kind() == std::io::ErrorKind::NotFound) =>
        {
            crate::WorkerState { last_task_id: 1000 }
        }
        Err(error) => return Err(error),
    };
    state.last_task_id = state
        .last_task_id
        .checked_add(1)
        .ok_or_else(|| anyhow!("worker task identity exhausted"))?;
    let mut bytes = serde_json::to_vec_pretty(&state)?;
    bytes.push(b'\n');
    atomic_write(path, &bytes)?;
    Ok(state.last_task_id)
}
