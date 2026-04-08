use anyhow::{anyhow, Result};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use super::{
    normalize_wrapped_env_value, MARKET_LOCK_TIMEOUT_MS_DEFAULT, MARKET_LOCK_TIMEOUT_MS_MAX,
    MARKET_LOCK_TIMEOUT_MS_MIN,
};

pub(crate) struct MarketFileLock {
    lock_path: PathBuf,
}

impl Drop for MarketFileLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.lock_path);
    }
}

pub(crate) fn market_lock_path(path: &Path) -> PathBuf {
    let file_name = path
        .file_name()
        .and_then(|v| v.to_str())
        .unwrap_or("market-data");
    path.with_file_name(format!("{}.lock", file_name))
}

pub(crate) fn market_lock_stale_after_ms() -> Option<u128> {
    let raw = std::env::var("TRNM_RPC_MARKET_LOCK_STALE_MS").ok()?;
    let normalized = normalize_wrapped_env_value(&raw);
    if normalized.is_empty() {
        return None;
    }
    let parsed = normalized.parse::<u128>().ok()?;
    Some(parsed.clamp(1_000, 15 * 60 * 1_000))
}

pub(crate) fn market_lock_timeout_ms() -> u64 {
    let raw = match std::env::var("TRNM_RPC_MARKET_LOCK_TIMEOUT_MS") {
        Ok(v) => v,
        Err(_) => return MARKET_LOCK_TIMEOUT_MS_DEFAULT,
    };
    let normalized = normalize_wrapped_env_value(&raw);
    if normalized.is_empty() {
        return MARKET_LOCK_TIMEOUT_MS_DEFAULT;
    }
    let parsed = match normalized.parse::<u64>() {
        Ok(v) => v,
        Err(_) => return MARKET_LOCK_TIMEOUT_MS_DEFAULT,
    };
    parsed.clamp(MARKET_LOCK_TIMEOUT_MS_MIN, MARKET_LOCK_TIMEOUT_MS_MAX)
}

pub(crate) fn acquire_market_file_lock(path: &Path) -> Result<MarketFileLock> {
    let lock_path = market_lock_path(path);
    if let Some(parent) = lock_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let stale_after_ms = market_lock_stale_after_ms();
    let timeout = Duration::from_millis(market_lock_timeout_ms());
    let start = Instant::now();
    loop {
        match OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&lock_path)
        {
            Ok(mut file) => {
                writeln!(file, "{}", std::process::id())?;
                return Ok(MarketFileLock { lock_path });
            }
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                if let Some(stale_after_ms) = stale_after_ms {
                    if let Ok(meta) = fs::metadata(&lock_path) {
                        if let Ok(modified) = meta.modified() {
                            let now = SystemTime::now();
                            if let Ok(elapsed) = now.duration_since(modified) {
                                if elapsed.as_millis() > stale_after_ms {
                                    let _ = fs::remove_file(&lock_path);
                                    continue;
                                }
                            }
                        }
                    }
                }
                if start.elapsed() >= timeout {
                    return Err(anyhow!(
                        "timed out waiting for market file lock after {}ms: {}",
                        timeout.as_millis(),
                        lock_path.display()
                    ));
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(err) => {
                return Err(anyhow!(
                    "failed to acquire market file lock {}: {}",
                    lock_path.display(),
                    err
                ));
            }
        }
    }
}

pub(crate) fn write_string_atomically(path: &Path, content: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let ts = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let tmp = path.with_file_name(format!(
        ".{}.tmp.{}.{}",
        path.file_name()
            .and_then(|v| v.to_str())
            .unwrap_or("market"),
        std::process::id(),
        ts
    ));

    fs::write(&tmp, content)?;
    if let Err(err) = fs::rename(&tmp, path) {
        let _ = fs::remove_file(&tmp);
        return Err(err.into());
    }
    Ok(())
}
