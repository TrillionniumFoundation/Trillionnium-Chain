use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{anyhow, Result};

use crate::envpaths::{
    market_bids_file, market_lock_stale_after_ms, market_lock_timeout_ms, market_reputation_file,
    market_tasks_file,
};
use crate::{MarketBid, MarketTask};

pub(crate) struct MarketFileLock {
    pub(crate) lock_path: PathBuf,
}

impl Drop for MarketFileLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.lock_path);
    }
}

#[cfg(test)]
pub(crate) fn market_lock_path(path: &Path) -> PathBuf {
    let file_name = path
        .file_name()
        .and_then(|v| v.to_str())
        .unwrap_or("market-data");
    path.with_file_name(format!("{}.lock", file_name))
}

#[cfg(not(test))]
fn market_lock_path(path: &Path) -> PathBuf {
    let file_name = path
        .file_name()
        .and_then(|v| v.to_str())
        .unwrap_or("market-data");
    path.with_file_name(format!("{}.lock", file_name))
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
                            if let Ok(elapsed) = SystemTime::now().duration_since(modified) {
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

fn write_string_atomically(path: &Path, content: &str) -> Result<()> {
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

pub(crate) fn load_market_tasks() -> Vec<MarketTask> {
    let path = market_tasks_file();
    let Ok(raw) = fs::read_to_string(path) else {
        return vec![];
    };
    raw.lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| serde_json::from_str::<MarketTask>(l).ok())
        .collect()
}

pub(crate) fn save_market_tasks(tasks: &[MarketTask]) -> Result<()> {
    let path = market_tasks_file();
    let mut out = String::new();
    for t in tasks {
        out.push_str(&serde_json::to_string(t)?);
        out.push('\n');
    }
    write_string_atomically(&path, &out)
}

pub(crate) fn load_market_bids() -> Vec<MarketBid> {
    let path = market_bids_file();
    let Ok(raw) = fs::read_to_string(path) else {
        return vec![];
    };
    raw.lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| serde_json::from_str::<MarketBid>(l).ok())
        .collect()
}

pub(crate) fn save_market_bids(bids: &[MarketBid]) -> Result<()> {
    let path = market_bids_file();
    let mut out = String::new();
    for b in bids {
        out.push_str(&serde_json::to_string(b)?);
        out.push('\n');
    }
    write_string_atomically(&path, &out)
}

pub(crate) fn normalize_market_worker_key(raw: &str) -> Option<String> {
    let sanitized = raw
        .trim()
        .chars()
        .filter_map(|ch| match ch {
            '\u{200B}' | '\u{200C}' | '\u{200D}' | '\u{2060}' | '\u{FEFF}' => Some(' '),
            '\u{00AD}' => None,
            _ if ch.is_whitespace() || ch.is_control() => Some(' '),
            _ => Some(ch),
        })
        .collect::<String>();
    let normalized = sanitized
        .to_ascii_lowercase()
        .split_ascii_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    if normalized.is_empty() {
        None
    } else {
        Some(normalized)
    }
}

pub(crate) fn market_worker_tie_break_key(raw: &str) -> String {
    normalize_market_worker_key(raw).unwrap_or_else(|| raw.trim().to_ascii_lowercase())
}

pub(crate) fn normalize_market_status_key(raw: &str) -> String {
    raw.trim()
        .chars()
        .filter_map(|ch| match ch {
            '\u{00AD}' => None,
            '\u{200B}' | '\u{200C}' | '\u{200D}' | '\u{2060}' | '\u{FEFF}' => Some(' '),
            _ if ch.is_whitespace() || ch.is_control() => Some(' '),
            _ => Some(ch),
        })
        .collect::<String>()
        .to_ascii_lowercase()
        .split_ascii_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn parse_market_reputation_value(value: &serde_json::Value) -> Option<i64> {
    value
        .as_i64()
        .or_else(|| {
            let float = value.as_f64()?;
            if !float.is_finite() || float.fract() != 0.0 {
                return None;
            }
            if float < i64::MIN as f64 || float > i64::MAX as f64 {
                return None;
            }
            Some(float as i64)
        })
        .or_else(|| value.as_str()?.trim().parse::<i64>().ok())
}

pub(crate) fn load_market_reputation() -> std::collections::BTreeMap<String, i64> {
    let path = market_reputation_file();
    let Ok(raw) = fs::read_to_string(path) else {
        return std::collections::BTreeMap::new();
    };

    let parsed = serde_json::from_str::<serde_json::Value>(&raw)
        .ok()
        .and_then(|value| value.as_object().cloned())
        .unwrap_or_default();

    let mut normalized: std::collections::BTreeMap<String, i64> = std::collections::BTreeMap::new();
    for (worker, rep_value) in parsed {
        let Some(rep) = parse_market_reputation_value(&rep_value) else {
            continue;
        };
        if let Some(key) = normalize_market_worker_key(&worker) {
            normalized
                .entry(key)
                .and_modify(|existing| *existing = (*existing).max(rep))
                .or_insert(rep);
        }
    }
    normalized
}
