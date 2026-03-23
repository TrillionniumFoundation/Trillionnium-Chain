use std::{
    collections::BTreeSet,
    fs::{self, OpenOptions},
    hash::{Hash, Hasher},
    io::Write,
    path::{Path, PathBuf},
};

use anyhow::{anyhow, Result};

use crate::envpaths::ingress_file;
use crate::fsutil::atomic_write_text_file;
use crate::market_io::acquire_market_file_lock;
use crate::runtime::now_ms;
use crate::{IngressQuarantineRecord, MessageIngressRecord};

pub(crate) fn ingress_quarantine_file_for(path: &Path) -> PathBuf {
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("requests.jsonl");
    path.with_file_name(format!("{}.quarantine.jsonl", file_name))
}

fn stable_line_hash(raw: &str) -> u64 {
    // Keep this deterministic across process restarts and toolchain/runtime changes
    // so quarantine dedupe remains stable for identical bad ingress rows.
    const FNV_OFFSET_BASIS: u64 = 0xcbf29ce484222325;
    const FNV_PRIME: u64 = 0x00000100000001B3;

    let mut hash = FNV_OFFSET_BASIS;
    for byte in raw.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

const MAX_INGRESS_QUARANTINE_RECORDS: usize = 256;
const MAX_INGRESS_QUARANTINE_RAW_LINE_BYTES: usize = 512;

fn truncate_quarantine_raw_line(raw: &str) -> String {
    if raw.len() <= MAX_INGRESS_QUARANTINE_RAW_LINE_BYTES {
        return raw.to_string();
    }

    let mut end = MAX_INGRESS_QUARANTINE_RAW_LINE_BYTES;
    while end > 0 && !raw.is_char_boundary(end) {
        end -= 1;
    }
    raw[..end].to_string()
}

fn quarantine_fingerprint(entry: &IngressQuarantineRecord) -> (usize, u64) {
    (entry.line_number, entry.line_hash)
}

fn existing_quarantine_fingerprints(path: &Path) -> BTreeSet<(usize, u64)> {
    let Ok(raw) = fs::read_to_string(path) else {
        return BTreeSet::new();
    };
    raw.lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .filter_map(|value| {
            let line_number = value.get("line_number")?.as_u64()? as usize;
            let line_hash = value
                .get("line_hash")
                .and_then(|hash| hash.as_u64())
                .or_else(|| {
                    value
                        .get("raw_line")
                        .and_then(|raw| raw.as_str())
                        .map(stable_line_hash)
                })?;
            Some((line_number, line_hash))
        })
        .collect()
}

fn append_quarantine_records(path: &Path, entries: &[IngressQuarantineRecord]) -> Result<usize> {
    if entries.is_empty() {
        return Ok(0);
    }
    let quarantine_path = ingress_quarantine_file_for(path);
    let _lock = acquire_market_file_lock(&quarantine_path)?;
    if let Some(parent) = quarantine_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut seen = existing_quarantine_fingerprints(&quarantine_path);
    let pending = entries
        .iter()
        .filter(|entry| seen.insert(quarantine_fingerprint(entry)))
        .collect::<Vec<_>>();
    if pending.is_empty() {
        return Ok(0);
    }
    let appended = pending.len();
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&quarantine_path)?;
    for entry in pending {
        writeln!(file, "{}", serde_json::to_string(entry)?)?;
    }
    file.sync_all()?;
    Ok(appended)
}

pub(crate) fn load_ingress_records() -> Vec<MessageIngressRecord> {
    let path = ingress_file();
    let Ok(raw) = fs::read_to_string(&path) else {
        return vec![];
    };
    let mut records = Vec::new();
    let mut quarantined = Vec::new();
    let source_path = path.display().to_string();
    let mut seen_quarantine_keys = std::collections::HashSet::new();
    for (idx, line) in raw.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str::<MessageIngressRecord>(line) {
            Ok(record) => records.push(record),
            Err(err) => {
                let line_hash = stable_line_hash(line);
                let raw_line = truncate_quarantine_raw_line(line);
                let quarantine_key = (source_path.clone(), line_hash, raw_line.clone());
                if !seen_quarantine_keys.insert(quarantine_key) {
                    continue;
                }
                if quarantined.len() >= MAX_INGRESS_QUARANTINE_RECORDS {
                    let drop_count = quarantined.len() + 1 - MAX_INGRESS_QUARANTINE_RECORDS;
                    quarantined.drain(0..drop_count);
                }
                quarantined.push(IngressQuarantineRecord {
                    source_path: source_path.clone(),
                    line_number: idx + 1,
                    line_hash,
                    raw_line,
                    error: err.to_string(),
                    quarantined_at_unix_ms: now_ms(),
                });
            }
        }
    }
    if !quarantined.is_empty() {
        match append_quarantine_records(&path, &quarantined) {
            Err(err) => {
                eprintln!(
                    "[trnm-rpc][warn][INGRESS_QUARANTINE_WRITE] path={} quarantined={} err={}",
                    path.display(),
                    quarantined.len(),
                    err
                );
            }
            Ok(appended) if appended > 0 => {
                eprintln!(
                    "[trnm-rpc][warn][INGRESS_QUARANTINE] path={} quarantined={} quarantine_path={}",
                    path.display(),
                    appended,
                    ingress_quarantine_file_for(&path).display()
                );
            }
            Ok(_) => {}
        }
    }
    records
}

pub(crate) fn save_ingress_records(records: &[MessageIngressRecord]) -> Result<()> {
    let path = ingress_file();
    let mut out = String::new();
    for rec in records {
        out.push_str(&serde_json::to_string(rec)?);
        out.push('\n');
    }
    atomic_write_text_file(&path, &out)
}

pub(crate) fn next_ingress_task_id(records: &[MessageIngressRecord]) -> Result<u64> {
    let max_existing = records.iter().map(|r| r.task_id).max().unwrap_or(10_000);
    max_existing
        .checked_add(1)
        .ok_or_else(|| anyhow!("ingress task_id exhausted: {}", max_existing))
}

pub(crate) fn is_same_submit_message_idempotency_scope(
    rec: &MessageIngressRecord,
    channel: &str,
    user_id: &str,
    session_id: &str,
    idempotency_key: &str,
) -> bool {
    rec.idempotency_key == idempotency_key
        && rec.session_id == session_id
        && rec.channel == channel
        && rec.user_id == user_id
}
