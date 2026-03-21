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
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    raw.hash(&mut hasher);
    hasher.finish()
}

fn quarantine_fingerprint(entry: &IngressQuarantineRecord) -> (String, usize, u64) {
    (
        entry.source_path.clone(),
        entry.line_number,
        entry.line_hash,
    )
}

fn load_existing_quarantine_fingerprints(path: &Path) -> BTreeSet<(String, usize, u64)> {
    let Ok(raw) = fs::read_to_string(path) else {
        return BTreeSet::new();
    };

    raw.lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .filter_map(|value| {
            Some((
                value.get("source_path")?.as_str()?.to_string(),
                usize::try_from(value.get("line_number")?.as_u64()?).ok()?,
                value.get("line_hash")?.as_u64()?,
            ))
        })
        .collect()
}

fn append_quarantine_records(path: &Path, entries: &[IngressQuarantineRecord]) -> Result<()> {
    if entries.is_empty() {
        return Ok(());
    }
    let quarantine_path = ingress_quarantine_file_for(path);
    let _lock = acquire_market_file_lock(&quarantine_path)?;
    if let Some(parent) = quarantine_path.parent() {
        fs::create_dir_all(parent)?;
    }

    let mut seen = load_existing_quarantine_fingerprints(&quarantine_path);
    let pending: Vec<_> = entries
        .iter()
        .filter(|entry| seen.insert(quarantine_fingerprint(entry)))
        .collect();
    if pending.is_empty() {
        return Ok(());
    }

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&quarantine_path)?;
    for entry in pending {
        writeln!(file, "{}", serde_json::to_string(entry)?)?;
    }
    file.sync_all()?;
    Ok(())
}

pub(crate) fn load_ingress_records() -> Vec<MessageIngressRecord> {
    let path = ingress_file();
    let Ok(raw) = fs::read_to_string(&path) else {
        return vec![];
    };
    let mut records = Vec::new();
    let mut quarantined = Vec::new();
    for (idx, line) in raw.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        match serde_json::from_str::<MessageIngressRecord>(trimmed) {
            Ok(record) => records.push(record),
            Err(err) => quarantined.push(IngressQuarantineRecord {
                source_path: path.display().to_string(),
                line_number: idx + 1,
                line_hash: stable_line_hash(trimmed),
                raw_line: line.to_string(),
                error: err.to_string(),
                quarantined_at_unix_ms: now_ms(),
            }),
        }
    }
    if !quarantined.is_empty() {
        if let Err(err) = append_quarantine_records(&path, &quarantined) {
            eprintln!(
                "[trnm-rpc][warn][INGRESS_QUARANTINE_WRITE] path={} quarantined={} err={}",
                path.display(),
                quarantined.len(),
                err
            );
        } else {
            eprintln!(
                "[trnm-rpc][warn][INGRESS_QUARANTINE] path={} quarantined={} quarantine_path={}",
                path.display(),
                quarantined.len(),
                ingress_quarantine_file_for(&path).display()
            );
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
