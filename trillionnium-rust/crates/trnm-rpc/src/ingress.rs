use std::{
    fs,
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

fn append_quarantine_records(path: &Path, entries: &[IngressQuarantineRecord]) -> Result<()> {
    let quarantine_path = ingress_quarantine_file_for(path);
    let _lock = acquire_market_file_lock(&quarantine_path)?;
    if let Some(parent) = quarantine_path.parent() {
        fs::create_dir_all(parent)?;
    }

    let mut seen = std::collections::HashMap::new();
    let mut retained = Vec::new();
    let mut existing_total = 0usize;
    let mut changed = false;
    if let Ok(existing_raw) = fs::read_to_string(&quarantine_path) {
        for line in existing_raw.lines().filter(|line| !line.trim().is_empty()) {
            existing_total += 1;
            let Ok(mut existing) = serde_json::from_str::<IngressQuarantineRecord>(line) else {
                changed = true;
                continue;
            };
            let original_raw_line = existing.raw_line.clone();
            existing.raw_line = truncate_quarantine_raw_line(&existing.raw_line);
            if existing.raw_line != original_raw_line {
                changed = true;
            }
            let key = (
                existing.source_path.clone(),
                existing.line_hash,
                existing.raw_line.clone(),
            );
            if let std::collections::hash_map::Entry::Vacant(slot) = seen.entry(key) {
                slot.insert(retained.len());
                retained.push(existing);
            }
        }
    }

    let mut changed = changed || existing_total != retained.len();
    for entry in entries {
        let key = (
            entry.source_path.clone(),
            entry.line_hash,
            entry.raw_line.clone(),
        );
        match seen.entry(key) {
            std::collections::hash_map::Entry::Vacant(slot) => {
                slot.insert(retained.len());
                retained.push(entry.clone());
                changed = true;
            }
            std::collections::hash_map::Entry::Occupied(mut slot) => {
                let idx = *slot.get();
                if retained[idx].line_number != entry.line_number
                    || retained[idx].error != entry.error
                    || retained[idx].quarantined_at_unix_ms != entry.quarantined_at_unix_ms
                {
                    retained.remove(idx);
                    for seen_idx in seen.values_mut() {
                        if *seen_idx > idx {
                            *seen_idx -= 1;
                        }
                    }
                    let new_idx = retained.len();
                    retained.push(entry.clone());
                    *slot.get_mut() = new_idx;
                    changed = true;
                }
            }
        }
    }
    if retained.len() > MAX_INGRESS_QUARANTINE_RECORDS {
        let drop_count = retained.len() - MAX_INGRESS_QUARANTINE_RECORDS;
        retained.drain(0..drop_count);
        changed = true;
    }
    if !changed {
        return Ok(());
    }

    let mut out = String::new();
    for entry in retained {
        out.push_str(&serde_json::to_string(&entry)?);
        out.push('\n');
    }
    atomic_write_text_file(&quarantine_path, &out)
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
    if let Err(err) = append_quarantine_records(&path, &quarantined) {
        if !quarantined.is_empty() {
            eprintln!(
                "[trnm-rpc][warn][INGRESS_QUARANTINE_WRITE] path={} quarantined={} err={}",
                path.display(),
                quarantined.len(),
                err
            );
        }
    } else if !quarantined.is_empty() {
        eprintln!(
            "[trnm-rpc][warn][INGRESS_QUARANTINE] path={} quarantined={} quarantine_path={}",
            path.display(),
            quarantined.len(),
            ingress_quarantine_file_for(&path).display()
        );

        if let Err(err) = save_ingress_records(&records) {
            eprintln!(
                "[trnm-rpc][warn][INGRESS_QUARANTINE_REWRITE] path={} retained={} err={}",
                path.display(),
                records.len(),
                err
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
