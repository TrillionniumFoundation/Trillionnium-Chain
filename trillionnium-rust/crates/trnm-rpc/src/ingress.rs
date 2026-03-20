use std::{
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
use crate::{IngressQuarantineRecord, MessageIngressRecord, push_tail_limited};

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

fn append_quarantine_records(path: &Path, entries: &[IngressQuarantineRecord]) -> Result<()> {
    if entries.is_empty() {
        return Ok(());
    }
    let quarantine_path = ingress_quarantine_file_for(path);
    let _lock = acquire_market_file_lock(&quarantine_path)?;
    if let Some(parent) = quarantine_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&quarantine_path)?;
    for entry in entries {
        writeln!(file, "{}", serde_json::to_string(entry)?)?;
    }
    file.sync_all()?;
    Ok(())
}

pub(crate) fn load_ingress_records() -> Vec<MessageIngressRecord> {
    const INGRESS_LINE_PARSE_MAX_BYTES: usize = 65_536;
    const INGRESS_QUARANTINE_RAW_LINE_MAX_BYTES: usize = 4096;
    const INGRESS_QUARANTINE_APPEND_MAX_RECORDS: usize = 128;

    fn truncate_for_quarantine(raw: &str) -> String {
        if raw.len() <= INGRESS_QUARANTINE_RAW_LINE_MAX_BYTES {
            return raw.to_string();
        }
        let mut end = INGRESS_QUARANTINE_RAW_LINE_MAX_BYTES;
        while end > 0 && !raw.is_char_boundary(end) {
            end -= 1;
        }
        raw[..end].to_string()
    }

    let path = ingress_file();
    let Ok(raw) = fs::read_to_string(&path) else {
        return vec![];
    };
    let mut records = Vec::new();
    let mut quarantined = Vec::new();
    let mut quarantined_total = 0usize;
    for (idx, line) in raw.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let parse_result = if line.len() > INGRESS_LINE_PARSE_MAX_BYTES {
            Err(anyhow!(
                "ingress line exceeds {} bytes parse bound (got {})",
                INGRESS_LINE_PARSE_MAX_BYTES,
                line.len()
            ))
        } else {
            serde_json::from_str::<MessageIngressRecord>(line).map_err(Into::into)
        };
        match parse_result {
            Ok(record) => records.push(record),
            Err(err) => {
                quarantined_total += 1;
                push_tail_limited(
                    &mut quarantined,
                    IngressQuarantineRecord {
                        source_path: path.display().to_string(),
                        line_number: idx + 1,
                        line_hash: stable_line_hash(line),
                        raw_line: truncate_for_quarantine(line),
                        error: err.to_string(),
                        quarantined_at_unix_ms: now_ms(),
                    },
                    INGRESS_QUARANTINE_APPEND_MAX_RECORDS,
                );
            }
        }
    }
    if !quarantined.is_empty() {
        if let Err(err) = append_quarantine_records(&path, &quarantined) {
            eprintln!(
                "[trnm-rpc][warn][INGRESS_QUARANTINE_WRITE] path={} quarantined_total={} quarantined_written={} err={}",
                path.display(),
                quarantined_total,
                quarantined.len(),
                err
            );
        } else {
            eprintln!(
                "[trnm-rpc][warn][INGRESS_QUARANTINE] path={} quarantined_total={} quarantined_written={} quarantine_path={}",
                path.display(),
                quarantined_total,
                quarantined.len(),
                ingress_quarantine_file_for(&path).display()
            );
            if let Err(err) = save_ingress_records(&records) {
                eprintln!(
                    "[trnm-rpc][warn][INGRESS_SALVAGE_WRITE] path={} retained_records={} err={}",
                    path.display(),
                    records.len(),
                    err
                );
            }
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
