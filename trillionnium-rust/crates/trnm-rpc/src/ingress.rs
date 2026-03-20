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

fn stable_bounded_bytes_hash(bytes: &[u8]) -> u64 {
    const INGRESS_LINE_HASH_FULL_MAX_BYTES: usize = 8_192;
    const INGRESS_LINE_HASH_EDGE_BYTES: usize = 4_096;

    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    bytes.len().hash(&mut hasher);
    if bytes.len() <= INGRESS_LINE_HASH_FULL_MAX_BYTES {
        bytes.hash(&mut hasher);
    } else {
        bytes[..INGRESS_LINE_HASH_EDGE_BYTES].hash(&mut hasher);
        bytes[bytes.len() - INGRESS_LINE_HASH_EDGE_BYTES..].hash(&mut hasher);
    }
    hasher.finish()
}

fn stable_line_hash(raw: &str) -> u64 {
    stable_bounded_bytes_hash(raw.as_bytes())
}

fn append_quarantine_records(path: &Path, entries: &[IngressQuarantineRecord]) -> Result<()> {
    const INGRESS_QUARANTINE_FILE_MAX_RECORDS: usize = 1024;
    const INGRESS_QUARANTINE_READ_MAX_BYTES: u64 = 1_048_576;

    if entries.is_empty() {
        return Ok(());
    }
    let quarantine_path = ingress_quarantine_file_for(path);
    let _lock = acquire_market_file_lock(&quarantine_path)?;
    if let Some(parent) = quarantine_path.parent() {
        fs::create_dir_all(parent)?;
    }

    let mut retained_lines: Vec<String> = match fs::metadata(&quarantine_path) {
        Ok(meta) if meta.len() > INGRESS_QUARANTINE_READ_MAX_BYTES => Vec::new(),
        _ => fs::read_to_string(&quarantine_path)
            .ok()
            .map(|raw| {
                raw.lines()
                    .filter(|line| !line.trim().is_empty())
                    .filter_map(|line| {
                        serde_json::from_str::<IngressQuarantineRecord>(line)
                            .ok()
                            .map(|_| line.to_string())
                    })
                    .collect()
            })
            .unwrap_or_default(),
    };
    for entry in entries {
        retained_lines.push(serde_json::to_string(entry)?);
    }
    if retained_lines.len() > INGRESS_QUARANTINE_FILE_MAX_RECORDS {
        retained_lines.drain(..retained_lines.len() - INGRESS_QUARANTINE_FILE_MAX_RECORDS);
    }

    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&quarantine_path)?;
    for line in retained_lines {
        writeln!(file, "{line}")?;
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

    fn truncate_bytes_for_quarantine(raw: &[u8]) -> String {
        let end = raw.len().min(INGRESS_QUARANTINE_RAW_LINE_MAX_BYTES);
        let lossy = String::from_utf8_lossy(&raw[..end]);
        truncate_for_quarantine(lossy.as_ref())
    }

    let path = ingress_file();
    let Ok(raw) = fs::read(&path) else {
        return vec![];
    };
    let mut records = Vec::new();
    let mut quarantined = Vec::new();
    let mut quarantined_total = 0usize;
    for (idx, line_bytes) in raw.split(|byte| *byte == b'\n').enumerate() {
        let line_bytes = match line_bytes.strip_suffix(b"\r") {
            Some(trimmed) => trimmed,
            None => line_bytes,
        };
        if line_bytes.iter().all(|byte| byte.is_ascii_whitespace()) {
            continue;
        }
        let parse_result = if line_bytes.len() > INGRESS_LINE_PARSE_MAX_BYTES {
            Err((
                stable_bounded_bytes_hash(line_bytes),
                truncate_bytes_for_quarantine(line_bytes),
                anyhow!(
                    "ingress line exceeds {} bytes parse bound (got {})",
                    INGRESS_LINE_PARSE_MAX_BYTES,
                    line_bytes.len()
                ),
            ))
        } else {
            match std::str::from_utf8(line_bytes) {
                Ok(line) => match serde_json::from_str::<MessageIngressRecord>(line) {
                Ok(record) => {
                    records.push(record);
                    continue;
                }
                Err(err) => Err((
                    stable_line_hash(line),
                    truncate_for_quarantine(line),
                    err.into(),
                )),
            },
                Err(_) => Err((
                    stable_bounded_bytes_hash(line_bytes),
                    truncate_bytes_for_quarantine(line_bytes),
                    anyhow!("ingress line is not valid utf-8"),
                )),
            }
        };
        let (line_hash, raw_line, err) = match parse_result {
            Ok(_) => unreachable!("successful parse path continues early"),
            Err(parts) => parts,
        };
        quarantined_total += 1;
        push_tail_limited(
            &mut quarantined,
            IngressQuarantineRecord {
                source_path: path.display().to_string(),
                line_number: idx + 1,
                line_hash,
                raw_line,
                error: err.to_string(),
                quarantined_at_unix_ms: now_ms(),
            },
            INGRESS_QUARANTINE_APPEND_MAX_RECORDS,
        );
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
