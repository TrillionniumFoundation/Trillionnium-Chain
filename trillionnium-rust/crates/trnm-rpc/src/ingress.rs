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
    const INGRESS_LINE_HASH_MIDDLE_BYTES: usize = 2_048;

    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    bytes.len().hash(&mut hasher);
    if bytes.len() <= INGRESS_LINE_HASH_FULL_MAX_BYTES {
        bytes.hash(&mut hasher);
    } else {
        bytes[..INGRESS_LINE_HASH_EDGE_BYTES].hash(&mut hasher);
        let middle_start = (bytes.len() - INGRESS_LINE_HASH_MIDDLE_BYTES) / 2;
        bytes[middle_start..middle_start + INGRESS_LINE_HASH_MIDDLE_BYTES].hash(&mut hasher);
        bytes[bytes.len() - INGRESS_LINE_HASH_EDGE_BYTES..].hash(&mut hasher);
    }
    hasher.finish()
}

fn quarantine_fingerprint(entry: &IngressQuarantineRecord) -> (String, usize, u64) {
    (
        entry.source_path.clone(),
        entry.line_number,
        entry.line_hash,
    )
}

fn quarantine_line_hash_from_value(value: &serde_json::Value) -> Option<u64> {
    if let Some(raw_line) = value.get("raw_line").and_then(|raw| raw.as_str()) {
        return Some(stable_line_hash(raw_line.trim()));
    }

    let line_hash = value.get("line_hash")?;
    if let Some(line_hash) = line_hash.as_u64() {
        return Some(line_hash);
    }

    line_hash.as_str()?.trim().parse::<u64>().ok()
}

fn quarantine_line_number_from_value(value: &serde_json::Value) -> Option<usize> {
    let line_number = value.get("line_number")?;
    if let Some(line_number) = line_number.as_u64() {
        return usize::try_from(line_number).ok();
    }

    line_number
        .as_str()?
        .trim()
        .parse::<usize>()
        .ok()
}

fn parse_quarantine_fingerprint_line(line: &str) -> Option<(String, usize, u64)> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return None;
    }

    let value = serde_json::from_str::<serde_json::Value>(trimmed).ok()?;
    Some((
        value.get("source_path")?.as_str()?.to_string(),
        quarantine_line_number_from_value(&value)?,
        quarantine_line_hash_from_value(&value)?,
    ))
}

fn load_existing_quarantine_fingerprints(path: &Path) -> BTreeSet<(String, usize, u64)> {
    let Ok(raw) = fs::read_to_string(path) else {
        return BTreeSet::new();
    };

    raw.lines()
        .filter_map(parse_quarantine_fingerprint_line)
        .collect()
}

fn append_quarantine_records(path: &Path, entries: &[IngressQuarantineRecord]) -> Result<()> {
    const INGRESS_QUARANTINE_FILE_MAX_RECORDS: usize = 1024;
    const INGRESS_QUARANTINE_READ_MAX_BYTES: u64 = 1_048_576;
    const INGRESS_QUARANTINE_RETAINED_LINE_MAX_BYTES: usize = 16_384;

    if entries.is_empty() {
        return Ok(0);
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
        .write(true)
        .truncate(true)
        .open(&quarantine_path)?;
    for entry in pending {
        writeln!(file, "{}", serde_json::to_string(entry)?)?;
    }
    file.sync_all()?;
    Ok(appended)
}

pub(crate) fn load_ingress_records() -> Vec<MessageIngressRecord> {
    const INGRESS_LINE_PARSE_MAX_BYTES: usize = 65_536;
    const INGRESS_QUARANTINE_FIELD_MAX_BYTES: usize = 4096;
    const INGRESS_QUARANTINE_RAW_LINE_MAX_BYTES: usize = 4096;
    const INGRESS_QUARANTINE_APPEND_MAX_RECORDS: usize = 128;

    fn sanitize_for_quarantine(raw: &str) -> String {
        raw.chars()
            .map(|ch| if is_forbidden_quarantine_char(ch) { '�' } else { ch })
            .collect()
    }

    fn truncate_sanitized_for_quarantine(raw: &str, max_bytes: usize) -> String {
        let sanitized = sanitize_for_quarantine(raw);
        if sanitized.len() <= max_bytes {
            return sanitized;
        }
        let mut end = max_bytes;
        while end > 0 && !sanitized.is_char_boundary(end) {
            end -= 1;
        }
        sanitized[..end].to_string()
    }

    fn canonicalize_quarantine_raw_line(raw: String) -> String {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            "whitespace-only line omitted".to_string()
        } else if trimmed.len() == raw.len() {
            raw
        } else {
            trimmed.to_string()
        }
    }

    fn canonicalize_quarantine_source_path(raw: String) -> String {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            "ingress path omitted".to_string()
        } else if trimmed.len() == raw.len() {
            raw
        } else {
            trimmed.to_string()
        }
    }

    fn truncate_for_quarantine(raw: &str) -> String {
        canonicalize_quarantine_raw_line(truncate_sanitized_for_quarantine(
            raw,
            INGRESS_QUARANTINE_RAW_LINE_MAX_BYTES,
        ))
    }

    fn truncate_bytes_for_quarantine(raw: &[u8]) -> String {
        let mut end = raw.len().min(INGRESS_QUARANTINE_RAW_LINE_MAX_BYTES);
        loop {
            let lossy = String::from_utf8_lossy(&raw[..end]);
            let bounded = truncate_for_quarantine(lossy.as_ref());
            if bounded.len() <= INGRESS_QUARANTINE_RAW_LINE_MAX_BYTES || end == 0 {
                return bounded;
            }
            end -= 1;
        }
    }

    fn quarantine_whitespace_raw_line(line_bytes: &[u8]) -> String {
        let raw_line = if line_bytes.is_empty() {
            "whitespace-only line omitted".to_string()
        } else {
            truncate_bytes_for_quarantine(line_bytes)
        };
        if raw_line.trim().is_empty() {
            "whitespace-only line omitted".to_string()
        } else {
            raw_line
        }
    }

    let path = ingress_file();
    let source_path_for_quarantine = canonicalize_quarantine_source_path(
        truncate_sanitized_for_quarantine(&path.display().to_string(), INGRESS_QUARANTINE_FIELD_MAX_BYTES),
    );
    let Ok(raw) = fs::read(&path) else {
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
    } else if skipped_whitespace_noise {
        if let Err(err) = save_ingress_records(&records) {
            eprintln!(
                "[trnm-rpc][warn][INGRESS_NOISE_COMPACT_WRITE] path={} retained_records={} err={}",
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
