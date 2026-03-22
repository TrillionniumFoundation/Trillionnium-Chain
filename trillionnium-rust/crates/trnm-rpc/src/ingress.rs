use std::{
    collections::HashSet,
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

fn stable_line_hash(raw: &str) -> u64 {
    stable_bounded_bytes_hash(raw.as_bytes())
}

fn is_forbidden_quarantine_char(ch: char) -> bool {
    ch.is_control()
        || matches!(
            ch,
            '\u{061C}'
                | '\u{200B}'
                | '\u{200C}'
                | '\u{200D}'
                | '\u{200E}'
                | '\u{200F}'
                | '\u{2028}'
                | '\u{2029}'
                | '\u{202A}'
                | '\u{202B}'
                | '\u{202C}'
                | '\u{202D}'
                | '\u{202E}'
                | '\u{2066}'
                | '\u{2067}'
                | '\u{2068}'
                | '\u{2069}'
                | '\u{2060}'
                | '\u{2061}'
                | '\u{2062}'
                | '\u{2063}'
                | '\u{2064}'
                | '\u{FEFF}'
                | '\u{E0001}'
                | '\u{E0020}'..='\u{E007F}'
        )
        || ('\u{FDD0}'..='\u{FDEF}').contains(&ch)
        || (ch as u32 & 0xFFFE == 0xFFFE && (ch as u32) <= 0x10FFFF)
}

pub(crate) fn quarantine_record_within_bounds(entry: &IngressQuarantineRecord) -> bool {
    const INGRESS_QUARANTINE_RETAINED_LINE_MAX_BYTES: usize = 16_384;
    const INGRESS_QUARANTINE_FIELD_MAX_BYTES: usize = 4096;
    const INGRESS_QUARANTINE_RAW_LINE_MAX_BYTES: usize = 4096;
    const INGRESS_QUARANTINE_LINE_NUMBER_MAX: usize = 1_048_576;

    fn contains_forbidden_quarantine_chars(raw: &str) -> bool {
        raw.chars().any(is_forbidden_quarantine_char)
    }

    if entry.line_number == 0
        || entry.line_number > INGRESS_QUARANTINE_LINE_NUMBER_MAX
        || entry.line_hash == 0
        || entry.source_path.trim().is_empty()
        || entry.raw_line.trim().is_empty()
        || entry.error.trim().is_empty()
        || entry.source_path != entry.source_path.trim()
        || entry.raw_line != entry.raw_line.trim()
        || entry.error != entry.error.trim()
        || entry.quarantined_at_unix_ms == 0
        || entry.raw_line.as_bytes().len() > INGRESS_QUARANTINE_RAW_LINE_MAX_BYTES
        || entry.source_path.as_bytes().len() > INGRESS_QUARANTINE_FIELD_MAX_BYTES
        || entry.error.as_bytes().len() > INGRESS_QUARANTINE_FIELD_MAX_BYTES
        || contains_forbidden_quarantine_chars(&entry.source_path)
        || contains_forbidden_quarantine_chars(&entry.raw_line)
        || contains_forbidden_quarantine_chars(&entry.error)
    {
        return false;
    }

    serde_json::to_string(entry)
        .map(|line| line.as_bytes().len() <= INGRESS_QUARANTINE_RETAINED_LINE_MAX_BYTES)
        .unwrap_or(false)
}

fn append_quarantine_records(path: &Path, entries: &[IngressQuarantineRecord]) -> Result<()> {
    const INGRESS_QUARANTINE_FILE_MAX_RECORDS: usize = 1024;
    const INGRESS_QUARANTINE_READ_MAX_BYTES: u64 = 1_048_576;
    const INGRESS_QUARANTINE_RETAINED_LINE_MAX_BYTES: usize = 16_384;

    if entries.is_empty() {
        return Ok(());
    }
    let quarantine_path = ingress_quarantine_file_for(path);
    let _lock = acquire_market_file_lock(&quarantine_path)?;
    if let Some(parent) = quarantine_path.parent() {
        fs::create_dir_all(parent)?;
    }

    let mut retained_lines = Vec::new();
    let mut retained_identities = HashSet::new();
    match fs::metadata(&quarantine_path) {
        Ok(meta) if meta.len() > INGRESS_QUARANTINE_READ_MAX_BYTES => {}
        _ => {
            if let Some(raw) = fs::read(&quarantine_path).ok() {
                for line in raw
                    .split(|byte| *byte == b'\n')
                    .filter_map(|line_bytes| std::str::from_utf8(line_bytes).ok())
                    .map(|line| line.trim_end_matches('\r'))
                    .filter(|line| !line.trim().is_empty())
                    .filter(|line| line.as_bytes().len() <= INGRESS_QUARANTINE_RETAINED_LINE_MAX_BYTES)
                {
                    let Some(entry) = serde_json::from_str::<IngressQuarantineRecord>(line).ok()
                    else {
                        continue;
                    };
                    if quarantine_record_within_bounds(&entry)
                        && retained_identities.insert((
                            entry.source_path.clone(),
                            entry.line_hash,
                            entry.raw_line.clone(),
                            entry.error.clone(),
                        ))
                    {
                        retained_lines.push(line.to_string());
                    }
                }
            }
        }
    }
    for entry in entries {
        if quarantine_record_within_bounds(entry)
            && retained_identities.insert((
                entry.source_path.clone(),
                entry.line_hash,
                entry.raw_line.clone(),
                entry.error.clone(),
            ))
        {
            retained_lines.push(serde_json::to_string(entry)?);
        }
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
    let mut quarantined_seen = HashSet::new();
    let mut quarantined_total = 0usize;
    let mut skipped_whitespace_noise = false;
    for (idx, line_bytes) in raw.split_terminator(|byte| *byte == b'\n').enumerate() {
        let line_on_disk_len = line_bytes.len();
        let line_bytes = match line_bytes.strip_suffix(b"\r") {
            Some(trimmed) => trimmed,
            None => line_bytes,
        };
        if line_bytes.iter().all(|byte| byte.is_ascii_whitespace()) {
            if line_on_disk_len > INGRESS_LINE_PARSE_MAX_BYTES {
                let raw_line = quarantine_whitespace_raw_line(line_bytes);
                let parse_result = Err((
                    stable_bounded_bytes_hash(line_bytes),
                    raw_line,
                    anyhow!(
                        "ingress line exceeds {} bytes parse bound (got {})",
                        INGRESS_LINE_PARSE_MAX_BYTES,
                        line_on_disk_len
                    ),
                ));
                let (line_hash, raw_line, err) = match parse_result {
                    Ok(_) => unreachable!("successful parse path continues early"),
                    Err(parts) => parts,
                };
                quarantined_total += 1;
                let error = err.to_string();
                if quarantined_seen.insert((line_hash, raw_line.clone(), error.clone())) {
                    push_tail_limited(
                        &mut quarantined,
                        IngressQuarantineRecord {
                            source_path: source_path_for_quarantine.clone(),
                            line_number: idx + 1,
                            line_hash,
                            raw_line,
                            error,
                            quarantined_at_unix_ms: now_ms(),
                        },
                        INGRESS_QUARANTINE_APPEND_MAX_RECORDS,
                    );
                }
                continue;
            }
            skipped_whitespace_noise = true;
            continue;
        }
        let parse_result = match std::str::from_utf8(line_bytes) {
            Ok(line) => {
                if line.trim().is_empty() {
                    if line_on_disk_len > INGRESS_LINE_PARSE_MAX_BYTES {
                        let raw_line = quarantine_whitespace_raw_line(line_bytes);
                        Err((
                            stable_line_hash(line),
                            raw_line,
                            anyhow!(
                                "ingress line exceeds {} bytes parse bound (got {})",
                                INGRESS_LINE_PARSE_MAX_BYTES,
                                line_on_disk_len
                            ),
                        ))
                    } else {
                        skipped_whitespace_noise = true;
                        continue;
                    }
                } else if line_on_disk_len > INGRESS_LINE_PARSE_MAX_BYTES {
                    Err((
                        stable_line_hash(line),
                        truncate_for_quarantine(line),
                        anyhow!(
                            "ingress line exceeds {} bytes parse bound (got {})",
                            INGRESS_LINE_PARSE_MAX_BYTES,
                            line_on_disk_len
                        ),
                    ))
                } else {
                    match serde_json::from_str::<MessageIngressRecord>(line) {
                        Ok(record) => {
                            records.push(record);
                            continue;
                        }
                        Err(err) => Err((
                            stable_line_hash(line),
                            truncate_for_quarantine(line),
                            err.into(),
                        )),
                    }
                }
            }
            Err(_) => {
                if line_on_disk_len > INGRESS_LINE_PARSE_MAX_BYTES {
                    Err((
                        stable_bounded_bytes_hash(line_bytes),
                        truncate_bytes_for_quarantine(line_bytes),
                        anyhow!(
                            "ingress line exceeds {} bytes parse bound (got {})",
                            INGRESS_LINE_PARSE_MAX_BYTES,
                            line_on_disk_len
                        ),
                    ))
                } else {
                    Err((
                        stable_bounded_bytes_hash(line_bytes),
                        truncate_bytes_for_quarantine(line_bytes),
                        anyhow!("ingress line is not valid utf-8"),
                    ))
                }
            }
        };
        let (line_hash, raw_line, err) = match parse_result {
            Ok(_) => unreachable!("successful parse path continues early"),
            Err(parts) => parts,
        };
        quarantined_total += 1;
        let error = err.to_string();
        if quarantined_seen.insert((line_hash, raw_line.clone(), error.clone())) {
            push_tail_limited(
                &mut quarantined,
                IngressQuarantineRecord {
                    source_path: source_path_for_quarantine.clone(),
                    line_number: idx + 1,
                    line_hash,
                    raw_line,
                    error,
                    quarantined_at_unix_ms: now_ms(),
                },
                INGRESS_QUARANTINE_APPEND_MAX_RECORDS,
            );
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
