use super::*;

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct IngressQuarantineRecord {
    pub(crate) source_path: String,
    pub(crate) line_number: usize,
    pub(crate) line_hash: u64,
    pub(crate) raw_line: String,
    pub(crate) error: String,
    pub(crate) quarantined_at_unix_ms: u128,
}

pub(crate) fn ingress_quarantine_file_for(path: &Path) -> PathBuf {
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("requests.jsonl");
    path.with_file_name(format!("{}.quarantine.jsonl", file_name))
}

pub(crate) fn stable_line_hash(raw: &str) -> u64 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    raw.hash(&mut hasher);
    hasher.finish()
}

pub(crate) fn append_quarantine_records(
    path: &Path,
    entries: &[IngressQuarantineRecord],
) -> Result<()> {
    if entries.is_empty() {
        return Ok(());
    }
    let quarantine_path = ingress_quarantine_file_for(path);
    let _lock = acquire_market_file_lock(&quarantine_path)?;
    if let Some(parent) = quarantine_path.parent() {
        fs::create_dir_all(parent)?;
    }

    let mut known_entries = std::collections::HashSet::new();
    if let Ok(existing) = fs::read_to_string(&quarantine_path) {
        for line in existing.lines().filter(|line| !line.trim().is_empty()) {
            if let Ok(record) = serde_json::from_str::<IngressQuarantineRecord>(line) {
                known_entries.insert((record.line_number, record.line_hash));
            }
        }
    }

    let new_entries: Vec<&IngressQuarantineRecord> = entries
        .iter()
        .filter(|entry| known_entries.insert((entry.line_number, entry.line_hash)))
        .collect();
    if new_entries.is_empty() {
        return Ok(());
    }

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&quarantine_path)?;
    for entry in new_entries {
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
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str::<MessageIngressRecord>(line) {
            Ok(record) => records.push(record),
            Err(err) => quarantined.push(IngressQuarantineRecord {
                source_path: path.display().to_string(),
                line_number: idx + 1,
                line_hash: stable_line_hash(line),
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

pub(crate) fn is_lower_hex_64(input: &str) -> bool {
    input.len() == 64
        && input
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub(crate) fn is_nonempty_no_whitespace(input: &str) -> bool {
    !input.is_empty() && !input.chars().any(|c| c.is_whitespace())
}

pub(crate) fn is_leap_year(year: u32) -> bool {
    (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400)
}

pub(crate) fn days_in_month(year: u32, month: u32) -> Option<u32> {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => Some(31),
        4 | 6 | 9 | 11 => Some(30),
        2 => Some(if is_leap_year(year) { 29 } else { 28 }),
        _ => None,
    }
}

pub(crate) fn is_canonical_rfc3339_utc_z(input: &str) -> bool {
    if input.len() != 20 {
        return false;
    }
    let bytes = input.as_bytes();
    if !(bytes[4] == b'-'
        && bytes[7] == b'-'
        && bytes[10] == b'T'
        && bytes[13] == b':'
        && bytes[16] == b':'
        && bytes[19] == b'Z'
        && bytes
            .iter()
            .enumerate()
            .all(|(i, b)| matches!(i, 4 | 7 | 10 | 13 | 16 | 19) || b.is_ascii_digit()))
    {
        return false;
    }

    let parse_u32 =
        |start: usize, end: usize| -> Option<u32> { input.get(start..end)?.parse().ok() };

    let Some(year) = parse_u32(0, 4) else {
        return false;
    };
    let Some(month) = parse_u32(5, 7) else {
        return false;
    };
    let Some(day) = parse_u32(8, 10) else {
        return false;
    };
    let Some(hour) = parse_u32(11, 13) else {
        return false;
    };
    let Some(minute) = parse_u32(14, 16) else {
        return false;
    };
    let Some(second) = parse_u32(17, 19) else {
        return false;
    };

    let Some(max_day) = days_in_month(year, month) else {
        return false;
    };

    (1..=max_day).contains(&day) && hour <= 23 && minute <= 59 && second <= 59
}

pub(crate) fn validate_task_metadata_core_fields(metadata: &TaskMetadata) -> Result<()> {
    if let Some(task_type) = metadata.task_type.as_deref() {
        if !is_nonempty_no_whitespace(task_type) {
            bail!("metadata.task_type must be non-empty and whitespace-free");
        }
    }

    if let Some(input_hash) = metadata.input_hash.as_deref() {
        if !is_lower_hex_64(input_hash) {
            bail!("metadata.input_hash must be 64-char lowercase hex");
        }
    }

    if let Some(model) = metadata.model.as_ref() {
        if let Some(model_id) = model.model_id.as_deref() {
            if !is_nonempty_no_whitespace(model_id) {
                bail!("metadata.model.model_id must be non-empty and whitespace-free");
            }
        }
        if let Some(model_digest) = model.model_digest.as_deref() {
            if !is_lower_hex_64(model_digest) {
                bail!("metadata.model.model_digest must be 64-char lowercase hex");
            }
        }
        if let Some(version) = model.version.as_deref() {
            if !is_nonempty_no_whitespace(version) {
                bail!("metadata.model.version must be non-empty and whitespace-free");
            }
        }
    }

    if let Some(provenance) = metadata.provenance.as_ref() {
        if let Some(producer_did) = provenance.producer_did.as_deref() {
            if !(producer_did.starts_with("did:") && is_nonempty_no_whitespace(producer_did)) {
                bail!("metadata.provenance.producer_did must be canonical did:* token");
            }
        }

        if let Some(produced_at) = provenance.produced_at.as_deref() {
            if !is_canonical_rfc3339_utc_z(produced_at) {
                bail!("metadata.provenance.produced_at must be canonical RFC3339 UTC Z timestamp");
            }
        }

        if let Some(provenance_index) = provenance.provenance_index.as_deref() {
            if !provenance_index.starts_with("prov:")
                || provenance_index.len() < 13
                || !is_nonempty_no_whitespace(provenance_index)
            {
                bail!("metadata.provenance.provenance_index must use prov:* canonical form");
            }
        }

        match provenance.privacy_tier {
            Some(PrivacyTier::Public) => {
                if provenance.provenance_index.is_some() {
                    bail!(
                        "metadata.provenance.provenance_index must be absent when privacy_tier=public"
                    );
                }
            }
            Some(PrivacyTier::Internal) | Some(PrivacyTier::Restricted) => {
                if provenance.provenance_index.is_none() {
                    bail!(
                        "metadata.provenance.provenance_index is required when privacy_tier=internal|restricted"
                    );
                }
            }
            None => {}
        }
    }

    Ok(())
}

pub(crate) fn validate_submit_message_metadata(text: &str) -> Result<()> {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(text) else {
        return Ok(());
    };

    let Some(metadata_value) = value.get("metadata") else {
        return Ok(());
    };

    let metadata: TaskMetadata = serde_json::from_value(metadata_value.clone())
        .map_err(|err| anyhow!("invalid metadata payload: {}", err))?;

    validate_task_metadata_core_fields(&metadata)
}

pub(crate) fn transition_request_status(current: &str, to: RequestStatus) -> Result<String> {
    let from = RequestStatus::parse(current).map_err(|e| anyhow::anyhow!("{}", e))?;
    let next = from.transition(to).map_err(|e| anyhow::anyhow!("{}", e))?;
    Ok(next.as_str().to_string())
}
