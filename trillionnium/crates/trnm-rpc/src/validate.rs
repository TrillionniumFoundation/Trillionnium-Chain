use anyhow::{anyhow, bail, Result};
use trnm_types::{PrivacyTier, RequestStatus, TaskMetadata};

pub(crate) fn is_lower_hex_64(input: &str) -> bool {
    input.len() == 64
        && input
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn is_nonempty_no_whitespace(input: &str) -> bool {
    !input.is_empty() && !input.chars().any(|c| c.is_whitespace())
}

fn is_leap_year(year: u32) -> bool {
    (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400)
}

fn days_in_month(year: u32, month: u32) -> Option<u32> {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => Some(31),
        4 | 6 | 9 | 11 => Some(30),
        2 => Some(if is_leap_year(year) { 29 } else { 28 }),
        _ => None,
    }
}

fn is_canonical_rfc3339_utc_z(input: &str) -> bool {
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
    let from = RequestStatus::parse(current).map_err(|e| anyhow!("{}", e))?;
    let next = from.transition(to).map_err(|e| anyhow!("{}", e))?;
    Ok(next.as_str().to_string())
}
