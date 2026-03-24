use sha2::{Digest, Sha256};
use std::{
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

pub(crate) fn now_ms() -> u128 {
    if let Ok(v) = std::env::var("TRNM_RPC_NOW_MS") {
        if let Ok(parsed) = v.parse::<u128>() {
            return parsed;
        }
    }
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

pub(crate) fn make_request_id(
    channel: &str,
    user_id: &str,
    session_id: &str,
    idempotency_key: &str,
    ts: u128,
) -> String {
    let mut h = Sha256::new();
    h.update(channel.as_bytes());
    h.update(b"|");
    h.update(user_id.as_bytes());
    h.update(b"|");
    h.update(session_id.as_bytes());
    h.update(b"|");
    h.update(idempotency_key.as_bytes());
    h.update(b"|");
    h.update(ts.to_string().as_bytes());
    let digest = hex::encode(h.finalize());
    format!("req_{}", &digest[..16])
}

pub(crate) fn normalize_wrapped_env_value(raw: &str) -> &str {
    let mut normalized = raw.trim();
    while normalized.len() >= 2 {
        let wrapped_by_quotes = (normalized.starts_with('"') && normalized.ends_with('"'))
            || (normalized.starts_with('\'') && normalized.ends_with('\''))
            || (normalized.starts_with('`') && normalized.ends_with('`'));
        if !wrapped_by_quotes {
            break;
        }
        normalized = normalized[1..normalized.len() - 1].trim();
    }
    normalized
}

pub(crate) fn env_u64_with_min(name: &str, default: u64, min: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| {
            let normalized = normalize_wrapped_env_value(&v);
            if normalized.is_empty() {
                None
            } else {
                normalized.parse::<u64>().ok()
            }
        })
        .map(|v| v.max(min))
        .unwrap_or(default.max(min))
}

pub(crate) fn env_u32_with_min(name: &str, default: u32, min: u32) -> u32 {
    std::env::var(name)
        .ok()
        .and_then(|v| {
            let normalized = normalize_wrapped_env_value(&v);
            if normalized.is_empty() {
                None
            } else {
                normalized.parse::<u32>().ok()
            }
        })
        .map(|v| v.max(min))
        .unwrap_or(default.max(min))
}

pub(crate) fn env_u128_clamped(name: &str, default: u128, min: u128, max: u128) -> u128 {
    std::env::var(name)
        .ok()
        .and_then(|v| normalize_wrapped_env_value(&v).parse::<u128>().ok())
        .map(|v| v.clamp(min, max))
        .unwrap_or(default)
}

pub(crate) fn env_i64_clamped(name: &str, default: i64, min: i64, max: i64) -> i64 {
    std::env::var(name)
        .ok()
        .and_then(|v| normalize_wrapped_env_value(&v).parse::<i64>().ok())
        .map(|v| v.clamp(min, max))
        .unwrap_or(default)
}

pub(crate) fn normalized_path_from_env(name: &str) -> Option<PathBuf> {
    let raw = std::env::var(name).ok()?;
    let normalized = normalize_wrapped_env_value(&raw);
    if normalized.is_empty() {
        None
    } else {
        Some(PathBuf::from(normalized))
    }
}
