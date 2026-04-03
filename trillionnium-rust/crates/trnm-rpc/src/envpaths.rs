use std::path::PathBuf;

use crate::{
    MARKET_LOCK_TIMEOUT_MS_DEFAULT, MARKET_LOCK_TIMEOUT_MS_MAX, MARKET_LOCK_TIMEOUT_MS_MIN,
    MARKET_REPUTATION_FILE_ENV, SUBMIT_MESSAGE_MAX_BYTES_DEFAULT, SUBMIT_MESSAGE_MAX_BYTES_ENV,
    SUBMIT_MESSAGE_MAX_BYTES_MIN, TASK_STATE_FILE_ENV,
};

pub(crate) fn run_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."))
}

pub(crate) fn identity_registry_file() -> PathBuf {
    if let Some(path) = normalized_path_from_env("TRNM_RPC_IDENTITY_REGISTRY_FILE") {
        return path;
    }
    run_root().join("run/rpc/identity_registry.json")
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

pub(crate) fn ingress_file() -> PathBuf {
    if let Some(path) = normalized_path_from_env("TRNM_RPC_INGRESS_FILE") {
        return path;
    }
    run_root().join("run/message-gateway/requests.jsonl")
}

pub(crate) fn submit_message_max_bytes() -> u64 {
    env_u64_with_min(
        SUBMIT_MESSAGE_MAX_BYTES_ENV,
        SUBMIT_MESSAGE_MAX_BYTES_DEFAULT,
        SUBMIT_MESSAGE_MAX_BYTES_MIN,
    )
}

pub(crate) fn normalize_wrapped_env_value(raw: &str) -> &str {
    let mut normalized = raw.trim_start_matches('\u{feff}').trim();
    while normalized.len() >= 2 {
        let wrapped_by_quotes = (normalized.starts_with('"') && normalized.ends_with('"'))
            || (normalized.starts_with('\'') && normalized.ends_with('\''))
            || (normalized.starts_with('`') && normalized.ends_with('`'));
        if !wrapped_by_quotes {
            break;
        }
        normalized = normalized[1..normalized.len() - 1]
            .trim_start_matches('\u{feff}')
            .trim();
    }
    normalized.trim_start_matches('\u{feff}').trim()
}

fn normalize_leading_wrapped_comment_value(raw: &str) -> Option<&str> {
    let normalized = raw.trim_start_matches('\u{feff}').trim();
    let quote = normalized.chars().next()?;
    if !matches!(quote, '"' | '\'' | '`') {
        return None;
    }

    let closing_idx = normalized[quote.len_utf8()..]
        .char_indices()
        .find_map(|(idx, ch)| (ch == quote).then_some(quote.len_utf8() + idx))?;
    let rest = normalized[closing_idx + quote.len_utf8()..]
        .trim_start_matches('\u{feff}')
        .trim_start();
    if !rest.starts_with('#') {
        return None;
    }

    Some(normalize_wrapped_env_value(&normalized[..closing_idx + quote.len_utf8()]))
}

pub(crate) fn normalized_path_from_env(name: &str) -> Option<PathBuf> {
    let raw = std::env::var(name).ok()?;
    let normalized = normalize_wrapped_env_value(&raw);
    let inline_comment_idx = normalized.char_indices().find_map(|(idx, ch)| {
        (ch == '#'
            && idx > 0
            && normalized[..idx]
                .chars()
                .last()
                .is_some_and(char::is_whitespace))
        .then_some(idx)
    });
    let normalized = inline_comment_idx
        .map(|idx| normalize_wrapped_env_value(normalized[..idx].trim_end()))
        .unwrap_or(normalized);
    let normalized = normalize_leading_wrapped_comment_value(normalized).unwrap_or(normalized);
    if normalized.is_empty() || normalized.starts_with('#') {
        None
    } else {
        Some(PathBuf::from(normalized))
    }
}

pub(crate) fn market_tasks_file() -> PathBuf {
    if let Some(path) = normalized_path_from_env("TRNM_RPC_MARKET_TASKS_FILE") {
        return path;
    }
    run_root().join("run/market/tasks.jsonl")
}

pub(crate) fn market_bids_file() -> PathBuf {
    if let Some(path) = normalized_path_from_env("TRNM_RPC_MARKET_BIDS_FILE") {
        return path;
    }
    run_root().join("run/market/bids.jsonl")
}

pub(crate) fn task_state_file() -> Option<PathBuf> {
    normalized_path_from_env(TASK_STATE_FILE_ENV)
}

pub(crate) fn market_lock_stale_after_ms() -> Option<u128> {
    let raw = std::env::var("TRNM_RPC_MARKET_LOCK_STALE_MS").ok()?;
    let normalized = normalize_wrapped_env_value(&raw);
    if normalized.is_empty() {
        return None;
    }
    let parsed = normalized.parse::<u128>().ok()?;
    Some(parsed.clamp(1_000, 15 * 60 * 1_000))
}

pub(crate) fn market_lock_timeout_ms() -> u64 {
    let raw = match std::env::var("TRNM_RPC_MARKET_LOCK_TIMEOUT_MS") {
        Ok(v) => v,
        Err(_) => return MARKET_LOCK_TIMEOUT_MS_DEFAULT,
    };
    let normalized = normalize_wrapped_env_value(&raw);
    if normalized.is_empty() {
        return MARKET_LOCK_TIMEOUT_MS_DEFAULT;
    }
    let parsed = match normalized.parse::<u64>() {
        Ok(v) => v,
        Err(_) => return MARKET_LOCK_TIMEOUT_MS_DEFAULT,
    };
    parsed.clamp(MARKET_LOCK_TIMEOUT_MS_MIN, MARKET_LOCK_TIMEOUT_MS_MAX)
}

pub(crate) fn market_reputation_file() -> PathBuf {
    if let Some(path) = normalized_path_from_env(MARKET_REPUTATION_FILE_ENV) {
        return path;
    }
    run_root().join("run/market/reputation.json")
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

pub(crate) fn account_state_file() -> PathBuf {
    if let Some(path) = normalized_path_from_env("TRNM_RPC_ACCOUNTS_FILE") {
        return path;
    }
    run_root().join("run/rpc/accounts.json")
}

pub(crate) fn tx_lifecycle_file() -> PathBuf {
    if let Some(path) = normalized_path_from_env("TRNM_RPC_TX_FILE") {
        return path;
    }
    run_root().join("run/rpc/txs.json")
}

pub(crate) fn faucet_limits_file() -> PathBuf {
    if let Some(path) = normalized_path_from_env("TRNM_RPC_FAUCET_LIMITS_FILE") {
        return path;
    }
    run_root().join("run/rpc/faucet_limits.json")
}
