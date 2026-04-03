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
        .trim_start()
        .trim_start_matches('\u{feff}')
        .trim_start();
    if !rest.starts_with('#') {
        return None;
    }

    Some(normalize_wrapped_env_value(&normalized[..closing_idx + quote.len_utf8()]))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalized_path_from_env_tolerates_bom_wrapped_comment_suffix() {
        let prev = std::env::var("TRNM_RPC_RUNTIME_ENV_TEST_PATH").ok();
        unsafe {
            std::env::set_var(
                "TRNM_RPC_RUNTIME_ENV_TEST_PATH",
                "\u{feff}  \"cfg/history/sources.txt\"# archived replay note ",
            );
        }

        let got = normalized_path_from_env("TRNM_RPC_RUNTIME_ENV_TEST_PATH");

        match prev {
            Some(value) => unsafe { std::env::set_var("TRNM_RPC_RUNTIME_ENV_TEST_PATH", value) },
            None => unsafe { std::env::remove_var("TRNM_RPC_RUNTIME_ENV_TEST_PATH") },
        }

        assert_eq!(got, Some(PathBuf::from("cfg/history/sources.txt")));
    }

    #[test]
    fn normalized_path_from_env_tolerates_leading_whitespace_before_bom_wrapped_comment_suffix() {
        let prev = std::env::var("TRNM_RPC_RUNTIME_ENV_TEST_PATH").ok();
        unsafe {
            std::env::set_var(
                "TRNM_RPC_RUNTIME_ENV_TEST_PATH",
                "  \u{feff}\"cfg/history/sources.txt\"# archived replay note ",
            );
        }

        let got = normalized_path_from_env("TRNM_RPC_RUNTIME_ENV_TEST_PATH");

        match prev {
            Some(value) => unsafe { std::env::set_var("TRNM_RPC_RUNTIME_ENV_TEST_PATH", value) },
            None => unsafe { std::env::remove_var("TRNM_RPC_RUNTIME_ENV_TEST_PATH") },
        }

        assert_eq!(got, Some(PathBuf::from("cfg/history/sources.txt")));
    }

    #[test]
    fn normalized_path_from_env_tolerates_whitespace_then_bom_before_comment_suffix() {
        let prev = std::env::var("TRNM_RPC_RUNTIME_ENV_TEST_PATH").ok();
        unsafe {
            std::env::set_var(
                "TRNM_RPC_RUNTIME_ENV_TEST_PATH",
                "\"cfg/history/sources.txt\"  \u{feff}# archived replay note ",
            );
        }

        let got = normalized_path_from_env("TRNM_RPC_RUNTIME_ENV_TEST_PATH");

        match prev {
            Some(value) => unsafe { std::env::set_var("TRNM_RPC_RUNTIME_ENV_TEST_PATH", value) },
            None => unsafe { std::env::remove_var("TRNM_RPC_RUNTIME_ENV_TEST_PATH") },
        }

        assert_eq!(got, Some(PathBuf::from("cfg/history/sources.txt")));
    }
}
