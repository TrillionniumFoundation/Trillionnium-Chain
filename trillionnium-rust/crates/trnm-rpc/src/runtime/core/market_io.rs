use super::*;

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

pub(crate) fn load_market_tasks() -> Vec<MarketTask> {
    let path = market_tasks_file();
    let Ok(raw) = fs::read_to_string(path) else {
        return vec![];
    };
    raw.lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| serde_json::from_str::<MarketTask>(l).ok())
        .collect()
}

pub(crate) fn save_market_tasks(tasks: &[MarketTask]) -> Result<()> {
    let path = market_tasks_file();
    let mut out = String::new();
    for t in tasks {
        out.push_str(&serde_json::to_string(t)?);
        out.push('\n');
    }
    write_string_atomically(&path, &out)
}

pub(crate) fn load_market_bids() -> Vec<MarketBid> {
    let path = market_bids_file();
    let Ok(raw) = fs::read_to_string(path) else {
        return vec![];
    };
    raw.lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| serde_json::from_str::<MarketBid>(l).ok())
        .collect()
}

pub(crate) fn save_market_bids(bids: &[MarketBid]) -> Result<()> {
    let path = market_bids_file();
    let mut out = String::new();
    for b in bids {
        out.push_str(&serde_json::to_string(b)?);
        out.push('\n');
    }
    write_string_atomically(&path, &out)
}

pub(crate) fn market_reputation_file() -> PathBuf {
    if let Some(path) = normalized_path_from_env(MARKET_REPUTATION_FILE_ENV) {
        return path;
    }
    run_root().join("run/market/reputation.json")
}

pub(crate) fn normalize_market_worker_key(raw: &str) -> Option<String> {
    let sanitized = raw
        .trim()
        .chars()
        .filter_map(|ch| match ch {
            '\u{200B}' | '\u{200C}' | '\u{200D}' | '\u{2060}' | '\u{FEFF}' => Some(' '),
            '\u{00AD}' => None,
            _ if ch.is_whitespace() || ch.is_control() => Some(' '),
            _ => Some(ch),
        })
        .collect::<String>();
    let normalized = sanitized
        .to_ascii_lowercase()
        .split_ascii_whitespace()
        .collect::<Vec<_>>()
        .join(" ");

    if normalized.is_empty() {
        None
    } else {
        Some(normalized)
    }
}

pub(crate) fn market_worker_tie_break_key(raw: &str) -> String {
    normalize_market_worker_key(raw).unwrap_or_else(|| raw.trim().to_ascii_lowercase())
}

pub(crate) fn normalize_market_status_key(raw: &str) -> String {
    raw.trim()
        .chars()
        .filter_map(|ch| match ch {
            '\u{00AD}' => None,
            '\u{200B}' | '\u{200C}' | '\u{200D}' | '\u{2060}' | '\u{FEFF}' => Some(' '),
            _ if ch.is_control() => Some(' '),
            _ => Some(ch),
        })
        .collect::<String>()
        .to_ascii_lowercase()
        .split_ascii_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

pub(crate) fn normalize_actor_or_signer(raw: &str) -> Option<String> {
    let sanitized: String = raw
        .trim()
        .chars()
        .filter_map(|ch| match ch {
            '\u{200B}' | '\u{200C}' | '\u{200D}' | '\u{2060}' | '\u{FEFF}' => Some(' '),
            _ if ch.is_control() => Some(' '),
            _ => Some(ch),
        })
        .collect();
    let collapsed = sanitized
        .split_ascii_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    if collapsed.is_empty() {
        None
    } else {
        Some(collapsed)
    }
}

pub(crate) fn parse_market_reputation_value(value: &serde_json::Value) -> Option<i64> {
    value
        .as_i64()
        .or_else(|| {
            let float = value.as_f64()?;
            if !float.is_finite() || float.fract() != 0.0 {
                return None;
            }
            if float < i64::MIN as f64 || float > i64::MAX as f64 {
                return None;
            }
            Some(float as i64)
        })
        .or_else(|| value.as_str()?.trim().parse::<i64>().ok())
}

pub(crate) fn load_market_reputation() -> BTreeMap<String, i64> {
    let path = market_reputation_file();
    let Ok(raw) = fs::read_to_string(path) else {
        return BTreeMap::new();
    };

    let parsed = serde_json::from_str::<serde_json::Value>(&raw)
        .ok()
        .and_then(|value| value.as_object().cloned())
        .unwrap_or_default();

    let mut normalized: BTreeMap<String, i64> = BTreeMap::new();
    for (worker, rep_value) in parsed {
        let Some(rep) = parse_market_reputation_value(&rep_value) else {
            continue;
        };
        if let Some(key) = normalize_market_worker_key(&worker) {
            normalized
                .entry(key)
                .and_modify(|existing| *existing = (*existing).max(rep))
                .or_insert(rep);
        }
    }
    normalized
}
