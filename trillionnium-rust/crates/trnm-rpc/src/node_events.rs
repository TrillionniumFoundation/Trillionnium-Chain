#[cfg(test)]
use std::io::{Read, Seek, SeekFrom};
use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
};

use crate::envpaths::{normalize_wrapped_env_value, normalized_path_from_env, run_root};
use crate::metering::{
    normalize_opt_kv, parse_event_log_kv, parse_event_metering_query_response, parse_i128_kv_value,
    parse_u128_kv_value, parse_u64_kv_value,
};
use crate::{
    LoadedNodeEvents, NodeEventRecord, NodeEventScanMode, NODE_EVENT_LOG_MANIFEST_ENV,
    NODE_EVENT_LOG_SOURCES_ENV,
};
#[cfg(test)]
use crate::{NODE_EVENT_LOG_TAIL_BYTES_DEFAULT, NODE_EVENT_LOG_TAIL_BYTES_MAX};

#[cfg(test)]
pub(crate) fn node_event_log_tail_bytes() -> u64 {
    std::env::var("TRNM_RPC_NODE_EVENT_LOG_TAIL_BYTES")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .map(|v| v.min(NODE_EVENT_LOG_TAIL_BYTES_MAX))
        .filter(|v| *v > 0)
        .unwrap_or(NODE_EVENT_LOG_TAIL_BYTES_DEFAULT)
}

#[cfg(test)]
pub(crate) fn read_log_tail(path: &Path, tail_bytes: u64) -> Option<String> {
    let mut file = fs::File::open(path).ok()?;
    let size = file.metadata().ok()?.len();
    let start = size.saturating_sub(tail_bytes);
    let mut started_mid_line = false;
    if start > 0 {
        if file.seek(SeekFrom::Start(start.saturating_sub(1))).is_err() {
            return None;
        }
        let mut prev = [0u8; 1];
        if file.read_exact(&mut prev).is_err() {
            return None;
        }
        started_mid_line = prev[0] != b'\n';
    }
    if file.seek(SeekFrom::Start(start)).is_err() {
        return None;
    }
    let mut bytes = Vec::new();
    if file.read_to_end(&mut bytes).is_err() {
        return None;
    }
    let buf = String::from_utf8_lossy(&bytes).into_owned();
    if start > 0 && started_mid_line {
        if let Some(idx) = buf.find('\n') {
            return Some(buf[idx + 1..].to_string());
        }
        return Some(String::new());
    }
    Some(buf)
}

fn parse_node_event_log_sources_list(raw: &str) -> Vec<PathBuf> {
    raw.split(|c: char| c == ',' || c == ';' || c == '\n')
        .filter_map(|part| {
            let normalized = normalize_wrapped_env_value(part);
            if normalized.is_empty() {
                None
            } else {
                Some(PathBuf::from(normalized))
            }
        })
        .collect()
}

#[cfg(test)]
pub(crate) fn discover_default_node_event_log_sources(root: &Path) -> Vec<PathBuf> {
    let run_dir = root.join("run");
    let mut out = BTreeSet::<PathBuf>::new();
    for seed in ["event-field-check.log", "parallel-sanity.log"] {
        let candidate = run_dir.join(seed);
        if candidate.is_file() {
            out.insert(candidate);
        }
    }
    if let Ok(entries) = fs::read_dir(&run_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let Some(name) = path.file_name().and_then(|v| v.to_str()) else {
                continue;
            };
            if name.ends_with(".log") {
                out.insert(path);
            }
        }
    }
    out.into_iter().collect()
}

#[cfg(not(test))]
fn discover_default_node_event_log_sources(root: &Path) -> Vec<PathBuf> {
    let run_dir = root.join("run");
    let mut out = BTreeSet::<PathBuf>::new();
    for seed in ["event-field-check.log", "parallel-sanity.log"] {
        let candidate = run_dir.join(seed);
        if candidate.is_file() {
            out.insert(candidate);
        }
    }
    if let Ok(entries) = fs::read_dir(&run_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let Some(name) = path.file_name().and_then(|v| v.to_str()) else {
                continue;
            };
            if name.ends_with(".log") {
                out.insert(path);
            }
        }
    }
    out.into_iter().collect()
}

#[cfg(test)]
pub(crate) fn load_node_event_log_sources(root: &Path) -> Vec<PathBuf> {
    let mut sources = BTreeSet::<PathBuf>::new();

    if let Some(manifest_path) = normalized_path_from_env(NODE_EVENT_LOG_MANIFEST_ENV) {
        if let Ok(raw) = fs::read_to_string(&manifest_path) {
            let manifest_dir = manifest_path.parent().unwrap_or_else(|| Path::new("."));
            for line in raw.lines() {
                let trimmed = line.trim();
                if trimmed.is_empty() || trimmed.starts_with('#') {
                    continue;
                }
                let normalized = normalize_wrapped_env_value(trimmed);
                if normalized.is_empty() || normalized.starts_with('#') {
                    continue;
                }
                let path = PathBuf::from(normalized);
                let resolved = if path.is_absolute() {
                    path
                } else {
                    manifest_dir.join(path)
                };
                sources.insert(resolved);
            }
        }
    }

    if let Ok(raw) = std::env::var(NODE_EVENT_LOG_SOURCES_ENV) {
        for path in parse_node_event_log_sources_list(&raw) {
            let resolved = if path.is_absolute() {
                path
            } else {
                root.join(path)
            };
            sources.insert(resolved);
        }
    }

    if sources.is_empty() {
        return discover_default_node_event_log_sources(root);
    }

    sources.into_iter().collect()
}

#[cfg(not(test))]
fn load_node_event_log_sources(root: &Path) -> Vec<PathBuf> {
    let mut sources = BTreeSet::<PathBuf>::new();

    if let Some(manifest_path) = normalized_path_from_env(NODE_EVENT_LOG_MANIFEST_ENV) {
        if let Ok(raw) = fs::read_to_string(&manifest_path) {
            let manifest_dir = manifest_path.parent().unwrap_or_else(|| Path::new("."));
            for line in raw.lines() {
                let trimmed = line.trim();
                if trimmed.is_empty() || trimmed.starts_with('#') {
                    continue;
                }
                let normalized = normalize_wrapped_env_value(trimmed);
                if normalized.is_empty() || normalized.starts_with('#') {
                    continue;
                }
                let path = PathBuf::from(normalized);
                let resolved = if path.is_absolute() {
                    path
                } else {
                    manifest_dir.join(path)
                };
                sources.insert(resolved);
            }
        }
    }

    if let Ok(raw) = std::env::var(NODE_EVENT_LOG_SOURCES_ENV) {
        for path in parse_node_event_log_sources_list(&raw) {
            let resolved = if path.is_absolute() {
                path
            } else {
                root.join(path)
            };
            sources.insert(resolved);
        }
    }

    if sources.is_empty() {
        return discover_default_node_event_log_sources(root);
    }

    sources.into_iter().collect()
}

fn node_event_log_candidates(root: &Path) -> Vec<PathBuf> {
    load_node_event_log_sources(root)
}

#[cfg(test)]
pub(crate) fn load_node_events_from_root(root: &Path, mode: NodeEventScanMode) -> LoadedNodeEvents {
    let candidates = node_event_log_candidates(root);
    let tail_bytes = node_event_log_tail_bytes();
    let mut lines = Vec::new();
    let mut truncated = false;
    for p in candidates {
        let raw = match mode {
            NodeEventScanMode::Authoritative => fs::read_to_string(&p).ok(),
            NodeEventScanMode::RecentTail => {
                if let Ok(meta) = fs::metadata(&p) {
                    if meta.len() > tail_bytes {
                        truncated = true;
                    }
                }
                read_log_tail(&p, tail_bytes)
            }
        };
        if let Some(raw) = raw {
            lines.extend(raw.lines().map(str::to_string));
        }
    }

    let mut out = Vec::new();
    for line in lines {
        let Some(event_pos) = line.find("[event]") else {
            continue;
        };
        let event_line = &line[event_pos..];
        if !event_line.contains("event_type=") {
            continue;
        }
        let kv = parse_event_log_kv(event_line);

        let Some(task_id) = kv.get("task_id").and_then(|s| parse_u64_kv_value(s)) else {
            continue;
        };
        let Some(tx_id) = kv.get("tx_id").and_then(|s| parse_u64_kv_value(s)) else {
            continue;
        };
        let Some(block_height) = kv.get("block_height").and_then(|s| parse_u64_kv_value(s)) else {
            continue;
        };
        let ts_unix_ms = kv
            .get("ts_unix_ms")
            .and_then(|s| parse_u128_kv_value(s))
            .unwrap_or(0);

        let normalize_opt = |k: &str| normalize_opt_kv(&kv, k);

        out.push(NodeEventRecord {
            event_type: kv
                .get("event_type")
                .cloned()
                .unwrap_or_else(|| "unknown".into()),
            task_id,
            from_status: kv
                .get("from_status")
                .cloned()
                .unwrap_or_else(|| "NONE".into()),
            to_status: kv
                .get("to_status")
                .cloned()
                .unwrap_or_else(|| "NONE".into()),
            actor: kv.get("actor").cloned().unwrap_or_else(|| "unknown".into()),
            tx_id,
            block_height,
            state_root: kv
                .get("state_root")
                .cloned()
                .unwrap_or_else(|| "unknown".into()),
            ts_unix_ms,
            signer: normalize_opt("signer"),
            challenger: normalize_opt("challenger"),
            tx_hash: normalize_opt("tx_hash"),
            resolution_code: normalize_opt("resolution_code"),
            treasury_delta: kv
                .get("treasury_delta")
                .and_then(|v| parse_i128_kv_value(v)),
            challenger_delta: kv
                .get("challenger_delta")
                .and_then(|v| parse_i128_kv_value(v)),
            bond_disposition: normalize_opt("bond_disposition"),
            metering: parse_event_metering_query_response(&kv),
        });
    }
    LoadedNodeEvents {
        events: out,
        mode,
        truncated,
    }
}

#[cfg(not(test))]
pub(crate) fn load_node_events_from_root(root: &Path, mode: NodeEventScanMode) -> LoadedNodeEvents {
    let candidates = node_event_log_candidates(root);
    let mut lines = Vec::new();
    let truncated = false;
    for p in candidates {
        let raw = match mode {
            NodeEventScanMode::Authoritative => fs::read_to_string(&p).ok(),
        };
        if let Some(raw) = raw {
            lines.extend(raw.lines().map(str::to_string));
        }
    }

    let mut out = Vec::new();
    for line in lines {
        let Some(event_pos) = line.find("[event]") else {
            continue;
        };
        let event_line = &line[event_pos..];
        if !event_line.contains("event_type=") {
            continue;
        }
        let kv = parse_event_log_kv(event_line);

        let Some(task_id) = kv.get("task_id").and_then(|s| parse_u64_kv_value(s)) else {
            continue;
        };
        let Some(tx_id) = kv.get("tx_id").and_then(|s| parse_u64_kv_value(s)) else {
            continue;
        };
        let Some(block_height) = kv.get("block_height").and_then(|s| parse_u64_kv_value(s)) else {
            continue;
        };
        let ts_unix_ms = kv
            .get("ts_unix_ms")
            .and_then(|s| parse_u128_kv_value(s))
            .unwrap_or(0);

        let normalize_opt = |k: &str| normalize_opt_kv(&kv, k);

        out.push(NodeEventRecord {
            event_type: kv
                .get("event_type")
                .cloned()
                .unwrap_or_else(|| "unknown".into()),
            task_id,
            from_status: kv
                .get("from_status")
                .cloned()
                .unwrap_or_else(|| "NONE".into()),
            to_status: kv
                .get("to_status")
                .cloned()
                .unwrap_or_else(|| "NONE".into()),
            actor: kv.get("actor").cloned().unwrap_or_else(|| "unknown".into()),
            tx_id,
            block_height,
            state_root: kv
                .get("state_root")
                .cloned()
                .unwrap_or_else(|| "unknown".into()),
            ts_unix_ms,
            signer: normalize_opt("signer"),
            challenger: normalize_opt("challenger"),
            tx_hash: normalize_opt("tx_hash"),
            resolution_code: normalize_opt("resolution_code"),
            treasury_delta: kv
                .get("treasury_delta")
                .and_then(|v| parse_i128_kv_value(v)),
            challenger_delta: kv
                .get("challenger_delta")
                .and_then(|v| parse_i128_kv_value(v)),
            bond_disposition: normalize_opt("bond_disposition"),
            metering: parse_event_metering_query_response(&kv),
        });
    }
    LoadedNodeEvents {
        events: out,
        mode,
        truncated,
    }
}

pub(crate) fn load_node_events(mode: NodeEventScanMode) -> LoadedNodeEvents {
    let root = run_root();
    load_node_events_from_root(&root, mode)
}

#[cfg(test)]
pub(crate) fn load_latest_node_events() -> Vec<NodeEventRecord> {
    load_node_events(NodeEventScanMode::RecentTail).events
}
