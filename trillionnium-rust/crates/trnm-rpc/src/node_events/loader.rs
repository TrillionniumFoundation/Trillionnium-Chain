#[cfg(test)]
use std::io::{Read, Seek, SeekFrom};
use std::{fs, path::Path};

use crate::{LoadedNodeEvents, NodeEventScanMode, NODE_EVENT_LOG_TAIL_BYTES_DEFAULT, NODE_EVENT_LOG_TAIL_BYTES_MAX};

use super::{mapping::parse_node_event_lines, sources::node_event_log_candidates};

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

fn load_node_event_lines(root: &Path, mode: NodeEventScanMode) -> (Vec<String>, bool) {
    let candidates = node_event_log_candidates(root);

    #[cfg(test)]
    let tail_bytes = node_event_log_tail_bytes();

    let mut lines = Vec::new();
    let mut truncated = false;
    for path in candidates {
        let raw = match mode {
            NodeEventScanMode::Authoritative => fs::read_to_string(&path).ok(),
            #[cfg(test)]
            NodeEventScanMode::RecentTail => {
                if let Ok(meta) = fs::metadata(&path) {
                    if meta.len() > tail_bytes {
                        truncated = true;
                    }
                }
                read_log_tail(&path, tail_bytes)
            }
        };
        if let Some(raw) = raw {
            lines.extend(raw.lines().map(str::to_string));
        }
    }

    (lines, truncated)
}

pub(super) fn load_node_events_from_root(root: &Path, mode: NodeEventScanMode) -> LoadedNodeEvents {
    let (lines, truncated) = load_node_event_lines(root, mode);
    let events = parse_node_event_lines(&lines);
    LoadedNodeEvents {
        events,
        mode,
        truncated,
    }
}
