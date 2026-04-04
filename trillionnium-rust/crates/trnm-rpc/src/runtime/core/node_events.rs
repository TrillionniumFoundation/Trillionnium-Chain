use super::*;

fn normalize_adapter_record_line(line: &str) -> &str {
    line.trim().trim_start_matches('\u{feff}').trim()
}

fn load_adapter_records_file(path: &PathBuf) -> Vec<AdapterRecord> {
    let Ok(raw) = fs::read(path) else {
        return vec![];
    };
    String::from_utf8_lossy(&raw)
        .lines()
        .map(normalize_adapter_record_line)
        .filter(|l| !l.is_empty())
        .filter_map(|l| serde_json::from_str::<AdapterRecord>(l).ok())
        .collect()
}

pub(crate) fn load_latest_adapter_records() -> Vec<AdapterRecord> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."));
    let dir = root.join("run/worker-agent");
    let Ok(entries) = fs::read_dir(&dir) else {
        return vec![];
    };

    let mut files: Vec<PathBuf> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .map(|s| s.starts_with("tx-adapter-") && s.ends_with(".jsonl"))
                .unwrap_or(false)
        })
        .collect();
    files.sort();

    for path in files.iter().rev() {
        let records = load_adapter_records_file(path);
        if !records.is_empty() {
            return records;
        }
    }

    vec![]
}

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

pub(crate) fn parse_event_log_kv(line: &str) -> BTreeMap<String, String> {
    let mut kv = BTreeMap::<String, String>::new();
    let mut i = 0usize;
    let bytes = line.as_bytes();
    let len = bytes.len();

    while i < len {
        while i < len && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= len {
            break;
        }

        let key_start = i;
        while i < len && !bytes[i].is_ascii_whitespace() && bytes[i] != b'=' {
            i += 1;
        }
        if i >= len || bytes[i] != b'=' {
            while i < len && !bytes[i].is_ascii_whitespace() {
                i += 1;
            }
            continue;
        }
        let key_end = i;
        i += 1;

        if key_end <= key_start {
            continue;
        }
        let key = &line[key_start..key_end];

        let value = if i < len && (bytes[i] == b'"' || bytes[i] == b'\'') {
            let quote = bytes[i];
            i += 1;
            let mut out = String::new();
            while i < len {
                let b = bytes[i];
                i += 1;
                if b == quote {
                    break;
                }
                if b == b'\\' && i < len {
                    out.push(bytes[i] as char);
                    i += 1;
                } else {
                    out.push(b as char);
                }
            }
            out
        } else {
            let val_start = i;
            while i < len && !bytes[i].is_ascii_whitespace() {
                i += 1;
            }
            line[val_start..i].to_string()
        };

        kv.insert(key.to_string(), value);
    }

    kv
}

pub(crate) fn parse_node_event_log_sources_list(raw: &str) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut start = 0usize;
    let mut quote: Option<char> = None;

    for (idx, ch) in raw.char_indices() {
        match quote {
            Some(active) if ch == active => quote = None,
            Some(_) => {}
            None if matches!(ch, '"' | '\'' | '`') => quote = Some(ch),
            None if matches!(ch, ',' | ';' | '\n' | '\r') => {
                let normalized = normalize_wrapped_env_value(raw[start..idx].trim());
                if !normalized.is_empty() {
                    out.push(PathBuf::from(normalized));
                }
                start = idx + ch.len_utf8();
            }
            None => {}
        }
    }

    let normalized = normalize_wrapped_env_value(raw[start..].trim());
    if !normalized.is_empty() {
        out.push(PathBuf::from(normalized));
    }

    out
}

#[cfg(test)]
mod tests {
    use super::parse_node_event_log_sources_list;
    use std::path::PathBuf;

    #[test]
    fn parse_node_event_log_sources_list_accepts_carriage_return_separators_for_historical_replay() {
        let parsed = parse_node_event_log_sources_list(
            "\"archive/node4.log\"\r'archive/node5.log'\rplain.log\r",
        );

        assert_eq!(
            parsed,
            vec![
                PathBuf::from("archive/node4.log"),
                PathBuf::from("archive/node5.log"),
                PathBuf::from("plain.log"),
            ],
            "carriage-return separated historical replay aliases should parse as distinct sources"
        );
    }

    #[test]
    fn parse_node_event_log_sources_list_keeps_wrapped_entries_with_internal_delimiters() {
        let parsed = parse_node_event_log_sources_list(
            "\"archive/node,4.log\";'archive/node;5.log';`archive/node\n6.log`,plain.log",
        );

        assert_eq!(
            parsed,
            vec![
                PathBuf::from("archive/node,4.log"),
                PathBuf::from("archive/node;5.log"),
                PathBuf::from("archive/node\n6.log"),
                PathBuf::from("plain.log"),
            ],
            "wrapped historical replay env entries should keep internal delimiters instead of being split into bogus paths"
        );
    }
}

fn normalize_lexical_path(path: PathBuf) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                if !normalized.pop() {
                    normalized.push(component.as_os_str());
                }
            }
            other => normalized.push(other.as_os_str()),
        }
    }
    normalized
}

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

pub(crate) fn load_node_event_log_sources(root: &Path) -> Vec<PathBuf> {
    let mut sources = BTreeSet::<PathBuf>::new();

    if let Some(manifest_path) = normalized_path_from_env(NODE_EVENT_LOG_MANIFEST_ENV) {
        let manifest_path = if manifest_path.is_absolute() {
            normalize_lexical_path(manifest_path)
        } else {
            normalize_lexical_path(root.join(manifest_path))
        };
        if let Ok(raw) = fs::read_to_string(&manifest_path) {
            let manifest_dir = manifest_path.parent().unwrap_or_else(|| Path::new("."));
            for path in parse_node_event_log_sources_list(&raw) {
                let normalized = normalize_wrapped_env_value(&path.to_string_lossy());
                if normalized.is_empty() || normalized.starts_with('#') {
                    continue;
                }
                let path = PathBuf::from(normalized);
                let resolved = if path.is_absolute() {
                    normalize_lexical_path(path)
                } else {
                    normalize_lexical_path(manifest_dir.join(path))
                };
                sources.insert(resolved);
            }
        }
    }

    if let Ok(raw) = std::env::var(NODE_EVENT_LOG_SOURCES_ENV) {
        for path in parse_node_event_log_sources_list(&raw) {
            let normalized = normalize_wrapped_env_value(&path.to_string_lossy());
            if normalized.is_empty() || normalized.starts_with('#') {
                continue;
            }
            let path = PathBuf::from(normalized);
            let resolved = if path.is_absolute() {
                normalize_lexical_path(path)
            } else {
                normalize_lexical_path(root.join(path))
            };
            sources.insert(resolved);
        }
    }

    if sources.is_empty() {
        return discover_default_node_event_log_sources(root);
    }

    sources.into_iter().collect()
}

pub(crate) fn node_event_log_candidates(root: &Path) -> Vec<PathBuf> {
    load_node_event_log_sources(root)
}

pub(crate) fn load_node_events_from_root(root: &Path, mode: NodeEventScanMode) -> LoadedNodeEvents {
    let candidates = node_event_log_candidates(root);
    #[cfg(test)]
    let tail_bytes = node_event_log_tail_bytes();
    let mut lines = Vec::new();
    #[cfg(test)]
    let mut truncated = false;
    #[cfg(not(test))]
    let truncated = false;
    for p in candidates {
        let raw = match mode {
            NodeEventScanMode::Authoritative => fs::read_to_string(&p).ok(),
            #[cfg(test)]
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

pub(crate) fn load_node_events(mode: NodeEventScanMode) -> LoadedNodeEvents {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."));
    load_node_events_from_root(&root, mode)
}

#[cfg(test)]
pub(crate) fn load_latest_node_events() -> Vec<NodeEventRecord> {
    load_node_events(NodeEventScanMode::RecentTail).events
}
