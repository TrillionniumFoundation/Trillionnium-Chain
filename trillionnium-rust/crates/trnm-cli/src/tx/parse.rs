use super::*;

pub(crate) fn normalize_tx_hash(raw: &str) -> Option<String> {
    let mut cleaned = raw.to_string();

    loop {
        let before = cleaned.len();
        cleaned = cleaned
            .trim_matches(|c: char| {
                c.is_whitespace()
                    || c.is_control()
                    || matches!(
                        c,
                        ',' | ';' | ':' | '(' | ')' | '[' | ']' | '{' | '}' | '<' | '>'
                            | '"' | '\'' | '`'
                    )
                    || matches!(c, '.' | '!' | '?')
                    || matches!(
                        c,
                        '\u{200B}'
                            | '\u{200C}'
                            | '\u{200D}'
                            | '\u{2060}'
                            | '\u{FEFF}'
                            | '\u{202A}'
                            | '\u{202B}'
                            | '\u{202C}'
                            | '\u{202D}'
                            | '\u{202E}'
                            | '\u{2066}'
                            | '\u{2067}'
                            | '\u{2068}'
                            | '\u{2069}'
                    )
            })
            .to_string();

        if cleaned.len() >= 2 {
            let q = cleaned.chars().next().unwrap();
            let last = cleaned.chars().last().unwrap();
            if (q == '"' || q == '\'' || q == '`') && q == last {
                cleaned = cleaned[1..cleaned.len() - 1].to_string();
                continue;
            }
        }
        if cleaned.len() == before {
            break;
        }
    }

    cleaned = cleaned.to_ascii_lowercase();

    if cleaned.starts_with("0x") && cleaned.len() > 2 {
        let body = &cleaned[2..];
        if body.chars().all(|c| c.is_ascii_hexdigit()) {
            return Some(cleaned);
        }
        return None;
    }

    let is_hex_like = cleaned.chars().all(|c| c.is_ascii_hexdigit());
    if is_hex_like && cleaned.len() >= 6 {
        return Some(cleaned);
    }

    None
}

fn json_value_tx_hash(v: &serde_json::Value) -> Option<String> {
    let direct = [
        "tx_hash",
        "txhash",
        "tx-hash",
        "txHash",
        "transaction_hash",
        "transaction-hash",
        "transactionHash",
    ];
    for key in direct {
        if let Some(h) = v.get(key).and_then(|x| x.as_str()) {
            if let Some(normalized) = normalize_tx_hash(h) {
                return Some(normalized);
            }
        }
    }

    for key in ["result", "tx_response", "txResponse", "response", "data"] {
        if let Some(found) = v.get(key).and_then(json_value_tx_hash) {
            return Some(found);
        }
    }

    None
}

pub(crate) fn extract_tx_hash(text: &str) -> Option<String> {
    for line in text.lines() {
        if let Some((key, value)) = parse_kv_line(line) {
            match key.as_str() {
                "tx_hash" | "txhash" | "tx-hash" | "transaction_hash" | "transactionhash"
                | "transaction-hash" => {
                    if let Some(normalized) = normalize_tx_hash(&value) {
                        return Some(normalized);
                    }
                }
                _ => {}
            }
        }

        let tokens = line.split_whitespace().collect::<Vec<_>>();
        if let Some(v) = tokens.iter().find_map(|w| {
            let trimmed = w.trim_matches(|c: char| {
                c.is_ascii_whitespace()
                    || matches!(c, ',' | ';' | '(' | ')' | '[' | ']' | '{' | '}' | '<' | '>')
            });
            let (k, v) = trimmed
                .split_once('=')
                .or_else(|| trimmed.split_once(':'))?;
            let key = k.trim_matches(|c: char| {
                c.is_ascii_whitespace()
                    || matches!(c, ',' | ';' | '(' | ')' | '[' | ']' | '{' | '}' | '<' | '>')
            });
            match key.to_ascii_lowercase().as_str() {
                "tx_hash" | "txhash" | "tx-hash" | "transaction_hash" | "transactionhash"
                | "transaction-hash" => normalize_tx_hash(v),
                _ => None,
            }
        }) {
            return Some(v);
        }

        for window in tokens.windows(3) {
            let key = window[0].trim_matches(|c: char| {
                c.is_ascii_whitespace()
                    || matches!(c, ',' | ';' | '(' | ')' | '[' | ']' | '{' | '}' | '<' | '>')
            });
            let sep = window[1].trim();
            let value = window[2].trim_matches(|c: char| {
                c.is_ascii_whitespace()
                    || matches!(c, ',' | ';' | '(' | ')' | '[' | ']' | '{' | '}' | '<' | '>')
            });
            if !matches!(sep, "=" | ":") {
                continue;
            }
            match key.to_ascii_lowercase().as_str() {
                "tx_hash" | "txhash" | "tx-hash" | "transaction_hash" | "transactionhash"
                | "transaction-hash" => {
                    if let Some(normalized) = normalize_tx_hash(value) {
                        return Some(normalized);
                    }
                }
                _ => {}
            }
        }
    }

    if let Ok(v) = serde_json::from_str::<serde_json::Value>(text) {
        return json_value_tx_hash(&v);
    }

    None
}

fn parse_kv_line(line: &str) -> Option<(String, String)> {
    let trimmed = line.trim();
    let (key, value) = if let Some((k, v)) = trimmed.split_once('=') {
        (k.trim(), v.trim())
    } else if let Some((k, v)) = trimmed.split_once(':') {
        (k.trim(), v.trim())
    } else {
        return None;
    };

    let key = key.trim_matches(|c: char| {
        c.is_ascii_whitespace()
            || matches!(c, ',' | ';' | '{' | '}' | '[' | ']' | '(' | ')' | '<' | '>')
    });
    let value = value.trim_matches(|c: char| {
        c.is_ascii_whitespace()
            || matches!(c, ',' | ';' | '{' | '}' | '[' | ']' | '(' | ')' | '<' | '>')
    });

    if key.is_empty() {
        return None;
    }

    Some((key.to_ascii_lowercase(), value.to_string()))
}

fn parse_inline_kv_token(token: &str) -> Option<(String, String)> {
    let trimmed = token.trim_matches(|c: char| {
        c.is_ascii_whitespace()
            || matches!(c, ',' | ';' | '{' | '}' | '[' | ']' | '(' | ')' | '<' | '>')
    });
    let (key, value) = if let Some((k, v)) = trimmed.split_once('=') {
        (k.trim(), v.trim())
    } else if let Some((k, v)) = trimmed.split_once(':') {
        (k.trim(), v.trim())
    } else {
        return None;
    };

    if key.is_empty() || value.is_empty() {
        return None;
    }

    Some((
        key.to_ascii_lowercase(),
        value
            .trim_matches(|c: char| {
                c.is_ascii_whitespace()
                    || matches!(c, ',' | ';' | '{' | '}' | '[' | ']' | '(' | ')' | '<' | '>')
            })
            .trim_matches('"')
            .trim_matches('\'')
            .trim_matches('`')
            .to_string(),
    ))
}

pub(crate) fn normalize_tx_status(raw: &str) -> Option<String> {
    let cleaned = raw
        .trim()
        .trim_matches(|c: char| {
            c.is_ascii_whitespace()
                || matches!(
                    c,
                    '"' | '\'' | '`' | '(' | ')' | '[' | ']' | '{' | '}' | ',' | ';' | ':'
                )
        })
        .trim_end_matches(|c: char| c.is_ascii_punctuation())
        .to_ascii_lowercase();
    let canonical = cleaned
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect::<String>()
        .trim_matches('_')
        .split('_')
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>()
        .join("_");
    match canonical.as_str() {
        "pending" | "submitted" | "accepted" | "queued" | "broadcast" | "broadcasted"
        | "broadcasting" | "processing" | "executing" | "in_progress" | "inflight"
        | "in_flight" => Some("pending".to_string()),
        "committed" | "confirmed" | "success" | "succeeded" | "ok" | "included" | "finalized"
        | "finalised" | "finalising" | "finalizing" | "complete" | "completed" | "done" => {
            Some("committed".to_string())
        }
        "fail" | "failed" | "error" | "rejected" | "reverted" | "aborted" | "dropped"
        | "timeout" | "timed_out" | "expired" => Some("fail".to_string()),
        _ => None,
    }
}

fn is_nullish_kv_value(raw: &str) -> bool {
    let cleaned = raw
        .trim()
        .trim_matches('"')
        .trim_matches('\'')
        .trim_matches('`')
        .trim_end_matches(|c: char| c.is_ascii_punctuation())
        .to_ascii_lowercase();
    cleaned.is_empty() || cleaned == "null"
}

fn normalize_json_error(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::Null => None,
        serde_json::Value::String(s) => {
            if is_nullish_kv_value(s) {
                None
            } else {
                Some(s.to_string())
            }
        }
        other => Some(other.to_string()),
    }
}

fn normalize_json_status(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::String(s) => normalize_tx_status(s),
        serde_json::Value::Number(n) => n
            .as_i64()
            .map(|code| if code == 0 { "committed" } else { "fail" }.to_string()),
        serde_json::Value::Bool(b) => Some(if *b { "committed" } else { "fail" }.to_string()),
        _ => None,
    }
}

fn json_u64_at_path(value: &serde_json::Value, path: &[&str]) -> Option<u64> {
    let mut current = value;
    for key in path {
        current = current.get(*key)?;
    }
    match current {
        serde_json::Value::Number(n) => n.as_u64(),
        serde_json::Value::String(s) => s.trim().parse::<u64>().ok(),
        _ => None,
    }
}

fn infer_json_tx_status(value: &serde_json::Value) -> Option<String> {
    for path in [
        ["tx_result", "code"].as_slice(),
        ["deliver_tx", "code"].as_slice(),
        ["check_tx", "code"].as_slice(),
        ["code"].as_slice(),
        ["tx_code"].as_slice(),
        ["transaction_code"].as_slice(),
        ["deliver_tx_code"].as_slice(),
        ["check_tx_code"].as_slice(),
    ] {
        if let Some(code) = json_u64_at_path(value, path) {
            return Some(if code == 0 { "committed" } else { "fail" }.to_string());
        }
    }
    None
}

fn infer_kv_tx_status(key: &str, value: &str) -> Option<String> {
    match key {
        "code" | "tx_code" | "txcode" | "transaction_code" | "transactioncode"
        | "deliver_tx_code" | "delivertxcode" | "check_tx_code" | "checktxcode" => {
            let cleaned = value
                .trim()
                .trim_matches('"')
                .trim_matches('\'')
                .trim_matches('`')
                .trim_end_matches(|c: char| c.is_ascii_punctuation());
            let code = cleaned.parse::<u64>().ok()?;
            Some(if code == 0 { "committed" } else { "fail" }.to_string())
        }
        _ => None,
    }
}

pub(crate) fn parse_tx_query_response(
    raw: &str,
    requested_tx_hash: &str,
) -> Result<TxQueryResponse> {
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(raw) {
        let payload = v.get("result").unwrap_or(&v);
        let nested_tx_response = payload
            .get("tx_response")
            .or_else(|| payload.get("txResponse"))
            .or_else(|| payload.get("response").and_then(|r| r.get("tx_response")))
            .or_else(|| payload.get("response").and_then(|r| r.get("txResponse")));
        let nested_response_data = payload
            .get("response")
            .and_then(|r| r.get("data"))
            .or_else(|| payload.get("responseData"));
        let primary = nested_tx_response
            .or(nested_response_data)
            .unwrap_or(payload);
        let raw_tx_hash = primary
            .get("tx_hash")
            .or_else(|| primary.get("txhash"))
            .or_else(|| primary.get("tx-hash"))
            .or_else(|| primary.get("txHash"))
            .or_else(|| primary.get("transaction_hash"))
            .or_else(|| primary.get("transaction-hash"))
            .or_else(|| primary.get("transactionHash"))
            .or_else(|| payload.get("tx_hash"))
            .or_else(|| payload.get("txhash"))
            .or_else(|| payload.get("tx-hash"))
            .or_else(|| payload.get("txHash"))
            .or_else(|| payload.get("transaction_hash"))
            .or_else(|| payload.get("transaction-hash"))
            .or_else(|| payload.get("transactionHash"))
            .and_then(|x| x.as_str());
        let tx_hash = match raw_tx_hash {
            Some(raw_hash) => normalize_tx_hash(raw_hash)
                .ok_or_else(|| anyhow!("invalid tx_hash field in tx query response"))?,
            None => normalize_tx_hash(requested_tx_hash)
                .unwrap_or_else(|| requested_tx_hash.to_string()),
        };
        let status = primary
            .get("status")
            .or_else(|| primary.get("tx_status"))
            .or_else(|| primary.get("txStatus"))
            .or_else(|| primary.get("transaction_status"))
            .or_else(|| primary.get("transactionStatus"))
            .or_else(|| primary.get("state"))
            .or_else(|| primary.get("tx_state"))
            .or_else(|| primary.get("txState"))
            .or_else(|| primary.get("transaction_state"))
            .or_else(|| primary.get("transactionState"))
            .or_else(|| payload.get("status"))
            .or_else(|| payload.get("tx_status"))
            .or_else(|| payload.get("txStatus"))
            .or_else(|| payload.get("transaction_status"))
            .or_else(|| payload.get("transactionStatus"))
            .or_else(|| payload.get("state"))
            .or_else(|| payload.get("tx_state"))
            .or_else(|| payload.get("txState"))
            .or_else(|| payload.get("transaction_state"))
            .or_else(|| payload.get("transactionState"))
            .and_then(normalize_json_status)
            .or_else(|| infer_json_tx_status(primary))
            .or_else(|| infer_json_tx_status(payload))
            .ok_or_else(|| anyhow!("missing/invalid status field in tx query response"))?;
        let error = primary
            .get("error")
            .or_else(|| primary.get("raw_log"))
            .or_else(|| primary.get("rawLog"))
            .or_else(|| primary.get("log"))
            .or_else(|| payload.get("error"))
            .or_else(|| payload.get("raw_log"))
            .or_else(|| payload.get("rawLog"))
            .or_else(|| payload.get("log"))
            .and_then(normalize_json_error);
        return Ok(TxQueryResponse {
            tx_hash,
            status,
            error,
        });
    }

    let mut tx_hash: Option<String> = None;
    let mut status: Option<String> = None;
    let mut error: Option<String> = None;
    for line in raw.lines() {
        let mut pairs = Vec::new();
        if let Some(pair) = parse_kv_line(line) {
            pairs.push(pair);
        }
        for token in line.split_whitespace() {
            if let Some(pair) = parse_inline_kv_token(token) {
                pairs.push(pair);
            }
        }

        for (key, value) in pairs {
            match key.as_str() {
                "tx_hash" | "txhash" | "tx-hash" | "transaction_hash" | "transactionhash"
                | "transaction-hash" => match normalize_tx_hash(&value) {
                    Some(normalized) => tx_hash = Some(normalized),
                    None => bail!("invalid tx_hash field in tx query response"),
                }
                "status" | "tx_status" | "txstatus" | "transaction_status"
                | "transactionstatus" | "state" | "tx_state" | "txstate" | "transaction_state"
                | "transactionstate" => {
                    if let Some(normalized) = normalize_tx_status(&value) {
                        status = Some(normalized);
                    }
                }
                "code" | "tx_code" | "txcode" | "transaction_code" | "transactioncode"
                | "deliver_tx_code" | "delivertxcode" | "check_tx_code" | "checktxcode" => {
                    if status.is_none() {
                        status = infer_kv_tx_status(&key, &value);
                    }
                }
                "error" | "raw_log" | "rawlog" | "log" => {
                    let cleaned = value.trim_matches(|c| matches!(c, '"' | '\'' | '`'));
                    if !is_nullish_kv_value(cleaned) {
                        match &error {
                            Some(existing) if existing.len() >= cleaned.len() => {}
                            _ => error = Some(cleaned.to_string()),
                        }
                    }
                }
                _ => {}
            }
        }
    }

    if let Some(status) = status {
        return Ok(TxQueryResponse {
            tx_hash: tx_hash.unwrap_or_else(|| requested_tx_hash.to_string()),
            status,
            error,
        });
    }

    bail!("failed to parse tx query response: {}", raw.trim())
}

pub(crate) fn tx_query(tx_hash: &str) -> Result<TxQueryResponse> {
    let requested = normalize_tx_hash(tx_hash)
        .ok_or_else(|| anyhow!("invalid tx hash for query (expected hex-like tx hash)"))?;

    if let Some(status) = query_local_tx_status(&requested) {
        return Ok(TxQueryResponse {
            tx_hash: requested,
            status,
            error: None,
        });
    }

    if let Ok(template) = std::env::var("TRNM_TX_QUERY_CMD") {
        let cmd = tpl(template, "tx_hash", &requested);
        let raw = run_template_raw(&cmd)?;
        let parsed = parse_tx_query_response(&raw, &requested)?;
        if let Some(got) = normalize_tx_hash(&parsed.tx_hash) {
            if requested != got {
                bail!(
                    "tx query response hash mismatch: requested={}, got={}",
                    requested,
                    got
                );
            }
        }
        return Ok(parsed);
    }

    let rpc_workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."));
    let cmd = format!("cargo run -q -p trnm-rpc -- get-tx --tx-hash {}", requested);
    match {
        let (program, args) = parse_template_command(&cmd)?;
        let out = ProcCommand::new(program)
            .args(args)
            .current_dir(&rpc_workspace)
            .output()?;
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        if !out.status.success() {
            Err(anyhow!(
                "query command failed rc={}: {}{}",
                out.status.code().unwrap_or(1),
                stdout,
                stderr
            ))
        } else {
            Ok(stdout.to_string())
        }
    } {
        Ok(raw) => {
            let parsed = parse_tx_query_response(&raw, &requested)?;
            if let Some(got) = normalize_tx_hash(&parsed.tx_hash) {
                if requested != got {
                    bail!(
                        "tx query response hash mismatch: requested={}, got={}",
                        requested,
                        got
                    );
                }
            }
            Ok(parsed)
        }
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("TX_NOT_FOUND") {
                if let Some(status) = query_local_tx_status(&requested) {
                    return Ok(TxQueryResponse {
                        tx_hash: requested,
                        status,
                        error: None,
                    });
                }
            }
            Err(e)
        }
    }
}
