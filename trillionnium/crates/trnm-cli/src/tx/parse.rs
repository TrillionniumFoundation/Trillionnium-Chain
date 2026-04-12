use super::*;

fn canonical_json_key(key: &str) -> String {
    key.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

fn json_get_alias<'a>(value: &'a serde_json::Value, aliases: &[&str]) -> Option<&'a serde_json::Value> {
    let object = value.as_object()?;
    object.iter().find_map(|(key, value)| {
        let canonical = canonical_json_key(key);
        aliases
            .iter()
            .any(|alias| canonical == canonical_json_key(alias))
            .then_some(value)
    })
}

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
                            | '"' | '\'' | '`' | '“' | '”' | '‘' | '’'
                            | '（' | '）' | '［' | '］' | '｛' | '｝' | '＜' | '＞'
                            | '「' | '」' | '『' | '』' | '《' | '》' | '〈' | '〉' | '｢' | '｣'
                            | '«' | '»' | '‹' | '›'
                            | '【' | '】' | '〔' | '〕' | '〖' | '〗' | '〘' | '〙' | '〚' | '〛'
                            | '〝' | '〞' | '〟'
                            | '，' | '；' | '：' | '！' | '？'
                            | '。' | '｡' | '．' | '﹒' | '․'
                    )
                    || matches!(c, '.' | '!' | '?')
                    || matches!(
                        c,
                        '\u{200B}'
                            | '\u{200C}'
                            | '\u{200D}'
                            | '\u{200E}'
                            | '\u{200F}'
                            | '\u{061C}'
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

    if cleaned.starts_with("0X") {
        cleaned.replace_range(..2, "0x");
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
    if let Some(h) = json_get_alias(v, &direct).and_then(|x| x.as_str()) {
        if let Some(normalized) = normalize_tx_hash(h) {
            return Some(normalized);
        }
    }

    for key in ["result", "tx_response", "txResponse", "response", "data"] {
        if let Some(found) = json_get_alias(v, &[key]).and_then(json_value_tx_hash) {
            return Some(found);
        }
    }

    None
}

fn is_text_tx_hash_key(key: &str) -> bool {
    let canonical = key
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_lowercase())
        .collect::<String>();
    matches!(canonical.as_str(), "txhash" | "transactionhash")
}

pub(crate) fn extract_tx_hash(text: &str) -> Option<String> {
    for line in text.lines() {
        if let Some((key, value)) = parse_kv_line(line) {
            if is_text_tx_hash_key(&key) {
                if let Some(normalized) = normalize_tx_hash(&value) {
                    return Some(normalized);
                }
            }
        }

        let tokens = line.split_whitespace().collect::<Vec<_>>();
        if let Some(v) = tokens.iter().find_map(|w| {
            let (key, value) = parse_inline_kv_token(w)?;
            is_text_tx_hash_key(&key)
                .then(|| normalize_tx_hash(&value))
                .flatten()
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
            if !matches!(sep, "=" | ":" | "＝" | "：") {
                continue;
            }
            if is_text_tx_hash_key(key) {
                if let Some(normalized) = normalize_tx_hash(value) {
                    return Some(normalized);
                }
            }
        }

        for window in tokens.windows(4) {
            let key = format!("{} {}", window[0], window[1]);
            let sep = window[2].trim();
            let value = window[3].trim_matches(|c: char| {
                c.is_ascii_whitespace()
                    || matches!(c, ',' | ';' | '(' | ')' | '[' | ']' | '{' | '}' | '<' | '>')
            });
            if !matches!(sep, "=" | ":" | "＝" | "：") {
                continue;
            }
            if is_text_tx_hash_key(&key) {
                if let Some(normalized) = normalize_tx_hash(value) {
                    return Some(normalized);
                }
            }
        }
    }

    if let Ok(v) = serde_json::from_str::<serde_json::Value>(text) {
        return json_value_tx_hash(&v);
    }

    None
}

fn trim_kv_key_noise(raw: &str) -> &str {
    raw.trim_matches(|c: char| {
        c.is_whitespace()
            || c.is_control()
            || matches!(
                c,
                ','
                    | ';'
                    | '{'
                    | '}'
                    | '['
                    | ']'
                    | '('
                    | ')'
                    | '<'
                    | '>'
                    | '"'
                    | '\''
                    | '`'
                    | '“'
                    | '”'
                    | '‘'
                    | '’'
                    | '（'
                    | '）'
                    | '［'
                    | '］'
                    | '｛'
                    | '｝'
                    | '＜'
                    | '＞'
                    | '「'
                    | '」'
                    | '『'
                    | '』'
                    | '《'
                    | '》'
                    | '〈'
                    | '〉'
                    | '｢'
                    | '｣'
                    | '«'
                    | '»'
                    | '‹'
                    | '›'
                    | '【'
                    | '】'
                    | '〔'
                    | '〕'
                    | '〖'
                    | '〗'
                    | '〘'
                    | '〙'
                    | '〚'
                    | '〛'
                    | '〝'
                    | '〞'
                    | '〟'
                    | '，'
                    | '；'
                    | '：'
                    | '！'
                    | '？'
            )
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
}

fn canonical_kv_key(key: &str) -> String {
    trim_kv_key_noise(key)
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

fn parse_kv_line(line: &str) -> Option<(String, String)> {
    let trimmed = line.trim();
    let (key, value) = if let Some((k, v)) = trimmed.split_once('=') {
        (k.trim(), v.trim())
    } else if let Some((k, v)) = trimmed.split_once(':') {
        (k.trim(), v.trim())
    } else if let Some((k, v)) = trimmed.split_once('＝') {
        (k.trim(), v.trim())
    } else if let Some((k, v)) = trimmed.split_once('：') {
        (k.trim(), v.trim())
    } else {
        return None;
    };

    let key = trim_kv_key_noise(key);
    let value = value.trim_matches(|c: char| {
        c.is_ascii_whitespace()
            || matches!(c, ',' | ';' | '{' | '}' | '[' | ']' | '(' | ')' | '<' | '>')
    });

    if key.is_empty() {
        return None;
    }

    Some((canonical_kv_key(key), value.to_string()))
}

fn parse_inline_kv_token(token: &str) -> Option<(String, String)> {
    let trimmed = token.trim_matches(|c: char| {
        c.is_whitespace()
            || c.is_control()
            || matches!(
                c,
                ','
                    | ';'
                    | '{'
                    | '}'
                    | '['
                    | ']'
                    | '('
                    | ')'
                    | '<'
                    | '>'
                    | '"'
                    | '\''
                    | '`'
                    | '“'
                    | '”'
                    | '‘'
                    | '’'
                    | '（'
                    | '）'
                    | '［'
                    | '］'
                    | '｛'
                    | '｝'
                    | '＜'
                    | '＞'
                    | '「'
                    | '」'
                    | '『'
                    | '』'
                    | '《'
                    | '》'
                    | '〈'
                    | '〉'
                    | '｢'
                    | '｣'
                    | '«'
                    | '»'
                    | '‹'
                    | '›'
                    | '【'
                    | '】'
                    | '〔'
                    | '〕'
                    | '〖'
                    | '〗'
                    | '〘'
                    | '〙'
                    | '〚'
                    | '〛'
                    | '〝'
                    | '〞'
                    | '〟'
                    | '，'
                    | '；'
                    | '：'
                    | '！'
                    | '？'
            )
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
    });
    let (key, value) = if let Some((k, v)) = trimmed.split_once('=') {
        (k.trim(), v.trim())
    } else if let Some((k, v)) = trimmed.split_once(':') {
        (k.trim(), v.trim())
    } else if let Some((k, v)) = trimmed.split_once('＝') {
        (k.trim(), v.trim())
    } else if let Some((k, v)) = trimmed.split_once('：') {
        (k.trim(), v.trim())
    } else {
        return None;
    };

    let key = trim_kv_key_noise(key);
    if key.is_empty() || value.is_empty() {
        return None;
    }

    Some((
        canonical_kv_key(key),
        value
            .trim_matches(|c: char| {
                c.is_whitespace()
                    || c.is_control()
                    || matches!(
                        c,
                        ','
                            | ';'
                            | '{'
                            | '}'
                            | '['
                            | ']'
                            | '('
                            | ')'
                            | '<'
                            | '>'
                            | '（'
                            | '）'
                            | '［'
                            | '］'
                            | '｛'
                            | '｝'
                            | '＜'
                            | '＞'
                            | '「'
                            | '」'
                            | '『'
                            | '』'
                            | '《'
                            | '》'
                            | '〈'
                            | '〉'
                            | '｢'
                            | '｣'
                            | '，'
                            | '；'
                            | '：'
                            | '！'
                            | '？'
                    )
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
            c.is_whitespace()
                || c.is_control()
                || matches!(
                    c,
                    '"'
                        | '\''
                        | '`'
                        | '“'
                        | '”'
                        | '‘'
                        | '’'
                        | '('
                        | ')'
                        | '['
                        | ']'
                        | '{'
                        | '}'
                        | '<'
                        | '>'
                        | ','
                        | ';'
                        | ':'
                        | '（'
                        | '）'
                        | '［'
                        | '］'
                        | '｛'
                        | '｝'
                        | '＜'
                        | '＞'
                        | '「'
                        | '」'
                        | '『'
                        | '』'
                        | '《'
                        | '》'
                        | '〈'
                        | '〉'
                        | '｢'
                        | '｣'
                        | '«'
                        | '»'
                        | '‹'
                        | '›'
                        | '【'
                        | '】'
                        | '〔'
                        | '〕'
                        | '〖'
                        | '〗'
                        | '〘'
                        | '〙'
                        | '〚'
                        | '〛'
                        | '，'
                        | '；'
                        | '：'
                        | '！'
                        | '？'
                )
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
        .trim_end_matches(|c: char| c.is_ascii_punctuation() || matches!(c, '！' | '？' | '，' | '；' | '：'))
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
        .trim_matches(|c: char| {
            c.is_whitespace()
                || c.is_control()
                || matches!(
                    c,
                    '"'
                        | '\''
                        | '`'
                        | '“'
                        | '”'
                        | '‘'
                        | '’'
                        | '<'
                        | '>'
                        | '('
                        | ')'
                        | '['
                        | ']'
                        | '{'
                        | '}'
                        | '（'
                        | '）'
                        | '［'
                        | '］'
                        | '｛'
                        | '｝'
                        | '＜'
                        | '＞'
                        | '「'
                        | '」'
                        | '『'
                        | '』'
                        | '《'
                        | '》'
                        | '〈'
                        | '〉'
                        | '｢'
                        | '｣'
                        | '«'
                        | '»'
                        | '‹'
                        | '›'
                        | '【'
                        | '】'
                        | '〔'
                        | '〕'
                        | '〖'
                        | '〗'
                        | '〘'
                        | '〙'
                        | '〚'
                        | '〛'
                        | '〝'
                        | '〞'
                        | '〟'
                )
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
        .trim_end_matches(|c: char| c.is_ascii_punctuation() || matches!(c, '！' | '？' | '，' | '；' | '：'))
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

fn json_u64_alias(value: &serde_json::Value, aliases: &[&str]) -> Option<u64> {
    let current = json_get_alias(value, aliases)?;
    match current {
        serde_json::Value::Number(n) => n.as_u64(),
        serde_json::Value::String(s) => s.trim().parse::<u64>().ok(),
        _ => None,
    }
}

fn infer_json_tx_status(value: &serde_json::Value) -> Option<String> {
    let nested = [
        ["tx_result", "tx-result"].as_slice(),
        ["deliver_tx", "deliver-tx"].as_slice(),
        ["check_tx", "check-tx"].as_slice(),
    ];
    for container_aliases in nested {
        if let Some(container) = json_get_alias(value, container_aliases) {
            if let Some(code) = json_u64_alias(container, &["code"]) {
                return Some(if code == 0 { "committed" } else { "fail" }.to_string());
            }
        }
    }

    for aliases in [
        ["code"].as_slice(),
        ["tx_code", "tx-code"].as_slice(),
        ["transaction_code", "transaction-code"].as_slice(),
        ["deliver_tx_code", "deliver-tx-code"].as_slice(),
        ["check_tx_code", "check-tx-code"].as_slice(),
    ] {
        if let Some(code) = json_u64_alias(value, aliases) {
            return Some(if code == 0 { "committed" } else { "fail" }.to_string());
        }
    }
    None
}

fn infer_kv_tx_status(key: &str, value: &str) -> Option<String> {
    match key {
        "code" | "txcode" | "transactioncode" | "delivertxcode" | "checktxcode" => {
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
        let payload = json_get_alias(&v, &["result"]).unwrap_or(&v);
        let nested_response = json_get_alias(payload, &["response"]);
        let nested_tx_response = json_get_alias(payload, &["tx_response", "txResponse"]).or_else(|| {
            nested_response.and_then(|r| json_get_alias(r, &["tx_response", "txResponse"]))
        });
        let nested_response_data = nested_response
            .and_then(|r| json_get_alias(r, &["data"]))
            .or_else(|| json_get_alias(payload, &["responseData"]))
            .or_else(|| json_get_alias(payload, &["data"]));
        let primary = nested_tx_response
            .or(nested_response_data)
            .or(nested_response)
            .unwrap_or(payload);
        let raw_tx_hash = json_get_alias(
            primary,
            &[
                "tx_hash",
                "txhash",
                "tx-hash",
                "txHash",
                "transaction_hash",
                "transaction-hash",
                "transactionHash",
            ],
        )
        .or_else(|| {
            json_get_alias(
                payload,
                &[
                    "tx_hash",
                    "txhash",
                    "tx-hash",
                    "txHash",
                    "transaction_hash",
                    "transaction-hash",
                    "transactionHash",
                ],
            )
        });
        let tx_hash = match raw_tx_hash {
            Some(raw_hash) => normalize_tx_hash(
                raw_hash
                    .as_str()
                    .ok_or_else(|| anyhow!("invalid tx_hash field in tx query response"))?,
            )
            .ok_or_else(|| anyhow!("invalid tx_hash field in tx query response"))?,
            None => normalize_tx_hash(requested_tx_hash)
                .unwrap_or_else(|| requested_tx_hash.to_string()),
        };
        let status = json_get_alias(
            primary,
            &[
                "status",
                "tx_status",
                "txStatus",
                "transaction_status",
                "transactionStatus",
                "state",
                "tx_state",
                "txState",
                "transaction_state",
                "transactionState",
            ],
        )
        .or_else(|| {
            json_get_alias(
                payload,
                &[
                    "status",
                    "tx_status",
                    "txStatus",
                    "transaction_status",
                    "transactionStatus",
                    "state",
                    "tx_state",
                    "txState",
                    "transaction_state",
                    "transactionState",
                ],
            )
        })
        .and_then(normalize_json_status)
            .or_else(|| infer_json_tx_status(primary))
            .or_else(|| infer_json_tx_status(payload))
            .ok_or_else(|| anyhow!("missing/invalid status field in tx query response"))?;
        let error = json_get_alias(primary, &["error", "raw_log", "rawLog", "log"])
            .or_else(|| json_get_alias(payload, &["error", "raw_log", "rawLog", "log"]))
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
                "txhash" | "transactionhash" => match normalize_tx_hash(&value) {
                    Some(normalized) => tx_hash = Some(normalized),
                    None => bail!("invalid tx_hash field in tx query response"),
                },
                "status" | "txstatus" | "transactionstatus" | "state" | "txstate"
                | "transactionstate" => {
                    if let Some(normalized) = normalize_tx_status(&value) {
                        status = Some(normalized);
                    }
                }
                "code" | "txcode" | "transactioncode" | "delivertxcode"
                | "checktxcode" => {
                    if status.is_none() {
                        status = infer_kv_tx_status(&key, &value);
                    }
                }
                "error" | "rawlog" | "log" => {
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
    if !requested.starts_with("0x") {
        bail!("invalid tx hash for query (expected 0x-prefixed hex tx hash)");
    }

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
