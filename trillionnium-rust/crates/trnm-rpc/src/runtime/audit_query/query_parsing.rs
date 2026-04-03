use super::*;

const INVALID_LIMIT_RESPONSE: &str =
    "{\"ok\":false,\"code\":\"BAD_REQUEST\",\"message\":\"invalid limit\"}";
const DUPLICATE_LIMIT_RESPONSE: &str =
    "{\"ok\":false,\"code\":\"BAD_REQUEST\",\"message\":\"duplicate limit\"}";
const INVALID_QUERY_RESPONSE: &str =
    r#"{"ok":false,"code":"BAD_REQUEST","message":"invalid query"}"#;
const DUPLICATE_SOURCE_RESPONSE: &str =
    r#"{"ok":false,"code":"BAD_REQUEST","message":"duplicate source"}"#;
const INVALID_SOURCE_RESPONSE: &str =
    r#"{"ok":false,"code":"BAD_REQUEST","message":"invalid source"}"#;
const DUPLICATE_EVENT_TYPE_RESPONSE: &str =
    r#"{"ok":false,"code":"BAD_REQUEST","message":"duplicate eventType"}"#;
const INVALID_EVENT_TYPE_RESPONSE: &str =
    r#"{"ok":false,"code":"BAD_REQUEST","message":"invalid eventType"}"#;
const DUPLICATE_CURSOR_RESPONSE: &str =
    r#"{"ok":false,"code":"BAD_REQUEST","message":"duplicate cursor"}"#;
const INVALID_CURSOR_RESPONSE: &str =
    r#"{"ok":false,"code":"BAD_REQUEST","message":"invalid cursor"}"#;

fn is_valid_normalized_audit_source(value: &str) -> bool {
    matches!(value, "trnm.task" | "trnm.adapter")
}

fn is_valid_normalized_audit_event_type(value: &str) -> bool {
    let Some(suffix) = value
        .strip_prefix("trnm.task.")
        .or_else(|| value.strip_prefix("trnm.adapter."))
    else {
        return false;
    };

    !suffix.is_empty()
        && suffix
            .chars()
            .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || matches!(ch, '.' | '-' | '_'))
}

pub(crate) fn parse_query_events_limit_from_path(path: &str) -> std::result::Result<usize, String> {
    validate_path_prefix(path, None, INVALID_LIMIT_RESPONSE)?;
    let Some(query) = extract_validated_query(path, INVALID_LIMIT_RESPONSE)? else {
        return Ok(QUERY_EVENTS_LIMIT_DEFAULT);
    };

    let mut parsed_limit: Option<usize> = None;
    for pair in query.split('&') {
        let (key, value) = split_query_pair(pair, INVALID_LIMIT_RESPONSE)?;
        let normalized_key = normalize_wrapped_env_value(key);
        if !normalized_key.eq_ignore_ascii_case("limit") || key != "limit" {
            return Err(bad_request(INVALID_LIMIT_RESPONSE));
        }
        if parsed_limit.is_some() {
            return Err(bad_request(DUPLICATE_LIMIT_RESPONSE));
        }

        let normalized = normalized_required_value(value, INVALID_LIMIT_RESPONSE)?;
        let requested = normalized
            .parse::<usize>()
            .map_err(|_| bad_request(INVALID_LIMIT_RESPONSE))?;
        parsed_limit = Some(clamp_limit(
            "QueryEventsHttp",
            requested,
            QUERY_EVENTS_LIMIT_DEFAULT,
            QUERY_EVENTS_LIMIT_MAX,
        ));
    }

    Ok(parsed_limit.unwrap_or(QUERY_EVENTS_LIMIT_DEFAULT))
}

pub(crate) fn parse_query_normalized_audit_events_query_from_path(
    path: &str,
) -> std::result::Result<QueryNormalizedAuditEventsQuery, String> {
    validate_path_prefix(
        path,
        Some("/query-normalized-audit-events"),
        INVALID_QUERY_RESPONSE,
    )?;

    let Some(query) = extract_validated_query(path, INVALID_QUERY_RESPONSE)? else {
        return Ok(default_normalized_audit_events_query());
    };

    let mut query_params = default_normalized_audit_events_query();
    let mut parsed_limit: Option<usize> = None;

    for pair in query.split('&') {
        let (key, value) = split_query_pair(pair, INVALID_QUERY_RESPONSE)?;
        let normalized_key = normalize_wrapped_env_value(key);
        match normalized_key {
            key if key.eq_ignore_ascii_case("source") && key == "source" => {
                if query_params.source.is_some() {
                    return Err(bad_request(DUPLICATE_SOURCE_RESPONSE));
                }
                let normalized = normalized_required_value(value, INVALID_SOURCE_RESPONSE)?;
                if !is_valid_normalized_audit_source(normalized) {
                    return Err(bad_request(INVALID_SOURCE_RESPONSE));
                }
                query_params.source = Some(normalized.to_string());
            }
            key if key.eq_ignore_ascii_case("eventType") && key == "eventType" => {
                if query_params.event_type.is_some() {
                    return Err(bad_request(DUPLICATE_EVENT_TYPE_RESPONSE));
                }
                let normalized = normalized_required_value(value, INVALID_EVENT_TYPE_RESPONSE)?;
                if !is_valid_normalized_audit_event_type(normalized) {
                    return Err(bad_request(INVALID_EVENT_TYPE_RESPONSE));
                }
                query_params.event_type = Some(normalized.to_string());
            }
            key if key.eq_ignore_ascii_case("cursor") && key == "cursor" => {
                if query_params.cursor.is_some() {
                    return Err(bad_request(DUPLICATE_CURSOR_RESPONSE));
                }
                let parsed = normalized_required_value(value, INVALID_CURSOR_RESPONSE)?
                    .parse::<usize>()
                    .map_err(|_| bad_request(INVALID_CURSOR_RESPONSE))?;
                query_params.cursor = Some(parsed);
            }
            key if key.eq_ignore_ascii_case("limit") && key == "limit" => {
                if parsed_limit.is_some() {
                    return Err(bad_request(DUPLICATE_LIMIT_RESPONSE));
                }
                let requested = normalized_required_value(value, INVALID_LIMIT_RESPONSE)?
                    .parse::<usize>()
                    .map_err(|_| bad_request(INVALID_LIMIT_RESPONSE))?;
                parsed_limit = Some(clamp_limit(
                    "QueryNormalizedAuditEventsHttp",
                    requested,
                    QUERY_NORMALIZED_AUDIT_EVENTS_LIMIT_DEFAULT,
                    QUERY_NORMALIZED_AUDIT_EVENTS_LIMIT_MAX,
                ));
            }
            _ => return Err(bad_request(INVALID_QUERY_RESPONSE)),
        }
    }

    if let Some(source) = query_params.source.as_deref() {
        if let Some(event_type) = query_params.event_type.as_deref() {
            let prefix = if source == "trnm.task" {
                "trnm.task."
            } else {
                "trnm.adapter."
            };
            if !event_type.starts_with(prefix) {
                return Err(bad_request(INVALID_EVENT_TYPE_RESPONSE));
            }
        }
    }

    if let Some(limit) = parsed_limit {
        query_params.limit = limit;
    }

    Ok(query_params)
}

fn default_normalized_audit_events_query() -> QueryNormalizedAuditEventsQuery {
    QueryNormalizedAuditEventsQuery {
        source: None,
        event_type: None,
        cursor: None,
        limit: QUERY_NORMALIZED_AUDIT_EVENTS_LIMIT_DEFAULT,
    }
}

fn contains_malformed_percent_encoding(value: &str) -> bool {
    let bytes = value.as_bytes();
    let mut idx = 0;
    while idx < bytes.len() {
        if bytes[idx] == b'%' {
            if idx + 2 >= bytes.len() {
                return true;
            }
            let hi = (bytes[idx + 1] as char).to_digit(16);
            let lo = (bytes[idx + 2] as char).to_digit(16);
            if hi.is_none() || lo.is_none() {
                return true;
            }
            idx += 3;
            continue;
        }
        idx += 1;
    }
    false
}

fn contains_percent_encoded_control_or_space(value: &str) -> bool {
    let bytes = value.as_bytes();
    let mut idx = 0;
    while idx + 2 < bytes.len() {
        if bytes[idx] == b'%' {
            let hi = (bytes[idx + 1] as char).to_digit(16);
            let lo = (bytes[idx + 2] as char).to_digit(16);
            if let (Some(hi), Some(lo)) = (hi, lo) {
                let decoded = ((hi << 4) | lo) as u8;
                if decoded <= 0x20 || decoded == 0x7f || (0x80..=0x9f).contains(&decoded) {
                    return true;
                }
            }
        }
        idx += 1;
    }
    false
}

fn validate_path_prefix<'a>(
    path: &'a str,
    required_prefix: Option<&str>,
    error_body: &str,
) -> std::result::Result<&'a str, String> {
    let path_without_query = path.split('?').next().unwrap_or(path);
    let normalized_path = path_without_query.to_ascii_lowercase();
    let has_invalid_path = !path_without_query.starts_with('/')
        || required_prefix.is_some_and(|prefix| path_without_query != prefix)
        || path_without_query.contains('\\')
        || path_without_query.contains('#')
        || path_without_query
            .chars()
            .any(|ch| ch.is_control() || ch.is_whitespace())
        || normalized_path.contains("%5c")
        || normalized_path.contains("%23")
        || normalized_path.contains("%2f")
        || normalized_path.contains("%2e")
        || contains_malformed_percent_encoding(path_without_query)
        || contains_percent_encoded_control_or_space(path_without_query)
        || path_without_query
            .split('/')
            .any(|segment| segment == "." || segment == "..");
    if has_invalid_path {
        Err(bad_request(error_body))
    } else {
        Ok(path_without_query)
    }
}

fn extract_validated_query<'a>(
    path: &'a str,
    error_body: &str,
) -> std::result::Result<Option<&'a str>, String> {
    let Some(query) = path.split_once('?').map(|(_, query)| query) else {
        return Ok(None);
    };

    if query.is_empty()
        || query.contains('?')
        || query.contains('#')
        || query.chars().any(|ch| ch.is_control() || ch.is_whitespace())
    {
        return Err(bad_request(error_body));
    }

    let normalized_query = query.to_ascii_lowercase();
    if normalized_query.contains("%26")
        || normalized_query.contains("%3d")
        || normalized_query.contains("%23")
        || normalized_query.contains("%3f")
        || contains_malformed_percent_encoding(query)
        || contains_percent_encoded_control_or_space(query)
    {
        return Err(bad_request(error_body));
    }

    Ok(Some(query))
}

fn split_query_pair<'a>(
    pair: &'a str,
    error_body: &str,
) -> std::result::Result<(&'a str, &'a str), String> {
    if pair.is_empty() {
        return Err(bad_request(error_body));
    }
    pair.split_once('=').ok_or_else(|| bad_request(error_body))
}

fn normalized_required_value<'a>(
    value: &'a str,
    error_body: &str,
) -> std::result::Result<&'a str, String> {
    let normalized = normalize_wrapped_env_value(value);
    if normalized.is_empty() {
        Err(bad_request(error_body))
    } else {
        Ok(normalized)
    }
}

fn bad_request(body: &str) -> String {
    http_json_response("400 Bad Request", body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_normalized_audit_events_accepts_only_exact_route_without_query() {
        let parsed = parse_query_normalized_audit_events_query_from_path(
            "/query-normalized-audit-events",
        )
        .expect("exact route should parse");

        assert_eq!(parsed, default_normalized_audit_events_query());
    }

    #[test]
    fn query_normalized_audit_events_rejects_trailing_slash_route() {
        let err = parse_query_normalized_audit_events_query_from_path(
            "/query-normalized-audit-events/",
        )
        .expect_err("trailing slash should fail closed");

        assert_eq!(err, http_json_response("400 Bad Request", INVALID_QUERY_RESPONSE));
    }

    #[test]
    fn query_normalized_audit_events_rejects_limit_case_drift() {
        let err = parse_query_normalized_audit_events_query_from_path(
            "/query-normalized-audit-events?Limit=25",
        )
        .expect_err("case-drifted limit key should fail closed");

        assert_eq!(err, http_json_response("400 Bad Request", INVALID_QUERY_RESPONSE));
    }

    #[test]
    fn query_normalized_audit_events_rejects_duplicate_limit_keys() {
        let err = parse_query_normalized_audit_events_query_from_path(
            "/query-normalized-audit-events?limit=25&limit=26",
        )
        .expect_err("duplicate limit should fail closed");

        assert_eq!(err, http_json_response("400 Bad Request", DUPLICATE_LIMIT_RESPONSE));
    }
}
