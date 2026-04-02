pub(crate) use super::*;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;

const MAX_ORACLE_QUERY_PATH_LEN: usize = 4096;

pub(crate) fn write_json_fixture<T: Serialize>(prefix: &str, value: &T) -> std::path::PathBuf {
    let path = unique_tmp_path(prefix, "json");
    let bytes = serde_json::to_vec_pretty(value).expect("serialize fixture");
    fs::write(&path, bytes).expect("write fixture");
    path
}

pub(crate) fn oracle_policy_fixture() -> serde_json::Value {
    json!({
        "max_staleness_ms": 60_000,
        "min_source_count": 2,
        "max_deviation_bps": 500,
        "max_update_rate_per_window": 60,
        "feed_id": "btc/usd",
    })
}

pub(crate) fn oracle_snapshot_fixture(
    aggregate_price: u64,
    reference_price: Option<u64>,
    observed_at_ms: u64,
) -> serde_json::Value {
    let reference_price = reference_price.unwrap_or(aggregate_price);
    json!({
        "observed_at_ms": observed_at_ms,
        "aggregate_price": aggregate_price,
        "reference_price": reference_price,
        "feed_id": "btc/usd",
        "sources": [
            {
                "source_id": "binance",
                "price": aggregate_price,
                "observed_at_ms": observed_at_ms,
            },
            {
                "source_id": "coinbase",
                "price": reference_price,
                "observed_at_ms": observed_at_ms,
            },
        ],
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct OracleValidationObservation {
    pub outcome: String,
    pub feed_id: String,
    pub stale_reject_total: u32,
    pub quorum_reject_total: u32,
    pub drift_reject_total: u32,
    pub accepted_total: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct OracleValidationMetrics {
    pub oracle_stale_reject_total: u32,
    pub oracle_quorum_reject_total: u32,
    pub oracle_drift_reject_total: u32,
    pub oracle_source_cardinality: u32,
    pub accepted_total: u32,
    pub sample_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct OracleValidateSnapshotResponse {
    pub ok: bool,
    pub now_ts_ms: u64,
    pub observation: OracleValidationObservation,
    pub metrics: OracleValidationMetrics,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct OracleValidateSnapshotTarget {
    pub snapshot: String,
    pub policy: String,
    pub now_ts_ms: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct SnapshotFile {
    observed_at_ms: u64,
    aggregate_price: u64,
    reference_price: u64,
    feed_id: String,
    sources: Vec<Value>,
    #[serde(default = "default_snapshot_sample_count")]
    sample_count: u32,
}

#[derive(Debug, Deserialize)]
struct PolicyFile {
    max_staleness_ms: u64,
    min_source_count: u64,
    max_deviation_bps: u64,
    #[serde(default = "default_max_update_rate_per_window")]
    max_update_rate_per_window: u64,
    feed_id: String,
}

const fn default_snapshot_sample_count() -> u32 {
    1
}

const fn default_max_update_rate_per_window() -> u64 {
    60
}

fn validate_policy_file(policy: &PolicyFile) -> Result<(), String> {
    if policy.min_source_count == 0 {
        return Err("invalid policy: min_source_count must be > 0".to_string());
    }
    if policy.max_staleness_ms == 0 {
        return Err("invalid policy: max_staleness_ms must be > 0".to_string());
    }
    if policy.max_deviation_bps > 10_000 {
        return Err("invalid policy: max_deviation_bps must be <= 10000".to_string());
    }
    if policy.max_update_rate_per_window == 0 {
        return Err("invalid policy: max_update_rate_per_window must be > 0".to_string());
    }
    if policy.min_source_count > policy.max_update_rate_per_window {
        return Err(
            "invalid policy: min_source_count must be <= max_update_rate_per_window".to_string(),
        );
    }
    Ok(())
}

fn validate_canonical_feed_id(raw: &str) -> Result<String, String> {
    let canonical = raw.trim().to_ascii_lowercase();
    if canonical.is_empty() {
        return Err("feed id is empty".to_string());
    }
    let has_non_canonical_chars = raw.chars().any(|ch| ch.is_whitespace() || ch.is_control());
    if raw != canonical || has_non_canonical_chars {
        return Err(format!(
            "feed id must be canonical lowercase+trim: raw={}, canonical={}",
            raw, canonical
        ));
    }
    Ok(canonical)
}

fn from_hex(n: u8) -> Option<u8> {
    match n {
        b'0'..=b'9' => Some(n - b'0'),
        b'a'..=b'f' => Some(n - b'a' + 10),
        b'A'..=b'F' => Some(n - b'A' + 10),
        _ => None,
    }
}

fn decode_url_component(input: &str) -> Option<String> {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                let hi = from_hex(bytes[i + 1])?;
                let lo = from_hex(bytes[i + 2])?;
                out.push((hi << 4) | lo);
                i += 3;
            }
            b'%' => return None,
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            byte => {
                out.push(byte);
                i += 1;
            }
        }
    }
    String::from_utf8(out).ok()
}

fn is_non_canonical_query_key(key: &str) -> bool {
    key.is_empty() || key.trim() != key || key.chars().any(|ch| ch.is_whitespace() || ch.is_control())
}

fn is_non_canonical_query_value(value: &str) -> bool {
    value.trim() != value || value.chars().any(|ch| ch.is_control())
}

fn contains_percent_encoded_control_or_del(value: &str) -> bool {
    let bytes = value.as_bytes();
    let mut idx = 0;
    while idx + 2 < bytes.len() {
        if bytes[idx] == b'%' {
            let hi = from_hex(bytes[idx + 1]);
            let lo = from_hex(bytes[idx + 2]);
            if let (Some(hi), Some(lo)) = (hi, lo) {
                let decoded = (hi << 4) | lo;
                if decoded <= 0x20 || decoded == 0x7f {
                    return true;
                }
            }
        }
        idx += 1;
    }
    false
}

pub(crate) fn parse_http_query_params(target: &str) -> Option<HashMap<String, String>> {
    let query = target.split_once('?')?.1;
    if query.is_empty()
        || query.contains('?')
        || query.contains('#')
        || query.chars().any(|ch| ch.is_control())
    {
        return None;
    }
    let normalized_query = query.to_ascii_lowercase();
    if normalized_query.contains("%26")
        || normalized_query.contains("%3d")
        || normalized_query.contains("%23")
        || normalized_query.contains("%3f")
        || contains_percent_encoded_control_or_del(query)
    {
        return None;
    }

    let mut out = HashMap::new();
    for pair in query.split('&') {
        if pair.is_empty() {
            return None;
        }
        let (raw_k, raw_v) = pair.split_once('=')?;
        let key = decode_url_component(raw_k)?;
        if is_non_canonical_query_key(&key) {
            return None;
        }
        let value = decode_url_component(raw_v)?;
        if out.insert(key, value).is_some() {
            return None;
        }
    }
    Some(out)
}

fn matches_exact_target_path(target: &str, path: &str) -> bool {
    target == path || target.strip_prefix(path).is_some_and(|suffix| suffix.starts_with('?'))
}

pub(crate) fn parse_oracle_validate_snapshot_target(
    target: &str,
) -> Result<OracleValidateSnapshotTarget, String> {
    if !(matches_exact_target_path(target, "/oracle/validate_snapshot")
        || matches_exact_target_path(target, "/oracle/metrics")
        || matches_exact_target_path(target, "/metrics"))
    {
        return Err("unexpected oracle target".to_string());
    }

    let params =
        parse_http_query_params(target).ok_or_else(|| "invalid query params".to_string())?;
    for key in params.keys() {
        if key != "snapshot" && key != "policy" && key != "now_ts_ms" {
            return Err(format!("unknown query parameter: {key}"));
        }
    }

    let snapshot = params
        .get("snapshot")
        .ok_or_else(|| "missing snapshot".to_string())?;
    if snapshot.trim().is_empty() {
        return Err("empty snapshot".to_string());
    }
    if is_non_canonical_query_value(snapshot) {
        return Err("non-canonical snapshot path".to_string());
    }
    let snapshot = snapshot.to_string();
    if snapshot.len() > MAX_ORACLE_QUERY_PATH_LEN {
        return Err("snapshot path too long".to_string());
    }

    let policy = params
        .get("policy")
        .ok_or_else(|| "missing policy".to_string())?;
    if policy.trim().is_empty() {
        return Err("empty policy".to_string());
    }
    if is_non_canonical_query_value(policy) {
        return Err("non-canonical policy path".to_string());
    }
    let policy = policy.to_string();
    if policy.len() > MAX_ORACLE_QUERY_PATH_LEN {
        return Err("policy path too long".to_string());
    }

    let now_ts_ms = match params.get("now_ts_ms") {
        Some(v) if !v.is_empty() && !v.trim().is_empty() => Some(
            v.parse::<u64>()
                .map_err(|_| "invalid now_ts_ms".to_string())?,
        ),
        Some(_) => return Err("empty now_ts_ms".to_string()),
        None => None,
    };

    Ok(OracleValidateSnapshotTarget {
        snapshot,
        policy,
        now_ts_ms,
    })
}

fn compute_deviation_bps(aggregate: u64, reference: u64) -> u64 {
    if reference == aggregate {
        return 0;
    }
    if reference == 0 {
        return 10_000;
    }
    let diff = aggregate.max(reference) - aggregate.min(reference);
    ((diff as u128 * 10_000) / (reference as u128)) as u64
}

fn canonical_source_cardinality(sources: &[Value]) -> u32 {
    let mut unique = HashSet::new();
    for source in sources {
        let Some(source_id) = source.get("source_id").and_then(Value::as_str) else {
            return sources.len() as u32;
        };
        let canonical = source_id.trim().to_ascii_lowercase();
        if canonical.is_empty() {
            continue;
        }
        unique.insert(canonical);
    }
    unique.len() as u32
}

pub(crate) fn oracle_validate_snapshot_response(
    snapshot_path: &Path,
    policy_path: &Path,
    now_ts_ms: u64,
) -> Result<OracleValidateSnapshotResponse, String> {
    let snapshot_text = fs::read_to_string(snapshot_path).map_err(|e| e.to_string())?;
    let policy_text = fs::read_to_string(policy_path).map_err(|e| e.to_string())?;

    let snapshot_val: SnapshotFile =
        serde_json::from_str(&snapshot_text).map_err(|e| e.to_string())?;
    let policy_val: PolicyFile = serde_json::from_str(&policy_text).map_err(|e| e.to_string())?;
    validate_policy_file(&policy_val)?;

    let source_count = snapshot_val.sources.len() as u32;
    let cardinality = canonical_source_cardinality(&snapshot_val.sources);
    let snapshot_feed_id = validate_canonical_feed_id(&snapshot_val.feed_id)?;
    let policy_feed_id = validate_canonical_feed_id(&policy_val.feed_id)?;

    if snapshot_feed_id != policy_feed_id {
        return Err(format!(
            "feed id mismatch: snapshot={}, policy={}",
            snapshot_feed_id, policy_feed_id
        ));
    }

    if source_count == 0 {
        return Err("snapshot has no sources".to_string());
    }

    let mut outcome = "accepted";
    let mut stale_reject_total = 0;
    let mut quorum_reject_total = 0;
    let mut drift_reject_total = 0;
    let mut accepted_total = 0;
    let mut error = None;

    let future = snapshot_val.observed_at_ms > now_ts_ms;
    let stale = now_ts_ms.saturating_sub(snapshot_val.observed_at_ms) > policy_val.max_staleness_ms;
    let quorum = cardinality < policy_val.min_source_count as u32;
    let rate = snapshot_val.sample_count as u64 > policy_val.max_update_rate_per_window;
    let drift = compute_deviation_bps(snapshot_val.aggregate_price, snapshot_val.reference_price)
        >= policy_val.max_deviation_bps;

    if future {
        outcome = "stale";
        stale_reject_total = 1;
        error = Some(format!(
            "snapshot future: observed_at_ms={} now_ts_ms={}",
            snapshot_val.observed_at_ms, now_ts_ms
        ));
    } else if stale {
        outcome = "stale";
        stale_reject_total = 1;
        error = Some(format!(
            "snapshot stale: observed_at_ms={} max_staleness_ms={}",
            snapshot_val.observed_at_ms, policy_val.max_staleness_ms
        ));
    } else if quorum {
        outcome = "quorum";
        quorum_reject_total = 1;
        error = Some("quorum reject".to_string());
    } else if rate {
        error = Some("rate".to_string());
    } else if drift {
        outcome = "drift";
        drift_reject_total = 1;
        error = Some("deviation exceeded".to_string());
    } else {
        accepted_total = 1;
    }

    let ok = error.is_none();

    Ok(OracleValidateSnapshotResponse {
        ok,
        now_ts_ms,
        observation: OracleValidationObservation {
            outcome: outcome.to_string(),
            feed_id: snapshot_feed_id,
            stale_reject_total,
            quorum_reject_total,
            drift_reject_total,
            accepted_total,
        },
        metrics: OracleValidationMetrics {
            oracle_stale_reject_total: stale_reject_total,
            oracle_quorum_reject_total: quorum_reject_total,
            oracle_drift_reject_total: drift_reject_total,
            oracle_source_cardinality: cardinality,
            accepted_total,
            sample_count: snapshot_val.sample_count,
        },
        error,
    })
}

fn base_prometheus_text() -> String {
    "trnm_rpc_service_up{service=\"trnm-rpc\"} 1\ntrnm_rpc_service_info{service=\"trnm-rpc\",version=\"1\"} 1\n".to_string()
}

fn metrics_from_target(target: &str) -> String {
    let req = parse_oracle_validate_snapshot_target(target).ok();
    let mut text = base_prometheus_text();
    let Some(req) = req else {
        return text;
    };

    let report = oracle_validate_snapshot_response(
        Path::new(&req.snapshot),
        Path::new(&req.policy),
        req.now_ts_ms.unwrap_or(0),
    );
    let Ok(report) = report else {
        return text;
    };

    let outcome = report.observation.outcome.as_str();
    let out_count = if report.ok { 1 } else { 0 };
    text.push_str(&format!(
        "oracle_validation_ok{{feed_id=\"{}\",outcome=\"{}\"}} {}\n",
        report.observation.feed_id, outcome, out_count
    ));
    text.push_str(&format!(
        "accepted_total{{feed_id=\"{}\",outcome=\"{}\"}} {}\n",
        report.observation.feed_id, outcome, report.metrics.accepted_total
    ));
    text.push_str(&format!(
        "oracle_source_cardinality{{feed_id=\"{}\",outcome=\"{}\"}} {}\n",
        report.observation.feed_id, outcome, report.metrics.oracle_source_cardinality
    ));
    text.push_str(&format!(
        "oracle_sample_count{{feed_id=\"{}\",outcome=\"{}\"}} {}\n",
        report.observation.feed_id, outcome, report.metrics.sample_count
    ));
    text
}

fn json_response<T: Serialize>(value: &T) -> String {
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\n\r\n{}",
        serde_json::to_string(value).expect("serialize response")
    )
}

fn error_response(message: &str) -> String {
    let body = json!({"code":"INVALID_REQUEST","message":message});
    format!(
        "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json; charset=utf-8\r\n\r\n{}",
        serde_json::to_string(&body).expect("serialize response")
    )
}

pub(crate) fn http_service_response_for_target(target: Option<&str>) -> String {
    let target = target.unwrap_or("/metrics");
    if matches_exact_target_path(target, "/oracle/validate_snapshot") {
        let req = parse_oracle_validate_snapshot_target(target);
        match req {
            Ok(request) => {
                let report = oracle_validate_snapshot_response(
                    Path::new(&request.snapshot),
                    Path::new(&request.policy),
                    request.now_ts_ms.unwrap_or(0),
                );
                match report {
                    Ok(resp) => json_response(&resp),
                    Err(err) => error_response(&err),
                }
            }
            Err(err) => error_response(&err),
        }
    } else if matches_exact_target_path(target, "/oracle/metrics")
        || matches_exact_target_path(target, "/metrics")
    {
        if !target.contains('?') {
            return format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4; charset=utf-8\r\n\r\n{}",
                base_prometheus_text()
            );
        }

        match parse_oracle_validate_snapshot_target(target) {
            Ok(_) => format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4; charset=utf-8\r\n\r\n{}",
                metrics_from_target(target)
            ),
            Err(err) => error_response(&err),
        }
    } else {
        "HTTP/1.1 404 Not Found\r\n\r\n".to_string()
    }
}

#[cfg(test)]
#[path = "../tests_rpc_oracle_snapshot_validation.rs"]
mod tests_rpc_oracle_snapshot_validation;

#[cfg(test)]
#[path = "../tests_rpc_oracle_snapshot_parse.rs"]
mod tests_rpc_oracle_snapshot_parse;

#[cfg(test)]
#[path = "../tests_rpc_oracle_snapshot_http.rs"]
mod tests_rpc_oracle_snapshot_http;
