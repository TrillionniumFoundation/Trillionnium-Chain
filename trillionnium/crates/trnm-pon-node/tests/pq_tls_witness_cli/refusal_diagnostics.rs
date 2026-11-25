//! Fixed-field projection of the already bounded child stderr prefix.
use serde_json::{json, Value};

const PREFIX: &str = "TRNM_PQ_TLS_CONNECTION_REFUSAL ";
const KINDS: &[&str] = &[
    "ProtocolInvalid",
    "Capacity",
    "Cancelled",
    "StaleContext",
    "IdentityConflict",
    "PolicyRefusal",
    "LocalStructure",
    "DependencyUnavailable",
    "Transport",
    "Serialization",
    "RemoteRefusal",
    "Unclassified",
];
const CODES: &[&str] = &[
    "PQ_NETWORK_DEADLINE",
    "PQ_NETWORK_EXPIRED",
    "PQ_NETWORK_REVOKED",
    "PQ_WITNESS_DEADLINE",
    "PQ_WITNESS_EOF",
    "PQ_WITNESS_UNAVAILABLE",
    "PQ_WITNESS_BUSY",
    "PQ_WITNESS_COMMIT_UNCERTAIN",
    "PQ_WITNESS_ROLLBACK",
    "PQ_WITNESS_LOCAL_ROOT",
    "PQ_TLS_CIPHERTEXT_LIMIT",
];

fn known(value: &Value, field: &str, labels: &'static [&'static str]) -> Option<&'static str> {
    let observed = value.get(field)?.as_str()?;
    labels.iter().copied().find(|label| *label == observed)
}

fn record(line: &str) -> Option<Value> {
    let body = line.strip_prefix(PREFIX)?;
    if body.len() > 768 {
        return None;
    }
    let value: Value = serde_json::from_str(body).ok()?;
    if value.get("schema")?.as_str()? != "pq-tls-connection-refusal-v1" {
        return None;
    }
    let stage = known(
        &value,
        "stage",
        &[
            "peer_address",
            "ingress_admission",
            "tls_handshake",
            "request_read",
            "request_dispatch",
            "response_write",
        ],
    )?;
    Some(json!({
        "schema": "pq-tls-connection-refusal-v1",
        "stage": stage,
        "elapsed_us": value.get("elapsed_us")?.as_u64()?,
        "stage_elapsed_us": value.get("stage_elapsed_us")?.as_u64()?,
        "deadline_elapsed": value.get("deadline_elapsed")?.as_bool()?,
        "error_kind": known(&value, "error_kind", KINDS),
        "error_code": known(&value, "error_code", CODES),
        "bio_error_kind": known(&value, "bio_error_kind", KINDS),
        "bio_error_code": known(&value, "bio_error_code", CODES),
        "ingress_charge_calls": value.get("ingress_charge_calls")?.as_u64()?,
        "ingress_charge_us": value.get("ingress_charge_us")?.as_u64()?,
    }))
}

pub(super) fn records(prefix: &[u8]) -> Vec<Value> {
    // Retain the original harness's 4 KiB byte cap. Arbitrary child text and
    // unknown JSON fields/labels never enter the failure report.
    let text = String::from_utf8_lossy(&prefix[..prefix.len().min(4096)]);
    text.lines().filter_map(record).take(16).collect()
}

const WITNESS_PREFIX: &str = "TRNM_PQ_WITNESS_PHASE ";
const WITNESS_PHASES: &[&str] = &[
    "challenge",
    "sign_self_verify",
    "wire_exchange",
    "reply_context",
    "reply_verify",
    "final_check",
    "storage_entry",
    "request_verify",
    "request_context",
    "read_state",
    "cas_prepare",
    "commit",
    "storage_final",
    "reply_sign_self_verify",
    "wire_read",
    "wire_write",
    "service_handle",
];
const WITNESS_CODES: &[&str] = &[
    "PQ_WITNESS_DEADLINE",
    "PQ_WITNESS_EOF",
    "PQ_WITNESS_UNAVAILABLE",
    "PQ_WITNESS_BUSY",
    "PQ_WITNESS_COMMIT_UNCERTAIN",
    "PQ_WITNESS_ROLLBACK",
    "PQ_WITNESS_STORAGE_IDENTITY",
    "PQ_WITNESS_SCHEMA",
    "PQ_WITNESS_STATE",
    "PQ_WITNESS_STATE_WIDTH",
    "other",
];
fn optional_integer(value: &Value) -> Option<Value> {
    if value.is_null() {
        Some(Value::Null)
    } else {
        value.as_u64().map(Value::from)
    }
}
fn optional_known(value: &Value, field: &str, labels: &'static [&'static str]) -> Option<Value> {
    if value.get(field)?.is_null() {
        Some(Value::Null)
    } else {
        known(value, field, labels).map(Value::from)
    }
}
fn witness_record(line: &str) -> Option<Value> {
    let body = line.strip_prefix(WITNESS_PREFIX)?;
    if body.len() > 2048 {
        return None;
    }
    let value: Value = serde_json::from_str(body).ok()?;
    if value.get("schema")?.as_str()? != "trnm-pq-witness-phase-v1"
        || value.get("phase_cost_columns")? != &json!(["phase", "calls", "wall_us", "cpu_ns"])
    {
        return None;
    }
    let kind = known(
        &value,
        "kind",
        &[
            "client_current",
            "client_cas",
            "service_current",
            "service_cas",
            "service_connection",
        ],
    )?;
    let ok = value.get("ok")?.as_bool()?;
    let expired = value.get("deadline_elapsed")?.as_bool()?;
    if ok && !expired {
        return None;
    }
    let raw_phases = value.get("phases")?.as_array()?;
    if raw_phases.len() > WITNESS_PHASES.len() {
        return None;
    }
    let mut phases = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for raw in raw_phases {
        let fields = raw.as_array()?;
        if fields.len() != 4 {
            return None;
        }
        let phase = fields[0].as_str()?;
        if !WITNESS_PHASES.contains(&phase) || !seen.insert(phase) {
            return None;
        }
        let calls = fields[1].as_u64()?;
        if !(1..=u64::from(u16::MAX)).contains(&calls) {
            return None;
        }
        phases.push(json!([
            phase,
            calls,
            fields[2].as_u64()?,
            optional_integer(&fields[3])?
        ]));
    }
    Some(json!({
        "schema":"trnm-pq-witness-phase-v1", "kind":kind, "ok":ok,
        "error_code":optional_known(&value, "error_code", WITNESS_CODES)?,
        "deadline_elapsed":expired, "elapsed_us":value.get("elapsed_us")?.as_u64()?,
        "cpu_ns":optional_integer(value.get("cpu_ns")?)?,
        "last_phase":optional_known(&value, "last_phase", WITNESS_PHASES)?,
        "phase_cost_columns":["phase", "calls", "wall_us", "cpu_ns"], "phases":phases,
    }))
}
pub(super) fn witness_records(prefix: &[u8]) -> Vec<Value> {
    // Keep the original 4 KiB stderr retention; never reread or widen it.
    // Even complete JSON is uncommitted if the single write lost its final LF.
    String::from_utf8_lossy(&prefix[..prefix.len().min(4096)])
        .split_inclusive('\n')
        .filter_map(|line| line.strip_suffix('\n').and_then(witness_record))
        .take(16)
        .collect()
}
