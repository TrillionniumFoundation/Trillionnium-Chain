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
