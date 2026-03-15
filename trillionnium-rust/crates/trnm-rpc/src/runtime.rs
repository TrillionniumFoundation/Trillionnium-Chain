use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

pub(crate) fn now_ms() -> u128 {
    if let Ok(v) = std::env::var("TRNM_RPC_NOW_MS") {
        if let Ok(parsed) = v.parse::<u128>() {
            return parsed;
        }
    }
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

pub(crate) fn make_request_id(
    channel: &str,
    user_id: &str,
    session_id: &str,
    idempotency_key: &str,
    ts: u128,
) -> String {
    let mut h = Sha256::new();
    h.update(channel.as_bytes());
    h.update(b"|");
    h.update(user_id.as_bytes());
    h.update(b"|");
    h.update(session_id.as_bytes());
    h.update(b"|");
    h.update(idempotency_key.as_bytes());
    h.update(b"|");
    h.update(ts.to_string().as_bytes());
    let digest = hex::encode(h.finalize());
    format!("req_{}", &digest[..16])
}
