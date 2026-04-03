use super::*;
use anyhow::anyhow;

pub(crate) fn default_tx_state_file() -> PathBuf {
    if let Ok(path) = std::env::var("TRNM_RPC_TX_FILE") {
        return PathBuf::from(path);
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .map(|p| p.join("run/rpc/txs.json"))
        .unwrap_or_else(|| PathBuf::from("run/rpc/txs.json"))
}

fn normalize_json_status(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::String(s) => super::parse::normalize_tx_status(s),
        serde_json::Value::Number(n) => n
            .as_i64()
            .map(|code| if code == 0 { "committed" } else { "fail" }.to_string()),
        serde_json::Value::Bool(b) => Some(if *b { "committed" } else { "fail" }.to_string()),
        _ => None,
    }
}

pub(crate) fn query_local_tx_status(tx_hash: &str) -> Option<String> {
    let requested = super::parse::normalize_tx_hash(tx_hash).unwrap_or_else(|| tx_hash.to_string());
    let path = default_tx_state_file();
    let raw = fs::read_to_string(path).ok()?;
    let v: serde_json::Value = serde_json::from_str(&raw).ok()?;
    let rec = v.get(&requested).or_else(|| {
        v.as_object()?.iter().find_map(|(key, value)| {
            (super::parse::normalize_tx_hash(key).as_deref() == Some(requested.as_str()))
                .then_some(value)
        })
    })?;
    [
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
    ]
    .into_iter()
    .find_map(|key| rec.get(key).and_then(normalize_json_status))
}

pub(crate) fn persist_local_pending_tx(tx_hash: &str) -> Result<()> {
    let normalized = super::parse::normalize_tx_hash(tx_hash)
        .ok_or_else(|| anyhow!("invalid tx hash for local pending state (expected hex-like tx hash)"))?;
    if !normalized.starts_with("0x") {
        return Err(anyhow!(
            "invalid tx hash for local pending state (expected 0x-prefixed hex tx hash)"
        ));
    }

    let path = default_tx_state_file();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let mut root: serde_json::Map<String, serde_json::Value> =
        if let Ok(raw) = fs::read_to_string(&path) {
            serde_json::from_str(&raw).unwrap_or_default()
        } else {
            serde_json::Map::new()
        };

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);

    root.insert(
        normalized.clone(),
        serde_json::json!({
            "tx_hash": normalized,
            "tx": {
                "from": "trnm1pendingplaceholderfrom",
                "to": "trnm1pendingplaceholderto",
                "amount": 0,
                "fee": 0,
                "nonce": 0,
                "signature": "pending"
            },
            "status": "pending",
            "error": null,
            "submitted_at_unix_ms": now_ms,
            "updated_at_unix_ms": now_ms
        }),
    );

    fs::write(path, serde_json::to_string_pretty(&root)?)?;
    Ok(())
}
