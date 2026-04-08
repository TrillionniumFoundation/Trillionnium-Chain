use super::*;

#[test]
fn wait_for_tx_timeout() {
    let result = wait_for_tx(
        "0xaaa",
        Duration::from_millis(1),
        Duration::from_millis(1),
        |_| {
            Ok(TxQueryResponse {
                tx_hash: "0xaaa".to_string(),
                status: "pending".to_string(),
                error: None,
            })
        },
    );
    assert!(result.is_err());
}

#[test]
fn wait_for_tx_success() {
    let result = wait_for_tx(
        "0xbbb",
        Duration::from_millis(10),
        Duration::from_millis(1),
        |_| {
            Ok(TxQueryResponse {
                tx_hash: "0xbbb".to_string(),
                status: "committed".to_string(),
                error: None,
            })
        },
    )
    .unwrap();
    assert_eq!(result.status, "committed");
}

#[test]
fn wait_for_tx_rejects_bare_hex_without_0x_prefix() {
    let result = wait_for_tx(
        "bbbccc",
        Duration::from_millis(10),
        Duration::from_millis(1),
        |_| unreachable!("query_fn should not run for invalid tx hash input"),
    );
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("expected 0x-prefixed hex tx hash"),
        "unexpected: {err}"
    );
}

#[test]
fn wait_for_tx_rejects_mismatched_tx_hash_from_query() {
    let result = wait_for_tx(
        "0xbbbccc",
        Duration::from_millis(10),
        Duration::from_millis(1),
        |_| {
            Ok(TxQueryResponse {
                tx_hash: "0xdeadbeef".to_string(),
                status: "pending".to_string(),
                error: None,
            })
        },
    );
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("tx wait response hash mismatch"),
        "unexpected: {err}"
    );
}

#[test]
fn wait_for_tx_rejects_invalid_tx_hash_from_query() {
    let result = wait_for_tx(
        "0xbbbccc",
        Duration::from_millis(10),
        Duration::from_millis(1),
        |_| {
            Ok(TxQueryResponse {
                tx_hash: "not-a-hash".to_string(),
                status: "pending".to_string(),
                error: None,
            })
        },
    );
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("tx wait response hash invalid"),
        "unexpected: {err}"
    );
}

#[test]
fn wait_for_tx_rejects_missing_tx_hash_from_query() {
    let result = wait_for_tx(
        "0xbbbccc",
        Duration::from_millis(10),
        Duration::from_millis(1),
        |_| {
            Ok(TxQueryResponse {
                tx_hash: String::new(),
                status: "committed".to_string(),
                error: None,
            })
        },
    );
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("tx wait response missing tx_hash"),
        "unexpected: {err}"
    );
}

#[test]
fn wait_for_tx_accepts_normalized_success_alias_as_terminal() {
    let result = wait_for_tx(
        "0xbbbccc",
        Duration::from_millis(10),
        Duration::from_millis(1),
        |_| {
            Ok(TxQueryResponse {
                tx_hash: "0xbbbccc".to_string(),
                status: "confirmed".to_string(),
                error: None,
            })
        },
    )
    .unwrap();
    assert_eq!(result.status, "confirmed");
}

#[test]
fn wait_for_tx_accepts_normalized_failure_alias_as_terminal() {
    let result = wait_for_tx(
        "0xbbbccc",
        Duration::from_millis(10),
        Duration::from_millis(1),
        |_| {
            Ok(TxQueryResponse {
                tx_hash: "0xbbbccc".to_string(),
                status: "timed_out".to_string(),
                error: Some("signer did not submit before deadline".to_string()),
            })
        },
    )
    .unwrap();
    assert_eq!(result.status, "timed_out");
}
