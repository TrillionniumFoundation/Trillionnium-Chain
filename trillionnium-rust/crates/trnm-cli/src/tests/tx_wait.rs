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
