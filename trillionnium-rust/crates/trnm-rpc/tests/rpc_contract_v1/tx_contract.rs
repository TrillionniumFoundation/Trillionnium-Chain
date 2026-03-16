use super::*;

#[test]
fn contract_sendtx_shape_stable() {
    let v = serde_json::to_value(SendTxResponse {
        tx_hash: "0xabc".into(),
        status: TxStatus::Pending,
    })
    .unwrap();
    assert_eq!(v, json!({"tx_hash":"0xabc","status":"pending"}));
}

#[test]
fn contract_gettx_shape_stable() {
    let v = serde_json::to_value(GetTxResponse {
        tx_hash: "0xabc".into(),
        status: TxStatus::Committed,
        error: None,
    })
    .unwrap();
    assert_eq!(
        v,
        json!({"tx_hash":"0xabc","status":"committed","error":null})
    );
}
