use super::*;

#[test]
fn contract_balance_shape_stable() {
    let v = serde_json::to_value(AccountBalanceQueryResponse {
        address: "trnm1abc".into(),
        balance: 1,
        version: 1,
    })
    .unwrap();
    assert_eq!(v, json!({"address":"trnm1abc","balance":1,"version":1}));
}

#[test]
fn contract_nonce_shape_stable() {
    let v = serde_json::to_value(AccountNonceQueryResponse {
        address: "trnm1abc".into(),
        nonce: 7,
        version: 1,
    })
    .unwrap();
    assert_eq!(v, json!({"address":"trnm1abc","nonce":7,"version":1}));
}

#[test]
fn contract_account_read_responses_reject_unknown_fields() {
    let balance_err = serde_json::from_value::<AccountBalanceQueryResponse>(json!({
        "address": "trnm1abc",
        "balance": 1,
        "version": 1,
        "extra": true
    }))
    .expect_err("balance response should fail closed on unknown fields");
    let balance_msg = balance_err.to_string();
    assert!(balance_msg.contains("unknown field") || balance_msg.contains("unexpected"));

    let nonce_err = serde_json::from_value::<AccountNonceQueryResponse>(json!({
        "address": "trnm1abc",
        "nonce": 7,
        "version": 1,
        "extra": true
    }))
    .expect_err("nonce response should fail closed on unknown fields");
    let nonce_msg = nonce_err.to_string();
    assert!(nonce_msg.contains("unknown field") || nonce_msg.contains("unexpected"));
}
