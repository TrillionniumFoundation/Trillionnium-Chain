use super::*;

#[test]
fn query_account_state_ok() {
    let address = format!("trnm1{}", "1".repeat(40));
    let mut accounts = BTreeMap::new();
    accounts.insert(
        address.clone(),
        AccountState {
            address: address.clone(),
            balance: 42,
            nonce: 7,
        },
    );

    let got = query_account_state(&accounts, &address).unwrap();
    assert_eq!(got.balance, 42);
    assert_eq!(got.nonce, 7);
}

#[test]
fn query_account_state_address_not_found() {
    let accounts = BTreeMap::new();
    let addr = &format!("trnm1{}", "2".repeat(40));
    let err = query_account_state(&accounts, addr).unwrap_err();
    assert_eq!(err.code(), "ACCOUNT_NOT_FOUND");
}

#[test]
fn query_account_state_invalid_input() {
    let accounts = BTreeMap::new();
    let err = query_account_state(&accounts, "not-an-address").unwrap_err();
    assert_eq!(err.code(), "INVALID_ADDRESS");
}

#[test]
fn query_account_state_rejects_non_hex_suffix() {
    let accounts = BTreeMap::new();
    let bad = format!("trnm1{}", "z".repeat(40));
    let err = query_account_state(&accounts, &bad).unwrap_err();
    assert_eq!(err.code(), "INVALID_ADDRESS");
}

#[test]
fn query_account_state_rejects_uppercase_hex_suffix() {
    let accounts = BTreeMap::new();
    let bad = format!("trnm1{}", "A".repeat(40));
    let err = query_account_state(&accounts, &bad).unwrap_err();
    assert_eq!(err.code(), "INVALID_ADDRESS");
}

#[test]
fn query_account_state_accepts_whitespace_drift() {
    let address = format!("trnm1{}", "1".repeat(40));
    let mut accounts = BTreeMap::new();
    accounts.insert(
        address.clone(),
        AccountState {
            address: address.clone(),
            balance: 42,
            nonce: 7,
        },
    );

    let got = query_account_state(&accounts, &format!("  {}\n", address)).unwrap();
    assert_eq!(got.address, address);
    assert_eq!(got.balance, 42);
    assert_eq!(got.nonce, 7);
}

#[test]
fn query_account_state_rejects_wrong_suffix_length() {
    let accounts = BTreeMap::new();

    let short = format!("trnm1{}", "1".repeat(39));
    assert_eq!(
        query_account_state(&accounts, &short).unwrap_err().code(),
        "INVALID_ADDRESS"
    );

    let long = format!("trnm1{}", "1".repeat(41));
    assert_eq!(
        query_account_state(&accounts, &long).unwrap_err().code(),
        "INVALID_ADDRESS"
    );
}

#[test]
fn account_state_rejects_unknown_fields() {
    let err = serde_json::from_value::<AccountState>(json!({
        "address": format!("trnm1{}", "1".repeat(40)),
        "balance": 42,
        "nonce": 7,
        "unexpected": "schema-drift"
    }))
    .unwrap_err();
    assert!(err.to_string().contains("unexpected"));
}

#[test]
fn account_balance_query_response_rejects_unknown_fields() {
    let err = serde_json::from_value::<AccountBalanceQueryResponse>(json!({
        "address": format!("trnm1{}", "1".repeat(40)),
        "balance": 42,
        "version": 3,
        "unexpected": "schema-drift"
    }))
    .unwrap_err();
    assert!(err.to_string().contains("unexpected"));
}

#[test]
fn account_nonce_query_response_rejects_unknown_fields() {
    let err = serde_json::from_value::<AccountNonceQueryResponse>(json!({
        "address": format!("trnm1{}", "1".repeat(40)),
        "nonce": 7,
        "version": 3,
        "unexpected": "schema-drift"
    }))
    .unwrap_err();
    assert!(err.to_string().contains("unexpected"));
}

#[test]
fn faucet_request_response_rejects_unknown_fields() {
    let err = serde_json::from_value::<FaucetRequestResponse>(json!({
        "ok": true,
        "code": "OK",
        "message": "granted",
        "address": format!("trnm1{}", "1".repeat(40)),
        "requested_amount": 10,
        "granted_amount": 10,
        "balance": 20,
        "nonce": 1,
        "window_seconds": 60,
        "next_allowed_unix_ms": 1700000000123u128,
        "version": 3,
        "unexpected": "schema-drift"
    }))
    .unwrap_err();
    assert!(err.to_string().contains("unexpected"));
}

#[test]
fn rpc_error_response_rejects_unknown_fields() {
    let err = serde_json::from_value::<RpcErrorResponse>(json!({
        "code": "INVALID_ADDRESS",
        "message": "invalid address format",
        "extra": true
    }))
    .unwrap_err();
    assert!(err.to_string().contains("extra"));
}
