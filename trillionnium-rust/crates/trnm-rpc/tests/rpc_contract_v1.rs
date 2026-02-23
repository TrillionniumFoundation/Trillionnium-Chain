use serde_json::json;
use trnm_rpc::{
    AccountBalanceQueryResponse, AccountNonceQueryResponse, GetTxResponse, RpcErrorResponse,
    SendTxResponse, TxStatus,
};

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
    assert_eq!(v, json!({"tx_hash":"0xabc","status":"committed","error":null}));
}

#[test]
fn contract_error_codes_stable() {
    let invalid = RpcErrorResponse {
        code: "INVALID_ADDRESS",
        message: "bad".into(),
    };
    let not_found = RpcErrorResponse {
        code: "ACCOUNT_NOT_FOUND",
        message: "nf".into(),
    };
    let tx_nf = RpcErrorResponse {
        code: "TX_NOT_FOUND",
        message: "tx".into(),
    };

    assert_eq!(invalid.code, "INVALID_ADDRESS");
    assert_eq!(not_found.code, "ACCOUNT_NOT_FOUND");
    assert_eq!(tx_nf.code, "TX_NOT_FOUND");
}
