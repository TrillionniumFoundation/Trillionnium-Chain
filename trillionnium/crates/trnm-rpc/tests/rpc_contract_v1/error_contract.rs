use super::*;

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
