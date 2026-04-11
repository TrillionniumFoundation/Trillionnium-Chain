use super::super::*;

#[test]
fn tx_query_parse_json_and_kv() {
    let json = "{\"tx_hash\":\"0xabc\",\"status\":\"committed\",\"error\":null}";
    let parsed = parse_tx_query_response(json, "0xabc").unwrap();
    assert_eq!(parsed.status, "committed");
    assert_eq!(parsed.error, None);

    let kv = "tx_hash=0xdef\nstatus=fail\nerror=insufficient balance\n";
    let parsed_kv = parse_tx_query_response(kv, "0xdef").unwrap();
    assert_eq!(parsed_kv.status, "fail");
    assert_eq!(parsed_kv.error.as_deref(), Some("insufficient balance"));
}

#[test]
fn tx_query_parse_json_nested_result_payload() {
    let json = "{\"result\":{\"tx_hash\":\"0xabc\",\"status\":\"success\",\"error\":null}}";
    let parsed = parse_tx_query_response(json, "0xfallback").unwrap();
    assert_eq!(parsed.tx_hash, "0xabc");
    assert_eq!(parsed.status, "committed");
    assert_eq!(parsed.error, None);
}

#[test]
fn tx_query_parse_json_nested_top_level_data_payload() {
    let json = "{\"data\":{\"tx_hash\":\"0xabc\",\"status\":\"success\",\"error\":null}}";
    let parsed = parse_tx_query_response(json, "0xfallback").unwrap();
    assert_eq!(parsed.tx_hash, "0xabc");
    assert_eq!(parsed.status, "committed");
    assert_eq!(parsed.error, None);
}

#[test]
fn tx_query_parse_json_accepts_camel_transaction_and_hyphenated_hash_keys() {
    let camel = "{\"result\":{\"txHash\":\"0xabc\",\"status\":\"success\"}}";
    let parsed_camel = parse_tx_query_response(camel, "0xfallback").unwrap();
    assert_eq!(parsed_camel.tx_hash, "0xabc");
    assert_eq!(parsed_camel.status, "committed");

    let transaction = "{\"transactionHash\":\"0xdef\",\"status\":\"committed\"}";
    let parsed_transaction = parse_tx_query_response(transaction, "0xfallback").unwrap();
    assert_eq!(parsed_transaction.tx_hash, "0xdef");
    assert_eq!(parsed_transaction.status, "committed");

    let hyphenated = "{\"result\":{\"tx-hash\":\"0xfeed01\",\"status\":\"success\"}}";
    let parsed_hyphenated = parse_tx_query_response(hyphenated, "0xfallback").unwrap();
    assert_eq!(parsed_hyphenated.tx_hash, "0xfeed01");
    assert_eq!(parsed_hyphenated.status, "committed");

    let transaction_hyphenated =
        "{\"transaction-hash\":\"0xfeed02\",\"status\":\"committed\"}";
    let parsed_transaction_hyphenated =
        parse_tx_query_response(transaction_hyphenated, "0xfallback").unwrap();
    assert_eq!(parsed_transaction_hyphenated.tx_hash, "0xfeed02");
    assert_eq!(parsed_transaction_hyphenated.status, "committed");
}

#[test]
fn tx_query_parse_json_accepts_case_and_separator_insensitive_keys() {
    let json = "{\"RESULT\":{\"TX_HASH\":\"0xABCD\",\"TX-STATUS\":\"SUCCESS\",\"RAW-LOG\":\"NULL\"}}";
    let parsed = parse_tx_query_response(json, "0xfallback").unwrap();
    assert_eq!(parsed.tx_hash, "0xabcd");
    assert_eq!(parsed.status, "committed");
    assert_eq!(parsed.error, None);
}

#[test]
fn tx_query_parse_json_treats_nullish_error_variants_as_empty() {
    let json = "{\"tx_hash\":\"0x777\",\"status\":\"committed\",\"error\":\"NULL,\"}";
    let parsed = parse_tx_query_response(json, "0xfallback").unwrap();
    assert_eq!(parsed.tx_hash, "0x777");
    assert_eq!(parsed.status, "committed");
    assert_eq!(parsed.error, None);
}

#[test]
fn tx_query_parse_json_preserves_non_string_error_payloads() {
    let json_numeric = "{\"tx_hash\":\"0x777\",\"status\":\"fail\",\"error\":404}";
    let parsed_numeric = parse_tx_query_response(json_numeric, "0xfallback").unwrap();
    assert_eq!(parsed_numeric.error.as_deref(), Some("404"));

    let json_obj = "{\"tx_hash\":\"0x777\",\"status\":\"fail\",\"error\":{\"code\":\"E_NONCE\"}}";
    let parsed_obj = parse_tx_query_response(json_obj, "0xfallback").unwrap();
    assert_eq!(parsed_obj.error.as_deref(), Some("{\"code\":\"E_NONCE\"}"));
}

#[test]
fn tx_query_parse_json_infers_status_from_hyphenated_code_aliases() {
    let root = "{\"tx_hash\":\"0x701\",\"tx-code\":0}";
    let parsed_root = parse_tx_query_response(root, "0xfallback").unwrap();
    assert_eq!(parsed_root.tx_hash, "0x701");
    assert_eq!(parsed_root.status, "committed");

    let nested = "{\"result\":{\"tx_hash\":\"0x702\",\"deliver-tx\":{\"code\":\"12\"}}}";
    let parsed_nested = parse_tx_query_response(nested, "0xfallback").unwrap();
    assert_eq!(parsed_nested.tx_hash, "0x702");
    assert_eq!(parsed_nested.status, "fail");

    let check = "{\"result\":{\"tx_hash\":\"0x703\",\"check-tx-code\":0}}";
    let parsed_check = parse_tx_query_response(check, "0xfallback").unwrap();
    assert_eq!(parsed_check.tx_hash, "0x703");
    assert_eq!(parsed_check.status, "committed");
}

#[test]
fn tx_query_parse_rejects_invalid_tx_hash_if_field_is_present() {
    let bad_json = "{\"tx_hash\":\"not-a-hash\",\"status\":\"committed\"}";
    let err_json = parse_tx_query_response(bad_json, "0xabc").unwrap_err();
    assert!(
        err_json
            .to_string()
            .contains("invalid tx_hash field in tx query response"),
        "unexpected: {err_json}"
    );

    let null_json = "{\"tx_hash\":null,\"status\":\"committed\"}";
    let err_null_json = parse_tx_query_response(null_json, "0xabc").unwrap_err();
    assert!(
        err_null_json
            .to_string()
            .contains("invalid tx_hash field in tx query response"),
        "unexpected: {err_null_json}"
    );

    let numeric_json = "{\"tx_hash\":12345,\"status\":\"committed\"}";
    let err_numeric_json = parse_tx_query_response(numeric_json, "0xabc").unwrap_err();
    assert!(
        err_numeric_json
            .to_string()
            .contains("invalid tx_hash field in tx query response"),
        "unexpected: {err_numeric_json}"
    );

    let bad_kv = "tx_hash=not-a-hash\nstatus=committed\n";
    let err_kv = parse_tx_query_response(bad_kv, "0xabc").unwrap_err();
    assert!(
        err_kv
            .to_string()
            .contains("invalid tx_hash field in tx query response"),
        "unexpected: {err_kv}"
    );
}
