use super::*;
#[test]
fn parse_tx_hash_accepts_space_separated_receipt_keys_with_tab_delimiter_padding() {
    let shell = parse_tx_hash("TX HASH\t=\t0xDEADBEEF")
        .expect("space-separated receipt hash with tab delimiter padding should parse");
    assert_eq!(shell, "deadbeef");
}

#[test]
fn parse_tx_hash_strips_bom_and_zero_width_fillers_around_receipt_value() {
    let json = parse_tx_hash("receipt={\"tx_hash\":\"\u{feff}\u{200b}0xDEADBEEF\u{2060}\"}")
        .expect("json receipt hash with bom and zero-width fillers should parse");
    assert_eq!(json, "deadbeef");
}

#[test]
fn parse_tx_hash_accepts_hyphenated_json_receipt_keys() {
    let json = parse_tx_hash("{\"tx-hash\": \"0xDEADBEEF\", \"status\": \"accepted\"}")
        .expect("hyphenated json receipt hash should parse");
    assert_eq!(json, "deadbeef");

    let uppercase = parse_tx_hash("{\"TX-HASH\" : \"ABCD1234\", \"status\": \"accepted\"}")
        .expect("uppercase hyphenated json receipt hash should parse");
    assert_eq!(uppercase, "abcd1234");
}

#[test]
fn parse_tx_hash_accepts_mixed_case_json_alias_receipts() {
    let json = parse_tx_hash("adapter stdout: {\"txHash\": \"ABCD1234\"}")
        .expect("camelCase json receipt hash should parse");
    assert_eq!(json, "abcd1234");
}

#[test]
fn parse_tx_hash_accepts_transaction_hash_alias_receipts() {
    let shell = parse_tx_hash("[adapter] commit accepted transaction_hash=0xDEADBEEF")
        .expect("transaction_hash shell receipt hash should parse");
    assert_eq!(shell, "deadbeef");

    let hyphenated = parse_tx_hash("[adapter] commit accepted transaction-hash : 0xC0FFEE12")
        .expect("transaction-hash shell receipt hash with spaced delimiter should parse");
    assert_eq!(hyphenated, "c0ffee12");

    let spaced = parse_tx_hash("adapter stdout: {'TRANSACTION HASH' : 'ABCD1234'}")
        .expect("space-separated single-quoted transaction hash receipt should parse");
    assert_eq!(spaced, "abcd1234");

    let camel = parse_tx_hash("adapter stdout: {\"transactionHash\": \"0xBADDCAFE\"}")
        .expect("camelCase transaction hash json receipt should parse");
    assert_eq!(camel, "baddcafe");
}

#[test]
fn parse_tx_hash_accepts_smart_quoted_transaction_hash_alias_with_fullwidth_colon() {
    let smart_quoted = parse_tx_hash("receipt={“transaction hash”： “0xDEADBEEF”}")
        .expect("smart-quoted transaction hash alias with fullwidth colon should parse");
    assert_eq!(smart_quoted, "deadbeef");
}

#[test]
fn parse_tx_hash_accepts_json_receipts_without_quotes_around_hash() {
    let json = parse_tx_hash("{\"txhash\":0xDEADBEEF,\"status\":\"accepted\"}")
        .expect("json receipt hash without quotes should parse");
    assert_eq!(json, "deadbeef");
}

#[test]
fn parse_tx_hash_accepts_single_quoted_json_style_receipts() {
    let single_quoted = parse_tx_hash("{'tx_hash': '0xDEADBEEF', 'status': 'accepted'}")
        .expect("single-quoted json-style receipt hash should parse");
    assert_eq!(single_quoted, "deadbeef");

    let uppercase = parse_tx_hash("adapter stdout: {'TX-HASH' : 'ABCD1234'}")
        .expect("single-quoted uppercase hyphenated receipt hash should parse");
    assert_eq!(uppercase, "abcd1234");
}
