use super::*;

#[test]
fn parse_tx_hash_accepts_short_failure_receipts_without_0x_prefix() {
    let parsed = parse_tx_hash("[adapter] simulated failure tx_hash=deadbeef")
        .expect("short failure receipt hash should parse");
    assert_eq!(parsed, "deadbeef");
}

#[test]
fn parse_tx_hash_accepts_colon_style_receipts() {
    let colon = parse_tx_hash("[adapter] commit accepted tx-hash:0xDEADBEEF")
        .expect("colon-delimited receipt hash should parse");
    assert_eq!(colon, "deadbeef");
}

#[test]
fn parse_tx_hash_accepts_fullwidth_delimiter_receipts() {
    let shell_equals = parse_tx_hash("[adapter] commit accepted tx_hash＝0xDEADBEEF")
        .expect("fullwidth equals shell receipt hash should parse");
    assert_eq!(shell_equals, "deadbeef");

    let shell_colon = parse_tx_hash("[adapter] commit accepted tx-hash：0xFACECAFE")
        .expect("fullwidth colon shell receipt hash should parse");
    assert_eq!(shell_colon, "facecafe");

    let json = parse_tx_hash("adapter stdout: {\"transaction_hash\"： \"0xBADDCAFE\"}")
        .expect("fullwidth colon json receipt hash should parse");
    assert_eq!(json, "baddcafe");
}

#[test]
fn parse_tx_hash_accepts_space_separated_receipt_keys() {
    let shell = parse_tx_hash("[adapter] commit accepted tx hash=0xDEADBEEF")
        .expect("space-separated shell receipt hash should parse");
    assert_eq!(shell, "deadbeef");

    let shell_with_spacing = parse_tx_hash("[adapter] commit accepted tx hash = 0xC0FFEE12")
        .expect("space-separated shell receipt hash with spaced delimiter should parse");
    assert_eq!(shell_with_spacing, "c0ffee12");

    let uppercase = parse_tx_hash("[adapter] commit accepted TX HASH:0xABCD1234")
        .expect("uppercase space-separated receipt hash should parse");
    assert_eq!(uppercase, "abcd1234");

    let uppercase_with_spacing = parse_tx_hash("[adapter] commit accepted TX HASH : 0xFACECAFE")
        .expect("uppercase space-separated receipt hash with spaced delimiter should parse");
    assert_eq!(uppercase_with_spacing, "facecafe");

    let json = parse_tx_hash("{\"tx hash\": \"0xBADDCAFE\", \"status\": \"accepted\"}")
        .expect("space-separated json receipt hash should parse");
    assert_eq!(json, "baddcafe");

    let single_quoted = parse_tx_hash("adapter stdout: {'TX HASH' : 'ABCD1234'}")
        .expect("single-quoted uppercase space-separated receipt hash should parse");
    assert_eq!(single_quoted, "abcd1234");
}

#[test]
fn parse_tx_hash_accepts_uppercase_receipt_keys() {
    let shell = parse_tx_hash("[adapter] commit accepted TX_HASH=0xDEADBEEF")
        .expect("uppercase shell receipt hash should parse");
    assert_eq!(shell, "deadbeef");

    let json = parse_tx_hash("{\"TX_HASH\": \"0xDEADBEEF\", \"status\": \"accepted\"}")
        .expect("uppercase json receipt hash should parse");
    assert_eq!(json, "deadbeef");

    let compact = parse_tx_hash("adapter stdout: {\"TXHASH\": \"ABCD1234\"}")
        .expect("uppercase compact json receipt hash should parse");
    assert_eq!(compact, "abcd1234");
}

#[test]
fn parse_tx_hash_accepts_json_style_receipts_with_whitespace_after_colon() {
    let json = parse_tx_hash("{\"tx_hash\": \"0xDEADBEEF\", \"status\": \"accepted\"}")
        .expect("json receipt hash with whitespace after colon should parse");
    assert_eq!(json, "deadbeef");
}

#[test]
fn parse_tx_hash_accepts_json_style_receipts_with_whitespace_before_colon() {
    let json = parse_tx_hash("{\"tx_hash\" : \"0xDEADBEEF\", \"status\": \"accepted\"}")
        .expect("json receipt hash with whitespace before colon should parse");
    assert_eq!(json, "deadbeef");
}

#[test]
fn parse_tx_hash_accepts_json_style_receipts_with_newlines_and_tabs_around_colon() {
    let json =
        parse_tx_hash("{\n\t\"tx_hash\"\n\t:\n\t\"0xDEADBEEF\",\n\t\"status\":\n\t\"accepted\"\n}")
            .expect("json receipt hash with newline/tab padding should parse");
    assert_eq!(json, "deadbeef");
}
