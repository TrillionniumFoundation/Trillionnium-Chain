use super::*;
#[test]
fn parse_tx_hash_accepts_smart_quoted_receipts() {
    let curly_double = parse_tx_hash("adapter stdout: {\"tx_hash\": “0xDEADBEEF”}")
        .expect("smart double-quoted receipt hash should parse");
    assert_eq!(curly_double, "deadbeef");

    let curly_single = parse_tx_hash("adapter stdout: {'transaction_hash': ‘ABCD1234’}")
        .expect("smart single-quoted receipt hash should parse");
    assert_eq!(curly_single, "abcd1234");
}

#[test]
fn parse_tx_hash_accepts_smart_quoted_receipt_keys() {
    let curly_double_key = parse_tx_hash("adapter stdout: {“tx_hash”: \"0xDEADBEEF\"}")
        .expect("smart double-quoted receipt key should parse");
    assert_eq!(curly_double_key, "deadbeef");

    let curly_single_key = parse_tx_hash("adapter stdout: {‘transaction_hash’: 'ABCD1234'}")
        .expect("smart single-quoted receipt key should parse");
    assert_eq!(curly_single_key, "abcd1234");
}

#[test]
fn parse_tx_hash_accepts_localized_quote_wrapped_receipts() {
    let guillemet = parse_tx_hash("adapter stdout: {«tx_hash»: «0xDEADBEEF»}")
        .expect("guillemet-quoted receipt hash should parse");
    assert_eq!(guillemet, "deadbeef");

    let single_angle = parse_tx_hash("adapter stdout: {〈tx_hash〉: 〈0xBADDCAFE〉}")
        .expect("single-angle-quoted receipt hash should parse");
    assert_eq!(single_angle, "baddcafe");

    let double_angle = parse_tx_hash("adapter stdout: {《transaction hash》: 《0xABCD1234》}")
        .expect("double-angle-quoted transaction hash alias should parse");
    assert_eq!(double_angle, "abcd1234");

    let corner_bracket = parse_tx_hash("adapter stdout: {「transaction hash」: 「0xFACECAFE」}")
        .expect("corner-bracket-quoted transaction hash alias should parse");
    assert_eq!(corner_bracket, "facecafe");

    let math_angle = parse_tx_hash("adapter stdout: {⟨tx_hash⟩: ⟨0xC001D00D⟩}")
        .expect("math-angle-quoted receipt hash should parse");
    assert_eq!(math_angle, "c001d00d");
}

#[test]
fn parse_tx_hash_accepts_backtick_wrapped_receipt_keys() {
    let backtick_key = parse_tx_hash("adapter stdout: {`tx_hash`: `0xFACECAFE`}")
        .expect("backtick-wrapped receipt key should parse");
    assert_eq!(backtick_key, "facecafe");
}

#[test]
fn parse_tx_hash_accepts_shell_escaped_quote_wrapped_receipt_values() {
    let shell_escaped_double = parse_tx_hash(r#"adapter stdout: {\"tx_hash\": \"0xDEADBEEF\"}"#)
        .expect("shell-escaped double-quoted receipt hash should parse");
    assert_eq!(shell_escaped_double, "deadbeef");

    let shell_escaped_single = parse_tx_hash("adapter stdout: {'tx_hash': \\'ABCD1234\\'}")
        .expect("shell-escaped single-quoted receipt hash should parse");
    assert_eq!(shell_escaped_single, "abcd1234");
}

#[test]
fn parse_tx_hash_accepts_json_receipts_embedded_in_log_lines() {
    let json =
        parse_tx_hash("info: adapter response payload={\"tx_hash\": \"deadbeef\"} next=cleanup")
            .expect("embedded json receipt hash should parse");
    assert_eq!(json, "deadbeef");
}

#[test]
fn parse_tx_hash_accepts_128_char_receipts_for_real_cli_compat() {
    let long_hash = format!("0x{}", "AB".repeat(64));
    let parsed =
        parse_tx_hash(&format!("tx_hash={long_hash}")).expect("128-char tx hash should parse");
    assert_eq!(parsed, "ab".repeat(64));
}
