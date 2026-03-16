use super::*;

#[test]
fn parse_tx_hash_accepts_quoted_and_trailing_punctuated_tokens() {
    let mixed_case =
        "tx_hash=\"0xABCDabcdABCDabcdABCDabcdABCDabcdABCDabcdABCDabcdABCDabcdABCDabcd\",";
    let parsed = parse_tx_hash(mixed_case).expect("hash should parse");
    assert_eq!(
        parsed,
        "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd"
    );

    let sentence_tail = "submitted tx_hash=0xABCDabcdABCDabcdABCDabcdABCDabcdABCDabcdABCDabcdABCDabcdABCDabcd. next";
    let parsed_tail =
        parse_tx_hash(sentence_tail).expect("hash with sentence punctuation should parse");
    assert_eq!(
        parsed_tail,
        "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd"
    );

    let backtick_wrapped =
            "adapter stdout: tx_hash=`0xABCDabcdABCDabcdABCDabcdABCDabcdABCDabcdABCDabcdABCDabcdABCDabcd`";
    let parsed_backtick =
        parse_tx_hash(backtick_wrapped).expect("backtick-wrapped hash should parse");
    assert_eq!(
        parsed_backtick,
        "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd"
    );
}

#[test]
fn parse_tx_hash_accepts_angle_bracket_wrapped_receipts() {
    let shell = parse_tx_hash(
            "[adapter] commit accepted tx_hash=<0xABCDabcdABCDabcdABCDabcdABCDabcdABCDabcdABCDabcdABCDabcdABCDabcd>",
        )
        .expect("angle-bracket shell receipt hash should parse");
    assert_eq!(
        shell,
        "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd"
    );

    let json = parse_tx_hash(
            "adapter stdout: {\"tx_hash\": \"<0xFACEfaceFACEfaceFACEfaceFACEfaceFACEfaceFACEfaceFACEfaceFACEface>\"}",
        )
        .expect("angle-bracket json receipt hash should parse");
    assert_eq!(
        json,
        "facefacefacefacefacefacefacefacefacefacefacefacefacefacefaceface"
    );
}

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
fn parse_tx_hash_accepts_unicode_dash_receipt_keys() {
    let non_breaking_shell = parse_tx_hash("[adapter] commit accepted tx‑hash=0xDEADBEEF")
        .expect("non-breaking hyphen shell receipt key should parse");
    assert_eq!(non_breaking_shell, "deadbeef");

    let em_dash_json = parse_tx_hash("adapter stdout: {\"transaction—hash\": \"0xFACECAFE\"}")
        .expect("em dash json receipt key should parse");
    assert_eq!(em_dash_json, "facecafe");

    let fullwidth_shell = parse_tx_hash("[adapter] commit accepted transaction－hash:0xBADDCAFE")
        .expect("fullwidth hyphen shell receipt key should parse");
    assert_eq!(fullwidth_shell, "baddcafe");
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
