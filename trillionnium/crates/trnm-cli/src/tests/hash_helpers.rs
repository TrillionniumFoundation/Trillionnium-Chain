use super::*;

#[test]
fn extract_tx_hash_supports_json_and_kv() {
    assert_eq!(extract_tx_hash("tx_hash=abc123").as_deref(), Some("abc123"));
    assert_eq!(
        extract_tx_hash("{\"tx_hash\":\"deadbeef\",\"status\":\"ok\"}").as_deref(),
        Some("deadbeef")
    );
}

#[test]
fn extract_tx_hash_trims_quotes_and_trailing_punctuation() {
    assert_eq!(
        extract_tx_hash("tx_hash=\"0xabc123\", status=submitted").as_deref(),
        Some("0xabc123")
    );
    assert_eq!(
        extract_tx_hash("{\"txhash\":\"0xdef456;\"}").as_deref(),
        Some("0xdef456")
    );
}

#[test]
fn extract_tx_hash_accepts_uppercase_0x_prefix() {
    assert_eq!(
        extract_tx_hash("tx_hash=0XABCD1234").as_deref(),
        Some("0xabcd1234")
    );
    assert_eq!(
        extract_tx_hash("{\"tx_hash\":\"0XBEEF42\"}").as_deref(),
        Some("0xbeef42")
    );
}

#[test]
fn extract_tx_hash_accepts_uppercase_prefixed_hashes_and_json_aliases() {
    assert_eq!(
        extract_tx_hash("tx_hash=0xDEADBEEFCAFEBABE").as_deref(),
        Some("0xdeadbeefcafebabe")
    );
    assert_eq!(
        extract_tx_hash("{\"txHash\":\"ABCDEF012345\",\"status\":\"ok\"}").as_deref(),
        Some("abcdef012345")
    );
}

#[test]
fn extract_tx_hash_accepts_nested_json_wrappers() {
    let wrapped = "{\"result\":{\"tx_response\":{\"txhash\":\"0xABC123\"}}}";
    assert_eq!(extract_tx_hash(wrapped).as_deref(), Some("0xabc123"));

    let response = "{\"response\":{\"data\":{\"transactionHash\":\"BEEF4567\"}}}";
    assert_eq!(extract_tx_hash(response).as_deref(), Some("beef4567"));
}

#[test]
fn extract_tx_hash_rejects_non_hex_prefixed_values() {
    assert_eq!(extract_tx_hash("tx_hash=0xzz99").as_deref(), None);
    assert_eq!(
        extract_tx_hash("{\"tx_hash\":\"0xhash-not-hex\"}").as_deref(),
        None
    );
}

#[test]
fn extract_tx_hash_accepts_case_insensitive_keys_and_colon_separator() {
    assert_eq!(
        extract_tx_hash("INFO start TX_HASH:0xbeef01, done").as_deref(),
        Some("0xbeef01")
    );
    assert_eq!(
        extract_tx_hash("meta txHash=0xcafe02;").as_deref(),
        Some("0xcafe02")
    );
}

#[test]
fn extract_tx_hash_accepts_hyphenated_key_aliases() {
    assert_eq!(
        extract_tx_hash("tx-hash=0xCAFE01").as_deref(),
        Some("0xcafe01")
    );
    assert_eq!(
        extract_tx_hash("transaction-hash: 0xBEEF02").as_deref(),
        Some("0xbeef02")
    );
}

#[test]
fn emitted_transaction_hash_camel_alias_round_trips_through_parser() {
    assert_eq!(
        format_transaction_hash_camel_alias_line("0xABCD1234"),
        "transactionHash=0xABCD1234".to_string()
    );
    assert_eq!(
        extract_tx_hash(&format_transaction_hash_camel_alias_line("0xABCD1234")).as_deref(),
        Some("0xabcd1234")
    );
}

#[test]
fn emitted_transaction_hash_spaced_alias_round_trips_through_parser() {
    assert_eq!(
        format_transaction_hash_spaced_alias_line("0xABCD1234"),
        "transaction hash=0xABCD1234".to_string()
    );
    assert_eq!(
        extract_tx_hash(&format_transaction_hash_spaced_alias_line("0xABCD1234")).as_deref(),
        Some("0xabcd1234")
    );
}

#[test]
fn emitted_tx_hash_spaced_alias_round_trips_through_parser() {
    assert_eq!(
        format_tx_hash_spaced_alias_line("0xABCD1234"),
        "tx hash=0xABCD1234".to_string()
    );
    assert_eq!(
        extract_tx_hash(&format_tx_hash_spaced_alias_line("0xABCD1234")).as_deref(),
        Some("0xabcd1234")
    );
}

#[test]
fn extract_tx_hash_accepts_spaced_key_aliases() {
    assert_eq!(
        extract_tx_hash("tx hash=0xCAFE03").as_deref(),
        Some("0xcafe03")
    );
    assert_eq!(
        extract_tx_hash("transaction hash : 0xBEEF04").as_deref(),
        Some("0xbeef04")
    );
    assert_eq!(
        extract_tx_hash("INFO transaction hash ＝ 0xBEEF05 done").as_deref(),
        Some("0xbeef05")
    );
}

#[test]
fn extract_tx_hash_accepts_spaced_separators() {
    assert_eq!(
        extract_tx_hash("tx_hash = 0xfeed55").as_deref(),
        Some("0xfeed55")
    );
    assert_eq!(
        extract_tx_hash("transactionHash : 0xBEEF66").as_deref(),
        Some("0xbeef66")
    );
}

#[test]
fn extract_tx_hash_accepts_fullwidth_separators() {
    assert_eq!(
        extract_tx_hash("tx_hash＝0xFEED77").as_deref(),
        Some("0xfeed77")
    );
    assert_eq!(
        extract_tx_hash("transactionHash：0xBEEF88").as_deref(),
        Some("0xbeef88")
    );
}

#[test]
fn extract_tx_hash_accepts_angle_bracket_wrapped_hashes() {
    assert_eq!(
        extract_tx_hash("tx_hash=<0xBEEF42>").as_deref(),
        Some("0xbeef42")
    );
    assert_eq!(
        extract_tx_hash("see <transactionHash:0xCAFE99> now").as_deref(),
        Some("0xcafe99")
    );
}

#[test]
fn extract_tx_hash_trims_sentence_punctuation_noise() {
    assert_eq!(
        extract_tx_hash("tx_hash=0xABCD1234.").as_deref(),
        Some("0xabcd1234")
    );
    assert_eq!(
        extract_tx_hash("transactionHash:0xBEEF42?!").as_deref(),
        Some("0xbeef42")
    );
}

#[test]
fn extract_tx_hash_trims_hidden_unicode_wrappers() {
    assert_eq!(
        extract_tx_hash("tx_hash=\u{2068}<0xABCD1234>\u{2069}").as_deref(),
        Some("0xabcd1234")
    );
    assert_eq!(
        extract_tx_hash("transactionHash:\u{feff}0xBEEF42\u{200b}?!").as_deref(),
        Some("0xbeef42")
    );
}

#[test]
fn extract_tx_hash_trims_bidi_control_wrappers() {
    assert_eq!(
        extract_tx_hash("tx_hash=\u{200e}0xABCD1234\u{200f}").as_deref(),
        Some("0xabcd1234")
    );
    assert_eq!(
        extract_tx_hash("transactionHash:\u{061c}0xBEEF42\u{200f}?!").as_deref(),
        Some("0xbeef42")
    );
}

#[test]
fn extract_tx_hash_trims_unicode_whitespace_noise() {
    assert_eq!(
        extract_tx_hash("tx_hash=\u{00a0}0xABCD1234\u{2003}").as_deref(),
        Some("0xabcd1234")
    );
    assert_eq!(
        extract_tx_hash("transactionHash:\u{2002}0xBEEF42\u{00a0};").as_deref(),
        Some("0xbeef42")
    );
}

#[test]
fn extract_tx_hash_accepts_single_sided_quote_noise() {
    assert_eq!(
        extract_tx_hash("tx_hash='0xABCD1234,").as_deref(),
        Some("0xabcd1234")
    );
    assert_eq!(
        extract_tx_hash("transactionHash: `0xBEEF42?!").as_deref(),
        Some("0xbeef42")
    );
}

#[test]
fn extract_tx_hash_trims_smart_quote_wrappers() {
    assert_eq!(
        extract_tx_hash("tx_hash=“0xABCD1234”").as_deref(),
        Some("0xabcd1234")
    );
    assert_eq!(
        extract_tx_hash("transactionHash: ‘0xBEEF42’?!").as_deref(),
        Some("0xbeef42")
    );
}

#[test]
fn extract_tx_hash_trims_fullwidth_wrapper_noise() {
    assert_eq!(
        extract_tx_hash("tx_hash=（《0xABCD1234》）；").as_deref(),
        Some("0xabcd1234")
    );
    assert_eq!(
        extract_tx_hash("transactionHash：『0xBEEF42』！？").as_deref(),
        Some("0xbeef42")
    );
}

#[test]
fn extract_tx_hash_trims_corner_quote_wrappers() {
    assert_eq!(
        extract_tx_hash("tx_hash=｢0xABCD1234｣").as_deref(),
        Some("0xabcd1234")
    );
    assert_eq!(
        extract_tx_hash("transactionHash: ｢0xBEEF42｣?!").as_deref(),
        Some("0xbeef42")
    );
}

#[test]
fn extract_tx_hash_trims_guillemet_and_lenticular_wrappers() {
    assert_eq!(
        extract_tx_hash("tx_hash=«0xABCD1234»").as_deref(),
        Some("0xabcd1234")
    );
    assert_eq!(
        extract_tx_hash("transactionHash: 【0xBEEF42】?!").as_deref(),
        Some("0xbeef42")
    );
}

#[test]
fn extract_tx_hash_trims_vertical_presentation_quotes() {
    assert_eq!(
        extract_tx_hash("tx_hash=〝0xABCD1234〞").as_deref(),
        Some("0xabcd1234")
    );
    assert_eq!(
        extract_tx_hash("transactionHash: 〟0xBEEF42〟?!").as_deref(),
        Some("0xbeef42")
    );
}

#[test]
fn extract_tx_hash_accepts_inline_fullwidth_separators() {
    assert_eq!(
        extract_tx_hash("INFO tx_hash＝0xFEED77 done").as_deref(),
        Some("0xfeed77")
    );
    assert_eq!(
        extract_tx_hash("INFO transactionHash：0xBEEF88 done").as_deref(),
        Some("0xbeef88")
    );
}

#[test]
fn extract_tx_hash_accepts_inline_unicode_wrapper_noise() {
    assert_eq!(
        extract_tx_hash("INFO tx_hash=【0xCAFE55】 done").as_deref(),
        Some("0xcafe55")
    );
    assert_eq!(
        extract_tx_hash("INFO tx_hash＝『0xABCD66』；done").as_deref(),
        Some("0xabcd66")
    );
}
