pub(crate) use super::*;

#[test]
fn normalize_tx_hash_lookup_tolerates_shell_wrapped_quotes() {
    assert_eq!(normalize_tx_hash_lookup("  \"0xAbC123\"  "), "0xabc123");
    assert_eq!(normalize_tx_hash_lookup(" '0xDeF456'\n"), "0xdef456");
    assert_eq!(normalize_tx_hash_lookup("'\"0xA1B2\"'"), "0xa1b2");
    assert_eq!(normalize_tx_hash_lookup(" `0xFf00` "), "0xff00");
    assert_eq!(normalize_tx_hash_lookup("`\"0xBEEF\"`"), "0xbeef");
}

#[test]
fn normalize_tx_hash_lookup_tolerates_log_delimiter_wrapping() {
    assert_eq!(normalize_tx_hash_lookup("\"0xAbC123\","), "0xabc123");
    assert_eq!(normalize_tx_hash_lookup("(\"0xDeF456\")"), "0xdef456");
    assert_eq!(normalize_tx_hash_lookup("{'0xA1B2'};"), "0xa1b2");
    assert_eq!(normalize_tx_hash_lookup("[ `0xFf00` ]"), "0xff00");
    assert_eq!(normalize_tx_hash_lookup("tx=0xBEEF"), "tx=0xbeef");
}

#[test]
fn normalize_tx_hash_lookup_accepts_common_key_value_forms() {
    assert_eq!(normalize_tx_hash_lookup("tx_hash=0xAbC123"), "0xabc123");
    assert_eq!(
        normalize_tx_hash_lookup("TxHash = \"0xDeF456\""),
        "0xdef456"
    );
    assert_eq!(normalize_tx_hash_lookup("hash= 0xA1B2"), "0xa1b2");
    assert_eq!(normalize_tx_hash_lookup("tx_hash:0xC0FFEE"), "0xc0ffee");
    assert_eq!(normalize_tx_hash_lookup("hash : `0xBEEF`"), "0xbeef");
    assert_eq!(normalize_tx_hash_lookup("tx-hash=0xCAFE"), "0xcafe");
    assert_eq!(normalize_tx_hash_lookup("tx_hash==0xFEED"), "0xfeed");
    assert_eq!(normalize_tx_hash_lookup("hash:: 0xBADA55"), "0xbada55");
    assert_eq!(normalize_tx_hash_lookup("tx hash = 0xF00D"), "0xf00d");
    assert_eq!(normalize_tx_hash_lookup("Tx.Hash: 0xFACE"), "0xface");
}

#[test]
fn normalize_tx_hash_lookup_trims_trailing_sentence_punctuation_after_hash_value() {
    assert_eq!(normalize_tx_hash_lookup("tx_hash=0xAbC123."), "0xabc123");
    assert_eq!(normalize_tx_hash_lookup("tx_hash=0xDeF456:"), "0xdef456");
}

#[test]
fn is_hex_like_tx_hash_accepts_only_0x_prefixed_hex() {
    assert!(is_hex_like_tx_hash("0xabc123"));
    assert!(is_hex_like_tx_hash("0xA1B2"));
    assert!(!is_hex_like_tx_hash("abc123"));
    assert!(!is_hex_like_tx_hash("0x"));
    assert!(!is_hex_like_tx_hash("0xzz99"));
    assert!(!is_hex_like_tx_hash("tx_hash=0xabc123"));
}

#[test]
fn normalize_market_worker_key_strips_soft_hyphen_alias_spoofing() {
    let got = normalize_market_worker_key("Worker\u{00AD} A").expect("normalized");
    assert_eq!(got, "worker a");
    assert_eq!(
        normalize_market_worker_key("Worker A").expect("normalized"),
        got
    );
}

#[test]
fn normalize_market_worker_key_collapses_non_ascii_whitespace_aliases() {
    let got = normalize_market_worker_key("Worker\u{00A0}A").expect("normalized");
    assert_eq!(got, "worker a");
    assert_eq!(
        normalize_market_worker_key("\u{2003}Worker\tA\n").expect("normalized"),
        got
    );
}

#[test]
fn normalize_actor_or_signer_strips_controls_and_zero_width() {
    let got = normalize_actor_or_signer(" \u{200B}alice\u{2060}\u{0007} bob ").expect("normalized");
    assert_eq!(got, "alice bob");
    assert!(normalize_actor_or_signer("\u{200B}\u{2060}\u{0000}").is_none());
}

#[test]
fn normalize_actor_or_signer_treats_controls_as_separators_not_concatenation() {
    let got = normalize_actor_or_signer("alice\u{0007}bob").expect("normalized");
    assert_eq!(got, "alice bob");
}

#[test]
fn parse_u64_kv_value_tolerates_log_token_wrapping() {
    assert_eq!(parse_u64_kv_value("42"), Some(42));
    assert_eq!(parse_u64_kv_value("\"42\","), Some(42));
    assert_eq!(parse_u64_kv_value(" '42';"), Some(42));
    assert_eq!(parse_u64_kv_value("`42`"), Some(42));
    assert_eq!(parse_u64_kv_value("(42)"), Some(42));
    assert_eq!(parse_u64_kv_value("[42]"), Some(42));
    assert_eq!(parse_u64_kv_value("{42}"), Some(42));
    assert_eq!(parse_u64_kv_value("42."), Some(42));
    assert_eq!(parse_u64_kv_value("42:"), Some(42));
    assert_eq!(parse_u64_kv_value("bad42"), None);
    assert_eq!(parse_u64_kv_value("42ms"), None);
}

#[test]
fn parse_u128_kv_value_tolerates_log_token_wrapping_without_suffix_false_positives() {
    assert_eq!(
        parse_u128_kv_value("1700000000123"),
        Some(1_700_000_000_123)
    );
    assert_eq!(
        parse_u128_kv_value("\"1700000000123\","),
        Some(1_700_000_000_123)
    );
    assert_eq!(
        parse_u128_kv_value("(1700000000123)"),
        Some(1_700_000_000_123)
    );
    assert_eq!(
        parse_u128_kv_value("1700000000123."),
        Some(1_700_000_000_123)
    );
    assert_eq!(parse_u128_kv_value("1700000000123ms"), None);
    assert_eq!(parse_u128_kv_value("ts=1700000000123"), None);
}

#[test]
fn parse_i128_kv_value_tolerates_signed_wrapping_without_suffix_false_positives() {
    assert_eq!(parse_i128_kv_value("-42"), Some(-42));
    assert_eq!(parse_i128_kv_value("\"-42\","), Some(-42));
    assert_eq!(parse_i128_kv_value("(+7)"), Some(7));
    assert_eq!(parse_i128_kv_value("-42."), Some(-42));
    assert_eq!(parse_i128_kv_value("-42ms"), None);
    assert_eq!(parse_i128_kv_value("delta=-42"), None);
}
