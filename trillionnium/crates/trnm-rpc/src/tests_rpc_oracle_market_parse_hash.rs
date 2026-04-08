use super::*;

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
fn normalize_tx_hash_lookup_trims_sentence_period_after_hash_value() {
    assert_eq!(normalize_tx_hash_lookup("tx_hash=0xAbC123."), "0xabc123");
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
