use super::super::*;

#[test]
fn tx_query_rejects_mismatched_tx_hash() {
    std::env::set_var(
        "TRNM_TX_QUERY_CMD",
        "printf '{\"tx_hash\":\"0xaaaa\",\"status\":\"committed\"}'",
    );
    let got = tx_query("0xbbbb");
    std::env::remove_var("TRNM_TX_QUERY_CMD");
    assert!(got.is_err());
}

#[test]
fn tx_query_rejects_non_hex_like_tx_hash_before_shell_exec() {
    std::env::set_var(
        "TRNM_TX_QUERY_CMD",
        "printf '{\"tx_hash\":\"0xaaaa\",\"status\":\"committed\"}'",
    );
    let got = tx_query("0xabc; touch /tmp/pwned");
    std::env::remove_var("TRNM_TX_QUERY_CMD");
    assert!(got.is_err());
    let msg = got.err().unwrap().to_string();
    assert!(
        msg.contains("invalid tx hash for query"),
        "unexpected: {msg}"
    );
}

#[test]
fn tx_query_rejects_bare_hex_without_0x_prefix_before_shell_exec() {
    std::env::set_var(
        "TRNM_TX_QUERY_CMD",
        "printf '{\"tx_hash\":\"0xaaaa\",\"status\":\"committed\"}'",
    );
    let got = tx_query("abcdef12");
    std::env::remove_var("TRNM_TX_QUERY_CMD");
    assert!(got.is_err());
    let msg = got.err().unwrap().to_string();
    assert!(
        msg.contains("expected 0x-prefixed hex tx hash"),
        "unexpected: {msg}"
    );
}

#[test]
fn tx_query_rejects_invalid_tx_hash_from_response() {
    std::env::set_var(
        "TRNM_TX_QUERY_CMD",
        "printf '{\"tx_hash\":\"not-a-hash\",\"status\":\"committed\"}'",
    );
    let got = tx_query("0xabc123");
    std::env::remove_var("TRNM_TX_QUERY_CMD");
    assert!(got.is_err());
    let msg = got.err().unwrap().to_string();
    assert!(
        msg.contains("invalid tx_hash field in tx query response"),
        "unexpected: {msg}"
    );
}
