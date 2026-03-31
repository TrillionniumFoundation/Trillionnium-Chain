use super::ENV_LOCK;
use super::*;

#[test]
fn tpl_replacement_works() {
    let got = tpl("send {from} {to} {amount}".to_string(), "from", "alice");
    let got = tpl(got, "to", "bob");
    let got = tpl(got, "amount", "7");
    assert_eq!(got, "send alice bob 7");
}

#[test]
fn persist_local_pending_tx_keeps_pending_state() {
    let _guard = ENV_LOCK.lock().unwrap();
    let unique = format!(
        "trnm-cli-test-{}-{}.json",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let path = std::env::temp_dir().join(unique);
    std::env::set_var("TRNM_RPC_TX_FILE", &path);

    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let tx_hash = format!("0x{:064x}", nonce);
    persist_local_pending_tx(&tx_hash).unwrap();

    let status = query_local_tx_status(&tx_hash).unwrap();
    assert_eq!(status, "pending");

    let _ = std::fs::remove_file(&path);
    std::env::remove_var("TRNM_RPC_TX_FILE");
}

#[test]
fn query_local_tx_status_normalizes_aliases_and_rejects_unknown() {
    let _guard = ENV_LOCK.lock().unwrap();
    let unique = format!(
        "trnm-cli-test-{}-{}.json",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let path = std::env::temp_dir().join(unique);
    std::env::set_var("TRNM_RPC_TX_FILE", &path);

    let ok_hash = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let bad_hash = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let payload = format!(
        "{{\n  \"{}\": {{\"status\": \"success!\"}},\n  \"{}\": {{\"status\": \"mystery\"}}\n}}",
        ok_hash, bad_hash
    );
    std::fs::write(&path, payload).unwrap();

    assert_eq!(query_local_tx_status(ok_hash).as_deref(), Some("committed"));
    assert_eq!(query_local_tx_status(bad_hash), None);

    let _ = std::fs::remove_file(&path);
    std::env::remove_var("TRNM_RPC_TX_FILE");
}

#[test]
fn query_local_tx_status_normalizes_requested_hash_noise() {
    let _guard = ENV_LOCK.lock().unwrap();
    let unique = format!(
        "trnm-cli-test-{}-{}.json",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let path = std::env::temp_dir().join(unique);
    std::env::set_var("TRNM_RPC_TX_FILE", &path);

    let canonical = "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
    let payload = format!(
        "{{\n  \"{}\": {{\"status\": \"pending\"}}\n}}",
        canonical
    );
    std::fs::write(&path, payload).unwrap();

    assert_eq!(
        query_local_tx_status("<0xABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890>?!")
            .as_deref(),
        Some("pending")
    );
    assert_eq!(
        query_local_tx_status("\u{2068}<0xABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890>\u{2069}\u{200b}")
            .as_deref(),
        Some("pending")
    );

    let _ = std::fs::remove_file(&path);
    std::env::remove_var("TRNM_RPC_TX_FILE");
}

#[test]
fn persist_local_pending_tx_normalizes_wrapped_tx_hash_input() {
    let _guard = ENV_LOCK.lock().unwrap();
    let unique = format!(
        "trnm-cli-test-{}-{}.json",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let path = std::env::temp_dir().join(unique);
    std::env::set_var("TRNM_RPC_TX_FILE", &path);

    let noisy = "\u{2068}<0xABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890>\u{2069},";
    let canonical = "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
    persist_local_pending_tx(noisy).unwrap();

    let raw = std::fs::read_to_string(&path).unwrap();
    assert!(raw.contains(canonical), "expected canonical hash in persisted state: {raw}");
    assert_eq!(query_local_tx_status(canonical).as_deref(), Some("pending"));

    let _ = std::fs::remove_file(&path);
    std::env::remove_var("TRNM_RPC_TX_FILE");
}

#[test]
fn persist_local_pending_tx_rejects_non_prefixed_hashes() {
    let err = persist_local_pending_tx("abcdef123456").unwrap_err().to_string();
    assert!(
        err.contains("expected 0x-prefixed hex tx hash"),
        "unexpected: {err}"
    );
}
