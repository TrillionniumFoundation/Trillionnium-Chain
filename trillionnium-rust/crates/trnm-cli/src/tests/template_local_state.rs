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
