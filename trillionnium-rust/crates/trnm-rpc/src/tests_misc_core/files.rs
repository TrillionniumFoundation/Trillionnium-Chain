pub(crate) use super::*;

#[test]
fn atomic_write_text_file_replaces_without_leaving_temp_files() {
    let path = unique_tmp_path("rpc-atomic-write", "json");
    let parent = path.parent().expect("temp parent").to_path_buf();
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap()
        .to_string();
    let _ = fs::remove_file(&path);

    atomic_write_text_file(&path, "{\"ok\":true}\n").expect("atomic write succeeds");
    let raw = fs::read_to_string(&path).expect("read atomic target");
    assert_eq!(raw, "{\"ok\":true}\n");

    let leftovers: Vec<_> = fs::read_dir(&parent)
        .expect("read temp dir")
        .filter_map(Result::ok)
        .map(|entry| entry.file_name().to_string_lossy().to_string())
        .filter(|name| name.starts_with(&format!(".{}.tmp-", file_name)))
        .collect();
    assert!(
        leftovers.is_empty(),
        "temporary atomic-write files should be cleaned"
    );

    let _ = fs::remove_file(&path);
}

#[test]
fn atomic_write_text_file_creates_missing_parent_directories() {
    let base = unique_tmp_path("rpc-atomic-write-nested", "tmp");
    let _ = fs::remove_file(&base);
    let _ = fs::remove_dir_all(&base);

    let path = base.join("nested").join("index.json");
    let parent = path.parent().expect("nested parent");
    assert!(
        !parent.exists(),
        "test setup should start with missing persistence directories"
    );

    atomic_write_text_file(&path, "{\"height\":9}\n")
        .expect("atomic write creates missing parent dirs");

    assert!(parent.exists(), "atomic write should create parent directories");
    let raw = fs::read_to_string(&path).expect("read nested atomic target");
    assert_eq!(raw, "{\"height\":9}\n");

    let _ = fs::remove_dir_all(&base);
}

#[test]
fn load_account_state_tolerates_utf8_bom_prefixed_json() {
    let path = unique_tmp_path("rpc-account-state-bom", "json");
    let _ = fs::remove_file(&path);
    fs::write(
        &path,
        "\u{feff}{\n  \"alice\": {\"address\":\"alice\",\"balance\":7,\"nonce\":3}\n}\n",
    )
    .expect("write BOM-prefixed account state");

    let accounts = load_account_state(&path);
    let alice = accounts.get("alice").expect("alice account should parse");
    assert_eq!(alice.address, "alice");
    assert_eq!(alice.balance, 7);
    assert_eq!(alice.nonce, 3);

    let _ = fs::remove_file(&path);
}

#[test]
fn load_account_state_tolerates_whitespace_prefixed_utf8_bom_json() {
    let path = unique_tmp_path("rpc-account-state-whitespace-bom", "json");
    let _ = fs::remove_file(&path);
    fs::write(
        &path,
        "  \n\t\u{feff}{\n  \"alice\": {\"address\":\"alice\",\"balance\":9,\"nonce\":4}\n}\n",
    )
    .expect("write whitespace-prefixed BOM account state");

    let accounts = load_account_state(&path);
    let alice = accounts.get("alice").expect("alice account should parse");
    assert_eq!(alice.address, "alice");
    assert_eq!(alice.balance, 9);
    assert_eq!(alice.nonce, 4);

    let _ = fs::remove_file(&path);
}

#[test]
fn load_account_state_tolerates_whitespace_after_utf8_bom_json() {
    let path = unique_tmp_path("rpc-account-state-post-bom-whitespace", "json");
    let _ = fs::remove_file(&path);
    fs::write(
        &path,
        "\u{feff}\r\n  {\n  \"alice\": {\"address\":\"alice\",\"balance\":11,\"nonce\":5}\n}\n",
    )
    .expect("write post-BOM-whitespace account state");

    let accounts = load_account_state(&path);
    let alice = accounts
        .get("alice")
        .expect("alice account should parse after BOM-adjacent whitespace");
    assert_eq!(alice.address, "alice");
    assert_eq!(alice.balance, 11);
    assert_eq!(alice.nonce, 5);

    let _ = fs::remove_file(&path);
}

#[test]
fn load_account_state_returns_empty_map_for_invalid_utf8_json() {
    let path = unique_tmp_path("rpc-account-state-invalid-utf8", "json");
    let _ = fs::remove_file(&path);
    fs::write(&path, b"\xff\xfe\xfa invalid-account-state\n")
        .expect("write invalid utf8 account state");

    let accounts = load_account_state(&path);
    assert!(
        accounts.is_empty(),
        "invalid utf-8 account state should fail closed to an empty durable map"
    );

    let _ = fs::remove_file(&path);
}

#[test]
fn load_faucet_limits_tolerates_whitespace_prefixed_utf8_bom_json() {
    let path = unique_tmp_path("rpc-faucet-limits-whitespace-bom", "json");
    let _ = fs::remove_file(&path);
    fs::write(
        &path,
        "\r\n  \t\u{feff}{\n  \"alice\": {\"window_start_unix_ms\":1234,\"count_in_window\":2}\n}\n",
    )
    .expect("write whitespace-prefixed BOM faucet limits");

    let limits = load_faucet_limits(&path);
    let alice = limits.get("alice").expect("alice limits should parse");
    assert_eq!(alice.window_start_unix_ms, 1234);
    assert_eq!(alice.count_in_window, 2);

    let _ = fs::remove_file(&path);
}

#[test]
fn load_faucet_limits_returns_empty_map_for_invalid_utf8_json() {
    let path = unique_tmp_path("rpc-faucet-limits-invalid-utf8", "json");
    let _ = fs::remove_file(&path);
    fs::write(&path, b"\xff\xfe\xfa invalid-faucet-limits\n")
        .expect("write invalid utf8 faucet limits");

    let limits = load_faucet_limits(&path);
    assert!(
        limits.is_empty(),
        "invalid utf-8 faucet limits should fail closed to an empty durable map"
    );

    let _ = fs::remove_file(&path);
}

#[test]
fn load_faucet_limits_tolerates_whitespace_after_utf8_bom_json() {
    let path = unique_tmp_path("rpc-faucet-limits-post-bom-whitespace", "json");
    let _ = fs::remove_file(&path);
    fs::write(
        &path,
        "\u{feff}\r\n  {\n  \"alice\": {\"window_start_unix_ms\":5678,\"count_in_window\":3}\n}\n",
    )
    .expect("write post-BOM-whitespace faucet limits");

    let limits = load_faucet_limits(&path);
    let alice = limits
        .get("alice")
        .expect("alice limits should parse after BOM-adjacent whitespace");
    assert_eq!(alice.window_start_unix_ms, 5678);
    assert_eq!(alice.count_in_window, 3);

    let _ = fs::remove_file(&path);
}

#[test]
fn load_tx_lifecycle_tolerates_whitespace_prefixed_utf8_bom_json() {
    let path = unique_tmp_path("rpc-tx-lifecycle-whitespace-bom", "json");
    let _ = fs::remove_file(&path);
    fs::write(
        &path,
        "\r\n\t\u{feff}{\n  \"0xabc\": {\n    \"tx_hash\": \"0xabc\",\n    \"tx\": {\n      \"from\": \"alice\",\n      \"to\": \"bob\",\n      \"amount\": 7,\n      \"fee\": 1,\n      \"nonce\": 4,\n      \"signature\": \"feedface\"\n    },\n    \"status\": \"committed\",\n    \"error\": null,\n    \"submitted_at_unix_ms\": 10,\n    \"updated_at_unix_ms\": 11\n  }\n}\n",
    )
    .expect("write whitespace-prefixed BOM tx lifecycle");

    let txs = load_tx_lifecycle(&path);
    let tx = txs.get("0xabc").expect("tx lifecycle should parse");
    assert_eq!(tx.tx_hash, "0xabc");
    assert_eq!(tx.tx.from, "alice");
    assert_eq!(tx.tx.to, "bob");
    assert_eq!(tx.tx.amount, 7);
    assert_eq!(tx.tx.fee, 1);
    assert_eq!(tx.tx.nonce, 4);
    assert_eq!(tx.status, TxStatus::Committed);
    assert_eq!(tx.error, None);
    assert_eq!(tx.submitted_at_unix_ms, 10);
    assert_eq!(tx.updated_at_unix_ms, 11);

    let _ = fs::remove_file(&path);
}

#[test]
fn load_tx_lifecycle_tolerates_whitespace_after_utf8_bom_json() {
    let path = unique_tmp_path("rpc-tx-lifecycle-post-bom-whitespace", "json");
    let _ = fs::remove_file(&path);
    fs::write(
        &path,
        "\u{feff}\r\n  {\n  \"0xdef\": {\n    \"tx_hash\": \"0xdef\",\n    \"tx\": {\n      \"from\": \"carol\",\n      \"to\": \"dave\",\n      \"amount\": 8,\n      \"fee\": 1,\n      \"nonce\": 5,\n      \"signature\": \"cafebabe\"\n    },\n    \"status\": \"committed\",\n    \"error\": null,\n    \"submitted_at_unix_ms\": 12,\n    \"updated_at_unix_ms\": 13\n  }\n}\n",
    )
    .expect("write post-BOM-whitespace tx lifecycle");

    let txs = load_tx_lifecycle(&path);
    let tx = txs
        .get("0xdef")
        .expect("tx lifecycle should parse after BOM-adjacent whitespace");
    assert_eq!(tx.tx_hash, "0xdef");
    assert_eq!(tx.tx.from, "carol");
    assert_eq!(tx.tx.to, "dave");
    assert_eq!(tx.tx.amount, 8);
    assert_eq!(tx.tx.fee, 1);
    assert_eq!(tx.tx.nonce, 5);
    assert_eq!(tx.status, TxStatus::Committed);
    assert_eq!(tx.error, None);
    assert_eq!(tx.submitted_at_unix_ms, 12);
    assert_eq!(tx.updated_at_unix_ms, 13);

    let _ = fs::remove_file(&path);
}

#[test]
fn load_tx_lifecycle_returns_empty_map_for_invalid_utf8_json() {
    let path = unique_tmp_path("rpc-tx-lifecycle-invalid-utf8", "json");
    let _ = fs::remove_file(&path);
    fs::write(&path, b"\xff\xfe\xfa invalid-tx-lifecycle\n")
        .expect("write invalid utf8 tx lifecycle");

    let txs = load_tx_lifecycle(&path);
    assert!(
        txs.is_empty(),
        "invalid utf-8 tx lifecycle should fail closed to an empty durable map"
    );

    let _ = fs::remove_file(&path);
}
