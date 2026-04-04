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
