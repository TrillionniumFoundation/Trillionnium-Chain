use std::{
    path::PathBuf,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

fn bin() -> String {
    if let Ok(v) = std::env::var("CARGO_BIN_EXE_trnm-cli") {
        return v;
    }
    if let Ok(v) = std::env::var("CARGO_BIN_EXE_trnm_cli") {
        return v;
    }
    if let Ok(target_dir) = std::env::var("CARGO_TARGET_DIR") {
        return PathBuf::from(target_dir)
            .join("debug/trnm-cli")
            .to_string_lossy()
            .to_string();
    }
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .join("../../target/debug/trnm-cli")
        .to_string_lossy()
        .to_string()
}

fn tmp_dir(label: &str) -> PathBuf {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let temp_root = std::env::temp_dir().canonicalize().unwrap_or_else(|_| std::env::temp_dir());
    let p = temp_root.join(format!("trnm-cli-{label}-{ts}"));
    std::fs::create_dir_all(&p).unwrap();
    p
}

#[test]
fn smoke_wallet_create_and_address() {
    let store = tmp_dir("wallet-create");
    let out = Command::new(bin())
        .args([
            "wallet",
            "create",
            "--name",
            "alice",
            "--out",
            store.to_string_lossy().as_ref(),
        ])
        .output()
        .unwrap();
    assert!(out.status.success());
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(s.contains("wallet_name=alice"));
    assert!(s.contains("address=trnm1"));

    let out2 = Command::new(bin())
        .args([
            "wallet",
            "address",
            "--name",
            "alice",
            "--store",
            store.to_string_lossy().as_ref(),
        ])
        .output()
        .unwrap();
    assert!(out2.status.success());
}

#[test]
fn smoke_wallet_import_accepts_wrapped_private_key_hex() {
    let store = tmp_dir("wallet-import-wrapped");
    let pk = " \u{2068}<\"0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\">\u{2069}\n";
    let out = Command::new(bin())
        .args([
            "wallet",
            "import",
            "--name",
            "alice",
            "--private-key-hex",
            pk,
            "--out",
            store.to_string_lossy().as_ref(),
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(s.contains("wallet_name=alice"));
    assert!(s.contains("address=trnm1"));
}

#[cfg(unix)]
#[test]
fn smoke_wallet_create_rejects_symlinked_ancestor_out_path() {
    use std::os::unix::fs::symlink;

    let root = tmp_dir("wallet-create-symlink-ancestor");
    let real_parent = root.join("real-parent");
    let linked_parent = root.join("linked-parent");
    std::fs::create_dir_all(&real_parent).unwrap();
    symlink(&real_parent, &linked_parent).unwrap();
    let store = linked_parent.join("wallets");

    let out = Command::new(bin())
        .args([
            "wallet",
            "create",
            "--name",
            "alice",
            "--out",
            store.to_string_lossy().as_ref(),
        ])
        .output()
        .unwrap();

    assert!(
        !out.status.success(),
        "symlinked keystore ancestor should fail closed"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("refusing non-canonical keystore path"),
        "unexpected stderr: {}",
        stderr
    );
    assert!(!real_parent.join("wallets").join("alice.key").exists());
}

#[test]
fn smoke_wallet_sign_rejects_multiline_message() {
    let store = tmp_dir("wallet-sign-message-guard");
    let pk = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let import = Command::new(bin())
        .args([
            "wallet",
            "import",
            "--name",
            "alice",
            "--private-key-hex",
            pk,
            "--out",
            store.to_string_lossy().as_ref(),
        ])
        .output()
        .unwrap();
    assert!(
        import.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&import.stderr)
    );

    let out = Command::new(bin())
        .args([
            "wallet",
            "sign",
            "--name",
            "alice",
            "--message",
            "hello\nworld",
            "--store",
            store.to_string_lossy().as_ref(),
        ])
        .output()
        .unwrap();
    assert!(!out.status.success(), "multiline signer input should fail closed");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("sign message must be single-line printable text without control characters"),
        "unexpected stderr: {}",
        stderr
    );
}

#[test]
fn smoke_wallet_sign_rejects_bidi_control_message() {
    let store = tmp_dir("wallet-sign-bidi-guard");
    let pk = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let import = Command::new(bin())
        .args([
            "wallet",
            "import",
            "--name",
            "alice",
            "--private-key-hex",
            pk,
            "--out",
            store.to_string_lossy().as_ref(),
        ])
        .output()
        .unwrap();
    assert!(
        import.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&import.stderr)
    );

    let out = Command::new(bin())
        .args([
            "wallet",
            "sign",
            "--name",
            "alice",
            "--message",
            "approve\u{202e}tx",
            "--store",
            store.to_string_lossy().as_ref(),
        ])
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "bidi-controlled signer input should fail closed"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("sign message must be single-line printable text without control characters"),
        "unexpected stderr: {}",
        stderr
    );
}

#[test]
fn smoke_wallet_sign_rejects_edge_or_non_ascii_whitespace() {
    let store = tmp_dir("wallet-sign-whitespace-guard");
    let pk = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let import = Command::new(bin())
        .args([
            "wallet",
            "import",
            "--name",
            "alice",
            "--private-key-hex",
            pk,
            "--out",
            store.to_string_lossy().as_ref(),
        ])
        .output()
        .unwrap();
    assert!(
        import.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&import.stderr)
    );

    for bad_message in [" approve tx", "approve tx ", "approve\u{00a0}tx"] {
        let out = Command::new(bin())
            .args([
                "wallet",
                "sign",
                "--name",
                "alice",
                "--message",
                bad_message,
                "--store",
                store.to_string_lossy().as_ref(),
            ])
            .output()
            .unwrap();
        assert!(
            !out.status.success(),
            "whitespace-polluted signer input should fail closed: {bad_message:?}"
        );
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains("sign message must not start or end with whitespace")
                || stderr.contains(
                    "sign message must be single-line printable text without control characters"
                ),
            "unexpected stderr for {bad_message:?}: {}",
            stderr
        );
    }
}

#[test]
fn smoke_wallet_sign_emits_message_sha256_hint() {
    let store = tmp_dir("wallet-sign");
    let pk = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let import = Command::new(bin())
        .args([
            "wallet",
            "import",
            "--name",
            "alice",
            "--private-key-hex",
            pk,
            "--out",
            store.to_string_lossy().as_ref(),
        ])
        .output()
        .unwrap();
    assert!(import.status.success());

    let message = "rotate signer to cold-key slot b";
    let out = Command::new(bin())
        .args([
            "wallet",
            "sign",
            "--name",
            "alice",
            "--message",
            message,
            "--store",
            store.to_string_lossy().as_ref(),
        ])
        .output()
        .unwrap();
    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(s.contains("wallet_name=alice"));
    assert!(s.contains(&format!("message={message}")));
    assert!(s.contains("message_sha256=0921750d68e4f12cb9b90b90e66f3406f4bcf49e1a4a312e693fa5d8236d1cab"));
    assert!(s.contains("signature="));
}

#[test]
fn smoke_query_balance_fallback_json() {
    let store = tmp_dir("query-balance");
    let pk = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let out = Command::new(bin())
        .args([
            "wallet",
            "import",
            "--name",
            "alice",
            "--private-key-hex",
            pk,
            "--out",
            store.to_string_lossy().as_ref(),
        ])
        .output()
        .unwrap();
    assert!(out.status.success());

    let out2 = Command::new(bin())
        .args([
            "query",
            "balance",
            "--name",
            "alice",
            "--store",
            store.to_string_lossy().as_ref(),
        ])
        .output()
        .unwrap();
    assert!(out2.status.success());
    let s = String::from_utf8_lossy(&out2.stdout);
    assert!(s.contains("\"address\""));
    assert!(s.contains("\"balance\""));
}

#[test]
fn smoke_tx_commit_query_fallback_roundtrip() {
    let tx_file = tmp_dir("tx-query-fallback").join("txs.json");

    let submit = Command::new(bin())
        .env("TRNM_RPC_TX_FILE", tx_file.to_string_lossy().as_ref())
        .args([
            "tx",
            "commit-result",
            "9999991",
            "worker_readiness",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "1",
        ])
        .output()
        .unwrap();
    assert!(submit.status.success());
    let submit_stdout = String::from_utf8_lossy(&submit.stdout);
    let tx_hash_line = submit_stdout
        .lines()
        .find(|line| line.starts_with("tx_hash="))
        .expect("commit-result should print tx_hash");
    let tx_hash = tx_hash_line.trim_start_matches("tx_hash=");
    assert!(!tx_hash.is_empty());

    let query = Command::new(bin())
        .env("TRNM_RPC_TX_FILE", tx_file.to_string_lossy().as_ref())
        .args(["tx", "query", tx_hash])
        .output()
        .unwrap();
    assert!(
        query.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&query.stderr)
    );
    let query_stdout = String::from_utf8_lossy(&query.stdout);
    assert!(query_stdout.contains(&format!("tx_hash={}", tx_hash)));
    assert!(query_stdout.contains("status=pending"));
}

#[test]
fn smoke_tx_transfer_template_path() {
    let store = tmp_dir("tx-transfer");
    let pk = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    let out = Command::new(bin())
        .args([
            "wallet",
            "import",
            "--name",
            "sender",
            "--private-key-hex",
            pk,
            "--out",
            store.to_string_lossy().as_ref(),
        ])
        .output()
        .unwrap();
    assert!(out.status.success());

    let out2 = Command::new(bin())
        .env(
            "TRNM_TX_TRANSFER_CMD",
            "echo tx_hash=0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )
        .args([
            "tx",
            "transfer",
            "--from",
            "sender",
            "--to",
            "trnm1deadbeef",
            "--amount",
            "42",
            "--store",
            store.to_string_lossy().as_ref(),
        ])
        .output()
        .unwrap();
    assert!(out2.status.success());
    let s = String::from_utf8_lossy(&out2.stdout);
    assert!(s.contains("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
    assert!(s.contains("\"status\": \"pending\""));
}
