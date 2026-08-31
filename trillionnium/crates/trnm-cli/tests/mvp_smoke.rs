use std::{
    io::Write,
    path::PathBuf,
    process::{Command, Output, Stdio},
    time::{SystemTime, UNIX_EPOCH},
};

use ed25519_dalek::{Signature, VerifyingKey};

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

fn create_owner_only_dir_all(path: &std::path::Path) {
    std::fs::create_dir_all(path).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
}

fn tmp_dir(label: &str) -> PathBuf {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let temp_root = std::env::temp_dir()
        .canonicalize()
        .unwrap_or_else(|_| std::env::temp_dir());
    let p = temp_root.join(format!("trnm-cli-{label}-{ts}"));
    create_owner_only_dir_all(&p);
    p
}

fn import_wallet(store: &std::path::Path, name: &str, private_key: &str) -> Output {
    let mut child = Command::new(bin())
        .args([
            "wallet",
            "import",
            "--name",
            name,
            "--private-key-stdin",
            "--out",
            store.to_string_lossy().as_ref(),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let _ = child
        .stdin
        .take()
        .expect("piped wallet import stdin")
        .write_all(private_key.as_bytes());
    child.wait_with_output().unwrap()
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
fn smoke_wallet_import_accepts_wrapped_private_key_from_stdin() {
    let store = tmp_dir("wallet-import-wrapped");
    let pk = " \u{2068}<\"0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\">\u{2069}\n";
    let out = import_wallet(&store, "alice", pk);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(s.contains("wallet_name=alice"));
    assert!(s.contains("address=trnm1"));
    assert!(s.contains("public_key="));
}

#[test]
fn smoke_wallet_import_rejects_private_key_in_argv() {
    let store = tmp_dir("wallet-import-argv-rejected");
    let out = Command::new(bin())
        .args([
            "wallet",
            "import",
            "--name",
            "alice",
            "--private-key-hex",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "--out",
            store.to_string_lossy().as_ref(),
        ])
        .output()
        .unwrap();

    assert!(!out.status.success(), "argv private key must fail closed");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("--private-key-hex is disabled")
            && stderr.contains("shell history and process listings")
            && stderr.contains("development-only"),
        "unexpected stderr: {stderr}"
    );
    assert!(!store.join("alice.key").exists());
}

#[cfg(unix)]
#[test]
fn smoke_wallet_create_rejects_symlinked_ancestor_out_path() {
    use std::os::unix::fs::symlink;

    let root = tmp_dir("wallet-create-symlink-ancestor");
    let real_parent = root.join("real-parent");
    let linked_parent = root.join("linked-parent");
    create_owner_only_dir_all(&real_parent);
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
        stderr.contains("refusing non-canonical keystore path")
            || stderr.contains("must be an absolute normalized symlink-free path"),
        "unexpected stderr: {}",
        stderr
    );
    assert!(!real_parent.join("wallets").join("alice.key").exists());
}

#[cfg(unix)]
#[test]
fn smoke_wallet_import_rejects_symlinked_final_out_path() {
    use std::os::unix::fs::symlink;

    let root = tmp_dir("wallet-import-symlink-final-store");
    let real_store = root.join("real-store");
    let linked_store = root.join("linked-store");
    create_owner_only_dir_all(&real_store);
    symlink(&real_store, &linked_store).unwrap();

    let out = import_wallet(
        &linked_store,
        "alice",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    );

    assert!(
        !out.status.success(),
        "symlinked final keystore path should fail closed for wallet import"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("explicit wallet store")
            || stderr.contains(
                "is a symlink; refusing to write keys through non-regular wallet store path"
            ),
        "unexpected stderr: {}",
        stderr
    );
    assert!(!real_store.join("alice.key").exists());
}

#[test]
fn smoke_wallet_sign_rejects_multiline_message() {
    let store = tmp_dir("wallet-sign-message-guard");
    let pk = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let import = import_wallet(&store, "alice", pk);
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
    assert!(
        !out.status.success(),
        "multiline signer input should fail closed"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr
            .contains("sign message must be single-line printable text without control characters"),
        "unexpected stderr: {}",
        stderr
    );
}

#[test]
fn smoke_wallet_sign_rejects_bidi_control_message() {
    let store = tmp_dir("wallet-sign-bidi-guard");
    let pk = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let import = import_wallet(&store, "alice", pk);
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
        stderr
            .contains("sign message must be single-line printable text without control characters"),
        "unexpected stderr: {}",
        stderr
    );
}

#[test]
fn smoke_wallet_sign_accepts_wrapped_absolute_env_store() {
    let store = tmp_dir("wallet-sign-valid-wrapped-env-store");
    let pk = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let import = import_wallet(&store, "alice", pk);
    assert!(
        import.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&import.stderr)
    );

    let wrapped_store = format!(" \u{2068}({{[{}]}})\u{2069} ", store.display());
    let out = Command::new(bin())
        .args([
            "wallet",
            "sign",
            "--name",
            "alice",
            "--message",
            "approve tx",
        ])
        .env("TRNM_WALLET_STORE", wrapped_store)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "wrapped absolute env keystore path should stay usable for offline signing, stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("wallet_name=alice"),
        "unexpected stdout: {}",
        stdout
    );
    assert!(
        stdout.contains("preimage_domain=trnm.cli.wallet-sign.v1"),
        "unexpected stdout: {}",
        stdout
    );
    assert!(
        stdout.contains("preimage_sha256="),
        "unexpected stdout: {}",
        stdout
    );
    assert!(
        stdout.contains("signature="),
        "unexpected stdout: {}",
        stdout
    );
}

#[test]
fn smoke_wallet_sign_rejects_invalid_env_store_fallback() {
    let store = tmp_dir("wallet-sign-invalid-env-store");
    let pk = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let import = import_wallet(&store, "alice", pk);
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
            "approve tx",
        ])
        .env("TRNM_WALLET_STORE", "\u{2068}\"./wallets\"\u{2069}")
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "invalid env keystore fallback should fail closed"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("TRNM_WALLET_STORE is set but invalid")
            || stderr.contains("must be an absolute normalized symlink-free path"),
        "unexpected stderr: {}",
        stderr
    );
}

#[test]
fn smoke_wallet_sign_rejects_invalid_explicit_store_path() {
    for invalid_store in ["./wallets", "/"] {
        let out = Command::new(bin())
            .args([
                "wallet",
                "sign",
                "--name",
                "alice",
                "--message",
                "approve tx",
                "--store",
                invalid_store,
            ])
            .output()
            .unwrap();
        assert!(
            !out.status.success(),
            "invalid explicit keystore path should fail closed: {invalid_store:?}"
        );
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains("explicit wallet store")
                && stderr.contains("must be an absolute normalized symlink-free path"),
            "unexpected stderr for {invalid_store:?}: {}",
            stderr
        );
    }
}

#[test]
fn smoke_wallet_sign_rejects_unsafe_message_before_store_resolution() {
    let out = Command::new(bin())
        .args([
            "wallet",
            "sign",
            "--name",
            "alice",
            "--message",
            "approve=tx",
            "--store",
            "./wallets",
        ])
        .output()
        .unwrap();

    assert!(
        !out.status.success(),
        "unsafe signer input should fail closed before keystore resolution"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("wallet sign message must be single-line ASCII printable text")
            && !stderr.contains("explicit wallet store"),
        "unexpected stderr: {}",
        stderr
    );
}

#[test]
fn smoke_wallet_sign_rejects_explicit_store_with_trailing_separator() {
    let store = tmp_dir("wallet-sign-trailing-separator");
    let pk = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let import = import_wallet(&store, "alice", pk);
    assert!(
        import.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&import.stderr)
    );

    let trailing_store = format!("{}/", store.display());
    let out = Command::new(bin())
        .args([
            "wallet",
            "sign",
            "--name",
            "alice",
            "--message",
            "approve tx",
            "--store",
            trailing_store.as_str(),
        ])
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "trailing-separator explicit keystore path should fail closed"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("explicit wallet store")
            && stderr.contains("must be an absolute normalized symlink-free path"),
        "unexpected stderr: {}",
        stderr
    );
}

#[cfg(unix)]
#[test]
fn smoke_wallet_sign_rejects_explicit_store_with_symlinked_ancestor() {
    use std::os::unix::fs::symlink;

    let root = tmp_dir("wallet-sign-symlink-ancestor");
    let real_parent = root.join("real-parent");
    let linked_parent = root.join("linked-parent");
    let real_store = real_parent.join("wallets");
    create_owner_only_dir_all(&real_store);
    symlink(&real_parent, &linked_parent).unwrap();

    let pk = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let import = import_wallet(&real_store, "alice", pk);
    assert!(
        import.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&import.stderr)
    );

    let linked_store = linked_parent.join("wallets");
    let out = Command::new(bin())
        .args([
            "wallet",
            "sign",
            "--name",
            "alice",
            "--message",
            "approve tx",
            "--store",
            linked_store.to_string_lossy().as_ref(),
        ])
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "symlinked explicit keystore ancestor should fail closed"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("explicit wallet store")
            && stderr.contains("must be an absolute normalized symlink-free path"),
        "unexpected stderr: {}",
        stderr
    );
}

#[cfg(unix)]
#[test]
fn smoke_wallet_sign_rejects_explicit_store_with_symlinked_final_path() {
    use std::os::unix::fs::symlink;

    let root = tmp_dir("wallet-sign-symlink-final-store");
    let real_store = root.join("real-store");
    let linked_store = root.join("linked-store");
    create_owner_only_dir_all(&real_store);
    symlink(&real_store, &linked_store).unwrap();

    let pk = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let import = import_wallet(&real_store, "alice", pk);
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
            "approve tx",
            "--store",
            linked_store.to_string_lossy().as_ref(),
        ])
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "symlinked explicit wallet sign store should fail closed"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("explicit wallet store")
            && stderr.contains("must be an absolute normalized symlink-free path"),
        "unexpected stderr: {}",
        stderr
    );
}

#[test]
fn smoke_wallet_address_rejects_invalid_env_store_fallback() {
    let store = tmp_dir("wallet-address-invalid-env-store");
    let pk = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let import = import_wallet(&store, "alice", pk);
    assert!(
        import.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&import.stderr)
    );

    let out = Command::new(bin())
        .args(["wallet", "address", "--name", "alice"])
        .env("TRNM_WALLET_STORE", "\u{2068}\"./wallets\"\u{2069}")
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "invalid env keystore fallback should fail closed for wallet address"
    );

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("TRNM_WALLET_STORE is set but invalid")
            || stderr.contains("must be an absolute normalized symlink-free path"),
        "unexpected stderr: {}",
        stderr
    );
}

#[cfg(unix)]
#[test]
fn smoke_wallet_address_rejects_explicit_store_with_symlinked_final_path() {
    use std::os::unix::fs::symlink;

    let root = tmp_dir("wallet-address-symlink-final-store");
    let real_store = root.join("real-store");
    let linked_store = root.join("linked-store");
    create_owner_only_dir_all(&real_store);
    symlink(&real_store, &linked_store).unwrap();

    let pk = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let import = import_wallet(&real_store, "alice", pk);
    assert!(
        import.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&import.stderr)
    );

    let out = Command::new(bin())
        .args([
            "wallet",
            "address",
            "--name",
            "alice",
            "--store",
            linked_store.to_string_lossy().as_ref(),
        ])
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "symlinked explicit wallet address store should fail closed"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("explicit wallet store")
            && stderr.contains("must be an absolute normalized symlink-free path"),
        "unexpected stderr: {}",
        stderr
    );
}

#[test]
fn smoke_wallet_sign_rejects_edge_whitespace_non_ascii_or_delimiter_payloads() {
    let store = tmp_dir("wallet-sign-whitespace-guard");
    let pk = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let import = import_wallet(&store, "alice", pk);
    assert!(
        import.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&import.stderr)
    );

    for bad_message in [
        " approve tx",
        "approve tx ",
        "approve\u{00a0}tx",
        "approve\u{034f}tx",
        "approve=tx",
        "approve:tx",
        "approve;tx",
        "approve,tx",
        "approve|tx",
        "\"approve tx\"",
        "'approve tx'",
        "`approve tx`",
        "<approve tx>",
        "(approve tx)",
        "[approve tx]",
        "{approve tx}",
    ] {
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
            "ambiguous signer input should fail closed: {bad_message:?}"
        );
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains("must not start or end with whitespace")
                || stderr.contains("leading or trailing whitespace")
                || stderr.contains("ASCII printable text")
                || stderr.contains("single-line printable text without control characters")
                || stderr.contains("delimiter punctuation")
                || stderr.contains("wrapper punctuation"),
            "unexpected stderr for {bad_message:?}: {}",
            stderr
        );
    }
}

#[test]
fn smoke_wallet_sign_emits_domain_separated_ed25519_signature() {
    let store = tmp_dir("wallet-sign");
    let pk = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let import = import_wallet(&store, "alice", pk);
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
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(s.contains("wallet_name=alice"));
    assert!(s.contains(&format!("message={message}")));
    assert!(s.contains("preimage_domain=trnm.cli.wallet-sign.v1"));
    assert!(s.contains("signed_bytes=domain-framed-utf8-v1"));
    assert!(s.contains("preimage_len="));
    assert!(s.contains("preimage_sha256="));
    assert!(!s.contains("message_sha256="));
    assert!(s.contains("signature_scheme=ed25519"));
    assert!(s.contains("signed_bytes=domain-framed-utf8-v1"));
    assert!(s.contains("public_key="));
    let signature = s
        .lines()
        .find_map(|line| line.strip_prefix("signature="))
        .expect("wallet sign signature line");
    assert_eq!(signature.len(), 128, "Ed25519 signature is 64 bytes");
    assert!(signature.chars().all(|c| c.is_ascii_hexdigit()));

    let public_key = s
        .lines()
        .find_map(|line| line.strip_prefix("public_key="))
        .expect("wallet sign public key line");
    let public_key_bytes: [u8; 32] = hex::decode(public_key).unwrap().try_into().unwrap();
    let signature_bytes: [u8; 64] = hex::decode(signature).unwrap().try_into().unwrap();
    let verifying_key = VerifyingKey::from_bytes(&public_key_bytes).unwrap();
    let signature = Signature::from_bytes(&signature_bytes);
    let domain = b"trnm.cli.wallet-sign.v1";
    let mut preimage = Vec::new();
    preimage.extend_from_slice(&(domain.len() as u32).to_be_bytes());
    preimage.extend_from_slice(domain);
    preimage.extend_from_slice(&(message.len() as u32).to_be_bytes());
    preimage.extend_from_slice(message.as_bytes());
    verifying_key.verify_strict(&preimage, &signature).unwrap();
    assert!(
        verifying_key
            .verify_strict(message.as_bytes(), &signature)
            .is_err(),
        "CLI output must not be an unframed raw-text signature"
    );
}

#[test]
fn smoke_query_balance_without_backend_fails_closed() {
    let store = tmp_dir("query-balance");
    let pk = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let out = import_wallet(&store, "alice", pk);
    assert!(out.status.success());

    let out2 = Command::new(bin())
        .env_remove("TRNM_QUERY_BALANCE_CMD")
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
    assert!(!out2.status.success(), "missing balance backend must fail");
    assert!(out2.stdout.is_empty(), "must not emit a synthetic balance");
    let stderr = String::from_utf8_lossy(&out2.stderr);
    assert!(
        stderr.contains("no real endpoint/backend is configured")
            && stderr.contains("synthetic balances are disabled")
            && stderr.contains("TRNM_QUERY_BALANCE_CMD"),
        "unexpected stderr: {stderr}"
    );
}

#[test]
fn smoke_query_balance_development_adapter_returns_only_adapter_value() {
    let out = Command::new(bin())
        .env(
            "TRNM_QUERY_BALANCE_CMD",
            r#"printf '%s' '{"address":"trnm1adapter","balance":"42","denom":"trnm"}'"#,
        )
        .args([
            "query",
            "balance",
            "--address",
            "trnm1adapter",
            "--denom",
            "trnm",
        ])
        .output()
        .unwrap();

    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("\"balance\": \"42\""));
    assert!(!stdout.contains("synthetic"));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("command-template adapter") && stderr.contains("development-only"),
        "adapter use must be explicitly labeled: {stderr}"
    );
}

#[test]
fn smoke_query_balance_rejects_exit_zero_malformed_adapter_output() {
    for (label, command) in [
        ("empty", "true"),
        ("scalar-without-identity", "printf '%s' '42'"),
        ("arbitrary", "printf '%s' 'request completed successfully'"),
        (
            "missing-address",
            r#"printf '%s' '{"balance":"42","denom":"trnm"}'"#,
        ),
        (
            "missing-denom",
            r#"printf '%s' '{"address":"trnm1adapter","balance":"42"}'"#,
        ),
        (
            "mismatched-address",
            r#"printf '%s' '{"address":"trnm1other","balance":"42","denom":"trnm"}'"#,
        ),
        (
            "mismatched-denom",
            r#"printf '%s' '{"address":"trnm1adapter","balance":"42","denom":"utrnm"}'"#,
        ),
        (
            "noncanonical-amount",
            r#"printf '%s' '{"address":"trnm1adapter","balance":"01","denom":"trnm"}'"#,
        ),
    ] {
        let out = Command::new(bin())
            .env("TRNM_QUERY_BALANCE_CMD", command)
            .args([
                "query",
                "balance",
                "--address",
                "trnm1adapter",
                "--denom",
                "trnm",
            ])
            .output()
            .unwrap();

        assert!(
            !out.status.success(),
            "malformed adapter case {label} must fail closed"
        );
        assert!(
            out.stdout.is_empty(),
            "malformed adapter case {label} must not emit a balance"
        );
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains("balance query response")
                || stderr.contains("no explicit balance amount"),
            "unexpected stderr for {label}: {stderr}"
        );
    }
}

#[test]
fn smoke_tx_submit_consumption_receipt_without_backend_fails_closed() {
    let root = tmp_dir("tx-query-fallback");
    let tx_file = root.join("txs.json");
    let receipt_path = root.join("receipt.json");
    std::fs::write(
        &receipt_path,
        r#"{
            "task_id":9999991,
            "consumer_id":"worker_readiness",
            "output_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "billing_window_id":"bw-smoke",
            "consumer_nonce":1
        }"#,
    )
    .unwrap();

    let submit = Command::new(bin())
        .env("TRNM_RPC_TX_FILE", tx_file.to_string_lossy().as_ref())
        .env_remove("TRNM_TX_SUBMIT_SETTLEMENT_RECEIPT_CMD")
        .env_remove("TRNM_TX_SUBMIT_CONSUMPTION_RECEIPT_CMD")
        .args([
            "tx",
            "submit-consumption-receipt",
            "--receipt-json",
            receipt_path.to_string_lossy().as_ref(),
        ])
        .output()
        .unwrap();
    assert!(!submit.status.success(), "missing tx backend must fail");
    assert!(
        submit.stdout.is_empty(),
        "must not emit a synthetic tx hash"
    );
    let stderr = String::from_utf8_lossy(&submit.stderr);
    assert!(
        stderr.contains("no real endpoint/backend is configured")
            && stderr.contains("synthetic pending transaction hashes are disabled"),
        "unexpected stderr: {stderr}"
    );
    assert!(
        !tx_file.exists(),
        "a missing backend must not persist synthetic pending state"
    );
}

#[test]
fn smoke_tx_query_local_pending_state_requires_exact_non_authoritative_opt_in() {
    let root = tmp_dir("tx-query-local-opt-in");
    let tx_file = root.join("txs.json");
    let tx_hash = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    std::fs::write(
        &tx_file,
        format!(
            r#"{{"{tx_hash}":{{"tx_hash":"{tx_hash}","status":"pending","status_source":"development_only_local_pending_cache","authoritative":false,"production_ready":false}}}}"#
        ),
    )
    .unwrap();

    let disabled = Command::new(bin())
        .env("TRNM_RPC_TX_FILE", &tx_file)
        .env("TRNM_TX_QUERY_CMD", "false")
        .env_remove("TRNM_CLI_DEVELOPMENT_ONLY_LOCAL_TX_STATE")
        .args(["tx", "query", tx_hash])
        .output()
        .unwrap();
    assert!(
        !disabled.status.success(),
        "local pending state must not replace a required backend without explicit opt-in"
    );
    assert!(disabled.stdout.is_empty());

    let malformed = Command::new(bin())
        .env("TRNM_RPC_TX_FILE", &tx_file)
        .env_remove("TRNM_TX_QUERY_CMD")
        .env("TRNM_CLI_DEVELOPMENT_ONLY_LOCAL_TX_STATE", " 1 ")
        .args(["tx", "query", tx_hash])
        .output()
        .unwrap();
    assert!(!malformed.status.success());
    assert!(malformed.stdout.is_empty());
    assert!(String::from_utf8_lossy(&malformed.stderr)
        .contains("TRNM_CLI_DEVELOPMENT_ONLY_LOCAL_TX_STATE must be exactly 1"));

    let enabled = Command::new(bin())
        .env("TRNM_RPC_TX_FILE", &tx_file)
        .env_remove("TRNM_TX_QUERY_CMD")
        .env("TRNM_CLI_DEVELOPMENT_ONLY_LOCAL_TX_STATE", "1")
        .args(["tx", "query", tx_hash])
        .output()
        .unwrap();
    assert!(
        enabled.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&enabled.stderr)
    );
    assert!(String::from_utf8_lossy(&enabled.stdout).contains("status=pending"));
    let stderr = String::from_utf8_lossy(&enabled.stderr);
    assert!(
        stderr.contains("source=development_only_local_pending_cache")
            && stderr.contains("authoritative=false")
            && stderr.contains("production_ready=false")
            && stderr.contains("not node inclusion or finality evidence"),
        "local status warning must be explicit: {stderr}"
    );
}

#[test]
fn smoke_tx_transfer_template_path() {
    let store = tmp_dir("tx-transfer");
    let pk = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    let out = import_wallet(&store, "sender", pk);
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

#[test]
fn smoke_tx_transfer_without_backend_fails_closed() {
    let store = tmp_dir("tx-transfer-no-backend");
    let pk = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let import = import_wallet(&store, "sender", pk);
    assert!(import.status.success());

    let out = Command::new(bin())
        .env_remove("TRNM_TX_TRANSFER_CMD")
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

    assert!(!out.status.success(), "missing transfer backend must fail");
    assert!(out.stdout.is_empty(), "must not emit a synthetic tx hash");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("no real endpoint/backend is configured")
            && stderr.contains("synthetic pending transaction hashes are disabled")
            && stderr.contains("TRNM_TX_TRANSFER_CMD"),
        "unexpected stderr: {stderr}"
    );
}

#[test]
fn smoke_tx_transfer_rejects_invalid_env_store_fallback() {
    let store = tmp_dir("tx-transfer-invalid-env-store");
    let pk = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    let import = import_wallet(&store, "sender", pk);
    assert!(import.status.success());

    let out = Command::new(bin())
        .env(
            "TRNM_TX_TRANSFER_CMD",
            "echo tx_hash=0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )
        .env("TRNM_WALLET_STORE", "\u{2068}\"./wallets\"\u{2069}")
        .args([
            "tx",
            "transfer",
            "--from",
            "sender",
            "--to",
            "trnm1deadbeef",
            "--amount",
            "42",
        ])
        .output()
        .unwrap();

    assert!(
        !out.status.success(),
        "invalid env keystore fallback should fail closed for tx transfer"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains(
            "TRNM_WALLET_STORE is set but invalid; refusing ambiguous keystore path fallback"
        ) || stderr.contains("must be an absolute normalized symlink-free path"),
        "unexpected stderr: {stderr}"
    );
}
