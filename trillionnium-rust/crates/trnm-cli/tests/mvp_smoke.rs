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
    let p = std::env::temp_dir().join(format!("trnm-cli-{label}-{ts}"));
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
    assert!(s.contains("submitted"));
}
