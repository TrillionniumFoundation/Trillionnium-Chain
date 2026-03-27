use super::*;

#[test]
fn wallet_import_hex_check() {
    let ok =
        ensure_hex_32_bytes("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
            .unwrap();
    assert_eq!(ok.len(), 64);
    assert!(ensure_hex_32_bytes("0x1234").is_err());
}

#[test]
fn write_key_refuses_to_overwrite_existing_wallet_file() {
    let unique = format!(
        "trnm-cli-wallet-test-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let store = std::env::temp_dir().join(unique);
    std::fs::create_dir_all(&store).unwrap();
    let existing = wallet_file(&store, "alice");
    std::fs::write(&existing, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n")
        .unwrap();

    let err = write_key(
        &store,
        "alice",
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    )
    .unwrap_err();
    assert!(
        err.to_string().contains("refusing to overwrite existing key"),
        "unexpected error: {err}"
    );
    assert_eq!(
        std::fs::read_to_string(&existing).unwrap(),
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
    );

    let _ = std::fs::remove_file(&existing);
    let _ = std::fs::remove_dir(&store);
}
