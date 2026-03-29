use super::*;

#[test]
fn wallet_import_hex_check() {
    let ok =
        ensure_hex_32_bytes("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
            .unwrap();
    assert_eq!(ok.len(), 64);

    let upper =
        ensure_hex_32_bytes("0XAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
            .unwrap();
    assert_eq!(upper, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");

    let wrapped = ensure_hex_32_bytes(
        " \u{2068}<\"0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\">\u{2069}\n",
    )
    .unwrap();
    assert_eq!(wrapped, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");

    let punctuated = ensure_hex_32_bytes(
        " (0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA,); ",
    )
    .unwrap();
    assert_eq!(punctuated, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");

    let smart_quoted = ensure_hex_32_bytes(
        "“0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA”",
    )
    .unwrap();
    assert_eq!(smart_quoted, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");

    let unicode_spaced = ensure_hex_32_bytes(
        "\u{00a0}\u{2003}0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\u{00a0}\u{2002}",
    )
    .unwrap();
    assert_eq!(unicode_spaced, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");

    let punctuated_sentence = ensure_hex_32_bytes(
        "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA?!.",
    )
    .unwrap();
    assert_eq!(punctuated_sentence, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");

    assert!(ensure_hex_32_bytes("0x1234").is_err());
}

#[test]
fn wallet_name_rejects_path_like_values() {
    for bad in [
        "",
        ".",
        "..",
        ".alice",
        "alice.",
        "-alice",
        "--help",
        "alice/bob",
        "alice\\bob",
        "alice:bob",
        "alice=debug",
        "alice|bob",
        "alice&bob",
        "alice$bob",
        "alice*bob",
        "alice?bob",
        "\"alice\"",
        "'alice'",
        "`alice`",
        "<alice>",
        "(alice)",
        "[alice]",
        "{alice}",
        "alice,",
        "alice;",
        "alice\n",
        "alice bob",
        " alice",
        "alice\t",
        "alice\u{00a0}bob",
        "alice\u{200b}bob",
        "alice\u{2060}bob",
        "alice\u{feff}bob",
        "alice\u{202e}bob",
        "alice\u{2066}bob",
        "alice\u{2069}bob",
        "alice\u{0007}bob",
    ] {
        let err = ensure_wallet_name(bad).unwrap_err();
        assert!(
            err.to_string().contains("invalid wallet name"),
            "unexpected error for {bad:?}: {err}"
        );
    }
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

#[test]
#[cfg(unix)]
fn write_key_sets_owner_only_permissions() {
    use std::os::unix::fs::PermissionsExt;

    let unique = format!(
        "trnm-cli-wallet-perm-test-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let store = std::env::temp_dir().join(unique);
    std::fs::create_dir_all(&store).unwrap();

    let path = write_key(
        &store,
        "alice",
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    )
    .unwrap();
    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "unexpected wallet file mode: {:o}", mode);

    let store_mode = std::fs::metadata(&store).unwrap().permissions().mode() & 0o777;
    assert_eq!(
        store_mode, 0o700,
        "unexpected wallet store mode: {:o}", store_mode
    );

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_dir(&store);
}

#[test]
#[cfg(unix)]
fn write_key_refuses_existing_dangling_symlink_wallet_path() {
    use std::os::unix::fs::symlink;

    let unique = format!(
        "trnm-cli-wallet-symlink-test-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let store = std::env::temp_dir().join(unique);
    std::fs::create_dir_all(&store).unwrap();
    let existing = wallet_file(&store, "alice");
    symlink(store.join("missing-target.key"), &existing).unwrap();

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
    assert!(std::fs::symlink_metadata(&existing).unwrap().file_type().is_symlink());

    let _ = std::fs::remove_file(&existing);
    let _ = std::fs::remove_dir(&store);
}

#[test]
#[cfg(unix)]
fn read_key_refuses_symlink_wallet_path() {
    use std::os::unix::fs::symlink;

    let unique = format!(
        "trnm-cli-wallet-read-symlink-test-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let store = std::env::temp_dir().join(unique);
    std::fs::create_dir_all(&store).unwrap();
    let target = store.join("target.key");
    std::fs::write(
        &target,
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n",
    )
    .unwrap();
    let existing = wallet_file(&store, "alice");
    symlink(&target, &existing).unwrap();

    let err = read_key(&store, "alice").unwrap_err();
    assert!(
        err.to_string().contains("refusing to follow non-regular wallet path"),
        "unexpected error: {err}"
    );
    assert!(std::fs::symlink_metadata(&existing).unwrap().file_type().is_symlink());

    let _ = std::fs::remove_file(&existing);
    let _ = std::fs::remove_file(&target);
    let _ = std::fs::remove_dir(&store);
}

#[test]
fn read_key_refuses_directory_wallet_path() {
    let unique = format!(
        "trnm-cli-wallet-read-dir-test-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let store = std::env::temp_dir().join(unique);
    std::fs::create_dir_all(&store).unwrap();
    let existing = wallet_file(&store, "alice");
    std::fs::create_dir(&existing).unwrap();

    let err = read_key(&store, "alice").unwrap_err();
    assert!(
        err.to_string().contains("not a regular file")
            || err.to_string().contains("refusing to follow non-regular wallet path"),
        "unexpected error: {err}"
    );

    let _ = std::fs::remove_dir(&existing);
    let _ = std::fs::remove_dir(&store);
}

#[test]
#[cfg(unix)]
fn read_key_refuses_group_or_world_accessible_wallet_file() {
    use std::os::unix::fs::PermissionsExt;

    let unique = format!(
        "trnm-cli-wallet-read-perm-test-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let store = std::env::temp_dir().join(unique);
    std::fs::create_dir_all(&store).unwrap();
    let existing = wallet_file(&store, "alice");
    std::fs::write(
        &existing,
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n",
    )
    .unwrap();
    std::fs::set_permissions(&existing, std::fs::Permissions::from_mode(0o644)).unwrap();

    let err = read_key(&store, "alice").unwrap_err();
    assert!(
        err.to_string().contains("has insecure permissions"),
        "unexpected error: {err}"
    );

    let _ = std::fs::remove_file(&existing);
    let _ = std::fs::remove_dir(&store);
}

#[test]
#[cfg(unix)]
fn write_key_refuses_symlink_wallet_store() {
    use std::os::unix::fs::symlink;

    let unique = format!(
        "trnm-cli-wallet-store-write-symlink-test-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let root = std::env::temp_dir().join(unique);
    let real_store = root.join("real-store");
    let symlink_store = root.join("symlink-store");
    std::fs::create_dir_all(&real_store).unwrap();
    symlink(&real_store, &symlink_store).unwrap();

    let err = write_key(
        &symlink_store,
        "alice",
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    )
    .unwrap_err();
    assert!(
        err.to_string().contains("refusing to write keys through non-regular wallet store path"),
        "unexpected error: {err}"
    );
    assert!(!wallet_file(&real_store, "alice").exists());

    let _ = std::fs::remove_file(&symlink_store);
    let _ = std::fs::remove_dir(&real_store);
    let _ = std::fs::remove_dir(&root);
}

#[test]
#[cfg(unix)]
fn read_key_refuses_symlink_wallet_store() {
    use std::os::unix::fs::symlink;

    let unique = format!(
        "trnm-cli-wallet-store-read-symlink-test-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let root = std::env::temp_dir().join(unique);
    let real_store = root.join("real-store");
    let symlink_store = root.join("symlink-store");
    std::fs::create_dir_all(&real_store).unwrap();
    std::fs::write(
        wallet_file(&real_store, "alice"),
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n",
    )
    .unwrap();
    symlink(&real_store, &symlink_store).unwrap();

    let err = read_key(&symlink_store, "alice").unwrap_err();
    assert!(
        err.to_string().contains("refusing to read keys through non-regular wallet store path"),
        "unexpected error: {err}"
    );

    let _ = std::fs::remove_file(wallet_file(&real_store, "alice"));
    let _ = std::fs::remove_file(&symlink_store);
    let _ = std::fs::remove_dir(&real_store);
    let _ = std::fs::remove_dir(&root);
}
