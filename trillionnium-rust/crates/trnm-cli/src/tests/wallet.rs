use super::*;
use super::ENV_LOCK;

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

    let bidi_wrapped = ensure_hex_32_bytes(
        "\u{061c}\u{200e}\u{200f}0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\u{200f}\u{200e}\u{061c}",
    )
    .unwrap();
    assert_eq!(bidi_wrapped, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");

    let punctuated_sentence = ensure_hex_32_bytes(
        "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA?!.",
    )
    .unwrap();
    assert_eq!(punctuated_sentence, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");

    let cjk_punctuated = ensure_hex_32_bytes(
        "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA。！？",
    )
    .unwrap();
    assert_eq!(cjk_punctuated, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");

    let fullwidth_dot_punctuated = ensure_hex_32_bytes(
        "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA．﹒․",
    )
    .unwrap();
    assert_eq!(fullwidth_dot_punctuated, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");

    let fullwidth_wrapped = ensure_hex_32_bytes(
        "（《0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA》）；",
    )
    .unwrap();
    assert_eq!(fullwidth_wrapped, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");

    let corner_quoted = ensure_hex_32_bytes(
        "｢0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA｣",
    )
    .unwrap();
    assert_eq!(corner_quoted, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");

    let guillemet_wrapped = ensure_hex_32_bytes(
        "«0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA»",
    )
    .unwrap();
    assert_eq!(guillemet_wrapped, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");

    let lenticular_wrapped = ensure_hex_32_bytes(
        "【0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA】",
    )
    .unwrap();
    assert_eq!(lenticular_wrapped, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");

    let vertical_wrapped = ensure_hex_32_bytes(
        "〝0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA〞",
    )
    .unwrap();
    assert_eq!(vertical_wrapped, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");

    let vertical_single_sided = ensure_hex_32_bytes(
        "〟0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA〟",
    )
    .unwrap();
    assert_eq!(vertical_single_sided, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");

    let corner_quoted = ensure_hex_32_bytes(
        "｢0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA｣",
    )
    .unwrap();
    assert_eq!(corner_quoted, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");

    assert!(ensure_hex_32_bytes("0x1234").is_err());
}

#[test]
fn normalize_wallet_store_env_trims_shell_wrapped_quotes() {
    assert_eq!(
        normalize_wallet_store_env("  \"/tmp/trnm-wallets\"  "),
        Some("/tmp/trnm-wallets")
    );
    assert_eq!(
        normalize_wallet_store_env("' /tmp/trnm-wallets '") ,
        Some("/tmp/trnm-wallets")
    );
    assert_eq!(
        normalize_wallet_store_env("`\"/tmp/trnm-wallets\"`") ,
        Some("/tmp/trnm-wallets")
    );
    assert_eq!(
        normalize_wallet_store_env(" “《/tmp/trnm-wallets》” "),
        Some("/tmp/trnm-wallets")
    );
    assert_eq!(
        normalize_wallet_store_env(" <\"/tmp/trnm-wallets\"> "),
        Some("/tmp/trnm-wallets")
    );
    assert_eq!(
        normalize_wallet_store_env(" ＜《/tmp/trnm-wallets》＞ "),
        Some("/tmp/trnm-wallets")
    );
    assert_eq!(
        normalize_wallet_store_env("【『 /tmp/trnm-wallets 』】"),
        Some("/tmp/trnm-wallets")
    );
    assert_eq!(
        normalize_wallet_store_env("〚〖〔 /tmp/trnm-wallets 〕〗〛"),
        Some("/tmp/trnm-wallets")
    );
    assert_eq!(
        normalize_wallet_store_env("〝/tmp/trnm-wallets〞"),
        Some("/tmp/trnm-wallets")
    );
    assert_eq!(
        normalize_wallet_store_env("〟/tmp/trnm-wallets〟"),
        Some("/tmp/trnm-wallets")
    );
    assert_eq!(
        normalize_wallet_store_env("\u{2068} \"/tmp/trnm-wallets\" \u{2069}"),
        Some("/tmp/trnm-wallets")
    );
    assert_eq!(
        normalize_wallet_store_env("\u{200e}\u{200f}\u{061c}《/tmp/trnm-wallets》\u{200b}"),
        Some("/tmp/trnm-wallets")
    );
    assert_eq!(
        normalize_wallet_store_env("\u{feff}《/tmp/trnm-wallets》\u{200b}"),
        Some("/tmp/trnm-wallets")
    );
    assert_eq!(normalize_wallet_store_env("\u{200e}\u{200f}\u{061c}"), None);
    assert_eq!(
        normalize_wallet_store_env("\u{00ad}\u{180e}《/tmp/trnm-wallets》\u{180e}\u{00ad}"),
        Some("/tmp/trnm-wallets")
    );
    assert_eq!(
        normalize_wallet_store_env("\u{200e}\"/tmp/trnm-wallets\"\u{200f}"),
        Some("/tmp/trnm-wallets")
    );
    assert_eq!(
        normalize_wallet_store_env(" \"/tmp/trnm-wallets  "),
        Some("/tmp/trnm-wallets")
    );
    assert_eq!(
        normalize_wallet_store_env("  /tmp/trnm-wallets\" "),
        Some("/tmp/trnm-wallets")
    );
    assert_eq!(
        normalize_wallet_store_env(" ‘/tmp/trnm-wallets "),
        Some("/tmp/trnm-wallets")
    );
    assert_eq!(
        normalize_wallet_store_env(" /tmp/trnm-wallets’ "),
        Some("/tmp/trnm-wallets")
    );
    assert_eq!(
        normalize_wallet_store_env(" 《/tmp/trnm-wallets "),
        Some("/tmp/trnm-wallets")
    );
    assert_eq!(
        normalize_wallet_store_env(" /tmp/trnm-wallets》 "),
        Some("/tmp/trnm-wallets")
    );
    assert_eq!(
        normalize_wallet_store_env(" 「/tmp/trnm-wallets "),
        Some("/tmp/trnm-wallets")
    );
    assert_eq!(
        normalize_wallet_store_env(" /tmp/trnm-wallets」 "),
        Some("/tmp/trnm-wallets")
    );
    assert_eq!(
        normalize_wallet_store_env(" (/tmp/trnm-wallets "),
        Some("/tmp/trnm-wallets")
    );
    assert_eq!(
        normalize_wallet_store_env(" /tmp/trnm-wallets] "),
        Some("/tmp/trnm-wallets")
    );
    assert_eq!(
        normalize_wallet_store_env(" ＜/tmp/trnm-wallets "),
        Some("/tmp/trnm-wallets")
    );
    assert_eq!(
        normalize_wallet_store_env(" /tmp/trnm-wallets】 "),
        Some("/tmp/trnm-wallets")
    );
    assert_eq!(normalize_wallet_store_env("   \"\"   "), None);
    assert_eq!(normalize_wallet_store_env("  “”  "), None);
    assert_eq!(normalize_wallet_store_env("\u{2068}\u{2069}"), None);
    assert_eq!(normalize_wallet_store_env("/tmp/trnm wallets"), None);
    assert_eq!(normalize_wallet_store_env("/tmp/trnm\u{200b}-wallets"), None);
    assert_eq!(normalize_wallet_store_env("/tmp/trnm\u{202e}wallets"), None);
}

#[test]
fn default_wallet_store_ignores_curdir_or_parent_segments_from_env() {
    let _guard = ENV_LOCK.lock().unwrap();
    let original_store = std::env::var_os("TRNM_WALLET_STORE");
    let original_home = std::env::var_os("HOME");
    let home = std::env::temp_dir().join(format!(
        "trnm-cli-wallet-home-test-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&home).unwrap();
    std::env::set_var("HOME", &home);

    std::env::set_var("TRNM_WALLET_STORE", "./wallets");
    assert_eq!(default_wallet_store(), home.join(".trnm").join("wallets"));

    std::env::set_var("TRNM_WALLET_STORE", "../wallets");
    assert_eq!(default_wallet_store(), home.join(".trnm").join("wallets"));

    std::env::set_var("TRNM_WALLET_STORE", "wallets");
    assert_eq!(default_wallet_store(), home.join(".trnm").join("wallets"));

    std::env::set_var("TRNM_WALLET_STORE", "nested/wallets");
    assert_eq!(default_wallet_store(), home.join(".trnm").join("wallets"));

    std::env::set_var("TRNM_WALLET_STORE", "~/wallets");
    assert_eq!(default_wallet_store(), home.join(".trnm").join("wallets"));

    std::env::set_var("TRNM_WALLET_STORE", "~/.trnm/wallets");
    assert_eq!(default_wallet_store(), home.join(".trnm").join("wallets"));

    std::env::set_var("TRNM_WALLET_STORE", "/tmp/trnm/../wallets");
    assert_eq!(default_wallet_store(), home.join(".trnm").join("wallets"));

    std::env::set_var("TRNM_WALLET_STORE", "/tmp/trnm/./wallets");
    assert_eq!(default_wallet_store(), home.join(".trnm").join("wallets"));

    std::env::set_var("TRNM_WALLET_STORE", "/tmp//trnm-wallets");
    assert_eq!(default_wallet_store(), home.join(".trnm").join("wallets"));

    std::env::set_var("TRNM_WALLET_STORE", "//tmp/trnm-wallets");
    assert_eq!(default_wallet_store(), home.join(".trnm").join("wallets"));

    for wrapped_root in ["/", " / ", "'/'", "《/》", "\u{2068}/\u{2069}", "＜/＞"] {
        std::env::set_var("TRNM_WALLET_STORE", wrapped_root);
        assert_eq!(
            default_wallet_store(),
            home.join(".trnm").join("wallets"),
            "wrapped root path should fail closed: {wrapped_root:?}"
        );
    }

    std::env::set_var("TRNM_WALLET_STORE", " /tmp/trnm-wallets ");
    assert_eq!(default_wallet_store(), std::path::PathBuf::from("/tmp/trnm-wallets"));

    match original_store {
        Some(value) => std::env::set_var("TRNM_WALLET_STORE", value),
        None => std::env::remove_var("TRNM_WALLET_STORE"),
    }
    match original_home {
        Some(value) => std::env::set_var("HOME", value),
        None => std::env::remove_var("HOME"),
    }
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn default_wallet_store_rejects_symlinked_ancestor_from_env() {
    let _guard = ENV_LOCK.lock().unwrap();
    let original_store = std::env::var_os("TRNM_WALLET_STORE");
    let original_home = std::env::var_os("HOME");
    let home = std::env::temp_dir().join(format!(
        "trnm-cli-wallet-env-symlink-home-test-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&home).unwrap();
    std::env::set_var("HOME", &home);

    let root = std::env::temp_dir().join(format!(
        "trnm-cli-wallet-env-symlink-root-test-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let real_parent = root.join("real-parent");
    let linked_parent = root.join("linked-parent");
    std::fs::create_dir_all(&real_parent).unwrap();
    std::os::unix::fs::symlink(&real_parent, &linked_parent).unwrap();

    std::env::set_var("TRNM_WALLET_STORE", linked_parent.join("wallets"));
    assert_eq!(default_wallet_store(), home.join(".trnm").join("wallets"));

    let _ = std::fs::remove_file(&linked_parent);
    let _ = std::fs::remove_dir_all(&real_parent);
    let _ = std::fs::remove_dir_all(&root);
    let _ = std::fs::remove_dir_all(&home);
    match original_store {
        Some(v) => std::env::set_var("TRNM_WALLET_STORE", v),
        None => std::env::remove_var("TRNM_WALLET_STORE"),
    }
    match original_home {
        Some(v) => std::env::set_var("HOME", v),
        None => std::env::remove_var("HOME"),
    }
}

#[test]
fn default_wallet_store_falls_back_to_absolute_cwd_when_home_missing_or_relative() {
    let _guard = ENV_LOCK.lock().unwrap();
    let original_store = std::env::var_os("TRNM_WALLET_STORE");
    let original_home = std::env::var_os("HOME");
    std::env::remove_var("TRNM_WALLET_STORE");

    let cwd = std::env::current_dir().unwrap();

    std::env::remove_var("HOME");
    assert_eq!(default_wallet_store(), cwd.join(".trnm").join("wallets"));

    std::env::set_var("HOME", "./relative-home");
    assert_eq!(default_wallet_store(), cwd.join(".trnm").join("wallets"));

    match original_store {
        Some(value) => std::env::set_var("TRNM_WALLET_STORE", value),
        None => std::env::remove_var("TRNM_WALLET_STORE"),
    }
    match original_home {
        Some(value) => std::env::set_var("HOME", value),
        None => std::env::remove_var("HOME"),
    }
}

#[test]
fn default_wallet_store_rejects_unsafe_absolute_cwd_fallback() {
    let _guard = ENV_LOCK.lock().unwrap();
    let original_store = std::env::var_os("TRNM_WALLET_STORE");
    let original_home = std::env::var_os("HOME");
    let original_cwd = std::env::current_dir().unwrap();

    let unique = format!(
        "trnm cli cwd fallback test {} {}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let unsafe_cwd = std::env::temp_dir().join(unique);
    std::fs::create_dir_all(&unsafe_cwd).unwrap();

    std::env::remove_var("TRNM_WALLET_STORE");
    std::env::remove_var("HOME");
    std::env::set_current_dir(&unsafe_cwd).unwrap();

    assert_eq!(
        default_wallet_store(),
        std::path::PathBuf::from("/").join(".trnm").join("wallets")
    );

    std::env::set_current_dir(&original_cwd).unwrap();
    match original_store {
        Some(value) => std::env::set_var("TRNM_WALLET_STORE", value),
        None => std::env::remove_var("TRNM_WALLET_STORE"),
    }
    match original_home {
        Some(value) => std::env::set_var("HOME", value),
        None => std::env::remove_var("HOME"),
    }
    let _ = std::fs::remove_dir_all(&unsafe_cwd);
}

#[test]
fn explicit_wallet_store_path_must_be_absolute_and_normalized() {
    let write_err = write_key(
        std::path::Path::new("./wallets"),
        "alice",
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    )
    .unwrap_err();
    assert!(
        write_err
            .to_string()
            .contains("must be an absolute normalized path"),
        "unexpected error: {write_err}"
    );

    let read_err = read_key(std::path::Path::new("/tmp/trnm/../wallets"), "alice").unwrap_err();
    assert!(
        read_err
            .to_string()
            .contains("must be an absolute normalized path"),
        "unexpected error: {read_err}"
    );

    let spaced_write_err = write_key(
        std::path::Path::new("/tmp/trnm wallets"),
        "alice",
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    )
    .unwrap_err();
    assert!(
        spaced_write_err
            .to_string()
            .contains("must be an absolute normalized path"),
        "unexpected error: {spaced_write_err}"
    );

    let hidden_read_err =
        read_key(std::path::Path::new("/tmp/trnm\u{200b}wallets"), "alice").unwrap_err();
    assert!(
        hidden_read_err
            .to_string()
            .contains("must be an absolute normalized path"),
        "unexpected error: {hidden_read_err}"
    );

    let bidi_write_err = write_key(
        std::path::Path::new("/tmp/trnm\u{202e}wallets"),
        "alice",
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    )
    .unwrap_err();
    assert!(
        bidi_write_err
            .to_string()
            .contains("must be an absolute normalized path"),
        "unexpected error: {bidi_write_err}"
    );

    let root_write_err = write_key(
        std::path::Path::new("/"),
        "alice",
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    )
    .unwrap_err();
    assert!(
        root_write_err
            .to_string()
            .contains("must be an absolute normalized path"),
        "unexpected error: {root_write_err}"
    );

    let root_read_err = read_key(std::path::Path::new("/"), "alice").unwrap_err();
    assert!(
        root_read_err
            .to_string()
            .contains("must be an absolute normalized path"),
        "unexpected error: {root_read_err}"
    );

    let wrapped_quote_err = write_key(
        std::path::Path::new("/tmp/《trnm-wallets》"),
        "alice",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    )
    .unwrap_err();
    assert!(
        wrapped_quote_err
            .to_string()
            .contains("must be an absolute normalized path"),
        "unexpected error: {wrapped_quote_err}"
    );

    let wrapped_bracket_err = read_key(std::path::Path::new("/tmp/【trnm-wallets】"), "alice")
        .unwrap_err();
    assert!(
        wrapped_bracket_err
            .to_string()
            .contains("must be an absolute normalized path"),
        "unexpected error: {wrapped_bracket_err}"
    );

    let soft_hyphen_err = write_key(
        std::path::Path::new("/tmp/trnm\u{00ad}wallets"),
        "alice",
        "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    )
    .unwrap_err();
    assert!(
        soft_hyphen_err
            .to_string()
            .contains("must be an absolute normalized path"),
        "unexpected error: {soft_hyphen_err}"
    );

    let mongolian_separator_err = read_key(std::path::Path::new("/tmp/trnm\u{180e}wallets"), "alice")
        .unwrap_err();
    assert!(
        mongolian_separator_err
            .to_string()
            .contains("must be an absolute normalized path"),
        "unexpected error: {mongolian_separator_err}"
    );
}

#[test]
fn ensure_safe_sign_message_rejects_ambiguous_whitespace_and_bidi_controls() {
    let leading_err = ensure_safe_sign_message(" approve tx").unwrap_err();
    assert!(
        leading_err
            .to_string()
            .contains("leading or trailing whitespace"),
        "unexpected error: {leading_err}"
    );

    let nbsp_err = ensure_safe_sign_message("approve\u{00a0}tx").unwrap_err();
    assert!(
        nbsp_err
            .to_string()
            .contains("control or bidi override characters"),
        "unexpected error: {nbsp_err}"
    );

    let bidi_err = ensure_safe_sign_message("approve\u{202e}tx").unwrap_err();
    assert!(
        bidi_err
            .to_string()
            .contains("control or bidi override characters"),
        "unexpected error: {bidi_err}"
    );

    ensure_safe_sign_message("approve tx").unwrap();
}

#[test]
fn wallet_name_rejects_path_like_values() {
    for bad in [
        "",
        ".",
        "..",
        ".alice",
        "alice.",
        "alice．",
        "alice。",
        "alice｡",
        "alice﹒",
        "alice․",
        "-alice",
        "－alice",
        "—alice",
        "–alice",
        "alice—bob",
        "alice－bob",
        "alice﹣bob",
        "--help",
        "alice/bob",
        "alice\\bob",
        "alice∕bob",
        "alice⁄bob",
        "alice／bob",
        "alice＼bob",
        "alice⧵bob",
        "alice⟋bob",
        "alice⟍bob",
        "alice:bob",
        "alice：bob",
        "alice=debug",
        "alice＝debug",
        "alice|bob",
        "alice｜bob",
        "alice&bob",
        "alice＆bob",
        "alice!",
        "alice！",
        "alice$bob",
        "alice*bob",
        "alice?bob",
        "alice，",
        "alice；",
        "\"alice\"",
        "'alice'",
        "`alice`",
        "<alice>",
        "(alice)",
        "[alice]",
        "{alice}",
        "“alice”",
        "‘alice’",
        "「alice」",
        "『alice』",
        "《alice》",
        "〈alice〉",
        "｢alice｣",
        "（alice）",
        "［alice］",
        "｛alice｝",
        "＜alice＞",
        "【alice】",
        "〔alice〕",
        "〖alice〗",
        "〘alice〙",
        "〚alice〛",
        "alice,",
        "alice;",
        "alice\n",
        "alice bob",
        " alice",
        "alice\t",
        "alice\u{00a0}bob",
        "alice\u{061c}bob",
        "alice\u{200b}bob",
        "alice\u{200e}bob",
        "alice\u{200f}bob",
        "alice\u{2060}bob",
        "alice\u{feff}bob",
        "alice\u{202e}bob",
        "alice\u{2066}bob",
        "alice\u{2069}bob",
        "alice\u{0007}bob",
        "con",
        "PRN",
        "aux",
        "nul",
        "com1",
        "CoM9",
        "lpt1",
        "LPT9",
    ] {
        let err = ensure_wallet_name(bad).unwrap_err();
        assert!(
            err.to_string().contains("invalid wallet name"),
            "unexpected error for {bad:?}: {err}"
        );
    }
}

#[test]
fn write_key_rejects_non_normalized_private_key_hex() {
    let unique = format!(
        "trnm-cli-wallet-invalid-hex-test-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let store = std::env::temp_dir().join(unique);
    std::fs::create_dir_all(&store).unwrap();

    let err = write_key(&store, "alice", "0x1234").unwrap_err();
    assert!(
        err.to_string()
            .contains("private key hex must be 32 bytes (64 hex chars)"),
        "unexpected error: {err}"
    );
    assert!(!wallet_file(&store, "alice").exists());

    let _ = std::fs::remove_dir_all(&store);
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
fn read_key_refuses_group_or_world_accessible_wallet_store() {
    use std::os::unix::fs::PermissionsExt;

    let unique = format!(
        "trnm-cli-wallet-store-read-perm-test-{}-{}",
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
    std::fs::set_permissions(&store, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::set_permissions(&existing, std::fs::Permissions::from_mode(0o600)).unwrap();

    let err = read_key(&store, "alice").unwrap_err();
    assert!(
        err.to_string().contains("wallet store") && err.to_string().contains("has insecure permissions"),
        "unexpected error: {err}"
    );

    let _ = std::fs::set_permissions(&store, std::fs::Permissions::from_mode(0o700));
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
fn write_key_refuses_group_or_world_accessible_wallet_store() {
    use std::os::unix::fs::PermissionsExt;

    let unique = format!(
        "trnm-cli-wallet-store-write-perm-test-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let store = std::env::temp_dir().join(unique);
    std::fs::create_dir_all(&store).unwrap();
    std::fs::set_permissions(&store, std::fs::Permissions::from_mode(0o755)).unwrap();

    let err = write_key(
        &store,
        "alice",
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    )
    .unwrap_err();
    assert!(
        err.to_string().contains("wallet store") && err.to_string().contains("has insecure permissions"),
        "unexpected error: {err}"
    );
    assert!(!wallet_file(&store, "alice").exists());

    let _ = std::fs::set_permissions(&store, std::fs::Permissions::from_mode(0o700));
    let _ = std::fs::remove_dir(&store);
}

#[test]
fn write_key_refuses_non_directory_wallet_store() {
    let unique = format!(
        "trnm-cli-wallet-store-write-file-test-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let root = std::env::temp_dir().join(unique);
    std::fs::create_dir_all(&root).unwrap();
    let file_store = root.join("wallet-store-file");
    std::fs::write(&file_store, "not a directory\n").unwrap();

    let err = write_key(
        &file_store,
        "alice",
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    )
    .unwrap_err();
    assert!(
        err.to_string().contains("wallet store")
            && err.to_string().contains("is not a directory")
            && err.to_string().contains("refusing to write keys through non-regular wallet store path"),
        "unexpected error: {err}"
    );
    assert!(!wallet_file(&file_store, "alice").exists());

    let _ = std::fs::remove_file(&file_store);
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

#[test]
#[cfg(unix)]
fn wallet_store_rejects_symlinked_ancestor_path_components() {
    use std::os::unix::fs::symlink;

    let unique = format!(
        "trnm-cli-wallet-ancestor-symlink-test-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let root = std::env::temp_dir().join(unique);
    let real_parent = root.join("real-parent");
    let linked_parent = root.join("linked-parent");
    std::fs::create_dir_all(&real_parent).unwrap();
    symlink(&real_parent, &linked_parent).unwrap();

    let store = linked_parent.join("wallets");
    let write_err = write_key(
        &store,
        "alice",
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    )
    .unwrap_err();
    assert!(
        write_err
            .to_string()
            .contains("traverses symlinked ancestor"),
        "unexpected error: {write_err}"
    );

    let wallet_path = real_parent.join("wallets").join("alice.key");
    std::fs::create_dir_all(wallet_path.parent().unwrap()).unwrap();
    std::fs::write(
        &wallet_path,
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n",
    )
    .unwrap();

    let read_err = read_key(&store, "alice").unwrap_err();
    assert!(
        read_err
            .to_string()
            .contains("traverses symlinked ancestor"),
        "unexpected error: {read_err}"
    );

    let _ = std::fs::remove_file(&wallet_path);
    let _ = std::fs::remove_dir(real_parent.join("wallets"));
    let _ = std::fs::remove_file(&linked_parent);
    let _ = std::fs::remove_dir(&real_parent);
    let _ = std::fs::remove_dir(&root);
}

#[test]
#[cfg(unix)]
fn wallet_create_rejects_symlinked_ancestor_from_env_store() {
    use std::os::unix::fs::symlink;

    let _guard = ENV_LOCK.lock().unwrap();
    let original_store = std::env::var_os("TRNM_WALLET_STORE");
    let unique = format!(
        "trnm-cli-wallet-env-ancestor-symlink-test-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let root = std::env::temp_dir().join(unique);
    let real_parent = root.join("real-parent");
    let linked_parent = root.join("linked-parent");
    std::fs::create_dir_all(&real_parent).unwrap();
    symlink(&real_parent, &linked_parent).unwrap();

    let store = linked_parent.join("wallets");
    std::env::set_var("TRNM_WALLET_STORE", store.as_os_str());

    let err = wallet_create("alice".to_string(), None).unwrap_err();
    assert!(
        err.to_string().contains("traverses symlinked ancestor"),
        "unexpected error: {err}"
    );
    assert!(!real_parent.join("wallets").join("alice.key").exists());

    match original_store {
        Some(value) => std::env::set_var("TRNM_WALLET_STORE", value),
        None => std::env::remove_var("TRNM_WALLET_STORE"),
    }
    let _ = std::fs::remove_file(&linked_parent);
    let _ = std::fs::remove_dir(&real_parent);
    let _ = std::fs::remove_dir(&root);
}
