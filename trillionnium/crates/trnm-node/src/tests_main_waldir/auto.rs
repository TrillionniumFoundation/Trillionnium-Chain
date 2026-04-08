use super::helpers::args_with_wal_dir;
use super::*;

#[test]
fn resolve_wal_dir_auto_isolates_existing_builtin_default_state() {
    let root = temp_wal_dir("default-wal-root");
    let base = root.join(DEFAULT_BFT_WAL_DIR);
    fs::create_dir_all(&base).unwrap();
    fs::write(wal_file(&base), "existing").unwrap();

    let args = args_with_wal_dir(DEFAULT_BFT_WAL_DIR.into(), WalDirMode::Auto);

    let cwd = std::env::current_dir().unwrap();
    std::env::set_current_dir(&root).unwrap();
    let (resolved, notice) = resolve_wal_dir(&args).unwrap();
    std::env::set_current_dir(cwd).unwrap();

    let notice = notice.expect("auto mode should surface an operator notice when isolating default WAL state");
    assert_ne!(resolved, PathBuf::from(DEFAULT_BFT_WAL_DIR));
    assert!(resolved.starts_with(PathBuf::from(DEFAULT_BFT_WAL_DIR)));
    assert!(
        notice.contains("[bft-wal]")
            && notice.contains("existing default WAL state detected")
            && notice.contains(DEFAULT_BFT_WAL_DIR)
            && notice.contains("isolating this run")
            && notice.contains(&resolved.display().to_string())
            && notice.contains("--bft-wal-mode reuse"),
        "unexpected auto-mode notice: {notice}"
    );

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn resolve_wal_dir_auto_isolates_existing_builtin_default_wal_meta_only_state() {
    let root = temp_wal_dir("default-wal-meta-root");
    let base = root.join(DEFAULT_BFT_WAL_DIR);
    fs::create_dir_all(&base).unwrap();
    fs::write(wal_meta_file(&base), "existing").unwrap();

    let args = args_with_wal_dir(DEFAULT_BFT_WAL_DIR.into(), WalDirMode::Auto);

    let cwd = std::env::current_dir().unwrap();
    std::env::set_current_dir(&root).unwrap();
    let (resolved, notice) = resolve_wal_dir(&args).unwrap();
    std::env::set_current_dir(cwd).unwrap();

    let notice = notice.expect("auto mode should surface an operator notice when wal-meta-only default WAL state triggers isolation");
    assert_ne!(resolved, PathBuf::from(DEFAULT_BFT_WAL_DIR));
    assert!(resolved.starts_with(PathBuf::from(DEFAULT_BFT_WAL_DIR)));
    assert!(
        notice.contains("[bft-wal]")
            && notice.contains("existing default WAL state detected")
            && notice.contains(DEFAULT_BFT_WAL_DIR)
            && notice.contains("isolating this run")
            && notice.contains(&resolved.display().to_string())
            && notice.contains("--bft-wal-mode reuse"),
        "unexpected auto-mode notice: {notice}"
    );

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn resolve_wal_dir_auto_isolates_existing_builtin_default_checkpoint_only_state() {
    let root = temp_wal_dir("default-checkpoint-root");
    let base = root.join(DEFAULT_BFT_WAL_DIR);
    fs::create_dir_all(&base).unwrap();
    fs::write(checkpoint_file(&base), "existing").unwrap();

    let args = args_with_wal_dir(DEFAULT_BFT_WAL_DIR.into(), WalDirMode::Auto);

    let cwd = std::env::current_dir().unwrap();
    std::env::set_current_dir(&root).unwrap();
    let (resolved, notice) = resolve_wal_dir(&args).unwrap();
    std::env::set_current_dir(cwd).unwrap();

    let notice = notice.expect("auto mode should surface an operator notice when checkpoint-only default WAL state triggers isolation");
    assert_ne!(resolved, PathBuf::from(DEFAULT_BFT_WAL_DIR));
    assert!(resolved.starts_with(PathBuf::from(DEFAULT_BFT_WAL_DIR)));
    assert!(
        notice.contains("[bft-wal]")
            && notice.contains("existing default WAL state detected")
            && notice.contains(DEFAULT_BFT_WAL_DIR)
            && notice.contains("isolating this run")
            && notice.contains(&resolved.display().to_string())
            && notice.contains("--bft-wal-mode reuse"),
        "unexpected auto-mode notice: {notice}"
    );

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn resolve_wal_dir_auto_keeps_explicit_custom_dir_even_if_state_exists() {
    let wal_dir = temp_wal_dir("custom-reuse");
    fs::create_dir_all(&wal_dir).unwrap();
    fs::write(wal_file(&wal_dir), "existing").unwrap();

    let args = args_with_wal_dir(wal_dir.display().to_string(), WalDirMode::Auto);

    let (resolved, notice) = resolve_wal_dir(&args).unwrap();
    assert_eq!(resolved, wal_dir);
    assert!(notice.is_none());

    let _ = fs::remove_dir_all(&resolved);
}

#[test]
fn resolve_wal_dir_auto_isolates_builtin_default_when_only_checkpoint_metadata_exists() {
    let root = temp_wal_dir("default-wal-checkpoint-only-root");
    let base = root.join(DEFAULT_BFT_WAL_DIR);
    fs::create_dir_all(&base).unwrap();
    persist_checkpoint_meta(
        &base,
        &[CheckpointMeta {
            height: 7,
            state_root_hex: "aa".repeat(32),
            wal_entry_hash_hex: "bb".repeat(32),
        }],
    )
    .unwrap();

    let args = args_with_wal_dir(DEFAULT_BFT_WAL_DIR.into(), WalDirMode::Auto);

    let cwd = std::env::current_dir().unwrap();
    std::env::set_current_dir(&root).unwrap();
    let (resolved, notice) = resolve_wal_dir(&args).unwrap();
    std::env::set_current_dir(cwd).unwrap();

    assert_ne!(resolved, PathBuf::from(DEFAULT_BFT_WAL_DIR));
    assert!(resolved.starts_with(PathBuf::from(DEFAULT_BFT_WAL_DIR)));
    let notice = notice.expect("auto mode should emit checkpoint-only isolation notice");
    assert!(notice.contains("isolating this run"));
    assert!(notice.contains(DEFAULT_BFT_WAL_DIR));

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn resolve_wal_dir_auto_isolates_builtin_default_when_only_empty_wal_meta_scaffold_exists() {
    let root = temp_wal_dir("default-wal-empty-meta-only-root");
    let base = root.join(DEFAULT_BFT_WAL_DIR);
    fs::create_dir_all(&base).unwrap();
    persist_wal_meta_entries(&base, &[]).unwrap();

    let args = args_with_wal_dir(DEFAULT_BFT_WAL_DIR.into(), WalDirMode::Auto);

    let cwd = std::env::current_dir().unwrap();
    std::env::set_current_dir(&root).unwrap();
    let (resolved, notice) = resolve_wal_dir(&args).unwrap();
    std::env::set_current_dir(cwd).unwrap();

    assert_ne!(resolved, PathBuf::from(DEFAULT_BFT_WAL_DIR));
    assert!(resolved.starts_with(PathBuf::from(DEFAULT_BFT_WAL_DIR)));
    let notice = notice.expect("auto mode should emit empty wal-meta scaffold isolation notice");
    assert!(notice.contains("isolating this run"));
    assert!(notice.contains(DEFAULT_BFT_WAL_DIR));

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn resolve_wal_dir_auto_allows_builtin_default_when_only_comment_only_checkpoint_scaffold_exists() {
    let root = temp_wal_dir("default-wal-comment-checkpoint-only-root");
    let base = root.join(DEFAULT_BFT_WAL_DIR);
    fs::create_dir_all(&base).unwrap();
    fs::write(
        checkpoint_file(&base),
        "# bootstrap placeholder\n   # retained until first checkpoint\n",
    )
    .unwrap();

    let args = args_with_wal_dir(DEFAULT_BFT_WAL_DIR.into(), WalDirMode::Auto);

    let cwd = std::env::current_dir().unwrap();
    std::env::set_current_dir(&root).unwrap();
    let (resolved, notice) = resolve_wal_dir(&args).unwrap();
    std::env::set_current_dir(cwd).unwrap();

    assert_eq!(resolved, PathBuf::from(DEFAULT_BFT_WAL_DIR));
    assert!(notice.is_none());

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn resolve_wal_dir_auto_allows_builtin_default_when_only_comment_only_wal_scaffold_exists() {
    let root = temp_wal_dir("default-wal-comment-meta-only-root");
    let base = root.join(DEFAULT_BFT_WAL_DIR);
    fs::create_dir_all(&base).unwrap();
    fs::write(
        wal_meta_file(&base),
        "# bootstrap placeholder\n\n   # retained until first committed block\n",
    )
    .unwrap();

    let args = args_with_wal_dir(DEFAULT_BFT_WAL_DIR.into(), WalDirMode::Auto);

    let cwd = std::env::current_dir().unwrap();
    std::env::set_current_dir(&root).unwrap();
    let (resolved, notice) = resolve_wal_dir(&args).unwrap();
    std::env::set_current_dir(cwd).unwrap();

    assert_eq!(resolved, PathBuf::from(DEFAULT_BFT_WAL_DIR));
    assert!(notice.is_none());

    let _ = fs::remove_dir_all(&root);
}
