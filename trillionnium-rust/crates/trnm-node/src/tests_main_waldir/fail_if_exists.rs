use super::helpers::args_with_wal_dir;
use super::*;

#[test]
fn resolve_wal_dir_fail_if_exists_rejects_stale_state() {
    let wal_dir = temp_wal_dir("fail-if-exists");
    fs::create_dir_all(&wal_dir).unwrap();
    fs::write(wal_meta_file(&wal_dir), "existing").unwrap();

    let args = args_with_wal_dir(wal_dir.display().to_string(), WalDirMode::FailIfExists);

    let err = resolve_wal_dir(&args).unwrap_err().to_string();
    assert!(
        err.contains("refusing to reuse existing BFT WAL state")
            && err.contains(&wal_dir.display().to_string())
            && err.contains("--bft-wal-mode reuse")
            && err.contains("--bft-wal-dir"),
        "unexpected fail-if-exists error: {err}"
    );

    let _ = fs::remove_dir_all(&wal_dir);
}

#[test]
fn resolve_wal_dir_fail_if_exists_rejects_checkpoint_only_state() {
    let wal_dir = temp_wal_dir("fail-if-exists-checkpoint-only");
    fs::create_dir_all(&wal_dir).unwrap();
    persist_checkpoint_meta(
        &wal_dir,
        &[CheckpointMeta {
            height: 7,
            state_root_hex: "aa".repeat(32),
            wal_entry_hash_hex: "bb".repeat(32),
        }],
    )
    .unwrap();

    let args = args_with_wal_dir(wal_dir.display().to_string(), WalDirMode::FailIfExists);

    let err = resolve_wal_dir(&args).unwrap_err().to_string();
    assert!(
        err.contains("refusing to reuse existing BFT WAL state")
            && err.contains(&wal_dir.display().to_string())
            && err.contains("--bft-wal-mode reuse")
            && err.contains("--bft-wal-dir"),
        "unexpected checkpoint-only fail-if-exists error: {err}"
    );

    let _ = fs::remove_dir_all(&wal_dir);
}

#[test]
fn resolve_wal_dir_fail_if_exists_rejects_wal_meta_only_state() {
    let wal_dir = temp_wal_dir("fail-if-exists-wal-meta-only");
    fs::create_dir_all(&wal_dir).unwrap();
    persist_wal_meta_entries(
        &wal_dir,
        &[WalMeta {
            height: 7,
            round: 0,
            proposal_hash: "proposal-a".into(),
            committed: true,
            state_root_hex: "aa".repeat(32),
            prev_hash_hex: None,
        }],
    )
    .unwrap();

    let args = args_with_wal_dir(wal_dir.display().to_string(), WalDirMode::FailIfExists);

    let err = resolve_wal_dir(&args).unwrap_err().to_string();
    assert!(
        err.contains("refusing to reuse existing BFT WAL state")
            && err.contains(&wal_dir.display().to_string())
            && err.contains("--bft-wal-mode reuse")
            && err.contains("--bft-wal-dir"),
        "unexpected wal-meta-only fail-if-exists error: {err}"
    );

    let _ = fs::remove_dir_all(&wal_dir);
}

#[test]
fn resolve_wal_dir_fail_if_exists_allows_comment_only_wal_scaffold() {
    let wal_dir = temp_wal_dir("fail-if-exists-comment-only-wal-scaffold");
    fs::create_dir_all(&wal_dir).unwrap();
    fs::write(
        wal_meta_file(&wal_dir),
        "# bootstrap placeholder\n\n   # retained until first committed block\n",
    )
    .unwrap();

    let args = args_with_wal_dir(wal_dir.display().to_string(), WalDirMode::FailIfExists);

    let (resolved, notice) = resolve_wal_dir(&args).unwrap();
    assert_eq!(resolved, wal_dir);
    assert!(notice.is_none());

    let _ = fs::remove_dir_all(&resolved);
}

#[test]
fn resolve_wal_dir_fail_if_exists_allows_comment_only_checkpoint_scaffold() {
    let wal_dir = temp_wal_dir("fail-if-exists-comment-only-checkpoint-scaffold");
    fs::create_dir_all(&wal_dir).unwrap();
    fs::write(
        checkpoint_file(&wal_dir),
        "# operator left a recovery note\n   # safe to reuse after catch-up succeeds\n",
    )
    .unwrap();

    let args = args_with_wal_dir(wal_dir.display().to_string(), WalDirMode::FailIfExists);

    let (resolved, notice) = resolve_wal_dir(&args).unwrap();
    assert_eq!(resolved, wal_dir);
    assert!(notice.is_none());

    let _ = fs::remove_dir_all(&resolved);
}

#[test]
fn resolve_wal_dir_fail_if_exists_allows_comment_only_consensus_wal_scaffold() {
    let wal_dir = temp_wal_dir("fail-if-exists-comment-only-consensus-wal-scaffold");
    fs::create_dir_all(&wal_dir).unwrap();
    fs::write(
        wal_file(&wal_dir),
        "# operator left a rejoin note\n   # safe to reuse after catch-up succeeds\n",
    )
    .unwrap();

    let args = args_with_wal_dir(wal_dir.display().to_string(), WalDirMode::FailIfExists);

    let (resolved, notice) = resolve_wal_dir(&args).unwrap();
    assert_eq!(resolved, wal_dir);
    assert!(notice.is_none());

    let _ = fs::remove_dir_all(&resolved);
}
