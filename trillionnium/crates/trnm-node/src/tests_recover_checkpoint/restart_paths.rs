use super::*;

#[test]
fn recover_fully_checkpointed_wal_rewrites_stale_consensus_wal_lock_to_retained_tip() {
    let wal_dir = temp_wal_dir("recover-fully-checkpointed-no-wal-rewrite");
    fs::create_dir_all(&wal_dir).unwrap();

    let e1 = WalMeta {
        height: 1,
        round: 7,
        proposal_hash: "h1".into(),
        committed: true,
        state_root_hex: "r1".into(),
        prev_hash_hex: None,
    };
    let h1 = e1.content_hash_hex();
    persist_wal_meta_entries(&wal_dir, &[e1]).unwrap();
    persist_checkpoint_meta(
        &wal_dir,
        &[CheckpointMeta {
            height: 1,
            wal_entry_hash_hex: h1,
            state_root_hex: "r1".into(),
        }],
    )
    .unwrap();
    fs::write(
        wal_file(&wal_dir),
        r#"next_height = 99
last_round = 42
locked_block_hash = "stale-lock"
"#,
    )
    .unwrap();

    let recovered = recover_wal_state(&wal_dir).unwrap();
    assert!(!recovered.metadata_only_recovery);
    assert_eq!(recovered.next_height, 2);
    assert_eq!(recovered.checkpoint_height_retained, Some(1));
    assert_eq!(recovered.restored_lock.as_deref(), Some("h1"));
    assert_ne!(recovered.restored_lock.as_deref(), Some("stale-lock"));

    let wal_raw = fs::read_to_string(wal_file(&wal_dir)).unwrap();
    let wal: ConsensusWal = toml::from_str(&wal_raw).unwrap();
    assert_eq!(wal.next_height, 2);
    assert_eq!(wal.last_round, 7);
    assert_eq!(wal.locked_block_hash.as_deref(), Some("h1"));

    let _ = fs::remove_dir_all(&wal_dir);
}

#[test]
fn recover_fully_checkpointed_multiple_entries_rewrite_stale_consensus_wal_to_retained_tip() {
    let wal_dir = temp_wal_dir("recover-fully-checkpointed-multi-no-wal-rewrite");
    fs::create_dir_all(&wal_dir).unwrap();

    let e1 = WalMeta {
        height: 1,
        round: 3,
        proposal_hash: "h1".into(),
        committed: true,
        state_root_hex: "r1".into(),
        prev_hash_hex: None,
    };
    let h1 = e1.content_hash_hex();
    let e2 = WalMeta {
        height: 2,
        round: 4,
        proposal_hash: "h2".into(),
        committed: true,
        state_root_hex: "r2".into(),
        prev_hash_hex: Some(h1.clone()),
    };
    let h2 = e2.content_hash_hex();
    persist_wal_meta_entries(&wal_dir, &[e1, e2]).unwrap();
    persist_checkpoint_meta(
        &wal_dir,
        &[
            CheckpointMeta {
                height: 1,
                wal_entry_hash_hex: h1,
                state_root_hex: "r1".into(),
            },
            CheckpointMeta {
                height: 2,
                wal_entry_hash_hex: h2,
                state_root_hex: "r2".into(),
            },
        ],
    )
    .unwrap();
    fs::write(
        wal_file(&wal_dir),
        r#"next_height = 99
last_round = 42
locked_block_hash = "stale-lock"
"#,
    )
    .unwrap();

    let recovered = recover_wal_state(&wal_dir).unwrap();
    assert!(!recovered.metadata_only_recovery);
    assert!(!recovered.truncated);
    assert_eq!(recovered.next_height, 3);
    assert_eq!(recovered.checkpoint_height_retained, Some(2));
    assert_eq!(recovered.restored_lock.as_deref(), Some("h2"));
    assert_ne!(recovered.restored_lock.as_deref(), Some("stale-lock"));

    let wal_raw = fs::read_to_string(wal_file(&wal_dir)).unwrap();
    let wal: ConsensusWal = toml::from_str(&wal_raw).unwrap();
    assert_eq!(wal.next_height, 3);
    assert_eq!(wal.last_round, 4);
    assert_eq!(wal.locked_block_hash.as_deref(), Some("h2"));

    let _ = fs::remove_dir_all(&wal_dir);
}

#[test]
fn recover_rewrites_consensus_wal_to_retained_checkpoint_after_metadata_only_truncation() {
    let wal_dir = temp_wal_dir("recover-metadata-only-tail-rewrites-consensus-wal");
    fs::create_dir_all(&wal_dir).unwrap();

    let e1 = WalMeta {
        height: 1,
        round: 3,
        proposal_hash: "h1".into(),
        committed: true,
        state_root_hex: "r1".into(),
        prev_hash_hex: None,
    };
    let h1 = e1.content_hash_hex();
    let e2 = WalMeta {
        height: 2,
        round: 4,
        proposal_hash: "h2".into(),
        committed: false,
        state_root_hex: "r2".into(),
        prev_hash_hex: Some(h1.clone()),
    };
    persist_wal_meta_entries(&wal_dir, &[e1, e2]).unwrap();
    persist_checkpoint_meta(
        &wal_dir,
        &[CheckpointMeta {
            height: 1,
            wal_entry_hash_hex: h1,
            state_root_hex: "r1".into(),
        }],
    )
    .unwrap();
    fs::write(
        wal_file(&wal_dir),
        r#"next_height = 99
last_round = 42
locked_block_hash = "stale-lock"
"#,
    )
    .unwrap();

    let recovered = recover_wal_state(&wal_dir).unwrap();
    assert!(recovered.metadata_only_recovery);
    assert!(recovered.truncated);
    assert_eq!(recovered.next_height, 2);
    assert!(recovered.restored_lock.is_none());

    let wal = fs::read_to_string(wal_file(&wal_dir)).unwrap();
    let wal: ConsensusWal = toml::from_str(&wal).unwrap();
    assert_eq!(wal.next_height, 2);
    assert_eq!(wal.last_round, 3);
    assert!(wal.locked_block_hash.is_none());

    let _ = fs::remove_dir_all(&wal_dir);
}

#[test]
fn recover_truncates_uncheckpointed_tail_without_claiming_metadata_recovery() {
    let wal_dir = temp_wal_dir("recover-truncates-uncheckpointed-tail");
    fs::create_dir_all(&wal_dir).unwrap();

    let e1 = WalMeta {
        height: 1,
        round: 0,
        proposal_hash: "h1".into(),
        committed: true,
        state_root_hex: "r1".into(),
        prev_hash_hex: None,
    };
    let h1 = e1.content_hash_hex();
    let e2 = WalMeta {
        height: 2,
        round: 0,
        proposal_hash: "h2".into(),
        committed: true,
        state_root_hex: "r2".into(),
        prev_hash_hex: Some(h1.clone()),
    };
    persist_wal_meta_entries(&wal_dir, &[e1, e2]).unwrap();
    persist_checkpoint_meta(
        &wal_dir,
        &[CheckpointMeta {
            height: 1,
            state_root_hex: "r1".into(),
            wal_entry_hash_hex: h1,
        }],
    )
    .unwrap();

    let recovered = recover_wal_state(&wal_dir).unwrap();
    assert!(recovered.truncated);
    assert!(
            recovered.metadata_only_recovery,
            "committed WAL beyond last checkpoint must stay fail-closed until StateStore restore/replay exists"
        );
    assert_eq!(recovered.next_height, 2);
    assert_eq!(recovered.checkpoint_height_retained, Some(1));
    assert!(recovered.restored_lock.is_none());
    assert_eq!(recovered.wal_entries_retained, 1);
    assert_eq!(load_wal_meta_entries(&wal_dir).unwrap().len(), 1);
    assert_eq!(load_checkpoint_meta(&wal_dir).unwrap().len(), 1);

    let _ = fs::remove_dir_all(&wal_dir);
}

#[test]
fn recover_allows_non_metadata_only_restart_when_checkpoint_covers_last_wal_entry() {
    let wal_dir = temp_wal_dir("recover-fully-checkpointed");
    fs::create_dir_all(&wal_dir).unwrap();

    let e1 = WalMeta {
        height: 1,
        round: 0,
        proposal_hash: "h1".into(),
        committed: true,
        state_root_hex: "r1".into(),
        prev_hash_hex: None,
    };
    let h1 = e1.content_hash_hex();
    let e2 = WalMeta {
        height: 2,
        round: 0,
        proposal_hash: "h2".into(),
        committed: true,
        state_root_hex: "r2".into(),
        prev_hash_hex: Some(h1.clone()),
    };
    let h2 = e2.content_hash_hex();
    persist_wal_meta_entries(&wal_dir, &[e1, e2]).unwrap();
    persist_checkpoint_meta(
        &wal_dir,
        &[
            CheckpointMeta {
                height: 1,
                state_root_hex: "r1".into(),
                wal_entry_hash_hex: h1,
            },
            CheckpointMeta {
                height: 2,
                state_root_hex: "r2".into(),
                wal_entry_hash_hex: h2,
            },
        ],
    )
    .unwrap();

    let recovered = recover_wal_state(&wal_dir).unwrap();
    assert!(!recovered.metadata_only_recovery);
    assert_eq!(recovered.next_height, 3);
    assert_eq!(recovered.checkpoint_height_retained, Some(2));
    assert_eq!(recovered.restored_lock.as_deref(), Some("h2"));
    assert_eq!(recovered.wal_entries_retained, 2);

    let _ = fs::remove_dir_all(&wal_dir);
}

#[test]
fn recover_without_checkpoint_and_without_retained_wal_is_not_metadata_only() {
    let wal_dir = temp_wal_dir("recover-no-checkpoint-no-retained-wal");
    fs::create_dir_all(&wal_dir).unwrap();

    let recovered = recover_wal_state(&wal_dir).unwrap();
    assert_eq!(recovered.next_height, 1);
    assert!(recovered.restored_lock.is_none());
    assert!(recovered.last_checkpoint.is_none());
    assert!(!recovered.truncated);
    assert!(!recovered.metadata_only_recovery);
    assert_eq!(recovered.wal_entries_retained, 0);
    assert_eq!(recovered.checkpoint_height_retained, None);

    let _ = fs::remove_dir_all(&wal_dir);
}
