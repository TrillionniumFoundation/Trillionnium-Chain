use super::*;

#[test]
fn recover_prunes_exact_duplicate_checkpoint_at_retained_height() {
    let wal_dir = temp_wal_dir("recover-prune-exact-duplicate-checkpoint");
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
        round: 5,
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
                wal_entry_hash_hex: h2.clone(),
            },
            CheckpointMeta {
                height: 2,
                state_root_hex: "r2".into(),
                wal_entry_hash_hex: h2.clone(),
            },
        ],
    )
    .unwrap();

    let recovered = recover_wal_state(&wal_dir).unwrap();
    assert_eq!(recovered.next_height, 3);
    assert!(recovered.truncated);
    assert!(!recovered.metadata_only_recovery);
    assert_eq!(recovered.checkpoint_height_retained, Some(2));
    assert_eq!(recovered.wal_entries_retained, 2);
    assert_eq!(recovered.restored_lock.as_deref(), Some("h2"));

    let checkpoints = load_checkpoint_meta(&wal_dir).unwrap();
    assert_eq!(checkpoints.len(), 2);
    assert_eq!(checkpoints[0].height, 1);
    assert_eq!(checkpoints[1].height, 2);
    assert_eq!(checkpoints[1].state_root_hex, "r2");
    assert_eq!(checkpoints[1].wal_entry_hash_hex, h2);

    let wal = fs::read_to_string(wal_file(&wal_dir)).unwrap();
    let wal: ConsensusWal = toml::from_str(&wal).unwrap();
    assert_eq!(wal.next_height, 3);
    assert_eq!(wal.last_round, 5);
    assert_eq!(wal.locked_block_hash.as_deref(), Some("h2"));

    let _ = fs::remove_dir_all(&wal_dir);
}

#[test]
fn recover_prunes_stale_duplicate_checkpoint_and_rewrites_consensus_wal_to_retained_tip() {
    let wal_dir = temp_wal_dir("recover-prune-duplicate-checkpoint-rewrites-wal");
    fs::create_dir_all(&wal_dir).unwrap();

    let e1 = WalMeta {
        height: 1,
        round: 2,
        proposal_hash: "h1".into(),
        committed: true,
        state_root_hex: "r1".into(),
        prev_hash_hex: None,
    };
    let h1 = e1.content_hash_hex();
    let e2 = WalMeta {
        height: 2,
        round: 5,
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
                state_root_hex: "stale-r2".into(),
                wal_entry_hash_hex: "stale-h2".into(),
            },
            CheckpointMeta {
                height: 2,
                state_root_hex: "r2".into(),
                wal_entry_hash_hex: h2.clone(),
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
    assert_eq!(recovered.next_height, 3);
    assert!(recovered.truncated);
    assert!(!recovered.metadata_only_recovery);
    assert_eq!(recovered.checkpoint_height_retained, Some(2));
    assert_eq!(recovered.wal_entries_retained, 2);
    assert_eq!(recovered.restored_lock.as_deref(), Some("h2"));

    let checkpoints = load_checkpoint_meta(&wal_dir).unwrap();
    assert_eq!(checkpoints.len(), 2);
    assert_eq!(checkpoints[0].height, 1);
    assert_eq!(checkpoints[1].height, 2);
    assert_eq!(checkpoints[1].state_root_hex, "r2");
    assert_eq!(checkpoints[1].wal_entry_hash_hex, h2);

    let wal = fs::read_to_string(wal_file(&wal_dir)).unwrap();
    let wal: ConsensusWal = toml::from_str(&wal).unwrap();
    assert_eq!(wal.next_height, 3);
    assert_eq!(wal.last_round, 5);
    assert_eq!(wal.locked_block_hash.as_deref(), Some("h2"));

    let _ = fs::remove_dir_all(&wal_dir);
}

#[test]
fn recover_truncates_to_latest_valid_checkpoint() {
    let wal_dir = temp_wal_dir("recover");
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
    let e3_bad = WalMeta {
        height: 3,
        round: 1,
        proposal_hash: "h3".into(),
        committed: true,
        state_root_hex: "r3".into(),
        prev_hash_hex: Some("broken".into()),
    };
    persist_wal_meta_entries(&wal_dir, &[e1, e2, e3_bad]).unwrap();
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
    assert_eq!(recovered.next_height, 3);
    assert!(recovered.truncated);
    assert!(!recovered.metadata_only_recovery);
    assert_eq!(recovered.wal_entries_retained, 2);
    assert_eq!(
        recovered.last_checkpoint.as_ref().map(|cp| cp.height),
        Some(2)
    );
    assert_eq!(recovered.restored_lock.as_deref(), Some("h2"));

    let entries = load_wal_meta_entries(&wal_dir).unwrap();
    assert_eq!(entries.len(), 2);

    let _ = fs::remove_dir_all(&wal_dir);
}

#[test]
fn recover_prunes_stale_duplicate_checkpoint_at_retained_height() {
    let wal_dir = temp_wal_dir("recover-prune-stale-duplicate-checkpoint");
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
                state_root_hex: "stale-r2".into(),
                wal_entry_hash_hex: "stale-h2".into(),
            },
            CheckpointMeta {
                height: 2,
                state_root_hex: "r2".into(),
                wal_entry_hash_hex: h2.clone(),
            },
        ],
    )
    .unwrap();

    let recovered = recover_wal_state(&wal_dir).unwrap();
    assert_eq!(recovered.next_height, 3);
    assert!(recovered.truncated);
    assert!(!recovered.metadata_only_recovery);
    assert_eq!(recovered.wal_entries_retained, 2);
    assert_eq!(recovered.checkpoint_height_retained, Some(2));

    let checkpoints = load_checkpoint_meta(&wal_dir).unwrap();
    assert_eq!(checkpoints.len(), 2);
    assert_eq!(checkpoints[0].height, 1);
    assert_eq!(checkpoints[1].height, 2);
    assert_eq!(checkpoints[1].state_root_hex, "r2");
    assert_eq!(checkpoints[1].wal_entry_hash_hex, h2);

    let _ = fs::remove_dir_all(&wal_dir);
}

#[test]
fn recover_prunes_identical_duplicate_checkpoint_at_retained_height() {
    let wal_dir = temp_wal_dir("recover-prune-identical-duplicate-checkpoint");
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
                wal_entry_hash_hex: h2.clone(),
            },
            CheckpointMeta {
                height: 2,
                state_root_hex: "r2".into(),
                wal_entry_hash_hex: h2.clone(),
            },
        ],
    )
    .unwrap();

    let recovered = recover_wal_state(&wal_dir).unwrap();
    assert_eq!(recovered.next_height, 3);
    assert!(recovered.truncated);
    assert!(!recovered.metadata_only_recovery);
    assert_eq!(recovered.wal_entries_retained, 2);
    assert_eq!(recovered.checkpoint_height_retained, Some(2));

    let checkpoints = load_checkpoint_meta(&wal_dir).unwrap();
    assert_eq!(checkpoints.len(), 2);
    assert_eq!(checkpoints[0].height, 1);
    assert_eq!(checkpoints[1].height, 2);
    assert_eq!(checkpoints[1].state_root_hex, "r2");
    assert_eq!(checkpoints[1].wal_entry_hash_hex, h2);

    let _ = fs::remove_dir_all(&wal_dir);
}
