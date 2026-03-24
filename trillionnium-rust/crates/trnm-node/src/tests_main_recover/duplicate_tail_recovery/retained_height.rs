use super::*;

#[test]
fn recover_height_regression_tail_truncates_to_last_valid_checkpoint() {
    let wal_dir = temp_wal_dir("recover-height-regression-tail");
    fs::create_dir_all(&wal_dir).unwrap();

    let e1 = WalMeta {
        height: 1,
        round: 0,
        proposal_hash: "p1".into(),
        state_root_hex: "r1".into(),
        prev_hash_hex: None,
        committed: true,
    };
    let h1 = e1.content_hash_hex();
    let e2 = WalMeta {
        height: 2,
        round: 0,
        proposal_hash: "p2".into(),
        state_root_hex: "r2".into(),
        prev_hash_hex: Some(h1.clone()),
        committed: true,
    };
    let h2 = e2.content_hash_hex();
    let regressed_e1 = WalMeta {
        height: 1,
        round: 1,
        proposal_hash: "p1-regressed".into(),
        state_root_hex: "r1-regressed".into(),
        prev_hash_hex: Some(h2.clone()),
        committed: true,
    };

    persist_wal_meta_entries(&wal_dir, &[e1.clone(), e2.clone(), regressed_e1]).unwrap();
    persist_checkpoint_meta(
        &wal_dir,
        &[
            CheckpointMeta {
                height: 1,
                state_root_hex: e1.state_root_hex.clone(),
                wal_entry_hash_hex: h1,
            },
            CheckpointMeta {
                height: 2,
                state_root_hex: e2.state_root_hex.clone(),
                wal_entry_hash_hex: h2,
            },
        ],
    )
    .unwrap();
    persist_consensus_wal(
        &wal_dir,
        &ConsensusWal {
            next_height: 99,
            last_round: 7,
            locked_block_hash: Some("stale-lock".into()),
        },
    )
    .unwrap();

    let recovered = recover_wal_state(&wal_dir).unwrap();
    assert_eq!(recovered.next_height, 3);
    assert_eq!(recovered.restored_lock, Some("p2".into()));
    assert_eq!(
        recovered.last_checkpoint.as_ref().map(|cp| cp.height),
        Some(2)
    );
    assert!(recovered.truncated);
    assert!(!recovered.metadata_only_recovery);
    assert_eq!(recovered.wal_entries_retained, 2);
    assert_eq!(recovered.checkpoint_height_retained, Some(2));

    let retained_entries = load_wal_meta_entries(&wal_dir).unwrap();
    assert_eq!(retained_entries.len(), 2);
    assert_eq!(retained_entries[0].height, 1);
    assert_eq!(retained_entries[1].height, 2);

    let checkpoints = load_checkpoint_meta(&wal_dir).unwrap();
    assert_eq!(checkpoints.len(), 2);
    assert_eq!(checkpoints[0].height, 1);
    assert_eq!(checkpoints[1].height, 2);

    let wal = fs::read_to_string(wal_file(&wal_dir)).unwrap();
    let wal: ConsensusWal = toml::from_str(&wal).unwrap();
    assert_eq!(wal.next_height, 3);
    assert_eq!(wal.last_round, 0);
    assert_eq!(wal.locked_block_hash, Some("p2".into()));

    let _ = fs::remove_dir_all(&wal_dir);
}

#[test]
fn recover_replayed_duplicate_genesis_height_tail_truncates_to_genesis_checkpoint() {
    let wal_dir = temp_wal_dir("recover-replayed-duplicate-genesis-height-tail");
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
    let replayed_e1 = WalMeta {
        height: 1,
        round: 1,
        proposal_hash: "h1-replay".into(),
        committed: true,
        state_root_hex: "r1-replay".into(),
        prev_hash_hex: Some(h1.clone()),
    };

    persist_wal_meta_entries(&wal_dir, &[e1, replayed_e1]).unwrap();
    persist_checkpoint_meta(
        &wal_dir,
        &[
            CheckpointMeta {
                height: 1,
                state_root_hex: "r1".into(),
                wal_entry_hash_hex: h1,
            },
            CheckpointMeta {
                height: 1,
                state_root_hex: "r1-replay".into(),
                wal_entry_hash_hex: "stale-replayed-h1".into(),
            },
        ],
    )
    .unwrap();
    fs::write(
        wal_file(&wal_dir),
        r#"next_height = 99
last_round = 42
locked_block_hash = "stale-genesis-replay-lock"
"#,
    )
    .unwrap();

    let recovered = recover_wal_state(&wal_dir).unwrap();
    assert_eq!(recovered.next_height, 2);
    assert_eq!(recovered.restored_lock.as_deref(), Some("h1"));
    assert_eq!(
        recovered.last_checkpoint.as_ref().map(|cp| cp.height),
        Some(1)
    );
    assert_eq!(recovered.checkpoint_height_retained, Some(1));
    assert_eq!(recovered.wal_entries_retained, 1);
    assert!(recovered.truncated);
    assert!(
        !recovered.metadata_only_recovery,
        "duplicate genesis-height replay tail should truncate back to the verified genesis checkpoint without claiming metadata-only recovery"
    );

    let retained = load_wal_meta_entries(&wal_dir).unwrap();
    assert_eq!(retained.len(), 1);
    assert_eq!(retained[0].height, 1);
    assert_eq!(retained[0].proposal_hash, "h1");

    let checkpoints = load_checkpoint_meta(&wal_dir).unwrap();
    assert_eq!(checkpoints.len(), 1);
    assert_eq!(checkpoints[0].height, 1);
    assert_eq!(checkpoints[0].state_root_hex, "r1");

    let wal = fs::read_to_string(wal_file(&wal_dir)).unwrap();
    let wal: ConsensusWal = toml::from_str(&wal).unwrap();
    assert_eq!(wal.next_height, 2);
    assert_eq!(wal.last_round, 0);
    assert_eq!(wal.locked_block_hash.as_deref(), Some("h1"));

    let _ = fs::remove_dir_all(&wal_dir);
}
