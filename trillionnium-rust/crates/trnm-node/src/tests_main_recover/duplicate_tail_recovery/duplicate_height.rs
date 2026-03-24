use super::*;

#[test]
fn recover_discards_committed_duplicate_height_tail_without_restoring_stale_lock() {
    let wal_dir = temp_wal_dir("recover-committed-duplicate-height-tail-no-stale-lock");
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
    let replayed_e2 = WalMeta {
        height: 2,
        round: 1,
        proposal_hash: "stale-duplicate-tail-lock".into(),
        committed: true,
        state_root_hex: "r2-replayed".into(),
        prev_hash_hex: Some(h1.clone()),
    };

    persist_wal_meta_entries(&wal_dir, &[e1, e2, replayed_e2.clone()]).unwrap();
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
                state_root_hex: replayed_e2.state_root_hex.clone(),
                wal_entry_hash_hex: replayed_e2.content_hash_hex(),
            },
        ],
    )
    .unwrap();
    persist_consensus_wal(
        &wal_dir,
        &ConsensusWal {
            next_height: 3,
            last_round: 1,
            locked_block_hash: Some("stale-duplicate-tail-lock".into()),
        },
    )
    .unwrap();

    let recovered = recover_wal_state(&wal_dir).unwrap();
    assert_eq!(recovered.next_height, 3);
    assert!(recovered.truncated);
    assert!(
        !recovered.metadata_only_recovery,
        "discarding a corrupt duplicate-height committed WAL tail should preserve recoverable state at the retained checkpoint"
    );
    assert_eq!(recovered.wal_entries_retained, 2);
    assert_eq!(recovered.checkpoint_height_retained, Some(2));
    assert_eq!(
        recovered.last_checkpoint.as_ref().map(|cp| cp.height),
        Some(2)
    );
    assert_eq!(recovered.restored_lock.as_deref(), Some("h2"));
    assert_ne!(
        recovered.restored_lock.as_deref(),
        Some("stale-duplicate-tail-lock")
    );

    let entries = load_wal_meta_entries(&wal_dir).unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[1].height, 2);
    assert_eq!(entries[1].proposal_hash, "h2");

    let checkpoints = load_checkpoint_meta(&wal_dir).unwrap();
    assert_eq!(checkpoints.len(), 2);
    assert_eq!(checkpoints[1].height, 2);
    assert_eq!(checkpoints[1].state_root_hex, "r2");
    assert_eq!(checkpoints[1].wal_entry_hash_hex, h2);
    assert!(checkpoints
        .iter()
        .all(|cp| cp.wal_entry_hash_hex != replayed_e2.content_hash_hex()));

    let wal = fs::read_to_string(wal_file(&wal_dir)).unwrap();
    let wal: ConsensusWal = toml::from_str(&wal).unwrap();
    assert_eq!(wal.next_height, 3);
    assert_eq!(wal.last_round, 0);
    assert_eq!(wal.locked_block_hash.as_deref(), Some("h2"));

    let _ = fs::remove_dir_all(&wal_dir);
}

#[test]
fn recover_replayed_duplicate_height_tail_truncates_to_last_valid_checkpoint() {
    let wal_dir = temp_wal_dir("recover-replayed-duplicate-height-tail");
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
    let replayed_e2 = WalMeta {
        height: 2,
        round: 1,
        proposal_hash: "h2-replay".into(),
        committed: true,
        state_root_hex: "r2-replay".into(),
        prev_hash_hex: Some(h2.clone()),
    };

    persist_wal_meta_entries(&wal_dir, &[e1, e2, replayed_e2]).unwrap();
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
    fs::write(
        wal_file(&wal_dir),
        "next_height = 99\nlast_round = 42\nlocked_block_hash = \"stale-replay-lock\"\n",
    )
    .unwrap();

    let recovered = recover_wal_state(&wal_dir).unwrap();
    assert_eq!(recovered.next_height, 3);
    assert_eq!(recovered.restored_lock.as_deref(), Some("h2"));
    assert_eq!(recovered.checkpoint_height_retained, Some(2));
    assert_eq!(recovered.wal_entries_retained, 2);
    assert!(recovered.truncated);
    assert!(
        !recovered.metadata_only_recovery,
        "duplicate-height replay tail should truncate back to the verified checkpoint without claiming application-state recovery"
    );

    let retained = load_wal_meta_entries(&wal_dir).unwrap();
    assert_eq!(retained.len(), 2);
    assert_eq!(retained[0].height, 1);
    assert_eq!(retained[1].height, 2);
    assert_eq!(retained[1].proposal_hash, "h2");

    let wal = fs::read_to_string(wal_file(&wal_dir)).unwrap();
    let wal: ConsensusWal = toml::from_str(&wal).unwrap();
    assert_eq!(wal.next_height, 3);
    assert_eq!(wal.last_round, 0);
    assert_eq!(wal.locked_block_hash.as_deref(), Some("h2"));

    let _ = fs::remove_dir_all(&wal_dir);
}

#[test]
fn recover_committed_identical_duplicate_genesis_height_tail_truncates_to_genesis_checkpoint() {
    let wal_dir = temp_wal_dir("recover-committed-identical-duplicate-genesis-height-tail");
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
    let duplicate_e1 = e1.clone();

    persist_wal_meta_entries(&wal_dir, &[e1, duplicate_e1]).unwrap();
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
                state_root_hex: "stale-r1".into(),
                wal_entry_hash_hex: "stale-identical-h1".into(),
            },
        ],
    )
    .unwrap();
    fs::write(
        wal_file(&wal_dir),
        "next_height = 88\nlast_round = 9\nlocked_block_hash = \"stale-duplicate-genesis-lock\"\n",
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
        "exact duplicate genesis-height tail should truncate back to the verified genesis checkpoint without claiming metadata-only recovery"
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

#[test]
fn recover_committed_identical_duplicate_height_tail_truncates_to_last_valid_checkpoint() {
    let wal_dir = temp_wal_dir("recover-committed-identical-duplicate-height-tail");
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
    let duplicate_e2 = e2.clone();

    persist_wal_meta_entries(&wal_dir, &[e1, e2, duplicate_e2]).unwrap();
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
    fs::write(
        wal_file(&wal_dir),
        r#"next_height = 88
last_round = 9
locked_block_hash = "stale-duplicate-lock"
"#,
    )
    .unwrap();

    let recovered = recover_wal_state(&wal_dir).unwrap();
    assert_eq!(recovered.next_height, 3);
    assert_eq!(recovered.restored_lock.as_deref(), Some("h2"));
    assert_eq!(recovered.checkpoint_height_retained, Some(2));
    assert_eq!(recovered.wal_entries_retained, 2);
    assert!(recovered.truncated);
    assert!(
        !recovered.metadata_only_recovery,
        "exact duplicate committed tail should truncate back to the verified checkpoint without claiming metadata-only recovery"
    );

    let retained = load_wal_meta_entries(&wal_dir).unwrap();
    assert_eq!(retained.len(), 2);
    assert_eq!(retained[0].height, 1);
    assert_eq!(retained[1].height, 2);
    assert_eq!(retained[1].proposal_hash, "h2");

    let wal = fs::read_to_string(wal_file(&wal_dir)).unwrap();
    let wal: ConsensusWal = toml::from_str(&wal).unwrap();
    assert_eq!(wal.next_height, 3);
    assert_eq!(wal.last_round, 0);
    assert_eq!(wal.locked_block_hash.as_deref(), Some("h2"));

    let _ = fs::remove_dir_all(&wal_dir);
}
