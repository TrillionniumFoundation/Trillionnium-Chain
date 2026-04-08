use super::*;

#[test]
fn recover_discards_metadata_only_tail_without_restoring_stale_lock() {
    let wal_dir = temp_wal_dir("recover-metadata-only-tail-no-stale-lock");
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
    let e3 = WalMeta {
        height: 3,
        round: 0,
        proposal_hash: "stale-tail-lock".into(),
        committed: false,
        state_root_hex: "r3".into(),
        prev_hash_hex: Some(h2.clone()),
    };

    persist_wal_meta_entries(&wal_dir, &[e1, e2, e3]).unwrap();
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
    assert!(recovered.metadata_only_recovery);
    assert_eq!(recovered.wal_entries_retained, 2);
    assert_eq!(
        recovered.last_checkpoint.as_ref().map(|cp| cp.height),
        Some(2)
    );
    assert!(recovered.restored_lock.is_none());
    assert_ne!(recovered.restored_lock.as_deref(), Some("stale-tail-lock"));

    let entries = load_wal_meta_entries(&wal_dir).unwrap();
    assert_eq!(entries.len(), 2);
    assert!(entries.iter().all(|entry| entry.committed));

    let _ = fs::remove_dir_all(&wal_dir);
}

#[test]
fn recover_prunes_checkpoint_for_metadata_only_tail() {
    let wal_dir = temp_wal_dir("recover-prune-metadata-only-tail-checkpoint");
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
    let e3 = WalMeta {
        height: 3,
        round: 0,
        proposal_hash: "metadata-only-tail".into(),
        committed: false,
        state_root_hex: "r3".into(),
        prev_hash_hex: Some(h2.clone()),
    };

    persist_wal_meta_entries(&wal_dir, &[e1, e2, e3.clone()]).unwrap();
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
            CheckpointMeta {
                height: 3,
                state_root_hex: "r3".into(),
                wal_entry_hash_hex: e3.content_hash_hex(),
            },
        ],
    )
    .unwrap();
    persist_consensus_wal(
        &wal_dir,
        &ConsensusWal {
            next_height: 99,
            last_round: 7,
            locked_block_hash: Some("stale-tail-lock".into()),
        },
    )
    .unwrap();

    let recovered = recover_wal_state(&wal_dir).unwrap();
    assert_eq!(recovered.next_height, 3);
    assert!(recovered.truncated);
    assert!(recovered.metadata_only_recovery);
    assert_eq!(
        recovered.last_checkpoint.as_ref().map(|cp| cp.height),
        Some(2)
    );
    assert!(recovered.restored_lock.is_none());

    let checkpoints = load_checkpoint_meta(&wal_dir).unwrap();
    assert_eq!(checkpoints.len(), 2);
    assert!(checkpoints.iter().all(|cp| cp.height <= 2));
    assert!(checkpoints
        .iter()
        .all(|cp| cp.wal_entry_hash_hex != e3.content_hash_hex()));

    let wal = fs::read_to_string(wal_file(&wal_dir)).unwrap();
    let wal: ConsensusWal = toml::from_str(&wal).unwrap();
    assert_eq!(wal.next_height, 3);
    assert_eq!(wal.last_round, 0);
    assert!(wal.locked_block_hash.is_none());

    let _ = fs::remove_dir_all(&wal_dir);
}

#[test]
fn recover_metadata_only_tail_prunes_stale_duplicate_checkpoint_at_retained_height() {
    let wal_dir = temp_wal_dir("recover-metadata-only-tail-prunes-stale-duplicate-checkpoint");
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
    let e3 = WalMeta {
        height: 3,
        round: 0,
        proposal_hash: "metadata-only-tail".into(),
        committed: false,
        state_root_hex: "r3".into(),
        prev_hash_hex: Some(h2.clone()),
    };

    persist_wal_meta_entries(&wal_dir, &[e1, e2, e3.clone()]).unwrap();
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
                state_root_hex: "r2-stale".into(),
                wal_entry_hash_hex: "stale-h2".into(),
            },
            CheckpointMeta {
                height: 2,
                state_root_hex: "r2".into(),
                wal_entry_hash_hex: h2.clone(),
            },
            CheckpointMeta {
                height: 3,
                state_root_hex: "r3".into(),
                wal_entry_hash_hex: e3.content_hash_hex(),
            },
        ],
    )
    .unwrap();

    let recovered = recover_wal_state(&wal_dir).unwrap();
    assert_eq!(recovered.next_height, 3);
    assert!(recovered.restored_lock.is_none());
    assert_eq!(recovered.checkpoint_height_retained, Some(2));
    assert_eq!(recovered.wal_entries_retained, 2);
    assert!(recovered.truncated);
    assert!(recovered.metadata_only_recovery);

    let checkpoints = load_checkpoint_meta(&wal_dir).unwrap();
    assert_eq!(checkpoints.len(), 2);
    assert_eq!(checkpoints[0].height, 1);
    assert_eq!(checkpoints[1].height, 2);
    assert_eq!(checkpoints[1].state_root_hex, "r2");
    assert_eq!(checkpoints[1].wal_entry_hash_hex, h2);

    let wal = fs::read_to_string(wal_file(&wal_dir)).unwrap();
    let wal: ConsensusWal = toml::from_str(&wal).unwrap();
    assert_eq!(wal.next_height, 3);
    assert_eq!(wal.last_round, 0);
    assert!(wal.locked_block_hash.is_none());

    let _ = fs::remove_dir_all(&wal_dir);
}

#[test]
fn recover_metadata_only_tail_prunes_stale_lower_checkpoint_that_no_longer_matches_retained_wal() {
    let wal_dir = temp_wal_dir("recover-metadata-only-tail-prune-stale-lower-checkpoint");
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
    let e3 = WalMeta {
        height: 3,
        round: 0,
        proposal_hash: "metadata-only-tail".into(),
        committed: false,
        state_root_hex: "r3".into(),
        prev_hash_hex: Some(h2.clone()),
    };

    persist_wal_meta_entries(&wal_dir, &[e1, e2, e3]).unwrap();
    persist_checkpoint_meta(
        &wal_dir,
        &[
            CheckpointMeta {
                height: 1,
                state_root_hex: "stale-r1".into(),
                wal_entry_hash_hex: "stale-h1".into(),
            },
            CheckpointMeta {
                height: 2,
                state_root_hex: "r2".into(),
                wal_entry_hash_hex: h2.clone(),
            },
        ],
    )
    .unwrap();
    persist_consensus_wal(
        &wal_dir,
        &ConsensusWal {
            next_height: 99,
            last_round: 7,
            locked_block_hash: Some("stale-tail-lock".into()),
        },
    )
    .unwrap();

    let recovered = recover_wal_state(&wal_dir).unwrap();
    assert_eq!(recovered.next_height, 3);
    assert!(recovered.truncated);
    assert!(recovered.metadata_only_recovery);
    assert_eq!(recovered.wal_entries_retained, 2);
    assert_eq!(recovered.checkpoint_height_retained, Some(2));
    assert!(recovered.restored_lock.is_none());

    let checkpoints = load_checkpoint_meta(&wal_dir).unwrap();
    assert_eq!(checkpoints.len(), 1);
    assert_eq!(checkpoints[0].height, 2);
    assert_eq!(checkpoints[0].state_root_hex, "r2");
    assert_eq!(checkpoints[0].wal_entry_hash_hex, h2);

    let wal = fs::read_to_string(wal_file(&wal_dir)).unwrap();
    let wal: ConsensusWal = toml::from_str(&wal).unwrap();
    assert_eq!(wal.next_height, 3);
    assert_eq!(wal.last_round, 0);
    assert!(wal.locked_block_hash.is_none());

    let _ = fs::remove_dir_all(&wal_dir);
}
