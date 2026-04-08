use super::*;

#[test]
fn recover_canonicalizes_retained_checkpoint_order_after_pruning() {
    let wal_dir = temp_wal_dir("recover-canonicalize-retained-checkpoint-order");
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
                height: 2,
                state_root_hex: "r2".into(),
                wal_entry_hash_hex: h2.clone(),
            },
            CheckpointMeta {
                height: 1,
                state_root_hex: "r1".into(),
                wal_entry_hash_hex: h1,
            },
        ],
    )
    .unwrap();

    let recovered = recover_wal_state(&wal_dir).unwrap();
    assert_eq!(recovered.next_height, 3);
    assert!(!recovered.metadata_only_recovery);
    assert_eq!(recovered.checkpoint_height_retained, Some(2));
    assert_eq!(recovered.wal_entries_retained, 2);

    let checkpoints = load_checkpoint_meta(&wal_dir).unwrap();
    assert_eq!(checkpoints.len(), 2);
    assert_eq!(checkpoints[0].height, 1);
    assert_eq!(checkpoints[0].state_root_hex, "r1");
    assert_eq!(checkpoints[1].height, 2);
    assert_eq!(checkpoints[1].state_root_hex, "r2");
    assert_eq!(checkpoints[1].wal_entry_hash_hex, h2);

    let _ = fs::remove_dir_all(&wal_dir);
}

#[test]
fn recover_canonicalizes_retained_checkpoint_order_without_truncating_clean_wal() {
    let wal_dir = temp_wal_dir("recover-canonicalize-checkpoints-clean-wal");
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
                height: 2,
                state_root_hex: "r2".into(),
                wal_entry_hash_hex: h2.clone(),
            },
            CheckpointMeta {
                height: 1,
                state_root_hex: "r1".into(),
                wal_entry_hash_hex: h1.clone(),
            },
        ],
    )
    .unwrap();
    persist_consensus_wal(
        &wal_dir,
        &ConsensusWal {
            next_height: 99,
            last_round: 99,
            locked_block_hash: Some("stale-lock".into()),
        },
    )
    .unwrap();

    let recovered = recover_wal_state(&wal_dir).unwrap();
    assert_eq!(recovered.next_height, 3);
    assert!(!recovered.truncated);
    assert!(!recovered.metadata_only_recovery);
    assert_eq!(recovered.checkpoint_height_retained, Some(2));
    assert_eq!(recovered.restored_lock.as_deref(), Some("h2"));

    let checkpoints = load_checkpoint_meta(&wal_dir).unwrap();
    assert_eq!(checkpoints.len(), 2);
    assert_eq!(checkpoints[0].height, 1);
    assert_eq!(checkpoints[0].state_root_hex, "r1");
    assert_eq!(checkpoints[0].wal_entry_hash_hex, h1);
    assert_eq!(checkpoints[1].height, 2);
    assert_eq!(checkpoints[1].state_root_hex, "r2");
    assert_eq!(checkpoints[1].wal_entry_hash_hex, h2);

    let wal_raw = fs::read_to_string(wal_file(&wal_dir)).unwrap();
    let wal: ConsensusWal = toml::from_str(&wal_raw).unwrap();
    assert_eq!(wal.next_height, 3);
    assert_eq!(wal.last_round, 5);
    assert_eq!(wal.locked_block_hash.as_deref(), Some("h2"));

    let _ = fs::remove_dir_all(&wal_dir);
}
