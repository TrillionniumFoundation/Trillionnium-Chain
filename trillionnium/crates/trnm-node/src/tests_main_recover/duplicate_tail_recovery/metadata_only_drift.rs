use super::*;

#[test]
fn recover_uncommitted_duplicate_height_tail_is_metadata_only_recovery() {
    let wal_dir = temp_wal_dir("recover-uncommitted-duplicate-height-tail");
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
        proposal_hash: "h2-replay-uncommitted".into(),
        committed: false,
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

    let recovered = recover_wal_state(&wal_dir).unwrap();
    assert_eq!(recovered.next_height, 3);
    assert!(recovered.restored_lock.is_none());
    assert_eq!(recovered.checkpoint_height_retained, Some(2));
    assert_eq!(recovered.wal_entries_retained, 2);
    assert!(recovered.truncated);
    assert!(
        recovered.metadata_only_recovery,
        "uncommitted replay metadata beyond the retained checkpoint must stay classified as metadata-only recovery"
    );

    let retained = load_wal_meta_entries(&wal_dir).unwrap();
    assert_eq!(retained.len(), 2);
    assert_eq!(retained[0].height, 1);
    assert_eq!(retained[1].height, 2);
    assert_eq!(retained[1].proposal_hash, "h2");

    let _ = fs::remove_dir_all(&wal_dir);
}

#[test]
fn recover_gap_skipping_tail_truncates_to_last_valid_checkpoint() {
    let wal_dir = temp_wal_dir("recover-gap-skipping-tail");
    fs::create_dir_all(&wal_dir).unwrap();

    let e1 = WalMeta {
        height: 1,
        round: 4,
        proposal_hash: "h1".into(),
        committed: true,
        state_root_hex: "r1".into(),
        prev_hash_hex: None,
    };
    let h1 = e1.content_hash_hex();
    let e3 = WalMeta {
        height: 3,
        round: 9,
        proposal_hash: "h3".into(),
        committed: true,
        state_root_hex: "r3".into(),
        prev_hash_hex: Some(h1.clone()),
    };

    persist_wal_meta_entries(&wal_dir, &[e1, e3.clone()]).unwrap();
    persist_checkpoint_meta(
        &wal_dir,
        &[
            CheckpointMeta {
                height: 1,
                state_root_hex: "r1".into(),
                wal_entry_hash_hex: h1.clone(),
            },
            CheckpointMeta {
                height: 3,
                state_root_hex: "r3".into(),
                wal_entry_hash_hex: e3.content_hash_hex(),
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
    assert_eq!(recovered.next_height, 2);
    assert!(recovered.restored_lock.is_none());
    assert_eq!(recovered.checkpoint_height_retained, Some(1));
    assert_eq!(recovered.wal_entries_retained, 1);
    assert!(recovered.truncated);
    assert!(
        recovered.metadata_only_recovery,
        "gap-skipping committed tail beyond the retained checkpoint must stay classified as metadata-only recovery until StateStore snapshot+replay exists"
    );

    let retained = load_wal_meta_entries(&wal_dir).unwrap();
    assert_eq!(retained.len(), 1);
    assert_eq!(retained[0].height, 1);
    assert_eq!(retained[0].proposal_hash, "h1");

    let retained_checkpoints = load_checkpoint_meta(&wal_dir).unwrap();
    assert_eq!(retained_checkpoints.len(), 1);
    assert_eq!(retained_checkpoints[0].height, 1);
    assert_eq!(retained_checkpoints[0].state_root_hex, "r1");
    assert_eq!(retained_checkpoints[0].wal_entry_hash_hex, h1);

    let wal = fs::read_to_string(wal_file(&wal_dir)).unwrap();
    let wal: ConsensusWal = toml::from_str(&wal).unwrap();
    assert_eq!(wal.next_height, 2);
    assert_eq!(wal.last_round, 4);
    assert!(wal.locked_block_hash.is_none());

    let _ = fs::remove_dir_all(&wal_dir);
}
