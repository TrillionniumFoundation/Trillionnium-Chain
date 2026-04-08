use super::*;

#[test]
fn recover_mixed_committed_tail_marks_metadata_only_even_if_later_tail_is_corrupt() {
    let wal_dir = temp_wal_dir("recover-mixed-committed-tail-metadata-only");
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
        round: 3,
        proposal_hash: "h2".into(),
        committed: true,
        state_root_hex: "r2".into(),
        prev_hash_hex: Some(h1.clone()),
    };
    let corrupt_e3 = WalMeta {
        height: 3,
        round: 4,
        proposal_hash: "h3-corrupt".into(),
        committed: true,
        state_root_hex: "r3-corrupt".into(),
        prev_hash_hex: Some("not-the-retained-tip".into()),
    };

    persist_wal_meta_entries(&wal_dir, &[e1, e2, corrupt_e3]).unwrap();
    persist_checkpoint_meta(
        &wal_dir,
        &[CheckpointMeta {
            height: 1,
            state_root_hex: "r1".into(),
            wal_entry_hash_hex: h1,
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
    assert!(recovered.truncated);
    assert!(
            recovered.metadata_only_recovery,
            "discarding any directly continuing committed tail beyond the retained checkpoint must stay fail-closed even if later tail entries are corrupt"
        );
    assert_eq!(recovered.next_height, 2);
    assert_eq!(recovered.checkpoint_height_retained, Some(1));
    assert_eq!(recovered.wal_entries_retained, 1);
    assert!(recovered.restored_lock.is_none());

    let retained = load_wal_meta_entries(&wal_dir).unwrap();
    assert_eq!(retained.len(), 1);
    assert_eq!(retained[0].height, 1);
    assert_eq!(retained[0].proposal_hash, "h1");

    let wal = fs::read_to_string(wal_file(&wal_dir)).unwrap();
    let wal: ConsensusWal = toml::from_str(&wal).unwrap();
    assert_eq!(wal.next_height, 2);
    assert_eq!(wal.last_round, 2);
    assert!(wal.locked_block_hash.is_none());

    let _ = fs::remove_dir_all(&wal_dir);
}

#[test]
fn recover_mixed_committed_tail_prunes_stale_duplicate_checkpoint_at_retained_height() {
    let wal_dir =
        temp_wal_dir("recover-mixed-committed-tail-prunes-stale-checkpoint-at-retained-height");
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
        round: 3,
        proposal_hash: "h2".into(),
        committed: true,
        state_root_hex: "r2".into(),
        prev_hash_hex: Some(h1.clone()),
    };
    let corrupt_e3 = WalMeta {
        height: 3,
        round: 4,
        proposal_hash: "h3-corrupt".into(),
        committed: true,
        state_root_hex: "r3-corrupt".into(),
        prev_hash_hex: Some("not-the-retained-tip".into()),
    };

    persist_wal_meta_entries(&wal_dir, &[e1, e2, corrupt_e3]).unwrap();
    persist_checkpoint_meta(
        &wal_dir,
        &[
            CheckpointMeta {
                height: 1,
                state_root_hex: "r1-stale".into(),
                wal_entry_hash_hex: "stale-h1".into(),
            },
            CheckpointMeta {
                height: 1,
                state_root_hex: "r1".into(),
                wal_entry_hash_hex: h1.clone(),
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
    assert!(recovered.truncated);
    assert!(recovered.metadata_only_recovery);
    assert_eq!(recovered.next_height, 2);
    assert_eq!(recovered.checkpoint_height_retained, Some(1));
    assert_eq!(recovered.wal_entries_retained, 1);
    assert!(recovered.restored_lock.is_none());

    let checkpoints = load_checkpoint_meta(&wal_dir).unwrap();
    assert_eq!(checkpoints.len(), 1);
    assert_eq!(checkpoints[0].height, 1);
    assert_eq!(checkpoints[0].state_root_hex, "r1");
    assert_eq!(checkpoints[0].wal_entry_hash_hex, h1);

    let wal = fs::read_to_string(wal_file(&wal_dir)).unwrap();
    let wal: ConsensusWal = toml::from_str(&wal).unwrap();
    assert_eq!(wal.next_height, 2);
    assert_eq!(wal.last_round, 2);
    assert!(wal.locked_block_hash.is_none());

    let _ = fs::remove_dir_all(&wal_dir);
}
