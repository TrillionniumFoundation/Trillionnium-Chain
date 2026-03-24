use super::*;

#[test]
fn recover_prunes_stale_lower_checkpoint_that_no_longer_matches_retained_wal() {
    let wal_dir = temp_wal_dir("recover-prune-stale-lower-checkpoint");
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

    let recovered = recover_wal_state(&wal_dir).unwrap();
    assert_eq!(recovered.next_height, 3);
    assert!(recovered.truncated);
    assert!(!recovered.metadata_only_recovery);
    assert_eq!(recovered.wal_entries_retained, 2);
    assert_eq!(recovered.checkpoint_height_retained, Some(2));

    let checkpoints = load_checkpoint_meta(&wal_dir).unwrap();
    assert_eq!(checkpoints.len(), 1);
    assert_eq!(checkpoints[0].height, 2);
    assert_eq!(checkpoints[0].state_root_hex, "r2");
    assert_eq!(checkpoints[0].wal_entry_hash_hex, h2);

    let _ = fs::remove_dir_all(&wal_dir);
}
