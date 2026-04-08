use super::*;

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
