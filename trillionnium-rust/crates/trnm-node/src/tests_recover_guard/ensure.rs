use super::*;

#[test]
fn ensure_recoverable_wal_state_rejects_metadata_only_recovery() {
    let wal_dir = temp_wal_dir("recover-guard-metadata-only");
    fs::create_dir_all(&wal_dir).unwrap();

    let recovered = RecoveredWalState {
        next_height: 4,
        restored_lock: None,
        last_checkpoint: Some(CheckpointMeta {
            height: 2,
            state_root_hex: "r2".into(),
            wal_entry_hash_hex: "h2".into(),
        }),
        truncated: true,
        metadata_only_recovery: true,
        wal_entries_retained: 3,
        checkpoint_height_retained: Some(2),
    };

    let err = ensure_recoverable_wal_state(&wal_dir, &recovered).unwrap_err();
    let err = format!("{err:#}");

    assert!(err.contains("refusing metadata-only recovery"));
    assert!(err.contains("retained 3 committed WAL entries through height 3"));
    assert!(err.contains("last retained checkpoint: 2"));

    let _ = fs::remove_dir_all(&wal_dir);
}

#[test]
fn ensure_recoverable_wal_state_allows_fully_checkpointed_recovery() {
    let wal_dir = temp_wal_dir("recover-guard-safe");
    fs::create_dir_all(&wal_dir).unwrap();

    let recovered = RecoveredWalState {
        next_height: 3,
        restored_lock: Some("h2".into()),
        last_checkpoint: Some(CheckpointMeta {
            height: 2,
            state_root_hex: "r2".into(),
            wal_entry_hash_hex: "h2".into(),
        }),
        truncated: false,
        metadata_only_recovery: false,
        wal_entries_retained: 2,
        checkpoint_height_retained: Some(2),
    };

    ensure_recoverable_wal_state(&wal_dir, &recovered).unwrap();

    let _ = fs::remove_dir_all(&wal_dir);
}
