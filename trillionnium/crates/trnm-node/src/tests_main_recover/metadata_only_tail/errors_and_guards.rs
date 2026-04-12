use super::*;

#[test]
fn recover_metadata_only_error_reports_retained_wal_entries() {
    let wal_dir = temp_wal_dir("recover-metadata-only-error");
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
    persist_wal_meta_entries(&wal_dir, &[e1]).unwrap();
    persist_checkpoint_meta(
        &wal_dir,
        &[CheckpointMeta {
            height: 1,
            state_root_hex: "r1".into(),
            wal_entry_hash_hex: h1,
        }],
    )
    .unwrap();

    let recovered = recover_wal_state(&wal_dir).unwrap();
    assert!(!recovered.metadata_only_recovery);
    assert_eq!(recovered.wal_entries_retained, 1);
    assert_eq!(recovered.checkpoint_height_retained, Some(1));
    assert_eq!(recovered.next_height, 2);

    let err = metadata_only_recovery_error(&wal_dir, &recovered);
    assert!(err.contains("retained 1 committed WAL entry through height 1"));
    assert!(err.contains("last retained checkpoint: 1"));
    assert!(err.contains("next startup height: 2"));

    let would_require_snapshot_restore = recovered
        .checkpoint_height_retained
        .map(|checkpoint_height| checkpoint_height < recovered.next_height.saturating_sub(1))
        .unwrap_or(recovered.wal_entries_retained > 0);
    assert!(
        !would_require_snapshot_restore,
        "fully checkpointed WAL metadata must not be escalated to metadata-only recovery misuse"
    );

    let _ = fs::remove_dir_all(&wal_dir);
}

#[test]
fn recover_metadata_only_error_reports_absent_checkpoint() {
    let wal_dir = temp_wal_dir("recover-metadata-only-error-no-checkpoint");
    fs::create_dir_all(&wal_dir).unwrap();

    let recovered = RecoveredWalState {
        next_height: 1,
        restored_lock: None,
        last_checkpoint: None,
        truncated: false,
        metadata_only_recovery: true,
        wal_entries_retained: 0,
        checkpoint_height_retained: None,
    };

    let err = metadata_only_recovery_error(&wal_dir, &recovered);

    assert!(err.contains("retained no committed WAL entries"));
    assert!(!err.contains("through height 0"));
    assert!(!err.contains("no retained checkpoint metadata"));
    assert!(err.contains("last retained checkpoint: none"));
    assert!(err.contains("next startup height: 1"));
    assert!(err.contains(
        "operator action: restart with a fresh --bft-wal-dir / --bft-wal-mode auto isolated run; if this node must rejoin from prior state, restore an application snapshot before retrying"
    ));

    let _ = fs::remove_dir_all(&wal_dir);
}

#[test]
fn recover_metadata_only_error_reports_plural_retained_entries_and_height() {
    let wal_dir = temp_wal_dir("recover-metadata-only-error-plural");
    fs::create_dir_all(&wal_dir).unwrap();

    let recovered = RecoveredWalState {
        next_height: 3,
        restored_lock: None,
        last_checkpoint: Some(CheckpointMeta {
            height: 1,
            state_root_hex: "r1".into(),
            wal_entry_hash_hex: "h1".into(),
        }),
        truncated: true,
        metadata_only_recovery: true,
        wal_entries_retained: 2,
        checkpoint_height_retained: Some(1),
    };

    let err = metadata_only_recovery_error(&wal_dir, &recovered);

    assert!(err.contains("retained 2 committed WAL entries through height 2"));
    assert!(err.contains("checkpoint lags retained WAL tip by 1 block"));
    assert!(err.contains("last retained checkpoint: 1"));
    assert!(err.contains("next startup height: 3"));
    assert!(err.contains(
        "does not yet restore application StateStore snapshots or replay committed blocks"
    ));

    let _ = fs::remove_dir_all(&wal_dir);
}

#[test]
fn recover_metadata_only_error_reports_singular_checkpoint_lag_block() {
    let wal_dir = temp_wal_dir("recover-metadata-only-error-lag-block-singular");
    fs::create_dir_all(&wal_dir).unwrap();

    let recovered = RecoveredWalState {
        next_height: 3,
        restored_lock: None,
        last_checkpoint: Some(CheckpointMeta {
            height: 1,
            state_root_hex: "r1".into(),
            wal_entry_hash_hex: "h1".into(),
        }),
        truncated: true,
        metadata_only_recovery: true,
        wal_entries_retained: 2,
        checkpoint_height_retained: Some(1),
    };

    let err = metadata_only_recovery_error(&wal_dir, &recovered);

    assert!(err.contains("retained 2 committed WAL entries through height 2"));
    assert!(err.contains("checkpoint lags retained WAL tip by 1 block"));
    assert!(!err.contains("checkpoint lags retained WAL tip by 1 blocks"));
    assert!(err.contains("last retained checkpoint: 1"));
    assert!(err.contains("next startup height: 3"));

    let _ = fs::remove_dir_all(&wal_dir);
}

#[test]
fn recover_metadata_only_error_reports_plural_checkpoint_lag_blocks() {
    let wal_dir = temp_wal_dir("recover-metadata-only-error-lag-blocks");
    fs::create_dir_all(&wal_dir).unwrap();

    let recovered = RecoveredWalState {
        next_height: 5,
        restored_lock: None,
        last_checkpoint: Some(CheckpointMeta {
            height: 2,
            state_root_hex: "r2".into(),
            wal_entry_hash_hex: "h2".into(),
        }),
        truncated: true,
        metadata_only_recovery: true,
        wal_entries_retained: 4,
        checkpoint_height_retained: Some(2),
    };

    let err = metadata_only_recovery_error(&wal_dir, &recovered);

    assert!(err.contains("retained 4 committed WAL entries through height 4"));
    assert!(err.contains("checkpoint lags retained WAL tip by 2 blocks"));
    assert!(err.contains("last retained checkpoint: 2"));
    assert!(err.contains("next startup height: 5"));

    let _ = fs::remove_dir_all(&wal_dir);
}

#[test]
fn recover_metadata_only_error_reports_missing_retained_checkpoint_metadata() {
    let wal_dir = temp_wal_dir("recover-metadata-only-error-missing-checkpoint-metadata");
    fs::create_dir_all(&wal_dir).unwrap();

    let recovered = RecoveredWalState {
        next_height: 4,
        restored_lock: None,
        last_checkpoint: None,
        truncated: true,
        metadata_only_recovery: true,
        wal_entries_retained: 3,
        checkpoint_height_retained: None,
    };

    let err = metadata_only_recovery_error(&wal_dir, &recovered);

    assert!(err.contains("retained 3 committed WAL entries through height 3"));
    assert!(err.contains("no retained checkpoint metadata"));
    assert!(err.contains("last retained checkpoint: none"));
    assert!(err.contains("next startup height: 4"));

    let _ = fs::remove_dir_all(&wal_dir);
}

#[test]
fn recover_metadata_only_error_with_no_retained_wal_does_not_emit_checkpoint_lag_or_missing_metadata_hint() {
    let wal_dir = temp_wal_dir("recover-metadata-only-error-no-retained-wal");
    fs::create_dir_all(&wal_dir).unwrap();

    let recovered = RecoveredWalState {
        next_height: 1,
        restored_lock: None,
        last_checkpoint: Some(CheckpointMeta {
            height: 7,
            state_root_hex: "r7".into(),
            wal_entry_hash_hex: "h7".into(),
        }),
        truncated: true,
        metadata_only_recovery: true,
        wal_entries_retained: 0,
        checkpoint_height_retained: Some(7),
    };

    let err = metadata_only_recovery_error(&wal_dir, &recovered);

    assert!(err.contains("retained no committed WAL entries"));
    assert!(!err.contains("checkpoint lags retained WAL tip"));
    assert!(!err.contains("no retained checkpoint metadata"));
    assert!(err.contains("last retained checkpoint: 7"));
    assert!(err.contains("next startup height: 1"));

    let _ = fs::remove_dir_all(&wal_dir);
}

#[test]
fn recover_metadata_only_error_reports_fully_checkpointed_retained_tip_without_false_lag_hint() {
    let wal_dir =
        temp_wal_dir("recover-metadata-only-error-fully-checkpointed-retained-tip");
    fs::create_dir_all(&wal_dir).unwrap();

    let recovered = RecoveredWalState {
        next_height: 3,
        restored_lock: None,
        last_checkpoint: Some(CheckpointMeta {
            height: 2,
            state_root_hex: "r2".into(),
            wal_entry_hash_hex: "h2".into(),
        }),
        truncated: true,
        metadata_only_recovery: true,
        wal_entries_retained: 2,
        checkpoint_height_retained: Some(2),
    };

    let err = metadata_only_recovery_error(&wal_dir, &recovered);

    assert!(err.contains("retained 2 committed WAL entries through height 2"));
    assert!(err.contains("last retained checkpoint: 2"));
    assert!(err.contains("next startup height: 3"));
    assert!(!err.contains("checkpoint lags retained WAL tip"));
    assert!(!err.contains("no retained checkpoint metadata"));

    let _ = fs::remove_dir_all(&wal_dir);
}

#[test]
fn ensure_recoverable_wal_state_rejects_metadata_only_recovery_with_singular_checkpoint_lag() {
    let wal_dir = temp_wal_dir("recover-guard-metadata-only-singular-lag");
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
    assert!(err.contains("checkpoint lags retained WAL tip by 1 block"));
    assert!(!err.contains("checkpoint lags retained WAL tip by 1 blocks"));
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
