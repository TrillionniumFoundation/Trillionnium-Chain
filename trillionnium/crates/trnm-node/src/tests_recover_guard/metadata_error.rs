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
    assert!(!err.contains("checkpoint lags retained WAL tip by 1 blocks"));
    assert!(err.contains("last retained checkpoint: 1"));
    assert!(err.contains("next startup height: 3"));
    assert!(err.contains(
        "does not yet restore application StateStore snapshots or replay committed blocks"
    ));
    assert!(err.contains(
        "operator action: restore an application snapshot that covers retained WAL tip height 2 before retrying join/rejoin; retained checkpoint height 1 is 1 block behind, so do not resume from metadata alone"
    ));

    let _ = fs::remove_dir_all(&wal_dir);
}

#[test]
fn recover_metadata_only_error_reports_multi_block_checkpoint_lag() {
    let wal_dir = temp_wal_dir("recover-metadata-only-error-multi-block-lag");
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
    assert!(!err.contains("checkpoint lags retained WAL tip by 2 block)"));
    assert!(err.contains("last retained checkpoint: 2"));
    assert!(err.contains("next startup height: 5"));

    let _ = fs::remove_dir_all(&wal_dir);
}

#[test]
fn recover_metadata_only_error_reports_singular_checkpoint_ahead_mismatch_operator_action() {
    let wal_dir = temp_wal_dir("recover-metadata-only-error-singular-checkpoint-ahead");
    fs::create_dir_all(&wal_dir).unwrap();

    let recovered = RecoveredWalState {
        next_height: 12,
        restored_lock: None,
        last_checkpoint: Some(CheckpointMeta {
            height: 12,
            state_root_hex: "r12".into(),
            wal_entry_hash_hex: "h12".into(),
        }),
        truncated: true,
        metadata_only_recovery: true,
        wal_entries_retained: 2,
        checkpoint_height_retained: Some(12),
    };

    let err = metadata_only_recovery_error(&wal_dir, &recovered);

    assert!(err.contains("retained 2 committed WAL entries through height 11"));
    assert!(err.contains(
        "retained checkpoint height 12 is ahead of retained WAL tip height 11 by 1 block"
    ));
    assert!(!err.contains("checkpoint leads tip by 1 blocks"));
    assert!(err.contains("last retained checkpoint: 12"));
    assert!(err.contains("next startup height: 12"));
    assert!(err.contains(
        "operator action: investigate WAL/checkpoint mismatch (retained WAL tip height 11, checkpoint height 12, checkpoint leads tip by 1 block), rebuild the recovery inputs, and only retry join/rejoin once WAL tip and checkpoint evidence agree"
    ));
    assert!(err.contains(
        "note: this startup already truncated a malformed WAL tail, so keep the repaired WAL/checkpoint artifacts for incident review if join/rejoin still fails"
    ));

    let _ = fs::remove_dir_all(&wal_dir);
}
