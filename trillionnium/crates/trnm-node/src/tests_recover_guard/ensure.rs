use super::*;

#[test]
fn ensure_recoverable_wal_state_rejects_metadata_only_recovery() {
    let wal_dir = temp_wal_dir("recover-guard-metadata-only");
    fs::create_dir_all(&wal_dir).unwrap();

    let wal1 = WalMeta {
        height: 1,
        round: 0,
        proposal_hash: "proposal-1".into(),
        committed: true,
        state_root_hex: "11".repeat(32),
        prev_hash_hex: None,
    };
    let wal1_hash = wal1.content_hash_hex();
    let wal2 = WalMeta {
        height: 2,
        round: 1,
        proposal_hash: "proposal-2".into(),
        committed: true,
        state_root_hex: "22".repeat(32),
        prev_hash_hex: Some(wal1_hash),
    };
    let wal2_hash = wal2.content_hash_hex();
    let wal3 = WalMeta {
        height: 3,
        round: 1,
        proposal_hash: "proposal-3".into(),
        committed: true,
        state_root_hex: "33".repeat(32),
        prev_hash_hex: Some(wal2_hash),
    };
    let wal_entries = vec![wal1, wal2, wal3];
    persist_wal_meta_entries(&wal_dir, &wal_entries).unwrap();
    let checkpoint = CheckpointMeta {
        height: 2,
        state_root_hex: wal_entries[1].state_root_hex.clone(),
        wal_entry_hash_hex: wal_entries[1].content_hash_hex(),
    };

    let recovered = RecoveredWalState {
        next_height: 4,
        restored_lock: None,
        last_checkpoint: Some(checkpoint.clone()),
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
    assert!(err.contains("checkpoint_evidence:"));
    assert!(err.contains("checkpoint_commitment="));
    assert!(err.contains("checkpoint_da_surface:"));
    assert!(err.contains("da_light_surface=checkpoint-wal-v1"));
    assert!(err.contains("light_verifier_surface=checkpoint-wal-v1"));
    assert!(err.contains("checkpoint_height_matches_wal=true"));
    assert!(err.contains("checkpoint_wal_entry_hash_matches_wal=true"));
    assert!(err.contains("wal_content_hash_matches_checkpoint=true"));

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

#[test]
fn ensure_recoverable_wal_state_allows_checkpoint_only_bootstrap_after_tail_repair() {
    let wal_dir = temp_wal_dir("recover-guard-checkpoint-only-tail-repair");
    fs::create_dir_all(&wal_dir).unwrap();

    let recovered = RecoveredWalState {
        next_height: 9,
        restored_lock: None,
        last_checkpoint: Some(CheckpointMeta {
            height: 8,
            state_root_hex: "r8".into(),
            wal_entry_hash_hex: "h8".into(),
        }),
        truncated: true,
        metadata_only_recovery: false,
        wal_entries_retained: 0,
        checkpoint_height_retained: Some(8),
    };

    ensure_recoverable_wal_state(&wal_dir, &recovered).unwrap();

    let _ = fs::remove_dir_all(&wal_dir);
}

#[test]
fn ensure_recoverable_wal_state_allows_single_block_lagging_checkpoint_resume() {
    let wal_dir = temp_wal_dir("recover-guard-lagging-checkpoint-resume");
    fs::create_dir_all(&wal_dir).unwrap();

    let recovered = RecoveredWalState {
        next_height: 8,
        restored_lock: Some("h7".into()),
        last_checkpoint: Some(CheckpointMeta {
            height: 6,
            state_root_hex: "r6".into(),
            wal_entry_hash_hex: "h6".into(),
        }),
        truncated: false,
        metadata_only_recovery: false,
        wal_entries_retained: 2,
        checkpoint_height_retained: Some(6),
    };

    ensure_recoverable_wal_state(&wal_dir, &recovered)
        .expect("single-block lagging checkpoint resume should remain admissible for join/rejoin catch-up");
    assert_eq!(recovery_startup_summary(&recovered), "retained_wal_entries=2 checkpoint_height_retained=6 checkpoint_tip_relation=behind:1 next_startup_height=8 wal_tail_truncated=false metadata_only_recovery=false join_rejoin_status=ready:retained_wal_resume_checkpoint_lagging");

    let _ = fs::remove_dir_all(&wal_dir);
}
