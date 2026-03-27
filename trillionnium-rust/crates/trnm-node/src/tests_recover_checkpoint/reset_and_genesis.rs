use super::*;

#[test]
fn recover_clears_orphan_checkpoints_when_wal_is_empty() {
    let wal_dir = temp_wal_dir("recover-orphan-checkpoints");
    fs::create_dir_all(&wal_dir).unwrap();

    persist_checkpoint_meta(
        &wal_dir,
        &[CheckpointMeta {
            height: 7,
            state_root_hex: "stale-root".into(),
            wal_entry_hash_hex: "stale-hash".into(),
        }],
    )
    .unwrap();

    let recovered = recover_wal_state(&wal_dir).unwrap();
    assert_eq!(recovered.next_height, 1);
    assert!(recovered.restored_lock.is_none());
    assert!(recovered.last_checkpoint.is_none());
    assert!(recovered.truncated);
    assert!(!recovered.metadata_only_recovery);
    assert_eq!(recovered.wal_entries_retained, 0);

    let checkpoints = load_checkpoint_meta(&wal_dir).unwrap();
    assert!(checkpoints.is_empty());

    let _ = fs::remove_dir_all(&wal_dir);
}

#[test]
fn recover_clears_checkpoint_only_snapshot_even_when_consensus_wal_file_exists() {
    let wal_dir = temp_wal_dir("recover-checkpoint-only-snapshot");
    fs::create_dir_all(&wal_dir).unwrap();

    persist_consensus_wal(
        &wal_dir,
        &ConsensusWal {
            next_height: 8,
            last_round: 3,
            locked_block_hash: Some("stale-lock".into()),
        },
    )
    .unwrap();
    persist_checkpoint_meta(
        &wal_dir,
        &[CheckpointMeta {
            height: 7,
            state_root_hex: "stale-root".into(),
            wal_entry_hash_hex: "stale-hash".into(),
        }],
    )
    .unwrap();

    let recovered = recover_wal_state(&wal_dir).unwrap();
    assert_eq!(recovered.next_height, 1);
    assert!(recovered.restored_lock.is_none());
    assert!(recovered.last_checkpoint.is_none());
    assert!(recovered.truncated);
    assert!(!recovered.metadata_only_recovery);
    assert_eq!(recovered.wal_entries_retained, 0);

    let checkpoints = load_checkpoint_meta(&wal_dir).unwrap();
    assert!(checkpoints.is_empty());
    let wal = fs::read_to_string(wal_file(&wal_dir)).unwrap();
    let wal: ConsensusWal = toml::from_str(&wal).unwrap();
    assert_eq!(wal.next_height, 1);
    assert_eq!(wal.last_round, 0);
    assert!(wal.locked_block_hash.is_none());

    let _ = fs::remove_dir_all(&wal_dir);
}

#[test]
fn recover_clears_checkpoint_only_snapshot_even_when_empty_wal_meta_file_exists() {
    let wal_dir = temp_wal_dir("recover-checkpoint-only-with-empty-wal-meta");
    fs::create_dir_all(&wal_dir).unwrap();

    persist_consensus_wal(
        &wal_dir,
        &ConsensusWal {
            next_height: 15,
            last_round: 2,
            locked_block_hash: Some("stale-lock".into()),
        },
    )
    .unwrap();
    persist_wal_meta_entries(&wal_dir, &[]).unwrap();
    persist_checkpoint_meta(
        &wal_dir,
        &[CheckpointMeta {
            height: 14,
            state_root_hex: "stale-root".into(),
            wal_entry_hash_hex: "stale-hash".into(),
        }],
    )
    .unwrap();

    let recovered = recover_wal_state(&wal_dir).unwrap();
    assert_eq!(recovered.next_height, 1);
    assert!(recovered.restored_lock.is_none());
    assert!(recovered.last_checkpoint.is_none());
    assert!(recovered.truncated);
    assert!(!recovered.metadata_only_recovery);
    assert_eq!(recovered.wal_entries_retained, 0);
    assert_eq!(recovered.checkpoint_height_retained, None);

    let entries = load_wal_meta_entries(&wal_dir).unwrap();
    assert!(entries.is_empty());
    let checkpoints = load_checkpoint_meta(&wal_dir).unwrap();
    assert!(checkpoints.is_empty());
    let wal = fs::read_to_string(wal_file(&wal_dir)).unwrap();
    let wal: ConsensusWal = toml::from_str(&wal).unwrap();
    assert_eq!(wal.next_height, 1);
    assert_eq!(wal.last_round, 0);
    assert!(wal.locked_block_hash.is_none());

    let _ = fs::remove_dir_all(&wal_dir);
}

#[test]
fn recover_resets_stale_consensus_wal_when_only_empty_checkpoint_file_exists() {
    let wal_dir = temp_wal_dir("recover-stale-consensus-wal-with-empty-checkpoint-file");
    fs::create_dir_all(&wal_dir).unwrap();

    persist_consensus_wal(
        &wal_dir,
        &ConsensusWal {
            next_height: 29,
            last_round: 4,
            locked_block_hash: Some("stale-lock".into()),
        },
    )
    .unwrap();
    persist_checkpoint_meta(&wal_dir, &[]).unwrap();

    let recovered = recover_wal_state(&wal_dir).unwrap();
    assert_eq!(recovered.next_height, 1);
    assert!(recovered.restored_lock.is_none());
    assert!(recovered.last_checkpoint.is_none());
    assert!(recovered.truncated);
    assert!(!recovered.metadata_only_recovery);
    assert_eq!(recovered.wal_entries_retained, 0);
    assert_eq!(recovered.checkpoint_height_retained, None);

    let entries = load_wal_meta_entries(&wal_dir).unwrap();
    assert!(entries.is_empty());
    let checkpoints = load_checkpoint_meta(&wal_dir).unwrap();
    assert!(checkpoints.is_empty());
    let wal = fs::read_to_string(wal_file(&wal_dir)).unwrap();
    let wal: ConsensusWal = toml::from_str(&wal).unwrap();
    assert_eq!(wal.next_height, 1);
    assert_eq!(wal.last_round, 0);
    assert!(wal.locked_block_hash.is_none());

    let _ = fs::remove_dir_all(&wal_dir);
}

#[test]
fn recover_rejects_uncommitted_genesis_entry_even_with_checkpoint_metadata() {
    let wal_dir = temp_wal_dir("recover-uncommitted-genesis-entry");
    fs::create_dir_all(&wal_dir).unwrap();

    let e1 = WalMeta {
        height: 1,
        round: 0,
        proposal_hash: "h1".into(),
        committed: false,
        state_root_hex: "r1".into(),
        prev_hash_hex: None,
    };

    persist_wal_meta_entries(&wal_dir, &[e1.clone()]).unwrap();
    persist_checkpoint_meta(
        &wal_dir,
        &[CheckpointMeta {
            height: 1,
            state_root_hex: "r1".into(),
            wal_entry_hash_hex: e1.content_hash_hex(),
        }],
    )
    .unwrap();
    persist_consensus_wal(
        &wal_dir,
        &ConsensusWal {
            next_height: 77,
            last_round: 9,
            locked_block_hash: Some("stale-lock".into()),
        },
    )
    .unwrap();

    let recovered = recover_wal_state(&wal_dir).unwrap();
    assert_eq!(recovered.next_height, 1);
    assert!(recovered.restored_lock.is_none());
    assert!(recovered.last_checkpoint.is_none());
    assert!(recovered.truncated);
    assert!(!recovered.metadata_only_recovery);
    assert_eq!(recovered.wal_entries_retained, 0);
    assert_eq!(recovered.checkpoint_height_retained, None);

    let entries = load_wal_meta_entries(&wal_dir).unwrap();
    assert!(entries.is_empty());
    let checkpoints = load_checkpoint_meta(&wal_dir).unwrap();
    assert!(checkpoints.is_empty());
    let wal = fs::read_to_string(wal_file(&wal_dir)).unwrap();
    let wal: ConsensusWal = toml::from_str(&wal).unwrap();
    assert_eq!(wal.next_height, 1);
    assert_eq!(wal.last_round, 0);
    assert!(wal.locked_block_hash.is_none());

    let _ = fs::remove_dir_all(&wal_dir);
}

#[test]
fn recover_rejects_genesis_entry_with_non_genesis_prev_hash_even_with_checkpoint_metadata() {
    let wal_dir = temp_wal_dir("recover-genesis-prev-hash");
    fs::create_dir_all(&wal_dir).unwrap();

    let e1 = WalMeta {
        height: 1,
        round: 0,
        proposal_hash: "h1".into(),
        committed: true,
        state_root_hex: "r1".into(),
        prev_hash_hex: Some("forged-parent".into()),
    };

    persist_wal_meta_entries(&wal_dir, &[e1.clone()]).unwrap();
    persist_checkpoint_meta(
        &wal_dir,
        &[CheckpointMeta {
            height: 1,
            state_root_hex: "r1".into(),
            wal_entry_hash_hex: e1.content_hash_hex(),
        }],
    )
    .unwrap();
    persist_consensus_wal(
        &wal_dir,
        &ConsensusWal {
            next_height: 42,
            last_round: 5,
            locked_block_hash: Some("stale-lock".into()),
        },
    )
    .unwrap();

    let recovered = recover_wal_state(&wal_dir).unwrap();
    assert_eq!(recovered.next_height, 1);
    assert!(recovered.restored_lock.is_none());
    assert!(recovered.last_checkpoint.is_none());
    assert!(recovered.truncated);
    assert!(!recovered.metadata_only_recovery);
    assert_eq!(recovered.wal_entries_retained, 0);
    assert_eq!(recovered.checkpoint_height_retained, None);

    let entries = load_wal_meta_entries(&wal_dir).unwrap();
    assert!(entries.is_empty());
    let checkpoints = load_checkpoint_meta(&wal_dir).unwrap();
    assert!(checkpoints.is_empty());
    let wal = fs::read_to_string(wal_file(&wal_dir)).unwrap();
    let wal: ConsensusWal = toml::from_str(&wal).unwrap();
    assert_eq!(wal.next_height, 1);
    assert_eq!(wal.last_round, 0);
    assert!(wal.locked_block_hash.is_none());

    let _ = fs::remove_dir_all(&wal_dir);
}

#[test]
fn recover_rejects_checkpointed_wal_chain_that_starts_above_genesis_height() {
    let wal_dir = temp_wal_dir("recover-starts-above-genesis-height");
    fs::create_dir_all(&wal_dir).unwrap();

    let e2 = WalMeta {
        height: 2,
        round: 0,
        proposal_hash: "h2".into(),
        committed: true,
        state_root_hex: "r2".into(),
        prev_hash_hex: None,
    };

    persist_wal_meta_entries(&wal_dir, &[e2.clone()]).unwrap();
    persist_checkpoint_meta(
        &wal_dir,
        &[CheckpointMeta {
            height: 2,
            state_root_hex: "r2".into(),
            wal_entry_hash_hex: e2.content_hash_hex(),
        }],
    )
    .unwrap();
    persist_consensus_wal(
        &wal_dir,
        &ConsensusWal {
            next_height: 88,
            last_round: 7,
            locked_block_hash: Some("stale-lock".into()),
        },
    )
    .unwrap();

    let recovered = recover_wal_state(&wal_dir).unwrap();
    assert_eq!(recovered.next_height, 1);
    assert!(recovered.restored_lock.is_none());
    assert!(recovered.last_checkpoint.is_none());
    assert!(recovered.truncated);
    assert!(!recovered.metadata_only_recovery);
    assert_eq!(recovered.wal_entries_retained, 0);
    assert_eq!(recovered.checkpoint_height_retained, None);

    let entries = load_wal_meta_entries(&wal_dir).unwrap();
    assert!(entries.is_empty());
    let checkpoints = load_checkpoint_meta(&wal_dir).unwrap();
    assert!(checkpoints.is_empty());
    let wal = fs::read_to_string(wal_file(&wal_dir)).unwrap();
    let wal: ConsensusWal = toml::from_str(&wal).unwrap();
    assert_eq!(wal.next_height, 1);
    assert_eq!(wal.last_round, 0);
    assert!(wal.locked_block_hash.is_none());

    let _ = fs::remove_dir_all(&wal_dir);
}

