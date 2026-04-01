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
    let wal = fs::read_to_string(wal_file(&wal_dir)).unwrap();
    let wal: ConsensusWal = toml::from_str(&wal).unwrap();
    assert_eq!(wal.next_height, 1);
    assert_eq!(wal.last_round, 0);
    assert!(wal.locked_block_hash.is_none());

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
fn recover_clears_checkpoint_only_snapshot_with_empty_wal_meta_scaffold_without_consensus_wal() {
    let wal_dir = temp_wal_dir("recover-checkpoint-only-empty-wal-meta-no-consensus-wal");
    fs::create_dir_all(&wal_dir).unwrap();

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
fn recover_resets_stale_consensus_wal_when_metadata_files_are_empty() {
    let wal_dir = temp_wal_dir("recover-stale-consensus-wal-without-metadata");
    fs::create_dir_all(&wal_dir).unwrap();

    persist_consensus_wal(
        &wal_dir,
        &ConsensusWal {
            next_height: 41,
            last_round: 6,
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
fn recover_resets_stale_consensus_wal_when_only_empty_wal_meta_file_exists() {
    let wal_dir = temp_wal_dir("recover-stale-consensus-wal-with-empty-wal-meta");
    fs::create_dir_all(&wal_dir).unwrap();

    persist_consensus_wal(
        &wal_dir,
        &ConsensusWal {
            next_height: 23,
            last_round: 5,
            locked_block_hash: Some("stale-lock".into()),
        },
    )
    .unwrap();
    persist_wal_meta_entries(&wal_dir, &[]).unwrap();

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
    assert!(checkpoint_file(&wal_dir).exists());
    assert!(wal_file(&wal_dir).exists());
    let wal = fs::read_to_string(wal_file(&wal_dir)).unwrap();
    let wal: ConsensusWal = toml::from_str(&wal).unwrap();
    assert_eq!(wal.next_height, 1);
    assert_eq!(wal.last_round, 0);
    assert!(wal.locked_block_hash.is_none());

    let _ = fs::remove_dir_all(&wal_dir);
}

#[test]
fn recover_resets_stale_consensus_wal_when_both_empty_metadata_files_exist() {
    let wal_dir = temp_wal_dir("recover-stale-consensus-wal-with-both-empty-metadata-files");
    fs::create_dir_all(&wal_dir).unwrap();

    persist_consensus_wal(
        &wal_dir,
        &ConsensusWal {
            next_height: 37,
            last_round: 7,
            locked_block_hash: Some("stale-lock".into()),
        },
    )
    .unwrap();
    persist_wal_meta_entries(&wal_dir, &[]).unwrap();
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
    assert!(wal_meta_file(&wal_dir).exists());
    assert!(checkpoint_file(&wal_dir).exists());
    assert!(wal_file(&wal_dir).exists());
    let wal = fs::read_to_string(wal_file(&wal_dir)).unwrap();
    let wal: ConsensusWal = toml::from_str(&wal).unwrap();
    assert_eq!(wal.next_height, 1);
    assert_eq!(wal.last_round, 0);
    assert!(wal.locked_block_hash.is_none());

    let _ = fs::remove_dir_all(&wal_dir);
}
