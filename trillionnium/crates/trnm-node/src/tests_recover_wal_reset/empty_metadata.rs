use super::*;

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
