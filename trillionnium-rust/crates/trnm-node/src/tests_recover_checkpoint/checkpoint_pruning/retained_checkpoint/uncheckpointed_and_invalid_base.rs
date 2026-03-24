use super::*;

#[test]
fn recover_discards_uncheckpointed_wal_without_claiming_recovery() {
    let wal_dir = temp_wal_dir("recover-uncheckpointed");
    fs::create_dir_all(&wal_dir).unwrap();

    persist_consensus_wal(
        &wal_dir,
        &ConsensusWal {
            next_height: 9,
            last_round: 4,
            locked_block_hash: Some("stale-lock".into()),
        },
    )
    .unwrap();

    let e1 = WalMeta {
        height: 1,
        round: 0,
        proposal_hash: "h1".into(),
        committed: true,
        state_root_hex: "r1".into(),
        prev_hash_hex: None,
    };
    persist_wal_meta_entries(&wal_dir, &[e1]).unwrap();

    let recovered = recover_wal_state(&wal_dir).unwrap();
    assert_eq!(recovered.next_height, 1);
    assert!(recovered.restored_lock.is_none());
    assert!(recovered.last_checkpoint.is_none());
    assert!(recovered.truncated);
    assert!(!recovered.metadata_only_recovery);
    assert_eq!(recovered.wal_entries_retained, 0);
    assert!(load_wal_meta_entries(&wal_dir).unwrap().is_empty());

    let wal = fs::read_to_string(wal_file(&wal_dir)).unwrap();
    let wal: ConsensusWal = toml::from_str(&wal).unwrap();
    assert_eq!(wal.next_height, 1);
    assert_eq!(wal.last_round, 0);
    assert!(wal.locked_block_hash.is_none());

    let _ = fs::remove_dir_all(&wal_dir);
}

#[test]
fn recover_discards_uncheckpointed_wal_that_starts_above_genesis_without_claiming_recovery() {
    let wal_dir = temp_wal_dir("recover-uncheckpointed-starts-above-genesis");
    fs::create_dir_all(&wal_dir).unwrap();

    persist_consensus_wal(
        &wal_dir,
        &ConsensusWal {
            next_height: 12,
            last_round: 5,
            locked_block_hash: Some("stale-lock".into()),
        },
    )
    .unwrap();

    let e2 = WalMeta {
        height: 2,
        round: 0,
        proposal_hash: "h2".into(),
        committed: true,
        state_root_hex: "r2".into(),
        prev_hash_hex: None,
    };
    persist_wal_meta_entries(&wal_dir, &[e2]).unwrap();

    let recovered = recover_wal_state(&wal_dir).unwrap();
    assert_eq!(recovered.next_height, 1);
    assert!(recovered.restored_lock.is_none());
    assert!(recovered.last_checkpoint.is_none());
    assert!(recovered.truncated);
    assert!(!recovered.metadata_only_recovery);
    assert_eq!(recovered.wal_entries_retained, 0);
    assert_eq!(recovered.checkpoint_height_retained, None);
    assert!(load_wal_meta_entries(&wal_dir).unwrap().is_empty());
    assert!(load_checkpoint_meta(&wal_dir).unwrap().is_empty());

    let wal = fs::read_to_string(wal_file(&wal_dir)).unwrap();
    let wal: ConsensusWal = toml::from_str(&wal).unwrap();
    assert_eq!(wal.next_height, 1);
    assert_eq!(wal.last_round, 0);
    assert!(wal.locked_block_hash.is_none());

    let _ = fs::remove_dir_all(&wal_dir);
}

#[test]
fn recover_rejects_checkpointed_wal_chain_without_genesis_base() {
    let wal_dir = temp_wal_dir("recover-no-genesis-base");
    fs::create_dir_all(&wal_dir).unwrap();

    let e10 = WalMeta {
        height: 10,
        round: 0,
        proposal_hash: "h10".into(),
        committed: true,
        state_root_hex: "r10".into(),
        prev_hash_hex: None,
    };

    persist_wal_meta_entries(&wal_dir, &[e10.clone()]).unwrap();
    persist_checkpoint_meta(
        &wal_dir,
        &[CheckpointMeta {
            height: 10,
            state_root_hex: "r10".into(),
            wal_entry_hash_hex: e10.content_hash_hex(),
        }],
    )
    .unwrap();
    persist_consensus_wal(
        &wal_dir,
        &ConsensusWal {
            next_height: 99,
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

    let retained = load_wal_meta_entries(&wal_dir).unwrap();
    assert!(retained.is_empty());
    let checkpoints = load_checkpoint_meta(&wal_dir).unwrap();
    assert!(checkpoints.is_empty());
    let wal = fs::read_to_string(wal_file(&wal_dir)).unwrap();
    let wal: ConsensusWal = toml::from_str(&wal).unwrap();
    assert_eq!(wal.next_height, 1);
    assert_eq!(wal.last_round, 0);
    assert!(wal.locked_block_hash.is_none());

    let _ = fs::remove_dir_all(&wal_dir);
}
