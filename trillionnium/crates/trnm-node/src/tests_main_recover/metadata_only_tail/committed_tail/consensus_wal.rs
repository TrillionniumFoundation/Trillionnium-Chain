use super::*;

#[test]
fn recover_committed_tail_beyond_checkpoint_rewrites_consensus_wal_fail_closed() {
    let wal_dir = temp_wal_dir("recover-committed-tail-beyond-checkpoint-rewrites-wal");
    fs::create_dir_all(&wal_dir).unwrap();

    let e1 = WalMeta {
        height: 1,
        round: 3,
        proposal_hash: "h1".into(),
        committed: true,
        state_root_hex: "r1".into(),
        prev_hash_hex: None,
    };
    let h1 = e1.content_hash_hex();
    let e2 = WalMeta {
        height: 2,
        round: 4,
        proposal_hash: "h2".into(),
        committed: true,
        state_root_hex: "r2".into(),
        prev_hash_hex: Some(h1.clone()),
    };

    persist_wal_meta_entries(&wal_dir, &[e1, e2]).unwrap();
    persist_checkpoint_meta(
        &wal_dir,
        &[CheckpointMeta {
            height: 1,
            state_root_hex: "r1".into(),
            wal_entry_hash_hex: h1,
        }],
    )
    .unwrap();
    fs::write(
        wal_file(&wal_dir),
        r#"next_height = 99
last_round = 42
locked_block_hash = "stale-lock"
"#,
    )
    .unwrap();

    let recovered = recover_wal_state(&wal_dir).unwrap();
    assert_eq!(recovered.next_height, 2);
    assert!(recovered.truncated);
    assert!(recovered.metadata_only_recovery);
    assert!(recovered.restored_lock.is_none());
    assert_eq!(recovered.checkpoint_height_retained, Some(1));
    assert_eq!(recovered.wal_entries_retained, 1);

    let wal = fs::read_to_string(wal_file(&wal_dir)).unwrap();
    let wal: ConsensusWal = toml::from_str(&wal).unwrap();
    assert_eq!(wal.next_height, 2);
    assert_eq!(wal.last_round, 3);
    assert!(wal.locked_block_hash.is_none());

    let _ = fs::remove_dir_all(&wal_dir);
}
