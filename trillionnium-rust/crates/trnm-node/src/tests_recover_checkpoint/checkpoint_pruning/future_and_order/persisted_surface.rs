use super::*;

#[test]
fn persist_checkpoint_meta_writes_canonical_checkpoint_order_for_da_consumers() {
    let wal_dir = temp_wal_dir("persist-canonicalize-checkpoints-da-surface");
    fs::create_dir_all(&wal_dir).unwrap();

    persist_checkpoint_meta(
        &wal_dir,
        &[
            CheckpointMeta {
                height: 2,
                state_root_hex: "root-z".into(),
                wal_entry_hash_hex: "hash-b".into(),
            },
            CheckpointMeta {
                height: 1,
                state_root_hex: "root-a".into(),
                wal_entry_hash_hex: "hash-c".into(),
            },
            CheckpointMeta {
                height: 2,
                state_root_hex: "root-a".into(),
                wal_entry_hash_hex: "hash-a".into(),
            },
        ],
    )
    .unwrap();

    let checkpoints = load_checkpoint_meta(&wal_dir).unwrap();
    assert_eq!(checkpoints.len(), 3);
    assert_eq!(checkpoints[0].height, 1);
    assert_eq!(checkpoints[0].wal_entry_hash_hex, "hash-c");
    assert_eq!(checkpoints[1].height, 2);
    assert_eq!(checkpoints[1].wal_entry_hash_hex, "hash-a");
    assert_eq!(checkpoints[1].state_root_hex, "root-a");
    assert_eq!(checkpoints[2].height, 2);
    assert_eq!(checkpoints[2].wal_entry_hash_hex, "hash-b");
    assert_eq!(checkpoints[2].state_root_hex, "root-z");

    let raw = fs::read_to_string(checkpoint_file(&wal_dir)).unwrap();
    let height1_pos = raw.find("height = 1").unwrap();
    let hash_a_pos = raw.find("wal_entry_hash_hex = \"hash-a\"").unwrap();
    let hash_b_pos = raw.find("wal_entry_hash_hex = \"hash-b\"").unwrap();
    assert!(height1_pos < hash_a_pos);
    assert!(hash_a_pos < hash_b_pos);

    let _ = fs::remove_dir_all(&wal_dir);
}
