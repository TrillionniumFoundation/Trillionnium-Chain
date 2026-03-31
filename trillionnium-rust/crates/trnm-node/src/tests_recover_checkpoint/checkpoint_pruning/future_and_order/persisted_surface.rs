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

#[test]
fn checkpoint_surface_roundtrip_keeps_conflicting_state_roots_distinct_for_same_wal_hash() {
    let wal_dir = temp_wal_dir("checkpoint-surface-conflicting-state-roots-same-wal-hash");
    fs::create_dir_all(&wal_dir).unwrap();

    let original = toml::to_string(&CheckpointMetaList {
        checkpoints: vec![
            CheckpointMeta {
                height: 12,
                state_root_hex: "root-z".into(),
                wal_entry_hash_hex: "shared-hash".into(),
            },
            CheckpointMeta {
                height: 12,
                state_root_hex: "root-a".into(),
                wal_entry_hash_hex: "shared-hash".into(),
            },
        ],
    })
    .unwrap();
    fs::write(checkpoint_file(&wal_dir), original).unwrap();

    let canonicalized = load_checkpoint_meta(&wal_dir).unwrap();
    assert_eq!(canonicalized.len(), 2);
    assert_eq!(canonicalized[0].state_root_hex, "root-a");
    assert_eq!(canonicalized[1].state_root_hex, "root-z");
    assert_eq!(canonicalized[0].wal_entry_hash_hex, "shared-hash");
    assert_eq!(canonicalized[1].wal_entry_hash_hex, "shared-hash");

    persist_checkpoint_meta(&wal_dir, &canonicalized).unwrap();
    let first_pass = fs::read_to_string(checkpoint_file(&wal_dir)).unwrap();
    persist_checkpoint_meta(&wal_dir, &canonicalized).unwrap();
    let second_pass = fs::read_to_string(checkpoint_file(&wal_dir)).unwrap();

    assert_eq!(
        first_pass, second_pass,
        "checkpoint surface must serialize to stable canonical bytes even when conflicting state roots share one wal hash so DA/light-verifier evidence linkage does not flap"
    );

    let root_a_idx = first_pass.find("state_root_hex = \"root-a\"").unwrap();
    let root_z_idx = first_pass.find("state_root_hex = \"root-z\"").unwrap();
    let shared_hash_count = first_pass.matches("wal_entry_hash_hex = \"shared-hash\"").count();
    assert!(
        root_a_idx < root_z_idx,
        "conflicting state roots must remain canonically ordered for a shared wal hash on the persisted checkpoint surface"
    );
    assert_eq!(
        shared_hash_count, 2,
        "shared wal-hash checkpoint evidence must not collapse distinct state roots on roundtrip"
    );

    let _ = fs::remove_dir_all(&wal_dir);
}

#[test]
fn checkpoint_surface_roundtrip_keeps_same_state_root_distinct_for_different_wal_hashes() {
    let wal_dir = temp_wal_dir("checkpoint-surface-same-state-root-distinct-wal-hashes");
    fs::create_dir_all(&wal_dir).unwrap();

    let original = toml::to_string(&CheckpointMetaList {
        checkpoints: vec![
            CheckpointMeta {
                height: 12,
                state_root_hex: "root-a".into(),
                wal_entry_hash_hex: "hash-z".into(),
            },
            CheckpointMeta {
                height: 12,
                state_root_hex: "root-a".into(),
                wal_entry_hash_hex: "hash-a".into(),
            },
        ],
    })
    .unwrap();
    fs::write(checkpoint_file(&wal_dir), original).unwrap();

    let canonicalized = load_checkpoint_meta(&wal_dir).unwrap();
    assert_eq!(canonicalized.len(), 2);
    assert_eq!(canonicalized[0].state_root_hex, "root-a");
    assert_eq!(canonicalized[1].state_root_hex, "root-a");
    assert_eq!(canonicalized[0].wal_entry_hash_hex, "hash-a");
    assert_eq!(canonicalized[1].wal_entry_hash_hex, "hash-z");

    persist_checkpoint_meta(&wal_dir, &canonicalized).unwrap();
    let first_pass = fs::read_to_string(checkpoint_file(&wal_dir)).unwrap();
    persist_checkpoint_meta(&wal_dir, &canonicalized).unwrap();
    let second_pass = fs::read_to_string(checkpoint_file(&wal_dir)).unwrap();

    assert_eq!(
        first_pass, second_pass,
        "checkpoint surface must serialize to stable canonical bytes even when one state_root links to multiple wal hashes so DA/light-verifier linkage evidence does not flap"
    );

    let hash_a_idx = first_pass.find("wal_entry_hash_hex = \"hash-a\"").unwrap();
    let hash_z_idx = first_pass.find("wal_entry_hash_hex = \"hash-z\"").unwrap();
    let root_a_count = first_pass.matches("state_root_hex = \"root-a\"").count();
    assert!(
        hash_a_idx < hash_z_idx,
        "same-state-root checkpoint evidence must remain canonically ordered by wal hash for persisted light-verifier surfaces"
    );
    assert_eq!(
        root_a_count, 2,
        "distinct wal-hash checkpoint evidence must not collapse just because the state_root matches on roundtrip"
    );

    let _ = fs::remove_dir_all(&wal_dir);
}
