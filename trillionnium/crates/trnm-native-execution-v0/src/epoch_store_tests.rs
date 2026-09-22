use super::*;

fn store(shape: usize) -> InMemoryNativeExecutionStoreV0 {
    let key = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
    let mut store = InMemoryNativeExecutionStoreV0::new(
        "epoch-store-test",
        vec![AuthorizedSignerV0::new(
            "operator",
            "operator",
            hex::encode(key.verifying_key().to_bytes()),
        )
        .unwrap()],
        ConsensusParametersV0::reference_shadow_v0(),
    )
    .unwrap();
    let writes = (0..shape)
        .map(|i| NativeStateWriteV0::raw(format!("key-{i}").into_bytes(), vec![i as u8]).unwrap())
        .collect();
    store.apply_seed_v0(0, writes).unwrap();
    store.apply_seed_v0(1, Vec::new()).unwrap();
    store.apply_seed_v0(2, Vec::new()).unwrap();
    store
}

// These coordinates exercise the storage algorithm only. Production callers
// cannot invoke from_coordinates; they need the opaque strict handoff receipt.
fn coordinates(store: &InMemoryNativeExecutionStoreV0) -> EpochApplicationCoordinatesV1 {
    EpochApplicationCoordinatesV1 {
        checkpoint_version: 2,
        checkpoint_root: store.parent_root_v0().unwrap().0,
        terminal_version: 4,
        first_version: 5,
        authorization_id: [9; 32],
    }
}

fn write(key: &[u8], value: &[u8]) -> CompleteStateWriteV0 {
    CompleteStateWriteV0::new(key.to_vec(), Some(value.to_vec())).unwrap()
}

#[test]
fn sparse_epoch_jmt_empty_leaf_internal_and_noop_match_contiguous_oracle() {
    for shape in [0, 1, 8] {
        for writes in [Vec::new(), vec![write(b"new-key", b"new-value")]] {
            let mut source = store(shape);
            let edge = coordinates(&source);
            let original_bytes = source.encode_authenticated_snapshot_v0().unwrap();
            let original_nodes = source.nodes.clone();
            let expected = plan_complete_state_update_v0(&source, 2, 3, writes.clone()).unwrap();
            let reader = CarriedRootReaderV1::from_coordinates(&source, edge).unwrap();
            assert_eq!(
                Sha256Jmt::new(&reader).get_root_hash(4).unwrap().0,
                edge.checkpoint_root
            );
            let plan = reader.plan(writes).unwrap();
            assert_eq!(plan.version(), 5);
            assert_eq!(plan.state_root(), expected.state_root());
            assert_eq!(
                source.encode_authenticated_snapshot_v0().unwrap(),
                original_bytes
            );
            source.apply_epoch_state_plan_v1(plan).unwrap();
            assert_eq!(
                source.roots.keys().copied().collect::<Vec<_>>(),
                vec![0, 1, 2, 5]
            );
            assert_eq!(source.verified_live_values_v0(2).unwrap().len(), shape);
            for (key, node) in original_nodes {
                assert_eq!(source.nodes.get(&key), Some(&node));
            }
            verify_absent_seal_rows(&source, edge).unwrap();
            source.validate_epoch_snapshot(&[edge]).unwrap();
            assert!(source.encode_authenticated_snapshot_v0().is_err());
            let bytes = source.encode_epoch_snapshot(&[edge]).unwrap();
            let restored = InMemoryNativeExecutionStoreV0::decode_epoch_snapshot(
                source.chain_id.clone(),
                source.signers.clone(),
                source.consensus_parameters,
                source.committed_command_ids.clone(),
                source.committed_signer_nonces.clone(),
                &bytes,
                &[edge],
            )
            .unwrap();
            assert_eq!(
                restored.verified_live_values_v0(5).unwrap(),
                source.verified_live_values_v0(5).unwrap()
            );
            assert!(
                InMemoryNativeExecutionStoreV0::decode_authenticated_snapshot_v0(
                    source.chain_id.clone(),
                    source.signers.clone(),
                    source.consensus_parameters,
                    BTreeSet::new(),
                    BTreeSet::new(),
                    &bytes,
                )
                .is_err()
            );
        }
    }
}

#[test]
fn carried_root_never_relabels_children_and_rejects_future_reads() {
    let source = store(8);
    let edge = coordinates(&source);
    let reader = CarriedRootReaderV1::from_coordinates(&source, edge).unwrap();
    let child = source
        .nodes
        .keys()
        .find(|key| !key.nibble_path().is_empty())
        .unwrap();
    assert_eq!(
        reader.get_node_option(child).unwrap(),
        source.get_node_option(child).unwrap()
    );
    let virtual_child = NodeKey::new(4, child.nibble_path().clone());
    assert!(reader.get_node_option(&virtual_child).unwrap().is_none());
    let hash = authenticated_key_hash_v0(b"key-0").unwrap();
    assert_eq!(
        reader.get_value_option(4, hash).unwrap(),
        source.get_value_option(2, hash).unwrap()
    );
    assert!(reader.get_value_option(5, hash).is_err());
    assert!(reader
        .get_node_option(&NodeKey::new(5, child.nibble_path().clone()))
        .is_err());
}

#[test]
fn epoch_reader_rejects_wrong_root_skip_and_real_seal_rows() {
    let source = store(1);
    let edge = coordinates(&source);
    for bad in [
        EpochApplicationCoordinatesV1 {
            checkpoint_root: [1; 32],
            ..edge
        },
        EpochApplicationCoordinatesV1 {
            first_version: 6,
            ..edge
        },
        EpochApplicationCoordinatesV1 {
            terminal_version: 3,
            ..edge
        },
        EpochApplicationCoordinatesV1 {
            authorization_id: [0; 32],
            ..edge
        },
    ] {
        assert!(CarriedRootReaderV1::from_coordinates(&source, bad).is_err());
    }
    let mut hidden_write = source.clone();
    hidden_write.values.insert(
        (authenticated_key_hash_v0(b"key-0").unwrap(), 3),
        Some(vec![9]),
    );
    assert!(CarriedRootReaderV1::from_coordinates(&hidden_write, edge).is_err());
    let mut hidden_node = source.clone();
    let (key, node) = source.nodes.iter().next().unwrap();
    hidden_node
        .nodes
        .insert(NodeKey::new(4, key.nibble_path().clone()), node.clone());
    assert!(CarriedRootReaderV1::from_coordinates(&hidden_node, edge).is_err());
}

#[test]
fn epoch_plan_rejects_stale_fork_without_mutation_and_prepared_children_are_exact() {
    let mut source = store(2);
    let edge = coordinates(&source);
    let plan = CarriedRootReaderV1::from_coordinates(&source, edge)
        .unwrap()
        .plan(vec![write(b"x", b"x")])
        .unwrap();
    let mut fork = store(3);
    let before = fork.encode_authenticated_snapshot_v0().unwrap();
    assert!(fork.apply_epoch_state_plan_v1(plan).is_err());
    assert_eq!(fork.encode_authenticated_snapshot_v0().unwrap(), before);
    let plan = CarriedRootReaderV1::from_coordinates(&source, edge)
        .unwrap()
        .plan(vec![write(b"x", b"x")])
        .unwrap();
    source.apply_epoch_state_plan_v1(plan).unwrap();
    for version in [6, 7] {
        let plan = plan_complete_state_update_v0(
            &source,
            version - 1,
            version,
            vec![write(b"x", &[version as u8])],
        )
        .unwrap();
        source.apply_complete_state_plan_v0(plan).unwrap();
        assert_eq!(
            source
                .verified_live_values_v0(version)
                .unwrap()
                .get(b"x".as_slice()),
            Some(&vec![version as u8])
        );
    }
    source.validate_epoch_snapshot(&[edge]).unwrap();
    assert!(source.validate_snapshot_v0().is_err());
    assert!(source.validate_epoch_snapshot(&[]).is_err());
    assert!(plan_complete_state_update_v0(&source, 7, 10, Vec::new()).is_err());
}

#[test]
fn sparse_snapshot_reopen_rejects_missing_edge_corruption_and_truncation() {
    let mut source = store(8);
    let edge = coordinates(&source);
    let plan = CarriedRootReaderV1::from_coordinates(&source, edge)
        .unwrap()
        .plan(vec![write(b"x", b"y")])
        .unwrap();
    source.apply_epoch_state_plan_v1(plan).unwrap();
    let bytes = source.encode_epoch_snapshot(&[edge]).unwrap();
    let reopen = |bytes: &[u8], edges: &[EpochApplicationCoordinatesV1]| {
        InMemoryNativeExecutionStoreV0::decode_epoch_snapshot(
            source.chain_id.clone(),
            source.signers.clone(),
            source.consensus_parameters,
            BTreeSet::new(),
            BTreeSet::new(),
            bytes,
            edges,
        )
    };
    assert!(reopen(&bytes, &[]).is_err());
    assert!(reopen(&bytes[..bytes.len() - 1], &[edge]).is_err());
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(reopen(&trailing, &[edge]).is_err());
    let mut corrupt: PersistentAuthTreeSnapshotV0 = borsh::from_slice(&bytes).unwrap();
    corrupt.roots.insert(2, RootHash([88; 32]));
    assert!(reopen(&borsh::to_vec(&corrupt).unwrap(), &[edge]).is_err());
}
