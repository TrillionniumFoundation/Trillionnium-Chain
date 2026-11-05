//! Bulk construction versus the retained original sequential insertion algorithm.
use super::*;
use crate::pon_wire::state_root;

fn insertion_reference(values: &BTreeMap<Vec<u8>, Vec<u8>>) -> Result<StateTree, StateError> {
    if values.len() > MAX_KEYS {
        return Err(StateError::Limit);
    }
    let mut tree = StateTree::default();
    for (key, value) in values {
        StateTree::bounds(key, Some(value))?;
        let path = hash(b"state-key", &[key]);
        let leaf = Arc::new(Node {
            path,
            depth: 256,
            digest: hash(b"state-leaf", &[key, value]),
            kind: Kind::Leaf {
                key: key.clone(),
                value: value.clone(),
            },
        });
        tree.root = Some(tree.insert(tree.root.as_ref(), leaf)?);
        tree.count += 1;
    }
    Ok(tree)
}

fn values(count: usize) -> BTreeMap<Vec<u8>, Vec<u8>> {
    (0..count)
        .map(|i| {
            (
                format!("bulk-key-{i:05}").into_bytes(),
                (i as u64).to_le_bytes().to_vec(),
            )
        })
        .collect()
}

fn equal_nodes(actual: &Node, expected: &Node) {
    assert_eq!(
        (actual.path, actual.depth, actual.digest),
        (expected.path, expected.depth, expected.digest)
    );
    match (&actual.kind, &expected.kind) {
        (Kind::Leaf { key: a, value: av }, Kind::Leaf { key: b, value: bv }) => {
            assert_eq!((a, av), (b, bv));
        }
        (
            Kind::Fork {
                left: al,
                right: ar,
                left_hash: ah,
                right_hash: ai,
            },
            Kind::Fork {
                left: bl,
                right: br,
                left_hash: bh,
                right_hash: bi,
            },
        ) => {
            assert_eq!((ah, ai), (bh, bi));
            equal_nodes(al, bl);
            equal_nodes(ar, br);
        }
        _ => panic!("compressed shape differs from original insertion"),
    }
}

fn equal_trees(actual: &StateTree, expected: &StateTree) {
    assert_eq!(actual.root(), expected.root());
    assert_eq!(actual.len(), expected.len());
    assert_eq!(actual.allocated_nodes(), expected.allocated_nodes());
    match (&actual.root, &expected.root) {
        (Some(a), Some(b)) => equal_nodes(a, b),
        (None, None) => (),
        _ => panic!("empty/present mismatch"),
    }
}

#[test]
fn bulk_matches_insertion_shape_and_full_wire_at_size_edges() {
    for count in [0, 1, 2, 3, 7, 8, 15, 16, 31, 32, 127, 257, 1025] {
        let values = values(count);
        let actual = StateTree::from_values(&values).unwrap();
        let expected = insertion_reference(&values).unwrap();
        equal_trees(&actual, &expected);
        assert_eq!(actual.root(), state_root(&values).unwrap());
        for (key, value) in &values {
            assert_eq!(actual.get(key).unwrap(), Some(value.as_slice()));
        }
    }
}

#[test]
fn bulk_matches_original_every_divergence_depth_and_path_direction() {
    // Deliberately constructed paths exercise structure, not real hash collisions
    // or an alternative public source of state-key hashes.
    for depth in 0..256 {
        for fill in [0u8, 255] {
            let mut paths = [[fill; 32]; 2];
            paths[1][depth / 8] ^= 128 >> (depth % 8);
            let mut leaves: Vec<_> = paths
                .into_iter()
                .enumerate()
                .map(|(i, path)| {
                    Arc::new(Node {
                        path,
                        depth: 256,
                        digest: hash(b"bulk-shape-test", &[&(i as u64).to_le_bytes()]),
                        kind: Kind::Leaf {
                            key: vec![i as u8],
                            value: vec![fill],
                        },
                    })
                })
                .collect();
            let mut expected = StateTree::default();
            for leaf in &leaves {
                expected.root = Some(
                    expected
                        .insert(expected.root.as_ref(), leaf.clone())
                        .unwrap(),
                );
                expected.count += 1;
            }
            leaves.sort_unstable_by_key(|leaf| leaf.path);
            let mut actual = StateTree::default();
            actual.root = Some(actual.sorted_subtree(&leaves));
            actual.count = leaves.len();
            equal_trees(&actual, &expected);
        }
    }
}

#[test]
fn bulk_real_65536_keys_preserves_every_leaf_and_original_root() {
    let values = values(MAX_KEYS);
    let actual = StateTree::from_values(&values).unwrap();
    let expected = insertion_reference(&values).unwrap();
    equal_trees(&actual, &expected);
    assert_eq!(actual.root(), state_root(&values).unwrap());
    assert_eq!(actual.allocated_nodes(), 2 * MAX_KEYS - 1);
    for (key, value) in &values {
        assert_eq!(actual.get(key).unwrap(), Some(value.as_slice()));
    }
}

#[test]
fn bulk_keeps_original_bounds_and_absent_empty_distinction() {
    for values in [
        BTreeMap::from([(vec![0; 161], vec![0])]),
        BTreeMap::from([(vec![0], vec![0; 4097])]),
        values(MAX_KEYS + 1),
    ] {
        assert_eq!(
            StateTree::from_values(&values).err(),
            Some(StateError::Limit)
        );
        assert_eq!(
            StateTree::from_values(&values).err(),
            insertion_reference(&values).err()
        );
    }
    for values in [
        BTreeMap::new(),
        BTreeMap::from([(vec![], vec![])]),
        BTreeMap::from([(vec![255; 160], vec![255; 4096])]),
    ] {
        equal_trees(
            &StateTree::from_values(&values).unwrap(),
            &insertion_reference(&values).unwrap(),
        );
    }
    assert_ne!(
        StateTree::from_values(&BTreeMap::new()).unwrap().root(),
        StateTree::from_values(&BTreeMap::from([(vec![], vec![])]))
            .unwrap()
            .root()
    );
}

#[test]
fn bulk_keeps_updates_inverse_and_failed_batch_snapshot_immutable() {
    let mut values = values(257);
    let original = StateTree::from_values(&values).unwrap();
    let mut actual = original.clone();
    let mut expected = insertion_reference(&values).unwrap();
    for round in 0..12 {
        let key = format!("bulk-key-{:05}", round * 23).into_bytes();
        let before = values.get(&key).cloned();
        let after = if round % 3 == 0 {
            None
        } else {
            Some(vec![round as u8; round])
        };
        let changes = [Change {
            key: key.clone(),
            before,
            after: after.clone(),
        }];
        let saved = actual.clone();
        actual = actual.apply(actual.root(), &changes).unwrap();
        expected = expected.apply(expected.root(), &changes).unwrap();
        if let Some(value) = after {
            values.insert(key, value);
        } else {
            values.remove(&key);
        }
        equal_trees(&actual, &expected);
        assert_eq!(actual.root(), state_root(&values).unwrap());
        let inverse = [Change {
            key: changes[0].key.clone(),
            before: changes[0].after.clone(),
            after: changes[0].before.clone(),
        }];
        equal_trees(&actual.apply(actual.root(), &inverse).unwrap(), &saved);
        let failing = [
            Change {
                key: b"new-key".to_vec(),
                before: None,
                after: Some(vec![1]),
            },
            Change {
                key: b"absent-key".to_vec(),
                before: Some(vec![9]),
                after: None,
            },
        ];
        assert_eq!(
            actual.apply(actual.root(), &failing).err(),
            Some(StateError::BeforeMismatch)
        );
        equal_trees(&actual, &expected);
    }
    equal_trees(&original, &insertion_reference(&self::values(257)).unwrap());
}

#[test]
#[ignore = "explicit full-build paired timing; not native Node throughput or public qualification"]
fn bulk_complete_construction_cost_observation() {
    use std::hint::black_box;
    use std::time::Instant;
    for count in [1024, 8192, MAX_KEYS] {
        let values = values(count);
        let expected = insertion_reference(&values).unwrap().root();
        for sample in 0..4usize {
            for offset in 0..2 {
                let bulk = (sample + offset) % 2 == 1;
                let start = Instant::now();
                let tree = if bulk {
                    StateTree::from_values(black_box(&values))
                } else {
                    insertion_reference(black_box(&values))
                }
                .unwrap();
                let root = tree.root();
                drop(tree);
                let elapsed_ns = start.elapsed().as_nanos();
                assert_eq!(root, expected);
                println!(
                    "{}",
                    serde_json::json!({"schema":"state-tree-bulk-build-cost-v1",
                    "keys":count,"sample":sample,"bulk":bulk,"elapsed_ns":elapsed_ns,
                    "same_root":true,"scope":"full constructor+root+drop; excludes input fixture, Node, SQLite and network",
                    "public_network_ready":false})
                );
            }
        }
    }
}

#[test]
fn bulk_nested_all_depths_matches_both_insertion_orders() {
    let mut paths = vec![[0u8; 32]];
    for bit in 0..256 {
        let mut path = [0u8; 32];
        path[bit / 8] = 128 >> (bit % 8);
        paths.push(path);
    }
    let mut leaves: Vec<_> = paths
        .into_iter()
        .enumerate()
        .map(|(i, path)| {
            Arc::new(Node {
                path,
                depth: 256,
                digest: hash(b"bulk-nested-path-test", &[&(i as u64).to_le_bytes()]),
                kind: Kind::Leaf {
                    key: (i as u64).to_le_bytes().to_vec(),
                    value: vec![],
                },
            })
        })
        .collect();
    leaves.sort_unstable_by_key(|leaf| leaf.path);
    let mut bulk = StateTree::default();
    bulk.root = Some(bulk.sorted_subtree(&leaves));
    bulk.count = leaves.len();
    for reverse in [false, true] {
        let mut original = StateTree::default();
        for offset in 0..leaves.len() {
            let index = if reverse {
                leaves.len() - offset - 1
            } else {
                offset
            };
            original.root = Some(
                original
                    .insert(original.root.as_ref(), leaves[index].clone())
                    .unwrap(),
            );
            original.count += 1;
        }
        equal_trees(&bulk, &original);
    }
}

#[test]
fn bulk_collision_in_valid_prefix_keeps_original_error_precedence() {
    // These synthetic hashed leaves cannot be supplied through the public API.
    let leaf = |path, key| {
        Arc::new(Node {
            path,
            depth: 256,
            digest: [9; 32],
            kind: Kind::Leaf {
                key: vec![key],
                value: vec![],
            },
        })
    };
    let first = leaf([0; 32], 1);
    let collision = leaf([0; 32], 2);
    let distinct = leaf([1; 32], 3);
    let original = StateTree::default();
    assert!(matches!(
        original.insert(Some(&first), collision.clone()),
        Err(StateError::KeyCollision)
    ));
    for late_error in [None, Some(StateError::Limit)] {
        assert!(matches!(
            StateTree::checked_leaf_prefix(vec![first.clone(), collision.clone()], late_error),
            Err(StateError::KeyCollision)
        ));
    }
    assert!(matches!(
        StateTree::checked_leaf_prefix(
            vec![distinct.clone(), first.clone()],
            Some(StateError::Limit)
        ),
        Err(StateError::Limit)
    ));
    assert!(matches!(
        StateTree::checked_leaf_prefix(vec![], Some(StateError::Limit)),
        Err(StateError::Limit)
    ));
    let sorted = StateTree::checked_leaf_prefix(vec![distinct, first], None).unwrap();
    assert_eq!(sorted[0].path, [0; 32]);
    assert_eq!(sorted[1].path, [1; 32]);
}
