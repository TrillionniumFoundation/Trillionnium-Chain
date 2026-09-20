//! Only the explicit epoch candidate can stage a sparse first-new delta.
use super::*;
use crate::epoch_edge::EpochExecutionContextV1;
use crate::store::{plan_complete_state_update_v0, CompleteStateWriteV0};

pub(crate) fn plan(
    reader: &IncrementalJmtReaderV1<'_>,
    context: &dyn EpochExecutionContextV1,
    writes: Vec<CompleteStateWriteV0>,
) -> Result<CompleteStatePlanV0> {
    let coordinates = context.coordinates_v1();
    coordinates.validate()?;
    ensure!(
        reader.version == coordinates.checkpoint_version
            && reader.root.0 == coordinates.checkpoint_root
            && reader.deltas.is_empty(),
        "incremental carried root source"
    );
    require_absent_incremental_seals_v1(reader.transaction, coordinates)?;
    let carried = Carried {
        reader,
        coordinates,
    };
    let mut plan = plan_complete_state_update_v0(
        &carried,
        coordinates.terminal_version,
        coordinates.first_version,
        writes,
    )?;
    ensure!(
        plan.tree_update_batch
            .node_batch
            .nodes()
            .keys()
            .all(|key| key.version() == coordinates.first_version)
            && plan
                .tree_update_batch
                .node_batch
                .values()
                .keys()
                .all(|(v, _)| *v == coordinates.first_version),
        "incremental epoch non-target writes"
    );
    plan.tree_update_batch.stale_node_index_batch.retain(|i| {
        !(i.node_key.version() == coordinates.terminal_version
            && i.node_key.nibble_path().is_empty())
    });
    plan.epoch_parent = Some(coordinates);
    plan.epoch_parameters = Some(*context.new_parameters_v1());
    Ok(plan)
}
struct Carried<'a, 'tx> {
    reader: &'a IncrementalJmtReaderV1<'tx>,
    coordinates: crate::epoch_edge::EpochApplicationCoordinatesV1,
}
impl TreeReader for Carried<'_, '_> {
    fn get_node_option(&self, key: &NodeKey) -> Result<Option<Node>> {
        ensure!(
            key.version() <= self.coordinates.terminal_version,
            "carried future node"
        );
        if key.version() == self.coordinates.terminal_version && key.nibble_path().is_empty() {
            self.reader
                .get_node_option(&root_key(self.coordinates.checkpoint_version))
        } else {
            self.reader.get_node_option(key)
        }
    }
    fn get_value_option(&self, version: u64, key: KeyHash) -> Result<Option<Vec<u8>>> {
        ensure!(
            version <= self.coordinates.terminal_version,
            "carried future value"
        );
        self.reader
            .get_value_option(version.min(self.coordinates.checkpoint_version), key)
    }
    fn get_rightmost_leaf(&self) -> Result<Option<(NodeKey, LeafNode)>> {
        self.reader.get_rightmost_leaf()
    }
}
impl HasPreimage for Carried<'_, '_> {
    fn preimage(&self, key: KeyHash) -> Result<Option<Vec<u8>>> {
        self.reader.preimage(key)
    }
}

pub(crate) fn stage(
    transaction: &Transaction<'_>,
    namespace: &IncrementalNamespaceV1,
    context: &dyn EpochExecutionContextV1,
    block: [u8; 32],
    plan: &CompleteStatePlanV0,
) -> Result<PreparedIncrementalDeltaV1> {
    let coordinates = context.coordinates_v1();
    ensure!(
        plan.epoch_parent == Some(coordinates)
            && plan.epoch_parameters == Some(*context.new_parameters_v1()),
        "sparse plan edge/config"
    );
    let parent =
        IncrementalParentV1::Committed(*context.application_parent_v1().block_id().as_bytes());
    let head = read_incremental_head_v1(transaction, namespace)?;
    ensure!(
        head.block == *context.application_parent_v1().block_id().as_bytes()
            && head.height == coordinates.checkpoint_version
            && head.root == coordinates.checkpoint_root,
        "sparse stage current checkpoint"
    );
    let raw = encode_epoch_storage_edge_v1(coordinates);
    let existing: bool = transaction.query_row(
        "SELECT EXISTS(SELECT 1 FROM ni_epoch_edge WHERE strict_binding=?1)",
        [coordinates.authorization_id.as_slice()],
        |r| r.get(0),
    )?;
    if existing {
        ensure!(
            load_epoch_storage_edge_v1(transaction, namespace, coordinates.authorization_id)?
                == coordinates,
            "sparse edge retry"
        );
    } else {
        let count: u64 =
            transaction.query_row("SELECT count(*) FROM ni_epoch_edge", [], |r| r.get(0))?;
        ensure!(count == 0, "single first-new edge candidate");
        transaction.execute(
            "INSERT INTO ni_epoch_edge VALUES(?1,?2,?3,?4,?5,0,NULL)",
            params![
                coordinates.authorization_id.as_slice(),
                &raw,
                hash(
                    b"trnm.native-incremental.edge.v1",
                    &[&namespace_digest(namespace)?, &raw]
                )
                .as_slice(),
                coordinates.checkpoint_version.to_be_bytes().as_slice(),
                coordinates.first_version.to_be_bytes().as_slice()
            ],
        )?;
    }
    stage_incremental_plan_inner_v1(
        transaction,
        namespace,
        parent,
        block,
        plan,
        Some(coordinates),
    )
}

/// Only the native owner, after strict finality verification, may invoke this
/// transaction-scoped sparse apply. This is not independent finality authority.
pub(crate) fn apply(
    tx: &Transaction<'_>,
    ns: &IncrementalNamespaceV1,
    context: &dyn EpochExecutionContextV1,
    expected: &IncrementalHeadV1,
    prepared: &PreparedIncrementalDeltaV1,
    operation: [u8; 32],
) -> Result<IncrementalHeadV1> {
    ensure!(
        expected.block == *context.application_parent_v1().block_id().as_bytes(),
        "sparse commit source block"
    );
    apply_incremental_delta_inner_v1(
        tx,
        ns,
        expected,
        prepared,
        operation,
        context.new_validator_set_v1().epoch().get(),
        Some(context.coordinates_v1()),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AuthorizedSignerV0, InMemoryNativeExecutionStoreV0, NativeStateWriteV0};
    #[test]
    fn carried_root_empty_leaf_internal_preserves_child_versions_and_rejects_seals() {
        for keys in 0..=2 {
            let signing = ed25519_dalek::SigningKey::from_bytes(&[17; 32]);
            let mut memory = InMemoryNativeExecutionStoreV0::new(
                "edge-storage",
                vec![AuthorizedSignerV0::new(
                    "s",
                    "operator",
                    hex::encode(signing.verifying_key().to_bytes()),
                )
                .unwrap()],
                trnm_consensus_types::ConsensusParametersV0::reference_shadow_v0(),
            )
            .unwrap();
            let writes = (0..keys)
                .map(|n| NativeStateWriteV0::raw(vec![b'a' + n], vec![n + 1]).unwrap())
                .collect();
            memory.apply_seed_v0(0, writes).unwrap();
            let ns = IncrementalNamespaceV1 {
                chain: "edge-storage".into(),
                genesis: [1; 32],
                namespace: [2; 32],
                owner_generation: 1,
            };
            let mut c = rusqlite::Connection::open_in_memory().unwrap();
            let tx = c.transaction().unwrap();
            install_incremental_schema_v1(&tx).unwrap();
            let head = import_incremental_snapshot_v1(
                &tx,
                &ns,
                IncrementalHeadV1 {
                    height: 0,
                    block: [3; 32],
                    root: memory.roots[&0].0,
                    commit_sequence: 0,
                    intent: [4; 32],
                    checksum: [0; 32],
                },
                0,
                &memory,
            )
            .unwrap();
            let reader =
                open_incremental_reader_v1(&tx, &ns, IncrementalParentV1::Committed(head.block))
                    .unwrap();
            let coordinates = crate::epoch_edge::EpochApplicationCoordinatesV1 {
                checkpoint_version: 0,
                checkpoint_root: head.root,
                terminal_version: 2,
                first_version: 3,
                authorization_id: [5; 32],
            };
            let carried = Carried {
                reader: &reader,
                coordinates,
            };
            let real = reader.get_node_option(&root_key(0)).unwrap();
            let alias = carried.get_node_option(&root_key(2)).unwrap();
            assert_eq!(real, alias);
            match keys {
                0 => assert!(matches!(alias, Some(Node::Null))),
                1 => assert!(matches!(alias, Some(Node::Leaf(_)))),
                _ => assert!(matches!(alias, Some(Node::Internal(_)))),
            }
            assert!(carried.get_node_option(&root_key(3)).is_err());
            for key in memory
                .nodes
                .keys()
                .filter(|key| !key.nibble_path().is_empty())
            {
                assert_eq!(
                    carried.get_node_option(key).unwrap(),
                    reader.get_node_option(key).unwrap()
                );
                assert!(carried
                    .get_node_option(&NodeKey::new(2, key.nibble_path().clone()))
                    .is_err());
            }
            let write =
                CompleteStateWriteV0::new(b"a".to_vec(), Some(b"changed".to_vec())).unwrap();
            let regular =
                plan_complete_state_update_v0(&reader, 0, 1, vec![write.clone()]).unwrap();
            let sparse = plan_complete_state_update_v0(&carried, 2, 3, vec![write]).unwrap();
            assert_eq!(regular.state_root(), sparse.state_root());
            require_absent_incremental_seals_v1(&tx, coordinates).unwrap();
            tx.execute(
                "INSERT INTO ni_values VALUES(?1,?2,0,?3)",
                params![
                    [19u8; 32].as_slice(),
                    1u64.to_be_bytes().as_slice(),
                    &[] as &[u8]
                ],
            )
            .unwrap();
            assert!(require_absent_incremental_seals_v1(&tx, coordinates).is_err());
        }
    }
}
