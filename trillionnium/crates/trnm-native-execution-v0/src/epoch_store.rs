//! The only virtual JMT read is the exact empty root of terminal seal-2.
//! This private adapter does not implement NativeExecutionStoreV0 and therefore
//! cannot masquerade as an ordinary executed parent.

use super::*;
use crate::epoch_edge::EpochApplicationCoordinatesV1;
use crate::AuthenticatedEpochApplicationEdgeV1;

const EPOCH_SNAPSHOT_CODEC_VERSION_V1: u16 = 2;

pub(crate) struct CarriedRootReaderV1<'a> {
    store: &'a InMemoryNativeExecutionStoreV0,
    coordinates: EpochApplicationCoordinatesV1,
    new_parameters: Option<ConsensusParametersV0>,
}

impl<'a> CarriedRootReaderV1<'a> {
    pub(crate) fn new(
        store: &'a InMemoryNativeExecutionStoreV0,
        edge: &AuthenticatedEpochApplicationEdgeV1,
    ) -> Result<Self> {
        ensure!(
            store.chain_id_v0()? == edge.consensus_parent().chain_id().as_str(),
            "epoch reader chain mismatch"
        );
        let mut reader = Self::from_coordinates(store, edge.coordinates())?;
        reader.new_parameters = Some(*edge.new_parameters());
        Ok(reader)
    }

    // Construction by raw coordinates remains inside this module for focused
    // storage tests; production callers must supply the opaque verified edge.
    fn from_coordinates(
        store: &'a InMemoryNativeExecutionStoreV0,
        coordinates: EpochApplicationCoordinatesV1,
    ) -> Result<Self> {
        coordinates.validate()?;
        let (version, root) = verify_parent_root_v0(store)?;
        ensure!(
            version == coordinates.checkpoint_version && root.0 == coordinates.checkpoint_root,
            "epoch reader does not open the exact checkpoint head"
        );
        verify_absent_seal_rows(store, coordinates)?;
        Ok(Self {
            store,
            coordinates,
            new_parameters: None,
        })
    }

    pub(crate) fn plan(&self, writes: Vec<CompleteStateWriteV0>) -> Result<EpochStatePlanV1> {
        let mut plan = plan_complete_state_update_v0(
            self,
            self.coordinates.terminal_version,
            self.coordinates.first_version,
            writes,
        )?;
        ensure!(
            plan.tree_update_batch
                .node_batch
                .nodes()
                .keys()
                .all(|key| key.version() == self.coordinates.first_version),
            "epoch JMT emitted a non-target node version"
        );
        ensure!(
            plan.tree_update_batch
                .node_batch
                .values()
                .keys()
                .all(|(version, _)| *version == self.coordinates.first_version),
            "epoch JMT emitted a non-target value version"
        );
        // An alias is not a physical node and cannot be retained as a stale
        // index that would later delete or relabel the checkpoint root.
        plan.tree_update_batch
            .stale_node_index_batch
            .retain(|index| {
                !(index.node_key.version() == self.coordinates.terminal_version
                    && index.node_key.nibble_path().is_empty())
            });
        plan.epoch_parameters = self.new_parameters;
        Ok(EpochStatePlanV1 {
            coordinates: self.coordinates,
            plan,
        })
    }
}

impl TreeReader for CarriedRootReaderV1<'_> {
    fn get_node_option(&self, key: &NodeKey) -> Result<Option<Node>> {
        if key.version() == self.coordinates.terminal_version && key.nibble_path().is_empty() {
            return self.store.get_node_option(&NodeKey::new(
                self.coordinates.checkpoint_version,
                key.nibble_path().clone(),
            ));
        }
        ensure!(
            key.version() <= self.coordinates.terminal_version,
            "epoch reader future node lookup"
        );
        // In particular, a nonempty seal path is never redirected to C.
        self.store.get_node_option(key)
    }

    fn get_value_option(&self, max_version: Version, hash: KeyHash) -> Result<Option<Vec<u8>>> {
        ensure!(
            max_version <= self.coordinates.terminal_version,
            "epoch reader future value lookup"
        );
        self.store
            .get_value_option(max_version.min(self.coordinates.checkpoint_version), hash)
    }

    fn get_rightmost_leaf(&self) -> Result<Option<(NodeKey, LeafNode)>> {
        self.store.get_rightmost_leaf()
    }
}

impl HasPreimage for CarriedRootReaderV1<'_> {
    fn preimage(&self, hash: KeyHash) -> Result<Option<Vec<u8>>> {
        self.store.preimage(hash)
    }
}

pub(crate) struct EpochStatePlanV1 {
    coordinates: EpochApplicationCoordinatesV1,
    plan: CompleteStatePlanV0,
}

impl EpochStatePlanV1 {
    pub(crate) fn into_complete_plan(mut self) -> CompleteStatePlanV0 {
        self.plan.epoch_parent = Some(self.coordinates);
        self.plan
    }
    #[cfg(test)]
    pub(crate) fn state_root(&self) -> trnm_consensus_types::StateRoot {
        self.plan.state_root()
    }
    #[cfg(test)]
    pub(crate) fn version(&self) -> Version {
        self.plan.version()
    }
}

pub(super) fn validate_epoch_parent_v1(
    store: &InMemoryNativeExecutionStoreV0,
    coordinates: EpochApplicationCoordinatesV1,
) -> Result<()> {
    CarriedRootReaderV1::from_coordinates(store, coordinates).map(|_| ())
}

fn verify_absent_seal_rows(
    store: &InMemoryNativeExecutionStoreV0,
    coordinates: EpochApplicationCoordinatesV1,
) -> Result<()> {
    let in_gap =
        |version| version > coordinates.checkpoint_version && version < coordinates.first_version;
    ensure!(
        !store.roots.keys().copied().any(in_gap),
        "seal has an application root"
    );
    ensure!(
        !store.nodes.keys().any(|key| in_gap(key.version())),
        "seal has a physical JMT node"
    );
    ensure!(
        !store.values.keys().any(|(_, version)| in_gap(*version)),
        "seal has a value write"
    );
    ensure!(
        !store
            .stale_nodes
            .iter()
            .any(|index| in_gap(index.node_key.version()) || in_gap(index.stale_since_version)),
        "seal has a physical stale-node record"
    );
    Ok(())
}

impl InMemoryNativeExecutionStoreV0 {
    #[cfg(test)]
    pub(crate) fn apply_epoch_state_plan_v1(
        &mut self,
        epoch_plan: EpochStatePlanV1,
    ) -> Result<trnm_consensus_types::StateRoot> {
        self.apply_complete_state_plan_v0(epoch_plan.into_complete_plan())
    }

    /// Local codec 2 is explicitly separated from contiguous snapshot codec 1.
    /// Exact verified edges are retained by the outer owner, never inferred
    /// from equal roots or deserialized acceptance flags.
    pub(crate) fn encode_epoch_authenticated_snapshot_v1(
        &self,
        edges: &[&AuthenticatedEpochApplicationEdgeV1],
    ) -> Result<Vec<u8>> {
        ensure!(
            edges
                .iter()
                .all(|edge| edge.consensus_parent().chain_id().as_str() == self.chain_id),
            "sparse snapshot edge chain mismatch"
        );
        if let Some(latest) = edges
            .iter()
            .max_by_key(|edge| edge.first_application_height())
        {
            ensure!(
                self.consensus_parameters == *latest.new_parameters(),
                "sparse snapshot active parameters differ from authenticated edge"
            );
        }
        let coordinates: Vec<_> = edges.iter().map(|edge| edge.coordinates()).collect();
        self.encode_epoch_snapshot(&coordinates)
    }

    fn encode_epoch_snapshot(
        &self,
        coordinates: &[EpochApplicationCoordinatesV1],
    ) -> Result<Vec<u8>> {
        self.validate_epoch_snapshot(coordinates)?;
        borsh::to_vec(&PersistentAuthTreeSnapshotRefV0 {
            codec_version: EPOCH_SNAPSHOT_CODEC_VERSION_V1,
            nodes: &self.nodes,
            values: &self.values,
            preimages: &self.preimages,
            stale_nodes: &self.stale_nodes,
            roots: &self.roots,
        })
        .context("encode sparse epoch snapshot")
    }

    #[cfg(test)]
    pub(crate) fn decode_epoch_authenticated_snapshot_v1(
        chain_id: String,
        signers: Vec<AuthorizedSignerV0>,
        parameters: ConsensusParametersV0,
        command_ids: BTreeSet<String>,
        nonces: BTreeSet<(String, u64)>,
        bytes: &[u8],
        edges: &[&AuthenticatedEpochApplicationEdgeV1],
    ) -> Result<Self> {
        ensure!(
            edges
                .iter()
                .all(|edge| edge.consensus_parent().chain_id().as_str() == chain_id),
            "sparse snapshot edge chain mismatch"
        );
        if let Some(latest) = edges
            .iter()
            .max_by_key(|edge| edge.first_application_height())
        {
            ensure!(
                parameters == *latest.new_parameters(),
                "sparse snapshot restore parameters differ from authenticated edge"
            );
        }
        let coordinates: Vec<_> = edges.iter().map(|edge| edge.coordinates()).collect();
        Self::decode_epoch_snapshot(
            chain_id,
            signers,
            parameters,
            command_ids,
            nonces,
            bytes,
            &coordinates,
        )
    }

    fn decode_epoch_snapshot(
        chain_id: String,
        signers: Vec<AuthorizedSignerV0>,
        parameters: ConsensusParametersV0,
        command_ids: BTreeSet<String>,
        nonces: BTreeSet<(String, u64)>,
        bytes: &[u8],
        coordinates: &[EpochApplicationCoordinatesV1],
    ) -> Result<Self> {
        let snapshot: PersistentAuthTreeSnapshotV0 =
            borsh::from_slice(bytes).context("decode sparse epoch snapshot")?;
        ensure!(
            snapshot.codec_version == EPOCH_SNAPSHOT_CODEC_VERSION_V1,
            "unsupported sparse epoch snapshot codec"
        );
        let mut store = Self::new(chain_id, signers, parameters)?;
        store.committed_command_ids = command_ids;
        store.committed_signer_nonces = nonces;
        store.nodes = snapshot.nodes;
        store.values = snapshot.values;
        store.preimages = snapshot.preimages;
        store.stale_nodes = snapshot.stale_nodes;
        store.roots = snapshot.roots;
        store.validate_epoch_snapshot(coordinates)?;
        Ok(store)
    }

    pub(crate) fn decode_recovered_epoch_snapshot_v1(
        chain_id: String,
        signers: Vec<AuthorizedSignerV0>,
        parameters: ConsensusParametersV0,
        command_ids: BTreeSet<String>,
        nonces: BTreeSet<(String, u64)>,
        bytes: &[u8],
        edges: &[([u8; 32], crate::epoch_recovery::AuditedEpochEvidenceV1)],
    ) -> Result<Self> {
        let mut coordinates = Vec::with_capacity(edges.len());
        for (binding, edge) in edges {
            ensure!(
                edge.activation.new_validator_set().chain_id().as_str() == chain_id,
                "recovered snapshot edge chain mismatch"
            );
            coordinates.push(edge.coordinates(*binding)?);
        }
        let latest = edges
            .last()
            .context("recovered sparse snapshot lacks edge")?;
        ensure!(
            parameters == *latest.1.activation.new_consensus_parameters(),
            "recovered snapshot parameters differ from strict edge"
        );
        Self::decode_epoch_snapshot(
            chain_id,
            signers,
            parameters,
            command_ids,
            nonces,
            bytes,
            &coordinates,
        )
    }

    fn validate_epoch_snapshot(&self, edges: &[EpochApplicationCoordinatesV1]) -> Result<()> {
        ensure!(
            !edges.is_empty(),
            "sparse snapshot requires verified epoch edges"
        );
        let mut expected = BTreeMap::new();
        for edge in edges {
            edge.validate()?;
            ensure!(
                expected.insert(edge.checkpoint_version, edge).is_none(),
                "duplicate epoch edge"
            );
            ensure!(
                self.roots.get(&edge.checkpoint_version) == Some(&RootHash(edge.checkpoint_root)),
                "sparse snapshot checkpoint root mismatch"
            );
            ensure!(
                self.roots.contains_key(&edge.first_version),
                "sparse snapshot missing first target root"
            );
            verify_absent_seal_rows(self, *edge)?;
        }
        self.validate_snapshot_with_gaps_v1(&expected)
    }
}

#[cfg(test)]
#[path = "epoch_store_tests.rs"]
mod tests;
