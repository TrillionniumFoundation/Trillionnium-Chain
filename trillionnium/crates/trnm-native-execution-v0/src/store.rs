use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

use anyhow::{ensure, Context, Result};
use borsh::{BorshDeserialize, BorshSerialize};
use jmt::{
    storage::{HasPreimage, LeafNode, Node, NodeKey, StaleNodeIndex, TreeReader, TreeUpdateBatch},
    JellyfishMerkleIterator, KeyHash, RootHash, Sha256Jmt, Version,
};
use sha2::{Digest, Sha256};
use trnm_consensus_types::ConsensusParametersV0;

use crate::AuthorizedSignerV0;

const KEY_DOMAIN: &[u8] = b"trnm/authenticated-state/v4";
const OBJECT_NAMESPACE: u8 = 1;
const OBJECT_RECORD_SCHEMA_VERSION: u16 = 1;
const NATIVE_AUTH_TREE_SNAPSHOT_CODEC_VERSION_V0: u16 = 1;

pub fn stored_object_key_v0(object_key_hex: &str) -> Result<Vec<u8>> {
    ensure!(!object_key_hex.is_empty(), "object key must not be empty");
    let component = object_key_hex.as_bytes();
    let component_len = u32::try_from(component.len()).context("object key exceeds u32")?;
    let mut key = Vec::with_capacity(KEY_DOMAIN.len() + 8 + component.len());
    key.extend_from_slice(KEY_DOMAIN);
    key.push(0);
    key.push(OBJECT_NAMESPACE);
    key.extend_from_slice(&1u16.to_be_bytes());
    key.extend_from_slice(&component_len.to_be_bytes());
    key.extend_from_slice(component);
    Ok(key)
}

pub fn authenticated_key_hash_v0(key: &[u8]) -> Result<KeyHash> {
    ensure!(!key.is_empty(), "authenticated key must not be empty");
    Ok(KeyHash::with::<Sha256>(key))
}

#[derive(Clone, Debug, Eq, PartialEq, BorshDeserialize, BorshSerialize)]
pub struct AuthenticatedObjectRecordV0 {
    schema_version: u16,
    object_type: String,
    object_version: u64,
    value_hash: [u8; 32],
    value: Vec<u8>,
}

impl AuthenticatedObjectRecordV0 {
    pub fn new(
        object_type: impl Into<String>,
        object_version: u64,
        value: Vec<u8>,
    ) -> Result<Self> {
        let object_type = object_type.into();
        ensure!(!object_type.is_empty(), "object type must not be empty");
        let record = Self {
            schema_version: OBJECT_RECORD_SCHEMA_VERSION,
            object_type,
            object_version,
            value_hash: Sha256::digest(&value).into(),
            value,
        };
        record.validate()?;
        Ok(record)
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        borsh::to_vec(self).context("encode authenticated object record")
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let record: Self =
            borsh::from_slice(bytes).context("decode authenticated object record")?;
        record.validate()?;
        Ok(record)
    }

    fn validate(&self) -> Result<()> {
        ensure!(
            self.schema_version == OBJECT_RECORD_SCHEMA_VERSION,
            "unsupported authenticated object record schema"
        );
        ensure!(
            !self.object_type.is_empty(),
            "object type must not be empty"
        );
        ensure!(
            self.value_hash == <[u8; 32]>::from(Sha256::digest(&self.value)),
            "authenticated object value hash mismatch"
        );
        Ok(())
    }

    pub fn object_type(&self) -> &str {
        &self.object_type
    }

    pub const fn object_version(&self) -> u64 {
        self.object_version
    }

    pub fn value(&self) -> &[u8] {
        &self.value
    }
}

/// Read-only trust boundary required by the candidate execution kernel.
///
/// Every method is supplied by one externally implementable candidate store:
/// chain ID, parameters, signer policy, replay answers, JMT data, preimages,
/// version, and root. The kernel checks their internal relations where it can,
/// but this tranche does not prove that they came from one lifecycle-bound,
/// pinned parent snapshot. Implementations are trusted test/vector inputs,
/// never production authority.
pub trait NativeExecutionStoreV0: TreeReader + HasPreimage {
    fn parent_version_v0(&self) -> Result<Version>;
    fn parent_root_v0(&self) -> Result<RootHash>;
    fn chain_id_v0(&self) -> Result<&str>;
    fn authorized_signers_v0(&self) -> Result<&[AuthorizedSignerV0]>;
    fn signer_policy_commitment_v0(&self) -> Result<[u8; 32]>;
    fn consensus_parameters_v0(&self) -> Result<ConsensusParametersV0>;
    fn committed_command_id_v0(&self, command_id: &str) -> Result<bool>;
    fn committed_signer_nonce_v0(&self, signer_id: &str, nonce: u64) -> Result<bool>;
}

#[derive(Clone, Debug, Eq, PartialEq, BorshDeserialize, BorshSerialize)]
pub struct NativeStateWriteV0 {
    key: Vec<u8>,
    value: Vec<u8>,
}

/// One exact write in the complete frozen-v0 post-state plan. `None` is a
/// namespace-authorized tombstone (currently used only by the PoCO planner).
#[derive(Clone, Debug, Eq, PartialEq, BorshDeserialize, BorshSerialize)]
pub struct CompleteStateWriteV0 {
    key: Vec<u8>,
    value: Option<Vec<u8>>,
}

impl CompleteStateWriteV0 {
    pub(crate) fn new(key: Vec<u8>, value: Option<Vec<u8>>) -> Result<Self> {
        ensure!(
            !key.is_empty(),
            "complete authenticated write key must not be empty"
        );
        Ok(Self { key, value })
    }

    pub fn key(&self) -> &[u8] {
        &self.key
    }

    pub fn value(&self) -> Option<&[u8]> {
        self.value.as_deref()
    }
}

impl NativeStateWriteV0 {
    pub fn from_object(
        object_key_hex: &str,
        object_type: &str,
        object_version: u64,
        value: Vec<u8>,
    ) -> Result<Self> {
        Ok(Self {
            key: stored_object_key_v0(object_key_hex)?,
            value: AuthenticatedObjectRecordV0::new(object_type, object_version, value)?
                .encode()?,
        })
    }

    pub fn raw(key: Vec<u8>, value: Vec<u8>) -> Result<Self> {
        ensure!(!key.is_empty(), "authenticated write key must not be empty");
        Ok(Self { key, value })
    }

    pub fn key(&self) -> &[u8] {
        &self.key
    }

    pub fn value(&self) -> &[u8] {
        &self.value
    }
}

/// Root after applying only the runtime-object writes derived by this kernel.
///
/// This is not a complete frozen-v0 ordinary-block `StateRoot`: validator
/// lifecycle, PoCO, cutoff, and other system writes are outside this tranche.
/// The distinct type prevents accidental use as a consensus header root.
///
/// ```compile_fail
/// use trnm_consensus_types::StateRoot;
/// use trnm_native_execution_v0::RuntimeObjectDeltaRootV0;
///
/// fn incorrectly_promote(root: RuntimeObjectDeltaRootV0) -> StateRoot {
///     root
/// }
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeObjectDeltaRootV0([u8; 32]);

impl RuntimeObjectDeltaRootV0 {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Uncommitted JMT plan containing runtime-object writes only.
#[derive(Debug)]
pub struct RuntimeObjectDeltaPlanV0 {
    version: Version,
    root_hash: RootHash,
    tree_update_batch: TreeUpdateBatch,
    preimages: BTreeMap<KeyHash, Vec<u8>>,
    writes: Vec<NativeStateWriteV0>,
}

/// Complete, inert authenticated-state plan for one exact next height.
///
/// The type has no public constructor and is deliberately not `Clone`: only
/// the complete executor can mint it, and only the durable native application
/// can consume it. It is not Core, Safety, signing, or finality authority.
#[derive(Debug)]
pub struct CompleteStatePlanV0 {
    version: Version,
    root_hash: RootHash,
    tree_update_batch: TreeUpdateBatch,
    preimages: BTreeMap<KeyHash, Vec<u8>>,
    writes: Vec<CompleteStateWriteV0>,
}

impl CompleteStatePlanV0 {
    pub const fn version(&self) -> Version {
        self.version
    }

    pub const fn state_root(&self) -> trnm_consensus_types::StateRoot {
        trnm_consensus_types::StateRoot::new(self.root_hash.0)
    }

    pub fn writes(&self) -> &[CompleteStateWriteV0] {
        &self.writes
    }
}

impl RuntimeObjectDeltaPlanV0 {
    pub const fn version(&self) -> Version {
        self.version
    }

    pub const fn runtime_object_delta_root(&self) -> RuntimeObjectDeltaRootV0 {
        RuntimeObjectDeltaRootV0(self.root_hash.0)
    }

    pub fn tree_update_batch(&self) -> &TreeUpdateBatch {
        &self.tree_update_batch
    }

    pub fn preimages(&self) -> &BTreeMap<KeyHash, Vec<u8>> {
        &self.preimages
    }

    pub fn writes(&self) -> &[NativeStateWriteV0] {
        &self.writes
    }
}

pub(crate) fn verify_parent_root_v0<S: NativeExecutionStoreV0>(
    store: &S,
) -> Result<(Version, RootHash)> {
    let version = store.parent_version_v0()?;
    let expected = store.parent_root_v0()?;
    let actual = Sha256Jmt::new(store)
        .get_root_hash(version)
        .with_context(|| format!("read authenticated parent root at version {version}"))?;
    ensure!(actual == expected, "authenticated parent root mismatch");
    Ok((version, expected))
}

pub(crate) fn read_authenticated_object_v0<S: NativeExecutionStoreV0>(
    store: &S,
    version: Version,
    trusted_root: RootHash,
    object_key_hex: &str,
) -> Result<Option<AuthenticatedObjectRecordV0>> {
    let key = stored_object_key_v0(object_key_hex)?;
    let hash = authenticated_key_hash_v0(&key)?;
    if let Some(preimage) = store.preimage(hash)? {
        ensure!(preimage == key, "SHA-256 authenticated key collision");
    }
    let (value, proof) = Sha256Jmt::new(store)
        .get_with_proof(hash, version)
        .with_context(|| format!("prove authenticated object {object_key_hex}"))?;
    match value {
        Some(value) => {
            proof.verify_existence(trusted_root, hash, &value)?;
            let preimage = store
                .preimage(hash)?
                .context("authenticated object is missing its key preimage")?;
            ensure!(preimage == key, "authenticated object preimage mismatch");
            Ok(Some(AuthenticatedObjectRecordV0::decode(&value)?))
        }
        None => {
            proof.verify_nonexistence(trusted_root, hash)?;
            Ok(None)
        }
    }
}

pub(crate) fn plan_state_update_v0<S: NativeExecutionStoreV0>(
    store: &S,
    parent_version: Version,
    target_version: Version,
    writes: Vec<NativeStateWriteV0>,
) -> Result<RuntimeObjectDeltaPlanV0> {
    ensure!(
        target_version
            == parent_version
                .checked_add(1)
                .context("parent version exhausted")?,
        "target JMT version is not the exact successor"
    );
    let mut hashed_writes = BTreeMap::new();
    let mut preimages = BTreeMap::new();
    for write in &writes {
        let hash = authenticated_key_hash_v0(write.key())?;
        ensure!(
            hashed_writes
                .insert(hash, Some(write.value().to_vec()))
                .is_none(),
            "duplicate authenticated state write"
        );
        if let Some(existing) = store.preimage(hash)? {
            ensure!(
                existing == write.key(),
                "SHA-256 authenticated key collision"
            );
        }
        ensure!(
            preimages.insert(hash, write.key().to_vec()).is_none(),
            "duplicate authenticated state preimage"
        );
    }
    let (root_hash, tree_update_batch) = Sha256Jmt::new(store)
        .put_value_set(hashed_writes, target_version)
        .with_context(|| format!("plan authenticated state version {target_version}"))?;
    Ok(RuntimeObjectDeltaPlanV0 {
        version: target_version,
        root_hash,
        tree_update_batch,
        preimages,
        writes,
    })
}

pub(crate) fn plan_complete_state_update_v0<S: NativeExecutionStoreV0>(
    store: &S,
    parent_version: Version,
    target_version: Version,
    writes: Vec<CompleteStateWriteV0>,
) -> Result<CompleteStatePlanV0> {
    ensure!(
        target_version
            == parent_version
                .checked_add(1)
                .context("parent version exhausted")?,
        "complete target JMT version is not the exact successor"
    );
    let mut raw_keys = BTreeSet::new();
    let mut hashed_writes = BTreeMap::new();
    let mut preimages = BTreeMap::new();
    for write in &writes {
        ensure!(
            raw_keys.insert(write.key().to_vec()),
            "duplicate complete authenticated write key"
        );
        let hash = authenticated_key_hash_v0(write.key())?;
        ensure!(
            hashed_writes
                .insert(hash, write.value().map(<[u8]>::to_vec))
                .is_none(),
            "complete authenticated write hash collision"
        );
        if let Some(existing) = store.preimage(hash)? {
            ensure!(
                existing == write.key(),
                "SHA-256 authenticated key collision"
            );
        }
        ensure!(
            preimages.insert(hash, write.key().to_vec()).is_none(),
            "duplicate complete authenticated state preimage"
        );
    }
    let (root_hash, tree_update_batch) = Sha256Jmt::new(store)
        .put_value_set(hashed_writes, target_version)
        .with_context(|| format!("plan complete authenticated state version {target_version}"))?;
    Ok(CompleteStatePlanV0 {
        version: target_version,
        root_hash,
        tree_update_batch,
        preimages,
        writes,
    })
}

/// Deterministic in-memory store used only by candidate vectors and tests.
#[derive(Clone, Debug)]
pub struct InMemoryNativeExecutionStoreV0 {
    chain_id: String,
    signers: Vec<AuthorizedSignerV0>,
    signer_policy_commitment: [u8; 32],
    consensus_parameters: ConsensusParametersV0,
    committed_command_ids: BTreeSet<String>,
    committed_signer_nonces: BTreeSet<(String, u64)>,
    nodes: BTreeMap<NodeKey, Node>,
    values: BTreeMap<(KeyHash, Version), Option<Vec<u8>>>,
    preimages: BTreeMap<KeyHash, Vec<u8>>,
    stale_nodes: BTreeSet<StaleNodeIndex>,
    roots: BTreeMap<Version, RootHash>,
}

/// The iterator owns an Arc, but the snapshot it reads is borrowed for the
/// entire audit. Rust prevents the owner from changing these collections while
/// proofs and iteration inspect them; no historical maps need to be cloned.
struct BorrowedNativeTreeReaderV0<'a>(&'a InMemoryNativeExecutionStoreV0);

impl TreeReader for BorrowedNativeTreeReaderV0<'_> {
    fn get_node_option(&self, node_key: &NodeKey) -> Result<Option<Node>> {
        self.0.get_node_option(node_key)
    }

    fn get_value_option(&self, max_version: Version, key_hash: KeyHash) -> Result<Option<Vec<u8>>> {
        self.0.get_value_option(max_version, key_hash)
    }

    fn get_rightmost_leaf(&self) -> Result<Option<(NodeKey, LeafNode)>> {
        self.0.get_rightmost_leaf()
    }
}

#[derive(BorshDeserialize, BorshSerialize)]
struct PersistentAuthTreeSnapshotV0 {
    codec_version: u16,
    nodes: BTreeMap<NodeKey, Node>,
    values: BTreeMap<(KeyHash, Version), Option<Vec<u8>>>,
    preimages: BTreeMap<KeyHash, Vec<u8>>,
    stale_nodes: BTreeSet<StaleNodeIndex>,
    roots: BTreeMap<Version, RootHash>,
}

/// Encoding-only view of `PersistentAuthTreeSnapshotV0`, in the same field order.
/// Borsh serializes references by delegating to the referenced value, preserving
/// the existing codec bytes without cloning the five historical collections.
/// This still encodes the full snapshot; it does not change persistence costs.
#[derive(BorshSerialize)]
struct PersistentAuthTreeSnapshotRefV0<'a> {
    codec_version: u16,
    nodes: &'a BTreeMap<NodeKey, Node>,
    values: &'a BTreeMap<(KeyHash, Version), Option<Vec<u8>>>,
    preimages: &'a BTreeMap<KeyHash, Vec<u8>>,
    stale_nodes: &'a BTreeSet<StaleNodeIndex>,
    roots: &'a BTreeMap<Version, RootHash>,
}

impl InMemoryNativeExecutionStoreV0 {
    pub fn new(
        chain_id: impl Into<String>,
        signers: Vec<AuthorizedSignerV0>,
        consensus_parameters: ConsensusParametersV0,
    ) -> Result<Self> {
        let chain_id = chain_id.into();
        ensure!(!chain_id.is_empty(), "chain id must not be empty");
        let signer_policy_commitment = crate::signer_policy_commitment_v0(&signers)?;
        Ok(Self {
            chain_id,
            signers,
            signer_policy_commitment,
            consensus_parameters,
            committed_command_ids: BTreeSet::new(),
            committed_signer_nonces: BTreeSet::new(),
            nodes: BTreeMap::new(),
            values: BTreeMap::new(),
            preimages: BTreeMap::new(),
            stale_nodes: BTreeSet::new(),
            roots: BTreeMap::new(),
        })
    }

    /// Reconstructs the fixed excluded-legacy vector parent for differential
    pub fn apply_seed_v0(
        &mut self,
        version: Version,
        writes: Vec<NativeStateWriteV0>,
    ) -> Result<RootHash> {
        let expected = self
            .roots
            .last_key_value()
            .map_or(0, |(version, _)| version + 1);
        ensure!(version == expected, "seed version is not contiguous");
        let mut hashed = BTreeMap::new();
        let mut preimages = BTreeMap::new();
        for write in writes {
            let hash = authenticated_key_hash_v0(write.key())?;
            ensure!(
                hashed.insert(hash, Some(write.value)).is_none(),
                "duplicate seed write"
            );
            ensure!(
                preimages.insert(hash, write.key).is_none(),
                "duplicate seed preimage"
            );
        }
        let (root, batch) = Sha256Jmt::new(self).put_value_set(hashed, version)?;
        self.apply_batch_v0(version, root, batch, preimages)?;
        Ok(root)
    }

    pub fn read_object_v0(
        &self,
        object_key_hex: &str,
    ) -> Result<Option<AuthenticatedObjectRecordV0>> {
        let version = self.parent_version_v0()?;
        let root = self.parent_root_v0()?;
        read_authenticated_object_v0(self, version, root, object_key_hex)
    }

    pub fn mark_committed_command_v0(
        &mut self,
        command_id: impl Into<String>,
        signer_id: impl Into<String>,
        nonce: u64,
    ) -> Result<()> {
        let command_id = command_id.into();
        let signer_id = signer_id.into();
        ensure!(
            !command_id.is_empty(),
            "committed command id must not be empty"
        );
        ensure!(
            !signer_id.is_empty(),
            "committed signer id must not be empty"
        );
        ensure!(nonce > 0, "committed signer nonce must be positive");
        self.committed_command_ids.insert(command_id);
        self.committed_signer_nonces.insert((signer_id, nonce));
        Ok(())
    }

    pub(crate) const fn replay_sets_v0(&self) -> (&BTreeSet<String>, &BTreeSet<(String, u64)>) {
        (&self.committed_command_ids, &self.committed_signer_nonces)
    }

    pub fn apply_runtime_object_delta_plan_v0(
        &mut self,
        plan: RuntimeObjectDeltaPlanV0,
    ) -> Result<RuntimeObjectDeltaRootV0> {
        let expected = self
            .roots
            .last_key_value()
            .map_or(0, |(version, _)| version + 1);
        ensure!(plan.version == expected, "state update plan is stale");
        let root = plan.root_hash;
        self.apply_batch_v0(plan.version, root, plan.tree_update_batch, plan.preimages)?;
        Ok(RuntimeObjectDeltaRootV0(root.0))
    }

    pub(crate) fn apply_complete_state_plan_v0(
        &mut self,
        plan: CompleteStatePlanV0,
    ) -> Result<trnm_consensus_types::StateRoot> {
        let expected = self
            .roots
            .last_key_value()
            .map_or(0, |(version, _)| version + 1);
        ensure!(plan.version == expected, "complete state plan is stale");
        let root = plan.root_hash;
        self.apply_batch_v0(plan.version, root, plan.tree_update_batch, plan.preimages)?;
        Ok(trnm_consensus_types::StateRoot::new(root.0))
    }

    pub(crate) fn encode_authenticated_snapshot_v0(&self) -> Result<Vec<u8>> {
        borsh::to_vec(&PersistentAuthTreeSnapshotRefV0 {
            codec_version: NATIVE_AUTH_TREE_SNAPSHOT_CODEC_VERSION_V0,
            nodes: &self.nodes,
            values: &self.values,
            preimages: &self.preimages,
            stale_nodes: &self.stale_nodes,
            roots: &self.roots,
        })
        .context("encode native authenticated snapshot")
    }

    pub(crate) fn decode_authenticated_snapshot_v0(
        chain_id: impl Into<String>,
        signers: Vec<AuthorizedSignerV0>,
        consensus_parameters: ConsensusParametersV0,
        committed_command_ids: BTreeSet<String>,
        committed_signer_nonces: BTreeSet<(String, u64)>,
        bytes: &[u8],
    ) -> Result<Self> {
        let snapshot: PersistentAuthTreeSnapshotV0 =
            borsh::from_slice(bytes).context("decode native authenticated snapshot")?;
        ensure!(
            snapshot.codec_version == NATIVE_AUTH_TREE_SNAPSHOT_CODEC_VERSION_V0,
            "unsupported native authenticated snapshot codec"
        );
        let chain_id = chain_id.into();
        ensure!(!chain_id.is_empty(), "chain id must not be empty");
        let signer_policy_commitment = crate::signer_policy_commitment_v0(&signers)?;
        let store = Self {
            chain_id,
            signers,
            signer_policy_commitment,
            consensus_parameters,
            committed_command_ids,
            committed_signer_nonces,
            nodes: snapshot.nodes,
            values: snapshot.values,
            preimages: snapshot.preimages,
            stale_nodes: snapshot.stale_nodes,
            roots: snapshot.roots,
        };
        store.validate_snapshot_v0()?;
        Ok(store)
    }

    fn validate_snapshot_v0(&self) -> Result<()> {
        ensure!(
            !self.roots.is_empty(),
            "authenticated snapshot has no roots"
        );
        let latest = *self
            .roots
            .last_key_value()
            .context("authenticated snapshot has no latest root")?
            .0;
        let tree = Sha256Jmt::new(self);
        let mut previous = None;
        for (&version, expected_root) in &self.roots {
            if let Some(previous) = previous {
                ensure!(
                    version == previous + 1,
                    "authenticated roots are not contiguous"
                );
            }
            // Check the actual retained commitment, not just root-node presence.
            // JMT addresses the root by NodeKey instead of scanning all nodes.
            let actual_root = tree
                .get_root_hash(version)
                .context("authenticated snapshot is missing a root node")?;
            ensure!(
                actual_root == *expected_root,
                "authenticated snapshot root mismatch at version {version}"
            );
            previous = Some(version);
        }
        ensure!(
            self.nodes.keys().all(|key| key.version() <= latest),
            "authenticated snapshot node version exceeds latest root"
        );
        ensure!(
            self.values.keys().all(|(_, version)| *version <= latest),
            "authenticated snapshot value version exceeds latest root"
        );
        ensure!(
            self.stale_nodes
                .iter()
                .all(|index| index.stale_since_version <= latest),
            "authenticated snapshot stale index exceeds latest root"
        );
        for (hash, preimage) in &self.preimages {
            ensure!(
                authenticated_key_hash_v0(preimage)? == *hash,
                "authenticated snapshot preimage hash mismatch"
            );
        }
        for leaf in self.nodes.values().filter_map(|node| match node {
            Node::Leaf(leaf) => Some(leaf),
            Node::Null | Node::Internal(_) => None,
        }) {
            ensure!(
                self.preimages.contains_key(&leaf.key_hash()),
                "authenticated snapshot live leaf lacks preimage"
            );
        }
        self.visit_verified_live_values_v0(latest, |_, _| {})
    }

    pub(crate) fn verified_live_values_v0(
        &self,
        version: Version,
    ) -> Result<BTreeMap<Vec<u8>, Vec<u8>>> {
        let mut live = BTreeMap::new();
        self.visit_verified_live_values_v0(version, |key, value| {
            live.insert(key.to_vec(), value);
        })?;
        Ok(live)
    }

    /// Consumers share the same proof and duplicate-key checks. Recovery can
    /// discard each verified value; full-map consumers explicitly retain it.
    fn visit_verified_live_values_v0(
        &self,
        version: Version,
        mut visit: impl FnMut(&[u8], Vec<u8>),
    ) -> Result<()> {
        let expected_root = self
            .roots
            .get(&version)
            .copied()
            .with_context(|| format!("missing authenticated root at version {version}"))?;
        let reader = Arc::new(BorrowedNativeTreeReaderV0(self));
        let iterator = JellyfishMerkleIterator::new(Arc::clone(&reader), version, KeyHash([0; 32]))
            .with_context(|| format!("open authenticated iterator at version {version}"))?;
        let tree = Sha256Jmt::new(self);
        let mut seen = BTreeSet::new();
        for entry in iterator {
            let (hash, value) = entry
                .with_context(|| format!("iterate authenticated tree at version {version}"))?;
            let (actual_value, proof) = tree
                .get_with_proof(hash, version)
                .with_context(|| format!("prove authenticated value at version {version}"))?;
            ensure!(
                actual_value.as_deref() == Some(value.as_slice()),
                "authenticated iterator value disagrees with leaf"
            );
            proof.verify_existence(expected_root, hash, &value)?;
            let preimage = self
                .preimages
                .get(&hash)
                .with_context(|| format!("missing authenticated key preimage {hash:?}"))?;
            ensure!(
                authenticated_key_hash_v0(preimage)? == hash,
                "authenticated live key preimage mismatch"
            );
            ensure!(
                seen.insert(preimage.as_slice()),
                "duplicate authenticated live key"
            );
            visit(preimage, value);
        }
        Ok(())
    }

    pub(crate) fn prove_raw_key_v0(
        &self,
        version: Version,
        key: &[u8],
    ) -> Result<(Option<Vec<u8>>, Vec<u8>)> {
        use prost::Message;
        let expected_root = self
            .roots
            .get(&version)
            .copied()
            .with_context(|| format!("missing authenticated root at version {version}"))?;
        let (value, proof) = Sha256Jmt::new(self)
            .get_with_ics23_proof(key.to_vec(), version)
            .context("create native JMT ICS23 proof")?;
        let proof_bytes = proof.encode_to_vec();
        ensure!(!proof_bytes.is_empty(), "native JMT ICS23 proof is empty");
        ensure!(expected_root == self.roots[&version], "proof root drift");
        Ok((value, proof_bytes))
    }

    fn apply_batch_v0(
        &mut self,
        version: Version,
        root: RootHash,
        batch: TreeUpdateBatch,
        preimages: BTreeMap<KeyHash, Vec<u8>>,
    ) -> Result<()> {
        for (hash, preimage) in &preimages {
            ensure!(
                authenticated_key_hash_v0(preimage)? == *hash,
                "preimage hash mismatch"
            );
            if let Some(existing) = self.preimages.get(hash) {
                ensure!(existing == preimage, "SHA-256 authenticated key collision");
            }
        }
        for (node_key, node) in batch.node_batch.nodes() {
            self.nodes.insert(node_key.clone(), node.clone());
        }
        for ((value_version, hash), value) in batch.node_batch.values() {
            self.values.insert((*hash, *value_version), value.clone());
        }
        self.stale_nodes.extend(batch.stale_node_index_batch);
        self.preimages.extend(preimages);
        self.roots.insert(version, root);
        Ok(())
    }
}

impl TreeReader for InMemoryNativeExecutionStoreV0 {
    fn get_node_option(&self, node_key: &NodeKey) -> Result<Option<Node>> {
        Ok(self.nodes.get(node_key).cloned())
    }

    fn get_value_option(&self, max_version: Version, key_hash: KeyHash) -> Result<Option<Vec<u8>>> {
        Ok(self
            .values
            .range((key_hash, 0)..=(key_hash, max_version))
            .next_back()
            .and_then(|(_, value)| value.clone()))
    }

    fn get_rightmost_leaf(&self) -> Result<Option<(NodeKey, LeafNode)>> {
        Ok(self
            .nodes
            .iter()
            .filter_map(|(key, node)| match node {
                Node::Leaf(leaf) => Some((key.clone(), leaf.clone())),
                Node::Null | Node::Internal(_) => None,
            })
            .max_by_key(|(key, leaf)| (leaf.key_hash(), key.version())))
    }
}

impl HasPreimage for InMemoryNativeExecutionStoreV0 {
    fn preimage(&self, key_hash: KeyHash) -> Result<Option<Vec<u8>>> {
        Ok(self.preimages.get(&key_hash).cloned())
    }
}

impl NativeExecutionStoreV0 for InMemoryNativeExecutionStoreV0 {
    fn parent_version_v0(&self) -> Result<Version> {
        self.roots
            .last_key_value()
            .map(|(version, _)| *version)
            .context("missing parent version")
    }

    fn parent_root_v0(&self) -> Result<RootHash> {
        self.roots
            .last_key_value()
            .map(|(_, root)| *root)
            .context("missing parent root")
    }

    fn chain_id_v0(&self) -> Result<&str> {
        Ok(&self.chain_id)
    }

    fn authorized_signers_v0(&self) -> Result<&[AuthorizedSignerV0]> {
        Ok(&self.signers)
    }

    fn signer_policy_commitment_v0(&self) -> Result<[u8; 32]> {
        Ok(self.signer_policy_commitment)
    }

    fn consensus_parameters_v0(&self) -> Result<ConsensusParametersV0> {
        Ok(self.consensus_parameters)
    }

    fn committed_command_id_v0(&self, command_id: &str) -> Result<bool> {
        Ok(self.committed_command_ids.contains(command_id))
    }

    fn committed_signer_nonce_v0(&self, signer_id: &str, nonce: u64) -> Result<bool> {
        Ok(self
            .committed_signer_nonces
            .contains(&(signer_id.to_string(), nonce)))
    }
}

#[cfg(test)]
mod snapshot_encoding_tests {
    use super::*;

    fn empty_store() -> InMemoryNativeExecutionStoreV0 {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        InMemoryNativeExecutionStoreV0::new(
            "trnm-snapshot-encoding-test",
            vec![AuthorizedSignerV0::new(
                "snapshot-signer",
                "operator",
                hex::encode(signing_key.verifying_key().to_bytes()),
            )
            .unwrap()],
            ConsensusParametersV0::reference_shadow_v0(),
        )
        .unwrap()
    }

    // Preserve the old owned encoding as an independent compatibility oracle.
    fn owned_snapshot_bytes(store: &InMemoryNativeExecutionStoreV0) -> Vec<u8> {
        borsh::to_vec(&PersistentAuthTreeSnapshotV0 {
            codec_version: NATIVE_AUTH_TREE_SNAPSHOT_CODEC_VERSION_V0,
            nodes: store.nodes.clone(),
            values: store.values.clone(),
            preimages: store.preimages.clone(),
            stale_nodes: store.stale_nodes.clone(),
            roots: store.roots.clone(),
        })
        .unwrap()
    }

    fn assert_encoding_and_restore(store: &InMemoryNativeExecutionStoreV0) {
        let bytes = store.encode_authenticated_snapshot_v0().unwrap();
        assert_eq!(bytes, owned_snapshot_bytes(store));
        let restored = InMemoryNativeExecutionStoreV0::decode_authenticated_snapshot_v0(
            store.chain_id.clone(),
            store.signers.clone(),
            store.consensus_parameters,
            store.committed_command_ids.clone(),
            store.committed_signer_nonces.clone(),
            &bytes,
        )
        .unwrap();
        assert_eq!(restored.encode_authenticated_snapshot_v0().unwrap(), bytes);
        assert_eq!(restored.roots, store.roots);
        for version in store.roots.keys().copied() {
            assert_eq!(
                restored.verified_live_values_v0(version).unwrap(),
                store.verified_live_values_v0(version).unwrap(),
            );
        }
    }

    fn historical_store() -> InMemoryNativeExecutionStoreV0 {
        let mut store = empty_store();
        for version in 0..3 {
            store
                .apply_seed_v0(
                    version,
                    vec![
                        NativeStateWriteV0::raw(b"account".to_vec(), vec![version as u8; 257])
                            .unwrap(),
                    ],
                )
                .unwrap();
        }
        store
    }

    fn restore(store: &InMemoryNativeExecutionStoreV0) -> Result<InMemoryNativeExecutionStoreV0> {
        InMemoryNativeExecutionStoreV0::decode_authenticated_snapshot_v0(
            store.chain_id.clone(),
            store.signers.clone(),
            store.consensus_parameters,
            store.committed_command_ids.clone(),
            store.committed_signer_nonces.clone(),
            &store.encode_authenticated_snapshot_v0().unwrap(),
        )
    }

    #[test]
    fn snapshot_rejects_corrupt_historical_root_below_healthy_latest_root() {
        let mut store = historical_store();
        let latest_root = store.parent_root_v0().unwrap();
        store.roots.insert(0, RootHash([42; 32]));
        assert_eq!(
            Sha256Jmt::new(&store).get_root_hash(2).unwrap(),
            latest_root
        );
        assert!(
            restore(&store).is_err(),
            "historical root corruption was admitted"
        );
    }

    #[test]
    fn snapshot_rejects_substituted_historical_root_node_below_healthy_head() {
        let mut store = historical_store();
        let historical_key = store
            .nodes
            .keys()
            .find(|key| key.version() == 0 && key.nibble_path().is_empty())
            .unwrap()
            .clone();
        store.nodes.insert(historical_key, Node::Null);
        assert_eq!(
            Sha256Jmt::new(&store).get_root_hash(2).unwrap(),
            store.parent_root_v0().unwrap(),
        );
        assert!(
            restore(&store).is_err(),
            "historical root-node substitution was admitted"
        );
    }

    #[test]
    fn snapshot_rejects_missing_historical_root_even_when_latest_is_healthy() {
        let mut store = historical_store();
        store
            .nodes
            .retain(|key, _| key.version() != 0 || !key.nibble_path().is_empty());
        assert!(restore(&store).is_err());
    }

    #[test]
    fn snapshot_audit_and_live_map_both_reject_corrupt_latest_value() {
        let mut store = historical_store();
        let hash = authenticated_key_hash_v0(b"account").unwrap();
        store.values.insert((hash, 2), Some(vec![99; 257]));
        assert!(restore(&store).is_err());
        assert!(store.verified_live_values_v0(2).is_err());
        let mut published = 0;
        assert!(store
            .visit_verified_live_values_v0(2, |_, _| published += 1)
            .is_err());
        assert_eq!(published, 0, "unverified value reached the consumer");
    }

    #[test]
    fn snapshot_audit_and_live_map_both_reject_corrupt_latest_preimage() {
        let mut store = historical_store();
        let hash = authenticated_key_hash_v0(b"account").unwrap();
        store.preimages.insert(hash, b"different-account".to_vec());
        assert!(restore(&store).is_err());
        assert!(store.verified_live_values_v0(2).is_err());
        let mut published = 0;
        assert!(store
            .visit_verified_live_values_v0(2, |_, _| published += 1)
            .is_err());
        assert_eq!(published, 0, "unverified preimage reached the consumer");
    }

    #[test]
    fn borrowed_snapshot_matches_owned_for_empty_collections_and_empty_roots() {
        let mut store = empty_store();
        let bytes = store.encode_authenticated_snapshot_v0().unwrap();
        assert_eq!(bytes, owned_snapshot_bytes(&store));
        // A u16 codec followed by five empty Borsh collection lengths (u32).
        assert_eq!(bytes, [vec![1, 0], vec![0; 20]].concat());
        let decoded: PersistentAuthTreeSnapshotV0 = borsh::from_slice(&bytes).unwrap();
        assert_eq!(borsh::to_vec(&decoded).unwrap(), bytes);

        for version in 0..=1 {
            store.apply_seed_v0(version, Vec::new()).unwrap();
            assert_encoding_and_restore(&store);
        }
    }

    #[test]
    fn borrowed_snapshot_matches_owned_across_updates_deletes_and_stale_history() {
        let mut store = empty_store();
        store
            .apply_seed_v0(
                0,
                vec![
                    NativeStateWriteV0::raw(b"c".to_vec(), vec![3; 513]).unwrap(),
                    NativeStateWriteV0::raw(b"a".to_vec(), vec![1; 257]).unwrap(),
                    NativeStateWriteV0::raw(b"b".to_vec(), vec![2; 129]).unwrap(),
                ],
            )
            .unwrap();
        assert_encoding_and_restore(&store);

        let updates = [
            vec![
                (b"a".to_vec(), Some(Vec::new())),
                (b"b".to_vec(), Some(vec![4; 65])),
            ],
            vec![(b"b".to_vec(), None), (b"d".to_vec(), Some(vec![5; 1025]))],
            vec![
                (b"a".to_vec(), None),
                (b"c".to_vec(), None),
                (b"d".to_vec(), None),
            ],
            vec![(b"b".to_vec(), Some(vec![6; 33]))],
        ];
        for (parent_version, writes) in updates.into_iter().enumerate() {
            let parent_version = parent_version as Version;
            let plan = plan_complete_state_update_v0(
                &store,
                parent_version,
                parent_version + 1,
                writes
                    .into_iter()
                    .map(|(key, value)| CompleteStateWriteV0::new(key, value).unwrap())
                    .collect(),
            )
            .unwrap();
            store.apply_complete_state_plan_v0(plan).unwrap();
            assert_encoding_and_restore(&store);
        }
        assert_eq!(store.roots.len(), 5);
        assert!(!store.stale_nodes.is_empty());
        assert!(store.values.values().any(Option::is_none));
        assert!(store.verified_live_values_v0(3).unwrap().is_empty());
        assert_eq!(store.verified_live_values_v0(4).unwrap().len(), 1);
    }
}
