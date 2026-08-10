//! Versioned authenticated state primitives for AppHash v4.
//!
//! This module deliberately keeps the JMT storage adapter independent from
//! SQLite and ABCI.  The in-memory implementation is useful for deterministic
//! planning, migration checks, and tests; a persistent adapter can implement
//! the same [`TreeReader`] and [`HasPreimage`] contracts.

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

use anyhow::{ensure, Context, Result};
use borsh::{BorshDeserialize, BorshSerialize};
use jmt::{
    ics23_spec,
    storage::{HasPreimage, LeafNode, Node, NodeKey, StaleNodeIndex, TreeReader, TreeUpdateBatch},
    JellyfishMerkleIterator, KeyHash, RootHash, Sha256Jmt, Version,
};
use prost::Message;
use sha2::{Digest, Sha256};

use crate::poco_transition::PocoWritePermitV0;

pub(crate) mod durable_plan;

const KEY_DOMAIN: &[u8] = b"trnm/authenticated-state/v4";
const POCO_SNAPSHOT_KEY_PREFIX: &[u8] = b"trnm/authenticated-state/v4\0\x08";
const OBJECT_RECORD_SCHEMA_VERSION: u16 = 1;
#[cfg(test)]
const LIFECYCLE_RECORD_SCHEMA_VERSION: u16 = 1;
const AUTH_TREE_SNAPSHOT_CODEC_VERSION: u16 = 1;
pub(crate) const MAX_AUTH_KEY_PREIMAGE_BYTES: usize = 1024 * 1024;
const PLANNED_AUTH_UPDATE_SEAL_CODEC_VERSION_V0: u16 = 0;
const PLANNED_AUTH_UPDATE_SEAL_HASH_PREFIX_V0: &[u8] = b"trnm.auth-tree.plan-seal.hash.v0";
const PLANNED_AUTH_UPDATE_SEAL_DOMAIN_V0: &[u8] = b"trnm.consensus-app.planned-auth-update.v0";

/// Consensus-state namespaces.  Discriminants are part of the AppHash v4 key
/// format and therefore must never be renumbered.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
#[allow(dead_code)]
pub enum StateNamespace {
    Object = 1,
    Account = 2,
    Task = 3,
    ValidatorLifecycle = 4,
    Config = 5,
    CommandReceipt = 6,
    GovernanceSequence = 7,
    PocoSnapshot = 8,
}

/// Constructs a collision-free, non-empty authenticated key.
///
/// Each component is length-prefixed, so components such as `["ab", "c"]`
/// cannot collide with `["a", "bc"]`.  Empty components are rejected because
/// ICS23 non-membership proofs require recoverable, non-empty preimages.
pub fn namespaced_key(namespace: StateNamespace, components: &[&[u8]]) -> Result<Vec<u8>> {
    ensure!(
        !components.is_empty(),
        "authenticated key needs a component"
    );
    ensure!(
        components.len() <= u16::MAX as usize,
        "too many authenticated key components"
    );

    let mut key = Vec::with_capacity(KEY_DOMAIN.len() + 8);
    key.extend_from_slice(KEY_DOMAIN);
    key.push(0);
    key.push(namespace as u8);
    key.extend_from_slice(&(components.len() as u16).to_be_bytes());

    for component in components {
        ensure!(
            !component.is_empty(),
            "authenticated key components must be non-empty"
        );
        let len = u32::try_from(component.len())
            .context("authenticated key component exceeds u32::MAX bytes")?;
        key.extend_from_slice(&len.to_be_bytes());
        key.extend_from_slice(component);
    }

    debug_assert!(!key.is_empty());
    Ok(key)
}

/// Authenticated key for an existing consensus-app `StoredObject`.
///
/// The current store names this field `object_key_hex`, but older fixtures use
/// short textual keys.  Commit its exact UTF-8 representation instead of
/// normalizing or re-encoding it during migration.
pub fn stored_object_key(object_key_hex: &str) -> Result<Vec<u8>> {
    namespaced_key(StateNamespace::Object, &[object_key_hex.as_bytes()])
}

pub(crate) fn stored_object_key_preimage(preimage: &[u8]) -> Result<String> {
    let header_len = KEY_DOMAIN.len() + 1 + 1 + 2;
    ensure!(
        preimage.len() >= header_len + 4,
        "authenticated object key preimage is truncated"
    );
    ensure!(
        &preimage[..KEY_DOMAIN.len()] == KEY_DOMAIN,
        "authenticated object key domain mismatch"
    );
    let mut cursor = KEY_DOMAIN.len();
    ensure!(
        preimage[cursor] == 0,
        "authenticated object key domain separator mismatch"
    );
    cursor += 1;
    ensure!(
        preimage[cursor] == StateNamespace::Object as u8,
        "authenticated key is not in the object namespace"
    );
    cursor += 1;
    let component_count =
        u16::from_be_bytes([preimage[cursor], preimage[cursor.saturating_add(1)]]);
    cursor += 2;
    ensure!(
        component_count == 1,
        "authenticated object key must have one component"
    );
    let component_len = u32::from_be_bytes(
        preimage[cursor..cursor + 4]
            .try_into()
            .expect("object key length was checked"),
    ) as usize;
    cursor += 4;
    ensure!(
        component_len > 0 && cursor.saturating_add(component_len) == preimage.len(),
        "authenticated object key component length mismatch"
    );
    String::from_utf8(preimage[cursor..].to_vec()).context("authenticated object key is not UTF-8")
}

#[cfg(test)]
pub fn account_key(account_id: &str) -> Result<Vec<u8>> {
    namespaced_key(StateNamespace::Account, &[account_id.as_bytes()])
}

#[cfg(test)]
pub fn task_key(task_id: &str) -> Result<Vec<u8>> {
    namespaced_key(StateNamespace::Task, &[task_id.as_bytes()])
}

/// Fixed key for the effective validator lifecycle/configuration state.
///
/// Sequence-specific history belongs in receipts; the current state has one
/// stable key so updates remain incremental.
pub fn validator_state_key() -> Result<Vec<u8>> {
    namespaced_key(StateNamespace::ValidatorLifecycle, &[b"current"])
}

fn key_hash(key: &[u8]) -> Result<KeyHash> {
    ensure!(!key.is_empty(), "authenticated key must be non-empty");
    Ok(KeyHash::with::<Sha256>(key))
}

pub(crate) fn authenticated_key_hash(key: &[u8]) -> Result<KeyHash> {
    key_hash(key)
}

/// Decodes the exact length-framed components of a namespace-8 key. Keys in
/// other namespaces return `None`; malformed namespace-8 preimages fail
/// closed so restore/startup cannot reinterpret them as ordinary objects.
pub(crate) fn poco_snapshot_key_components(key: &[u8]) -> Result<Option<Vec<&[u8]>>> {
    if !key.starts_with(POCO_SNAPSHOT_KEY_PREFIX) {
        return Ok(None);
    }
    let mut cursor = POCO_SNAPSHOT_KEY_PREFIX.len();
    ensure!(
        key.len() >= cursor.saturating_add(2),
        "PoCO snapshot key component count is truncated"
    );
    let component_count = u16::from_be_bytes(
        key[cursor..cursor + 2]
            .try_into()
            .expect("component count length checked"),
    ) as usize;
    cursor += 2;
    ensure!(
        (1..=3).contains(&component_count),
        "PoCO snapshot key component count is invalid"
    );
    let mut components = Vec::with_capacity(component_count);
    for _ in 0..component_count {
        ensure!(
            key.len() >= cursor.saturating_add(4),
            "PoCO snapshot key component length is truncated"
        );
        let length = u32::from_be_bytes(
            key[cursor..cursor + 4]
                .try_into()
                .expect("component length checked"),
        ) as usize;
        cursor += 4;
        ensure!(length > 0, "PoCO snapshot key component is empty");
        let end = cursor
            .checked_add(length)
            .context("PoCO snapshot key component length overflow")?;
        ensure!(end <= key.len(), "PoCO snapshot key component is truncated");
        components.push(&key[cursor..end]);
        cursor = end;
    }
    ensure!(cursor == key.len(), "PoCO snapshot key has trailing bytes");
    Ok(Some(components))
}

/// Exact value committed for an object leaf.
///
/// The redundant `value_hash` is authenticated along with the bytes and is
/// checked on construction and decoding.  This makes corruption detectable
/// before a record is interpreted by the runtime.
#[derive(Clone, Debug, Eq, PartialEq, BorshDeserialize, BorshSerialize)]
pub struct AuthenticatedObjectRecord {
    pub schema_version: u16,
    pub object_type: String,
    pub object_version: u64,
    pub value_hash: [u8; 32],
    pub value: Vec<u8>,
}

impl AuthenticatedObjectRecord {
    pub fn new(
        object_type: impl Into<String>,
        object_version: u64,
        value: Vec<u8>,
    ) -> Result<Self> {
        let object_type = object_type.into();
        ensure!(!object_type.is_empty(), "object type must be non-empty");
        let value_hash = Sha256::digest(&value).into();
        Ok(Self {
            schema_version: OBJECT_RECORD_SCHEMA_VERSION,
            object_type,
            object_version,
            value_hash,
            value,
        })
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        borsh::to_vec(self).context("encode authenticated object record")
    }

    pub fn decode(encoded: &[u8]) -> Result<Self> {
        let record: Self =
            borsh::from_slice(encoded).context("decode authenticated object record")?;
        record.validate()?;
        Ok(record)
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.schema_version == OBJECT_RECORD_SCHEMA_VERSION,
            "unsupported object record schema {}",
            self.schema_version
        );
        ensure!(
            !self.object_type.is_empty(),
            "object type must be non-empty"
        );
        ensure!(
            self.value_hash == <[u8; 32]>::from(Sha256::digest(&self.value)),
            "authenticated object value hash mismatch"
        );
        Ok(())
    }
}

/// Validator-set transition committed under [`StateNamespace::ValidatorLifecycle`].
#[cfg(test)]
#[allow(dead_code)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, BorshDeserialize, BorshSerialize)]
#[repr(u8)]
#[borsh(use_discriminant = true)]
pub enum ValidatorLifecycleAction {
    Add = 1,
    Remove = 2,
    Rotate = 3,
}

/// Exact lifecycle record committed to the authenticated tree.
#[cfg(test)]
#[derive(Clone, Debug, Eq, PartialEq, BorshDeserialize, BorshSerialize)]
pub struct ValidatorLifecycleRecord {
    pub schema_version: u16,
    pub sequence: u64,
    pub action: ValidatorLifecycleAction,
    pub validator_id: String,
    pub previous_consensus_key: Option<[u8; 32]>,
    pub consensus_key: Option<[u8; 32]>,
    pub voting_power: u64,
    pub effective_height: u64,
}

#[cfg(test)]
impl ValidatorLifecycleRecord {
    pub fn rotate(
        sequence: u64,
        validator_id: impl Into<String>,
        previous_consensus_key: [u8; 32],
        consensus_key: [u8; 32],
        voting_power: u64,
        effective_height: u64,
    ) -> Result<Self> {
        Self {
            schema_version: LIFECYCLE_RECORD_SCHEMA_VERSION,
            sequence,
            action: ValidatorLifecycleAction::Rotate,
            validator_id: validator_id.into(),
            previous_consensus_key: Some(previous_consensus_key),
            consensus_key: Some(consensus_key),
            voting_power,
            effective_height,
        }
        .validated()
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        borsh::to_vec(self).context("encode validator lifecycle record")
    }

    pub fn decode(encoded: &[u8]) -> Result<Self> {
        let record: Self =
            borsh::from_slice(encoded).context("decode validator lifecycle record")?;
        record.validate()?;
        Ok(record)
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.schema_version == LIFECYCLE_RECORD_SCHEMA_VERSION,
            "unsupported lifecycle record schema {}",
            self.schema_version
        );
        ensure!(
            !self.validator_id.is_empty(),
            "validator id must be non-empty"
        );
        ensure!(
            self.effective_height > 0,
            "lifecycle effective height must be positive"
        );
        match self.action {
            ValidatorLifecycleAction::Add => {
                ensure!(
                    self.previous_consensus_key.is_none()
                        && self.consensus_key.is_some()
                        && self.voting_power > 0,
                    "invalid validator add lifecycle record"
                );
            }
            ValidatorLifecycleAction::Remove => {
                ensure!(
                    self.previous_consensus_key.is_some()
                        && self.consensus_key.is_none()
                        && self.voting_power == 0,
                    "invalid validator remove lifecycle record"
                );
            }
            ValidatorLifecycleAction::Rotate => {
                ensure!(
                    self.previous_consensus_key.is_some()
                        && self.consensus_key.is_some()
                        && self.previous_consensus_key != self.consensus_key
                        && self.voting_power > 0,
                    "invalid validator rotation lifecycle record"
                );
            }
        }
        Ok(())
    }

    fn validated(self) -> Result<Self> {
        self.validate()?;
        Ok(self)
    }
}

/// A single raw authenticated write.  `None` is a deletion/tombstone.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthWrite {
    key: Vec<u8>,
    value: Option<Vec<u8>>,
}

impl AuthWrite {
    pub fn put(key: Vec<u8>, value: Vec<u8>) -> Result<Self> {
        ensure!(!key.is_empty(), "authenticated key must be non-empty");
        ensure!(
            !key.starts_with(POCO_SNAPSHOT_KEY_PREFIX),
            "PoCO snapshot writes require the atomic PoCO planner"
        );
        Ok(Self {
            key,
            value: Some(value),
        })
    }

    #[cfg(test)]
    pub fn delete(key: Vec<u8>) -> Result<Self> {
        ensure!(!key.is_empty(), "authenticated key must be non-empty");
        ensure!(
            !key.starts_with(POCO_SNAPSHOT_KEY_PREFIX),
            "PoCO snapshot writes require the atomic PoCO planner"
        );
        Ok(Self { key, value: None })
    }

    pub(crate) fn put_poco_snapshot(
        _permit: PocoWritePermitV0,
        key: Vec<u8>,
        value: Vec<u8>,
    ) -> Result<Self> {
        ensure!(
            key.starts_with(POCO_SNAPSHOT_KEY_PREFIX),
            "sealed PoCO write is outside the PoCO snapshot namespace"
        );
        Ok(Self {
            key,
            value: Some(value),
        })
    }

    pub(crate) fn delete_poco_snapshot(_permit: PocoWritePermitV0, key: Vec<u8>) -> Result<Self> {
        ensure!(
            key.starts_with(POCO_SNAPSHOT_KEY_PREFIX),
            "sealed PoCO delete is outside the PoCO snapshot namespace"
        );
        Ok(Self { key, value: None })
    }

    pub(crate) fn key(&self) -> &[u8] {
        &self.key
    }

    pub(crate) fn value(&self) -> Option<&[u8]> {
        self.value.as_deref()
    }
}

/// A deterministic JMT update that has not yet been applied to storage.
#[derive(Clone, Debug)]
pub struct PlannedAuthUpdate {
    pub version: Version,
    pub root_hash: RootHash,
    pub tree_update_batch: TreeUpdateBatch,
    preimages: BTreeMap<KeyHash, Vec<u8>>,
}

/// Process-local integrity seal for every persistence-bearing plan field.
///
/// This type deliberately has no public constructor, byte accessor, clone,
/// serde, or Borsh surface. It is an internal continuity check between the
/// planner and its later consumer, not a wire commitment or execution
/// authority.
pub(crate) struct PlannedAuthUpdateSealV0([u8; 32]);

impl PartialEq for PlannedAuthUpdateSealV0 {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Eq for PlannedAuthUpdateSealV0 {}

impl std::fmt::Debug for PlannedAuthUpdateSealV0 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PlannedAuthUpdateSealV0")
            .field("opaque", &true)
            .finish_non_exhaustive()
    }
}

/// Frozen deterministic preimage for [`PlannedAuthUpdateSealV0`]. JMT node
/// statistics are intentionally omitted: neither the in-memory apply path nor
/// SQLite persistence consumes them. All state-affecting plan contents are
/// included explicitly so a future `TreeUpdateBatch` metadata change cannot
/// silently change this seal's meaning.
#[derive(BorshSerialize)]
struct PlannedAuthUpdateSealPreimageV0<'a> {
    codec_version: u16,
    version: Version,
    root_hash: &'a RootHash,
    nodes: &'a BTreeMap<NodeKey, Node>,
    values: &'a BTreeMap<(Version, KeyHash), Option<Vec<u8>>>,
    stale_node_indices: &'a BTreeSet<StaleNodeIndex>,
    preimages: &'a BTreeMap<KeyHash, Vec<u8>>,
}

impl PlannedAuthUpdate {
    pub(crate) fn preimages(&self) -> &BTreeMap<KeyHash, Vec<u8>> {
        &self.preimages
    }

    /// Seals the exact version, root, nodes, values, stale indices, and key
    /// preimages of this deterministic plan without granting persistence or
    /// terminal authority.
    pub(crate) fn seal_v0(&self) -> Result<PlannedAuthUpdateSealV0> {
        let encoded = borsh::to_vec(&PlannedAuthUpdateSealPreimageV0 {
            codec_version: PLANNED_AUTH_UPDATE_SEAL_CODEC_VERSION_V0,
            version: self.version,
            root_hash: &self.root_hash,
            nodes: self.tree_update_batch.node_batch.nodes(),
            values: self.tree_update_batch.node_batch.values(),
            stale_node_indices: &self.tree_update_batch.stale_node_index_batch,
            preimages: &self.preimages,
        })
        .context("encode planned authenticated update seal preimage")?;
        Ok(PlannedAuthUpdateSealV0(framed_plan_seal_hash_v0(&encoded)?))
    }

    /// Recomputes the complete deterministic plan seal and fails closed if any
    /// persistence-bearing field drifted after the plan was sealed.
    pub(crate) fn verify_seal_v0(&self, expected: &PlannedAuthUpdateSealV0) -> Result<()> {
        let actual = self.seal_v0()?;
        ensure!(
            &actual == expected,
            "planned authenticated update seal mismatch"
        );
        Ok(())
    }
}

fn framed_plan_seal_hash_v0(encoded: &[u8]) -> Result<[u8; 32]> {
    let mut hasher = Sha256::new();
    for frame in [
        PLANNED_AUTH_UPDATE_SEAL_HASH_PREFIX_V0,
        PLANNED_AUTH_UPDATE_SEAL_DOMAIN_V0,
        encoded,
    ] {
        let length = u32::try_from(frame.len()).context("plan seal hash frame exceeds u32::MAX")?;
        hasher.update(length.to_be_bytes());
        hasher.update(frame);
    }
    Ok(hasher.finalize().into())
}

/// ICS23 proof plus the exact root/version it proves against.
#[derive(Clone, Debug)]
pub struct AuthProof {
    pub version: Version,
    pub root_hash: RootHash,
    pub key: Vec<u8>,
    pub value: Option<Vec<u8>>,
    pub commitment_proof: ics23::CommitmentProof,
}

impl AuthProof {
    pub fn encoded_commitment_proof(&self) -> Vec<u8> {
        self.commitment_proof.encode_to_vec()
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PruneStats {
    pub nodes_removed: usize,
    pub value_versions_removed: usize,
    pub preimages_removed: usize,
    pub stale_indices_removed: usize,
    pub roots_removed: usize,
}

/// Cloneable, deterministic, versioned in-memory JMT storage.
#[derive(Clone, Debug, Default)]
pub struct InMemoryAuthTree {
    nodes: BTreeMap<NodeKey, Node>,
    // Hash-first ordering keeps point reads logarithmic in total history.
    values: BTreeMap<(KeyHash, Version), Option<Vec<u8>>>,
    preimages: BTreeMap<KeyHash, Vec<u8>>,
    stale_nodes: BTreeSet<StaleNodeIndex>,
    roots: BTreeMap<Version, RootHash>,
}

struct VersionedReadView<'a> {
    nodes: &'a BTreeMap<NodeKey, Node>,
    values: &'a BTreeMap<(KeyHash, Version), Option<Vec<u8>>>,
}

/// Read-only overlay for proving a bounded planned update without cloning or
/// applying the complete authenticated-tree history.
struct PlannedReadView<'a> {
    base: &'a InMemoryAuthTree,
    plan: &'a PlannedAuthUpdate,
}

impl TreeReader for PlannedReadView<'_> {
    fn get_node_option(&self, node_key: &NodeKey) -> Result<Option<Node>> {
        Ok(self
            .plan
            .tree_update_batch
            .node_batch
            .get_node(node_key)
            .cloned()
            .or_else(|| self.base.nodes.get(node_key).cloned()))
    }

    fn get_value_option(&self, max_version: Version, key_hash: KeyHash) -> Result<Option<Vec<u8>>> {
        if self.plan.version <= max_version {
            if let Some(value) = self
                .plan
                .tree_update_batch
                .node_batch
                .values()
                .get(&(self.plan.version, key_hash))
            {
                return Ok(value.clone());
            }
        }
        self.base.get_value_option(max_version, key_hash)
    }

    fn get_rightmost_leaf(&self) -> Result<Option<(NodeKey, LeafNode)>> {
        let base = self.base.get_rightmost_leaf()?;
        let planned = self
            .plan
            .tree_update_batch
            .node_batch
            .nodes()
            .iter()
            .filter_map(|(node_key, node)| match node {
                Node::Leaf(leaf) => Some((node_key.clone(), leaf.clone())),
                Node::Null | Node::Internal(_) => None,
            })
            .max_by_key(|(node_key, leaf)| (leaf.key_hash(), node_key.version()));
        Ok([base, planned]
            .into_iter()
            .flatten()
            .max_by_key(|(node_key, leaf)| (leaf.key_hash(), node_key.version())))
    }
}

impl HasPreimage for PlannedReadView<'_> {
    fn preimage(&self, key_hash: KeyHash) -> Result<Option<Vec<u8>>> {
        Ok(self
            .plan
            .preimages
            .get(&key_hash)
            .cloned()
            .or_else(|| self.base.preimages.get(&key_hash).cloned()))
    }
}

impl<'a> VersionedReadView<'a> {
    fn new(tree: &'a InMemoryAuthTree) -> Self {
        Self {
            nodes: &tree.nodes,
            values: &tree.values,
        }
    }
}

impl TreeReader for VersionedReadView<'_> {
    fn get_node_option(&self, node_key: &NodeKey) -> Result<Option<Node>> {
        Ok(self.nodes.get(node_key).cloned())
    }

    fn get_value_option(&self, max_version: Version, key_hash: KeyHash) -> Result<Option<Vec<u8>>> {
        Ok(self
            .values
            .range((key_hash, 0)..=(key_hash, max_version))
            .next_back()
            .and_then(|(_, value)| value.as_ref().cloned()))
    }

    fn get_rightmost_leaf(&self) -> Result<Option<(NodeKey, LeafNode)>> {
        Ok(self
            .nodes
            .iter()
            .filter_map(|(node_key, node)| match node {
                Node::Leaf(leaf) => Some((node_key, leaf)),
                Node::Null | Node::Internal(_) => None,
            })
            .max_by_key(|(node_key, leaf)| (leaf.key_hash(), node_key.version()))
            .map(|(node_key, leaf)| (node_key.clone(), leaf.clone())))
    }
}

#[derive(BorshDeserialize, BorshSerialize)]
struct AuthTreeSnapshot {
    codec_version: u16,
    nodes: BTreeMap<NodeKey, Node>,
    values: BTreeMap<(KeyHash, Version), Option<Vec<u8>>>,
    preimages: BTreeMap<KeyHash, Vec<u8>>,
    stale_nodes: BTreeSet<StaleNodeIndex>,
    roots: BTreeMap<Version, RootHash>,
}

impl InMemoryAuthTree {
    pub(crate) fn encode_snapshot(&self) -> Result<Vec<u8>> {
        borsh::to_vec(&AuthTreeSnapshot {
            codec_version: AUTH_TREE_SNAPSHOT_CODEC_VERSION,
            nodes: self.nodes.clone(),
            values: self.values.clone(),
            preimages: self.preimages.clone(),
            stale_nodes: self.stale_nodes.clone(),
            roots: self.roots.clone(),
        })
        .context("encode authenticated tree snapshot")
    }

    pub(crate) fn decode_snapshot(bytes: &[u8]) -> Result<Self> {
        let snapshot: AuthTreeSnapshot =
            borsh::from_slice(bytes).context("decode authenticated tree snapshot")?;
        ensure!(
            snapshot.codec_version == AUTH_TREE_SNAPSHOT_CODEC_VERSION,
            "unsupported authenticated tree snapshot codec"
        );
        Self::from_parts(
            snapshot.nodes,
            snapshot.values,
            snapshot.preimages,
            snapshot.stale_nodes,
            snapshot.roots,
        )
    }

    /// Reconstructs an in-memory tree from persistent storage.
    ///
    /// This checks version continuity, root-node presence, key preimages, and
    /// the latest root proof before the loaded tree is accepted.
    pub(crate) fn from_parts(
        nodes: BTreeMap<NodeKey, Node>,
        values: BTreeMap<(KeyHash, Version), Option<Vec<u8>>>,
        preimages: BTreeMap<KeyHash, Vec<u8>>,
        stale_nodes: BTreeSet<StaleNodeIndex>,
        roots: BTreeMap<Version, RootHash>,
    ) -> Result<Self> {
        for (hash, preimage) in &preimages {
            ensure!(
                key_hash(preimage)? == *hash,
                "authenticated key preimage hash mismatch"
            );
        }

        if roots.is_empty() {
            ensure!(
                nodes.is_empty()
                    && values.is_empty()
                    && preimages.is_empty()
                    && stale_nodes.is_empty(),
                "authenticated storage has data but no roots"
            );
            return Ok(Self::default());
        }

        let root_node_versions = nodes
            .keys()
            .filter(|key| key.nibble_path().is_empty())
            .map(NodeKey::version)
            .collect::<BTreeSet<_>>();
        let mut previous_version = None;
        for version in roots.keys().copied() {
            if let Some(previous) = previous_version {
                ensure!(
                    version == previous + 1,
                    "authenticated roots are not contiguous at {previous} -> {version}"
                );
            }
            ensure!(
                root_node_versions.contains(&version),
                "missing authenticated root node at version {version}"
            );
            previous_version = Some(version);
        }
        let latest = previous_version.expect("non-empty roots have a latest version");
        ensure!(
            nodes.keys().all(|node_key| node_key.version() <= latest),
            "authenticated node version exceeds latest root"
        );
        ensure!(
            values.keys().all(|(_, version)| *version <= latest),
            "authenticated value version exceeds latest root"
        );
        ensure!(
            stale_nodes
                .iter()
                .all(|index| index.stale_since_version <= latest),
            "authenticated stale index exceeds latest root"
        );

        for leaf in nodes.values().filter_map(|node| match node {
            Node::Leaf(leaf) => Some(leaf),
            Node::Null | Node::Internal(_) => None,
        }) {
            ensure!(
                preimages.contains_key(&leaf.key_hash()),
                "missing authenticated key preimage for live leaf"
            );
        }

        let store = Self {
            nodes,
            values,
            preimages,
            stale_nodes,
            roots,
        };
        let expected_root = store.roots[&latest];
        let verified = store.verified_live_values(latest)?;
        if verified.is_empty() {
            ensure!(
                expected_root == Sha256Jmt::<Self>::EMPTY_ROOT,
                "non-empty authenticated root has no provable value"
            );
        }

        Ok(store)
    }

    pub(crate) fn nodes(&self) -> &BTreeMap<NodeKey, Node> {
        &self.nodes
    }

    pub(crate) fn values(&self) -> &BTreeMap<(KeyHash, Version), Option<Vec<u8>>> {
        &self.values
    }

    pub(crate) fn preimages(&self) -> &BTreeMap<KeyHash, Vec<u8>> {
        &self.preimages
    }

    pub(crate) fn stale_nodes(&self) -> &BTreeSet<StaleNodeIndex> {
        &self.stale_nodes
    }

    pub(crate) fn roots(&self) -> &BTreeMap<Version, RootHash> {
        &self.roots
    }

    pub fn latest_version(&self) -> Option<Version> {
        self.roots.last_key_value().map(|(version, _)| *version)
    }

    pub fn expected_next_version(&self) -> Version {
        self.latest_version().map_or(0, |version| version + 1)
    }

    pub fn root_hash(&self, version: Version) -> Option<RootHash> {
        self.roots.get(&version).copied()
    }

    #[cfg(test)]
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    #[cfg(test)]
    pub fn stale_index_count(&self) -> usize {
        self.stale_nodes.len()
    }

    /// Plans a value set at exactly `version` without mutating this store.
    pub fn plan_put_value_set(
        &self,
        version: Version,
        writes: impl IntoIterator<Item = AuthWrite>,
    ) -> Result<PlannedAuthUpdate> {
        plan_put_value_set(self, self.expected_next_version(), version, writes)
    }

    /// Atomically applies a previously planned update.
    pub fn apply(&mut self, plan: PlannedAuthUpdate) -> Result<RootHash> {
        ensure!(
            plan.version == self.expected_next_version(),
            "stale plan version {}; expected {}",
            plan.version,
            self.expected_next_version()
        );
        ensure!(
            !self.roots.contains_key(&plan.version),
            "authenticated root already exists at version {}",
            plan.version
        );

        for (hash, preimage) in &plan.preimages {
            ensure!(
                key_hash(preimage)? == *hash,
                "authenticated key preimage hash mismatch"
            );
            if let Some(existing) = self.preimages.get(hash) {
                ensure!(
                    existing == preimage,
                    "SHA-256 authenticated key collision in preimage store"
                );
            }
        }

        for (node_key, node) in plan.tree_update_batch.node_batch.nodes() {
            self.nodes.insert(node_key.clone(), node.clone());
        }
        for ((version, hash), value) in plan.tree_update_batch.node_batch.values() {
            self.values.insert((*hash, *version), value.clone());
        }
        self.stale_nodes
            .extend(plan.tree_update_batch.stale_node_index_batch);
        self.preimages.extend(plan.preimages);
        self.roots.insert(plan.version, plan.root_hash);
        Ok(plan.root_hash)
    }

    /// Plans and applies one exact version.
    #[cfg(test)]
    pub fn put_value_set(
        &mut self,
        version: Version,
        writes: impl IntoIterator<Item = AuthWrite>,
    ) -> Result<RootHash> {
        let plan = self.plan_put_value_set(version, writes)?;
        self.apply(plan)
    }

    /// Generates an ICS23 membership or non-membership proof.
    pub fn prove(&self, version: Version, key: Vec<u8>) -> Result<AuthProof> {
        let root_hash = self
            .root_hash(version)
            .with_context(|| format!("missing authenticated root at version {version}"))?;
        prove_with_reader(self, version, root_hash, key)
    }

    /// Reads one exact key at a committed version without allocating an ICS23
    /// proof. The private preimage map is checked to fail closed on a
    /// theoretical key-hash collision.
    pub(crate) fn value_at(&self, version: Version, key: &[u8]) -> Result<Option<Vec<u8>>> {
        self.root_hash(version)
            .with_context(|| format!("missing authenticated root at version {version}"))?;
        let hash = key_hash(key)?;
        if let Some(preimage) = self.preimages.get(&hash) {
            ensure!(preimage == key, "SHA-256 authenticated key collision");
        }
        self.get_value_option(version, hash)
    }

    /// Generates an ICS23 proof against the root of a not-yet-applied bounded
    /// plan through an overlay reader; the full tree is never cloned.
    pub(crate) fn prove_planned(
        &self,
        plan: &PlannedAuthUpdate,
        key: Vec<u8>,
    ) -> Result<AuthProof> {
        ensure!(
            plan.version == self.expected_next_version(),
            "planned proof version is stale"
        );
        let reader = PlannedReadView { base: self, plan };
        prove_with_reader(&reader, plan.version, plan.root_hash, key)
    }

    /// Returns every live key/value pair at `version` and verifies each value
    /// against that version's root before exposing it to domain-state loading.
    pub(crate) fn verified_live_values(
        &self,
        version: Version,
    ) -> Result<BTreeMap<Vec<u8>, Vec<u8>>> {
        self.root_hash(version)
            .with_context(|| format!("missing authenticated root at version {version}"))?;
        let expected_root = self
            .root_hash(version)
            .expect("authenticated root existence checked");
        let reader = Arc::new(VersionedReadView::new(self));
        let iterator = JellyfishMerkleIterator::new(Arc::clone(&reader), version, KeyHash([0; 32]))
            .with_context(|| format!("open authenticated tree iterator at version {version}"))?;
        let tree = Sha256Jmt::new(reader.as_ref());
        let mut live = BTreeMap::new();
        for entry in iterator {
            let (hash, value) = entry
                .with_context(|| format!("iterate authenticated tree at version {version}"))?;
            let (actual_value, proof) = tree
                .get_with_proof(hash, version)
                .with_context(|| format!("prove authenticated value at version {version}"))?;
            ensure!(
                actual_value.as_deref() == Some(value.as_slice()),
                "authenticated iterator value disagrees with JMT leaf"
            );
            proof
                .verify_existence(expected_root, hash, &value)
                .with_context(|| format!("verify authenticated root at version {version}"))?;
            let preimage = self
                .preimages
                .get(&hash)
                .with_context(|| format!("missing live authenticated key preimage {hash:?}"))?
                .clone();
            ensure!(
                key_hash(&preimage)? == hash,
                "live authenticated key preimage hash mismatch"
            );
            ensure!(
                live.insert(preimage, value).is_none(),
                "duplicate live authenticated key preimage"
            );
        }
        Ok(live)
    }

    /// Removes versions older than `retain_from_version`, preserving all data
    /// required to query and prove that version and every newer version.
    pub fn prune_versions_before(&mut self, retain_from_version: Version) -> Result<PruneStats> {
        let latest = self
            .latest_version()
            .context("cannot prune an empty tree")?;
        ensure!(
            retain_from_version <= latest,
            "cannot retain future version {retain_from_version}; latest is {latest}"
        );

        let mut stats = PruneStats::default();
        let stale_to_prune = self
            .stale_nodes
            .iter()
            .filter(|index| index.stale_since_version <= retain_from_version)
            .cloned()
            .collect::<Vec<_>>();
        for stale in &stale_to_prune {
            if self.nodes.remove(&stale.node_key).is_some() {
                stats.nodes_removed += 1;
            }
            if self.stale_nodes.remove(stale) {
                stats.stale_indices_removed += 1;
            }
        }

        // Root nodes are never referenced as children, so removing all old
        // root node keys makes the pruning boundary explicit even after empty
        // versions.
        let old_root_nodes = self
            .nodes
            .keys()
            .filter(|key| key.nibble_path().is_empty() && key.version() < retain_from_version)
            .cloned()
            .collect::<Vec<_>>();
        for node_key in old_root_nodes {
            if self.nodes.remove(&node_key).is_some() {
                stats.nodes_removed += 1;
            }
        }

        let old_roots = self
            .roots
            .range(..retain_from_version)
            .map(|(version, _)| *version)
            .collect::<Vec<_>>();
        for version in old_roots {
            if self.roots.remove(&version).is_some() {
                stats.roots_removed += 1;
            }
        }

        // Keep one anchor value at or before the retention boundary for every
        // key plus all subsequent updates.
        let hashes = self
            .values
            .keys()
            .map(|(hash, _)| *hash)
            .collect::<BTreeSet<_>>();
        let mut keep_values = BTreeSet::new();
        for hash in hashes {
            if let Some(((_, version), _)) = self
                .values
                .range((hash, 0)..=(hash, retain_from_version))
                .next_back()
            {
                keep_values.insert((hash, *version));
            }
        }
        let obsolete_values = self
            .values
            .keys()
            .filter(|(hash, version)| {
                *version < retain_from_version && !keep_values.contains(&(*hash, *version))
            })
            .copied()
            .collect::<Vec<_>>();
        for key in obsolete_values {
            if self.values.remove(&key).is_some() {
                stats.value_versions_removed += 1;
            }
        }

        let live_preimages = self
            .nodes
            .values()
            .filter_map(|node| match node {
                Node::Leaf(leaf) => Some(leaf.key_hash()),
                Node::Null | Node::Internal(_) => None,
            })
            .collect::<BTreeSet<_>>();
        let dead_preimages = self
            .preimages
            .keys()
            .filter(|hash| !live_preimages.contains(hash))
            .copied()
            .collect::<Vec<_>>();
        for hash in dead_preimages {
            if self.preimages.remove(&hash).is_some() {
                stats.preimages_removed += 1;
            }
        }

        Ok(stats)
    }
}

pub(crate) fn plan_put_value_set<R: TreeReader>(
    reader: &R,
    expected_next_version: Version,
    version: Version,
    writes: impl IntoIterator<Item = AuthWrite>,
) -> Result<PlannedAuthUpdate> {
    ensure!(
        version == expected_next_version,
        "version {} is not the exact next version {}",
        version,
        expected_next_version
    );

    let mut hashed_writes = BTreeMap::new();
    let mut preimages = BTreeMap::new();
    for write in writes {
        let hash = key_hash(&write.key)?;
        ensure!(
            hashed_writes.insert(hash, write.value).is_none(),
            "duplicate authenticated key in value set"
        );
        match preimages.entry(hash) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(write.key);
            }
            std::collections::btree_map::Entry::Occupied(entry) => {
                ensure!(
                    entry.get() == &write.key,
                    "SHA-256 authenticated key collision"
                );
            }
        }
    }

    let tree = Sha256Jmt::new(reader);
    let (root_hash, tree_update_batch) = tree
        .put_value_set(hashed_writes, version)
        .with_context(|| format!("plan authenticated tree version {version}"))?;

    Ok(PlannedAuthUpdate {
        version,
        root_hash,
        tree_update_batch,
        preimages,
    })
}

pub(crate) fn prove_with_reader<R: TreeReader + HasPreimage>(
    reader: &R,
    version: Version,
    root_hash: RootHash,
    key: Vec<u8>,
) -> Result<AuthProof> {
    ensure!(!key.is_empty(), "authenticated proof key must be non-empty");
    let tree = Sha256Jmt::new(reader);
    let (value, commitment_proof) = tree
        .get_with_ics23_proof(key.clone(), version)
        .with_context(|| format!("create ICS23 proof at version {version}"))?;
    Ok(AuthProof {
        version,
        root_hash,
        key,
        value,
        commitment_proof,
    })
}

impl TreeReader for InMemoryAuthTree {
    fn get_node_option(&self, node_key: &NodeKey) -> Result<Option<Node>> {
        Ok(self.nodes.get(node_key).cloned())
    }

    fn get_value_option(&self, max_version: Version, key_hash: KeyHash) -> Result<Option<Vec<u8>>> {
        Ok(self
            .values
            .range((key_hash, 0)..=(key_hash, max_version))
            .next_back()
            .and_then(|(_, value)| value.as_ref().cloned()))
    }

    fn get_rightmost_leaf(&self) -> Result<Option<(NodeKey, LeafNode)>> {
        Ok(self
            .nodes
            .iter()
            .filter_map(|(node_key, node)| match node {
                Node::Leaf(leaf) => Some((node_key, leaf)),
                Node::Null | Node::Internal(_) => None,
            })
            .max_by_key(|(node_key, leaf)| (leaf.key_hash(), node_key.version()))
            .map(|(node_key, leaf)| (node_key.clone(), leaf.clone())))
    }
}

impl HasPreimage for InMemoryAuthTree {
    fn preimage(&self, key_hash: KeyHash) -> Result<Option<Vec<u8>>> {
        Ok(self.preimages.get(&key_hash).cloned())
    }
}

pub fn verify_ics23_membership(proof: &AuthProof, expected_value: &[u8]) -> bool {
    let root = proof.root_hash.as_ref().to_vec();
    ics23::verify_membership::<ics23::HostFunctionsManager>(
        &proof.commitment_proof,
        &ics23_spec(),
        &root,
        &proof.key,
        expected_value,
    )
}

pub fn verify_ics23_non_membership(proof: &AuthProof) -> bool {
    let root = proof.root_hash.as_ref().to_vec();
    ics23::verify_non_membership::<ics23::HostFunctionsManager>(
        &proof.commitment_proof,
        &ics23_spec(),
        &root,
        &proof.key,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn put(key: Vec<u8>, value: &[u8]) -> AuthWrite {
        AuthWrite::put(key, value.to_vec()).expect("valid write")
    }

    fn planned_update_seal_fixture() -> PlannedAuthUpdate {
        let first = account_key("seal-first").expect("first key");
        let second = account_key("seal-second").expect("second key");
        let third = task_key("seal-third").expect("third key");
        let mut tree = InMemoryAuthTree::default();
        tree.put_value_set(
            0,
            [
                put(first.clone(), b"first-before"),
                put(second.clone(), b"second-before"),
                put(third.clone(), b"third-before"),
            ],
        )
        .expect("seal parent state");
        tree.plan_put_value_set(
            1,
            [
                put(first, b"first-after"),
                AuthWrite::delete(second).expect("delete second"),
                put(task_key("seal-created").expect("created key"), b"created"),
            ],
        )
        .expect("seal plan")
    }

    fn assert_planned_update_seal_rejects_drift(
        mut plan: PlannedAuthUpdate,
        mutate: impl FnOnce(&mut PlannedAuthUpdate),
    ) {
        let seal = plan.seal_v0().expect("seal plan");
        plan.verify_seal_v0(&seal).expect("unchanged plan");
        mutate(&mut plan);
        assert!(
            plan.verify_seal_v0(&seal).is_err(),
            "mutated persistence-bearing plan field must invalidate the seal"
        );
    }

    #[test]
    fn namespaced_keys_are_nonempty_and_unambiguous() {
        let left =
            namespaced_key(StateNamespace::Object, &[b"ab", b"c"]).expect("valid namespaced key");
        let right =
            namespaced_key(StateNamespace::Object, &[b"a", b"bc"]).expect("valid namespaced key");
        assert!(!left.is_empty());
        assert_ne!(left, right);
        assert!(namespaced_key(StateNamespace::Object, &[]).is_err());
        assert!(namespaced_key(StateNamespace::Object, &[b""]).is_err());
        assert_ne!(
            stored_object_key("aa").expect("stored object key"),
            validator_state_key().expect("validator state key")
        );
    }

    #[test]
    fn records_round_trip_and_detect_corruption() {
        let record =
            AuthenticatedObjectRecord::new("account", 7, b"balance=42".to_vec()).expect("record");
        let encoded = record.encode().expect("encode");
        assert_eq!(
            AuthenticatedObjectRecord::decode(&encoded).expect("decode"),
            record
        );

        let mut corrupt = record.clone();
        corrupt.value.push(0);
        assert!(corrupt.encode().is_err());

        let lifecycle =
            ValidatorLifecycleRecord::rotate(3, "validator-1", [1; 32], [2; 32], 10, 50)
                .expect("lifecycle");
        assert_eq!(
            ValidatorLifecycleRecord::decode(&lifecycle.encode().expect("encode")).expect("decode"),
            lifecycle
        );
    }

    #[test]
    fn incremental_root_and_empty_version_are_deterministic() {
        let account = account_key("alice").expect("key");
        let task = task_key("task-1").expect("key");
        let mut tree = InMemoryAuthTree::default();

        let root0 = tree
            .put_value_set(0, [put(account.clone(), b"10"), put(task, b"open")])
            .expect("version zero");
        let root1 = tree
            .put_value_set(1, [put(account.clone(), b"9")])
            .expect("incremental update");
        let root2 = tree
            .put_value_set(2, std::iter::empty())
            .expect("empty version");

        assert_ne!(root0, root1);
        assert_eq!(root1, root2);
        assert_eq!(tree.latest_version(), Some(2));
        assert!(tree.plan_put_value_set(4, std::iter::empty()).is_err());
    }

    #[test]
    fn planned_update_seal_is_deterministic_for_the_same_logical_write_set() {
        let first = account_key("seal-order-first").expect("first key");
        let second = account_key("seal-order-second").expect("second key");
        let tree = InMemoryAuthTree::default();
        let forward = tree
            .plan_put_value_set(
                0,
                [put(first.clone(), b"first"), put(second.clone(), b"second")],
            )
            .expect("forward plan");
        let reverse = tree
            .plan_put_value_set(0, [put(second, b"second"), put(first, b"first")])
            .expect("reverse plan");
        let forward_seal = forward.seal_v0().expect("forward seal");
        let reverse_seal = reverse.seal_v0().expect("reverse seal");

        assert_eq!(forward_seal, reverse_seal);
        forward
            .verify_seal_v0(&forward_seal)
            .expect("verify forward seal");
    }

    #[test]
    fn planned_update_seal_covers_every_persistence_bearing_field() {
        assert_planned_update_seal_rejects_drift(planned_update_seal_fixture(), |plan| {
            plan.version = plan.version.checked_add(1).expect("bounded test version");
        });
        assert_planned_update_seal_rejects_drift(planned_update_seal_fixture(), |plan| {
            plan.root_hash.0[0] ^= 1;
        });
        assert_planned_update_seal_rejects_drift(planned_update_seal_fixture(), |plan| {
            let root_key = plan
                .tree_update_batch
                .node_batch
                .nodes()
                .keys()
                .find(|key| key.nibble_path().is_empty())
                .expect("planned root node")
                .clone();
            let foreign_leaf = plan
                .tree_update_batch
                .node_batch
                .nodes()
                .values()
                .find(|node| matches!(node, Node::Leaf(_)))
                .expect("planned leaf node")
                .clone();
            plan.tree_update_batch
                .node_batch
                .insert_node(root_key, foreign_leaf);
        });
        assert_planned_update_seal_rejects_drift(planned_update_seal_fixture(), |plan| {
            let (version, hash) = *plan
                .tree_update_batch
                .node_batch
                .values()
                .keys()
                .next()
                .expect("planned value");
            plan.tree_update_batch.node_batch.insert_value(
                version,
                hash,
                b"seal-drifted-value".to_vec(),
            );
        });
        assert_planned_update_seal_rejects_drift(planned_update_seal_fixture(), |plan| {
            assert!(
                !plan.tree_update_batch.stale_node_index_batch.is_empty(),
                "fixture must include stale indices"
            );
            plan.tree_update_batch.stale_node_index_batch.clear();
        });
        assert_planned_update_seal_rejects_drift(planned_update_seal_fixture(), |plan| {
            plan.preimages
                .values_mut()
                .next()
                .expect("planned preimage")
                .push(0);
        });
    }

    #[test]
    fn verifies_ics23_existence_and_nonexistence() {
        let alice = account_key("alice").expect("key");
        let bob = account_key("bob").expect("key");
        let missing = account_key("carol").expect("key");
        let mut tree = InMemoryAuthTree::default();
        tree.put_value_set(0, [put(alice, b"10"), put(bob, b"20")])
            .expect("commit");

        let existence = tree
            .prove(0, account_key("alice").expect("key"))
            .expect("proof");
        assert_eq!(existence.value.as_deref(), Some(b"10".as_slice()));
        assert!(verify_ics23_membership(&existence, b"10"));

        let nonexistence = tree.prove(0, missing).expect("proof");
        assert!(nonexistence.value.is_none());
        assert!(verify_ics23_non_membership(&nonexistence));
        assert!(!nonexistence.encoded_commitment_proof().is_empty());
    }

    #[test]
    fn planned_overlay_proofs_match_applied_tree_and_stale_plans_fail() {
        let mut keys = (0..16)
            .map(|index| account_key(&format!("overlay-{index}")))
            .collect::<Result<Vec<_>>>()
            .expect("keys");
        keys.sort_by_key(|key| key_hash(key).expect("hash"));
        let deleted = keys[0].clone();
        let updated = keys[3].clone();
        let unchanged = keys[7].clone();
        let created_rightmost = keys[15].clone();
        let missing = task_key("overlay-missing").expect("missing key");

        let mut tree = InMemoryAuthTree::default();
        tree.put_value_set(
            0,
            [
                put(deleted.clone(), b"delete-me"),
                put(updated.clone(), b"before"),
                put(unchanged.clone(), b"stable"),
            ],
        )
        .expect("initial tree");
        assert_eq!(
            tree.value_at(0, &updated).expect("point read").as_deref(),
            Some(b"before".as_slice())
        );

        let plan = tree
            .plan_put_value_set(
                1,
                [
                    AuthWrite::delete(deleted.clone()).expect("delete"),
                    put(updated.clone(), b"after"),
                    put(created_rightmost.clone(), b"new-rightmost"),
                ],
            )
            .expect("plan");
        let stale_sibling = tree
            .plan_put_value_set(1, [put(updated.clone(), b"sibling")])
            .expect("sibling plan");

        let planned = [
            (deleted, None),
            (updated.clone(), Some(b"after".as_slice())),
            (unchanged, Some(b"stable".as_slice())),
            (created_rightmost, Some(b"new-rightmost".as_slice())),
            (missing, None),
        ]
        .into_iter()
        .map(|(key, expected)| {
            let proof = tree
                .prove_planned(&plan, key.clone())
                .expect("planned proof");
            assert_eq!(proof.root_hash, plan.root_hash);
            assert_eq!(proof.value.as_deref(), expected);
            if let Some(value) = expected {
                assert!(verify_ics23_membership(&proof, value));
            } else {
                assert!(verify_ics23_non_membership(&proof));
            }
            (key, proof)
        })
        .collect::<Vec<_>>();

        tree.apply(plan).expect("apply plan");
        for (key, planned_proof) in planned {
            let applied = tree.prove(1, key).expect("applied proof");
            assert_eq!(applied.root_hash, planned_proof.root_hash);
            assert_eq!(applied.value, planned_proof.value);
            assert_eq!(
                applied.encoded_commitment_proof(),
                planned_proof.encoded_commitment_proof()
            );
        }
        assert!(tree.prove_planned(&stale_sibling, updated).is_err());
        assert!(tree.apply(stale_sibling).is_err());

        let point_key = account_key("overlay-3").expect("point key");
        let point_hash = key_hash(&point_key).expect("point hash");
        let original = tree.preimages.insert(point_hash, b"collision".to_vec());
        assert!(tree.value_at(1, &point_key).is_err());
        match original {
            Some(original) => {
                tree.preimages.insert(point_hash, original);
            }
            None => {
                tree.preimages.remove(&point_hash);
            }
        }
    }

    #[test]
    fn historical_proofs_remain_version_exact() {
        let key = account_key("alice").expect("key");
        let mut tree = InMemoryAuthTree::default();
        let root0 = tree
            .put_value_set(0, [put(key.clone(), b"10")])
            .expect("v0");
        let root1 = tree
            .put_value_set(1, [put(key.clone(), b"11")])
            .expect("v1");

        let old = tree.prove(0, key.clone()).expect("old proof");
        let current = tree.prove(1, key).expect("current proof");
        assert_eq!(old.root_hash, root0);
        assert_eq!(current.root_hash, root1);
        assert!(verify_ics23_membership(&old, b"10"));
        assert!(verify_ics23_membership(&current, b"11"));
        assert!(!verify_ics23_membership(&old, b"11"));
    }

    #[test]
    fn pruning_drops_old_roots_but_preserves_retained_proofs() {
        let alice = account_key("alice").expect("key");
        let bob = account_key("bob").expect("key");
        let mut tree = InMemoryAuthTree::default();
        tree.put_value_set(0, [put(alice.clone(), b"10"), put(bob.clone(), b"20")])
            .expect("v0");
        tree.put_value_set(1, [put(alice.clone(), b"11")])
            .expect("v1");
        tree.put_value_set(2, std::iter::empty()).expect("v2");

        assert!(verify_ics23_membership(
            &tree.prove(0, alice.clone()).expect("historical proof"),
            b"10"
        ));
        let nodes_before = tree.node_count();
        let stale_before = tree.stale_index_count();
        let stats = tree.prune_versions_before(1).expect("prune");
        assert!(stats.roots_removed >= 1);
        assert!(stats.nodes_removed >= 1);
        assert!(tree.node_count() < nodes_before);
        assert!(tree.stale_index_count() < stale_before);
        assert!(tree.prove(0, alice).is_err());

        let retained = tree.prove(1, bob.clone()).expect("retained proof");
        let latest = tree.prove(2, bob).expect("latest proof");
        assert!(verify_ics23_membership(&retained, b"20"));
        assert!(verify_ics23_membership(&latest, b"20"));
    }

    #[test]
    fn stored_parts_rebuild_with_latest_root_validation() {
        let key = stored_object_key("ab12").expect("key");
        let mut tree = InMemoryAuthTree::default();
        let plan = tree
            .plan_put_value_set(0, [put(key.clone(), b"record")])
            .expect("plan");
        assert_eq!(plan.preimages().len(), 1);
        tree.apply(plan).expect("apply");

        let rebuilt = InMemoryAuthTree::from_parts(
            tree.nodes().clone(),
            tree.values().clone(),
            tree.preimages().clone(),
            tree.stale_nodes().clone(),
            tree.roots().clone(),
        )
        .expect("rebuild");
        assert!(verify_ics23_membership(
            &rebuilt.prove(0, key).expect("proof"),
            b"record"
        ));

        let mut corrupt_roots = tree.roots().clone();
        corrupt_roots.insert(0, RootHash([0; 32]));
        assert!(InMemoryAuthTree::from_parts(
            tree.nodes().clone(),
            tree.values().clone(),
            tree.preimages().clone(),
            tree.stale_nodes().clone(),
            corrupt_roots,
        )
        .is_err());
    }

    #[test]
    fn snapshot_decode_verifies_every_reachable_value() {
        let first = account_key("alice").expect("first key");
        let second = account_key("bob").expect("second key");
        let mut tree = InMemoryAuthTree::default();
        tree.put_value_set(0, [put(first, b"alice-value"), put(second, b"bob-value")])
            .expect("commit two leaves");

        let encoded = tree.encode_snapshot().expect("encode snapshot");
        let snapshot: AuthTreeSnapshot = borsh::from_slice(&encoded).expect("decode snapshot");
        let live_hashes = snapshot
            .values
            .keys()
            .map(|(hash, _)| *hash)
            .collect::<BTreeSet<_>>();
        assert_eq!(live_hashes.len(), 2);
        let non_first_hash = *live_hashes.last().expect("second live hash");

        let mut altered = AuthTreeSnapshot {
            codec_version: snapshot.codec_version,
            nodes: snapshot.nodes.clone(),
            values: snapshot.values.clone(),
            preimages: snapshot.preimages.clone(),
            stale_nodes: snapshot.stale_nodes.clone(),
            roots: snapshot.roots.clone(),
        };
        *altered
            .values
            .get_mut(&(non_first_hash, 0))
            .expect("second value row") = Some(b"tampered-value".to_vec());
        assert!(
            InMemoryAuthTree::decode_snapshot(
                &borsh::to_vec(&altered).expect("encode altered snapshot")
            )
            .is_err(),
            "a non-first value that is not committed by the root must be rejected"
        );

        let mut missing = snapshot;
        missing.values.remove(&(non_first_hash, 0));
        assert!(
            InMemoryAuthTree::decode_snapshot(
                &borsh::to_vec(&missing).expect("encode missing-value snapshot")
            )
            .is_err(),
            "every reachable leaf must have a value row"
        );
    }
}
