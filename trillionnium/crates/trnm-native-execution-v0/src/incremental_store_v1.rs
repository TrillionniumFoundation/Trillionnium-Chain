//! Transaction-scoped incremental JMT storage. These are storage operations,
//! not finality or execution authority. The native owner must join them to its
//! application P/commit transaction and retain its existing durability barriers.
//! No open call creates or migrates a schema; installation is explicit.

use std::collections::BTreeMap;

use anyhow::{ensure, Context, Result};
use jmt::{
    storage::{HasPreimage, LeafNode, Node, NodeBatch, NodeKey, TreeReader},
    KeyHash, RootHash, Sha256Jmt, Version,
};
use rusqlite::{params, OptionalExtension, Transaction};
use sha2::{Digest, Sha256};

use crate::store::{authenticated_key_hash_v0, CompleteStatePlanV0};

const INCREMENTAL_SCHEMA_SQL: &str = include_str!("incremental_schema_v1.sql");
const MAX_NODES: usize = 65_537;
const MAX_WRITES: usize = 1_024;
const MAX_NODE_BYTES: usize = 4_096;
const MAX_KEY_BYTES: usize = 128;
const MAX_PREIMAGE_BYTES: usize = 65_536;
const MAX_VALUE_BYTES: usize = 16 * 1024 * 1024;
const MAX_DELTA_BYTES: usize = 335_544_320;
const MAX_PREPARED: usize = 128;
const MAX_DEPTH: usize = 8;
const MAX_PREPARED_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const MAX_READER_DELTA_BYTES: usize = 64 * 1024 * 1024;
const MAX_PINS: u64 = 16_384;

/// Local profile and owner identity, independently retained by the application
/// owner. Supplying these values from the same database is not rollback defense.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IncrementalNamespaceV1 {
    pub chain: String,
    pub genesis: [u8; 32],
    pub namespace: [u8; 32],
    pub owner_generation: u64,
}

/// Exact storage head. It is deliberately not an application commit receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IncrementalHeadV1 {
    pub height: u64,
    pub block: [u8; 32],
    pub root: [u8; 32],
    pub commit_sequence: u64,
    pub intent: [u8; 32],
    pub checksum: [u8; 32],
}

/// Inert parent reference. Resolution checks the immutable persisted row and
/// its complete bounded ancestry; the enum alone grants no authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IncrementalParentV1 {
    Committed([u8; 32]),
    Prepared([u8; 32]),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedIncrementalDeltaV1 {
    pub artifact: [u8; 32],
    pub block: [u8; 32],
    pub height: u64,
    pub root: [u8; 32],
    pub persist_sequence: u64,
}

#[derive(Debug)]
struct Delta {
    batch: NodeBatch,
    preimages: BTreeMap<KeyHash, Vec<u8>>,
}

impl Delta {
    fn encode(&self) -> Result<Vec<u8>> {
        ensure!(
            self.batch.nodes().len() <= MAX_NODES,
            "incremental node capacity"
        );
        ensure!(
            self.batch.values().len() <= MAX_WRITES,
            "incremental write capacity"
        );
        ensure!(
            self.preimages.len() <= MAX_WRITES,
            "incremental preimage capacity"
        );
        let mut bytes = 1u16.to_be_bytes().to_vec();
        put_count(&mut bytes, self.batch.nodes().len())?;
        for (key, node) in self.batch.nodes() {
            put_bytes(&mut bytes, &borsh::to_vec(key)?, MAX_KEY_BYTES)?;
            put_bytes(&mut bytes, &borsh::to_vec(node)?, MAX_NODE_BYTES)?;
        }
        put_count(&mut bytes, self.batch.values().len())?;
        let mut value_bytes = 0usize;
        for ((version, key), value) in self.batch.values() {
            bytes.extend_from_slice(&version.to_be_bytes());
            bytes.extend_from_slice(&key.0);
            bytes.push(u8::from(value.is_some()));
            let raw = value.as_deref().unwrap_or_default();
            value_bytes = value_bytes
                .checked_add(raw.len())
                .context("value sum overflow")?;
            ensure!(value_bytes <= MAX_VALUE_BYTES, "incremental value capacity");
            put_bytes(&mut bytes, raw, MAX_VALUE_BYTES)?;
        }
        put_count(&mut bytes, self.preimages.len())?;
        let mut preimage_bytes = 0usize;
        for (key, preimage) in &self.preimages {
            preimage_bytes = preimage_bytes
                .checked_add(preimage.len())
                .context("preimage sum overflow")?;
            ensure!(
                preimage_bytes <= MAX_VALUE_BYTES,
                "incremental preimage capacity"
            );
            ensure!(
                authenticated_key_hash_v0(preimage)? == *key,
                "incremental preimage hash"
            );
            bytes.extend_from_slice(&key.0);
            put_bytes(&mut bytes, preimage, MAX_PREIMAGE_BYTES)?;
        }
        ensure!(bytes.len() <= MAX_DELTA_BYTES, "incremental delta capacity");
        Ok(bytes)
    }

    fn decode(bytes: &[u8], target: u64) -> Result<Self> {
        ensure!(bytes.len() <= MAX_DELTA_BYTES, "incremental delta capacity");
        let mut input = Input { bytes, at: 0 };
        ensure!(
            input.take(2)? == 1u16.to_be_bytes(),
            "incremental delta schema"
        );
        let count = input.count(MAX_NODES)?;
        let mut nodes = BTreeMap::new();
        for _ in 0..count {
            let key_bytes = input.bytes(MAX_KEY_BYTES)?;
            let key: NodeKey = borsh::from_slice(key_bytes)?;
            ensure!(borsh::to_vec(&key)? == key_bytes, "noncanonical node key");
            validate_node_key(&key)?;
            ensure!(key.version() == target, "delta node target mismatch");
            ensure!(
                key.nibble_path().num_nibbles() <= 64,
                "node path exceeds key width"
            );
            let node_bytes = input.bytes(MAX_NODE_BYTES)?;
            let node: Node = borsh::from_slice(node_bytes)?;
            ensure!(borsh::to_vec(&node)? == node_bytes, "noncanonical node");
            validate_node(&node)?;
            validate_node_at(&key, &node)?;
            ensure!(
                nodes
                    .last_key_value()
                    .is_none_or(|(previous, _)| previous < &key),
                "node order"
            );
            nodes.insert(key, node);
        }
        let count = input.count(MAX_WRITES)?;
        let mut values = BTreeMap::new();
        let mut value_bytes = 0usize;
        for _ in 0..count {
            let version = input.u64()?;
            let key = KeyHash(input.hash()?);
            ensure!(version == target, "delta value target mismatch");
            let present = input.take(1)?[0];
            ensure!(present <= 1, "invalid value presence");
            let raw = input.bytes(MAX_VALUE_BYTES)?;
            value_bytes = value_bytes
                .checked_add(raw.len())
                .context("value sum overflow")?;
            ensure!(value_bytes <= MAX_VALUE_BYTES, "incremental value capacity");
            ensure!(present == 1 || raw.is_empty(), "tombstone has bytes");
            let tuple = (version, key);
            ensure!(
                values
                    .last_key_value()
                    .is_none_or(|(previous, _)| previous < &tuple),
                "value order"
            );
            values.insert(tuple, (present == 1).then(|| raw.to_vec()));
        }
        let count = input.count(MAX_WRITES)?;
        let mut preimages = BTreeMap::new();
        let mut preimage_bytes = 0usize;
        for _ in 0..count {
            let key = KeyHash(input.hash()?);
            let raw = input.bytes(MAX_PREIMAGE_BYTES)?;
            preimage_bytes = preimage_bytes
                .checked_add(raw.len())
                .context("preimage sum overflow")?;
            ensure!(
                preimage_bytes <= MAX_VALUE_BYTES,
                "incremental preimage capacity"
            );
            ensure!(
                authenticated_key_hash_v0(raw)? == key,
                "incremental preimage hash"
            );
            ensure!(
                preimages
                    .last_key_value()
                    .is_none_or(|(previous, _)| previous < &key),
                "preimage order"
            );
            preimages.insert(key, raw.to_vec());
        }
        ensure!(input.at == bytes.len(), "incremental delta trailing bytes");
        ensure!(
            values.keys().all(|(_, key)| preimages.contains_key(key)),
            "delta lacks write preimage"
        );
        Ok(Self {
            batch: NodeBatch::new(nodes, values),
            preimages,
        })
    }
}

fn put_count(bytes: &mut Vec<u8>, value: usize) -> Result<()> {
    bytes.extend_from_slice(&u32::try_from(value)?.to_be_bytes());
    Ok(())
}
fn put_bytes(bytes: &mut Vec<u8>, value: &[u8], maximum: usize) -> Result<()> {
    ensure!(value.len() <= maximum, "incremental field capacity");
    ensure!(
        bytes
            .len()
            .checked_add(4)
            .and_then(|n| n.checked_add(value.len()))
            .is_some_and(|n| n <= MAX_DELTA_BYTES),
        "incremental delta capacity"
    );
    put_count(bytes, value.len())?;
    bytes.extend_from_slice(value);
    Ok(())
}
struct Input<'a> {
    bytes: &'a [u8],
    at: usize,
}
impl<'a> Input<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.at.checked_add(n).context("delta offset overflow")?;
        let part = self.bytes.get(self.at..end).context("truncated delta")?;
        self.at = end;
        Ok(part)
    }
    fn count(&mut self, max: usize) -> Result<usize> {
        let n = u32::from_be_bytes(self.take(4)?.try_into()?) as usize;
        ensure!(
            n <= max && n <= self.bytes.len() - self.at,
            "incremental count capacity"
        );
        Ok(n)
    }
    fn bytes(&mut self, max: usize) -> Result<&'a [u8]> {
        let n = self.count(max)?;
        self.take(n)
    }
    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into()?))
    }
    fn hash(&mut self) -> Result<[u8; 32]> {
        Ok(self.take(32)?.try_into()?)
    }
}

fn hash(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for part in std::iter::once(domain).chain(parts.iter().copied()) {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part);
    }
    hasher.finalize().into()
}
fn fixed<const N: usize>(bytes: Vec<u8>) -> Result<[u8; N]> {
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("incremental fixed-width mismatch"))
}
fn u64_blob(bytes: Vec<u8>) -> Result<u64> {
    Ok(u64::from_be_bytes(fixed(bytes)?))
}
fn node_hash(node: &Node) -> [u8; 32] {
    match node {
        // Exact constant in the pinned JMT 0.12.0 root algorithm.
        Node::Null => *b"SPARSE_MERKLE_PLACEHOLDER_HASH__",
        Node::Leaf(node) => node.hash::<Sha256>(),
        Node::Internal(node) => node.hash::<Sha256>(),
    }
}
fn root_key(version: u64) -> NodeKey {
    NodeKey::new(version, std::iter::empty().collect())
}
fn validate_node_key(key: &NodeKey) -> Result<()> {
    #[derive(borsh::BorshDeserialize)]
    struct PathShape {
        count: usize,
        bytes: Vec<u8>,
    }
    let path: PathShape = borsh::from_slice(&borsh::to_vec(key.nibble_path())?)?;
    ensure!(
        path.count <= 64 && path.bytes.len() == path.count.div_ceil(2),
        "invalid node path shape"
    );
    ensure!(
        path.count.is_multiple_of(2) || path.bytes.last().is_some_and(|last| last & 15 == 0),
        "noncanonical node path padding"
    );
    Ok(())
}
fn validate_node(node: &Node) -> Result<()> {
    if let Node::Internal(internal) = node {
        let children: Vec<_> = internal.children_sorted().collect();
        ensure!(
            !children.is_empty() && children.len() <= 16,
            "empty/oversized internal node"
        );
        ensure!(
            children.len() != 1 || !children[0].1.is_leaf(),
            "uncompressed internal leaf"
        );
        let leaves = children
            .iter()
            .try_fold(0usize, |n, (_, child)| n.checked_add(child.leaf_count()))
            .context("node leaf count overflow")?;
        ensure!(
            children
                .iter()
                .all(|(_, child)| child.is_leaf() || child.leaf_count() >= 2),
            "invalid child leaf count"
        );
        ensure!(
            leaves == internal.leaf_count() && leaves >= 2,
            "internal leaf count mismatch"
        );
        // Pinned JMT Borsh order ends with Children::num_children followed by
        // InternalNode::leaf_count. Both are redundant usize fields.
        let counts = borsh::to_vec(&(children.len(), leaves))?;
        ensure!(
            borsh::to_vec(internal)?.ends_with(&counts),
            "internal node cached count mismatch"
        );
    }
    Ok(())
}
pub(crate) fn audit_jmt_node_record_v1(key: &NodeKey, node: &Node) -> Result<()> {
    validate_node_key(key)?;
    validate_node(node)?;
    validate_node_at(key, node)
}

fn validate_node_at(key: &NodeKey, node: &Node) -> Result<()> {
    match node {
        Node::Null => ensure!(key.nibble_path().num_nibbles() == 0, "null below root"),
        Node::Internal(internal) => {
            ensure!(
                key.nibble_path().num_nibbles() < 64,
                "internal node below key width"
            );
            ensure!(
                internal
                    .children_sorted()
                    .all(|(_, child)| child.version <= key.version()),
                "future child reference"
            );
        }
        Node::Leaf(leaf) => {
            let hash = leaf.key_hash().0;
            for (position, nibble) in key.nibble_path().nibbles().enumerate() {
                let expected = if position % 2 == 0 {
                    hash[position / 2] >> 4
                } else {
                    hash[position / 2] & 15
                };
                ensure!(u8::from(nibble) == expected, "leaf path/key mismatch");
            }
        }
    }
    Ok(())
}

/// A pinned reader borrows the owner's SQLite transaction. Prepared data is
/// isolated by artifact and overlaid newest-first, never inserted under shared
/// committed NodeKeys. Historical roots and value floors remain retained.
pub struct IncrementalJmtReaderV1<'a> {
    transaction: &'a Transaction<'a>,
    version: u64,
    root: RootHash,
    anchor_version: u64,
    deltas: Vec<Delta>,
    retained_delta_bytes: usize,
}

impl IncrementalJmtReaderV1<'_> {
    pub const fn version(&self) -> u64 {
        self.version
    }
    pub const fn root(&self) -> RootHash {
        self.root
    }
    /// Enumerates only the reachable current tree, with a finite application
    /// projection budget. It never scans historical node/value versions.
    pub(crate) fn verified_live_values_v1(&self) -> Result<BTreeMap<Vec<u8>, Vec<u8>>> {
        let mut pending = vec![(root_key(self.version), self.root.0)];
        let mut visited = 0usize;
        let mut retained = 0usize;
        let mut result = BTreeMap::new();
        while let Some((key, expected)) = pending.pop() {
            visited = visited.checked_add(1).context("live node count overflow")?;
            ensure!(visited <= 1_048_576, "live node traversal capacity");
            let node = self
                .get_node_option(&key)?
                .context("reachable node missing")?;
            ensure!(node_hash(&node) == expected, "reachable node hash mismatch");
            match node {
                Node::Null => ensure!(key.nibble_path().is_empty(), "null child in live traversal"),
                Node::Leaf(leaf) => {
                    ensure!(result.len() < 65_536, "live value count capacity");
                    let preimage = self
                        .preimage(leaf.key_hash())?
                        .context("live preimage missing")?;
                    let value = self.prove(&preimage)?.context("live value missing")?;
                    retained = retained
                        .checked_add(preimage.len())
                        .and_then(|n| n.checked_add(value.len()))
                        .context("live projection byte overflow")?;
                    ensure!(
                        retained <= 64 * 1024 * 1024,
                        "live projection byte capacity"
                    );
                    ensure!(
                        result.insert(preimage, value).is_none(),
                        "duplicate live preimage"
                    );
                }
                Node::Internal(internal) => {
                    for (nibble, child) in internal.children_sorted() {
                        let path = key
                            .nibble_path()
                            .nibbles()
                            .chain(std::iter::once(nibble))
                            .collect();
                        pending.push((NodeKey::new(child.version, path), child.hash));
                    }
                }
            }
        }
        Ok(result)
    }

    pub fn prove(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let key_hash = authenticated_key_hash_v0(key)?;
        let (value, proof) = Sha256Jmt::new(self).get_with_proof(key_hash, self.version)?;
        match value.as_deref() {
            Some(value) => {
                proof.verify_existence(self.root, key_hash, value)?;
                ensure!(
                    self.preimage(key_hash)?.as_deref() == Some(key),
                    "incremental preimage mismatch"
                );
            }
            None => proof.verify_nonexistence(self.root, key_hash)?,
        }
        Ok(value)
    }
}

impl TreeReader for IncrementalJmtReaderV1<'_> {
    fn get_node_option(&self, key: &NodeKey) -> Result<Option<Node>> {
        validate_node_key(key)?;
        ensure!(key.version() <= self.version, "future incremental node");
        for delta in &self.deltas {
            if let Some(node) = delta.batch.get_node(key) {
                return Ok(Some(node.clone()));
            }
        }
        if key.version() > self.anchor_version {
            return Ok(None);
        }
        type BoundedNodeRow = (Vec<u8>, Option<Vec<u8>>, Vec<u8>);
        let raw: Option<BoundedNodeRow> = self
            .transaction
            .query_row(
                "SELECT node_version,CASE WHEN length(node_bytes)<=4096 THEN node_bytes ELSE NULL END,node_hash FROM ni_nodes WHERE node_key=?1",
                [borsh::to_vec(key)?],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        raw.map(|(version, bytes, expected)| {
            let bytes = bytes.context("stored node capacity")?;
            ensure!(
                u64_blob(version)? == key.version(),
                "stored node version mismatch"
            );
            ensure!(bytes.len() <= MAX_NODE_BYTES, "stored node capacity");
            let node: Node = borsh::from_slice(&bytes)?;
            validate_node(&node)?;
            validate_node_at(key, &node)?;
            ensure!(
                borsh::to_vec(&node)? == bytes && node_hash(&node) == fixed::<32>(expected)?,
                "stored node hash/canonical mismatch"
            );
            Ok(node)
        })
        .transpose()
    }
    fn get_value_option(&self, max_version: Version, key: KeyHash) -> Result<Option<Vec<u8>>> {
        ensure!(max_version <= self.version, "future incremental value");
        for delta in &self.deltas {
            if let Some((_, value)) = delta
                .batch
                .values()
                .iter()
                .find(|((version, hash), _)| *version <= max_version && *hash == key)
            {
                return Ok(value.clone());
            }
        }
        let maximum = max_version.min(self.anchor_version).to_be_bytes();
        let raw: Option<(u8, Option<Vec<u8>>)> = self.transaction.query_row(
            "SELECT present,CASE WHEN length(value)<=16777216 THEN value ELSE NULL END FROM ni_values WHERE key_hash=?1 AND version<=?2 ORDER BY version DESC LIMIT 1",
            params![key.0.as_slice(), maximum.as_slice()], |row| Ok((row.get(0)?, row.get(1)?)),
        ).optional()?;
        match raw {
            None => Ok(None),
            Some((0, bytes)) => {
                let bytes = bytes.context("stored value capacity")?;
                ensure!(bytes.is_empty(), "stored tombstone has bytes");
                Ok(None)
            }
            Some((1, bytes)) => {
                let bytes = bytes.context("stored value capacity")?;
                ensure!(bytes.len() <= MAX_VALUE_BYTES, "stored value capacity");
                Ok(Some(bytes))
            }
            Some(_) => anyhow::bail!("stored value presence"),
        }
    }
    fn get_rightmost_leaf(&self) -> Result<Option<(NodeKey, LeafNode)>> {
        anyhow::bail!(
            "restore-only rightmost-leaf API is unavailable on retained multi-version state"
        )
    }
}
impl HasPreimage for IncrementalJmtReaderV1<'_> {
    fn preimage(&self, key: KeyHash) -> Result<Option<Vec<u8>>> {
        for delta in &self.deltas {
            if let Some(preimage) = delta.preimages.get(&key) {
                return Ok(Some(preimage.clone()));
            }
        }
        let raw: Option<Option<Vec<u8>>> = self
            .transaction
            .query_row(
                "SELECT CASE WHEN length(preimage)<=65536 THEN preimage ELSE NULL END FROM ni_preimages WHERE key_hash=?1",
                [key.0.as_slice()],
                |row| row.get(0),
            )
            .optional()?;
        let raw = raw
            .map(|value| value.context("stored preimage capacity"))
            .transpose()?;
        if let Some(bytes) = &raw {
            ensure!(
                bytes.len() <= MAX_PREIMAGE_BYTES && authenticated_key_hash_v0(bytes)? == key,
                "stored preimage hash/capacity"
            );
        }
        Ok(raw)
    }
}

/// Explicit schema installation inside the owner's migration transaction.
/// Existing tables reject, including an interrupted or foreign installation.
pub fn install_incremental_schema_v1(transaction: &Transaction<'_>) -> Result<()> {
    transaction.execute_batch(INCREMENTAL_SCHEMA_SQL)?;
    Ok(())
}

/// Invoke once during the owner's explicit migration/open audit. This compares
/// complete SQL definitions, including implicit indexes, and rejects triggers,
/// extra indexes or altered constraints on any ni_* table. It does not enable
/// the owner's signing or execution interfaces.
pub fn check_incremental_schema_v1(transaction: &Transaction<'_>) -> Result<()> {
    type SchemaObject = (String, String, String, Option<String>);
    fn inventory(connection: &rusqlite::Connection) -> Result<Vec<SchemaObject>> {
        let mut statement = connection.prepare("SELECT type,name,tbl_name,sql FROM sqlite_schema WHERE name GLOB 'ni_*' OR tbl_name GLOB 'ni_*' ORDER BY type,name")?;
        let rows = statement
            .query_map([], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }
    let reference = rusqlite::Connection::open_in_memory()?;
    reference.execute_batch(INCREMENTAL_SCHEMA_SQL)?;
    ensure!(
        inventory(transaction)? == inventory(&reference)?,
        "incremental schema inventory mismatch"
    );
    Ok(())
}

fn namespace_digest(namespace: &IncrementalNamespaceV1) -> Result<[u8; 32]> {
    ensure!(
        !namespace.chain.is_empty() && namespace.chain.len() <= 128,
        "incremental chain length"
    );
    ensure!(
        namespace.genesis != [0; 32]
            && namespace.namespace != [0; 32]
            && namespace.owner_generation > 0,
        "incremental namespace identity"
    );
    Ok(hash(
        b"trnm.native-incremental.namespace.v1",
        &[
            namespace.chain.as_bytes(),
            &namespace.genesis,
            &namespace.namespace,
            &namespace.owner_generation.to_be_bytes(),
        ],
    ))
}
fn head_checksum(namespace: &IncrementalNamespaceV1, head: &IncrementalHeadV1) -> Result<[u8; 32]> {
    Ok(hash(
        b"trnm.native-incremental.head.v1",
        &[
            &namespace_digest(namespace)?,
            &head.height.to_be_bytes(),
            &head.block,
            &head.root,
            &head.commit_sequence.to_be_bytes(),
            &head.intent,
        ],
    ))
}
fn check_namespace(
    transaction: &Transaction<'_>,
    namespace: &IncrementalNamespaceV1,
) -> Result<()> {
    namespace_digest(namespace)?;
    let (chain, genesis, id, generation): (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) = transaction
        .query_row(
            "SELECT CASE WHEN length(chain)<=255 THEN chain ELSE NULL END,genesis,namespace,owner_generation FROM ni_meta WHERE id=1 AND schema=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )?;
    ensure!(
        chain == namespace.chain.as_bytes()
            && fixed::<32>(genesis)? == namespace.genesis
            && fixed::<32>(id)? == namespace.namespace
            && u64_blob(generation)? == namespace.owner_generation,
        "incremental namespace mismatch"
    );
    Ok(())
}

/// Reads and audits the namespace head without replaying historical snapshots.
/// The owner must compare it with its independently pinned checksum. Historical
/// node/value corruption is detected on authenticated reads, not silently healed.
pub fn read_incremental_head_v1(
    transaction: &Transaction<'_>,
    namespace: &IncrementalNamespaceV1,
) -> Result<IncrementalHeadV1> {
    namespace_digest(namespace)?;
    let mut statement = transaction.prepare("SELECT CASE WHEN length(chain)<=255 THEN chain ELSE NULL END,genesis,namespace,owner_generation,head_height,head_block,head_version,head_root,commit_sequence,head_intent,head_checksum FROM ni_meta WHERE id=1 AND schema=1")?;
    let mut rows = statement.query([])?;
    let row = rows.next()?.context("incremental namespace missing")?;
    ensure!(
        row.get::<_, Vec<u8>>(0)? == namespace.chain.as_bytes()
            && fixed::<32>(row.get(1)?)? == namespace.genesis
            && fixed::<32>(row.get(2)?)? == namespace.namespace
            && u64_blob(row.get(3)?)? == namespace.owner_generation,
        "incremental namespace mismatch"
    );
    let height = u64_blob(row.get(4)?)?;
    ensure!(
        height == u64_blob(row.get(6)?)?,
        "incremental head version mismatch"
    );
    let head = IncrementalHeadV1 {
        height,
        block: fixed(row.get(5)?)?,
        root: fixed(row.get(7)?)?,
        commit_sequence: u64_blob(row.get(8)?)?,
        intent: fixed(row.get(9)?)?,
        checksum: fixed(row.get(10)?)?,
    };
    ensure!(
        head.checksum == head_checksum(namespace, &head)?,
        "incremental head checksum"
    );
    ensure!(rows.next()?.is_none(), "duplicate incremental head");
    let reader = open_incremental_reader_v1(
        transaction,
        namespace,
        IncrementalParentV1::Committed(head.block),
    )?;
    ensure!(
        reader.version == head.height && reader.root.0 == head.root,
        "head/root row mismatch"
    );
    let (sequence, intent): (Vec<u8>, Vec<u8>) = transaction.query_row(
        "SELECT commit_sequence,intent FROM ni_roots WHERE block_id=?1",
        [head.block.as_slice()],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    ensure!(
        u64_blob(sequence)? == head.commit_sequence && fixed::<32>(intent)? == head.intent,
        "head/root commit mismatch"
    );
    Ok(head)
}

/// One explicit, preverified bootstrap import. Its caller owns genesis/snapshot
/// authentication and finality; the storage layer checks all retained JMT data.
pub fn import_incremental_snapshot_v1(
    transaction: &Transaction<'_>,
    namespace: &IncrementalNamespaceV1,
    mut head: IncrementalHeadV1,
    epoch: u64,
    snapshot: &crate::InMemoryNativeExecutionStoreV0,
) -> Result<IncrementalHeadV1> {
    namespace_digest(namespace)?;
    snapshot.validate_snapshot_v0()?;
    ensure!(
        snapshot.chain_id == namespace.chain,
        "snapshot chain mismatch"
    );
    ensure!(
        snapshot.roots.last_key_value() == Some((&head.height, &RootHash(head.root))),
        "snapshot pinned head mismatch"
    );
    ensure!(
        head.block != [0; 32] && head.intent != [0; 32],
        "snapshot identity missing"
    );
    ensure!(snapshot.roots.len() == 1, "incremental bootstrap requires a single authenticated root; multi-root migration requires explicit root/block pins");
    ensure!(
        head.height == 0,
        "incremental initial import currently admits canonical genesis only"
    );
    ensure!(
        head.commit_sequence == 0,
        "incremental genesis sequence must be zero"
    );
    let batch = NodeBatch::new(
        snapshot.nodes.clone(),
        snapshot
            .values
            .iter()
            .map(|((key, version), value)| ((*version, *key), value.clone()))
            .collect(),
    );
    write_committed_batch(transaction, &batch, &snapshot.preimages)?;
    head.checksum = head_checksum(namespace, &head)?;
    insert_root(transaction, &head, epoch)?;
    transaction.execute(
        "INSERT INTO ni_meta VALUES(1,1,?1,?2,?3,?4,?5,?6,?5,?7,?8,?9,?10)",
        params![
            namespace.chain.as_bytes(),
            namespace.genesis.as_slice(),
            namespace.namespace.as_slice(),
            namespace.owner_generation.to_be_bytes().as_slice(),
            head.height.to_be_bytes().as_slice(),
            head.block.as_slice(),
            head.root.as_slice(),
            head.commit_sequence.to_be_bytes().as_slice(),
            head.intent.as_slice(),
            head.checksum.as_slice(),
        ],
    )?;
    transaction.execute(
        "INSERT INTO ni_sequence VALUES(1,?1)",
        [head.commit_sequence.to_be_bytes().as_slice()],
    )?;
    Ok(head)
}

/// Explicit ordinary-history migration. The native owner supplies the exact
/// already-authenticated root/block list and binds source_anchor into its own
/// migration record. This storage function does not establish finality.
pub fn import_incremental_history_v1(
    transaction: &Transaction<'_>,
    namespace: &IncrementalNamespaceV1,
    roots: &[(IncrementalHeadV1, u64)],
    snapshot: &crate::InMemoryNativeExecutionStoreV0,
    source_anchor: [u8; 32],
) -> Result<IncrementalHeadV1> {
    namespace_digest(namespace)?;
    snapshot.validate_snapshot_v0()?;
    ensure!(
        source_anchor != [0; 32] && snapshot.chain_id == namespace.chain,
        "history import source mismatch"
    );
    ensure!(
        !roots.is_empty()
            && roots.len() <= MAX_PINS as usize
            && roots.len() == snapshot.roots.len(),
        "history import root capacity/count"
    );
    for (index, ((head, _), (version, root))) in roots.iter().zip(&snapshot.roots).enumerate() {
        ensure!(
            head.height == *version
                && head.root == root.0
                && head.height == index as u64
                && head.commit_sequence == index as u64
                && head.block != [0; 32]
                && head.intent != [0; 32],
            "history import coordinate mismatch"
        );
    }
    let batch = NodeBatch::new(
        snapshot.nodes.clone(),
        snapshot
            .values
            .iter()
            .map(|((key, version), value)| ((*version, *key), value.clone()))
            .collect(),
    );
    write_committed_batch(transaction, &batch, &snapshot.preimages)?;
    let mut last = None;
    for (root, epoch) in roots {
        let mut root = root.clone();
        root.checksum = head_checksum(namespace, &root)?;
        insert_root(transaction, &root, *epoch)?;
        let bytes = head_bytes(&root);
        let checksum = hash(
            b"trnm.native-incremental.imported-root.v1",
            &[&namespace_digest(namespace)?, &source_anchor, &bytes],
        );
        transaction.execute(
            "INSERT INTO ni_imported_root VALUES(?1,?2,?3,?4)",
            params![
                root.height.to_be_bytes().as_slice(),
                source_anchor.as_slice(),
                bytes,
                checksum.as_slice()
            ],
        )?;
        last = Some(root);
    }
    let head = last.context("history root missing")?;
    transaction.execute(
        "INSERT INTO ni_meta VALUES(1,1,?1,?2,?3,?4,?5,?6,?5,?7,?8,?9,?10)",
        params![
            namespace.chain.as_bytes(),
            namespace.genesis.as_slice(),
            namespace.namespace.as_slice(),
            namespace.owner_generation.to_be_bytes().as_slice(),
            head.height.to_be_bytes().as_slice(),
            head.block.as_slice(),
            head.root.as_slice(),
            head.commit_sequence.to_be_bytes().as_slice(),
            head.intent.as_slice(),
            head.checksum.as_slice()
        ],
    )?;
    transaction.execute(
        "INSERT INTO ni_sequence VALUES(1,?1)",
        [head.commit_sequence.to_be_bytes().as_slice()],
    )?;
    ensure!(
        read_incremental_head_v1(transaction, namespace)? == head,
        "history import readback mismatch"
    );
    Ok(head)
}

/// Deletes only an explicit uncommitted subtree. Child-first order and exact
/// anchor-pin release prevent a prepared descendant from losing its parent.
/// Owner P rows must be retired in this same transaction.
pub fn retire_incremental_prepared_v1(
    transaction: &Transaction<'_>,
    namespace: &IncrementalNamespaceV1,
    artifacts: &[[u8; 32]],
) -> Result<()> {
    check_namespace(transaction, namespace)?;
    ensure!(artifacts.len() <= MAX_PREPARED, "retire capacity");
    let selected: std::collections::BTreeSet<_> = artifacts.iter().copied().collect();
    ensure!(
        selected.len() == artifacts.len(),
        "duplicate retired artifact"
    );
    let mut rows = artifacts
        .iter()
        .map(|id| load_prepared(transaction, namespace, *id))
        .collect::<Result<Vec<_>>>()?;
    rows.sort_by_key(|r| std::cmp::Reverse(r.target.persist_sequence));
    for row in rows {
        ensure!(!row.committed, "cannot retire committed delta");
        let children: u64 = transaction.query_row(
            "SELECT count(*) FROM ni_prepared WHERE parent_kind=1 AND parent_id=?1",
            [row.artifact.as_slice()],
            |r| r.get(0),
        )?;
        ensure!(children == 0, "cannot retire referenced delta");
        ensure!(
            transaction.execute(
                "DELETE FROM ni_pin WHERE owner=?1 AND reason=1 AND version=?2 AND root=?3",
                params![
                    row.artifact.as_slice(),
                    row.anchor_version.to_be_bytes().as_slice(),
                    row.anchor_root.as_slice()
                ]
            )? == 1,
            "retired delta pin missing"
        );
        adjust_reference(transaction, &root_key(row.anchor_version), false)?;
        ensure!(
            transaction.execute(
                "DELETE FROM ni_prepared WHERE artifact=?1 AND phase=0",
                [row.artifact.as_slice()]
            )? == 1,
            "retired delta missing"
        );
    }
    Ok(())
}

struct PreparedRow {
    artifact: [u8; 32],
    parent: IncrementalParentV1,
    parent_height: u64,
    parent_root: [u8; 32],
    anchor_version: u64,
    anchor_root: [u8; 32],
    target: PreparedIncrementalDeltaV1,
    bytes: Vec<u8>,
    delta_hash: [u8; 32],
    committed: bool,
    epoch: Option<crate::epoch_edge::EpochApplicationCoordinatesV1>,
}
fn load_prepared(
    transaction: &Transaction<'_>,
    namespace: &IncrementalNamespaceV1,
    artifact: [u8; 32],
) -> Result<PreparedRow> {
    let length: u64 = transaction.query_row(
        "SELECT length(delta) FROM ni_prepared WHERE artifact=?1",
        [artifact.as_slice()],
        |row| row.get(0),
    )?;
    ensure!(length <= MAX_DELTA_BYTES as u64, "stored delta capacity");
    let mut statement = transaction.prepare("SELECT parent_kind,parent_id,parent_height,parent_version,parent_root,anchor_version,anchor_root,owner_generation,profile,target_height,block_id,delta,delta_hash,expected_root,persist_sequence,phase,edge FROM ni_prepared WHERE artifact=?1")?;
    let mut rows = statement.query([artifact.as_slice()])?;
    let row = rows
        .next()?
        .context("prepared incremental artifact missing")?;
    let id = fixed(row.get(1)?)?;
    let parent = match row.get::<_, u8>(0)? {
        0 => IncrementalParentV1::Committed(id),
        1 => IncrementalParentV1::Prepared(id),
        _ => anyhow::bail!("prepared parent kind"),
    };
    let parent_height = u64_blob(row.get(2)?)?;
    ensure!(
        parent_height == u64_blob(row.get(3)?)?,
        "prepared parent version"
    );
    ensure!(
        u64_blob(row.get(7)?)? == namespace.owner_generation
            && fixed::<32>(row.get(8)?)? == namespace_digest(namespace)?,
        "prepared owner/profile mismatch"
    );
    let epoch = row
        .get::<_, Option<Vec<u8>>>(16)?
        .map(|raw| load_epoch_storage_edge_v1(transaction, namespace, fixed(raw)?))
        .transpose()?;
    ensure!(
        epoch.is_none() || cfg!(feature = "incremental-epoch-candidate"),
        "epoch delta feature disabled"
    );
    let bytes: Vec<u8> = row.get(11)?;
    ensure!(bytes.len() <= MAX_DELTA_BYTES, "stored delta capacity");
    let delta_hash = fixed(row.get(12)?)?;
    ensure!(
        hash(b"trnm.native-incremental.delta.v1", &[&bytes]) == delta_hash,
        "stored delta hash"
    );
    let target = PreparedIncrementalDeltaV1 {
        artifact,
        height: u64_blob(row.get(9)?)?,
        block: fixed(row.get(10)?)?,
        root: fixed(row.get(13)?)?,
        persist_sequence: u64_blob(row.get(14)?)?,
    };
    if let Some(edge) = epoch {
        ensure!(
            matches!(parent, IncrementalParentV1::Committed(_))
                && edge.checkpoint_version == parent_height
                && edge.first_version == target.height
                && edge.checkpoint_root == fixed::<32>(row.get(4)?)?,
            "epoch delta parent/target"
        );
    } else {
        ensure!(
            parent_height.checked_add(1) == Some(target.height),
            "ordinary delta is not successor"
        );
    }
    let phase = row.get::<_, u8>(15)?;
    ensure!(phase <= 1, "prepared phase");
    let prepared = PreparedRow {
        artifact,
        parent,
        parent_height,
        parent_root: fixed(row.get(4)?)?,
        anchor_version: u64_blob(row.get(5)?)?,
        anchor_root: fixed(row.get(6)?)?,
        target,
        bytes,
        delta_hash,
        committed: phase == 1,
        epoch,
    };
    ensure!(
        storage_artifact_id(namespace, &prepared)? == artifact,
        "prepared incremental record binding mismatch"
    );
    ensure!(
        prepared.anchor_version <= parent_height
            && committed_root(transaction, prepared.anchor_version)? == prepared.anchor_root,
        "prepared incremental anchor mismatch"
    );
    Ok(prepared)
}

pub fn open_incremental_reader_v1<'a>(
    transaction: &'a Transaction<'a>,
    namespace: &IncrementalNamespaceV1,
    mut parent: IncrementalParentV1,
) -> Result<IncrementalJmtReaderV1<'a>> {
    check_namespace(transaction, namespace)?;
    let mut deltas = Vec::new();
    let mut expected: Option<(u64, [u8; 32])> = None;
    let mut target = None;
    let mut younger_sequence = u64::MAX;
    let mut newest_anchor = 0;
    let mut retained_bytes = 0usize;
    loop {
        match parent {
            IncrementalParentV1::Committed(block) => {
                let (version, root) = checked_committed_root(transaction, namespace, block)?;
                ensure!(
                    expected.is_none_or(|tuple| tuple == (version, root)),
                    "prepared ancestry root mismatch"
                );
                ensure!(
                    newest_anchor <= version,
                    "prepared anchor exceeds committed ancestry"
                );
                let (tip, tip_root) = target.unwrap_or((version, root));
                let reader = IncrementalJmtReaderV1 {
                    transaction,
                    version: tip,
                    root: RootHash(tip_root),
                    anchor_version: version,
                    deltas,
                    retained_delta_bytes: retained_bytes,
                };
                ensure!(
                    Sha256Jmt::new(&reader).get_root_hash(tip)? == reader.root,
                    "incremental root node mismatch"
                );
                return Ok(reader);
            }
            IncrementalParentV1::Prepared(artifact) => {
                let length: u64 = transaction.query_row(
                    "SELECT length(delta) FROM ni_prepared WHERE artifact=?1",
                    [artifact.as_slice()],
                    |row| row.get(0),
                )?;
                retained_bytes = retained_bytes
                    .checked_add(usize::try_from(length)?)
                    .context("incremental reader size overflow")?;
                ensure!(
                    retained_bytes <= MAX_READER_DELTA_BYTES,
                    "incremental reader recovery capacity"
                );
                let row = load_prepared(transaction, namespace, artifact)?;
                ensure!(
                    row.target.persist_sequence < younger_sequence,
                    "prepared ancestry cycle/order"
                );
                younger_sequence = row.target.persist_sequence;
                ensure!(
                    expected.is_none_or(|tuple| tuple == (row.target.height, row.target.root)),
                    "prepared parent substitution"
                );
                if row.committed {
                    expected = Some((row.target.height, row.target.root));
                    parent = IncrementalParentV1::Committed(row.target.block);
                    // Once an ancestor commits, remaining suffixes are rebased
                    // onto that exact root; their original older pins stay held.
                    continue;
                }
                ensure!(deltas.len() < MAX_DEPTH, "prepared ancestry depth capacity");
                target.get_or_insert((row.target.height, row.target.root));
                newest_anchor = newest_anchor.max(row.anchor_version);
                deltas.push(Delta::decode(&row.bytes, row.target.height)?);
                expected = Some((row.parent_height, row.parent_root));
                parent = row.parent;
            }
        }
    }
}

fn checked_committed_root(
    transaction: &Transaction<'_>,
    namespace: &IncrementalNamespaceV1,
    block: [u8; 32],
) -> Result<(u64, [u8; 32])> {
    let mut statement = transaction.prepare("SELECT version,root,commit_sequence,intent,CASE WHEN length(root_node_key)<=128 THEN root_node_key ELSE NULL END,consensus_height FROM ni_roots WHERE block_id=?1")?;
    let mut rows = statement.query([block.as_slice()])?;
    let row = rows.next()?.context("committed incremental root missing")?;
    let version = u64_blob(row.get(0)?)?;
    let root = fixed(row.get(1)?)?;
    let sequence = u64_blob(row.get(2)?)?;
    let intent = fixed(row.get(3)?)?;
    ensure!(
        row.get::<_, Vec<u8>>(4)? == borsh::to_vec(&root_key(version))?
            && u64_blob(row.get(5)?)? == version,
        "committed root coordinate mismatch"
    );
    let pin: Vec<u8> = transaction.query_row(
        "SELECT reference_count FROM ni_pin WHERE owner=?1 AND reason=0 AND version=?2 AND root=?3",
        params![
            block.as_slice(),
            version.to_be_bytes().as_slice(),
            root.as_slice()
        ],
        |row| row.get(0),
    )?;
    ensure!(u64_blob(pin)? == 1, "retained root pin mismatch");
    let imported: Option<(Vec<u8>, Vec<u8>, Vec<u8>)> = transaction
        .query_row(
            "SELECT source_anchor,result,checksum FROM ni_imported_root WHERE version=?1",
            [version.to_be_bytes().as_slice()],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()?;
    if let Some((anchor, bytes, checksum)) = imported {
        let mut imported = IncrementalHeadV1 {
            height: version,
            block,
            root,
            commit_sequence: sequence,
            intent,
            checksum: [0; 32],
        };
        imported.checksum = head_checksum(namespace, &imported)?;
        ensure!(
            fixed::<32>(anchor.clone())? != [0; 32]
                && bytes == head_bytes(&imported)
                && fixed::<32>(checksum)?
                    == hash(
                        b"trnm.native-incremental.imported-root.v1",
                        &[&namespace_digest(namespace)?, &anchor, &bytes]
                    ),
            "imported root binding mismatch"
        );
    } else if version == 0 {
        ensure!(sequence == 0, "genesis root sequence mismatch");
    } else {
        let mut result = IncrementalHeadV1 {
            height: version,
            block,
            root,
            commit_sequence: sequence,
            intent,
            checksum: [0; 32],
        };
        result.checksum = head_checksum(namespace, &result)?;
        let mut statement = transaction.prepare("SELECT c.target_block,c.target_root,c.successor_sequence,c.result,p.block_id,p.expected_root,p.phase FROM ni_commit c JOIN ni_prepared p ON p.artifact=c.artifact WHERE c.operation=?1")?;
        let mut rows = statement.query([intent.as_slice()])?;
        let row = rows
            .next()?
            .context("committed root lacks commit/prepared record")?;
        ensure!(
            fixed::<32>(row.get(0)?)? == block
                && fixed::<32>(row.get(1)?)? == root
                && u64_blob(row.get(2)?)? == sequence
                && row.get::<_, Vec<u8>>(3)? == head_bytes(&result)
                && fixed::<32>(row.get(4)?)? == block
                && fixed::<32>(row.get(5)?)? == root
                && row.get::<_, u8>(6)? == 1,
            "committed root/prepared/result mismatch"
        );
    }
    Ok((version, root))
}

fn parent_fields(parent: IncrementalParentV1) -> (u8, [u8; 32]) {
    match parent {
        IncrementalParentV1::Committed(id) => (0, id),
        IncrementalParentV1::Prepared(id) => (1, id),
    }
}
fn storage_artifact_id(namespace: &IncrementalNamespaceV1, row: &PreparedRow) -> Result<[u8; 32]> {
    let (kind, parent) = parent_fields(row.parent);
    let ordinary = hash(
        b"trnm.native-incremental.prepared.v1",
        &[
            &namespace_digest(namespace)?,
            &[kind],
            &parent,
            &row.parent_height.to_be_bytes(),
            &row.parent_root,
            &row.anchor_version.to_be_bytes(),
            &row.anchor_root,
            &row.target.height.to_be_bytes(),
            &row.target.block,
            &row.target.root,
            &row.delta_hash,
            &row.target.persist_sequence.to_be_bytes(),
        ],
    );
    Ok(match row.epoch {
        None => ordinary,
        Some(edge) => hash(
            b"trnm.native-incremental.prepared-epoch.v1",
            &[&ordinary, &encode_epoch_storage_edge_v1(edge)],
        ),
    })
}

/// Stage only a changed-node/value batch. The returned storage artifact must be
/// bound into the application's durable P; it is not the native execution
/// artifact ID and does not assert consensus validity or finality.
pub fn stage_incremental_plan_v1(
    transaction: &Transaction<'_>,
    namespace: &IncrementalNamespaceV1,
    parent: IncrementalParentV1,
    block: [u8; 32],
    plan: &CompleteStatePlanV0,
) -> Result<PreparedIncrementalDeltaV1> {
    ensure!(
        plan.epoch_parent.is_none(),
        "ordinary incremental plan cannot contain epoch edge"
    );
    stage_incremental_plan_inner_v1(transaction, namespace, parent, block, plan, None)
}

fn stage_incremental_plan_inner_v1(
    transaction: &Transaction<'_>,
    namespace: &IncrementalNamespaceV1,
    parent: IncrementalParentV1,
    block: [u8; 32],
    plan: &CompleteStatePlanV0,
    epoch: Option<crate::epoch_edge::EpochApplicationCoordinatesV1>,
) -> Result<PreparedIncrementalDeltaV1> {
    ensure!(block != [0; 32], "incremental target block missing");
    ensure!(plan.epoch_parent == epoch, "incremental plan edge differs");
    let head = read_incremental_head_v1(transaction, namespace)?;
    let reader = open_incremental_reader_v1(transaction, namespace, parent)?;
    if let Some(edge) = epoch {
        ensure!(
            reader.version == edge.checkpoint_version
                && reader.root.0 == edge.checkpoint_root
                && plan.version == edge.first_version
                && reader.deltas.is_empty()
                && matches!(parent, IncrementalParentV1::Committed(_)),
            "epoch stage exact committed parent"
        );
        require_absent_incremental_seals_v1(transaction, edge)?;
    } else {
        ensure!(
            reader.version.checked_add(1) == Some(plan.version),
            "incremental target is not successor"
        );
    }
    ensure!(
        reader.deltas.len() < MAX_DEPTH,
        "prepared ancestry depth capacity"
    );
    let delta = Delta {
        batch: plan.tree_update_batch.node_batch.clone(),
        preimages: plan.preimages.clone(),
    };
    let bytes = delta.encode()?;
    ensure!(
        reader
            .retained_delta_bytes
            .checked_add(bytes.len())
            .is_some_and(|n| n <= MAX_READER_DELTA_BYTES),
        "staged delta exceeds readable suffix capacity"
    );
    // Decode before storing so staging and restart share one canonical contract.
    let decoded = Delta::decode(&bytes, plan.version)?;
    let delta_hash = hash(b"trnm.native-incremental.delta.v1", &[&bytes]);
    let existing: Option<Vec<u8>> = transaction
        .query_row(
            "SELECT artifact FROM ni_prepared WHERE block_id=?1",
            [block.as_slice()],
            |row| row.get(0),
        )
        .optional()?;
    if let Some(existing) = existing {
        let existing = load_prepared(transaction, namespace, fixed(existing)?)?;
        ensure!(
            existing.parent == parent
                && existing.epoch == epoch
                && existing.parent_height == reader.version
                && existing.parent_root == reader.root.0
                && existing.target.height == plan.version
                && existing.target.root == plan.root_hash.0
                && existing.delta_hash == delta_hash
                && existing.bytes == bytes,
            "conflicting incremental retry"
        );
        return Ok(existing.target);
    }
    let (count, retained): (u64, u64) = transaction.query_row(
        "SELECT count(*),coalesce(sum(length(delta)),0) FROM ni_prepared WHERE phase=0",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let reserved_descendants = 2usize.saturating_sub(reader.deltas.len());
    let reservation_bytes = (reserved_descendants as u64)
        .checked_mul(MAX_DELTA_BYTES as u64)
        .context("prepared reservation overflow")?;
    ensure!(
        count
            .checked_add(1 + reserved_descendants as u64)
            .is_some_and(|count| count <= MAX_PREPARED as u64)
            && retained
                .checked_add(bytes.len() as u64)
                .and_then(|total| total.checked_add(reservation_bytes))
                .is_some_and(|total| total <= MAX_PREPARED_BYTES),
        "prepared incremental capacity"
    );
    // This version creates only retained-root and speculative-parent pins, and
    // never deletes retained roots. Derive their count without scanning history.
    let pins = head
        .commit_sequence
        .checked_add(1)
        .and_then(|value| value.checked_add(count))
        .context("incremental pin count overflow")?;
    ensure!(pins < MAX_PINS, "incremental pin capacity");
    let watermark: Vec<u8> = transaction.query_row(
        "SELECT persist_sequence FROM ni_sequence WHERE id=1",
        [],
        |r| r.get(0),
    )?;
    let watermark = u64_blob(watermark)?;
    let maximum: Option<Vec<u8>> =
        transaction.query_row("SELECT max(persist_sequence) FROM ni_prepared", [], |r| {
            r.get(0)
        })?;
    ensure!(
        watermark >= head.commit_sequence
            && maximum
                .map(u64_blob)
                .transpose()?
                .is_none_or(|n| n <= watermark),
        "incremental persist watermark regressed"
    );
    let sequence = watermark
        .checked_add(1)
        .context("persist sequence exhausted")?;
    let mut row = PreparedRow {
        artifact: [0; 32],
        parent,
        parent_height: reader.version,
        parent_root: reader.root.0,
        anchor_version: reader.anchor_version,
        anchor_root: committed_root(transaction, reader.anchor_version)?,
        target: PreparedIncrementalDeltaV1 {
            artifact: [0; 32],
            block,
            height: plan.version,
            root: plan.root_hash.0,
            persist_sequence: sequence,
        },
        bytes,
        delta_hash,
        committed: false,
        epoch,
    };
    row.artifact = storage_artifact_id(namespace, &row)?;
    row.target.artifact = row.artifact;
    let mut deltas = vec![decoded];
    deltas.extend(reader.deltas);
    let target_reader = IncrementalJmtReaderV1 {
        transaction,
        version: plan.version,
        root: plan.root_hash,
        anchor_version: reader.anchor_version,
        deltas,
        retained_delta_bytes: reader.retained_delta_bytes + row.bytes.len(),
    };
    ensure!(
        Sha256Jmt::new(&target_reader).get_root_hash(plan.version)? == plan.root_hash,
        "incremental computed root mismatch"
    );
    for write in plan.writes() {
        ensure!(
            target_reader.prove(write.key())?.as_deref() == write.value(),
            "incremental write proof mismatch"
        );
    }
    let (kind, parent_id) = parent_fields(parent);
    ensure!(
        transaction.execute(
            "UPDATE ni_sequence SET persist_sequence=?1 WHERE id=1 AND persist_sequence=?2",
            params![
                sequence.to_be_bytes().as_slice(),
                watermark.to_be_bytes().as_slice()
            ]
        )? == 1,
        "incremental persist watermark CAS"
    );
    transaction.execute("INSERT INTO ni_prepared VALUES(?1,?2,?3,?4,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,0,?16)", params![
        row.artifact.as_slice(), kind, parent_id.as_slice(), row.parent_height.to_be_bytes().as_slice(), row.parent_root.as_slice(),
        row.anchor_version.to_be_bytes().as_slice(), row.anchor_root.as_slice(), namespace.owner_generation.to_be_bytes().as_slice(), namespace_digest(namespace)?.as_slice(),
        row.target.height.to_be_bytes().as_slice(), block.as_slice(), row.bytes, row.delta_hash.as_slice(), row.target.root.as_slice(), sequence.to_be_bytes().as_slice(), row.epoch.map(|edge| edge.authorization_id.to_vec()),
    ])?;
    transaction.execute(
        "INSERT INTO ni_pin VALUES(?1,1,?2,?3,?4,NULL)",
        params![
            row.artifact.as_slice(),
            row.anchor_version.to_be_bytes().as_slice(),
            row.anchor_root.as_slice(),
            1u64.to_be_bytes().as_slice()
        ],
    )?;
    adjust_reference(transaction, &root_key(row.anchor_version), true)?;
    Ok(row.target)
}

fn committed_root(transaction: &Transaction<'_>, version: u64) -> Result<[u8; 32]> {
    fixed(transaction.query_row(
        "SELECT root FROM ni_roots WHERE version=?1",
        [version.to_be_bytes().as_slice()],
        |row| row.get(0),
    )?)
}

fn adjust_reference(transaction: &Transaction<'_>, key: &NodeKey, add: bool) -> Result<()> {
    let bytes = borsh::to_vec(key)?;
    let current = u64_blob(transaction.query_row(
        "SELECT refs FROM ni_nodes WHERE node_key=?1",
        [&bytes],
        |row| row.get(0),
    )?)?;
    let next = if add {
        current.checked_add(1)
    } else {
        current.checked_sub(1)
    }
    .context("node reference overflow/underflow")?;
    ensure!(
        transaction.execute(
            "UPDATE ni_nodes SET refs=?1 WHERE node_key=?2 AND refs=?3",
            params![
                next.to_be_bytes().as_slice(),
                bytes,
                current.to_be_bytes().as_slice()
            ]
        )? == 1,
        "node reference CAS"
    );
    Ok(())
}
fn write_committed_batch(
    transaction: &Transaction<'_>,
    batch: &NodeBatch,
    preimages: &BTreeMap<KeyHash, Vec<u8>>,
) -> Result<()> {
    for (key, node) in batch.nodes() {
        validate_node_key(key)?;
        validate_node(node)?;
        validate_node_at(key, node)?;
        let key_bytes = borsh::to_vec(key)?;
        let node_bytes = borsh::to_vec(node)?;
        ensure!(
            key_bytes.len() <= MAX_KEY_BYTES && node_bytes.len() <= MAX_NODE_BYTES,
            "committed node capacity"
        );
        transaction.execute(
            "INSERT INTO ni_nodes VALUES(?1,?2,?3,?4,?5)",
            params![
                key_bytes,
                key.version().to_be_bytes().as_slice(),
                node_bytes,
                node_hash(node).as_slice(),
                0u64.to_be_bytes().as_slice()
            ],
        )?;
    }
    for (key, node) in batch.nodes() {
        if let Node::Internal(internal) = node {
            for (nibble, child) in internal.children_sorted() {
                ensure!(child.version <= key.version(), "future child version");
                ensure!(
                    key.nibble_path().num_nibbles() < 64,
                    "internal path too long"
                );
                let path = key
                    .nibble_path()
                    .nibbles()
                    .chain(std::iter::once(nibble))
                    .collect();
                let child_key = NodeKey::new(child.version, path);
                let stored: Vec<u8> = transaction.query_row(
                    "SELECT node_bytes FROM ni_nodes WHERE node_key=?1 AND length(node_bytes)<=4096",
                    [borsh::to_vec(&child_key)?],
                    |row| row.get(0),
                )?;
                let stored: Node = borsh::from_slice(&stored)?;
                validate_node(&stored)?;
                validate_node_at(&child_key, &stored)?;
                ensure!(
                    node_hash(&stored) == child.hash,
                    "incremental child dependency mismatch"
                );
                let (is_leaf, leaves) = match &stored {
                    Node::Leaf(_) => (true, 1),
                    Node::Internal(internal) => (false, internal.leaf_count()),
                    Node::Null => anyhow::bail!("null internal dependency"),
                };
                ensure!(
                    child.is_leaf() == is_leaf && child.leaf_count() == leaves,
                    "incremental child metadata mismatch"
                );
                adjust_reference(transaction, &child_key, true)?;
            }
        }
    }
    for ((version, key), value) in batch.values() {
        ensure!(
            value
                .as_ref()
                .is_none_or(|bytes| bytes.len() <= MAX_VALUE_BYTES),
            "committed value capacity"
        );
        transaction.execute(
            "INSERT INTO ni_values VALUES(?1,?2,?3,?4)",
            params![
                key.0.as_slice(),
                version.to_be_bytes().as_slice(),
                u8::from(value.is_some()),
                value.as_deref().unwrap_or_default()
            ],
        )?;
    }
    for (key, bytes) in preimages {
        ensure!(
            bytes.len() <= MAX_PREIMAGE_BYTES && authenticated_key_hash_v0(bytes)? == *key,
            "committed preimage mismatch"
        );
        let existing: Option<Vec<u8>> = transaction
            .query_row(
                "SELECT CASE WHEN length(preimage)<=65536 THEN preimage ELSE NULL END FROM ni_preimages WHERE key_hash=?1",
                [key.0.as_slice()],
                |row| row.get(0),
            )
            .optional()?;
        match existing {
            Some(existing) => ensure!(existing == *bytes, "preimage collision"),
            None => {
                transaction.execute(
                    "INSERT INTO ni_preimages VALUES(?1,?2)",
                    params![key.0.as_slice(), bytes],
                )?;
            }
        }
    }
    Ok(())
}
fn insert_root(transaction: &Transaction<'_>, head: &IncrementalHeadV1, epoch: u64) -> Result<()> {
    let key = root_key(head.height);
    let expected: Vec<u8> = transaction.query_row(
        "SELECT node_hash FROM ni_nodes WHERE node_key=?1",
        [borsh::to_vec(&key)?],
        |row| row.get(0),
    )?;
    ensure!(
        fixed::<32>(expected)? == head.root,
        "committed root node hash mismatch"
    );
    transaction.execute(
        "INSERT INTO ni_roots VALUES(?1,?2,?1,?3,?4,?5,?6,?7)",
        params![
            head.height.to_be_bytes().as_slice(),
            epoch.to_be_bytes().as_slice(),
            head.block.as_slice(),
            head.root.as_slice(),
            borsh::to_vec(&key)?,
            head.commit_sequence.to_be_bytes().as_slice(),
            head.intent.as_slice()
        ],
    )?;
    transaction.execute(
        "INSERT INTO ni_pin VALUES(?1,0,?2,?3,?4,NULL)",
        params![
            head.block.as_slice(),
            head.height.to_be_bytes().as_slice(),
            head.root.as_slice(),
            1u64.to_be_bytes().as_slice()
        ],
    )?;
    adjust_reference(transaction, &key, true)?;
    Ok(())
}

fn head_bytes(head: &IncrementalHeadV1) -> Vec<u8> {
    [
        &head.height.to_be_bytes()[..],
        &head.block,
        &head.root,
        &head.commit_sequence.to_be_bytes(),
        &head.intent,
        &head.checksum,
    ]
    .concat()
}

/// Apply in the same transaction as the owner's already verified application
/// finality/commit record. This function cannot itself establish finality. It
/// compares the full predecessor and persists only the selected delta; forks
/// remain isolated. The caller must roll back the transaction on any error.
pub fn apply_incremental_delta_v1(
    transaction: &Transaction<'_>,
    namespace: &IncrementalNamespaceV1,
    expected: &IncrementalHeadV1,
    prepared: &PreparedIncrementalDeltaV1,
    operation: [u8; 32],
    epoch: u64,
) -> Result<IncrementalHeadV1> {
    apply_incremental_delta_inner_v1(
        transaction,
        namespace,
        expected,
        prepared,
        operation,
        epoch,
        None,
    )
}

fn apply_incremental_delta_inner_v1(
    transaction: &Transaction<'_>,
    namespace: &IncrementalNamespaceV1,
    expected: &IncrementalHeadV1,
    prepared: &PreparedIncrementalDeltaV1,
    operation: [u8; 32],
    epoch: u64,
    edge: Option<crate::epoch_edge::EpochApplicationCoordinatesV1>,
) -> Result<IncrementalHeadV1> {
    ensure!(
        operation != [0; 32] && expected.checksum == head_checksum(namespace, expected)?,
        "incremental expected head/operation"
    );
    let parent_epoch: Vec<u8> = transaction.query_row(
        "SELECT epoch FROM ni_roots WHERE version=?1",
        [expected.height.to_be_bytes().as_slice()],
        |record| record.get(0),
    )?;
    let parent_epoch = u64_blob(parent_epoch)?;
    let row = load_prepared(transaction, namespace, prepared.artifact)?;
    match edge {
        None => {
            ensure!(
                parent_epoch == epoch,
                "ordinary incremental commit cannot change epoch"
            );
            ensure!(
                row.epoch.is_none(),
                "ordinary apply cannot commit an epoch delta"
            );
        }
        Some(edge) => {
            edge.validate()?;
            ensure!(
                row.epoch == Some(edge)
                    && expected.height == edge.checkpoint_version
                    && expected.root == edge.checkpoint_root
                    && prepared.height == edge.first_version
                    && parent_epoch.checked_add(1) == Some(epoch),
                "epoch apply exact edge/epochs"
            );
            require_absent_incremental_seals_v1(transaction, edge)?;
        }
    }
    ensure!(
        row.target == *prepared,
        "incremental prepared target substitution"
    );
    let sequence = expected
        .commit_sequence
        .checked_add(1)
        .context("commit sequence exhausted")?;
    let mut target = IncrementalHeadV1 {
        height: prepared.height,
        block: prepared.block,
        root: prepared.root,
        commit_sequence: sequence,
        intent: operation,
        checksum: [0; 32],
    };
    target.checksum = head_checksum(namespace, &target)?;
    let prior: Option<Vec<u8>> = transaction
        .query_row(
            "SELECT result FROM ni_commit WHERE operation=?1",
            [operation.as_slice()],
            |record| record.get(0),
        )
        .optional()?;
    if let Some(prior) = prior {
        ensure!(
            row.committed && prior == head_bytes(&target),
            "incremental operation retry mismatch"
        );
        let mut statement = transaction.prepare("SELECT predecessor_checksum,expected_sequence,artifact,target_block,target_root,successor_sequence FROM ni_commit WHERE operation=?1")?;
        let mut rows = statement.query([operation.as_slice()])?;
        let record = rows.next()?.context("incremental retry disappeared")?;
        ensure!(
            fixed::<32>(record.get(0)?)? == expected.checksum
                && u64_blob(record.get(1)?)? == expected.commit_sequence
                && fixed::<32>(record.get(2)?)? == prepared.artifact
                && fixed::<32>(record.get(3)?)? == target.block
                && fixed::<32>(record.get(4)?)? == target.root
                && u64_blob(record.get(5)?)? == target.commit_sequence,
            "incremental retry bound fields mismatch"
        );
        ensure!(
            committed_root(transaction, target.height)? == target.root,
            "incremental retry missing committed root"
        );
        return Ok(target);
    }
    ensure!(
        !row.committed && read_incremental_head_v1(transaction, namespace)? == *expected,
        "incremental head CAS mismatch"
    );
    let parent_block = match row.parent {
        IncrementalParentV1::Committed(block) => block,
        IncrementalParentV1::Prepared(artifact) => {
            let parent = load_prepared(transaction, namespace, artifact)?;
            ensure!(parent.committed, "cannot commit before prepared parent");
            parent.target.block
        }
    };
    ensure!(
        parent_block == expected.block
            && row.parent_height == expected.height
            && row.parent_root == expected.root,
        "incremental commit parent mismatch"
    );
    let delta = Delta::decode(&row.bytes, prepared.height)?;
    write_committed_batch(transaction, &delta.batch, &delta.preimages)?;
    insert_root(transaction, &target, epoch)?;
    if let Some(edge) = edge {
        ensure!(transaction.execute("UPDATE ni_epoch_edge SET phase=1,committed_block=?1 WHERE strict_binding=?2 AND phase=0 AND committed_block IS NULL",params![target.block.as_slice(),edge.authorization_id.as_slice()])?==1,"epoch edge commit CAS");
    }
    ensure!(
        transaction.execute(
            "UPDATE ni_prepared SET phase=1 WHERE artifact=?1 AND phase=0",
            [prepared.artifact.as_slice()]
        )? == 1,
        "incremental prepared phase CAS"
    );
    transaction.execute(
        "INSERT INTO ni_commit VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
        params![
            operation.as_slice(),
            expected.checksum.as_slice(),
            expected.commit_sequence.to_be_bytes().as_slice(),
            prepared.artifact.as_slice(),
            target.block.as_slice(),
            target.root.as_slice(),
            sequence.to_be_bytes().as_slice(),
            head_bytes(&target)
        ],
    )?;
    ensure!(
        transaction.execute(
            "DELETE FROM ni_pin WHERE owner=?1 AND reason=1 AND version=?2 AND root=?3",
            params![
                prepared.artifact.as_slice(),
                row.anchor_version.to_be_bytes().as_slice(),
                row.anchor_root.as_slice()
            ]
        )? == 1,
        "incremental speculative pin missing"
    );
    adjust_reference(transaction, &root_key(row.anchor_version), false)?;
    ensure!(transaction.execute("UPDATE ni_meta SET head_height=?1,head_version=?1,head_block=?2,head_root=?3,commit_sequence=?4,head_intent=?5,head_checksum=?6 WHERE id=1 AND namespace=?7 AND owner_generation=?8 AND head_checksum=?9 AND head_height=?10 AND head_root=?11 AND commit_sequence=?12", params![
        target.height.to_be_bytes().as_slice(), target.block.as_slice(), target.root.as_slice(), sequence.to_be_bytes().as_slice(), operation.as_slice(), target.checksum.as_slice(),
        namespace.namespace.as_slice(), namespace.owner_generation.to_be_bytes().as_slice(), expected.checksum.as_slice(), expected.height.to_be_bytes().as_slice(), expected.root.as_slice(), expected.commit_sequence.to_be_bytes().as_slice(),
    ])? == 1, "incremental head update CAS");
    ensure!(
        read_incremental_head_v1(transaction, namespace)? == target,
        "incremental post-apply readback mismatch"
    );
    Ok(target)
}

#[cfg(test)]
#[path = "incremental_store_v1_tests.rs"]
mod tests;

fn encode_epoch_storage_edge_v1(edge: crate::epoch_edge::EpochApplicationCoordinatesV1) -> Vec<u8> {
    [
        &edge.authorization_id[..],
        &edge.checkpoint_version.to_be_bytes(),
        &edge.checkpoint_root,
        &edge.terminal_version.to_be_bytes(),
        &edge.first_version.to_be_bytes(),
    ]
    .concat()
}
fn decode_epoch_storage_edge_v1(
    raw: &[u8],
) -> Result<crate::epoch_edge::EpochApplicationCoordinatesV1> {
    ensure!(raw.len() == 88, "incremental edge coordinate length");
    let edge = crate::epoch_edge::EpochApplicationCoordinatesV1 {
        authorization_id: raw[..32].try_into()?,
        checkpoint_version: u64::from_be_bytes(raw[32..40].try_into()?),
        checkpoint_root: raw[40..72].try_into()?,
        terminal_version: u64::from_be_bytes(raw[72..80].try_into()?),
        first_version: u64::from_be_bytes(raw[80..88].try_into()?),
    };
    edge.validate()?;
    Ok(edge)
}
fn require_absent_incremental_seals_v1(
    tx: &Transaction<'_>,
    edge: crate::epoch_edge::EpochApplicationCoordinatesV1,
) -> Result<()> {
    for table in ["ni_roots", "ni_values"] {
        let count: u64 = tx.query_row(
            &format!("SELECT count(*) FROM {table} WHERE version>?1 AND version<?2"),
            params![
                edge.checkpoint_version.to_be_bytes().as_slice(),
                edge.first_version.to_be_bytes().as_slice()
            ],
            |r| r.get(0),
        )?;
        ensure!(count == 0, "seal has an incremental root/value");
    }
    let count: u64 = tx.query_row(
        "SELECT count(*) FROM ni_nodes WHERE node_version>?1 AND node_version<?2",
        params![
            edge.checkpoint_version.to_be_bytes().as_slice(),
            edge.first_version.to_be_bytes().as_slice()
        ],
        |r| r.get(0),
    )?;
    ensure!(count == 0, "seal has physical incremental node");
    Ok(())
}

#[cfg(feature = "incremental-epoch-candidate")]
#[path = "incremental_epoch_storage_v1.rs"]
pub(crate) mod epoch_candidate_v1;

fn load_epoch_storage_edge_v1(
    tx: &Transaction<'_>,
    namespace: &IncrementalNamespaceV1,
    binding: [u8; 32],
) -> Result<crate::epoch_edge::EpochApplicationCoordinatesV1> {
    type EdgeColumns = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, u8, Option<Vec<u8>>);
    let (raw, checksum, checkpoint, first, phase, consumed): EdgeColumns = tx.query_row(
        "SELECT CASE WHEN length(edge)=88 THEN edge ELSE NULL END,checksum,checkpoint_version,first_height,phase,committed_block FROM ni_epoch_edge WHERE strict_binding=?1",
        [binding.as_slice()], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?)))?;
    let edge = decode_epoch_storage_edge_v1(&raw)?;
    ensure!(
        edge.authorization_id == binding
            && edge.checkpoint_version == u64_blob(checkpoint)?
            && edge.first_version == u64_blob(first)?
            && ((phase == 0 && consumed.is_none())
                || (phase == 1
                    && consumed
                        .as_ref()
                        .is_some_and(|b| b.len() == 32 && b.as_slice() != [0; 32])))
            && fixed::<32>(checksum)?
                == hash(
                    b"trnm.native-incremental.edge.v1",
                    &[&namespace_digest(namespace)?, &raw]
                ),
        "incremental stored edge mismatch"
    );
    Ok(edge)
}
