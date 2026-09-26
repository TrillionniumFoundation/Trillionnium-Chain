//! Local authenticated replay membership. Every present leaf has the exact
//! value [1]; absence is proved against the P-bound root, never inferred from
//! a missing SQL index row. This tree does not enter the consensus state root.
use crate::store::incremental_store_v1::audit_jmt_node_record_v1;
use anyhow::{ensure, Context, Result};
use jmt::{
    storage::{LeafNode, Node, NodeKey, TreeReader},
    KeyHash, RootHash, Sha256Jmt,
};
use rusqlite::{params, OptionalExtension, Transaction};
use std::collections::{BTreeMap, BTreeSet};

pub(super) const SCHEMA:&str="CREATE TABLE native_incremental_replay_node_v1 (node_key BLOB PRIMARY KEY CHECK(length(node_key)<=128),node BLOB NOT NULL CHECK(length(node)<=4096)) STRICT, WITHOUT ROWID";
const MAX_DELTA: usize = 16 * 1024 * 1024;
const MAX_NODES: usize = 65_537;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ReplayHead {
    pub version: u64,
    pub root: [u8; 32],
}
#[derive(Clone, Debug)]
pub(super) struct ReplayDelta {
    pub head: ReplayHead,
    nodes: BTreeMap<NodeKey, Node>,
}

pub(super) fn command_key(id: &str) -> Result<KeyHash> {
    ensure!(!id.is_empty() && id.len() <= 4096, "replay command length");
    Ok(KeyHash(trnm_finality_types::hash_domain(
        "trnm.native-incremental.replay-command.v1",
        &[id.as_bytes()],
    )))
}
pub(super) fn nonce_key(signer: &str, nonce: u64) -> Result<KeyHash> {
    ensure!(
        !signer.is_empty() && signer.len() <= 4096,
        "replay signer length"
    );
    Ok(KeyHash(trnm_finality_types::hash_domain(
        "trnm.native-incremental.replay-nonce.v1",
        &[signer.as_bytes(), &nonce.to_be_bytes()],
    )))
}
impl ReplayDelta {
    pub fn encode(&self) -> Result<Vec<u8>> {
        ensure!(self.nodes.len() <= MAX_NODES, "replay delta node capacity");
        let mut out = 1u16.to_be_bytes().to_vec();
        out.extend(self.head.version.to_be_bytes());
        out.extend(self.head.root);
        out.extend(u32::try_from(self.nodes.len())?.to_be_bytes());
        for (key, node) in &self.nodes {
            audit_jmt_node_record_v1(key, node)?;
            ensure!(
                key.version() == self.head.version,
                "replay delta node version"
            );
            let key = borsh::to_vec(key)?;
            let node = borsh::to_vec(node)?;
            ensure!(
                key.len() <= 128 && node.len() <= 4096,
                "replay delta record capacity"
            );
            out.extend(u32::try_from(key.len())?.to_be_bytes());
            out.extend(key);
            out.extend(u32::try_from(node.len())?.to_be_bytes());
            out.extend(node);
            ensure!(out.len() <= MAX_DELTA, "replay delta byte capacity");
        }
        Ok(out)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        ensure!(bytes.len() <= MAX_DELTA, "replay delta byte capacity");
        let mut at = 0;
        fn take<'a>(bytes: &'a [u8], at: &mut usize, n: usize) -> Result<&'a [u8]> {
            let end = at.checked_add(n).context("replay length overflow")?;
            let value = bytes.get(*at..end).context("truncated replay delta")?;
            *at = end;
            Ok(value)
        }
        ensure!(
            take(bytes, &mut at, 2)? == 1u16.to_be_bytes(),
            "replay delta codec"
        );
        let version = u64::from_be_bytes(take(bytes, &mut at, 8)?.try_into()?);
        let root = take(bytes, &mut at, 32)?.try_into()?;
        let count = u32::from_be_bytes(take(bytes, &mut at, 4)?.try_into()?) as usize;
        ensure!(count <= MAX_NODES, "replay node count capacity");
        let mut nodes = BTreeMap::new();
        for _ in 0..count {
            let length = u32::from_be_bytes(take(bytes, &mut at, 4)?.try_into()?) as usize;
            ensure!(length <= 128, "replay key capacity");
            let key: NodeKey = borsh::from_slice(take(bytes, &mut at, length)?)?;
            ensure!(
                key.version() == version && key.nibble_path().num_nibbles() <= 64,
                "replay key coordinate"
            );
            let length = u32::from_be_bytes(take(bytes, &mut at, 4)?.try_into()?) as usize;
            ensure!(length <= 4096, "replay node capacity");
            let node: Node = borsh::from_slice(take(bytes, &mut at, length)?)?;
            audit_jmt_node_record_v1(&key, &node)?;
            ensure!(
                nodes
                    .last_key_value()
                    .is_none_or(|(previous, _)| previous < &key),
                "replay node order"
            );
            nodes.insert(key, node);
        }
        let result = Self {
            head: ReplayHead { version, root },
            nodes,
        };
        ensure!(
            at == bytes.len() && result.encode()? == bytes,
            "noncanonical replay delta"
        );
        Ok(result)
    }
}

pub(super) struct ReplayReader<'a> {
    transaction: &'a Transaction<'a>,
    base: Option<ReplayHead>,
    pub head: Option<ReplayHead>,
    deltas: &'a [ReplayDelta],
}
impl<'a> ReplayReader<'a> {
    pub fn new(
        transaction: &'a Transaction<'a>,
        base: Option<ReplayHead>,
        deltas: &'a [ReplayDelta],
    ) -> Result<Self> {
        ensure!(deltas.len() <= 8, "replay prepared depth capacity");
        let mut previous = base;
        for delta in deltas.iter().rev() {
            ensure!(
                previous.map_or(Some(0), |h| h.version.checked_add(1)) == Some(delta.head.version),
                "replay parent version mismatch"
            );
            previous = Some(delta.head);
        }
        let reader = Self {
            transaction,
            base,
            head: previous,
            deltas,
        };
        if let Some(head) = reader.head {
            ensure!(
                Sha256Jmt::new(&reader).get_root_hash(head.version)?.0 == head.root,
                "replay root mismatch"
            );
        }
        Ok(reader)
    }
    pub fn verify_exact_cardinality(&self, expected: usize) -> Result<()> {
        ensure!(expected <= 65_536, "replay baseline cardinality capacity");
        let head = self.head.context("replay baseline head missing")?;
        let mut pending = vec![(
            NodeKey::new(head.version, std::iter::empty().collect()),
            head.root,
        )];
        let mut count = 0;
        let mut visited = 0;
        while let Some((key, expected_hash)) = pending.pop() {
            visited += 1;
            ensure!(
                visited <= 1_048_576 && key.nibble_path().num_nibbles() <= 64,
                "replay baseline traversal capacity"
            );
            let node = self
                .get_node_option(&key)?
                .context("replay baseline node missing")?;
            let actual = match &node {
                Node::Null => *b"SPARSE_MERKLE_PLACEHOLDER_HASH__",
                Node::Leaf(n) => n.hash::<sha2::Sha256>(),
                Node::Internal(n) => n.hash::<sha2::Sha256>(),
            };
            ensure!(actual == expected_hash, "replay baseline node hash");
            match node {
                Node::Null => ensure!(key.nibble_path().is_empty(), "null replay child"),
                Node::Leaf(_) => {
                    count += 1;
                    ensure!(count <= expected, "unexpected replay baseline leaf");
                }
                Node::Internal(n) => {
                    ensure!(
                        key.nibble_path().num_nibbles() < 64,
                        "replay internal path capacity"
                    );
                    for (nibble, child) in n.children_sorted() {
                        let path = key
                            .nibble_path()
                            .nibbles()
                            .chain(std::iter::once(nibble))
                            .collect();
                        ensure!(child.version <= key.version(), "future replay child");
                        pending.push((NodeKey::new(child.version, path), child.hash));
                    }
                }
            }
        }
        ensure!(count == expected, "replay baseline cardinality mismatch");
        Ok(())
    }
    pub fn contains(&self, key: KeyHash) -> Result<bool> {
        let Some(head) = self.head else {
            return Ok(false);
        };
        let (value, proof) = Sha256Jmt::new(self).get_with_proof(key, head.version)?;
        if let Some(value) = value {
            ensure!(value == [1], "replay membership value");
            proof.verify_existence(RootHash(head.root), key, &value)?;
            Ok(true)
        } else {
            proof.verify_nonexistence(RootHash(head.root), key)?;
            Ok(false)
        }
    }
    pub fn append(&self, keys: impl IntoIterator<Item = KeyHash>) -> Result<ReplayDelta> {
        let mut unique = BTreeSet::new();
        for key in keys {
            ensure!(
                unique.insert(key) && !self.contains(key)?,
                "duplicate committed or prepared replay identity"
            );
        }
        let version = self
            .head
            .map_or(Some(0), |h| h.version.checked_add(1))
            .context("replay version exhausted")?;
        let (root, batch) = Sha256Jmt::new(self)
            .put_value_set(unique.into_iter().map(|k| (k, Some(vec![1]))), version)?;
        let result = ReplayDelta {
            head: ReplayHead {
                version,
                root: root.0,
            },
            nodes: batch.node_batch.nodes().clone(),
        };
        result.encode()?;
        Ok(result)
    }
}
impl TreeReader for ReplayReader<'_> {
    fn get_node_option(&self, key: &NodeKey) -> Result<Option<Node>> {
        for delta in self.deltas {
            if let Some(node) = delta.nodes.get(key) {
                return Ok(Some(node.clone()));
            }
        }
        if self.base.is_none_or(|head| key.version() > head.version) {
            return Ok(None);
        }
        let raw:Option<Option<Vec<u8>>>=self.transaction.query_row("SELECT CASE WHEN length(node)<=4096 THEN node ELSE NULL END FROM native_incremental_replay_node_v1 WHERE node_key=?1",[borsh::to_vec(key)?],|r|r.get(0)).optional()?;
        raw.map(|bytes| {
            let bytes = bytes.context("replay stored node capacity")?;
            let node = borsh::from_slice(&bytes)?;
            audit_jmt_node_record_v1(key, &node)?;
            ensure!(borsh::to_vec(&node)? == bytes, "replay stored node codec");
            Ok(node)
        })
        .transpose()
    }
    fn get_value_option(&self, max_version: u64, _key: KeyHash) -> Result<Option<Vec<u8>>> {
        ensure!(
            self.head.is_none_or(|head| max_version <= head.version),
            "future replay value read"
        );
        // JMT calls this only after authenticating the matching leaf. All leaves
        // in this append-only local membership tree have exactly this value.
        Ok(Some(vec![1]))
    }
    fn get_rightmost_leaf(&self) -> Result<Option<(NodeKey, LeafNode)>> {
        anyhow::bail!("replay restore API unavailable")
    }
}
pub(super) fn apply(transaction: &Transaction<'_>, delta: &ReplayDelta) -> Result<()> {
    for (key, node) in &delta.nodes {
        transaction.execute(
            "INSERT INTO native_incremental_replay_node_v1 VALUES(?1,?2)",
            params![borsh::to_vec(key)?, borsh::to_vec(node)?],
        )?;
    }
    let view = ReplayReader::new(transaction, Some(delta.head), &[])?;
    ensure!(view.head == Some(delta.head), "replay delta apply mismatch");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    #[test]
    fn replay_tree_proves_prepared_and_committed_membership_without_sql_identity_index() {
        let mut connection = Connection::open_in_memory().unwrap();
        let tx = connection.transaction().unwrap();
        tx.execute_batch(SCHEMA).unwrap();
        let first = command_key("source-command").unwrap();
        let second = nonce_key("signer", 4).unwrap();
        let initial = ReplayReader::new(&tx, None, &[])
            .unwrap()
            .append([first])
            .unwrap();
        apply(&tx, &initial).unwrap();
        let base = ReplayReader::new(&tx, Some(initial.head), &[]).unwrap();
        assert!(base.contains(first).unwrap());
        assert!(!base.contains(second).unwrap());
        assert!(base.append([first]).is_err());
        let next = base.append([second]).unwrap();
        let suffix = [next.clone()];
        let prepared = ReplayReader::new(&tx, Some(initial.head), &suffix).unwrap();
        assert!(prepared.contains(first).unwrap());
        assert!(prepared.contains(second).unwrap());
        assert!(prepared.append([second]).is_err());
        assert!(!ReplayReader::new(&tx, Some(initial.head), &[])
            .unwrap()
            .contains(second)
            .unwrap());
        let encoded = next.encode().unwrap();
        assert_eq!(
            ReplayDelta::decode(&encoded).unwrap().encode().unwrap(),
            encoded
        );
        for length in 0..encoded.len() {
            assert!(ReplayDelta::decode(&encoded[..length]).is_err());
        }
        let mut trailing = encoded;
        trailing.push(0);
        assert!(ReplayDelta::decode(&trailing).is_err());
        apply(&tx, &next).unwrap();
        let committed = ReplayReader::new(&tx, Some(next.head), &[]).unwrap();
        committed.verify_exact_cardinality(2).unwrap();
        assert!(committed.verify_exact_cardinality(1).is_err());
        let empty = committed.append([]).unwrap();
        assert_eq!(empty.head.root, next.head.root);
        assert_eq!(empty.head.version, next.head.version + 1);
        apply(&tx, &empty).unwrap();
        assert!(ReplayReader::new(&tx, Some(empty.head), &[])
            .unwrap()
            .contains(second)
            .unwrap());
    }

    #[test]
    fn missing_or_oversized_replay_node_is_failure_never_absence() {
        for oversized in [false, true] {
            let mut connection = Connection::open_in_memory().unwrap();
            let tx = connection.transaction().unwrap();
            tx.execute_batch(SCHEMA).unwrap();
            let keys = [KeyHash([1; 32]), KeyHash([2; 32])];
            let initial = ReplayReader::new(&tx, None, &[])
                .unwrap()
                .append(keys)
                .unwrap();
            apply(&tx, &initial).unwrap();
            let (key, node) = initial
                .nodes
                .iter()
                .find(|(key, node)| !key.nibble_path().is_empty() && matches!(node, Node::Leaf(_)))
                .unwrap();
            let Node::Leaf(leaf) = node else {
                unreachable!()
            };
            if oversized {
                tx.execute_batch("PRAGMA ignore_check_constraints=ON")
                    .unwrap();
                tx.execute("UPDATE native_incremental_replay_node_v1 SET node=zeroblob(4097) WHERE node_key=?1",[borsh::to_vec(key).unwrap()]).unwrap();
            } else {
                tx.execute(
                    "DELETE FROM native_incremental_replay_node_v1 WHERE node_key=?1",
                    [borsh::to_vec(key).unwrap()],
                )
                .unwrap();
            }
            let view = ReplayReader::new(&tx, Some(initial.head), &[]).unwrap();
            assert!(view.contains(leaf.key_hash()).is_err());
            assert!(view.verify_exact_cardinality(2).is_err());
        }
    }

    #[test]
    fn malformed_replay_internal_cached_count_and_wrong_parent_fail_before_use() {
        let mut connection = Connection::open_in_memory().unwrap();
        let tx = connection.transaction().unwrap();
        tx.execute_batch(SCHEMA).unwrap();
        let mut delta = ReplayReader::new(&tx, None, &[])
            .unwrap()
            .append([KeyHash([1; 32]), KeyHash([2; 32])])
            .unwrap();
        let root = NodeKey::new(0, std::iter::empty().collect());
        let mut bytes = borsh::to_vec(delta.nodes.get(&root).unwrap()).unwrap();
        let end = bytes.len();
        bytes[end - 8..].fill(0);
        delta.nodes.insert(root, borsh::from_slice(&bytes).unwrap());
        assert!(delta.encode().is_err());
        let empty = ReplayReader::new(&tx, None, &[])
            .unwrap()
            .append([])
            .unwrap();
        assert!(ReplayReader::new(
            &tx,
            Some(ReplayHead {
                version: 5,
                root: empty.head.root
            }),
            &[empty]
        )
        .is_err());
    }
}
