//! Structurally shared in-memory sparse state commitment, identical to `pon_wire::state_root`.
//! One leaf and at most one fork per key: no allocation of 256 nodes per account.
//! A checked batch is staged on immutable Arc nodes and published only in its entirety.
use crate::pon_wire::{hash, Hash};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

const MAX_KEYS: usize = 65_536;
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StateError {
    Limit,
    DuplicateKey,
    BeforeMismatch,
    KeyCollision,
}
#[derive(Debug, Clone)]
pub struct Change {
    pub key: Vec<u8>,
    pub before: Option<Vec<u8>>,
    pub after: Option<Vec<u8>>,
}
#[derive(Clone)]
enum Kind {
    Leaf {
        key: Vec<u8>,
        value: Vec<u8>,
    },
    Fork {
        left: Arc<Node>,
        right: Arc<Node>,
        left_hash: Hash,
        right_hash: Hash,
    },
}
#[derive(Clone)]
struct Node {
    path: Hash,
    depth: usize,
    digest: Hash,
    kind: Kind,
}
#[derive(Clone)]
pub struct StateTree {
    root: Option<Arc<Node>>,
    empty: Arc<[Hash; 257]>,
    count: usize,
}
fn bit(path: &Hash, depth: usize) -> bool {
    path[depth / 8] & (128 >> (depth % 8)) != 0
}
fn common(a: &Hash, b: &Hash) -> usize {
    for (i, (&x, &y)) in a.iter().zip(b).enumerate() {
        if x != y {
            return i * 8 + (x ^ y).leading_zeros() as usize;
        }
    }
    256
}
impl Default for StateTree {
    fn default() -> Self {
        let mut empty = [[0; 32]; 257];
        empty[256] = hash(b"state-empty", &[]);
        for d in (0..256).rev() {
            empty[d] = hash(b"state-node", &[&empty[d + 1], &empty[d + 1]]);
        }
        Self {
            root: None,
            empty: Arc::new(empty),
            count: 0,
        }
    }
}
impl StateTree {
    pub fn from_values(values: &BTreeMap<Vec<u8>, Vec<u8>>) -> Result<Self, StateError> {
        if values.len() > MAX_KEYS {
            return Err(StateError::Limit);
        }
        let mut tree = Self::default();
        for (key, value) in values {
            Self::bounds(key, Some(value))?;
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
    pub fn len(&self) -> usize {
        self.count
    }
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
    pub fn root(&self) -> Hash {
        self.root
            .as_ref()
            .map_or(self.empty[0], |n| self.lift(n, 0))
    }
    fn bounds(key: &[u8], value: Option<&Vec<u8>>) -> Result<(), StateError> {
        if key.len() > 160 || value.is_some_and(|v| v.len() > 4096) {
            Err(StateError::Limit)
        } else {
            Ok(())
        }
    }
    fn lift(&self, node: &Node, depth: usize) -> Hash {
        let mut value = node.digest;
        for d in (depth..node.depth).rev() {
            value = if bit(&node.path, d) {
                hash(b"state-node", &[&self.empty[d + 1], &value])
            } else {
                hash(b"state-node", &[&value, &self.empty[d + 1]])
            };
        }
        value
    }
    fn fork(&self, depth: usize, left: Arc<Node>, right: Arc<Node>) -> Arc<Node> {
        let left_hash = self.lift(&left, depth + 1);
        let right_hash = self.lift(&right, depth + 1);
        Arc::new(Node {
            path: left.path,
            depth,
            digest: hash(b"state-node", &[&left_hash, &right_hash]),
            kind: Kind::Fork {
                left,
                right,
                left_hash,
                right_hash,
            },
        })
    }
    fn insert(
        &self,
        existing: Option<&Arc<Node>>,
        leaf: Arc<Node>,
    ) -> Result<Arc<Node>, StateError> {
        let Some(node) = existing else {
            return Ok(leaf);
        };
        let depth = common(&node.path, &leaf.path);
        if depth < node.depth {
            return Ok(if bit(&leaf.path, depth) {
                self.fork(depth, node.clone(), leaf)
            } else {
                self.fork(depth, leaf, node.clone())
            });
        }
        match &node.kind {
            Kind::Leaf { key, .. } => {
                let Kind::Leaf { key: new_key, .. } = &leaf.kind else {
                    unreachable!()
                };
                if key != new_key {
                    Err(StateError::KeyCollision)
                } else {
                    Ok(leaf)
                }
            }
            Kind::Fork {
                left,
                right,
                left_hash,
                right_hash,
            } => {
                let (left, right, lh, rh) = if bit(&leaf.path, node.depth) {
                    let new = self.insert(Some(right), leaf)?;
                    let digest = self.lift(&new, node.depth + 1);
                    (left.clone(), new, *left_hash, digest)
                } else {
                    let new = self.insert(Some(left), leaf)?;
                    let digest = self.lift(&new, node.depth + 1);
                    (new, right.clone(), digest, *right_hash)
                };
                Ok(Arc::new(Node {
                    path: left.path,
                    depth: node.depth,
                    digest: hash(b"state-node", &[&lh, &rh]),
                    kind: Kind::Fork {
                        left,
                        right,
                        left_hash: lh,
                        right_hash: rh,
                    },
                }))
            }
        }
    }
    fn remove(&self, node: &Arc<Node>, path: &Hash) -> Option<Arc<Node>> {
        if common(&node.path, path) < node.depth {
            return Some(node.clone());
        }
        match &node.kind {
            Kind::Leaf { .. } => None,
            Kind::Fork {
                left,
                right,
                left_hash,
                right_hash,
            } => {
                if bit(path, node.depth) {
                    let Some(new) = self.remove(right, path) else {
                        return Some(left.clone());
                    };
                    let rh = self.lift(&new, node.depth + 1);
                    Some(Arc::new(Node {
                        path: left.path,
                        depth: node.depth,
                        digest: hash(b"state-node", &[left_hash, &rh]),
                        kind: Kind::Fork {
                            left: left.clone(),
                            right: new,
                            left_hash: *left_hash,
                            right_hash: rh,
                        },
                    }))
                } else {
                    let Some(new) = self.remove(left, path) else {
                        return Some(right.clone());
                    };
                    let lh = self.lift(&new, node.depth + 1);
                    Some(Arc::new(Node {
                        path: new.path,
                        depth: node.depth,
                        digest: hash(b"state-node", &[&lh, right_hash]),
                        kind: Kind::Fork {
                            left: new,
                            right: right.clone(),
                            left_hash: lh,
                            right_hash: *right_hash,
                        },
                    }))
                }
            }
        }
    }
    pub fn get(&self, key: &[u8]) -> Result<Option<&[u8]>, StateError> {
        let path = hash(b"state-key", &[key]);
        let mut node = self.root.as_deref();
        while let Some(n) = node {
            if common(&n.path, &path) < n.depth {
                return Ok(None);
            }
            match &n.kind {
                Kind::Leaf { key: k, value } => {
                    return if k == key {
                        Ok(Some(value))
                    } else {
                        Err(StateError::KeyCollision)
                    }
                }
                Kind::Fork { left, right, .. } => {
                    node = Some(if bit(&path, n.depth) { right } else { left })
                }
            }
        }
        Ok(None)
    }
    /// `before` is tested against the same immutable predecessor for every distinct key.
    /// A late invalid change, capacity violation or collision leaves `self` untouched.
    pub fn apply(&self, expected: Hash, changes: &[Change]) -> Result<Self, StateError> {
        if self.root() != expected {
            return Err(StateError::BeforeMismatch);
        }
        if changes.len() > MAX_KEYS {
            return Err(StateError::Limit);
        }
        let mut seen = BTreeSet::new();
        let mut count = self.count;
        for c in changes {
            Self::bounds(&c.key, c.before.as_ref())?;
            Self::bounds(&c.key, c.after.as_ref())?;
            if !seen.insert(&c.key) {
                return Err(StateError::DuplicateKey);
            }
            if self.get(&c.key)? != c.before.as_deref() {
                return Err(StateError::BeforeMismatch);
            }
            match (c.before.is_some(), c.after.is_some()) {
                (false, true) => count += 1,
                (true, false) => count -= 1,
                _ => (),
            }
        }
        if count > MAX_KEYS {
            return Err(StateError::Limit);
        }
        let mut next = self.clone();
        next.count = count;
        for c in changes {
            if c.before == c.after {
                continue;
            }
            let path = hash(b"state-key", &[&c.key]);
            if let Some(v) = &c.after {
                let leaf = Arc::new(Node {
                    path,
                    depth: 256,
                    digest: hash(b"state-leaf", &[&c.key, v]),
                    kind: Kind::Leaf {
                        key: c.key.clone(),
                        value: v.clone(),
                    },
                });
                next.root = Some(next.insert(next.root.as_ref(), leaf)?);
            } else if let Some(node) = &next.root {
                next.root = next.remove(node, &path)
            }
        }
        Ok(next)
    }
    /// Counts compressed nodes, not virtual empty padding hashes.
    pub fn allocated_nodes(&self) -> usize {
        fn count(node: &Node) -> usize {
            match &node.kind {
                Kind::Leaf { .. } => 1,
                Kind::Fork { left, right, .. } => 1 + count(left) + count(right),
            }
        }
        self.root.as_deref().map_or(0, count)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::pon_wire::state_root;
    fn values(n: usize) -> BTreeMap<Vec<u8>, Vec<u8>> {
        (0..n)
            .map(|i| (format!("key{i}").into_bytes(), i.to_le_bytes().to_vec()))
            .collect()
    }
    #[test]
    fn compressed_roots_equal_independent_full_builder() {
        for n in [0, 1, 2, 3, 31, 128, 257] {
            let values = values(n);
            let t = StateTree::from_values(&values).unwrap();
            assert_eq!(t.root(), state_root(&values).unwrap());
            assert_eq!(t.allocated_nodes(), n.saturating_mul(2).saturating_sub(1));
        }
    }
    #[test]
    fn updates_deletes_and_empty_values_preserve_frozen_snapshots() {
        let mut values = values(100);
        let initial = StateTree::from_values(&values).unwrap();
        let old = initial.root();
        let mut tree = initial.clone();
        for i in 0..80 {
            let key = format!("key{i}").into_bytes();
            let before = values.get(&key).cloned();
            let after = if i % 3 == 0 {
                None
            } else {
                Some(if i % 3 == 1 { vec![] } else { vec![42] })
            };
            tree = tree
                .apply(
                    tree.root(),
                    &[Change {
                        key: key.clone(),
                        before,
                        after: after.clone(),
                    }],
                )
                .unwrap();
            if let Some(v) = after {
                values.insert(key, v);
            } else {
                values.remove(&key);
            }
            assert_eq!(tree.root(), state_root(&values).unwrap());
            assert_eq!(initial.root(), old);
        }
    }
    #[test]
    fn failing_last_change_leaves_predecessor_and_content_unchanged() {
        let t = StateTree::from_values(&values(2)).unwrap();
        let old = t.root();
        let bad = [
            Change {
                key: b"new".to_vec(),
                before: None,
                after: Some(vec![9]),
            },
            Change {
                key: b"key0".to_vec(),
                before: Some(vec![99]),
                after: None,
            },
        ];
        assert!(matches!(
            t.apply(old, &bad),
            Err(StateError::BeforeMismatch)
        ));
        assert_eq!(t.root(), old);
        assert_eq!(t.get(b"new").unwrap(), None);
    }
    #[test]
    fn wrong_root_duplicate_key_and_oversize_are_rejected() {
        let t = StateTree::default();
        let c = Change {
            key: b"x".to_vec(),
            before: None,
            after: Some(vec![]),
        };
        assert!(matches!(
            t.apply([9; 32], &[]),
            Err(StateError::BeforeMismatch)
        ));
        assert!(matches!(
            t.apply(t.root(), &[c.clone(), c]),
            Err(StateError::DuplicateKey)
        ));
        assert!(matches!(
            t.apply(
                t.root(),
                &[Change {
                    key: vec![0; 161],
                    before: None,
                    after: Some(vec![])
                }]
            ),
            Err(StateError::Limit)
        ));
        assert!(t.is_empty());
    }
    #[test]
    fn mixed_batches_match_full_builder_and_inverse_restores_predecessor() {
        let mut current = values(64);
        let mut tree = StateTree::from_values(&current).unwrap();
        let original = tree.clone();
        let original_values = current.clone();
        for round in 0..24usize {
            let before_tree = tree.clone();
            let before_values = current.clone();
            let mut changes = Vec::new();
            for index in 0..7usize {
                let key = format!("key{}", (round * 17 + index * 13) % 97).into_bytes();
                let before = current.get(&key).cloned();
                let after = if (round + index) % 3 == 0 {
                    None
                } else {
                    Some(vec![(round + index) as u8; index])
                };
                changes.push(Change { key, before, after });
            }
            tree = tree.apply(tree.root(), &changes).unwrap();
            for change in &changes {
                if let Some(value) = &change.after {
                    current.insert(change.key.clone(), value.clone());
                } else {
                    current.remove(&change.key);
                }
            }
            assert_eq!(tree.root(), state_root(&current).unwrap());
            assert_eq!(tree.len(), current.len());
            assert_eq!(tree.allocated_nodes(), current.len() * 2 - 1);
            let inverse: Vec<_> = changes
                .iter()
                .map(|c| Change {
                    key: c.key.clone(),
                    before: c.after.clone(),
                    after: c.before.clone(),
                })
                .collect();
            let restored = tree.apply(tree.root(), &inverse).unwrap();
            assert_eq!(restored.root(), before_tree.root());
            for (key, value) in &before_values {
                assert_eq!(restored.get(key).unwrap(), Some(value.as_slice()));
            }
        }
        assert_eq!(original.root(), state_root(&original_values).unwrap());
    }

    #[test]
    fn all_deletions_return_empty_and_values_remain_bounded() {
        let values = values(8);
        let original = StateTree::from_values(&values).unwrap();
        let changes: Vec<_> = values
            .iter()
            .map(|(key, value)| Change {
                key: key.clone(),
                before: Some(value.clone()),
                after: None,
            })
            .collect();
        let empty = original.apply(original.root(), &changes).unwrap();
        assert!(empty.is_empty());
        assert_eq!(empty.allocated_nodes(), 0);
        assert_eq!(empty.root(), StateTree::default().root());
        let oversize = Change {
            key: vec![],
            before: None,
            after: Some(vec![0; 4097]),
        };
        assert!(matches!(
            empty.apply(empty.root(), &[oversize]),
            Err(StateError::Limit)
        ));
        let too_many = vec![
            Change {
                key: vec![],
                before: None,
                after: None
            };
            MAX_KEYS + 1
        ];
        assert!(matches!(
            empty.apply(empty.root(), &too_many),
            Err(StateError::Limit)
        ));
        assert_eq!(original.root(), state_root(&values).unwrap());
    }
}
