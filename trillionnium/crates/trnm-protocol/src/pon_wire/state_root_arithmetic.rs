//! Bounded reuse of the original sparse-tree arithmetic from complete inputs.
//!
//! The only public calculation accepts actual key/value bytes. Every call hashes
//! every supplied row with the original key/leaf domains and checks all original
//! wire bounds and key-path collisions. No caller can install leaf hashes, a
//! root claim, a partial update, a row-set verdict or an authenticated capability.
//!
//! One retained entry groups the sorted original leaf hashes by a fixed prefix.
//! A partition root is reused only when its complete original hash tuple slice
//! is identical. This adds no digest assumption to the original tree: identical
//! original leaf hashes necessarily produce the same original subtree root.
//! Different value byte sizes therefore do not force repeated unary-path work.
use super::{hash, state_empty_hashes, state_node_hash, state_root_from_hashes};
use super::{Hash, StateRootInputError, WireError};

const PARTITION_DEPTH: usize = 12;

struct Partition {
    prefix: u16,
    start: usize,
    end: usize,
    root: Hash,
}

struct Material {
    leaves: Box<[(Hash, Hash)]>,
    partitions: Box<[Partition]>,
}

/// Arithmetic work from the last successful complete input, not a validation
/// verdict. Retained byte counts include both arrays at their allocated lengths.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StateRootArithmeticObservation {
    pub input_keys: usize,
    pub reused_partitions: usize,
    pub computed_partitions: usize,
    pub retained_payload_bytes: usize,
    pub retention_refused: bool,
}

/// One optional mathematical entry. Its byte limit controls retention only;
/// refusing material never changes accepted inputs or the original state root.
/// The opaque type cannot be restored from serialized roots or hash claims.
pub struct StateRootArithmetic {
    max_retained_payload_bytes: usize,
    material: Option<Material>,
    observation: StateRootArithmeticObservation,
}

impl StateRootArithmetic {
    pub fn new(max_retained_payload_bytes: usize) -> Self {
        Self {
            max_retained_payload_bytes,
            material: None,
            observation: StateRootArithmeticObservation::default(),
        }
    }

    pub fn observation(&self) -> StateRootArithmeticObservation {
        self.observation
    }

    pub fn retained_payload_bytes(&self) -> usize {
        self.material.as_ref().map_or(0, |material| {
            std::mem::size_of_val(material.leaves.as_ref())
                + std::mem::size_of_val(material.partitions.as_ref())
        })
    }

    /// Complete original wire input, including producer failures. On any input
    /// error, no partially computed entry replaces the last complete material.
    /// Callers whose grammar errors precede wire limits must perform that full
    /// grammar pass first, exactly as for `state_root_from_entries`.
    pub fn root_from_entries<K, V, E>(
        &mut self,
        entries: impl IntoIterator<Item = Result<(K, V), E>>,
    ) -> Result<Hash, StateRootInputError<E>>
    where
        K: AsRef<[u8]>,
        V: AsRef<[u8]>,
    {
        let mut leaves = Vec::new();
        for row in entries {
            let (key, value) = row.map_err(StateRootInputError::Input)?;
            let (key, value) = (key.as_ref(), value.as_ref());
            if leaves.len() == 65_536 || key.len() > 160 || value.len() > 4096 {
                return Err(StateRootInputError::Wire(WireError::Limit));
            }
            leaves.push((
                hash(b"state-key", &[key]),
                hash(b"state-leaf", &[key, value]),
            ));
        }
        self.root_from_hashes(leaves)
            .map_err(StateRootInputError::Wire)
    }

    // Private: raw hashes can never enter through an external/root-claim API.
    fn root_from_hashes(&mut self, mut leaves: Vec<(Hash, Hash)>) -> Result<Hash, WireError> {
        leaves.sort_unstable_by_key(|row| row.0);
        if leaves.windows(2).any(|pair| pair[0].0 == pair[1].0) {
            return Err(WireError::KeyCollision);
        }
        let count = usize::from(!leaves.is_empty())
            + leaves
                .windows(2)
                .filter(|pair| prefix(&pair[0].0) != prefix(&pair[1].0))
                .count();
        // The input hash vector has the same bounded transient size as the
        // original root. At most 4096 partition records can be retained. Boxed
        // slices prevent unused Vec capacity from escaping the retention charge.
        let retained = leaves.len() * std::mem::size_of::<(Hash, Hash)>()
            + count * std::mem::size_of::<Partition>();
        if retained > self.max_retained_payload_bytes {
            self.material = None;
            self.observation = StateRootArithmeticObservation {
                input_keys: leaves.len(),
                retention_refused: true,
                ..StateRootArithmeticObservation::default()
            };
            return state_root_from_hashes(leaves);
        }

        let empty = state_empty_hashes();
        let mut partitions = Vec::with_capacity(count);
        let mut reused = 0;
        let mut start = 0;
        while start < leaves.len() {
            let id = prefix(&leaves[start].0);
            let end = start + leaves[start..].partition_point(|row| prefix(&row.0) == id);
            let prior = self.material.as_ref().and_then(|material| {
                let index = material
                    .partitions
                    .binary_search_by_key(&id, |partition| partition.prefix)
                    .ok()?;
                let partition = &material.partitions[index];
                (material.leaves[partition.start..partition.end] == leaves[start..end])
                    .then_some(partition.root)
            });
            let root = match prior {
                Some(root) => {
                    reused += 1;
                    root
                }
                None => subtree(&leaves[start..end], PARTITION_DEPTH, empty),
            };
            partitions.push(Partition {
                prefix: id,
                start,
                end,
                root,
            });
            start = end;
        }
        let root = partition_root(&partitions, 0, empty);
        self.observation = StateRootArithmeticObservation {
            input_keys: leaves.len(),
            reused_partitions: reused,
            computed_partitions: count - reused,
            retained_payload_bytes: retained,
            retention_refused: false,
        };
        self.material = Some(Material {
            leaves: leaves.into_boxed_slice(),
            partitions: partitions.into_boxed_slice(),
        });
        Ok(root)
    }
}

fn prefix(path: &Hash) -> u16 {
    u16::from_be_bytes([path[0], path[1]]) >> (16 - PARTITION_DEPTH)
}

fn subtree(leaves: &[(Hash, Hash)], depth: usize, empty: &[Hash; 257]) -> Hash {
    if leaves.is_empty() {
        return empty[depth];
    }
    if depth == 256 {
        return leaves[0].1;
    }
    let split = leaves.partition_point(|row| row.0[depth / 8] & (128 >> (depth % 8)) == 0);
    state_node_hash(
        &subtree(&leaves[..split], depth + 1, empty),
        &subtree(&leaves[split..], depth + 1, empty),
    )
}

fn partition_root(partitions: &[Partition], depth: usize, empty: &[Hash; 257]) -> Hash {
    if partitions.is_empty() {
        return empty[depth];
    }
    if depth == PARTITION_DEPTH {
        return partitions[0].root;
    }
    let mask = 1 << (PARTITION_DEPTH - depth - 1);
    let split = partitions.partition_point(|partition| partition.prefix & mask == 0);
    state_node_hash(
        &partition_root(&partitions[..split], depth + 1, empty),
        &partition_root(&partitions[split..], depth + 1, empty),
    )
}

#[cfg(test)]
mod tests;
