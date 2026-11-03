//! Bounded reuse of the original sparse-tree arithmetic from complete inputs.
//!
//! Public calculations accept only actual key/value bytes. Every row keeps the
//! original wire bounds and key-path collision checks. Optional string entries
//! reuse original key/leaf hashes only after exact full key and value equality;
//! they cannot supply a root claim, partial update or authenticated capability.
//!
//! One retained entry groups the sorted original leaf hashes by a fixed prefix.
//! A partition root is reused only when its complete original hash tuple slice
//! is identical. The original tree arrays take priority in the same byte pool;
//! any remainder can retain a bounded subset of unescaped ASCII JSON strings.
use super::{hash, state_empty_hashes, state_node_hash, state_root_from_hashes};
use super::{Hash, StateRootInputError, WireError};

const PARTITION_DEPTH: usize = 12;
const STRING_SET_CHARGE: usize = std::mem::size_of::<Box<[ExactString]>>();

struct Partition {
    prefix: u16,
    start: usize,
    end: usize,
    root: Hash,
}

// Constructed only from bounded actual wire bytes and their original hashes.
// The canonical value includes both quotes; its body has no JSON escapes.
struct ExactString {
    key: Box<[u8]>,
    value: Box<[u8]>,
    hashes: (Hash, Hash),
}

impl ExactString {
    fn charge(&self) -> usize {
        std::mem::size_of::<Self>() + self.key.len() + self.value.len()
    }
}

struct Material {
    leaves: Box<[(Hash, Hash)]>,
    partitions: Box<[Partition]>,
    strings: Box<[ExactString]>,
}

impl Material {
    fn string_index(&self, key: &[u8]) -> Option<usize> {
        // Large sorted States commonly exceed the retained string prefix. Do
        // not binary-search that prefix for every remaining unretained key.
        if key < self.strings.first()?.key.as_ref() || key > self.strings.last()?.key.as_ref() {
            return None;
        }
        self.strings
            .binary_search_by(|entry| entry.key.as_ref().cmp(key))
            .ok()
    }

    fn string_charge(&self) -> usize {
        if self.strings.is_empty() {
            0
        } else {
            STRING_SET_CHARGE + self.strings.iter().map(ExactString::charge).sum::<usize>()
        }
    }

    fn retained_payload_bytes(&self) -> usize {
        std::mem::size_of_val(self.leaves.as_ref())
            + std::mem::size_of_val(self.partitions.as_ref())
            + self.string_charge()
    }
}

/// Arithmetic work from the last successful complete input, not a validation
/// verdict. Boxed lengths charge all retained allocations, entry descriptors
/// and the additional string-array handle; no spare Vec capacity is retained.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StateRootArithmeticObservation {
    pub input_keys: usize,
    pub leaf_hashes_computed: usize,
    pub exact_string_hits: usize,
    pub string_encodings_reused: usize,
    pub reused_partitions: usize,
    pub computed_partitions: usize,
    pub retained_payload_bytes: usize,
    pub retained_string_entries: usize,
    pub retained_string_charge_bytes: usize,
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

/// An operation-local complete input. Only actual bytes can add a leaf; no
/// caller can install a prehash or root. Dropping an unfinished or failed input
/// preserves the preceding complete material. Grammar checks that precede wire
/// limits remain the caller's responsibility, as for `root_from_entries`.
///
/// ```compile_fail
/// use trnm_protocol::pon_wire::StateRootArithmetic;
/// let mut arithmetic = StateRootArithmetic::new(1024);
/// let mut input = arithmetic.input_builder();
/// input.leaves.push(([0u8; 32], [0u8; 32]));
/// ```
pub struct StateRootInputBuilder<'a> {
    arithmetic: &'a mut StateRootArithmetic,
    leaves: Vec<(Hash, Hash)>,
    prior_strings_used: Vec<bool>,
    pending_strings: Vec<ExactString>,
    pending_budget: usize,
    observation: StateRootArithmeticObservation,
    failed: Option<WireError>,
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
        self.material
            .as_ref()
            .map_or(0, Material::retained_payload_bytes)
    }

    pub fn input_builder(&mut self) -> StateRootInputBuilder<'_> {
        let prior_strings = self.material.as_ref().map_or(0, |m| m.strings.len());
        // Pending entries use only unused space in the existing pool. A changed
        // cached row gets no replacement credit while its old bytes still live.
        // On success, unused old strings are dropped; a later call can refill.
        let pending_budget = self
            .max_retained_payload_bytes
            .saturating_sub(self.retained_payload_bytes())
            .saturating_sub(STRING_SET_CHARGE);
        StateRootInputBuilder {
            arithmetic: self,
            leaves: Vec::new(),
            prior_strings_used: vec![false; prior_strings],
            pending_strings: Vec::new(),
            pending_budget,
            observation: StateRootArithmeticObservation::default(),
            failed: None,
        }
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
        let mut input = self.input_builder();
        for row in entries {
            let (key, value) = row.map_err(StateRootInputError::Input)?;
            input
                .add_encoded(key.as_ref(), value.as_ref())
                .map_err(StateRootInputError::Wire)?;
        }
        input.finish().map_err(StateRootInputError::Wire)
    }

    // Private test seam: raw hashes cannot enter through any public input API.
    #[cfg(test)]
    fn root_from_hashes(&mut self, leaves: Vec<(Hash, Hash)>) -> Result<Hash, WireError> {
        let observation = StateRootArithmeticObservation {
            input_keys: leaves.len(),
            leaf_hashes_computed: leaves.len(),
            ..StateRootArithmeticObservation::default()
        };
        self.finish_inputs(leaves, Vec::new(), Vec::new(), observation)
    }

    fn finish_inputs(
        &mut self,
        mut leaves: Vec<(Hash, Hash)>,
        prior_strings_used: Vec<bool>,
        pending_strings: Vec<ExactString>,
        mut observation: StateRootArithmeticObservation,
    ) -> Result<Hash, WireError> {
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
        let tree_charge = leaves.len() * std::mem::size_of::<(Hash, Hash)>()
            + count * std::mem::size_of::<Partition>();
        if tree_charge > self.max_retained_payload_bytes {
            self.material = None;
            observation.retention_refused = true;
            self.observation = observation;
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
        // Publish tree material first. Reuse ownership of current exact matches
        // rather than cloning their payload on each warm complete calculation.
        let prior_strings = self
            .material
            .take()
            .map_or_else(Vec::new, |material| material.strings.into_vec());
        let mut remaining = self.max_retained_payload_bytes - tree_charge;
        let mut strings = Vec::new();
        for entry in prior_strings
            .into_iter()
            .zip(prior_strings_used)
            .filter_map(|(entry, used)| used.then_some(entry))
            .chain(pending_strings)
        {
            let charge = entry.charge() + usize::from(strings.is_empty()) * STRING_SET_CHARGE;
            if charge <= remaining {
                remaining -= charge;
                strings.push(entry);
            }
        }
        strings.sort_unstable_by(|a, b| a.key.cmp(&b.key));
        let material = Material {
            leaves: leaves.into_boxed_slice(),
            partitions: partitions.into_boxed_slice(),
            strings: strings.into_boxed_slice(),
        };
        observation.reused_partitions = reused;
        observation.computed_partitions = count - reused;
        observation.retained_payload_bytes = material.retained_payload_bytes();
        observation.retained_string_entries = material.strings.len();
        observation.retained_string_charge_bytes = material.string_charge();
        self.observation = observation;
        self.material = Some(material);
        Ok(root)
    }
}

impl StateRootInputBuilder<'_> {
    fn bounds(&mut self, key: &[u8], value_len: usize) -> Result<(), WireError> {
        if let Some(error) = self.failed {
            return Err(error);
        }
        if self.leaves.len() == 65_536 || key.len() > 160 || value_len > 4096 {
            self.failed = Some(WireError::Limit);
            return Err(WireError::Limit);
        }
        Ok(())
    }

    fn prior_string(&self, key: &[u8]) -> Option<(usize, &ExactString)> {
        let material = self.arithmetic.material.as_ref()?;
        let index = material.string_index(key)?;
        Some((index, &material.strings[index]))
    }

    fn add_exact(&mut self, index: usize, hashes: (Hash, Hash), reused_encoding: bool) {
        self.leaves.push(hashes);
        self.prior_strings_used[index] = true;
        self.observation.input_keys += 1;
        self.observation.exact_string_hits += 1;
        self.observation.string_encodings_reused += usize::from(reused_encoding);
    }

    /// Try a complete current raw JSON string. A hit proves byte-for-byte
    /// equality with a previously encoded unescaped ASCII string under this
    /// exact key, then adds that row. A miss adds nothing: the caller must use
    /// its original canonical encoder and `add_encoded`, with its original
    /// grammar/error order. No caller-supplied eligibility flag is trusted.
    pub fn try_plain_json_string(&mut self, key: &[u8], value: &str) -> Result<bool, WireError> {
        if let Some(error) = self.failed {
            return Err(error);
        }
        let hit = self.prior_string(key).and_then(|(index, prior)| {
            (&prior.value[1..prior.value.len() - 1] == value.as_bytes()).then_some((
                index,
                prior.hashes,
                prior.value.len(),
            ))
        });
        let Some((index, hashes, encoded_len)) = hit else {
            return Ok(false);
        };
        self.bounds(key, encoded_len)?;
        self.add_exact(index, hashes, true);
        Ok(true)
    }

    /// Add complete canonical/wire bytes. The original wire bounds precede
    /// hashing; exact strings can avoid hashing only after full byte equality.
    /// Other values use the original domains even when their lengths coincide.
    pub fn add_encoded(&mut self, key: &[u8], value: &[u8]) -> Result<(), WireError> {
        self.bounds(key, value.len())?;
        let hit = self.prior_string(key).and_then(|(index, prior)| {
            (prior.value.as_ref() == value).then_some((index, prior.hashes))
        });
        if let Some((index, hashes)) = hit {
            self.add_exact(index, hashes, false);
            return Ok(());
        }
        let hashes = (
            hash(b"state-key", &[key]),
            hash(b"state-leaf", &[key, value]),
        );
        self.leaves.push(hashes);
        self.observation.input_keys += 1;
        self.observation.leaf_hashes_computed += 1;
        let charge = std::mem::size_of::<ExactString>() + key.len() + value.len();
        // Check the budget before scanning/copying a candidate. In particular,
        // an already full warm entry does not rescan every large uncached row.
        if charge <= self.pending_budget && plain_json_string(value) {
            self.pending_budget -= charge;
            self.pending_strings.push(ExactString {
                key: key.into(),
                value: value.into(),
                hashes,
            });
        }
        Ok(())
    }

    pub fn finish(self) -> Result<Hash, WireError> {
        if let Some(error) = self.failed {
            return Err(error);
        }
        self.arithmetic.finish_inputs(
            self.leaves,
            self.prior_strings_used,
            self.pending_strings,
            self.observation,
        )
    }
}

fn plain_json_string(value: &[u8]) -> bool {
    value.len() >= 2
        && value[0] == b'"'
        && value[value.len() - 1] == b'"'
        && value[1..value.len() - 1]
            .iter()
            .all(|&byte| (0x20..=0x7f).contains(&byte) && byte != b'"' && byte != b'\\')
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
