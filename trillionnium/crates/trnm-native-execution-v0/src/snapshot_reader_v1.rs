//! Record-bounded reader for the unchanged Borsh authenticated-tree snapshot.
//! No whole serialized snapshot is retained. The five decoded JMT collections
//! are still retained and the existing full root/live-value audit still runs.

use std::io::{self, Read, Write};

use super::*;

#[derive(Clone, Copy, Debug)]
pub(crate) struct SnapshotReadLimitsV1 {
    pub maximum_entries: u32,
    pub maximum_record_bytes: usize,
}

#[derive(Debug)]
pub(crate) struct SnapshotReadLimitV1;

impl std::fmt::Display for SnapshotReadLimitV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("native snapshot local read budget exhausted")
    }
}
impl std::error::Error for SnapshotReadLimitV1 {}

fn limit_error() -> io::Error {
    io::Error::other(SnapshotReadLimitV1)
}

/// Limits *retained encoded bytes* for one entry. Variable application values
/// additionally check their declared length before allocating. JMT's own bounded
/// node codec remains the dependency boundary, not a replacement implementation.
struct RecordReader<'a, R> {
    input: &'a mut R,
    bytes: Vec<u8>,
    maximum: usize,
}

impl<R: Read> Read for RecordReader<'_, R> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        let remaining = self.maximum.saturating_sub(self.bytes.len());
        if remaining == 0 {
            return Err(limit_error());
        }
        let count = output.len().min(remaining);
        self.bytes.try_reserve(count).map_err(|_| limit_error())?;
        let read = self.input.read(&mut output[..count])?;
        self.bytes.extend_from_slice(&output[..read]);
        Ok(read)
    }
}

struct CompareWriter<'a> {
    expected: &'a [u8],
    offset: usize,
}
impl Write for CompareWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let end = self
            .offset
            .checked_add(bytes.len())
            .ok_or_else(limit_error)?;
        if self.expected.get(self.offset..end) != Some(bytes) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "noncanonical snapshot entry",
            ));
        }
        self.offset = end;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn record<R: Read, T: BorshSerialize>(
    input: &mut R,
    maximum: usize,
    decode: impl FnOnce(&mut RecordReader<'_, R>) -> io::Result<T>,
) -> io::Result<T> {
    let mut reader = RecordReader {
        input,
        bytes: Vec::new(),
        maximum,
    };
    let value = decode(&mut reader)?;
    let mut compare = CompareWriter {
        expected: &reader.bytes,
        offset: 0,
    };
    BorshSerialize::serialize(&value, &mut compare)?;
    if compare.offset != reader.bytes.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "noncanonical snapshot entry length",
        ));
    }
    Ok(value)
}

// JMT 0.12.0 serializes NodeKey as u64 version, u64 nibble count,
// u32 byte count and at most 32 packed bytes. Validate the length relation
// before invoking its derived decoder (which bypasses NibblePath constructors).
fn node_key<R: Read>(reader: &mut R) -> io::Result<NodeKey> {
    let mut encoded = [0_u8; 52];
    reader.read_exact(&mut encoded[..20])?;
    let nibbles = u64::from_le_bytes(encoded[8..16].try_into().expect("fixed length"));
    let length = u32::from_le_bytes(encoded[16..20].try_into().expect("fixed length")) as usize;
    if nibbles > 64 || length != (nibbles as usize).div_ceil(2) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid JMT nibble dimensions",
        ));
    }
    reader.read_exact(&mut encoded[20..20 + length])?;
    if nibbles % 2 == 1 && encoded[19 + length] & 15 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "nonzero JMT nibble padding",
        ));
    }
    NodeKey::try_from_slice(&encoded[..20 + length])
}

struct FixedWriter<const N: usize> {
    bytes: [u8; N],
    used: usize,
}
impl<const N: usize> Write for FixedWriter<N> {
    fn write(&mut self, value: &[u8]) -> io::Result<usize> {
        let end = self.used.checked_add(value.len()).ok_or_else(limit_error)?;
        if end > N {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "oversized JMT structural record",
            ));
        }
        self.bytes[self.used..end].copy_from_slice(value);
        self.used = end;
        Ok(value.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn validate_key_shape(key: &NodeKey) -> Result<()> {
    let mut encoded = FixedWriter::<52> {
        bytes: [0; 52],
        used: 0,
    };
    BorshSerialize::serialize(key, &mut encoded)?;
    let mut bytes = &encoded.bytes[..encoded.used];
    let restored = node_key(&mut bytes)?;
    ensure!(
        bytes.is_empty() && restored == *key,
        "noncanonical JMT node key"
    );
    Ok(())
}

/// Reject constructor-invariant violations before JMT lookup/iteration can
/// observe unchecked Borsh node caches. These checks do not authenticate old
/// roots against finality, nor establish pruning or replay-floor authority.
pub(super) fn validate_native_node_shapes_v1(store: &InMemoryNativeExecutionStoreV0) -> Result<()> {
    for (key, node) in &store.nodes {
        validate_key_shape(key)?;
        let depth = key.nibble_path().num_nibbles();
        match node {
            Node::Null => ensure!(depth == 0, "null JMT node outside root"),
            Node::Leaf(leaf) => {
                let hash = leaf.key_hash().0;
                for index in 0..depth {
                    let expected = (hash[index / 2] >> if index % 2 == 0 { 4 } else { 0 }) & 15;
                    ensure!(
                        u8::from(key.nibble_path().get_nibble(index)) == expected,
                        "JMT leaf does not match its key path"
                    );
                }
            }
            Node::Internal(internal) => {
                ensure!(depth < 64, "internal JMT node at terminal depth");
                let mut count = 0_u64;
                let mut leaves = 0_usize;
                let mut only_leaf = false;
                for (_, child) in internal.children_sorted() {
                    ensure!(
                        child.version <= key.version(),
                        "JMT child version exceeds parent"
                    );
                    let child_leaves = child.leaf_count();
                    ensure!(
                        child_leaves > 0 && (child.is_leaf() || child_leaves >= 2),
                        "invalid JMT child leaf count"
                    );
                    leaves = leaves
                        .checked_add(child_leaves)
                        .context("JMT leaf count overflow")?;
                    count += 1;
                    only_leaf = child.is_leaf();
                }
                ensure!(
                    count > 0 && !(count == 1 && only_leaf),
                    "invalid JMT internal children"
                );
                ensure!(
                    leaves == internal.leaf_count(),
                    "inconsistent JMT cached leaf count"
                );
                // The final two u64 fields of this pinned Borsh Node variant
                // are Children.num_children and InternalNode.leaf_count.
                let mut encoded = FixedWriter::<1024> {
                    bytes: [0; 1024],
                    used: 0,
                };
                BorshSerialize::serialize(node, &mut encoded)?;
                ensure!(encoded.used >= 16, "short JMT internal record");
                let offset = encoded.used - 16;
                let cached = u64::from_le_bytes(
                    encoded.bytes[offset..offset + 8]
                        .try_into()
                        .expect("fixed length"),
                );
                ensure!(cached == count, "inconsistent JMT cached child count");
            }
        }
    }
    // All node/key constructor invariants have now been checked, so traversing
    // exact child coordinates and hashing their bounded node shapes is safe.
    // Cached counts, types and versions are not independently authenticated by
    // a parent's hash: bind them to the actual retained child, not to each other.
    for (key, node) in &store.nodes {
        match node {
            Node::Internal(internal) => {
                for (nibble, child) in internal.children_sorted() {
                    let path = key
                        .nibble_path()
                        .nibbles()
                        .chain(std::iter::once(nibble))
                        .collect();
                    let child_key = NodeKey::new(child.version, path);
                    let actual = store
                        .nodes
                        .get(&child_key)
                        .context("missing retained JMT child")?;
                    let (hash, leaf_count, is_leaf) = match actual {
                        Node::Null => anyhow::bail!("internal JMT child cannot be null"),
                        Node::Leaf(leaf) => (leaf.hash::<Sha256>(), 1, true),
                        Node::Internal(node) => (node.hash::<Sha256>(), node.leaf_count(), false),
                    };
                    ensure!(
                        hash == child.hash
                            && leaf_count == child.leaf_count()
                            && is_leaf == child.is_leaf(),
                        "retained JMT child metadata or hash mismatch"
                    );
                }
            }
            Node::Leaf(leaf) => {
                let hash = leaf.key_hash();
                let value = store
                    .values
                    .range((hash, 0)..=(hash, key.version()))
                    .next_back()
                    .and_then(|(_, value)| value.as_deref())
                    .context("retained JMT leaf has no value at its own version")?;
                let reconstructed = LeafNode::new(hash, jmt::ValueHash::with::<Sha256>(value));
                ensure!(
                    &reconstructed == leaf,
                    "retained JMT historical leaf/value mismatch"
                );
            }
            Node::Null => {}
        }
    }
    for index in &store.stale_nodes {
        validate_key_shape(&index.node_key)?;
        ensure!(
            index.node_key.version() < index.stale_since_version,
            "JMT stale node version is not older than its stale marker"
        );
    }
    Ok(())
}

fn bounded_bytes<R: Read>(reader: &mut RecordReader<'_, R>) -> io::Result<Vec<u8>> {
    let count = u32::deserialize_reader(reader)? as usize;
    if count > reader.maximum.saturating_sub(reader.bytes.len()) {
        return Err(limit_error());
    }
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(count).map_err(|_| limit_error())?;
    bytes.resize(count, 0);
    reader.read_exact(&mut bytes)?;
    Ok(bytes)
}

fn count<R: Read>(reader: &mut R, remaining: &mut u32) -> io::Result<u32> {
    let count = u32::deserialize_reader(reader)?;
    *remaining = remaining.checked_sub(count).ok_or_else(limit_error)?;
    Ok(count)
}

fn insert_sorted<K: Ord, V>(map: &mut BTreeMap<K, V>, key: K, value: V) -> io::Result<()> {
    if map.last_key_value().is_some_and(|(prior, _)| prior >= &key) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unordered or duplicate snapshot key",
        ));
    }
    map.insert(key, value);
    Ok(())
}

impl InMemoryNativeExecutionStoreV0 {
    /// Reads the existing codec in field order, rejects noncanonical maps before
    /// insertion and runs the same JMT validation as the original slice decoder.
    /// Replay sets are deliberately empty: this private result is used only by
    /// the read verifier, never by an execution/signing owner or install API.
    pub(crate) fn decode_authenticated_snapshot_reader_v1(
        chain_id: &str,
        signers: Vec<AuthorizedSignerV0>,
        parameters: ConsensusParametersV0,
        input: &mut impl Read,
        limits: SnapshotReadLimitsV1,
    ) -> Result<Self> {
        ensure!(
            limits.maximum_entries > 0 && limits.maximum_record_bytes > 0,
            "invalid native reader limits"
        );
        let codec = u16::deserialize_reader(input)?;
        ensure!(
            codec == NATIVE_AUTH_TREE_SNAPSHOT_CODEC_VERSION_V0,
            "unsupported native authenticated snapshot codec"
        );
        let mut store = Self::new(chain_id, signers, parameters)?;
        let mut remaining = limits.maximum_entries;
        for _ in 0..count(input, &mut remaining)? {
            let (key, value) = record(input, limits.maximum_record_bytes, |reader| {
                Ok((node_key(reader)?, Node::deserialize_reader(reader)?))
            })?;
            insert_sorted(&mut store.nodes, key, value)?;
        }
        for _ in 0..count(input, &mut remaining)? {
            let (key, value) = record(input, limits.maximum_record_bytes, |reader| {
                let key = <(KeyHash, Version)>::deserialize_reader(reader)?;
                let value = match u8::deserialize_reader(reader)? {
                    0 => None,
                    1 => Some(bounded_bytes(reader)?),
                    _ => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "invalid value option",
                        ))
                    }
                };
                Ok((key, value))
            })?;
            insert_sorted(&mut store.values, key, value)?;
        }
        for _ in 0..count(input, &mut remaining)? {
            let (key, value) = record(input, limits.maximum_record_bytes, |reader| {
                Ok((KeyHash::deserialize_reader(reader)?, bounded_bytes(reader)?))
            })?;
            insert_sorted(&mut store.preimages, key, value)?;
        }
        for _ in 0..count(input, &mut remaining)? {
            let index = record(input, limits.maximum_record_bytes, |reader| {
                Ok(StaleNodeIndex {
                    stale_since_version: u64::deserialize_reader(reader)?,
                    node_key: node_key(reader)?,
                })
            })?;
            ensure!(
                store.stale_nodes.last().is_none_or(|prior| prior < &index),
                "unordered or duplicate stale-node index"
            );
            store.stale_nodes.insert(index);
        }
        for _ in 0..count(input, &mut remaining)? {
            let (key, value) = record(input, limits.maximum_record_bytes, |reader| {
                Ok((
                    Version::deserialize_reader(reader)?,
                    RootHash::deserialize_reader(reader)?,
                ))
            })?;
            insert_sorted(&mut store.roots, key, value)?;
        }
        let mut trailing = [0_u8; 1];
        ensure!(
            input.read(&mut trailing)? == 0,
            "trailing native snapshot bytes"
        );
        store.validate_snapshot_v0()?;
        Ok(store)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn huge_collection_is_rejected_without_consuming_entry_payload() {
        let mut bytes = Vec::from(u32::MAX.to_le_bytes());
        bytes.extend_from_slice(b"unread entry");
        let mut input = bytes.as_slice();
        let mut remaining = 8;
        assert!(count(&mut input, &mut remaining).is_err());
        assert_eq!(remaining, 8);
        assert_eq!(input, b"unread entry");
    }

    #[test]
    fn vector_prefix_over_budget_does_not_read_or_allocate_its_payload() {
        let bytes = u32::MAX.to_le_bytes();
        let mut input = bytes.as_slice();
        let mut reader = RecordReader {
            input: &mut input,
            bytes: Vec::new(),
            maximum: 1024,
        };
        assert!(bounded_bytes(&mut reader).is_err());
        assert_eq!(reader.bytes, bytes);
    }

    #[test]
    fn map_order_is_checked_without_overwriting_prior_values() {
        let mut map = BTreeMap::from([(3_u64, 7_u64)]);
        assert!(insert_sorted(&mut map, 3, 8).is_err());
        assert!(insert_sorted(&mut map, 2, 9).is_err());
        assert_eq!(map, BTreeMap::from([(3, 7)]));
        insert_sorted(&mut map, 4, 10).unwrap();
    }

    #[test]
    fn record_limit_and_reencoding_have_positive_controls() {
        let bytes = 42_u64.to_le_bytes();
        assert_eq!(
            record(&mut bytes.as_slice(), 8, |r| u64::deserialize_reader(r)).unwrap(),
            42
        );
        assert!(record(&mut bytes.as_slice(), 7, |r| u64::deserialize_reader(r)).is_err());
        assert!(record(&mut bytes.as_slice(), 8, |r| {
            u64::deserialize_reader(r).map(|_| 43_u64)
        })
        .is_err());
    }

    fn seeded_store() -> InMemoryNativeExecutionStoreV0 {
        let key = ed25519_dalek::SigningKey::from_bytes(&[37; 32]);
        let signer = AuthorizedSignerV0::new(
            "did:reader",
            "operator",
            hex::encode(key.verifying_key().to_bytes()),
        )
        .unwrap();
        let mut store = InMemoryNativeExecutionStoreV0::new(
            "reader-test",
            vec![signer],
            ConsensusParametersV0::reference_shadow_v0(),
        )
        .unwrap();
        store
            .apply_seed_v0(
                0,
                vec![
                    NativeStateWriteV0::raw(b"left".to_vec(), b"a".to_vec()).unwrap(),
                    NativeStateWriteV0::raw(b"right".to_vec(), b"b".to_vec()).unwrap(),
                ],
            )
            .unwrap();
        store
    }

    #[test]
    fn nibble_dimensions_reject_before_declared_payload_is_read() {
        for (nibbles, length) in [(65_u64, 33_u32), (1, 0), (2, u32::MAX), (u64::MAX, 0)] {
            let mut bytes = Vec::from(0_u64.to_le_bytes());
            bytes.extend_from_slice(&nibbles.to_le_bytes());
            bytes.extend_from_slice(&length.to_le_bytes());
            bytes.extend_from_slice(b"unread");
            let mut input = bytes.as_slice();
            assert!(node_key(&mut input).is_err());
            assert_eq!(input, b"unread");
        }
    }

    #[test]
    fn odd_nibble_padding_has_a_positive_control_and_rejects_alias() {
        let mut bytes = Vec::from(0_u64.to_le_bytes());
        bytes.extend_from_slice(&1_u64.to_le_bytes());
        bytes.extend_from_slice(&1_u32.to_le_bytes());
        bytes.push(0x10);
        assert_eq!(
            node_key(&mut bytes.as_slice())
                .unwrap()
                .nibble_path()
                .num_nibbles(),
            1
        );
        *bytes.last_mut().unwrap() = 0x11;
        assert!(node_key(&mut bytes.as_slice()).is_err());
    }

    #[test]
    fn forged_child_count_cannot_hide_behind_unchanged_jmt_root() {
        let mut store = seeded_store();
        let (key, node) = store
            .nodes
            .iter()
            .find(|(_, node)| matches!(node, Node::Internal(_)))
            .unwrap();
        let key = key.clone();
        let mut bytes = borsh::to_vec(node).unwrap();
        let count_offset = bytes.len() - 16;
        bytes[count_offset..count_offset + 8].copy_from_slice(&0_u64.to_le_bytes());
        let replacement = Node::try_from_slice(&bytes).unwrap();
        store.nodes.insert(key, replacement);
        // Cached child counts are not part of the authenticated hash.
        assert_eq!(
            Sha256Jmt::new(&store).get_root_hash(0).unwrap(),
            store.roots[&0]
        );
        assert!(store.validate_snapshot_v0().is_err());
    }

    #[test]
    fn forged_leaf_count_and_future_child_version_are_rejected() {
        for mutate_count in [true, false] {
            let mut store = seeded_store();
            let (key, node) = store
                .nodes
                .iter()
                .find(|(_, node)| matches!(node, Node::Internal(_)))
                .unwrap();
            let key = key.clone();
            let mut bytes = borsh::to_vec(node).unwrap();
            if mutate_count {
                let offset = bytes.len() - 8;
                bytes[offset..].copy_from_slice(&u64::MAX.to_le_bytes());
            } else {
                // Node variant then 16 Option<Child> entries in the pinned codec.
                let mut offset = 1;
                while bytes[offset] == 0 {
                    offset += 1;
                }
                assert_eq!(bytes[offset], 1);
                offset += 1 + 32;
                bytes[offset..offset + 8].copy_from_slice(&u64::MAX.to_le_bytes());
            }
            store
                .nodes
                .insert(key, Node::try_from_slice(&bytes).unwrap());
            assert!(store.validate_snapshot_v0().is_err());
        }
    }

    #[test]
    fn invalid_derived_node_key_is_rejected_without_panicking() {
        let mut store = seeded_store();
        let mut key_bytes = Vec::from(0_u64.to_le_bytes());
        key_bytes.extend_from_slice(&u64::MAX.to_le_bytes());
        key_bytes.extend_from_slice(&0_u32.to_le_bytes());
        let key = NodeKey::try_from_slice(&key_bytes).unwrap();
        store.nodes.insert(key, Node::Null);
        assert!(std::panic::catch_unwind(|| store.validate_snapshot_v0())
            .unwrap()
            .is_err());
    }

    #[test]
    fn streamed_and_slice_snapshot_decoders_preserve_the_same_native_bytes() {
        let mut store = seeded_store();
        store
            .apply_seed_v0(
                1,
                vec![NativeStateWriteV0::raw(b"left".to_vec(), b"updated".to_vec()).unwrap()],
            )
            .unwrap();
        let bytes = store.encode_authenticated_snapshot_v0().unwrap();
        let from_slice = InMemoryNativeExecutionStoreV0::decode_authenticated_snapshot_v0(
            &store.chain_id,
            store.signers.clone(),
            store.consensus_parameters,
            BTreeSet::new(),
            BTreeSet::new(),
            &bytes,
        )
        .unwrap();
        let from_reader = InMemoryNativeExecutionStoreV0::decode_authenticated_snapshot_reader_v1(
            &store.chain_id,
            store.signers.clone(),
            store.consensus_parameters,
            &mut bytes.as_slice(),
            SnapshotReadLimitsV1 {
                maximum_entries: 1024,
                maximum_record_bytes: 1024,
            },
        )
        .unwrap();
        assert_eq!(
            from_slice.encode_authenticated_snapshot_v0().unwrap(),
            bytes
        );
        assert_eq!(
            from_reader.encode_authenticated_snapshot_v0().unwrap(),
            bytes
        );
        assert_eq!(
            from_reader.parent_root_v0().unwrap(),
            store.parent_root_v0().unwrap()
        );
    }

    #[test]
    fn stale_marker_cannot_precede_its_node() {
        let mut store = seeded_store();
        store
            .apply_seed_v0(
                1,
                vec![NativeStateWriteV0::raw(b"left".to_vec(), b"updated".to_vec()).unwrap()],
            )
            .unwrap();
        let mut bad = store.stale_nodes.first().unwrap().clone();
        bad.stale_since_version = bad.node_key.version();
        store.stale_nodes.insert(bad);
        assert!(store.validate_snapshot_v0().is_err());
    }
    #[test]
    fn historical_leaf_value_corruption_rejects_below_a_valid_latest_root() {
        let mut store = seeded_store();
        store
            .apply_seed_v0(
                1,
                vec![NativeStateWriteV0::raw(b"left".to_vec(), b"updated".to_vec()).unwrap()],
            )
            .unwrap();
        let old_hash = authenticated_key_hash_v0(b"left").unwrap();
        *store.values.get_mut(&(old_hash, 0)).unwrap() =
            Some(b"tampered historical value".to_vec());
        assert_eq!(
            Sha256Jmt::new(&store).get_root_hash(1).unwrap(),
            store.roots[&1]
        );
        store.visit_verified_live_values_v0(1, |_, _| {}).unwrap();
        assert!(store.validate_snapshot_v0().is_err());
    }

    #[test]
    fn missing_historical_child_rejects_below_a_valid_latest_root() {
        let mut store = seeded_store();
        store
            .apply_seed_v0(
                1,
                vec![NativeStateWriteV0::raw(b"left".to_vec(), b"updated".to_vec()).unwrap()],
            )
            .unwrap();
        let hash = authenticated_key_hash_v0(b"left").unwrap();
        let key = store
            .nodes
            .iter()
            .find_map(|(key, node)| match node {
                Node::Leaf(leaf) if key.version() == 0 && leaf.key_hash() == hash => {
                    Some(key.clone())
                }
                _ => None,
            })
            .unwrap();
        store.nodes.remove(&key);
        assert_eq!(
            Sha256Jmt::new(&store).get_root_hash(1).unwrap(),
            store.roots[&1]
        );
        store.visit_verified_live_values_v0(1, |_, _| {}).unwrap();
        assert!(store.validate_snapshot_v0().is_err());
    }
}
