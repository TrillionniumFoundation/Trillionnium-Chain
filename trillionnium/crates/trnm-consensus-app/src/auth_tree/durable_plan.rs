//! Canonical durable representation for one exact JMT update plan.
//!
//! The outer record belongs to `trnm-consensus-app`. It deliberately does not
//! serialize `TreeUpdateBatch` wholesale and never exposes the process-local
//! `PlannedAuthUpdateSealV0`. Individual `NodeKey` and `Node` values use the
//! exact Borsh representation already persisted by the application store and
//! are pinned to the exact `jmt = 0.12.0` dependency. A future JMT/layout
//! upgrade must introduce a new codec/layout identifier and retain an explicit
//! decoder for this one.
//!
//! Every failure here is a local codec, resource, or invariant failure. It must
//! never be converted into deterministic block invalidity.

use anyhow::{ensure, Context, Result};
use borsh::BorshDeserialize;
use jmt::{
    storage::{Node, NodeKey, StaleNodeIndex, TreeReader},
    KeyHash, RootHash, Sha256Jmt, Version,
};

use super::{
    key_hash, plan_put_value_set, AuthWrite, PlannedAuthUpdate, MAX_AUTH_KEY_PREIMAGE_BYTES,
};

const DURABLE_AUTH_PLAN_CODEC_VERSION_V0: u16 = 0;
const DURABLE_AUTH_PLAN_JMT_LAYOUT_V0: &[u8] = b"jmt-sha256-0.12.0-node-borsh-v0";

// The validation artifact table currently reserves at most 64 MiB per
// artifact. Keep this component independently bounded so it can never consume
// more than that future envelope.
const MAX_DURABLE_AUTH_PLAN_BYTES_V0: usize = 64 * 1024 * 1024;
const MAX_DURABLE_AUTH_PLAN_NODE_KEY_BYTES_V0: usize = 4 * 1024;
const MAX_DURABLE_AUTH_PLAN_NODE_BYTES_V0: usize = 64 * 1024;
const MAX_DURABLE_AUTH_PLAN_VALUE_BYTES_V0: usize = 16 * 1024 * 1024;

/// Parsed physical plan bytes that have not yet been reproduced from their
/// exact parent reader and canonical write recipe.
///
/// Keeping this wrapper distinct prevents database bytes from becoming an
/// apply-capable [`PlannedAuthUpdate`] merely because their framing and Borsh
/// payloads are self-consistent.
#[allow(dead_code)]
pub(crate) struct UnverifiedDurablePlannedAuthUpdateV0 {
    encoded: Box<[u8]>,
    target_version: Version,
}

#[allow(dead_code)]
impl UnverifiedDurablePlannedAuthUpdateV0 {
    /// Replans the canonical writes against the caller's exact parent reader
    /// and returns an inert verified carrier only when every
    /// persistence-bearing field matches the durable physical record.
    ///
    /// This historical check deliberately permits the target version to have
    /// become occupied by a competing/finalized branch after evaluation. It
    /// does not grant apply authority.
    pub(crate) fn revalidate_v0<R: TreeReader>(
        self,
        reader: &R,
        expected_next_version: Version,
        expected_parent_root: Option<RootHash>,
        writes: impl IntoIterator<Item = AuthWrite>,
    ) -> Result<RevalidatedDurablePlannedAuthUpdateV0> {
        ensure!(
            self.target_version == expected_next_version,
            "durable JMT target is not the expected exact-next version"
        );
        verify_parent_root_v0(reader, expected_next_version, expected_parent_root)?;
        let replanned =
            plan_put_value_set(reader, expected_next_version, self.target_version, writes)?;
        ensure!(
            replanned.encode_durable_jmt_plan_v0()?.as_slice() == self.encoded.as_ref(),
            "durable JMT physical plan does not match canonical replanning"
        );
        Ok(RevalidatedDurablePlannedAuthUpdateV0 {
            encoded: self.encoded,
            target_version: self.target_version,
            parent_root: expected_parent_root,
        })
    }
}

/// Exact-parent/canonical-write verified plan that remains inert until the
/// current authoritative apply boundary rechecks head/root and target
/// occupancy.
#[allow(dead_code)]
pub(crate) struct RevalidatedDurablePlannedAuthUpdateV0 {
    encoded: Box<[u8]>,
    target_version: Version,
    parent_root: Option<RootHash>,
}

#[allow(dead_code)]
impl RevalidatedDurablePlannedAuthUpdateV0 {
    /// Consumes the inert verified carrier and releases its fresh plan only at
    /// an exact-current-parent, unoccupied-target boundary.
    ///
    /// The caller must additionally own the application/domain head authority
    /// that makes this reader the current Finalize parent.
    pub(crate) fn into_applicable_v0<R: TreeReader>(
        self,
        current_reader: &R,
        expected_next_version: Version,
        writes: impl IntoIterator<Item = AuthWrite>,
    ) -> Result<PlannedAuthUpdate> {
        ensure!(
            self.target_version == expected_next_version,
            "revalidated durable JMT target is not the current exact-next version"
        );
        verify_parent_root_v0(current_reader, expected_next_version, self.parent_root)?;
        ensure!(
            Sha256Jmt::new(current_reader)
                .get_root_hash_option(self.target_version)
                .context("check revalidated durable JMT target root absence")?
                .is_none(),
            "revalidated durable JMT target version is already occupied"
        );
        let replanned = plan_put_value_set(
            current_reader,
            expected_next_version,
            self.target_version,
            writes,
        )?;
        ensure!(
            replanned.encode_durable_jmt_plan_v0()?.as_slice() == self.encoded.as_ref(),
            "current durable JMT physical plan does not match the evaluated artifact"
        );
        Ok(replanned)
    }
}

fn verify_parent_root_v0<R: TreeReader>(
    reader: &R,
    target_version: Version,
    expected_parent_root: Option<RootHash>,
) -> Result<()> {
    match target_version.checked_sub(1) {
        Some(parent_version) => {
            let expected_parent_root = expected_parent_root
                .context("durable JMT replanning is missing the expected parent root")?;
            let actual_parent_root = Sha256Jmt::new(reader)
                .get_root_hash_option(parent_version)
                .context("load durable JMT replanning parent root")?;
            ensure!(
                actual_parent_root == Some(expected_parent_root),
                "durable JMT replanning parent root mismatch"
            );
        }
        None => {
            ensure!(
                expected_parent_root.is_none(),
                "genesis durable JMT replanning cannot bind a parent root"
            );
            ensure!(
                Sha256Jmt::new(reader)
                    .get_root_hash_option(Version::MAX)
                    .context("check durable JMT pre-genesis root absence")?
                    .is_none(),
                "genesis durable JMT replanning found a pre-genesis root"
            );
        }
    }
    Ok(())
}

impl PlannedAuthUpdate {
    /// Encodes every persistence-bearing field of this plan in a bounded,
    /// canonical app-owned record.
    ///
    /// This is inert data, not validation, callback, or apply authority. The
    /// consumer must still rebind the artifact to its exact parent/config and
    /// revalidate the plan before persistence.
    #[allow(dead_code)]
    pub(crate) fn encode_durable_jmt_plan_v0(&self) -> Result<Vec<u8>> {
        validate_plan_shape_v0(self)?;

        let mut encoded = Vec::new();
        append_bounded_v0(
            &mut encoded,
            &DURABLE_AUTH_PLAN_CODEC_VERSION_V0.to_be_bytes(),
            "durable JMT plan codec version",
        )?;
        push_u16_framed_v0(
            &mut encoded,
            DURABLE_AUTH_PLAN_JMT_LAYOUT_V0,
            DURABLE_AUTH_PLAN_JMT_LAYOUT_V0.len(),
            "durable JMT layout identifier",
        )?;
        append_bounded_v0(
            &mut encoded,
            &self.version.to_be_bytes(),
            "durable JMT plan version",
        )?;
        append_bounded_v0(&mut encoded, &self.root_hash.0, "durable JMT root hash")?;

        let nodes = self.tree_update_batch.node_batch.nodes();
        push_count_v0(&mut encoded, nodes.len(), "durable JMT node")?;
        for (node_key, node) in nodes {
            let node_key = borsh::to_vec(node_key).context("encode durable JMT node key")?;
            let node = borsh::to_vec(node).context("encode durable JMT node")?;
            push_u32_framed_v0(
                &mut encoded,
                &node_key,
                MAX_DURABLE_AUTH_PLAN_NODE_KEY_BYTES_V0,
                "durable JMT node key",
            )?;
            push_u32_framed_v0(
                &mut encoded,
                &node,
                MAX_DURABLE_AUTH_PLAN_NODE_BYTES_V0,
                "durable JMT node",
            )?;
        }

        let values = self.tree_update_batch.node_batch.values();
        push_count_v0(&mut encoded, values.len(), "durable JMT value")?;
        for ((version, key_hash), value) in values {
            append_bounded_v0(
                &mut encoded,
                &version.to_be_bytes(),
                "durable JMT value version",
            )?;
            append_bounded_v0(&mut encoded, &key_hash.0, "durable JMT value key hash")?;
            match value {
                None => push_u8_v0(&mut encoded, 0, "durable JMT value presence tag")?,
                Some(value) => {
                    push_u8_v0(&mut encoded, 1, "durable JMT value presence tag")?;
                    push_u32_framed_v0(
                        &mut encoded,
                        value,
                        MAX_DURABLE_AUTH_PLAN_VALUE_BYTES_V0,
                        "durable JMT value",
                    )?;
                }
            }
        }

        let stale_indices = &self.tree_update_batch.stale_node_index_batch;
        push_count_v0(&mut encoded, stale_indices.len(), "durable stale JMT index")?;
        for stale in stale_indices {
            append_bounded_v0(
                &mut encoded,
                &stale.stale_since_version.to_be_bytes(),
                "durable stale JMT index version",
            )?;
            let node_key =
                borsh::to_vec(&stale.node_key).context("encode durable stale JMT node key")?;
            push_u32_framed_v0(
                &mut encoded,
                &node_key,
                MAX_DURABLE_AUTH_PLAN_NODE_KEY_BYTES_V0,
                "durable stale JMT node key",
            )?;
        }

        push_count_v0(
            &mut encoded,
            self.preimages.len(),
            "durable JMT key preimage",
        )?;
        for (key_hash, preimage) in &self.preimages {
            append_bounded_v0(&mut encoded, &key_hash.0, "durable JMT preimage hash")?;
            push_u32_framed_v0(
                &mut encoded,
                preimage,
                MAX_AUTH_KEY_PREIMAGE_BYTES,
                "durable JMT key preimage",
            )?;
        }

        ensure!(
            encoded.len() <= MAX_DURABLE_AUTH_PLAN_BYTES_V0,
            "durable JMT plan record exceeds {} bytes",
            MAX_DURABLE_AUTH_PLAN_BYTES_V0
        );
        Ok(encoded)
    }

    /// Strictly decodes the app-owned
    /// `jmt-sha256-0.12.0-node-borsh-v0` physical plan representation while
    /// retaining only bounded raw bytes plus inert target metadata.
    #[allow(dead_code)]
    pub(crate) fn decode_durable_jmt_plan_v0(
        encoded: &[u8],
    ) -> Result<UnverifiedDurablePlannedAuthUpdateV0> {
        ensure!(
            encoded.len() <= MAX_DURABLE_AUTH_PLAN_BYTES_V0,
            "durable JMT plan record exceeds {} bytes",
            MAX_DURABLE_AUTH_PLAN_BYTES_V0
        );
        let mut decoder = DurableAuthPlanDecoderV0::new(encoded);
        ensure!(
            decoder.read_u16_v0("durable JMT plan codec version")?
                == DURABLE_AUTH_PLAN_CODEC_VERSION_V0,
            "unsupported durable JMT plan codec version"
        );
        ensure!(
            decoder.read_u16_framed_v0(
                DURABLE_AUTH_PLAN_JMT_LAYOUT_V0.len(),
                "durable JMT layout identifier",
            )? == DURABLE_AUTH_PLAN_JMT_LAYOUT_V0,
            "unsupported durable JMT layout identifier"
        );
        let version = decoder.read_u64_v0("durable JMT plan version")?;
        let _: [u8; 32] = decoder.read_array_v0("durable JMT root hash")?;

        let node_count = decoder.read_count_v0("durable JMT node count", 10)?;
        let mut previous_node_key = None;
        for _ in 0..node_count {
            let node_key_bytes = decoder.read_u32_framed_v0(
                MAX_DURABLE_AUTH_PLAN_NODE_KEY_BYTES_V0,
                "durable JMT node key",
            )?;
            let node_key: NodeKey = decode_exact_borsh_v0(node_key_bytes, "durable JMT node key")?;
            ensure!(
                node_key.version() == version,
                "durable JMT node belongs to a different version"
            );
            if let Some(previous) = &previous_node_key {
                ensure!(
                    previous < &node_key,
                    "durable JMT node keys are not strictly canonical"
                );
            }
            previous_node_key = Some(node_key);

            let node_bytes = decoder
                .read_u32_framed_v0(MAX_DURABLE_AUTH_PLAN_NODE_BYTES_V0, "durable JMT node")?;
            let _: Node = decode_exact_borsh_v0(node_bytes, "durable JMT node")?;
        }

        let value_count = decoder.read_count_v0("durable JMT value count", 41)?;
        let mut previous_value_key = None;
        for _ in 0..value_count {
            let value_version = decoder.read_u64_v0("durable JMT value version")?;
            ensure!(
                value_version == version,
                "durable JMT value belongs to a different version"
            );
            let key_hash = KeyHash(decoder.read_array_v0("durable JMT value key hash")?);
            let value_key = (value_version, key_hash);
            if let Some(previous) = &previous_value_key {
                ensure!(
                    previous < &value_key,
                    "durable JMT value keys are not strictly canonical"
                );
            }
            previous_value_key = Some(value_key);
            match decoder.read_u8_v0("durable JMT value presence tag")? {
                0 => {}
                1 => {
                    decoder.read_u32_framed_v0(
                        MAX_DURABLE_AUTH_PLAN_VALUE_BYTES_V0,
                        "durable JMT value",
                    )?;
                }
                _ => anyhow::bail!("unknown durable JMT value presence tag"),
            }
        }

        let stale_count = decoder.read_count_v0("durable stale JMT index count", 13)?;
        let mut previous_stale = None;
        for _ in 0..stale_count {
            let stale_since_version = decoder.read_u64_v0("durable stale JMT index version")?;
            ensure!(
                stale_since_version == version,
                "durable stale JMT index belongs to a different version"
            );
            let node_key_bytes = decoder.read_u32_framed_v0(
                MAX_DURABLE_AUTH_PLAN_NODE_KEY_BYTES_V0,
                "durable stale JMT node key",
            )?;
            let node_key: NodeKey =
                decode_exact_borsh_v0(node_key_bytes, "durable stale JMT node key")?;
            let stale = StaleNodeIndex {
                stale_since_version,
                node_key,
            };
            if let Some(previous) = &previous_stale {
                ensure!(
                    previous < &stale,
                    "durable stale JMT indices are not strictly canonical"
                );
            }
            previous_stale = Some(stale);
        }

        let preimage_count = decoder.read_count_v0("durable JMT key preimage count", 37)?;
        let mut previous_preimage_hash = None;
        for _ in 0..preimage_count {
            let stored_hash = KeyHash(decoder.read_array_v0("durable JMT preimage hash")?);
            if let Some(previous) = previous_preimage_hash {
                ensure!(
                    previous < stored_hash,
                    "durable JMT preimage hashes are not strictly canonical"
                );
            }
            previous_preimage_hash = Some(stored_hash);
            let preimage = decoder
                .read_u32_framed_v0(MAX_AUTH_KEY_PREIMAGE_BYTES, "durable JMT key preimage")?;
            ensure!(
                key_hash(preimage)? == stored_hash,
                "durable JMT key preimage hash mismatch"
            );
        }
        decoder.finish_v0()?;

        Ok(UnverifiedDurablePlannedAuthUpdateV0 {
            encoded: encoded.into(),
            target_version: version,
        })
    }
}

fn validate_plan_shape_v0(plan: &PlannedAuthUpdate) -> Result<()> {
    ensure!(
        plan.tree_update_batch
            .node_batch
            .nodes()
            .keys()
            .all(|node_key| node_key.version() == plan.version),
        "durable JMT node belongs to a different version"
    );
    ensure!(
        plan.tree_update_batch
            .node_batch
            .values()
            .keys()
            .all(|(version, _)| *version == plan.version),
        "durable JMT value belongs to a different version"
    );
    ensure!(
        plan.tree_update_batch
            .stale_node_index_batch
            .iter()
            .all(|stale| stale.stale_since_version == plan.version),
        "durable stale JMT index belongs to a different version"
    );
    for (stored_hash, preimage) in &plan.preimages {
        ensure!(
            key_hash(preimage)? == *stored_hash,
            "durable JMT key preimage hash mismatch"
        );
    }
    Ok(())
}

fn decode_exact_borsh_v0<T>(encoded: &[u8], label: &str) -> Result<T>
where
    T: BorshDeserialize + borsh::BorshSerialize,
{
    let decoded = T::try_from_slice(encoded).with_context(|| format!("decode {label}"))?;
    ensure!(
        borsh::to_vec(&decoded).with_context(|| format!("re-encode {label}"))? == encoded,
        "{label} is not in canonical jmt-0.12.0 Borsh form"
    );
    Ok(decoded)
}

fn push_count_v0(encoded: &mut Vec<u8>, count: usize, label: &str) -> Result<()> {
    let count = u32::try_from(count).with_context(|| format!("{label} count exceeds u32::MAX"))?;
    append_bounded_v0(encoded, &count.to_be_bytes(), label)
}

fn push_u8_v0(encoded: &mut Vec<u8>, value: u8, label: &str) -> Result<()> {
    append_bounded_v0(encoded, &[value], label)
}

fn push_u16_framed_v0(
    encoded: &mut Vec<u8>,
    value: &[u8],
    max_len: usize,
    label: &str,
) -> Result<()> {
    ensure!(value.len() <= max_len, "{label} exceeds {max_len} bytes");
    let length = u16::try_from(value.len()).with_context(|| format!("{label} exceeds u16::MAX"))?;
    append_bounded_v0(encoded, &length.to_be_bytes(), label)?;
    append_bounded_v0(encoded, value, label)?;
    Ok(())
}

fn push_u32_framed_v0(
    encoded: &mut Vec<u8>,
    value: &[u8],
    max_len: usize,
    label: &str,
) -> Result<()> {
    ensure!(value.len() <= max_len, "{label} exceeds {max_len} bytes");
    let length = u32::try_from(value.len()).with_context(|| format!("{label} exceeds u32::MAX"))?;
    append_bounded_v0(encoded, &length.to_be_bytes(), label)?;
    append_bounded_v0(encoded, value, label)?;
    Ok(())
}

fn append_bounded_v0(encoded: &mut Vec<u8>, value: &[u8], label: &str) -> Result<()> {
    append_with_limit_v0(encoded, value, MAX_DURABLE_AUTH_PLAN_BYTES_V0, label)
}

fn append_with_limit_v0(
    encoded: &mut Vec<u8>,
    value: &[u8],
    maximum_bytes: usize,
    label: &str,
) -> Result<()> {
    let next_len = encoded
        .len()
        .checked_add(value.len())
        .with_context(|| format!("{label} overflows durable JMT plan length"))?;
    ensure!(
        next_len <= maximum_bytes,
        "{label} exceeds durable JMT plan budget of {} bytes",
        maximum_bytes
    );
    encoded.extend_from_slice(value);
    Ok(())
}

struct DurableAuthPlanDecoderV0<'a> {
    remaining: &'a [u8],
}

impl<'a> DurableAuthPlanDecoderV0<'a> {
    fn new(encoded: &'a [u8]) -> Self {
        Self { remaining: encoded }
    }

    fn take_v0(&mut self, length: usize, label: &str) -> Result<&'a [u8]> {
        ensure!(
            self.remaining.len() >= length,
            "{label} is truncated in durable JMT plan record"
        );
        let (value, remaining) = self.remaining.split_at(length);
        self.remaining = remaining;
        Ok(value)
    }

    fn read_u8_v0(&mut self, label: &str) -> Result<u8> {
        Ok(self.take_v0(1, label)?[0])
    }

    fn read_u16_v0(&mut self, label: &str) -> Result<u16> {
        Ok(u16::from_be_bytes(
            self.take_v0(2, label)?
                .try_into()
                .expect("checked u16 frame length"),
        ))
    }

    fn read_u32_v0(&mut self, label: &str) -> Result<u32> {
        Ok(u32::from_be_bytes(
            self.take_v0(4, label)?
                .try_into()
                .expect("checked u32 frame length"),
        ))
    }

    fn read_u64_v0(&mut self, label: &str) -> Result<u64> {
        Ok(u64::from_be_bytes(
            self.take_v0(8, label)?
                .try_into()
                .expect("checked u64 frame length"),
        ))
    }

    fn read_array_v0<const N: usize>(&mut self, label: &str) -> Result<[u8; N]> {
        Ok(self
            .take_v0(N, label)?
            .try_into()
            .expect("checked fixed frame length"))
    }

    fn read_count_v0(&mut self, label: &str, minimum_item_bytes: usize) -> Result<usize> {
        let count = usize::try_from(self.read_u32_v0(label)?)
            .with_context(|| format!("{label} does not fit usize"))?;
        ensure!(
            minimum_item_bytes > 0
                && count <= self.remaining.len().saturating_div(minimum_item_bytes),
            "{label} cannot fit in the remaining durable JMT plan bytes"
        );
        Ok(count)
    }

    fn read_u16_framed_v0(&mut self, max_len: usize, label: &str) -> Result<&'a [u8]> {
        let length = usize::from(self.read_u16_v0(label)?);
        ensure!(length <= max_len, "{label} exceeds {max_len} bytes");
        self.take_v0(length, label)
    }

    fn read_u32_framed_v0(&mut self, max_len: usize, label: &str) -> Result<&'a [u8]> {
        let length = usize::try_from(self.read_u32_v0(label)?)
            .with_context(|| format!("{label} length does not fit usize"))?;
        ensure!(length <= max_len, "{label} exceeds {max_len} bytes");
        self.take_v0(length, label)
    }

    fn finish_v0(self) -> Result<()> {
        ensure!(
            self.remaining.is_empty(),
            "durable JMT plan record has trailing bytes"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::ops::Range;

    use sha2::{Digest, Sha256};

    use super::*;
    use crate::auth_tree::{account_key, task_key, AuthWrite, InMemoryAuthTree};

    fn put(key: Vec<u8>, value: &[u8]) -> AuthWrite {
        AuthWrite::put(key, value.to_vec()).expect("valid write")
    }

    fn fixture() -> (InMemoryAuthTree, Vec<AuthWrite>, PlannedAuthUpdate) {
        let first = account_key("durable-plan-first").expect("first key");
        let second = account_key("durable-plan-second").expect("second key");
        let mut tree = InMemoryAuthTree::default();
        tree.put_value_set(
            0,
            [
                put(first.clone(), b"first-before"),
                put(second.clone(), b"second-before"),
            ],
        )
        .expect("parent state");
        let writes = vec![
            put(first, b"first-after"),
            AuthWrite::delete(second).expect("delete second"),
            put(
                task_key("durable-plan-created").expect("created key"),
                b"created",
            ),
        ];
        let plan = tree
            .plan_put_value_set(1, writes.clone())
            .expect("durable plan");
        (tree, writes, plan)
    }

    fn assert_same_persistence_fields(left: &PlannedAuthUpdate, right: &PlannedAuthUpdate) {
        assert_eq!(left.version, right.version);
        assert_eq!(left.root_hash, right.root_hash);
        assert_eq!(
            left.tree_update_batch.node_batch.nodes(),
            right.tree_update_batch.node_batch.nodes()
        );
        assert_eq!(
            left.tree_update_batch.node_batch.values(),
            right.tree_update_batch.node_batch.values()
        );
        assert_eq!(
            left.tree_update_batch.stale_node_index_batch,
            right.tree_update_batch.stale_node_index_batch
        );
        assert_eq!(left.preimages, right.preimages);
    }

    fn read_u32_at(encoded: &[u8], offset: usize) -> usize {
        u32::from_be_bytes(
            encoded[offset..offset + 4]
                .try_into()
                .expect("test u32 frame"),
        ) as usize
    }

    fn node_entry_ranges(encoded: &[u8]) -> Vec<Range<usize>> {
        let header_len = 2 + 2 + DURABLE_AUTH_PLAN_JMT_LAYOUT_V0.len() + 8 + 32;
        let node_count = read_u32_at(encoded, header_len);
        let mut cursor = header_len + 4;
        let mut ranges = Vec::with_capacity(node_count);
        for _ in 0..node_count {
            let start = cursor;
            let node_key_len = read_u32_at(encoded, cursor);
            cursor += 4 + node_key_len;
            let node_len = read_u32_at(encoded, cursor);
            cursor += 4 + node_len;
            ranges.push(start..cursor);
        }
        ranges
    }

    fn first_present_value_range(encoded: &[u8]) -> Range<usize> {
        let nodes = node_entry_ranges(encoded);
        let mut cursor = nodes.last().expect("fixture nodes").end;
        let value_count = read_u32_at(encoded, cursor);
        cursor += 4;
        for _ in 0..value_count {
            cursor += 8 + 32;
            let tag = encoded[cursor];
            cursor += 1;
            match tag {
                0 => {}
                1 => {
                    let value_len = read_u32_at(encoded, cursor);
                    cursor += 4;
                    return cursor..cursor + value_len;
                }
                other => panic!("unexpected fixture value tag {other}"),
            }
        }
        panic!("fixture needs a present value")
    }

    #[test]
    fn durable_jmt_plan_round_trips_every_persistence_field() {
        let (tree, writes, plan) = fixture();
        let encoded = plan.encode_durable_jmt_plan_v0().expect("encode plan");
        let candidate =
            PlannedAuthUpdate::decode_durable_jmt_plan_v0(&encoded).expect("decode plan");
        let revalidated = candidate
            .revalidate_v0(&tree, 1, tree.root_hash(0), writes.clone())
            .expect("revalidate exact plan");
        let decoded = revalidated
            .into_applicable_v0(&tree, 1, writes)
            .expect("release exact unoccupied plan");

        assert_same_persistence_fields(&plan, &decoded);
        assert_eq!(
            decoded
                .encode_durable_jmt_plan_v0()
                .expect("re-encode plan"),
            encoded
        );
        assert_eq!(
            plan.seal_v0().expect("source seal"),
            decoded.seal_v0().expect("decoded seal")
        );

        assert!(!plan.tree_update_batch.node_stats.is_empty());
        let mut without_stats = plan.clone();
        without_stats.tree_update_batch.node_stats.clear();
        assert_eq!(
            without_stats
                .encode_durable_jmt_plan_v0()
                .expect("encode plan without diagnostics"),
            encoded,
            "diagnostic JMT node statistics must not enter the durable apply recipe"
        );
    }

    #[test]
    fn durable_genesis_empty_plan_round_trips_through_replanning() {
        let tree = InMemoryAuthTree::default();
        let plan = tree
            .plan_put_value_set(0, std::iter::empty())
            .expect("empty genesis plan");
        assert!(
            plan.tree_update_batch
                .node_batch
                .nodes()
                .values()
                .any(|node| matches!(node, Node::Null)),
            "empty genesis fixture must freeze the JMT null-node adapter"
        );
        let encoded = plan.encode_durable_jmt_plan_v0().expect("encode plan");
        let candidate =
            PlannedAuthUpdate::decode_durable_jmt_plan_v0(&encoded).expect("decode plan");
        let revalidated = candidate
            .revalidate_v0(&tree, 0, None, std::iter::empty())
            .expect("revalidate empty genesis plan");
        let replanned = revalidated
            .into_applicable_v0(&tree, 0, std::iter::empty())
            .expect("release empty genesis plan");
        assert_same_persistence_fields(&plan, &replanned);
    }

    #[test]
    fn durable_jmt_plan_codec_has_a_frozen_jmt_0_12_layout_vector() {
        let (_, _, plan) = fixture();
        assert!(plan
            .tree_update_batch
            .node_batch
            .nodes()
            .values()
            .any(|node| matches!(node, Node::Internal(_))));
        assert!(plan
            .tree_update_batch
            .node_batch
            .nodes()
            .values()
            .any(|node| matches!(node, Node::Leaf(_))));
        assert!(!plan.tree_update_batch.stale_node_index_batch.is_empty());
        assert!(plan
            .tree_update_batch
            .node_batch
            .values()
            .values()
            .any(Option::is_none));
        assert!(plan
            .tree_update_batch
            .node_batch
            .values()
            .values()
            .any(Option::is_some));
        let encoded = plan.encode_durable_jmt_plan_v0().expect("encode plan");
        assert_eq!(encoded.len(), 1_050);
        assert_eq!(
            Sha256::digest(&encoded).as_slice(),
            [
                0x3c, 0x63, 0xc1, 0x09, 0x8b, 0xb3, 0x13, 0xf4, 0xdd, 0x12, 0x88, 0xb4, 0x5b, 0xf1,
                0x62, 0x17, 0xa9, 0x75, 0xa2, 0x68, 0x91, 0x8d, 0x31, 0x21, 0x93, 0x91, 0x02, 0xfb,
                0x34, 0x40, 0xfc, 0x0b,
            ]
        );
    }

    #[test]
    fn durable_jmt_plan_decoder_rejects_version_layout_truncation_and_suffix() {
        let (_, _, plan) = fixture();
        let encoded = plan.encode_durable_jmt_plan_v0().expect("encode plan");

        let mut unknown_version = encoded.clone();
        unknown_version[..2].copy_from_slice(&1_u16.to_be_bytes());
        assert!(PlannedAuthUpdate::decode_durable_jmt_plan_v0(&unknown_version).is_err());

        let mut unknown_layout = encoded.clone();
        let layout_offset = 4;
        unknown_layout[layout_offset] ^= 1;
        assert!(PlannedAuthUpdate::decode_durable_jmt_plan_v0(&unknown_layout).is_err());

        assert!(
            PlannedAuthUpdate::decode_durable_jmt_plan_v0(&encoded[..encoded.len() - 1]).is_err()
        );

        let mut suffixed = encoded;
        suffixed.push(0);
        assert!(PlannedAuthUpdate::decode_durable_jmt_plan_v0(&suffixed).is_err());
    }

    #[test]
    fn durable_jmt_plan_decoder_rejects_noncanonical_and_semantic_drift() {
        let (tree, writes, plan) = fixture();
        let encoded = plan.encode_durable_jmt_plan_v0().expect("encode plan");

        let header_len = 2 + 2 + DURABLE_AUTH_PLAN_JMT_LAYOUT_V0.len() + 8 + 32;
        let mut zero_first_node_key_length = encoded.clone();
        zero_first_node_key_length[header_len + 4..header_len + 8]
            .copy_from_slice(&0_u32.to_be_bytes());
        assert!(
            PlannedAuthUpdate::decode_durable_jmt_plan_v0(&zero_first_node_key_length).is_err()
        );

        let mut oversized_first_node_key = encoded.clone();
        oversized_first_node_key[header_len + 4..header_len + 8].copy_from_slice(
            &u32::try_from(MAX_DURABLE_AUTH_PLAN_NODE_KEY_BYTES_V0 + 1)
                .expect("bounded test length")
                .to_be_bytes(),
        );
        assert!(PlannedAuthUpdate::decode_durable_jmt_plan_v0(&oversized_first_node_key).is_err());

        let mut impossible_node_count = encoded.clone();
        impossible_node_count[header_len..header_len + 4].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(PlannedAuthUpdate::decode_durable_jmt_plan_v0(&impossible_node_count).is_err());

        let mut root_drift = encoded;
        let root_offset = 2 + 2 + DURABLE_AUTH_PLAN_JMT_LAYOUT_V0.len() + 8;
        root_drift[root_offset] ^= 1;
        let candidate = PlannedAuthUpdate::decode_durable_jmt_plan_v0(&root_drift)
            .expect("root remains an inert field until parent-bound artifact revalidation");
        assert!(candidate
            .revalidate_v0(&tree, 1, tree.root_hash(0), writes)
            .is_err());
    }

    #[test]
    fn durable_jmt_plan_decoder_rejects_duplicate_and_reordered_nodes() {
        let (_, _, plan) = fixture();
        let encoded = plan.encode_durable_jmt_plan_v0().expect("encode plan");
        let node_ranges = node_entry_ranges(&encoded);
        assert!(node_ranges.len() >= 2, "fixture needs multiple nodes");

        let first = node_ranges[0].clone();
        let second = node_ranges[1].clone();
        assert_eq!(first.end, second.start);
        let mut reordered = Vec::with_capacity(encoded.len());
        reordered.extend_from_slice(&encoded[..first.start]);
        reordered.extend_from_slice(&encoded[second.clone()]);
        reordered.extend_from_slice(&encoded[first.clone()]);
        reordered.extend_from_slice(&encoded[second.end..]);
        assert!(PlannedAuthUpdate::decode_durable_jmt_plan_v0(&reordered).is_err());

        let header_len = 2 + 2 + DURABLE_AUTH_PLAN_JMT_LAYOUT_V0.len() + 8 + 32;
        let mut duplicated = encoded.clone();
        let node_count = read_u32_at(&duplicated, header_len);
        duplicated[header_len..header_len + 4]
            .copy_from_slice(&(node_count as u32 + 1).to_be_bytes());
        duplicated.splice(first.end..first.end, encoded[first].iter().copied());
        assert!(PlannedAuthUpdate::decode_durable_jmt_plan_v0(&duplicated).is_err());
    }

    #[test]
    fn durable_jmt_plan_revalidation_rejects_parent_recipe_and_physical_splices() {
        let (tree, writes, plan) = fixture();
        let encoded = plan.encode_durable_jmt_plan_v0().expect("encode plan");

        let candidate =
            PlannedAuthUpdate::decode_durable_jmt_plan_v0(&encoded).expect("decode plan");
        candidate
            .revalidate_v0(&tree, 1, tree.root_hash(0), writes.iter().cloned().rev())
            .expect("canonical write order must not change the exact plan");

        let candidate =
            PlannedAuthUpdate::decode_durable_jmt_plan_v0(&encoded).expect("decode plan");
        let mut wrong_parent_root = tree.root_hash(0).expect("parent root");
        wrong_parent_root.0[0] ^= 1;
        assert!(candidate
            .revalidate_v0(&tree, 1, Some(wrong_parent_root), writes.clone())
            .is_err());

        let candidate =
            PlannedAuthUpdate::decode_durable_jmt_plan_v0(&encoded).expect("decode plan");
        let mut different_writes = writes.clone();
        different_writes.push(put(
            task_key("durable-plan-spliced-write").expect("spliced key"),
            b"spliced",
        ));
        assert!(candidate
            .revalidate_v0(&tree, 1, tree.root_hash(0), different_writes)
            .is_err());

        let mut value_splice = encoded;
        let value_range = first_present_value_range(&value_splice);
        value_splice[value_range.start] ^= 1;
        let candidate = PlannedAuthUpdate::decode_durable_jmt_plan_v0(&value_splice)
            .expect("self-consistent physical value remains unverified");
        assert!(candidate
            .revalidate_v0(&tree, 1, tree.root_hash(0), writes)
            .is_err());
    }

    #[test]
    fn durable_jmt_plan_apply_release_requires_an_unoccupied_exact_target() {
        let (tree, writes, plan) = fixture();
        let encoded = plan.encode_durable_jmt_plan_v0().expect("encode plan");

        let candidate =
            PlannedAuthUpdate::decode_durable_jmt_plan_v0(&encoded).expect("decode plan");
        assert!(candidate
            .revalidate_v0(&tree, 2, tree.root_hash(1), writes.clone())
            .is_err());

        let mut occupied = tree.clone();
        occupied.apply(plan).expect("occupy target version");
        let candidate =
            PlannedAuthUpdate::decode_durable_jmt_plan_v0(&encoded).expect("decode plan");
        let revalidated = candidate
            .revalidate_v0(&occupied, 1, occupied.root_hash(0), writes.clone())
            .expect("historical plan remains verifiable after target occupation");
        assert!(revalidated
            .into_applicable_v0(&occupied, 1, writes)
            .is_err());
    }

    #[test]
    fn durable_jmt_plan_apply_release_rejects_equal_root_different_history_transplant() {
        let first = account_key("durable-history-first").expect("first key");
        let second = account_key("durable-history-second").expect("second key");
        let third = task_key("durable-history-third").expect("third key");
        let base = [
            put(first.clone(), b"first"),
            put(second.clone(), b"second"),
            put(third.clone(), b"third"),
        ];
        let mut primary = InMemoryAuthTree::default();
        let mut alternate = InMemoryAuthTree::default();
        primary
            .put_value_set(0, base.clone())
            .expect("primary base");
        alternate.put_value_set(0, base).expect("alternate base");
        primary
            .put_value_set(1, [put(first, b"first")])
            .expect("primary history");
        alternate
            .put_value_set(1, [put(second, b"second")])
            .expect("alternate history");
        assert_eq!(primary.root_hash(1), alternate.root_hash(1));
        assert_ne!(
            primary.encode_snapshot().expect("primary snapshot"),
            alternate.encode_snapshot().expect("alternate snapshot")
        );

        let writes = vec![put(third, b"third-after")];
        let primary_plan = primary
            .plan_put_value_set(2, writes.clone())
            .expect("primary target plan");
        let alternate_plan = alternate
            .plan_put_value_set(2, writes.clone())
            .expect("alternate target plan");
        assert_eq!(primary_plan.root_hash, alternate_plan.root_hash);
        let encoded = primary_plan
            .encode_durable_jmt_plan_v0()
            .expect("encode primary plan");
        assert_ne!(
            encoded,
            alternate_plan
                .encode_durable_jmt_plan_v0()
                .expect("encode alternate plan"),
            "fixture must carry distinct physical JMT histories"
        );

        let candidate =
            PlannedAuthUpdate::decode_durable_jmt_plan_v0(&encoded).expect("decode primary plan");
        let revalidated = candidate
            .revalidate_v0(&primary, 2, primary.root_hash(1), writes.clone())
            .expect("revalidate against primary history");
        assert!(revalidated
            .into_applicable_v0(&alternate, 2, writes)
            .is_err());
    }

    #[test]
    fn durable_jmt_plan_apply_release_retains_the_verified_parent_root() {
        let key = account_key("durable-parent-binding").expect("key");
        let mut primary = InMemoryAuthTree::default();
        let mut alternate = InMemoryAuthTree::default();
        primary
            .put_value_set(0, [put(key.clone(), b"primary-parent")])
            .expect("primary parent");
        alternate
            .put_value_set(0, [put(key.clone(), b"alternate-parent")])
            .expect("alternate parent");
        assert_ne!(primary.root_hash(0), alternate.root_hash(0));

        let writes = vec![put(key, b"same-target")];
        let primary_plan = primary
            .plan_put_value_set(1, writes.clone())
            .expect("primary target plan");
        let alternate_plan = alternate
            .plan_put_value_set(1, writes.clone())
            .expect("alternate target plan");
        let encoded = primary_plan
            .encode_durable_jmt_plan_v0()
            .expect("encode primary plan");
        assert_eq!(
            encoded,
            alternate_plan
                .encode_durable_jmt_plan_v0()
                .expect("encode alternate plan"),
            "fixture must demonstrate identical target bytes from distinct parents"
        );

        let candidate =
            PlannedAuthUpdate::decode_durable_jmt_plan_v0(&encoded).expect("decode primary plan");
        let revalidated = candidate
            .revalidate_v0(&primary, 1, primary.root_hash(0), writes.clone())
            .expect("revalidate primary parent");
        assert!(revalidated
            .into_applicable_v0(&alternate, 1, writes)
            .is_err());
    }

    #[test]
    fn durable_jmt_plan_bounded_writer_fails_before_an_over_budget_append() {
        let mut encoded = vec![0; 7];
        assert!(append_with_limit_v0(&mut encoded, &[1, 2], 8, "test frame").is_err());
        assert_eq!(encoded, vec![0; 7]);

        append_with_limit_v0(&mut encoded, &[1], 8, "test frame").expect("exact budget");
        assert_eq!(encoded.len(), 8);
        assert!(append_with_limit_v0(&mut encoded, &[2], 8, "test frame").is_err());
        assert_eq!(encoded.len(), 8);

        let maximum_preimage = vec![7; MAX_AUTH_KEY_PREIMAGE_BYTES];
        let mut framed = Vec::new();
        push_u32_framed_v0(
            &mut framed,
            &maximum_preimage,
            MAX_AUTH_KEY_PREIMAGE_BYTES,
            "test preimage",
        )
        .expect("maximum durable key preimage");
        assert_eq!(framed.len(), 4 + MAX_AUTH_KEY_PREIMAGE_BYTES);

        let oversized_preimage = vec![7; MAX_AUTH_KEY_PREIMAGE_BYTES + 1];
        let mut rejected = Vec::new();
        assert!(push_u32_framed_v0(
            &mut rejected,
            &oversized_preimage,
            MAX_AUTH_KEY_PREIMAGE_BYTES,
            "test preimage",
        )
        .is_err());
        assert!(rejected.is_empty());
    }

    #[test]
    fn durable_jmt_plan_adapter_keeps_its_exact_dependency_and_container_boundary() {
        let manifest = include_str!("../../Cargo.toml");
        assert!(manifest.contains("jmt = \"=0.12.0\""));

        let source = include_str!("durable_plan.rs");
        for forbidden in [
            ["borsh::to_vec(", "&self.tree_update_batch", ")"].concat(),
            ["borsh::to_vec(", "&plan.tree_update_batch", ")"].concat(),
            ["PlannedAuthUpdateSealV0", "("].concat(),
        ] {
            assert!(
                !source.contains(&forbidden),
                "durable JMT plan adapter gained forbidden surface: {forbidden}"
            );
        }
    }
}
