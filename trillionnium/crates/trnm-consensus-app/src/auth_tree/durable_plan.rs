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

use std::collections::BTreeMap;

use anyhow::{anyhow, ensure, Context, Result};
use borsh::{BorshDeserialize, BorshSerialize};
use jmt::{
    storage::{HasPreimage, LeafNode, Node, NodeKey, StaleNodeIndex, TreeReader},
    KeyHash, RootHash, Sha256Jmt, Version,
};
use sha2::{Digest, Sha256};

use super::{
    key_hash, plan_put_value_set, AuthWrite, PlannedAuthUpdate, MAX_AUTH_KEY_PREIMAGE_BYTES,
};

const DURABLE_AUTH_PLAN_CODEC_VERSION_V0: u16 = 0;
const DURABLE_AUTH_PLAN_JMT_LAYOUT_V0: &[u8] = b"jmt-sha256-0.12.0-node-borsh-v0";
const DURABLE_AUTH_PLAN_COMMITMENT_DOMAIN_V0: &[u8] =
    b"trnm.consensus-app.durable-jmt-plan-commitment.v0";
const SPECULATIVE_AUTH_PATH_ANCHOR_TOKEN_DOMAIN_V0: &[u8] =
    b"trnm.consensus-app.speculative-auth-path-anchor.v0";
const SPECULATIVE_AUTH_PATH_LAYER_TOKEN_DOMAIN_V0: &[u8] =
    b"trnm.consensus-app.speculative-auth-path-layer.v0";

pub(crate) const DURABLE_AUTH_PLAN_COMMITMENT_BYTES_V0: usize = 32;

/// Legacy bound for the test/reference full-plan byte codec below. Production
/// Valid artifacts retain only the streaming commitment and do not require the
/// complete physical plan to fit this envelope.
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
pub(crate) struct UnverifiedDurablePlannedAuthUpdateV0<'a> {
    encoded: &'a [u8],
    target_version: Version,
    root_hash: RootHash,
}

#[allow(dead_code)]
impl<'a> UnverifiedDurablePlannedAuthUpdateV0<'a> {
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
    ) -> Result<RevalidatedDurablePlannedAuthUpdateV0<'a>> {
        ensure!(
            self.target_version == expected_next_version,
            "durable JMT target is not the expected exact-next version"
        );
        verify_parent_root_v0(reader, expected_next_version, expected_parent_root)?;
        let replanned =
            plan_put_value_set(reader, expected_next_version, self.target_version, writes)?;
        ensure!(
            replanned.encode_durable_jmt_plan_v0()?.as_slice() == self.encoded,
            "durable JMT physical plan does not match canonical replanning"
        );
        Ok(RevalidatedDurablePlannedAuthUpdateV0 {
            encoded: self.encoded,
            target_version: self.target_version,
            parent_root: expected_parent_root,
            root_hash: self.root_hash,
        })
    }

    /// Replans from one inert, canonical raw write recipe without exposing a
    /// general tombstone constructor or any apply-capable write carrier to the
    /// sibling artifact module.  The result remains historical verification
    /// only and still requires [`RevalidatedDurablePlannedAuthUpdateV0::into_applicable_v0`]
    /// at a future authoritative apply boundary.
    pub(crate) fn revalidate_raw_recipe_v0<'b, R, I>(
        self,
        reader: &R,
        expected_next_version: Version,
        expected_parent_root: Option<RootHash>,
        writes: I,
    ) -> Result<RevalidatedDurablePlannedAuthUpdateV0<'a>>
    where
        R: TreeReader,
        I: IntoIterator<Item = (&'b [u8], Option<&'b [u8]>)>,
    {
        let rebuilt = rebuild_raw_write_recipe_v0(writes)?;
        self.revalidate_v0(reader, expected_next_version, expected_parent_root, rebuilt)
    }
}

/// Exact-parent and raw-recipe verification result for a fixed durable plan
/// commitment.  It intentionally has no method that can release a
/// [`PlannedAuthUpdate`] or otherwise grant apply authority.
#[allow(dead_code)]
pub(crate) struct RevalidatedDurableAuthPlanCommitmentV0 {
    commitment: [u8; DURABLE_AUTH_PLAN_COMMITMENT_BYTES_V0],
    target_version: Version,
    parent_root: Option<RootHash>,
    root_hash: RootHash,
}

#[allow(dead_code)]
impl RevalidatedDurableAuthPlanCommitmentV0 {
    pub(crate) const fn commitment_v0(&self) -> [u8; DURABLE_AUTH_PLAN_COMMITMENT_BYTES_V0] {
        self.commitment
    }

    pub(crate) const fn target_version_v0(&self) -> Version {
        self.target_version
    }

    pub(crate) const fn parent_root_v0(&self) -> Option<RootHash> {
        self.parent_root
    }

    pub(crate) const fn root_hash_v0(&self) -> RootHash {
        self.root_hash
    }
}

/// Replans one canonical borrowed raw-write recipe from its exact authenticated
/// parent and compares both the resulting root and the streaming commitment of
/// every persistence-bearing JMT field.
///
/// The returned carrier is historical evidence only.  In particular, it does
/// not retain the fresh plan and cannot be converted into apply authority.
#[allow(dead_code)]
pub(crate) fn revalidate_durable_jmt_plan_commitment_v0<'a, R, I>(
    reader: &R,
    expected_next_version: Version,
    expected_parent_root: Option<RootHash>,
    expected_root_hash: RootHash,
    expected_commitment: [u8; DURABLE_AUTH_PLAN_COMMITMENT_BYTES_V0],
    writes: I,
) -> Result<RevalidatedDurableAuthPlanCommitmentV0>
where
    R: TreeReader,
    I: IntoIterator<Item = (&'a [u8], Option<&'a [u8]>)>,
{
    verify_parent_root_v0(reader, expected_next_version, expected_parent_root)?;
    let rebuilt = rebuild_raw_write_recipe_v0(writes)?;
    let replanned = plan_put_value_set(
        reader,
        expected_next_version,
        expected_next_version,
        rebuilt,
    )?;
    ensure!(
        replanned.root_hash == expected_root_hash,
        "durable JMT commitment root does not match canonical replanning"
    );
    ensure!(
        replanned.durable_jmt_plan_commitment_v0()? == expected_commitment,
        "durable JMT commitment does not match canonical replanning"
    );
    Ok(RevalidatedDurableAuthPlanCommitmentV0 {
        commitment: expected_commitment,
        target_version: expected_next_version,
        parent_root: expected_parent_root,
        root_hash: expected_root_hash,
    })
}

/// One freshly reproduced speculative JMT plan whose exact parent, root, and
/// physical-plan commitment have all been checked against a durable Valid
/// artifact.
///
/// The inner [`PlannedAuthUpdate`] is intentionally private and this carrier
/// exposes neither persistence nor authoritative-apply conversion.  It can be
/// consumed only as another read layer while reconstructing one exact
/// BlockId lineage.
pub(crate) struct RevalidatedSpeculativeAuthPlanV0 {
    plan: PlannedAuthUpdate,
}

impl RevalidatedSpeculativeAuthPlanV0 {
    /// Releases the freshly reproduced physical plan only to the authoritative
    /// ApplicationStore finalization transaction.
    ///
    /// The one-shot permit has no constructor outside `store`; keeping it as
    /// an argument prevents ordinary validation, overlay reconstruction, and
    /// sibling app modules from turning an inert durable commitment into
    /// persistence authority.
    pub(crate) fn into_native_finalization_apply_plan_v0(
        self,
        _permit: crate::store::NativeFinalizationApplyPlanPermitV0,
    ) -> PlannedAuthUpdate {
        self.plan
    }
}

#[cfg(test)]
impl RevalidatedSpeculativeAuthPlanV0 {
    pub(crate) const fn version_v0(&self) -> Version {
        self.plan.version
    }

    pub(crate) const fn root_hash_v0(&self) -> RootHash {
        self.plan.root_hash
    }
}

/// Read-only stack of independently reproduced speculative plans over one
/// authenticated committed reader.  A caller creates a distinct stack per
/// BlockId lineage; sibling plans are therefore never merged even when their
/// JMT target versions are equal.
#[cfg(test)]
pub(crate) struct SpeculativeAuthPlanStackReaderV0<'a, R> {
    base: &'a R,
    plans: &'a [RevalidatedSpeculativeAuthPlanV0],
}

#[cfg(test)]
impl<'a, R> SpeculativeAuthPlanStackReaderV0<'a, R> {
    pub(crate) const fn new_v0(base: &'a R, plans: &'a [RevalidatedSpeculativeAuthPlanV0]) -> Self {
        Self { base, plans }
    }
}

#[cfg(test)]
impl<R: TreeReader> TreeReader for SpeculativeAuthPlanStackReaderV0<'_, R> {
    fn get_node_option(&self, node_key: &NodeKey) -> Result<Option<Node>> {
        for plan in self.plans.iter().rev() {
            if let Some(node) = plan.plan.tree_update_batch.node_batch.nodes().get(node_key) {
                return Ok(Some(node.clone()));
            }
        }
        self.base.get_node_option(node_key)
    }

    fn get_value_option(&self, max_version: Version, key_hash: KeyHash) -> Result<Option<Vec<u8>>> {
        for plan in self.plans.iter().rev() {
            if plan.plan.version > max_version {
                continue;
            }
            if let Some(value) = plan
                .plan
                .tree_update_batch
                .node_batch
                .values()
                .get(&(plan.plan.version, key_hash))
            {
                return Ok(value.clone());
            }
        }
        self.base.get_value_option(max_version, key_hash)
    }

    fn get_rightmost_leaf(&self) -> Result<Option<(NodeKey, LeafNode)>> {
        let base = self.base.get_rightmost_leaf()?;
        let planned = self
            .plans
            .iter()
            .flat_map(|plan| plan.plan.tree_update_batch.node_batch.nodes().iter())
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

#[cfg(test)]
impl<R: TreeReader + HasPreimage> HasPreimage for SpeculativeAuthPlanStackReaderV0<'_, R> {
    fn preimage(&self, key_hash: KeyHash) -> Result<Option<Vec<u8>>> {
        for plan in self.plans.iter().rev() {
            if let Some(preimage) = plan.plan.preimages.get(&key_hash) {
                return Ok(Some(preimage.clone()));
            }
        }
        self.base.preimage(key_hash)
    }
}

/// One explicitly bounded resource dimension for an indexed speculative path.
#[cfg_attr(not(test), allow(dead_code))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SpeculativeAuthPathResourceV0 {
    NodeFacts,
    ValueFacts,
    PreimageFacts,
    LeafFacts,
    IndexedBytes,
    TotalWorkUnits,
}

/// A typed indexed-path failure. Resource failures remain distinguishable so
/// the owning host can map them to local backpressure rather than durable
/// corruption.
#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug)]
pub(crate) enum SpeculativeAuthPathErrorV0 {
    Revalidation(anyhow::Error),
    ResourceLimit {
        resource: SpeculativeAuthPathResourceV0,
        current: u64,
        added: u64,
        maximum: u64,
    },
    HostAllocation {
        stage: &'static str,
        detail: String,
    },
}

impl std::fmt::Display for SpeculativeAuthPathErrorV0 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Revalidation(error) => write!(formatter, "{error:#}"),
            Self::ResourceLimit {
                resource,
                current,
                added,
                maximum,
            } => write!(
                formatter,
                "indexed speculative path {resource:?} resource limit exceeded: {current} + {added} > {maximum}"
            ),
            Self::HostAllocation { stage, detail } => {
                write!(formatter, "{stage}: {detail}")
            }
        }
    }
}

impl std::error::Error for SpeculativeAuthPathErrorV0 {}

/// Explicit limits for one fixed-snapshot forest traversal.
///
/// Fact and byte limits bound the current root-to-tip path. Work units are
/// monotonic across sibling pops and therefore bound the complete traversal,
/// not only its peak depth.
#[cfg_attr(not(test), allow(dead_code))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SpeculativeAuthPathLimitsV0 {
    maximum_node_facts: u64,
    maximum_value_facts: u64,
    maximum_preimage_facts: u64,
    maximum_leaf_facts: u64,
    maximum_indexed_bytes: u64,
    maximum_total_work_units: u64,
}

#[cfg_attr(not(test), allow(dead_code))]
impl SpeculativeAuthPathLimitsV0 {
    const UNBOUNDED: Self =
        Self::new_v0(u64::MAX, u64::MAX, u64::MAX, u64::MAX, u64::MAX, u64::MAX);

    pub(crate) const fn new_v0(
        maximum_node_facts: u64,
        maximum_value_facts: u64,
        maximum_preimage_facts: u64,
        maximum_leaf_facts: u64,
        maximum_indexed_bytes: u64,
        maximum_total_work_units: u64,
    ) -> Self {
        Self {
            maximum_node_facts,
            maximum_value_facts,
            maximum_preimage_facts,
            maximum_leaf_facts,
            maximum_indexed_bytes,
            maximum_total_work_units,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct SpeculativeAuthPathUsageV0 {
    node_facts: u64,
    value_facts: u64,
    preimage_facts: u64,
    leaf_facts: u64,
    indexed_bytes: u64,
    total_work_units: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SpeculativeAuthPathLayerTokenV0([u8; 32]);

/// Mutable, read-only index of the currently authenticated speculative path.
///
/// The authenticated anchor is checked against a caller-supplied base reader at
/// construction, but the path deliberately owns no reference to that reader.
/// Reads and replanning borrow the fixed-snapshot base only for the duration of
/// one operation, so a SQLite-backed owner never needs to build a self-reference.
/// Generic [`TreeReader`] has no stable identity, so the owning store must pass
/// the same fixed database snapshot to every operation. Parent-root and exact
/// physical-plan commitment checks reject a foreign base whenever it changes
/// authenticated replanning; two semantically equivalent bases with the same
/// root are intentionally indistinguishable at this layer.
/// A plan can enter only through [`Self::replan_and_push_v0`] or the explicitly
/// non-branching [`Self::replan_and_append_tip_v0`]; both reproduce it against
/// this exact path immediately before installation. This prevents a detached
/// plan verified over sibling A from being transplanted onto sibling B,
/// including equal-root/different-physical-history siblings. Every successful
/// push returns a linear, opaque frame which must be popped in strict LIFO order
/// before entering a sibling branch.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) struct RevalidatedSpeculativeAuthPathV0 {
    nodes: BTreeMap<NodeKey, Node>,
    values: BTreeMap<KeyHash, BTreeMap<Version, Option<Vec<u8>>>>,
    preimages: BTreeMap<KeyHash, RevalidatedSpeculativePreimageV0>,
    leaves: BTreeMap<(KeyHash, Version, NodeKey), LeafNode>,
    tip_version: Version,
    tip_root: RootHash,
    tip_layer_token: SpeculativeAuthPathLayerTokenV0,
    limits: SpeculativeAuthPathLimitsV0,
    usage: SpeculativeAuthPathUsageV0,
}

struct RevalidatedSpeculativePreimageV0 {
    bytes: Vec<u8>,
    references: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SpeculativeAuthPathInstallModeV0 {
    Reversible,
    AppendOnly,
}

struct SpeculativeAuthPathUndoKeysV0 {
    node_keys: Vec<NodeKey>,
    value_keys: Vec<(KeyHash, Version)>,
    preimage_keys: Vec<KeyHash>,
    leaf_keys: Vec<(KeyHash, Version, NodeKey)>,
}

/// Opaque undo record for one indexed speculative path layer.
///
/// The frame is neither cloneable nor serializable and contains only removal
/// keys. In particular, it cannot recreate the revalidated plan consumed by
/// [`RevalidatedSpeculativeAuthPathV0::replan_and_push_v0`].
#[cfg_attr(not(test), allow(dead_code))]
#[must_use = "a speculative path frame must be popped before entering a sibling branch"]
pub(crate) struct RevalidatedSpeculativeAuthPathFrameV0 {
    version: Version,
    root: RootHash,
    layer_token: SpeculativeAuthPathLayerTokenV0,
    parent_version: Version,
    parent_root: RootHash,
    parent_layer_token: SpeculativeAuthPathLayerTokenV0,
    node_keys: Vec<NodeKey>,
    value_keys: Vec<(KeyHash, Version)>,
    preimage_keys: Vec<KeyHash>,
    leaf_keys: Vec<(KeyHash, Version, NodeKey)>,
    layer_usage: SpeculativeAuthPathUsageV0,
}

#[cfg_attr(not(test), allow(dead_code))]
impl RevalidatedSpeculativeAuthPathV0 {
    pub(crate) fn new_v0<R: TreeReader>(
        base: &R,
        anchor_version: Version,
        anchor_root: RootHash,
        limits: SpeculativeAuthPathLimitsV0,
    ) -> std::result::Result<Self, SpeculativeAuthPathErrorV0> {
        let actual_anchor = Sha256Jmt::new(base)
            .get_root_hash_option(anchor_version)
            .context("load indexed speculative path anchor root")
            .map_err(SpeculativeAuthPathErrorV0::Revalidation)?;
        if actual_anchor != Some(anchor_root) {
            return Err(path_revalidation_error_v0(
                "indexed speculative path anchor does not match its fixed base reader",
            ));
        }
        Ok(Self {
            nodes: BTreeMap::new(),
            values: BTreeMap::new(),
            preimages: BTreeMap::new(),
            leaves: BTreeMap::new(),
            tip_version: anchor_version,
            tip_root: anchor_root,
            tip_layer_token: speculative_auth_path_anchor_token_v0(anchor_version, anchor_root),
            limits,
            usage: SpeculativeAuthPathUsageV0::default(),
        })
    }

    pub(crate) const fn tip_version_v0(&self) -> Version {
        self.tip_version
    }

    pub(crate) const fn tip_root_v0(&self) -> RootHash {
        self.tip_root
    }

    /// Reproduces one durable plan against this exact path and installs it only
    /// after all path-resource limits and collision checks pass.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn replan_and_push_v0<'write, R, I>(
        &mut self,
        base: &R,
        expected_next_version: Version,
        expected_parent_root: RootHash,
        expected_root_hash: RootHash,
        expected_commitment: [u8; DURABLE_AUTH_PLAN_COMMITMENT_BYTES_V0],
        writes: I,
    ) -> std::result::Result<RevalidatedSpeculativeAuthPathFrameV0, SpeculativeAuthPathErrorV0>
    where
        R: TreeReader,
        I: IntoIterator<Item = (&'write [u8], Option<&'write [u8]>)>,
    {
        if self.tip_version.checked_add(1) != Some(expected_next_version) {
            return Err(path_revalidation_error_v0(
                "indexed speculative JMT path target is not the exact successor",
            ));
        }
        if self.tip_root != expected_parent_root {
            return Err(path_revalidation_error_v0(
                "indexed speculative JMT path parent root does not match its current tip",
            ));
        }

        let verified = {
            let reader = SpeculativeAuthPathReaderV0::new_v0(base, self);
            replan_speculative_jmt_plan_with_limits_v0(
                &reader,
                expected_next_version,
                Some(expected_parent_root),
                expected_root_hash,
                expected_commitment,
                writes,
                self.limits,
            )?
        };
        match self.install_verified_plan_v0(
            verified,
            expected_commitment,
            SpeculativeAuthPathInstallModeV0::Reversible,
        )? {
            Some(frame) => Ok(frame),
            None => {
                unreachable!("reversible indexed speculative installation returned append-only")
            }
        }
    }

    /// Reproduces and permanently appends one exact tip without retaining an
    /// undo frame.
    ///
    /// This is only for linear root-to-tip reconstruction where the caller will
    /// never branch below the appended layer. A previously issued frame cannot
    /// pop through an appended tip: its layer token no longer matches, so such a
    /// misuse is rejected before the index changes. Forest traversal must use
    /// [`Self::replan_and_push_v0`] and [`Self::pop_verified_plan_v0`] instead.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn replan_and_append_tip_v0<'write, R, I>(
        &mut self,
        base: &R,
        expected_next_version: Version,
        expected_parent_root: RootHash,
        expected_root_hash: RootHash,
        expected_commitment: [u8; DURABLE_AUTH_PLAN_COMMITMENT_BYTES_V0],
        writes: I,
    ) -> std::result::Result<(), SpeculativeAuthPathErrorV0>
    where
        R: TreeReader,
        I: IntoIterator<Item = (&'write [u8], Option<&'write [u8]>)>,
    {
        if self.tip_version.checked_add(1) != Some(expected_next_version) {
            return Err(path_revalidation_error_v0(
                "indexed speculative JMT path target is not the exact successor",
            ));
        }
        if self.tip_root != expected_parent_root {
            return Err(path_revalidation_error_v0(
                "indexed speculative JMT path parent root does not match its current tip",
            ));
        }

        let verified = {
            let reader = SpeculativeAuthPathReaderV0::new_v0(base, self);
            replan_speculative_jmt_plan_with_limits_v0(
                &reader,
                expected_next_version,
                Some(expected_parent_root),
                expected_root_hash,
                expected_commitment,
                writes,
                self.limits,
            )?
        };
        match self.install_verified_plan_v0(
            verified,
            expected_commitment,
            SpeculativeAuthPathInstallModeV0::AppendOnly,
        )? {
            None => Ok(()),
            Some(_) => {
                unreachable!("append-only indexed speculative installation returned undo frame")
            }
        }
    }

    fn install_verified_plan_v0(
        &mut self,
        verified: RevalidatedSpeculativeAuthPlanV0,
        expected_commitment: [u8; DURABLE_AUTH_PLAN_COMMITMENT_BYTES_V0],
        mode: SpeculativeAuthPathInstallModeV0,
    ) -> std::result::Result<
        Option<RevalidatedSpeculativeAuthPathFrameV0>,
        SpeculativeAuthPathErrorV0,
    > {
        let version = verified.plan.version;
        if self.tip_version.checked_add(1) != Some(version) {
            return Err(path_revalidation_error_v0(
                "indexed speculative JMT path target is not the exact successor",
            ));
        }

        let node_batch = &verified.plan.tree_update_batch.node_batch;
        let indexed_key_copies = if mode == SpeculativeAuthPathInstallModeV0::Reversible {
            2
        } else {
            1
        };
        let mut layer_usage = SpeculativeAuthPathUsageV0 {
            node_facts: usize_to_u64_v0(node_batch.nodes().len())?,
            value_facts: usize_to_u64_v0(node_batch.values().len())?,
            preimage_facts: usize_to_u64_v0(verified.plan.preimages.len())?,
            ..SpeculativeAuthPathUsageV0::default()
        };
        for (node_key, node) in node_batch.nodes() {
            if self.nodes.contains_key(node_key) {
                return Err(path_revalidation_error_v0(
                    "indexed speculative JMT path contains a duplicate node key",
                ));
            }
            add_borsh_index_bytes_v0(&mut layer_usage.indexed_bytes, node_key, indexed_key_copies)?;
            add_borsh_index_bytes_v0(&mut layer_usage.indexed_bytes, node, 1)?;
            if let Node::Leaf(leaf) = node {
                let leaf_key = (leaf.key_hash(), node_key.version(), node_key.clone());
                if self.leaves.contains_key(&leaf_key) {
                    return Err(path_revalidation_error_v0(
                        "indexed speculative JMT path contains a duplicate leaf key",
                    ));
                }
                layer_usage.leaf_facts = layer_usage.leaf_facts.checked_add(1).ok_or(
                    SpeculativeAuthPathErrorV0::ResourceLimit {
                        resource: SpeculativeAuthPathResourceV0::LeafFacts,
                        current: 0,
                        added: u64::MAX,
                        maximum: self.limits.maximum_leaf_facts,
                    },
                )?;
                add_borsh_index_bytes_v0(
                    &mut layer_usage.indexed_bytes,
                    node_key,
                    indexed_key_copies,
                )?;
                add_index_bytes_v0(
                    &mut layer_usage.indexed_bytes,
                    indexed_key_copies * (32 + 8),
                )?;
                add_borsh_index_bytes_v0(&mut layer_usage.indexed_bytes, leaf, 1)?;
            }
        }

        for ((value_version, key_hash), value) in node_batch.values() {
            if *value_version != version {
                return Err(path_revalidation_error_v0(
                    "indexed speculative JMT value belongs to a foreign version",
                ));
            }
            if self
                .values
                .get(key_hash)
                .is_some_and(|versions| versions.contains_key(value_version))
            {
                return Err(path_revalidation_error_v0(
                    "indexed speculative JMT path contains a duplicate value key",
                ));
            }
            add_index_bytes_v0(
                &mut layer_usage.indexed_bytes,
                indexed_key_copies * (32 + 8) + 1,
            )?;
            if let Some(value) = value {
                add_index_bytes_v0(&mut layer_usage.indexed_bytes, value.len())?;
            }
        }

        for (key_hash, preimage) in &verified.plan.preimages {
            if let Some(existing) = self.preimages.get(key_hash) {
                if existing.references == 0
                    || existing.references.checked_add(1).is_none()
                    || existing.bytes != *preimage
                {
                    return Err(path_revalidation_error_v0(
                        "indexed speculative JMT path contains a conflicting preimage",
                    ));
                }
                if mode == SpeculativeAuthPathInstallModeV0::Reversible {
                    add_index_bytes_v0(&mut layer_usage.indexed_bytes, 32)?;
                }
            } else {
                add_index_bytes_v0(
                    &mut layer_usage.indexed_bytes,
                    indexed_key_copies * 32 + std::mem::size_of::<usize>() + preimage.len(),
                )?;
            }
        }

        layer_usage.total_work_units = layer_usage
            .node_facts
            .checked_add(layer_usage.value_facts)
            .and_then(|total| total.checked_add(layer_usage.preimage_facts))
            .and_then(|total| total.checked_add(layer_usage.leaf_facts))
            .ok_or(SpeculativeAuthPathErrorV0::ResourceLimit {
                resource: SpeculativeAuthPathResourceV0::TotalWorkUnits,
                current: self.usage.total_work_units,
                added: u64::MAX,
                maximum: self.limits.maximum_total_work_units,
            })?;
        self.preflight_layer_usage_v0(layer_usage)?;

        let undo_keys = if mode == SpeculativeAuthPathInstallModeV0::Reversible {
            let mut node_keys = Vec::new();
            let mut value_keys = Vec::new();
            let mut preimage_keys = Vec::new();
            let mut leaf_keys = Vec::new();
            reserve_undo_keys_v0(
                &mut node_keys,
                node_batch.nodes().len(),
                "reserve indexed speculative node undo keys",
            )?;
            reserve_undo_keys_v0(
                &mut leaf_keys,
                usize::try_from(layer_usage.leaf_facts).unwrap_or(usize::MAX),
                "reserve indexed speculative leaf undo keys",
            )?;
            reserve_undo_keys_v0(
                &mut value_keys,
                node_batch.values().len(),
                "reserve indexed speculative value undo keys",
            )?;
            reserve_undo_keys_v0(
                &mut preimage_keys,
                verified.plan.preimages.len(),
                "reserve indexed speculative preimage undo keys",
            )?;
            for (node_key, node) in node_batch.nodes() {
                node_keys.push(node_key.clone());
                if let Node::Leaf(leaf) = node {
                    leaf_keys.push((leaf.key_hash(), node_key.version(), node_key.clone()));
                }
            }
            value_keys.extend(
                node_batch
                    .values()
                    .keys()
                    .map(|(value_version, key_hash)| (*key_hash, *value_version)),
            );
            preimage_keys.extend(verified.plan.preimages.keys().copied());
            Some(SpeculativeAuthPathUndoKeysV0 {
                node_keys,
                value_keys,
                preimage_keys,
                leaf_keys,
            })
        } else {
            None
        };

        for (node_key, node) in node_batch.nodes() {
            let replaced = self.nodes.insert(node_key.clone(), node.clone());
            debug_assert!(replaced.is_none());
            if let Node::Leaf(leaf) = node {
                let leaf_key = (leaf.key_hash(), node_key.version(), node_key.clone());
                let replaced = self.leaves.insert(leaf_key, leaf.clone());
                debug_assert!(replaced.is_none());
            }
        }
        for ((value_version, key_hash), value) in node_batch.values() {
            let replaced = self
                .values
                .entry(*key_hash)
                .or_default()
                .insert(*value_version, value.clone());
            debug_assert!(replaced.is_none());
        }
        for (key_hash, preimage) in &verified.plan.preimages {
            match self.preimages.entry(*key_hash) {
                std::collections::btree_map::Entry::Vacant(entry) => {
                    entry.insert(RevalidatedSpeculativePreimageV0 {
                        bytes: preimage.clone(),
                        references: 1,
                    });
                }
                std::collections::btree_map::Entry::Occupied(mut entry) => {
                    entry.get_mut().references += 1;
                }
            }
        }

        let parent_version = self.tip_version;
        let parent_root = self.tip_root;
        let parent_layer_token = self.tip_layer_token;
        let root = verified.plan.root_hash;
        let layer_token = speculative_auth_path_layer_token_v0(
            parent_layer_token,
            version,
            root,
            expected_commitment,
        );
        self.apply_layer_usage_v0(layer_usage);
        self.tip_version = version;
        self.tip_root = root;
        self.tip_layer_token = layer_token;
        Ok(undo_keys.map(
            |SpeculativeAuthPathUndoKeysV0 {
                 node_keys,
                 value_keys,
                 preimage_keys,
                 leaf_keys,
             }| RevalidatedSpeculativeAuthPathFrameV0 {
                version,
                root,
                layer_token,
                parent_version,
                parent_root,
                parent_layer_token,
                node_keys,
                value_keys,
                preimage_keys,
                leaf_keys,
                layer_usage,
            },
        ))
    }

    /// Removes one exact top layer. A foreign or out-of-order frame is rejected
    /// before any indexed fact is changed.
    pub(crate) fn pop_verified_plan_v0(
        &mut self,
        frame: RevalidatedSpeculativeAuthPathFrameV0,
    ) -> std::result::Result<(), SpeculativeAuthPathErrorV0> {
        if self.tip_version != frame.version
            || self.tip_root != frame.root
            || self.tip_layer_token != frame.layer_token
        {
            return Err(path_revalidation_error_v0(
                "indexed speculative JMT path frame is not the current exact layer",
            ));
        }
        if !(frame
            .node_keys
            .iter()
            .all(|key| self.nodes.contains_key(key))
            && frame
                .leaf_keys
                .iter()
                .all(|key| self.leaves.contains_key(key))
            && frame.value_keys.iter().all(|(key_hash, version)| {
                self.values
                    .get(key_hash)
                    .is_some_and(|versions| versions.contains_key(version))
            })
            && frame.preimage_keys.iter().all(|key_hash| {
                self.preimages
                    .get(key_hash)
                    .is_some_and(|preimage| preimage.references > 0)
            })
            && self.current_usage_contains_v0(frame.layer_usage))
        {
            return Err(path_revalidation_error_v0(
                "indexed speculative JMT path frame differs from the current index",
            ));
        }

        for key in &frame.node_keys {
            let removed = self.nodes.remove(key);
            debug_assert!(removed.is_some());
        }
        for key in &frame.leaf_keys {
            let removed = self.leaves.remove(key);
            debug_assert!(removed.is_some());
        }
        for (key_hash, version) in &frame.value_keys {
            let remove_hash = {
                let versions = self
                    .values
                    .get_mut(key_hash)
                    .expect("prevalidated indexed speculative value hash");
                let removed = versions.remove(version);
                debug_assert!(removed.is_some());
                versions.is_empty()
            };
            if remove_hash {
                self.values.remove(key_hash);
            }
        }
        for key_hash in &frame.preimage_keys {
            let remove_hash = {
                let preimage = self
                    .preimages
                    .get_mut(key_hash)
                    .expect("prevalidated indexed speculative preimage");
                preimage.references -= 1;
                preimage.references == 0
            };
            if remove_hash {
                self.preimages.remove(key_hash);
            }
        }
        self.remove_layer_usage_v0(frame.layer_usage);
        self.tip_version = frame.parent_version;
        self.tip_root = frame.parent_root;
        self.tip_layer_token = frame.parent_layer_token;
        Ok(())
    }

    fn preflight_layer_usage_v0(
        &self,
        layer: SpeculativeAuthPathUsageV0,
    ) -> std::result::Result<(), SpeculativeAuthPathErrorV0> {
        preflight_speculative_auth_usage_v0(self.usage, layer, self.limits)
    }

    fn apply_layer_usage_v0(&mut self, layer: SpeculativeAuthPathUsageV0) {
        self.usage.node_facts += layer.node_facts;
        self.usage.value_facts += layer.value_facts;
        self.usage.preimage_facts += layer.preimage_facts;
        self.usage.leaf_facts += layer.leaf_facts;
        self.usage.indexed_bytes += layer.indexed_bytes;
        self.usage.total_work_units += layer.total_work_units;
    }

    fn current_usage_contains_v0(&self, layer: SpeculativeAuthPathUsageV0) -> bool {
        self.usage.node_facts >= layer.node_facts
            && self.usage.value_facts >= layer.value_facts
            && self.usage.preimage_facts >= layer.preimage_facts
            && self.usage.leaf_facts >= layer.leaf_facts
            && self.usage.indexed_bytes >= layer.indexed_bytes
    }

    fn remove_layer_usage_v0(&mut self, layer: SpeculativeAuthPathUsageV0) {
        self.usage.node_facts -= layer.node_facts;
        self.usage.value_facts -= layer.value_facts;
        self.usage.preimage_facts -= layer.preimage_facts;
        self.usage.leaf_facts -= layer.leaf_facts;
        self.usage.indexed_bytes -= layer.indexed_bytes;
        // Total work is intentionally monotonic across sibling traversal.
    }
}

/// Indexed read view over one exact speculative path and its authenticated
/// committed base. Lookups touch at most one keyed speculative entry before
/// falling back to the base reader; they never iterate over path depth.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) struct SpeculativeAuthPathReaderV0<'a, R> {
    base: &'a R,
    path: &'a RevalidatedSpeculativeAuthPathV0,
}

#[cfg_attr(not(test), allow(dead_code))]
impl<'a, R> SpeculativeAuthPathReaderV0<'a, R> {
    pub(crate) const fn new_v0(base: &'a R, path: &'a RevalidatedSpeculativeAuthPathV0) -> Self {
        Self { base, path }
    }
}

impl<R: TreeReader> TreeReader for SpeculativeAuthPathReaderV0<'_, R> {
    fn get_node_option(&self, node_key: &NodeKey) -> Result<Option<Node>> {
        if let Some(node) = self.path.nodes.get(node_key) {
            return Ok(Some(node.clone()));
        }
        self.base.get_node_option(node_key)
    }

    fn get_value_option(&self, max_version: Version, key_hash: KeyHash) -> Result<Option<Vec<u8>>> {
        if let Some((_, value)) = self
            .path
            .values
            .get(&key_hash)
            .and_then(|versions| versions.range(..=max_version).next_back())
        {
            return Ok(value.clone());
        }
        self.base.get_value_option(max_version, key_hash)
    }

    fn get_rightmost_leaf(&self) -> Result<Option<(NodeKey, LeafNode)>> {
        let base = self.base.get_rightmost_leaf()?;
        let planned = self
            .path
            .leaves
            .last_key_value()
            .map(|((_, _, node_key), leaf)| (node_key.clone(), leaf.clone()));
        Ok([base, planned]
            .into_iter()
            .flatten()
            .max_by_key(|(node_key, leaf)| (leaf.key_hash(), node_key.version())))
    }
}

impl<R: TreeReader + HasPreimage> HasPreimage for SpeculativeAuthPathReaderV0<'_, R> {
    fn preimage(&self, key_hash: KeyHash) -> Result<Option<Vec<u8>>> {
        if let Some(preimage) = self.path.preimages.get(&key_hash) {
            return Ok(Some(preimage.bytes.clone()));
        }
        self.base.preimage(key_hash)
    }
}

fn path_revalidation_error_v0(message: &'static str) -> SpeculativeAuthPathErrorV0 {
    SpeculativeAuthPathErrorV0::Revalidation(anyhow!(message))
}

fn usize_to_u64_v0(value: usize) -> std::result::Result<u64, SpeculativeAuthPathErrorV0> {
    u64::try_from(value).map_err(|_| SpeculativeAuthPathErrorV0::ResourceLimit {
        resource: SpeculativeAuthPathResourceV0::TotalWorkUnits,
        current: 0,
        added: u64::MAX,
        maximum: u64::MAX,
    })
}

fn add_index_bytes_v0(
    total: &mut u64,
    added: usize,
) -> std::result::Result<(), SpeculativeAuthPathErrorV0> {
    let added = usize_to_u64_v0(added)?;
    *total = total
        .checked_add(added)
        .ok_or(SpeculativeAuthPathErrorV0::ResourceLimit {
            resource: SpeculativeAuthPathResourceV0::IndexedBytes,
            current: *total,
            added,
            maximum: u64::MAX,
        })?;
    Ok(())
}

fn add_index_bytes_with_limit_v0(
    total: &mut u64,
    added: usize,
    maximum: u64,
) -> std::result::Result<(), SpeculativeAuthPathErrorV0> {
    let added = usize_to_u64_v0(added)?;
    let current = *total;
    if current.checked_add(added).is_none_or(|next| next > maximum) {
        return Err(SpeculativeAuthPathErrorV0::ResourceLimit {
            resource: SpeculativeAuthPathResourceV0::IndexedBytes,
            current,
            added,
            maximum,
        });
    }
    *total += added;
    Ok(())
}

fn add_borsh_index_bytes_v0<T: BorshSerialize>(
    total: &mut u64,
    value: &T,
    copies: usize,
) -> std::result::Result<(), SpeculativeAuthPathErrorV0> {
    let one = borsh::object_length(value)
        .context("measure indexed speculative path fact")
        .map_err(SpeculativeAuthPathErrorV0::Revalidation)?;
    let added = one
        .checked_mul(copies)
        .ok_or(SpeculativeAuthPathErrorV0::ResourceLimit {
            resource: SpeculativeAuthPathResourceV0::IndexedBytes,
            current: *total,
            added: u64::MAX,
            maximum: u64::MAX,
        })?;
    add_index_bytes_v0(total, added)
}

fn measure_standalone_speculative_auth_plan_usage_v0(
    plan: &PlannedAuthUpdate,
) -> std::result::Result<SpeculativeAuthPathUsageV0, SpeculativeAuthPathErrorV0> {
    let node_batch = &plan.tree_update_batch.node_batch;
    let mut usage = SpeculativeAuthPathUsageV0 {
        node_facts: usize_to_u64_v0(node_batch.nodes().len())?,
        value_facts: usize_to_u64_v0(node_batch.values().len())?,
        preimage_facts: usize_to_u64_v0(plan.preimages.len())?,
        ..SpeculativeAuthPathUsageV0::default()
    };
    for (node_key, node) in node_batch.nodes() {
        add_borsh_index_bytes_v0(&mut usage.indexed_bytes, node_key, 1)?;
        add_borsh_index_bytes_v0(&mut usage.indexed_bytes, node, 1)?;
        if let Node::Leaf(leaf) = node {
            usage.leaf_facts = usage.leaf_facts.checked_add(1).ok_or(
                SpeculativeAuthPathErrorV0::ResourceLimit {
                    resource: SpeculativeAuthPathResourceV0::LeafFacts,
                    current: 0,
                    added: u64::MAX,
                    maximum: u64::MAX,
                },
            )?;
            add_borsh_index_bytes_v0(&mut usage.indexed_bytes, node_key, 1)?;
            add_index_bytes_v0(&mut usage.indexed_bytes, 32 + 8)?;
            add_borsh_index_bytes_v0(&mut usage.indexed_bytes, leaf, 1)?;
        }
    }
    for ((value_version, _), value) in node_batch.values() {
        if *value_version != plan.version {
            return Err(path_revalidation_error_v0(
                "speculative JMT value belongs to a foreign version",
            ));
        }
        add_index_bytes_v0(&mut usage.indexed_bytes, 32 + 8 + 1)?;
        if let Some(value) = value {
            add_index_bytes_v0(&mut usage.indexed_bytes, value.len())?;
        }
    }
    for preimage in plan.preimages.values() {
        add_index_bytes_v0(
            &mut usage.indexed_bytes,
            32 + std::mem::size_of::<usize>() + preimage.len(),
        )?;
    }
    usage.total_work_units = usage
        .node_facts
        .checked_add(usage.value_facts)
        .and_then(|total| total.checked_add(usage.preimage_facts))
        .and_then(|total| total.checked_add(usage.leaf_facts))
        .ok_or(SpeculativeAuthPathErrorV0::ResourceLimit {
            resource: SpeculativeAuthPathResourceV0::TotalWorkUnits,
            current: 0,
            added: u64::MAX,
            maximum: u64::MAX,
        })?;
    Ok(usage)
}

fn preflight_speculative_auth_usage_v0(
    current: SpeculativeAuthPathUsageV0,
    added: SpeculativeAuthPathUsageV0,
    limits: SpeculativeAuthPathLimitsV0,
) -> std::result::Result<(), SpeculativeAuthPathErrorV0> {
    for (resource, current, added, maximum) in [
        (
            SpeculativeAuthPathResourceV0::NodeFacts,
            current.node_facts,
            added.node_facts,
            limits.maximum_node_facts,
        ),
        (
            SpeculativeAuthPathResourceV0::ValueFacts,
            current.value_facts,
            added.value_facts,
            limits.maximum_value_facts,
        ),
        (
            SpeculativeAuthPathResourceV0::PreimageFacts,
            current.preimage_facts,
            added.preimage_facts,
            limits.maximum_preimage_facts,
        ),
        (
            SpeculativeAuthPathResourceV0::LeafFacts,
            current.leaf_facts,
            added.leaf_facts,
            limits.maximum_leaf_facts,
        ),
        (
            SpeculativeAuthPathResourceV0::IndexedBytes,
            current.indexed_bytes,
            added.indexed_bytes,
            limits.maximum_indexed_bytes,
        ),
        (
            SpeculativeAuthPathResourceV0::TotalWorkUnits,
            current.total_work_units,
            added.total_work_units,
            limits.maximum_total_work_units,
        ),
    ] {
        if current
            .checked_add(added)
            .is_none_or(|total| total > maximum)
        {
            return Err(SpeculativeAuthPathErrorV0::ResourceLimit {
                resource,
                current,
                added,
                maximum,
            });
        }
    }
    Ok(())
}

fn reserve_undo_keys_v0<T>(
    values: &mut Vec<T>,
    additional: usize,
    stage: &'static str,
) -> std::result::Result<(), SpeculativeAuthPathErrorV0> {
    values.try_reserve_exact(additional).map_err(|error| {
        SpeculativeAuthPathErrorV0::HostAllocation {
            stage,
            detail: error.to_string(),
        }
    })
}

fn speculative_auth_path_anchor_token_v0(
    version: Version,
    root: RootHash,
) -> SpeculativeAuthPathLayerTokenV0 {
    speculative_auth_path_token_v0(
        SPECULATIVE_AUTH_PATH_ANCHOR_TOKEN_DOMAIN_V0,
        &[&version.to_be_bytes(), root.as_ref()],
    )
}

fn speculative_auth_path_layer_token_v0(
    parent: SpeculativeAuthPathLayerTokenV0,
    version: Version,
    root: RootHash,
    commitment: [u8; DURABLE_AUTH_PLAN_COMMITMENT_BYTES_V0],
) -> SpeculativeAuthPathLayerTokenV0 {
    speculative_auth_path_token_v0(
        SPECULATIVE_AUTH_PATH_LAYER_TOKEN_DOMAIN_V0,
        &[
            &parent.0,
            &version.to_be_bytes(),
            root.as_ref(),
            &commitment,
        ],
    )
}

fn speculative_auth_path_token_v0(
    domain: &[u8],
    frames: &[&[u8]],
) -> SpeculativeAuthPathLayerTokenV0 {
    let mut hasher = Sha256::new();
    hasher.update((domain.len() as u64).to_be_bytes());
    hasher.update(domain);
    for frame in frames {
        hasher.update((frame.len() as u64).to_be_bytes());
        hasher.update(frame);
    }
    SpeculativeAuthPathLayerTokenV0(hasher.finalize().into())
}

/// Reproduces and retains one speculative plan only after exact-parent/root
/// and full physical-plan commitment verification.  This is deliberately
/// separate from the historical inert verifier above because a child block
/// needs a read layer for its exact parent, while no caller receives an
/// apply-capable [`PlannedAuthUpdate`].
#[cfg(test)]
pub(crate) fn replan_speculative_jmt_plan_v0<'a, R, I>(
    reader: &R,
    expected_next_version: Version,
    expected_parent_root: Option<RootHash>,
    expected_root_hash: RootHash,
    expected_commitment: [u8; DURABLE_AUTH_PLAN_COMMITMENT_BYTES_V0],
    writes: I,
) -> Result<RevalidatedSpeculativeAuthPlanV0>
where
    R: TreeReader,
    I: IntoIterator<Item = (&'a [u8], Option<&'a [u8]>)>,
{
    replan_speculative_jmt_plan_with_limits_v0(
        reader,
        expected_next_version,
        expected_parent_root,
        expected_root_hash,
        expected_commitment,
        writes,
        SpeculativeAuthPathLimitsV0::UNBOUNDED,
    )
    .map_err(anyhow::Error::new)
}

/// Reproduces one exact JMT plan under a host-local, version-bound resource
/// envelope.
///
/// The raw write count and bytes are checked before cloning the recipe or
/// invoking JMT, and the complete resulting plan is measured with the same
/// indexed accounting used by speculative lineage reconstruction before it is
/// released.  `jmt = 0.12.0` still performs infallible collection growth inside
/// `plan_put_value_set`; these checks bound admitted work and preserve typed
/// failures, but they are not a claim that allocator exhaustion can always be
/// recovered in-process.
#[allow(clippy::too_many_arguments)]
pub(crate) fn replan_speculative_jmt_plan_with_limits_v0<'a, R, I>(
    reader: &R,
    expected_next_version: Version,
    expected_parent_root: Option<RootHash>,
    expected_root_hash: RootHash,
    expected_commitment: [u8; DURABLE_AUTH_PLAN_COMMITMENT_BYTES_V0],
    writes: I,
    limits: SpeculativeAuthPathLimitsV0,
) -> std::result::Result<RevalidatedSpeculativeAuthPlanV0, SpeculativeAuthPathErrorV0>
where
    R: TreeReader,
    I: IntoIterator<Item = (&'a [u8], Option<&'a [u8]>)>,
{
    verify_parent_root_v0(reader, expected_next_version, expected_parent_root)
        .map_err(SpeculativeAuthPathErrorV0::Revalidation)?;
    let rebuilt = rebuild_raw_write_recipe_with_limits_v0(writes, limits)?;
    let plan = plan_put_value_set(
        reader,
        expected_next_version,
        expected_next_version,
        rebuilt,
    )
    .map_err(SpeculativeAuthPathErrorV0::Revalidation)?;
    if plan.root_hash != expected_root_hash {
        return Err(path_revalidation_error_v0(
            "speculative JMT root does not match canonical replanning",
        ));
    }
    if plan
        .durable_jmt_plan_commitment_v0()
        .map_err(SpeculativeAuthPathErrorV0::Revalidation)?
        != expected_commitment
    {
        return Err(path_revalidation_error_v0(
            "speculative JMT physical plan does not match its durable commitment",
        ));
    }
    let usage = measure_standalone_speculative_auth_plan_usage_v0(&plan)?;
    preflight_speculative_auth_usage_v0(SpeculativeAuthPathUsageV0::default(), usage, limits)?;
    Ok(RevalidatedSpeculativeAuthPlanV0 { plan })
}

/// Exact-parent/canonical-write verified plan that remains inert until the
/// current authoritative apply boundary rechecks head/root and target
/// occupancy.
#[allow(dead_code)]
pub(crate) struct RevalidatedDurablePlannedAuthUpdateV0<'a> {
    encoded: &'a [u8],
    target_version: Version,
    parent_root: Option<RootHash>,
    root_hash: RootHash,
}

#[allow(dead_code)]
impl RevalidatedDurablePlannedAuthUpdateV0<'_> {
    pub(crate) const fn root_hash_v0(&self) -> RootHash {
        self.root_hash
    }

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
            replanned.encode_durable_jmt_plan_v0()?.as_slice() == self.encoded,
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

fn rebuild_raw_write_recipe_v0<'a>(
    writes: impl IntoIterator<Item = (&'a [u8], Option<&'a [u8]>)>,
) -> Result<Vec<AuthWrite>> {
    let writes = writes.into_iter();
    let (minimum_write_count, maximum_write_count) = writes.size_hint();
    let mut rebuilt: Vec<AuthWrite> = Vec::new();
    rebuilt
        .try_reserve_exact(maximum_write_count.unwrap_or(minimum_write_count))
        .context("reserve durable write recipe entries")?;
    for (key, value) in writes {
        ensure!(
            !key.is_empty(),
            "durable write recipe contains an empty key"
        );
        ensure!(
            key.len() <= MAX_AUTH_KEY_PREIMAGE_BYTES,
            "durable write recipe key exceeds the preimage bound"
        );
        ensure!(
            value.is_none_or(|value| value.len() <= MAX_DURABLE_AUTH_PLAN_VALUE_BYTES_V0),
            "durable write recipe value exceeds the plan value bound"
        );
        if let Some(previous) = rebuilt.last() {
            ensure!(
                previous.key.as_slice() < key,
                "durable write recipe keys are not strictly canonical"
            );
        }
        rebuilt.push(AuthWrite {
            key: try_copy_plan_bytes_v0(key, "durable write recipe key")?,
            value: value
                .map(|value| try_copy_plan_bytes_v0(value, "durable write recipe value"))
                .transpose()?,
        });
    }
    Ok(rebuilt)
}

fn rebuild_raw_write_recipe_with_limits_v0<'a>(
    writes: impl IntoIterator<Item = (&'a [u8], Option<&'a [u8]>)>,
    limits: SpeculativeAuthPathLimitsV0,
) -> std::result::Result<Vec<AuthWrite>, SpeculativeAuthPathErrorV0> {
    let writes = writes.into_iter();
    let (minimum_write_count_usize, _) = writes.size_hint();
    let minimum_write_count = usize_to_u64_v0(minimum_write_count_usize)?;
    let minimum_work_units =
        minimum_write_count
            .checked_mul(2)
            .ok_or(SpeculativeAuthPathErrorV0::ResourceLimit {
                resource: SpeculativeAuthPathResourceV0::TotalWorkUnits,
                current: 0,
                added: u64::MAX,
                maximum: limits.maximum_total_work_units,
            })?;
    preflight_speculative_auth_usage_v0(
        SpeculativeAuthPathUsageV0::default(),
        SpeculativeAuthPathUsageV0 {
            value_facts: minimum_write_count,
            preimage_facts: minimum_write_count,
            total_work_units: minimum_work_units,
            ..SpeculativeAuthPathUsageV0::default()
        },
        limits,
    )?;

    let mut rebuilt: Vec<AuthWrite> = Vec::new();
    rebuilt
        .try_reserve_exact(minimum_write_count_usize)
        .map_err(|error| SpeculativeAuthPathErrorV0::HostAllocation {
            stage: "reserve bounded durable write recipe entries",
            detail: error.to_string(),
        })?;
    let mut raw_usage = SpeculativeAuthPathUsageV0::default();
    for (key, value) in writes {
        if key.is_empty() {
            return Err(path_revalidation_error_v0(
                "durable write recipe contains an empty key",
            ));
        }
        if key.len() > MAX_AUTH_KEY_PREIMAGE_BYTES {
            return Err(path_revalidation_error_v0(
                "durable write recipe key exceeds the preimage bound",
            ));
        }
        if value.is_some_and(|value| value.len() > MAX_DURABLE_AUTH_PLAN_VALUE_BYTES_V0) {
            return Err(path_revalidation_error_v0(
                "durable write recipe value exceeds the plan value bound",
            ));
        }
        if let Some(previous) = rebuilt.last() {
            if previous.key.as_slice() >= key {
                return Err(path_revalidation_error_v0(
                    "durable write recipe keys are not strictly canonical",
                ));
            }
        }

        raw_usage.preimage_facts = raw_usage.preimage_facts.checked_add(1).ok_or(
            SpeculativeAuthPathErrorV0::ResourceLimit {
                resource: SpeculativeAuthPathResourceV0::PreimageFacts,
                current: raw_usage.preimage_facts,
                added: 1,
                maximum: limits.maximum_preimage_facts,
            },
        )?;
        raw_usage.value_facts = raw_usage.value_facts.checked_add(1).ok_or(
            SpeculativeAuthPathErrorV0::ResourceLimit {
                resource: SpeculativeAuthPathResourceV0::ValueFacts,
                current: raw_usage.value_facts,
                added: 1,
                maximum: limits.maximum_value_facts,
            },
        )?;
        add_index_bytes_with_limit_v0(
            &mut raw_usage.indexed_bytes,
            key.len(),
            limits.maximum_indexed_bytes,
        )?;
        if let Some(value) = value {
            add_index_bytes_with_limit_v0(
                &mut raw_usage.indexed_bytes,
                value.len(),
                limits.maximum_indexed_bytes,
            )?;
        }
        raw_usage.total_work_units = raw_usage
            .preimage_facts
            .checked_add(raw_usage.value_facts)
            .ok_or(SpeculativeAuthPathErrorV0::ResourceLimit {
                resource: SpeculativeAuthPathResourceV0::TotalWorkUnits,
                current: 0,
                added: u64::MAX,
                maximum: limits.maximum_total_work_units,
            })?;
        preflight_speculative_auth_usage_v0(
            SpeculativeAuthPathUsageV0::default(),
            raw_usage,
            limits,
        )?;

        if rebuilt.len() == rebuilt.capacity() {
            rebuilt.try_reserve_exact(1).map_err(|error| {
                SpeculativeAuthPathErrorV0::HostAllocation {
                    stage: "grow bounded durable write recipe entries",
                    detail: error.to_string(),
                }
            })?;
        }
        rebuilt.push(AuthWrite {
            key: try_copy_plan_bytes_with_resource_error_v0(
                key,
                "copy bounded durable write recipe key",
            )?,
            value: value
                .map(|value| {
                    try_copy_plan_bytes_with_resource_error_v0(
                        value,
                        "copy bounded durable write recipe value",
                    )
                })
                .transpose()?,
        });
    }
    Ok(rebuilt)
}

fn try_copy_plan_bytes_with_resource_error_v0(
    value: &[u8],
    stage: &'static str,
) -> std::result::Result<Vec<u8>, SpeculativeAuthPathErrorV0> {
    let mut copied = Vec::new();
    copied.try_reserve_exact(value.len()).map_err(|error| {
        SpeculativeAuthPathErrorV0::HostAllocation {
            stage,
            detail: error.to_string(),
        }
    })?;
    copied.extend_from_slice(value);
    Ok(copied)
}

impl PlannedAuthUpdate {
    /// Streams the exact canonical v0 durable-plan record into SHA-256 without
    /// ever materializing the complete physical plan as one `Vec<u8>`.
    ///
    /// The commitment preimage is:
    ///
    /// `u16(domain_len) || domain || durable_plan_codec_v0_bytes`
    ///
    /// and therefore binds the app codec version, pinned JMT/Borsh layout,
    /// target version, root, and every node, value, stale index, and key
    /// preimage field in their canonical map/set order.
    pub(crate) fn durable_jmt_plan_commitment_v0(
        &self,
    ) -> Result<[u8; DURABLE_AUTH_PLAN_COMMITMENT_BYTES_V0]> {
        validate_plan_shape_v0(self)?;

        let mut commitment = DurableAuthPlanCommitmentWriterV0::new_v0()?;
        commitment.write_v0(&DURABLE_AUTH_PLAN_CODEC_VERSION_V0.to_be_bytes());
        commitment.write_u16_framed_v0(
            DURABLE_AUTH_PLAN_JMT_LAYOUT_V0,
            DURABLE_AUTH_PLAN_JMT_LAYOUT_V0.len(),
            "durable JMT layout identifier",
        )?;
        commitment.write_v0(&self.version.to_be_bytes());
        commitment.write_v0(&self.root_hash.0);

        let nodes = self.tree_update_batch.node_batch.nodes();
        commitment.write_count_v0(nodes.len(), "durable JMT node")?;
        for (node_key, node) in nodes {
            let node_key = borsh::to_vec(node_key).context("encode durable JMT node key")?;
            let node = borsh::to_vec(node).context("encode durable JMT node")?;
            commitment.write_u32_framed_v0(
                &node_key,
                MAX_DURABLE_AUTH_PLAN_NODE_KEY_BYTES_V0,
                "durable JMT node key",
            )?;
            commitment.write_u32_framed_v0(
                &node,
                MAX_DURABLE_AUTH_PLAN_NODE_BYTES_V0,
                "durable JMT node",
            )?;
        }

        let values = self.tree_update_batch.node_batch.values();
        commitment.write_count_v0(values.len(), "durable JMT value")?;
        for ((version, key_hash), value) in values {
            commitment.write_v0(&version.to_be_bytes());
            commitment.write_v0(&key_hash.0);
            match value {
                None => commitment.write_v0(&[0]),
                Some(value) => {
                    commitment.write_v0(&[1]);
                    commitment.write_u32_framed_v0(
                        value,
                        MAX_DURABLE_AUTH_PLAN_VALUE_BYTES_V0,
                        "durable JMT value",
                    )?;
                }
            }
        }

        let stale_indices = &self.tree_update_batch.stale_node_index_batch;
        commitment.write_count_v0(stale_indices.len(), "durable stale JMT index")?;
        for stale in stale_indices {
            commitment.write_v0(&stale.stale_since_version.to_be_bytes());
            let node_key =
                borsh::to_vec(&stale.node_key).context("encode durable stale JMT node key")?;
            commitment.write_u32_framed_v0(
                &node_key,
                MAX_DURABLE_AUTH_PLAN_NODE_KEY_BYTES_V0,
                "durable stale JMT node key",
            )?;
        }

        commitment.write_count_v0(self.preimages.len(), "durable JMT key preimage")?;
        for (key_hash, preimage) in &self.preimages {
            commitment.write_v0(&key_hash.0);
            commitment.write_u32_framed_v0(
                preimage,
                MAX_AUTH_KEY_PREIMAGE_BYTES,
                "durable JMT key preimage",
            )?;
        }
        Ok(commitment.finish_v0())
    }

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
    ) -> Result<UnverifiedDurablePlannedAuthUpdateV0<'_>> {
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
        let root_hash = RootHash(decoder.read_array_v0("durable JMT root hash")?);

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
            encoded,
            target_version: version,
            root_hash,
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

struct DurableAuthPlanCommitmentWriterV0 {
    hasher: Sha256,
}

impl DurableAuthPlanCommitmentWriterV0 {
    fn new_v0() -> Result<Self> {
        let domain_length = u16::try_from(DURABLE_AUTH_PLAN_COMMITMENT_DOMAIN_V0.len())
            .context("durable JMT commitment domain exceeds u16::MAX")?;
        let mut hasher = Sha256::new();
        hasher.update(domain_length.to_be_bytes());
        hasher.update(DURABLE_AUTH_PLAN_COMMITMENT_DOMAIN_V0);
        Ok(Self { hasher })
    }

    fn write_v0(&mut self, value: &[u8]) {
        self.hasher.update(value);
    }

    fn write_count_v0(&mut self, count: usize, label: &str) -> Result<()> {
        let count =
            u32::try_from(count).with_context(|| format!("{label} count exceeds u32::MAX"))?;
        self.write_v0(&count.to_be_bytes());
        Ok(())
    }

    fn write_u16_framed_v0(
        &mut self,
        value: &[u8],
        maximum_length: usize,
        label: &str,
    ) -> Result<()> {
        ensure!(
            value.len() <= maximum_length,
            "{label} exceeds {maximum_length} bytes"
        );
        let length =
            u16::try_from(value.len()).with_context(|| format!("{label} exceeds u16::MAX"))?;
        self.write_v0(&length.to_be_bytes());
        self.write_v0(value);
        Ok(())
    }

    fn write_u32_framed_v0(
        &mut self,
        value: &[u8],
        maximum_length: usize,
        label: &str,
    ) -> Result<()> {
        ensure!(
            value.len() <= maximum_length,
            "{label} exceeds {maximum_length} bytes"
        );
        let length =
            u32::try_from(value.len()).with_context(|| format!("{label} exceeds u32::MAX"))?;
        self.write_v0(&length.to_be_bytes());
        self.write_v0(value);
        Ok(())
    }

    fn finish_v0(self) -> [u8; DURABLE_AUTH_PLAN_COMMITMENT_BYTES_V0] {
        self.hasher.finalize().into()
    }
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
    if next_len > encoded.capacity() {
        encoded
            .try_reserve_exact(next_len - encoded.len())
            .with_context(|| format!("reserve memory for {label}"))?;
    }
    encoded.extend_from_slice(value);
    Ok(())
}

fn try_copy_plan_bytes_v0(value: &[u8], label: &str) -> Result<Vec<u8>> {
    let mut copied = Vec::new();
    copied
        .try_reserve_exact(value.len())
        .with_context(|| format!("reserve memory for {label}"))?;
    copied.extend_from_slice(value);
    Ok(copied)
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
    use std::{cell::Cell, ops::Range};

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

    #[test]
    fn speculative_plan_stack_reconstructs_only_its_exact_ancestor_lineage() {
        let key = account_key("speculative-lineage-key").expect("lineage key");
        let child_key = task_key("speculative-lineage-child").expect("child key");
        let mut base = InMemoryAuthTree::default();
        base.put_value_set(0, [put(key.clone(), b"committed")])
            .expect("committed base");

        let first_writes = vec![put(key.clone(), b"first")];
        let first_plan = base
            .plan_put_value_set(1, first_writes.clone())
            .expect("first speculative plan");
        let first_commitment = first_plan
            .durable_jmt_plan_commitment_v0()
            .expect("first commitment");
        let first = replan_speculative_jmt_plan_v0(
            &base,
            1,
            base.root_hash(0),
            first_plan.root_hash,
            first_commitment,
            first_writes
                .iter()
                .map(|write| (write.key(), write.value())),
        )
        .expect("reproduce first speculative plan");

        let first_layers = [first];
        let first_reader = SpeculativeAuthPlanStackReaderV0::new_v0(&base, &first_layers);
        let second_writes = vec![
            put(key.clone(), b"second"),
            put(child_key.clone(), b"child"),
        ];
        let second_plan = plan_put_value_set(&first_reader, 2, 2, second_writes.clone())
            .expect("second speculative plan");
        let second_commitment = second_plan
            .durable_jmt_plan_commitment_v0()
            .expect("second commitment");
        let second = replan_speculative_jmt_plan_v0(
            &first_reader,
            2,
            Some(first_layers[0].root_hash_v0()),
            second_plan.root_hash,
            second_commitment,
            second_writes
                .iter()
                .map(|write| (write.key(), write.value())),
        )
        .expect("reproduce child speculative plan");

        let layers = [
            first_layers.into_iter().next().expect("first layer"),
            second,
        ];
        let reader = SpeculativeAuthPlanStackReaderV0::new_v0(&base, &layers);
        assert_eq!(
            reader
                .get_value_option(2, key_hash(&key).expect("key hash"))
                .expect("read child value"),
            Some(b"second".to_vec())
        );
        assert_eq!(
            reader
                .get_value_option(2, key_hash(&child_key).expect("child hash"))
                .expect("read new child value"),
            Some(b"child".to_vec())
        );
        assert_eq!(layers[0].version_v0(), 1);
        assert_eq!(layers[1].version_v0(), 2);
    }

    #[test]
    fn same_height_sibling_plan_stacks_never_merge() {
        let key = account_key("speculative-sibling-key").expect("sibling key");
        let mut base = InMemoryAuthTree::default();
        base.put_value_set(0, [put(key.clone(), b"committed")])
            .expect("committed base");

        let left_writes = vec![put(key.clone(), b"left")];
        let right_writes = vec![put(key.clone(), b"right")];
        let left_plan = base
            .plan_put_value_set(1, left_writes.clone())
            .expect("left sibling plan");
        let right_plan = base
            .plan_put_value_set(1, right_writes.clone())
            .expect("right sibling plan");
        assert_ne!(left_plan.root_hash, right_plan.root_hash);

        let left = replan_speculative_jmt_plan_v0(
            &base,
            1,
            base.root_hash(0),
            left_plan.root_hash,
            left_plan
                .durable_jmt_plan_commitment_v0()
                .expect("left commitment"),
            left_writes.iter().map(|write| (write.key(), write.value())),
        )
        .expect("reproduce left sibling");
        let right = replan_speculative_jmt_plan_v0(
            &base,
            1,
            base.root_hash(0),
            right_plan.root_hash,
            right_plan
                .durable_jmt_plan_commitment_v0()
                .expect("right commitment"),
            right_writes
                .iter()
                .map(|write| (write.key(), write.value())),
        )
        .expect("reproduce right sibling");
        let left_layers = [left];
        let right_layers = [right];
        let left_reader = SpeculativeAuthPlanStackReaderV0::new_v0(&base, &left_layers);
        let right_reader = SpeculativeAuthPlanStackReaderV0::new_v0(&base, &right_layers);
        let key_hash = key_hash(&key).expect("sibling key hash");
        assert_eq!(
            left_reader
                .get_value_option(1, key_hash)
                .expect("left value"),
            Some(b"left".to_vec())
        );
        assert_eq!(
            right_reader
                .get_value_option(1, key_hash)
                .expect("right value"),
            Some(b"right".to_vec())
        );
    }

    struct CountingTreeReaderV0<'a> {
        inner: &'a InMemoryAuthTree,
        node_reads: Cell<usize>,
        value_reads: Cell<usize>,
        rightmost_reads: Cell<usize>,
        preimage_reads: Cell<usize>,
    }

    impl<'a> CountingTreeReaderV0<'a> {
        fn new_v0(inner: &'a InMemoryAuthTree) -> Self {
            Self {
                inner,
                node_reads: Cell::new(0),
                value_reads: Cell::new(0),
                rightmost_reads: Cell::new(0),
                preimage_reads: Cell::new(0),
            }
        }

        fn reset_v0(&self) {
            self.node_reads.set(0);
            self.value_reads.set(0);
            self.rightmost_reads.set(0);
            self.preimage_reads.set(0);
        }
    }

    impl TreeReader for CountingTreeReaderV0<'_> {
        fn get_node_option(&self, node_key: &NodeKey) -> Result<Option<Node>> {
            self.node_reads.set(self.node_reads.get() + 1);
            self.inner.get_node_option(node_key)
        }

        fn get_value_option(
            &self,
            max_version: Version,
            key_hash: KeyHash,
        ) -> Result<Option<Vec<u8>>> {
            self.value_reads.set(self.value_reads.get() + 1);
            self.inner.get_value_option(max_version, key_hash)
        }

        fn get_rightmost_leaf(&self) -> Result<Option<(NodeKey, LeafNode)>> {
            self.rightmost_reads.set(self.rightmost_reads.get() + 1);
            self.inner.get_rightmost_leaf()
        }
    }

    impl HasPreimage for CountingTreeReaderV0<'_> {
        fn preimage(&self, key_hash: KeyHash) -> Result<Option<Vec<u8>>> {
            self.preimage_reads.set(self.preimage_reads.get() + 1);
            self.inner.preimage(key_hash)
        }
    }

    fn revalidated_speculative_plan_v0<R: TreeReader>(
        reader: &R,
        version: Version,
        parent_root: Option<RootHash>,
        writes: &[AuthWrite],
    ) -> RevalidatedSpeculativeAuthPlanV0 {
        let planned = plan_put_value_set(reader, version, version, writes.to_vec())
            .expect("plan indexed speculative layer");
        let commitment = planned
            .durable_jmt_plan_commitment_v0()
            .expect("commit indexed speculative layer");
        replan_speculative_jmt_plan_v0(
            reader,
            version,
            parent_root,
            planned.root_hash,
            commitment,
            writes.iter().map(|write| (write.key(), write.value())),
        )
        .expect("revalidate indexed speculative layer")
    }

    fn speculative_auth_path_limits_for_test_v0() -> SpeculativeAuthPathLimitsV0 {
        SpeculativeAuthPathLimitsV0::new_v0(
            u64::MAX,
            u64::MAX,
            u64::MAX,
            u64::MAX,
            u64::MAX,
            u64::MAX,
        )
    }

    fn speculative_auth_path_for_test_v0<R: TreeReader>(
        base: &R,
        anchor_version: Version,
        anchor_root: RootHash,
    ) -> RevalidatedSpeculativeAuthPathV0 {
        RevalidatedSpeculativeAuthPathV0::new_v0(
            base,
            anchor_version,
            anchor_root,
            speculative_auth_path_limits_for_test_v0(),
        )
        .expect("open indexed speculative path fixture")
    }

    fn replan_and_push_fixture_v0<R: TreeReader>(
        base: &R,
        path: &mut RevalidatedSpeculativeAuthPathV0,
        verified: RevalidatedSpeculativeAuthPlanV0,
        writes: &[AuthWrite],
    ) -> RevalidatedSpeculativeAuthPathFrameV0 {
        let expected_version = verified.version_v0();
        let expected_root = verified.root_hash_v0();
        let expected_commitment = verified
            .plan
            .durable_jmt_plan_commitment_v0()
            .expect("commit indexed speculative fixture");
        let expected_parent_root = path.tip_root_v0();
        path.replan_and_push_v0(
            base,
            expected_version,
            expected_parent_root,
            expected_root,
            expected_commitment,
            writes.iter().map(|write| (write.key(), write.value())),
        )
        .expect("replan and push indexed speculative fixture")
    }

    type SpeculativeAuthPathValueSnapshotV0 = ([u8; 32], Vec<(Version, Option<Vec<u8>>)>);
    type SpeculativeAuthPathLeafSnapshotV0 = ([u8; 32], Version, Vec<u8>, Vec<u8>);

    #[derive(Debug, Eq, PartialEq)]
    struct SpeculativeAuthPathSnapshotV0 {
        nodes: Vec<(Vec<u8>, Vec<u8>)>,
        values: Vec<SpeculativeAuthPathValueSnapshotV0>,
        preimages: Vec<([u8; 32], Vec<u8>, usize)>,
        leaves: Vec<SpeculativeAuthPathLeafSnapshotV0>,
        tip_version: Version,
        tip_root: [u8; 32],
        tip_layer_token: [u8; 32],
        limits: [u64; 6],
        usage: [u64; 6],
    }

    fn speculative_auth_path_snapshot_v0(
        path: &RevalidatedSpeculativeAuthPathV0,
    ) -> SpeculativeAuthPathSnapshotV0 {
        SpeculativeAuthPathSnapshotV0 {
            nodes: path
                .nodes
                .iter()
                .map(|(key, node)| {
                    (
                        borsh::to_vec(key).expect("encode indexed snapshot node key"),
                        borsh::to_vec(node).expect("encode indexed snapshot node"),
                    )
                })
                .collect(),
            values: path
                .values
                .iter()
                .map(|(key_hash, versions)| {
                    (
                        key_hash.0,
                        versions
                            .iter()
                            .map(|(version, value)| (*version, value.clone()))
                            .collect(),
                    )
                })
                .collect(),
            preimages: path
                .preimages
                .iter()
                .map(|(key_hash, preimage)| {
                    (key_hash.0, preimage.bytes.clone(), preimage.references)
                })
                .collect(),
            leaves: path
                .leaves
                .iter()
                .map(|((key_hash, version, node_key), leaf)| {
                    (
                        key_hash.0,
                        *version,
                        borsh::to_vec(node_key).expect("encode indexed snapshot leaf node key"),
                        borsh::to_vec(leaf).expect("encode indexed snapshot leaf"),
                    )
                })
                .collect(),
            tip_version: path.tip_version,
            tip_root: path.tip_root.0,
            tip_layer_token: path.tip_layer_token.0,
            limits: [
                path.limits.maximum_node_facts,
                path.limits.maximum_value_facts,
                path.limits.maximum_preimage_facts,
                path.limits.maximum_leaf_facts,
                path.limits.maximum_indexed_bytes,
                path.limits.maximum_total_work_units,
            ],
            usage: [
                path.usage.node_facts,
                path.usage.value_facts,
                path.usage.preimage_facts,
                path.usage.leaf_facts,
                path.usage.indexed_bytes,
                path.usage.total_work_units,
            ],
        }
    }

    fn duplicate_speculative_auth_path_frame_for_test_v0(
        frame: &RevalidatedSpeculativeAuthPathFrameV0,
    ) -> RevalidatedSpeculativeAuthPathFrameV0 {
        RevalidatedSpeculativeAuthPathFrameV0 {
            version: frame.version,
            root: frame.root,
            layer_token: frame.layer_token,
            parent_version: frame.parent_version,
            parent_root: frame.parent_root,
            parent_layer_token: frame.parent_layer_token,
            node_keys: frame.node_keys.clone(),
            value_keys: frame.value_keys.clone(),
            preimage_keys: frame.preimage_keys.clone(),
            leaf_keys: frame.leaf_keys.clone(),
            layer_usage: frame.layer_usage,
        }
    }

    fn expect_speculative_auth_path_error_v0<T>(
        result: std::result::Result<T, SpeculativeAuthPathErrorV0>,
        message: &'static str,
    ) -> SpeculativeAuthPathErrorV0 {
        match result {
            Ok(_) => panic!("{message}"),
            Err(error) => error,
        }
    }

    #[test]
    fn indexed_speculative_path_pop_isolates_same_height_siblings() {
        let shared_key = account_key("indexed-sibling-shared").expect("shared key");
        let left_only = task_key("indexed-sibling-left").expect("left-only key");
        let right_only = task_key("indexed-sibling-right").expect("right-only key");
        let mut base = InMemoryAuthTree::default();
        base.put_value_set(0, [put(shared_key.clone(), b"committed")])
            .expect("committed sibling base");

        let left_writes = vec![
            put(shared_key.clone(), b"left"),
            put(left_only.clone(), b"left-only"),
        ];
        let right_writes = vec![
            put(shared_key.clone(), b"right"),
            put(right_only.clone(), b"right-only"),
        ];
        let anchor_root = base.root_hash(0).expect("committed sibling root");
        let left = revalidated_speculative_plan_v0(&base, 1, Some(anchor_root), &left_writes);
        let right = revalidated_speculative_plan_v0(&base, 1, Some(anchor_root), &right_writes);

        let mut path = speculative_auth_path_for_test_v0(&base, 0, anchor_root);
        let left_frame = replan_and_push_fixture_v0(&base, &mut path, left, &left_writes);
        let work_after_left = path.usage.total_work_units;
        assert!(work_after_left > 0);
        {
            let reader = SpeculativeAuthPathReaderV0::new_v0(&base, &path);
            assert_eq!(
                reader
                    .get_value_option(1, key_hash(&shared_key).expect("shared hash"))
                    .expect("read left shared value"),
                Some(b"left".to_vec())
            );
            assert_eq!(
                reader
                    .get_value_option(1, key_hash(&left_only).expect("left hash"))
                    .expect("read left-only value"),
                Some(b"left-only".to_vec())
            );
            assert_eq!(
                reader
                    .get_value_option(1, key_hash(&right_only).expect("right hash"))
                    .expect("right sibling must be absent"),
                None
            );
        }
        path.pop_verified_plan_v0(left_frame)
            .expect("pop left sibling");
        assert_eq!(path.usage.total_work_units, work_after_left);
        assert!(path.nodes.is_empty());
        assert!(path.values.is_empty());
        assert!(path.preimages.is_empty());
        assert!(path.leaves.is_empty());
        assert_eq!(path.tip_version_v0(), 0);

        let right_frame = replan_and_push_fixture_v0(&base, &mut path, right, &right_writes);
        let work_after_right = path.usage.total_work_units;
        assert!(work_after_right > work_after_left);
        {
            let reader = SpeculativeAuthPathReaderV0::new_v0(&base, &path);
            assert_eq!(
                reader
                    .get_value_option(1, key_hash(&shared_key).expect("shared hash"))
                    .expect("read right shared value"),
                Some(b"right".to_vec())
            );
            assert_eq!(
                reader
                    .get_value_option(1, key_hash(&right_only).expect("right hash"))
                    .expect("read right-only value"),
                Some(b"right-only".to_vec())
            );
            assert_eq!(
                reader
                    .get_value_option(1, key_hash(&left_only).expect("left hash"))
                    .expect("popped left sibling must remain absent"),
                None
            );
        }
        path.pop_verified_plan_v0(right_frame)
            .expect("pop right sibling");
        assert_eq!(path.usage.total_work_units, work_after_right);
        let reader = SpeculativeAuthPathReaderV0::new_v0(&base, &path);
        assert_eq!(
            reader
                .get_value_option(1, key_hash(&shared_key).expect("shared hash"))
                .expect("read committed value after sibling pops"),
            Some(b"committed".to_vec())
        );
    }

    #[test]
    fn indexed_speculative_path_deep_lookup_uses_keyed_state_and_exact_preimage_refcounts() {
        const DEPTH: Version = 32;

        let committed_key = account_key("indexed-depth-committed").expect("committed key");
        let deleted_key = account_key("indexed-depth-deleted").expect("deleted key");
        let speculative_key = task_key("indexed-depth-shared").expect("speculative key");
        let missing_key = task_key("indexed-depth-missing").expect("missing key");
        let mut base_tree = InMemoryAuthTree::default();
        base_tree
            .put_value_set(
                0,
                [
                    put(committed_key, b"committed"),
                    put(deleted_key.clone(), b"delete-me"),
                ],
            )
            .expect("committed deep base");
        let base = CountingTreeReaderV0::new_v0(&base_tree);
        let anchor_root = base_tree.root_hash(0).expect("committed deep root");
        let mut path = speculative_auth_path_for_test_v0(&base, 0, anchor_root);
        let mut frames = Vec::new();
        let mut parent_root = anchor_root;

        for version in 1..=DEPTH {
            let value = format!("value-{version}");
            let mut writes = vec![put(speculative_key.clone(), value.as_bytes())];
            if version == 1 {
                writes.push(AuthWrite::delete(deleted_key.clone()).expect("delete indexed key"));
            }
            writes.sort_by(|left, right| left.key().cmp(right.key()));
            let verified = {
                let reader = SpeculativeAuthPathReaderV0::new_v0(&base, &path);
                revalidated_speculative_plan_v0(&reader, version, Some(parent_root), &writes)
            };
            parent_root = verified.root_hash_v0();
            frames.push(replan_and_push_fixture_v0(
                &base, &mut path, verified, &writes,
            ));
        }

        let speculative_hash = key_hash(&speculative_key).expect("speculative hash");
        assert_eq!(path.tip_version_v0(), DEPTH);
        assert_eq!(
            path.values
                .get(&speculative_hash)
                .expect("indexed versions")
                .len(),
            usize::try_from(DEPTH).expect("depth fits usize")
        );
        assert_eq!(
            path.preimages
                .get(&speculative_hash)
                .expect("indexed shared preimage")
                .references,
            usize::try_from(DEPTH).expect("depth fits usize")
        );

        base.reset_v0();
        {
            let reader = SpeculativeAuthPathReaderV0::new_v0(&base, &path);
            assert_eq!(
                reader
                    .get_value_option(1, speculative_hash)
                    .expect("read first indexed version"),
                Some(b"value-1".to_vec())
            );
            assert_eq!(
                reader
                    .get_value_option(DEPTH, speculative_hash)
                    .expect("read deepest indexed version"),
                Some(format!("value-{DEPTH}").into_bytes())
            );
            assert_eq!(
                reader
                    .preimage(speculative_hash)
                    .expect("read indexed preimage"),
                Some(speculative_key.clone())
            );
            let indexed_node_key = path.nodes.keys().next().expect("indexed node key").clone();
            assert!(reader
                .get_node_option(&indexed_node_key)
                .expect("read indexed node")
                .is_some());
            assert_eq!(base.value_reads.get(), 0);
            assert_eq!(base.preimage_reads.get(), 0);
            assert_eq!(base.node_reads.get(), 0);

            assert_eq!(
                reader
                    .get_value_option(DEPTH, key_hash(&deleted_key).expect("deleted hash"))
                    .expect("read indexed tombstone"),
                None
            );
            assert_eq!(base.value_reads.get(), 0);

            assert_eq!(
                reader
                    .get_value_option(DEPTH, key_hash(&missing_key).expect("missing hash"))
                    .expect("read missing value"),
                None
            );
            assert_eq!(base.value_reads.get(), 1);
        }

        while let Some(frame) = frames.pop() {
            path.pop_verified_plan_v0(frame)
                .expect("pop deep indexed layer");
        }
        assert!(path.nodes.is_empty());
        assert!(path.values.is_empty());
        assert!(path.preimages.is_empty());
        assert!(path.leaves.is_empty());
        assert_eq!(path.tip_version_v0(), 0);
    }

    #[test]
    fn indexed_speculative_path_rejects_out_of_order_foreign_and_double_pop_without_mutation() {
        let key = account_key("indexed-frame-order").expect("frame-order key");
        let mut base = InMemoryAuthTree::default();
        base.put_value_set(0, [put(key.clone(), b"committed")])
            .expect("committed frame-order base");
        let anchor_root = base.root_hash(0).expect("committed frame-order root");
        let first_writes = vec![put(key.clone(), b"first")];
        let first = revalidated_speculative_plan_v0(&base, 1, Some(anchor_root), &first_writes);
        let mut path = speculative_auth_path_for_test_v0(&base, 0, anchor_root);
        let first_frame = replan_and_push_fixture_v0(&base, &mut path, first, &first_writes);

        let second_writes = vec![put(key, b"second")];
        let second = {
            let reader = SpeculativeAuthPathReaderV0::new_v0(&base, &path);
            revalidated_speculative_plan_v0(&reader, 2, Some(path.tip_root_v0()), &second_writes)
        };
        let second_frame = replan_and_push_fixture_v0(&base, &mut path, second, &second_writes);
        let total_work_after_two_pushes = path.usage.total_work_units;

        let before_out_of_order = speculative_auth_path_snapshot_v0(&path);
        let out_of_order = duplicate_speculative_auth_path_frame_for_test_v0(&first_frame);
        let error = path
            .pop_verified_plan_v0(out_of_order)
            .expect_err("ancestor frame must not pop through its child");
        assert!(error.to_string().contains("not the current exact layer"));
        assert_eq!(
            speculative_auth_path_snapshot_v0(&path),
            before_out_of_order
        );

        let already_popped = duplicate_speculative_auth_path_frame_for_test_v0(&second_frame);
        path.pop_verified_plan_v0(second_frame)
            .expect("pop current child frame");
        assert_eq!(path.usage.total_work_units, total_work_after_two_pushes);
        let before_double_pop = speculative_auth_path_snapshot_v0(&path);
        let error = path
            .pop_verified_plan_v0(already_popped)
            .expect_err("popped child frame must not be accepted twice");
        assert!(error.to_string().contains("not the current exact layer"));
        assert_eq!(speculative_auth_path_snapshot_v0(&path), before_double_pop);

        let mut foreign = duplicate_speculative_auth_path_frame_for_test_v0(&first_frame);
        foreign.layer_token.0[0] ^= 0x80;
        let before_foreign = speculative_auth_path_snapshot_v0(&path);
        let error = path
            .pop_verified_plan_v0(foreign)
            .expect_err("foreign frame token must be rejected");
        assert!(error.to_string().contains("not the current exact layer"));
        assert_eq!(speculative_auth_path_snapshot_v0(&path), before_foreign);

        path.pop_verified_plan_v0(first_frame)
            .expect("pop current ancestor frame");
        assert_eq!(path.usage.total_work_units, total_work_after_two_pushes);
        assert_eq!(path.tip_version_v0(), 0);
    }

    #[test]
    fn indexed_speculative_path_exact_limits_pass_and_cap_plus_one_preserves_state() {
        let key = task_key("indexed-exact-cap").expect("exact-cap key");
        let mut base = InMemoryAuthTree::default();
        base.put_value_set(
            0,
            [put(
                account_key("indexed-exact-cap-base").expect("exact-cap base key"),
                b"base",
            )],
        )
        .expect("committed exact-cap base");
        let anchor_root = base.root_hash(0).expect("committed exact-cap root");
        let writes = vec![put(key, b"speculative")];
        let planned = base
            .plan_put_value_set(1, writes.clone())
            .expect("plan exact-cap layer");
        let expected_root = planned.root_hash;
        let expected_commitment = planned
            .durable_jmt_plan_commitment_v0()
            .expect("commit exact-cap layer");

        let mut measuring_path = speculative_auth_path_for_test_v0(&base, 0, anchor_root);
        let measured_frame = measuring_path
            .replan_and_push_v0(
                &base,
                1,
                anchor_root,
                expected_root,
                expected_commitment,
                writes.iter().map(|write| (write.key(), write.value())),
            )
            .expect("measure exact-cap layer");
        let layer = measured_frame.layer_usage;
        assert!(layer.indexed_bytes > 0);

        let exact_limits = SpeculativeAuthPathLimitsV0::new_v0(
            layer.node_facts,
            layer.value_facts,
            layer.preimage_facts,
            layer.leaf_facts,
            layer.indexed_bytes,
            layer.total_work_units,
        );
        let mut exact_path =
            RevalidatedSpeculativeAuthPathV0::new_v0(&base, 0, anchor_root, exact_limits)
                .expect("open exact-cap indexed path");
        let exact_frame = exact_path
            .replan_and_push_v0(
                &base,
                1,
                anchor_root,
                expected_root,
                expected_commitment,
                writes.iter().map(|write| (write.key(), write.value())),
            )
            .expect("all exact indexed caps must pass");
        exact_path
            .pop_verified_plan_v0(exact_frame)
            .expect("pop exact-cap layer");

        let too_small_limits = SpeculativeAuthPathLimitsV0::new_v0(
            layer.node_facts,
            layer.value_facts,
            layer.preimage_facts,
            layer.leaf_facts,
            layer.indexed_bytes - 1,
            layer.total_work_units,
        );
        let mut limited_path =
            RevalidatedSpeculativeAuthPathV0::new_v0(&base, 0, anchor_root, too_small_limits)
                .expect("open cap-plus-one indexed path");
        let before_limit = speculative_auth_path_snapshot_v0(&limited_path);
        let error = expect_speculative_auth_path_error_v0(
            limited_path.replan_and_push_v0(
                &base,
                1,
                anchor_root,
                expected_root,
                expected_commitment,
                writes.iter().map(|write| (write.key(), write.value())),
            ),
            "one indexed byte above the cap must fail",
        );
        assert!(matches!(
            error,
            SpeculativeAuthPathErrorV0::ResourceLimit {
                resource: SpeculativeAuthPathResourceV0::IndexedBytes,
                ..
            }
        ));
        assert_eq!(
            speculative_auth_path_snapshot_v0(&limited_path),
            before_limit
        );

        let mut wrong_commitment = expected_commitment;
        wrong_commitment[0] ^= 0x01;
        let before_commitment = speculative_auth_path_snapshot_v0(&limited_path);
        let error = expect_speculative_auth_path_error_v0(
            limited_path.replan_and_push_v0(
                &base,
                1,
                anchor_root,
                expected_root,
                wrong_commitment,
                writes.iter().map(|write| (write.key(), write.value())),
            ),
            "wrong physical-plan commitment must fail before install",
        );
        assert!(matches!(error, SpeculativeAuthPathErrorV0::Revalidation(_)));
        assert_eq!(
            speculative_auth_path_snapshot_v0(&limited_path),
            before_commitment
        );
    }

    #[test]
    fn bounded_apply_replanning_accepts_exact_cap_and_rejects_cap_plus_one_without_state_change() {
        let key = task_key("bounded-apply-exact-cap").expect("bounded apply key");
        let mut base = InMemoryAuthTree::default();
        base.put_value_set(
            0,
            [put(
                account_key("bounded-apply-base").expect("bounded apply base key"),
                b"base",
            )],
        )
        .expect("committed bounded apply base");
        let anchor_root = base.root_hash(0).expect("bounded apply base root");
        let writes = vec![put(key, b"bounded-apply-value")];
        let planned = base
            .plan_put_value_set(1, writes.clone())
            .expect("plan bounded apply target");
        let expected_root = planned.root_hash;
        let expected_commitment = planned
            .durable_jmt_plan_commitment_v0()
            .expect("commit bounded apply target");
        let before = base.encode_snapshot().expect("snapshot bounded apply base");

        let measured = replan_speculative_jmt_plan_with_limits_v0(
            &base,
            1,
            Some(anchor_root),
            expected_root,
            expected_commitment,
            writes.iter().map(|write| (write.key(), write.value())),
            SpeculativeAuthPathLimitsV0::UNBOUNDED,
        )
        .expect("measure bounded apply target");
        let usage = measure_standalone_speculative_auth_plan_usage_v0(&measured.plan)
            .expect("measure bounded apply resource usage");
        assert!(usage.indexed_bytes > 0);
        let exact_limits = SpeculativeAuthPathLimitsV0::new_v0(
            usage.node_facts,
            usage.value_facts,
            usage.preimage_facts,
            usage.leaf_facts,
            usage.indexed_bytes,
            usage.total_work_units,
        );
        replan_speculative_jmt_plan_with_limits_v0(
            &base,
            1,
            Some(anchor_root),
            expected_root,
            expected_commitment,
            writes.iter().map(|write| (write.key(), write.value())),
            exact_limits,
        )
        .expect("the exact bounded apply cap must pass");
        assert_eq!(
            base.encode_snapshot().expect("snapshot exact-cap base"),
            before,
            "exact-cap replanning mutated its authenticated base",
        );

        let cap_plus_one_limits = SpeculativeAuthPathLimitsV0::new_v0(
            usage.node_facts,
            usage.value_facts,
            usage.preimage_facts,
            usage.leaf_facts,
            usage.indexed_bytes - 1,
            usage.total_work_units,
        );
        let error = match replan_speculative_jmt_plan_with_limits_v0(
            &base,
            1,
            Some(anchor_root),
            expected_root,
            expected_commitment,
            writes.iter().map(|write| (write.key(), write.value())),
            cap_plus_one_limits,
        ) {
            Ok(_) => panic!("one indexed byte above the bounded apply cap unexpectedly passed"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            SpeculativeAuthPathErrorV0::ResourceLimit {
                resource: SpeculativeAuthPathResourceV0::IndexedBytes,
                ..
            }
        ));
        assert_eq!(
            base.encode_snapshot().expect("snapshot rejected-cap base"),
            before,
            "cap-plus-one replanning mutated its authenticated base",
        );
    }

    #[test]
    fn indexed_speculative_path_rejects_foreign_base_when_authenticated_replanning_changes() {
        let key = account_key("indexed-foreign-base").expect("foreign-base key");
        let mut base = InMemoryAuthTree::default();
        base.put_value_set(0, [put(key.clone(), b"committed")])
            .expect("committed primary base");
        let anchor_root = base.root_hash(0).expect("committed primary root");
        let writes = vec![put(key.clone(), b"child")];
        let planned = base
            .plan_put_value_set(1, writes.clone())
            .expect("plan primary child");
        let expected_commitment = planned
            .durable_jmt_plan_commitment_v0()
            .expect("commit primary child");

        let mut foreign = InMemoryAuthTree::default();
        foreign
            .put_value_set(0, [put(key, b"foreign")])
            .expect("committed foreign base");
        assert_ne!(foreign.root_hash(0), Some(anchor_root));

        let mut path = speculative_auth_path_for_test_v0(&base, 0, anchor_root);
        let before = speculative_auth_path_snapshot_v0(&path);
        let error = expect_speculative_auth_path_error_v0(
            path.replan_and_push_v0(
                &foreign,
                1,
                anchor_root,
                planned.root_hash,
                expected_commitment,
                writes.iter().map(|write| (write.key(), write.value())),
            ),
            "foreign base must fail exact parent replanning",
        );
        assert!(matches!(error, SpeculativeAuthPathErrorV0::Revalidation(_)));
        assert_eq!(speculative_auth_path_snapshot_v0(&path), before);
    }

    #[test]
    fn indexed_speculative_linear_append_retains_no_pop_authority() {
        let key = account_key("indexed-linear-append").expect("linear-append key");
        let mut base = InMemoryAuthTree::default();
        base.put_value_set(0, [put(key.clone(), b"committed")])
            .expect("committed linear-append base");
        let anchor_root = base.root_hash(0).expect("committed linear-append root");
        let first_writes = vec![put(key.clone(), b"first")];
        let first = revalidated_speculative_plan_v0(&base, 1, Some(anchor_root), &first_writes);
        let mut path = speculative_auth_path_for_test_v0(&base, 0, anchor_root);
        let first_frame = replan_and_push_fixture_v0(&base, &mut path, first, &first_writes);

        let second_writes = vec![put(key.clone(), b"second")];
        let second_plan = {
            let reader = SpeculativeAuthPathReaderV0::new_v0(&base, &path);
            plan_put_value_set(&reader, 2, 2, second_writes.clone())
                .expect("plan linear append tip")
        };
        let second_root = second_plan.root_hash;
        let second_commitment = second_plan
            .durable_jmt_plan_commitment_v0()
            .expect("commit linear append tip");

        let mut reversible_path = speculative_auth_path_for_test_v0(&base, 0, anchor_root);
        let comparison_first =
            revalidated_speculative_plan_v0(&base, 1, Some(anchor_root), &first_writes);
        let _comparison_first_frame = replan_and_push_fixture_v0(
            &base,
            &mut reversible_path,
            comparison_first,
            &first_writes,
        );
        let reversible_second_parent_root = reversible_path.tip_root_v0();
        let reversible_second_frame = reversible_path
            .replan_and_push_v0(
                &base,
                2,
                reversible_second_parent_root,
                second_root,
                second_commitment,
                second_writes
                    .iter()
                    .map(|write| (write.key(), write.value())),
            )
            .expect("push comparison reversible tip");
        let reversible_second_indexed_bytes = reversible_second_frame.layer_usage.indexed_bytes;

        let indexed_bytes_before_append = path.usage.indexed_bytes;
        let second_parent_root = path.tip_root_v0();
        path.replan_and_append_tip_v0(
            &base,
            2,
            second_parent_root,
            second_root,
            second_commitment,
            second_writes
                .iter()
                .map(|write| (write.key(), write.value())),
        )
        .expect("append exact linear tip");
        assert_eq!(path.tip_version_v0(), 2);
        let append_indexed_bytes = path.usage.indexed_bytes - indexed_bytes_before_append;
        assert!(append_indexed_bytes < reversible_second_indexed_bytes);

        let before_old_pop = speculative_auth_path_snapshot_v0(&path);
        let error = path
            .pop_verified_plan_v0(first_frame)
            .expect_err("an older reversible frame must not pop through an appended tip");
        assert!(error.to_string().contains("not the current exact layer"));
        assert_eq!(speculative_auth_path_snapshot_v0(&path), before_old_pop);

        let reader = SpeculativeAuthPathReaderV0::new_v0(&base, &path);
        assert_eq!(
            reader
                .get_value_option(2, key_hash(&key).expect("linear-append hash"))
                .expect("read appended tip"),
            Some(b"second".to_vec())
        );
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
    fn durable_jmt_plan_commitment_streams_the_exact_canonical_record_v0() {
        let (_, _, plan) = fixture();
        let encoded = plan.encode_durable_jmt_plan_v0().expect("encode plan");
        let mut expected = Sha256::new();
        expected.update(
            u16::try_from(DURABLE_AUTH_PLAN_COMMITMENT_DOMAIN_V0.len())
                .expect("commitment domain length")
                .to_be_bytes(),
        );
        expected.update(DURABLE_AUTH_PLAN_COMMITMENT_DOMAIN_V0);
        expected.update(&encoded);
        let expected: [u8; DURABLE_AUTH_PLAN_COMMITMENT_BYTES_V0] = expected.finalize().into();

        assert_eq!(
            plan.durable_jmt_plan_commitment_v0()
                .expect("stream durable plan commitment"),
            expected,
        );
        assert_eq!(
            expected,
            [
                0xb4, 0x89, 0x9b, 0x7f, 0xf2, 0xfe, 0xb2, 0x4c, 0x53, 0x24, 0x61, 0xd5, 0x72, 0xb7,
                0x81, 0x22, 0x3c, 0xa0, 0xe2, 0xb2, 0x8a, 0x2f, 0xda, 0x99, 0x52, 0x27, 0xa1, 0xd1,
                0xca, 0x15, 0x5a, 0xf6,
            ],
            "domain-separated durable JMT commitment vector drifted"
        );
        let mut without_stats = plan.clone();
        without_stats.tree_update_batch.node_stats.clear();
        assert_eq!(
            without_stats
                .durable_jmt_plan_commitment_v0()
                .expect("commitment without diagnostics"),
            expected,
            "diagnostic node statistics must not enter the commitment"
        );
    }

    #[test]
    fn durable_jmt_plan_commitment_revalidation_is_exact_and_inert_v0() {
        let (tree, writes, plan) = fixture();
        let commitment = plan
            .durable_jmt_plan_commitment_v0()
            .expect("commit exact durable plan");
        let parent_root = tree.root_hash(0);
        let revalidated = revalidate_durable_jmt_plan_commitment_v0(
            &tree,
            1,
            parent_root,
            plan.root_hash,
            commitment,
            writes.iter().map(|write| (write.key(), write.value())),
        )
        .expect("revalidate exact commitment");
        assert_eq!(revalidated.commitment_v0(), commitment);
        assert_eq!(revalidated.target_version_v0(), 1);
        assert_eq!(revalidated.parent_root_v0(), parent_root);
        assert_eq!(revalidated.root_hash_v0(), plan.root_hash);

        let mut wrong_commitment = commitment;
        wrong_commitment[0] ^= 1;
        assert!(revalidate_durable_jmt_plan_commitment_v0(
            &tree,
            1,
            parent_root,
            plan.root_hash,
            wrong_commitment,
            writes.iter().map(|write| (write.key(), write.value())),
        )
        .is_err());

        let mut wrong_root = plan.root_hash;
        wrong_root.0[0] ^= 1;
        assert!(revalidate_durable_jmt_plan_commitment_v0(
            &tree,
            1,
            parent_root,
            wrong_root,
            commitment,
            writes.iter().map(|write| (write.key(), write.value())),
        )
        .is_err());

        let mut wrong_parent = parent_root.expect("fixture parent root");
        wrong_parent.0[0] ^= 1;
        assert!(revalidate_durable_jmt_plan_commitment_v0(
            &tree,
            1,
            Some(wrong_parent),
            plan.root_hash,
            commitment,
            writes.iter().map(|write| (write.key(), write.value())),
        )
        .is_err());

        let mut spliced_writes = writes;
        spliced_writes.push(put(
            task_key("durable-plan-commitment-splice").expect("spliced key"),
            b"spliced",
        ));
        spliced_writes.sort_by(|left, right| left.key().cmp(right.key()));
        assert!(revalidate_durable_jmt_plan_commitment_v0(
            &tree,
            1,
            parent_root,
            plan.root_hash,
            commitment,
            spliced_writes
                .iter()
                .map(|write| (write.key(), write.value())),
        )
        .is_err());
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
        let primary_commitment = primary_plan
            .durable_jmt_plan_commitment_v0()
            .expect("commit primary plan");
        assert_ne!(
            primary_commitment,
            alternate_plan
                .durable_jmt_plan_commitment_v0()
                .expect("commit alternate plan"),
            "the commitment must bind equal-root physical history"
        );
        revalidate_durable_jmt_plan_commitment_v0(
            &primary,
            2,
            primary.root_hash(1),
            primary_plan.root_hash,
            primary_commitment,
            writes.iter().map(|write| (write.key(), write.value())),
        )
        .expect("revalidate commitment against primary history");
        assert!(revalidate_durable_jmt_plan_commitment_v0(
            &alternate,
            2,
            alternate.root_hash(1),
            primary_plan.root_hash,
            primary_commitment,
            writes.iter().map(|write| (write.key(), write.value())),
        )
        .is_err());
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
