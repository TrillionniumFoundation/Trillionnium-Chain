//! Atomic PoCO snapshot mutation and semantic-value admission.
//!
//! This module closes a narrow storage invariant: one authenticated JMT
//! version contains every PoCO entry mutation and the manifest rewrite for
//! that exact version in the same `PlannedAuthUpdate`.  It deliberately does
//! not treat arbitrary `AuthWrite` values or caller-normalized B2-G facts as
//! runtime authority. B2-H3b1 additionally seals the exact physical projection
//! admitted by production codecs, SQLite persistence, migration, and snapshot
//! restore; it still does not authorize a production PoCO mutation source.

use std::collections::BTreeMap;

use anyhow::{ensure, Context, Result};
use sha2::{Digest, Sha256};
use trnm_consensus_types::{
    decode_consensus_parameters_v0_exact, decode_consumption_certificate_v0_exact,
    decode_validator_key_proof_of_possession_v0_exact, decode_validator_set_v0_exact, BlockId,
    CertificateId, Epoch, Height, StateRoot, SCHEMA_VERSION_V0,
};

use crate::{
    auth_tree::{AuthWrite, InMemoryAuthTree, PlannedAuthUpdate},
    poco_application::{
        poco_application_authority_identity_v0, validate_application_authority_projection_v0,
        PocoApplicationAuthorityStateV0, SealedPocoApplicationPlanV0,
    },
    poco_semantics::{
        validate_semantic_mutation_v0, BondStateV0, GovernanceApprovalV0, JailReasonV0,
        LifecycleStateV0, MeasurementStateV0, RegistrationStateV0, RelationshipClassV0,
        RolloutPhaseV0, SemanticFactV0, SettlementStateV0,
    },
    poco_snapshot::{
        decode_poco_snapshot_physical_key_v0_exact, poco_snapshot_entry_key,
        poco_snapshot_manifest_key, validate_entries, validate_logical_key,
        verify_live_poco_snapshot_projection_v0, AuthenticatedPocoSnapshotNamespaceV0,
        PocoSnapshotEntryKindV0, PocoSnapshotEntryV0, PocoSnapshotManifestV0,
        PocoSnapshotNamespaceProofV0, PocoSnapshotPhysicalKeyV0, MAX_POCO_SNAPSHOT_ENTRIES,
        MAX_POCO_SNAPSHOT_ICS23_PROOF_BYTES, MAX_POCO_SNAPSHOT_VALUE_BYTES,
    },
};

const HASH_PREFIX: &[u8] = b"trnm.cev0.hash.v0";
const IDENTITY_DOMAIN: &[u8] = b"trnm.poco-bft.snapshot-value-identity.v0";
const MUTATION_DOMAIN: &[u8] = b"trnm.poco-bft.snapshot-mutation.v0";
const MUTATION_NODE_DOMAIN: &[u8] = b"trnm.poco-bft.snapshot-mutation-node.v0";
const MUTATION_ROOT_DOMAIN: &[u8] = b"trnm.poco-bft.snapshot-mutation-root.v0";
const POCO_KEY_PREFIX: &[u8] = b"trnm/authenticated-state/v4\0\x08";

/// Largest v0 semantic identity is the complete seven-field Consumption
/// Certificate uniqueness tuple: three framed 128-byte IDs, one Hash32 and
/// three u64 values.
pub const MAX_POCO_SEMANTIC_IDENTITY_BYTES: usize = 452;
pub const MAX_POCO_SEMANTIC_PAYLOAD_BYTES: usize = 65_384;

/// Exact production projection recovered from physical namespace-8 leaves.
/// Unlike the H2 proof contract, production persistence admits no unreferenced
/// namespace-8 leaf: every physical entry must be named by the one manifest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ProductionPocoProjectionV0 {
    manifest: PocoSnapshotManifestV0,
    entries: Vec<PocoSnapshotEntryV0>,
}

impl ProductionPocoProjectionV0 {
    pub(crate) const fn manifest(&self) -> PocoSnapshotManifestV0 {
        self.manifest
    }

    pub(crate) fn entries(&self) -> &[PocoSnapshotEntryV0] {
        &self.entries
    }
}

/// Removes and validates the complete physical PoCO namespace from a verified
/// live JMT projection. An empty namespace is valid before PoCO activation.
/// Once any namespace-8 leaf exists, one exact manifest and exactly its listed
/// semantic entries are required; hidden/unreferenced leaves fail closed.
pub(crate) fn take_and_validate_production_poco_projection_v0(
    state_height: u64,
    live: &mut BTreeMap<Vec<u8>, Vec<u8>>,
) -> Result<Option<ProductionPocoProjectionV0>> {
    let mut physical = Vec::new();
    for key in live.keys() {
        if let Some(decoded) = decode_poco_snapshot_physical_key_v0_exact(key)? {
            physical.push((key.clone(), decoded));
        }
    }
    if physical.is_empty() {
        return Ok(None);
    }
    ensure!(
        physical.len() <= MAX_POCO_SNAPSHOT_ENTRIES.saturating_add(1),
        "production PoCO namespace exceeds physical leaf bound"
    );

    let manifest_key = poco_snapshot_manifest_key()?;
    let manifest_bytes = live
        .remove(&manifest_key)
        .context("production PoCO namespace is missing its manifest")?;
    let manifest = PocoSnapshotManifestV0::decode_exact(&manifest_bytes)?;
    ensure!(
        manifest.cutoff_height().get() <= state_height,
        "production PoCO manifest height is ahead of state head"
    );

    let mut entries = Vec::with_capacity(physical.len().saturating_sub(1));
    for (key, decoded) in physical {
        match decoded {
            PocoSnapshotPhysicalKeyV0::Manifest => {
                ensure!(key == manifest_key, "noncanonical PoCO manifest key")
            }
            PocoSnapshotPhysicalKeyV0::Entry { kind, logical_key } => {
                let value = live
                    .remove(&key)
                    .context("production PoCO entry disappeared during validation")?;
                decode_poco_snapshot_value_v0_exact(kind, &logical_key, &value)?;
                entries.push(PocoSnapshotEntryV0::new(kind, logical_key, value)?);
            }
        }
    }
    entries.sort_by(|left, right| {
        (left.kind, left.logical_key.as_slice()).cmp(&(right.kind, right.logical_key.as_slice()))
    });
    validate_target_projection_bound(&entries)?;
    validate_entries(&entries)?;
    ensure!(
        manifest.entry_count() as usize == entries.len(),
        "production PoCO manifest entry count mismatch"
    );
    ensure!(
        PocoSnapshotManifestV0::from_entries(manifest.cutoff_height(), &entries)? == manifest,
        "production PoCO manifest ordered root mismatch"
    );
    let projection = ProductionPocoProjectionV0 { manifest, entries };
    for entry in projection
        .entries()
        .iter()
        .filter(|entry| entry.kind == PocoSnapshotEntryKindV0::ConsensusParameters)
    {
        let parts = decode_poco_snapshot_value_parts_v0_exact(
            entry.kind,
            &entry.logical_key,
            &entry.value,
        )?;
        let parameters = decode_consensus_parameters_v0_exact(parts.payload)
            .map_err(|error| anyhow::anyhow!("decode retained PoCO parameters: {error:?}"))?;
        crate::validate_poco_parameter_retention_v0(&parameters)?;
    }
    validate_application_authority_projection_v0(&projection)?;
    Ok(Some(projection))
}

/// Zero-sized construction permit for raw namespace-8 writes. Its private
/// field keeps production construction inside this planner module; tests may
/// request an explicit test-only permit to build authenticated fixtures.
#[derive(Clone, Copy)]
pub(crate) struct PocoWritePermitV0(());

impl PocoWritePermitV0 {
    const fn planner() -> Self {
        Self(())
    }

    #[cfg(test)]
    pub(crate) const fn test_only() -> Self {
        Self(())
    }
}

/// Converts the private H3b2b1 application plan into the only raw
/// namespace-8 writes admitted by the production JMT merger. The complete
/// batch is bounded and structurally re-decoded before any bytes are cloned.
pub(crate) fn auth_writes_from_sealed_poco_application_v0(
    plan: &SealedPocoApplicationPlanV0,
) -> Result<Vec<AuthWrite>> {
    let writes = plan.namespace_writes().collect::<Vec<_>>();
    ensure!(
        !writes.is_empty() && writes.len() <= MAX_POCO_SNAPSHOT_ENTRIES.saturating_add(1),
        "sealed PoCO application write count is outside bound"
    );
    let mut total = 0usize;
    let mut seen = std::collections::BTreeSet::new();
    let mut manifest_count = 0usize;
    let expected_manifest = plan.target_manifest().encode();
    for (key, value) in &writes {
        total = total
            .checked_add(key.len())
            .and_then(|size| size.checked_add(value.map_or(0, <[u8]>::len)))
            .context("sealed PoCO application write size overflow")?;
        ensure!(
            total <= crate::poco_snapshot::MAX_POCO_SNAPSHOT_BUNDLE_BYTES,
            "sealed PoCO application writes exceed 8 MiB"
        );
        ensure!(seen.insert(*key), "duplicate sealed PoCO application write");
        match decode_poco_snapshot_physical_key_v0_exact(key)?
            .context("sealed PoCO application write is outside namespace 8")?
        {
            PocoSnapshotPhysicalKeyV0::Manifest => {
                manifest_count += 1;
                ensure!(
                    value == &Some(expected_manifest.as_slice()),
                    "sealed PoCO application manifest drift"
                );
            }
            PocoSnapshotPhysicalKeyV0::Entry { kind, logical_key } => match value {
                Some(value) => {
                    decode_poco_snapshot_value_v0_exact(kind, &logical_key, value)?;
                }
                None => ensure!(
                    kind != PocoSnapshotEntryKindV0::ApplicationAuthorityState,
                    "application authority state cannot be pruned"
                ),
            },
        }
    }
    ensure!(
        manifest_count == 1,
        "sealed PoCO application plan must rewrite exactly one manifest"
    );

    writes
        .into_iter()
        .map(|(key, value)| match value {
            Some(value) => AuthWrite::put_poco_snapshot(
                PocoWritePermitV0::planner(),
                key.to_vec(),
                value.to_vec(),
            ),
            None => AuthWrite::delete_poco_snapshot(PocoWritePermitV0::planner(), key.to_vec()),
        })
        .collect()
}

/// Scheduled cutoffs must carry an exact manifest height even when the block
/// has no business operation. This private one-write plan preserves the
/// ordered namespace content and changes only the manifest timestamp.
pub(crate) fn scheduled_cutoff_manifest_refresh_write_v0(
    target_height: Height,
    source: &ProductionPocoProjectionV0,
) -> Result<AuthWrite> {
    let manifest = PocoSnapshotManifestV0::from_entries(target_height, source.entries())?;
    AuthWrite::put_poco_snapshot(
        PocoWritePermitV0::planner(),
        poco_snapshot_manifest_key()?,
        manifest.encode(),
    )
}

/// Produces the exact namespace-8 portion of AppHash version zero. This is
/// the only activation path for H3b2b1; a legacy projection cannot acquire a
/// kind-16 authority head through a later ordinary runtime transaction.
pub(crate) fn genesis_poco_snapshot_writes_v0(
    entries: &[PocoSnapshotEntryV0],
) -> Result<Vec<AuthWrite>> {
    if entries.is_empty() {
        return Ok(Vec::new());
    }
    ensure!(
        entries.len() <= MAX_POCO_SNAPSHOT_ENTRIES,
        "genesis PoCO entry count exceeds bound"
    );
    validate_entries(entries)?;
    validate_target_projection_bound(entries)?;
    let mut writes = Vec::with_capacity(entries.len().saturating_add(1));
    for entry in entries {
        decode_poco_snapshot_value_v0_exact(entry.kind, &entry.logical_key, &entry.value)?;
        writes.push(AuthWrite::put_poco_snapshot(
            PocoWritePermitV0::planner(),
            entry.jmt_key()?,
            entry.value.clone(),
        )?);
    }
    let manifest = PocoSnapshotManifestV0::from_entries(Height::new(0), entries)?;
    writes.push(AuthWrite::put_poco_snapshot(
        PocoWritePermitV0::planner(),
        poco_snapshot_manifest_key()?,
        manifest.encode(),
    )?);
    Ok(writes)
}

pub fn encode_poco_snapshot_value_envelope_v0(
    kind: PocoSnapshotEntryKindV0,
    revision: u64,
    identity: &[u8],
    payload: &[u8],
) -> Result<(Vec<u8>, Vec<u8>)> {
    ensure!(revision > 0, "semantic value revision must be positive");
    ensure!(
        !identity.is_empty() && identity.len() <= MAX_POCO_SEMANTIC_IDENTITY_BYTES,
        "semantic identity length is outside bound"
    );
    ensure!(
        !payload.is_empty() && payload.len() <= MAX_POCO_SEMANTIC_PAYLOAD_BYTES,
        "semantic payload length is outside bound"
    );
    let envelope_len = 19usize
        .checked_add(identity.len())
        .and_then(|length| length.checked_add(payload.len()))
        .context("semantic value envelope length overflow")?;
    ensure!(
        envelope_len <= MAX_POCO_SNAPSHOT_VALUE_BYTES,
        "semantic value envelope exceeds snapshot value bound"
    );
    let _ = validate_kind_payload(kind, identity, payload)?;
    let logical_key = semantic_identity_digest(kind, identity).to_vec();
    let mut value = Vec::with_capacity(19 + identity.len() + payload.len());
    value.extend_from_slice(&SCHEMA_VERSION_V0.to_be_bytes());
    value.push(kind as u8);
    value.extend_from_slice(&revision.to_be_bytes());
    encode_bytes(&mut value, identity);
    encode_bytes(&mut value, payload);
    debug_assert!(decode_poco_snapshot_value_v0_exact(kind, &logical_key, &value).is_ok());
    Ok((logical_key, value))
}

/// Successful exact admission of one kind-specific snapshot value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedPocoSnapshotValueV0 {
    kind: PocoSnapshotEntryKindV0,
    revision: u64,
    identity_digest: [u8; 32],
    payload_digest: [u8; 32],
}

#[derive(Clone, Debug)]
pub(crate) struct DecodedPocoSnapshotValuePartsV0<'a> {
    pub(crate) verified: VerifiedPocoSnapshotValueV0,
    pub(crate) identity: &'a [u8],
    pub(crate) payload: &'a [u8],
    pub(crate) fact: SemanticFactV0,
}

impl VerifiedPocoSnapshotValueV0 {
    pub const fn kind(self) -> PocoSnapshotEntryKindV0 {
        self.kind
    }

    pub const fn revision(self) -> u64 {
        self.revision
    }

    pub const fn identity_digest(self) -> [u8; 32] {
        self.identity_digest
    }

    pub const fn payload_digest(self) -> [u8; 32] {
        self.payload_digest
    }
}

/// Exact value envelope shared by all 15 kinds.
///
/// `logical_key` is the domain-separated digest of `(kind, identity)`.  The
/// nested payload then has a strict kind-specific decoder; no kind may smuggle
/// a different payload under the same manifest key.
pub fn decode_poco_snapshot_value_v0_exact(
    expected_kind: PocoSnapshotEntryKindV0,
    logical_key: &[u8],
    bytes: &[u8],
) -> Result<VerifiedPocoSnapshotValueV0> {
    Ok(decode_poco_snapshot_value_parts_v0_exact(expected_kind, logical_key, bytes)?.verified)
}

pub(crate) fn decode_poco_snapshot_value_parts_v0_exact<'a>(
    expected_kind: PocoSnapshotEntryKindV0,
    logical_key: &[u8],
    bytes: &'a [u8],
) -> Result<DecodedPocoSnapshotValuePartsV0<'a>> {
    validate_logical_key(logical_key)?;
    ensure!(
        logical_key.len() == 32,
        "semantic logical key must be Hash32"
    );
    ensure!(
        !bytes.is_empty() && bytes.len() <= MAX_POCO_SNAPSHOT_VALUE_BYTES,
        "semantic snapshot value length is outside bound"
    );
    let mut cursor = Cursor::new(bytes);
    ensure!(
        cursor.u16()? == SCHEMA_VERSION_V0,
        "semantic value schema version mismatch"
    );
    let kind = PocoSnapshotEntryKindV0::from_u8(cursor.u8()?)?;
    ensure!(kind == expected_kind, "semantic value kind mismatch");
    let revision = cursor.u64()?;
    ensure!(revision > 0, "semantic value revision must be positive");
    let identity = cursor.bytes(MAX_POCO_SEMANTIC_IDENTITY_BYTES)?;
    let payload = cursor.bytes(MAX_POCO_SEMANTIC_PAYLOAD_BYTES)?;
    cursor.finish()?;
    let identity_digest = semantic_identity_digest(kind, identity);
    ensure!(
        logical_key == identity_digest,
        "logical key/value identity mismatch"
    );
    let fact = validate_kind_payload(kind, identity, payload)?;
    Ok(DecodedPocoSnapshotValuePartsV0 {
        verified: VerifiedPocoSnapshotValueV0 {
            kind,
            revision,
            identity_digest,
            payload_digest: domain_hash(b"trnm.poco-bft.snapshot-value-payload.v0", payload),
        },
        identity,
        payload,
        fact,
    })
}

/// Canonically ordered compare-and-set mutation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PocoSnapshotMutationV0 {
    pub kind: PocoSnapshotEntryKindV0,
    pub logical_key: Vec<u8>,
    pub expected_value: Option<Vec<u8>>,
    pub next_value: Option<Vec<u8>>,
}

impl PocoSnapshotMutationV0 {
    pub fn put(
        kind: PocoSnapshotEntryKindV0,
        logical_key: Vec<u8>,
        expected_value: Option<Vec<u8>>,
        next_value: Vec<u8>,
    ) -> Result<Self> {
        let value = Self {
            kind,
            logical_key,
            expected_value,
            next_value: Some(next_value),
        };
        value.validate_shape()?;
        Ok(value)
    }

    pub fn delete(
        kind: PocoSnapshotEntryKindV0,
        logical_key: Vec<u8>,
        expected_value: Vec<u8>,
    ) -> Result<Self> {
        let value = Self {
            kind,
            logical_key,
            expected_value: Some(expected_value),
            next_value: None,
        };
        value.validate_shape()?;
        Ok(value)
    }

    fn validate_shape(&self) -> Result<()> {
        validate_logical_key(&self.logical_key)?;
        ensure!(
            self.expected_value.is_some() || self.next_value.is_some(),
            "empty compare-and-set mutation"
        );
        let expected = self
            .expected_value
            .as_deref()
            .map(|value| {
                decode_poco_snapshot_value_parts_v0_exact(self.kind, &self.logical_key, value)
            })
            .transpose()?;
        let next = self
            .next_value
            .as_deref()
            .map(|value| {
                decode_poco_snapshot_value_parts_v0_exact(self.kind, &self.logical_key, value)
            })
            .transpose()?;
        match (&expected, &next) {
            (None, Some(next)) => ensure!(
                next.verified.revision == 1,
                "created value revision must be 1"
            ),
            (Some(expected), Some(next)) => ensure!(
                expected.verified.revision.checked_add(1) == Some(next.verified.revision),
                "updated value revision is not exact successor"
            ),
            (Some(_), None) => {}
            (None, None) => unreachable!("empty mutation rejected above"),
        }
        validate_semantic_mutation_v0(
            expected.as_ref().map(|parts| &parts.fact),
            next.as_ref().map(|parts| &parts.fact),
        )?;
        Ok(())
    }

    pub(crate) fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&SCHEMA_VERSION_V0.to_be_bytes());
        bytes.push(self.kind as u8);
        encode_bytes(&mut bytes, &self.logical_key);
        encode_optional_bytes(&mut bytes, self.expected_value.as_deref());
        encode_optional_bytes(&mut bytes, self.next_value.as_deref());
        bytes
    }
}

/// Private-field, origin-bound head used to continue the in-memory PoCO state
/// chain after one cutoff token established its initial projection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PocoStateHeadKernelV0 {
    origin_proof_id: CertificateId,
    origin_epoch: Epoch,
    origin_cutoff_height: Height,
    origin_cutoff_block_id: BlockId,
    height: Height,
    state_root: StateRoot,
    manifest_height: Height,
    entries_root: [u8; 32],
    entry_count: u32,
}

impl PocoStateHeadKernelV0 {
    pub const fn origin_proof_id(self) -> CertificateId {
        self.origin_proof_id
    }
    pub const fn origin_epoch(self) -> Epoch {
        self.origin_epoch
    }
    pub const fn origin_cutoff_height(self) -> Height {
        self.origin_cutoff_height
    }
    pub const fn origin_cutoff_block_id(self) -> BlockId {
        self.origin_cutoff_block_id
    }
    pub const fn height(self) -> Height {
        self.height
    }
    pub const fn state_root(self) -> StateRoot {
        self.state_root
    }
    pub const fn manifest_height(self) -> Height {
        self.manifest_height
    }
    pub const fn entries_root(self) -> [u8; 32] {
        self.entries_root
    }
    pub const fn entry_count(self) -> u32 {
        self.entry_count
    }
}

/// Converts the private B2-H2 cutoff token into the first reusable PoCO state
/// head. This preserves the cutoff token's caller-verifier caveat; it is not a
/// durable-finality or production-runtime authorization. Subsequent heads can
/// only be obtained by applying a planned in-memory atomic transition.
pub const fn poco_state_head_from_authenticated_cutoff_v0(
    authenticated: AuthenticatedPocoSnapshotNamespaceV0,
) -> PocoStateHeadKernelV0 {
    PocoStateHeadKernelV0 {
        origin_proof_id: authenticated.proof_id(),
        origin_epoch: authenticated.epoch(),
        origin_cutoff_height: authenticated.cutoff_height(),
        origin_cutoff_block_id: authenticated.cutoff_block_id(),
        height: authenticated.cutoff_height(),
        state_root: authenticated.cutoff_state_root(),
        manifest_height: authenticated.cutoff_height(),
        entries_root: authenticated.entries_root(),
        entry_count: authenticated.entry_count(),
    }
}

/// Private-field plan proving that the exact source projection was rebound to
/// one origin-bound head before one all-or-nothing in-memory JMT update.
#[derive(Debug)]
pub struct PlannedPocoSnapshotTransitionV0 {
    source_head: PocoStateHeadKernelV0,
    target_head: PocoStateHeadKernelV0,
    mutation_root: [u8; 32],
    mutation_count: u32,
    writes: Vec<AuthWrite>,
}

impl PlannedPocoSnapshotTransitionV0 {
    pub const fn source_height(&self) -> Height {
        self.source_head.height
    }

    pub const fn source_state_root(&self) -> StateRoot {
        self.source_head.state_root
    }

    pub const fn source_entries_root(&self) -> [u8; 32] {
        self.source_head.entries_root
    }

    pub const fn target_height(&self) -> Height {
        self.target_head.height
    }

    pub const fn target_state_root(&self) -> StateRoot {
        self.target_head.state_root
    }

    pub const fn target_entries_root(&self) -> [u8; 32] {
        self.target_head.entries_root
    }

    pub const fn target_entry_count(&self) -> u32 {
        self.target_head.entry_count
    }

    pub const fn mutation_root(&self) -> [u8; 32] {
        self.mutation_root
    }

    pub const fn mutation_count(&self) -> u32 {
        self.mutation_count
    }

    /// Applies the already planned all-or-nothing JMT update. A stale tree
    /// head is rejected by both this check and `InMemoryAuthTree::apply`.
    pub fn apply(
        self,
        tree: &mut InMemoryAuthTree,
    ) -> Result<AppliedInMemoryPocoSnapshotTransitionV0> {
        ensure!(
            tree.latest_version() == Some(self.source_head.height.get())
                && tree.root_hash(self.source_head.height.get())
                    == Some((*self.source_head.state_root.as_bytes()).into()),
            "PoCO transition source tree changed after planning"
        );
        // Replan on the exact target tree history. Equal JMT version/root pairs
        // can arise from different historical NodeKey layouts, so a batch
        // created against one history must never be transplanted into another.
        let plan = tree.plan_put_value_set(self.target_head.height.get(), self.writes)?;
        ensure!(
            <[u8; 32]>::from(plan.root_hash) == *self.target_head.state_root.as_bytes(),
            "replanned PoCO transition root drift"
        );
        let root = tree.apply(plan)?;
        ensure!(
            <[u8; 32]>::from(root) == *self.target_head.state_root.as_bytes(),
            "applied PoCO transition root drift"
        );
        Ok(AppliedInMemoryPocoSnapshotTransitionV0 {
            source_head: self.source_head,
            target_head: self.target_head,
            mutation_root: self.mutation_root,
            mutation_count: self.mutation_count,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AppliedInMemoryPocoSnapshotTransitionV0 {
    source_head: PocoStateHeadKernelV0,
    target_head: PocoStateHeadKernelV0,
    mutation_root: [u8; 32],
    mutation_count: u32,
}

impl AppliedInMemoryPocoSnapshotTransitionV0 {
    pub const fn target_height(self) -> Height {
        self.target_head.height
    }
    pub const fn target_state_root(self) -> StateRoot {
        self.target_head.state_root
    }
    pub const fn target_entries_root(self) -> [u8; 32] {
        self.target_head.entries_root
    }
    pub const fn target_entry_count(self) -> u32 {
        self.target_head.entry_count
    }
    pub const fn mutation_root(self) -> [u8; 32] {
        self.mutation_root
    }
    pub const fn mutation_count(self) -> u32 {
        self.mutation_count
    }
    pub const fn source_height(self) -> Height {
        self.source_head.height
    }
    pub const fn source_state_root(self) -> StateRoot {
        self.source_head.state_root
    }
    pub const fn state_head(self) -> PocoStateHeadKernelV0 {
        self.target_head
    }
}

/// Plans one exact next JMT version. The source bundle is reverified in the
/// same call and every raw value is semantically decoded before normalized or
/// derived state can be consumed.
pub fn plan_poco_snapshot_transition_v0(
    tree: &InMemoryAuthTree,
    source_head: PocoStateHeadKernelV0,
    source_bundle: &PocoSnapshotNamespaceProofV0,
    target_height: Height,
    mutations: &[PocoSnapshotMutationV0],
    refresh_manifest_at_target: bool,
    other_authenticated_writes: Vec<AuthWrite>,
) -> Result<PlannedPocoSnapshotTransitionV0> {
    validate_transition_admission_bounds(mutations, &other_authenticated_writes)?;
    ensure!(
        tree.latest_version() == Some(source_head.height.get()),
        "committed PoCO source is not the current JMT head"
    );
    ensure!(
        tree.root_hash(source_head.height.get())
            == Some((*source_head.state_root.as_bytes()).into()),
        "committed PoCO source root is not the current JMT root"
    );
    ensure!(
        target_height.get() == tree.expected_next_version(),
        "PoCO transition target is not the exact next JMT version"
    );
    let verified = verify_live_poco_snapshot_projection_v0(
        source_head.height.get(),
        *source_head.state_root.as_bytes(),
        source_bundle,
    )?;
    ensure!(
        verified.manifest().entry_count() == source_head.entry_count
            && verified.manifest().entries_root() == source_head.entries_root
            && verified.manifest().cutoff_height() == source_head.manifest_height,
        "source bundle is not the exact committed projection"
    );
    let mut entries = BTreeMap::new();
    for member in &source_bundle.members {
        decode_poco_snapshot_value_v0_exact(
            member.entry.kind,
            &member.entry.logical_key,
            &member.entry.value,
        )?;
        ensure!(
            entries
                .insert(
                    (member.entry.kind, member.entry.logical_key.clone()),
                    member.entry.value.clone(),
                )
                .is_none(),
            "duplicate source semantic entry"
        );
    }
    let mut poco_writes = Vec::with_capacity(mutations.len().saturating_add(1));
    for mutation in mutations {
        let map_key = (mutation.kind, mutation.logical_key.clone());
        ensure!(
            entries.get(&map_key) == mutation.expected_value.as_ref(),
            "PoCO compare-and-set precondition mismatch"
        );
        let jmt_key = poco_snapshot_entry_key(mutation.kind, &mutation.logical_key)?;
        ensure!(
            tree.value_at(source_head.height.get(), &jmt_key)?.as_ref()
                == mutation.expected_value.as_ref(),
            "PoCO compare-and-set physical leaf mismatch"
        );
        match &mutation.next_value {
            Some(value) => {
                entries.insert(map_key, value.clone());
                poco_writes.push(AuthWrite::put_poco_snapshot(
                    PocoWritePermitV0::planner(),
                    jmt_key,
                    value.clone(),
                )?);
            }
            None => {
                entries.remove(&map_key);
                poco_writes.push(AuthWrite::delete_poco_snapshot(
                    PocoWritePermitV0::planner(),
                    jmt_key,
                )?);
            }
        }
    }
    let target_entries = entries
        .into_iter()
        .map(|((kind, logical_key), value)| PocoSnapshotEntryV0 {
            kind,
            logical_key,
            value,
        })
        .collect::<Vec<_>>();
    validate_target_projection_bound(&target_entries)?;
    validate_entries(&target_entries)?;
    let rewrite_manifest = !mutations.is_empty() || refresh_manifest_at_target;
    let manifest = if rewrite_manifest {
        let manifest = PocoSnapshotManifestV0::from_entries(target_height, &target_entries)?;
        poco_writes.push(AuthWrite::put_poco_snapshot(
            PocoWritePermitV0::planner(),
            poco_snapshot_manifest_key()?,
            manifest.encode(),
        )?);
        manifest
    } else {
        source_bundle.manifest
    };
    let mut all_writes = other_authenticated_writes;
    all_writes.extend(poco_writes);
    let plan = tree.plan_put_value_set(target_height.get(), all_writes.clone())?;
    validate_target_reprovable_bundle_bound(tree, &plan, &manifest, &target_entries)?;
    let target_state_root = StateRoot::new(plan.root_hash.into());
    let target_head = PocoStateHeadKernelV0 {
        height: target_height,
        state_root: target_state_root,
        manifest_height: manifest.cutoff_height(),
        entries_root: manifest.entries_root(),
        entry_count: u32::try_from(target_entries.len()).expect("entry hard bound fits u32"),
        ..source_head
    };
    Ok(PlannedPocoSnapshotTransitionV0 {
        source_head,
        target_head,
        mutation_root: ordered_mutation_root(mutations),
        mutation_count: u32::try_from(mutations.len()).expect("mutation hard bound fits u32"),
        writes: all_writes,
    })
}

fn validate_kind_payload(
    kind: PocoSnapshotEntryKindV0,
    identity: &[u8],
    payload: &[u8],
) -> Result<SemanticFactV0> {
    let mut cursor = Cursor::new(payload);
    match kind {
        PocoSnapshotEntryKindV0::ConsumptionCertificate => {
            ensure!(identity.len() == 32, "certificate identity must be Hash32");
            let certificate = decode_consumption_certificate_v0_exact(payload)
                .map_err(|error| anyhow::anyhow!("decode certificate payload: {error:?}"))?;
            ensure!(
                certificate.certificate_id().as_bytes() == identity,
                "certificate identity mismatch"
            );
            Ok(SemanticFactV0::ConsumptionCertificate)
        }
        PocoSnapshotEntryKindV0::ConsumerKeyAuthorization => {
            let mut identity_cursor = Cursor::new(identity);
            let identity_consumer = identity_cursor.bytes(128)?;
            let identity_key = identity_cursor.bytes(128)?;
            identity_cursor.finish()?;
            ensure!(
                cursor.bytes(128)? == identity_consumer,
                "consumer identity mismatch"
            );
            ensure!(
                cursor.bytes(128)? == identity_key,
                "consumer key identity mismatch"
            );
            let public_key = cursor.fixed::<32>()?;
            ensure!(public_key != [0; 32], "zero consumer public key");
            let active_from = cursor.u64()?;
            let revoked_at = cursor.optional_u64()?;
            ensure!(
                revoked_at.is_none_or(|height| height > active_from),
                "invalid key interval"
            );
            cursor.finish()?;
            Ok(SemanticFactV0::ConsumerKeyAuthorization {
                public_key,
                active_from,
                revoked_at,
            })
        }
        PocoSnapshotEntryKindV0::ConsumerNonce => {
            let mut identity_cursor = Cursor::new(identity);
            let consumer = identity_cursor.bytes(128)?;
            let consumer_key = identity_cursor.bytes(128)?;
            let provider = identity_cursor.bytes(128)?;
            identity_cursor.finish()?;
            ensure!(provider != consumer, "nonce provider equals consumer");
            ensure!(cursor.bytes(128)? == consumer, "nonce consumer mismatch");
            ensure!(
                cursor.bytes(128)? == consumer_key,
                "nonce consumer key mismatch"
            );
            ensure!(cursor.bytes(128)? == provider, "nonce provider mismatch");
            let max_accepted_nonce = cursor.u64()?;
            cursor.finish()?;
            Ok(SemanticFactV0::ConsumerNonce { max_accepted_nonce })
        }
        PocoSnapshotEntryKindV0::UniqueConsumptionTuple => {
            let mut identity_cursor = Cursor::new(identity);
            let consumer = identity_cursor.bytes(128)?;
            let provider = identity_cursor.bytes(128)?;
            let task = identity_cursor.bytes(128)?;
            let output_commitment = identity_cursor.fixed::<32>()?;
            let billing_start = identity_cursor.u64()?;
            let billing_end = identity_cursor.u64()?;
            let consumer_nonce = identity_cursor.u64()?;
            identity_cursor.finish()?;
            ensure!(provider != consumer, "tuple provider equals consumer");
            ensure!(cursor.bytes(128)? == consumer, "tuple consumer mismatch");
            ensure!(cursor.bytes(128)? == provider, "tuple provider mismatch");
            ensure!(cursor.bytes(128)? == task, "tuple task mismatch");
            ensure!(
                cursor.fixed::<32>()? == output_commitment,
                "tuple output commitment mismatch"
            );
            ensure!(
                cursor.u64()? == billing_start,
                "tuple billing start mismatch"
            );
            ensure!(cursor.u64()? == billing_end, "tuple billing end mismatch");
            ensure!(
                cursor.u64()? == consumer_nonce,
                "tuple consumer nonce mismatch"
            );
            ensure!(
                billing_start <= billing_end,
                "invalid tuple billing interval"
            );
            let certificate_id = cursor.fixed::<32>()?;
            let accepted_height = cursor.u64()?;
            ensure!(
                accepted_height > billing_end,
                "tuple acceptance does not follow billing interval"
            );
            cursor.finish()?;
            Ok(SemanticFactV0::UniqueConsumptionTuple {
                certificate_id,
                accepted_height,
            })
        }
        PocoSnapshotEntryKindV0::MeterDefinition => {
            let mut identity_cursor = Cursor::new(identity);
            let meter_id = identity_cursor.bytes(128)?;
            let meter_version = identity_cursor.u32()?;
            identity_cursor.finish()?;
            ensure!(cursor.bytes(128)? == meter_id, "meter identity mismatch");
            ensure!(
                cursor.u32()? == meter_version,
                "meter version identity mismatch"
            );
            let unit_scale = cursor.u128()?;
            ensure!(unit_scale > 0, "meter unit scale must be positive");
            let active_from = cursor.u64()?;
            let retired_at = cursor.optional_u64()?;
            ensure!(
                retired_at.is_none_or(|height| height > active_from),
                "invalid meter interval"
            );
            cursor.finish()?;
            Ok(SemanticFactV0::MeterDefinition {
                unit_scale,
                active_from,
                retired_at,
            })
        }
        PocoSnapshotEntryKindV0::Settlement => {
            ensure!(identity.len() == 32, "settlement identity must be Hash32");
            ensure!(
                cursor.fixed::<32>()? == identity,
                "settlement certificate mismatch"
            );
            let commitment = cursor.fixed::<32>()?;
            let state = SettlementStateV0::try_from(cursor.u8()?)?;
            let finalized_height = cursor.u64()?;
            cursor.finish()?;
            Ok(SemanticFactV0::Settlement {
                commitment,
                state,
                finalized_height,
            })
        }
        PocoSnapshotEntryKindV0::MeasurementEvidence => {
            ensure!(identity.len() == 32, "measurement identity must be Hash32");
            ensure!(
                cursor.fixed::<32>()? == identity,
                "measurement certificate mismatch"
            );
            let evidence_root = cursor.optional_fixed_32()?;
            let state = MeasurementStateV0::try_from(cursor.u8()?)?;
            cursor.finish()?;
            Ok(SemanticFactV0::MeasurementEvidence {
                evidence_root,
                state,
            })
        }
        PocoSnapshotEntryKindV0::RelationshipClassification => {
            let mut identity_cursor = Cursor::new(identity);
            let provider = identity_cursor.bytes(128)?;
            let consumer = identity_cursor.bytes(128)?;
            let task = identity_cursor.bytes(128)?;
            identity_cursor.finish()?;
            ensure!(
                cursor.bytes(128)? == provider,
                "relationship provider mismatch"
            );
            ensure!(
                cursor.bytes(128)? == consumer,
                "relationship consumer mismatch"
            );
            ensure!(cursor.bytes(128)? == task, "relationship task mismatch");
            let class = RelationshipClassV0::try_from(cursor.u8()?)?;
            let expires_at = cursor.u64()?;
            cursor.finish()?;
            Ok(SemanticFactV0::RelationshipClassification { class, expires_at })
        }
        PocoSnapshotEntryKindV0::ValidatorRegistration => {
            let validator_id = cursor.bytes(128)?;
            ensure!(validator_id == identity, "validator identity mismatch");
            let consensus_key = cursor.fixed::<32>()?;
            ensure!(consensus_key != [0; 32], "zero validator key");
            let registration_nonce = cursor.u64()?;
            let state = RegistrationStateV0::try_from(cursor.u8()?)?;
            let proof_bytes = cursor.bytes(MAX_POCO_SEMANTIC_PAYLOAD_BYTES)?;
            let proof = decode_validator_key_proof_of_possession_v0_exact(proof_bytes)
                .map_err(|error| anyhow::anyhow!("decode validator PoP payload: {error:?}"))?;
            let fields = proof.fields();
            ensure!(
                fields.validator_id.as_bytes() == validator_id,
                "validator PoP identity mismatch"
            );
            ensure!(
                fields.public_key.as_bytes() == &consensus_key,
                "validator PoP key mismatch"
            );
            ensure!(
                fields.registration_nonce == registration_nonce,
                "validator PoP nonce mismatch"
            );
            cursor.finish()?;
            Ok(SemanticFactV0::ValidatorRegistration {
                consensus_key,
                registration_nonce,
                proof_digest: domain_hash(
                    b"trnm.poco-bft.validator-registration-pop.v0",
                    proof_bytes,
                ),
                state,
            })
        }
        PocoSnapshotEntryKindV0::ActiveBond => {
            ensure!(
                cursor.bytes(128)? == identity,
                "bond validator identity mismatch"
            );
            let amount = cursor.u128()?;
            ensure!(amount > 0, "active bond must be positive");
            let locked_until = cursor.u64()?;
            let state = BondStateV0::try_from(cursor.u8()?)?;
            cursor.finish()?;
            Ok(SemanticFactV0::ActiveBond {
                amount,
                locked_until,
                state,
            })
        }
        PocoSnapshotEntryKindV0::JailStatus => {
            ensure!(
                cursor.bytes(128)? == identity,
                "jail validator identity mismatch"
            );
            let jailed_until = cursor.u64()?;
            let reason = JailReasonV0::try_from(cursor.u8()?)?;
            cursor.finish()?;
            Ok(SemanticFactV0::JailStatus {
                jailed_until,
                reason,
            })
        }
        PocoSnapshotEntryKindV0::RevocationOrChallenge => {
            ensure!(identity.len() == 32, "revocation identity must be Hash32");
            ensure!(
                cursor.fixed::<32>()? == identity,
                "revocation certificate mismatch"
            );
            let state = LifecycleStateV0::try_from(cursor.u8()?)?;
            let effective_height = cursor.u64()?;
            cursor.finish()?;
            Ok(SemanticFactV0::RevocationOrChallenge {
                state,
                effective_height,
            })
        }
        PocoSnapshotEntryKindV0::ValidatorConfiguration => {
            ensure!(
                identity.len() == 9 && (1..=2).contains(&identity[0]),
                "validator configuration identity must be role + epoch"
            );
            let set = decode_validator_set_v0_exact(payload)
                .map_err(|error| anyhow::anyhow!("decode validator set payload: {error:?}"))?;
            ensure!(
                set.epoch().get().to_be_bytes() == identity[1..],
                "validator set epoch mismatch"
            );
            Ok(SemanticFactV0::ValidatorConfiguration)
        }
        PocoSnapshotEntryKindV0::ConsensusParameters => {
            ensure!(
                identity.len() == 9 && (1..=2).contains(&identity[0]),
                "parameters identity must be role + target epoch"
            );
            decode_consensus_parameters_v0_exact(payload)
                .map_err(|error| anyhow::anyhow!("decode consensus parameters: {error:?}"))?;
            Ok(SemanticFactV0::ConsensusParameters)
        }
        PocoSnapshotEntryKindV0::RolloutOrGovernance => {
            ensure!(
                identity.len() == 8,
                "governance identity must be target epoch u64"
            );
            let target_epoch = u64::from_be_bytes(
                identity
                    .try_into()
                    .expect("governance identity width checked"),
            );
            let phase = RolloutPhaseV0::try_from(cursor.u8()?)?;
            let parameters_hash = cursor.fixed::<32>()?;
            let activation_height = cursor.u64()?;
            ensure!(activation_height > 0, "zero governance activation height");
            let approval = GovernanceApprovalV0::try_from(cursor.u8()?)?;
            cursor.finish()?;
            Ok(SemanticFactV0::RolloutOrGovernance {
                target_epoch,
                phase,
                parameters_hash,
                activation_height,
                approval,
            })
        }
        PocoSnapshotEntryKindV0::ApplicationAuthorityState => {
            ensure!(
                identity == poco_application_authority_identity_v0(),
                "application authority identity mismatch"
            );
            let authority = PocoApplicationAuthorityStateV0::decode_exact(payload)?;
            Ok(SemanticFactV0::ApplicationAuthorityState {
                state_revision: authority.revision(),
                last_target_height: authority.last_target_height(),
                nullifier_root: authority.nullifier_root()?,
                nullifier_count: authority.nullifier_count(),
            })
        }
    }
}

fn validate_transition_admission_bounds(
    mutations: &[PocoSnapshotMutationV0],
    other_writes: &[AuthWrite],
) -> Result<()> {
    ensure!(
        mutations.len() <= MAX_POCO_SNAPSHOT_ENTRIES,
        "too many PoCO mutations"
    );
    ensure!(
        other_writes.len() <= MAX_POCO_SNAPSHOT_ENTRIES,
        "too many generic authenticated writes"
    );
    ensure!(
        mutations
            .len()
            .checked_add(other_writes.len())
            .and_then(|count| count.checked_add(1))
            .is_some_and(|count| count <= MAX_POCO_SNAPSHOT_ENTRIES),
        "too many writes in atomic PoCO transition"
    );
    let mut total = 0usize;
    let mut previous = None;
    for mutation in mutations {
        validate_logical_key(&mutation.logical_key)?;
        let identity = (mutation.kind, mutation.logical_key.as_slice());
        if let Some(previous) = previous {
            ensure!(
                previous < identity,
                "PoCO mutations are not canonical and unique"
            );
        }
        previous = Some(identity);
        total = total
            .checked_add(mutation.logical_key.len())
            .and_then(|value| {
                value.checked_add(mutation.expected_value.as_ref().map_or(0, Vec::len))
            })
            .and_then(|value| value.checked_add(mutation.next_value.as_ref().map_or(0, Vec::len)))
            .context("PoCO transition admission size overflow")?;
        ensure!(
            total <= crate::poco_snapshot::MAX_POCO_SNAPSHOT_BUNDLE_BYTES,
            "PoCO transition inputs exceed 8 MiB"
        );
    }
    for write in other_writes {
        ensure!(
            !write.key().starts_with(POCO_KEY_PREFIX),
            "generic authenticated write attempted to bypass PoCO planner"
        );
        total = total
            .checked_add(write.key().len())
            .and_then(|value| value.checked_add(write.value().map_or(0, <[u8]>::len)))
            .context("PoCO transition admission size overflow")?;
        ensure!(
            total <= crate::poco_snapshot::MAX_POCO_SNAPSHOT_BUNDLE_BYTES,
            "PoCO transition inputs exceed 8 MiB"
        );
    }
    for mutation in mutations {
        mutation.validate_shape()?;
    }
    Ok(())
}

fn validate_target_projection_bound(entries: &[PocoSnapshotEntryV0]) -> Result<()> {
    let mut total = 0usize;
    for entry in entries {
        total = total
            .checked_add(entry.logical_key.len())
            .and_then(|size| size.checked_add(entry.value.len()))
            .context("PoCO target projection size overflow")?;
    }
    ensure!(
        total <= crate::poco_snapshot::MAX_POCO_SNAPSHOT_BUNDLE_BYTES,
        "PoCO target projection exceeds 8 MiB before hashing"
    );
    Ok(())
}

fn validate_target_reprovable_bundle_bound(
    tree: &InMemoryAuthTree,
    plan: &PlannedAuthUpdate,
    manifest: &PocoSnapshotManifestV0,
    entries: &[PocoSnapshotEntryV0],
) -> Result<()> {
    let mut total = manifest.encode().len();
    let manifest_proof = tree.prove_planned(plan, poco_snapshot_manifest_key()?)?;
    total = checked_add_auth_proof_size(total, &manifest_proof)?;
    ensure!(
        total <= crate::poco_snapshot::MAX_POCO_SNAPSHOT_BUNDLE_BYTES,
        "PoCO target projection cannot fit a zero-absence H2 proof bundle"
    );
    for entry in entries {
        total = total
            .checked_add(entry.logical_key.len())
            .and_then(|size| size.checked_add(entry.value.len()))
            .context("PoCO target proof-bundle size overflow")?;
        ensure!(
            total <= crate::poco_snapshot::MAX_POCO_SNAPSHOT_BUNDLE_BYTES,
            "PoCO target projection cannot fit a zero-absence H2 proof bundle"
        );
        let proof = tree.prove_planned(plan, entry.jmt_key()?)?;
        total = checked_add_auth_proof_size(total, &proof)?;
        ensure!(
            total <= crate::poco_snapshot::MAX_POCO_SNAPSHOT_BUNDLE_BYTES,
            "PoCO target projection cannot fit a zero-absence H2 proof bundle"
        );
    }
    Ok(())
}

fn checked_add_auth_proof_size(total: usize, proof: &crate::auth_tree::AuthProof) -> Result<usize> {
    let encoded_proof = proof.encoded_commitment_proof();
    ensure!(
        encoded_proof.len() <= MAX_POCO_SNAPSHOT_ICS23_PROOF_BYTES,
        "planned PoCO ICS23 proof exceeds 1 MiB"
    );
    total
        .checked_add(proof.key.len())
        .and_then(|size| size.checked_add(proof.value.as_ref().map_or(0, Vec::len)))
        .and_then(|size| size.checked_add(encoded_proof.len()))
        .context("PoCO target proof-bundle size overflow")
}

fn semantic_identity_digest(kind: PocoSnapshotEntryKindV0, identity: &[u8]) -> [u8; 32] {
    let mut bytes = Vec::with_capacity(7 + identity.len());
    bytes.extend_from_slice(&SCHEMA_VERSION_V0.to_be_bytes());
    bytes.push(kind as u8);
    encode_bytes(&mut bytes, identity);
    domain_hash(IDENTITY_DOMAIN, &bytes)
}

fn ordered_mutation_root(mutations: &[PocoSnapshotMutationV0]) -> [u8; 32] {
    let mut layer = mutations
        .iter()
        .map(|mutation| domain_hash(MUTATION_DOMAIN, &mutation.canonical_bytes()))
        .collect::<Vec<_>>();
    let mut level = 0u32;
    while layer.len() > 1 {
        let mut next = Vec::with_capacity(layer.len().div_ceil(2));
        for pair in layer.chunks(2) {
            let left = pair[0];
            let right = pair.get(1).copied().unwrap_or(left);
            let mut bytes = Vec::with_capacity(70);
            bytes.extend_from_slice(&SCHEMA_VERSION_V0.to_be_bytes());
            bytes.extend_from_slice(&level.to_be_bytes());
            bytes.extend_from_slice(&left);
            bytes.extend_from_slice(&right);
            next.push(domain_hash(MUTATION_NODE_DOMAIN, &bytes));
        }
        layer = next;
        level += 1;
    }
    let mut bytes = Vec::with_capacity(39);
    bytes.extend_from_slice(&SCHEMA_VERSION_V0.to_be_bytes());
    bytes.extend_from_slice(&(mutations.len() as u32).to_be_bytes());
    match layer.first() {
        Some(root) => {
            bytes.push(1);
            bytes.extend_from_slice(root);
        }
        None => bytes.push(0),
    }
    domain_hash(MUTATION_ROOT_DOMAIN, &bytes)
}

fn domain_hash(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for frame in [HASH_PREFIX, domain, bytes] {
        hasher.update((frame.len() as u32).to_be_bytes());
        hasher.update(frame);
    }
    hasher.finalize().into()
}

fn encode_bytes(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(&(value.len() as u32).to_be_bytes());
    output.extend_from_slice(value);
}

fn encode_optional_bytes(output: &mut Vec<u8>, value: Option<&[u8]>) {
    match value {
        Some(value) => {
            output.push(1);
            encode_bytes(output, value);
        }
        None => output.push(0),
    }
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8]> {
        let end = self
            .offset
            .checked_add(length)
            .context("semantic value offset overflow")?;
        let value = self
            .bytes
            .get(self.offset..end)
            .context("semantic value is truncated")?;
        self.offset = end;
        Ok(value)
    }

    fn fixed<const N: usize>(&mut self) -> Result<[u8; N]> {
        Ok(self
            .take(N)?
            .try_into()
            .expect("fixed slice length checked"))
    }

    fn u8(&mut self) -> Result<u8> {
        Ok(self.fixed::<1>()?[0])
    }

    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(self.fixed()?))
    }

    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.fixed()?))
    }

    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.fixed()?))
    }

    fn u128(&mut self) -> Result<u128> {
        Ok(u128::from_be_bytes(self.fixed()?))
    }

    fn bytes(&mut self, maximum: usize) -> Result<&'a [u8]> {
        let length = usize::try_from(self.u32()?).context("semantic value length overflow")?;
        ensure!(
            length > 0 && length <= maximum,
            "semantic bytes length is outside bound"
        );
        self.take(length)
    }

    fn optional_u64(&mut self) -> Result<Option<u64>> {
        match self.u8()? {
            0 => Ok(None),
            1 => Ok(Some(self.u64()?)),
            _ => anyhow::bail!("invalid optional u64 tag"),
        }
    }

    fn optional_fixed_32(&mut self) -> Result<Option<[u8; 32]>> {
        match self.u8()? {
            0 => Ok(None),
            1 => Ok(Some(self.fixed()?)),
            _ => anyhow::bail!("invalid optional Hash32 tag"),
        }
    }

    fn finish(&self) -> Result<()> {
        ensure!(
            self.offset == self.bytes.len(),
            "semantic value has trailing bytes"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    const TRANSITION_VECTOR: &str = include_str!(
        "../../../../docs/protocol/poco-bft-v0/vectors/poco-snapshot-transition-v0.json"
    );
    const CERTIFICATE_VECTOR: &str = include_str!(
        "../../../../docs/protocol/poco-bft-v0/vectors/consumption-certificate-v0.json"
    );
    const CANDIDATE_VECTOR: &str = include_str!(
        "../../../../docs/protocol/poco-bft-v0/vectors/snapshot-candidate-kernel-v0.json"
    );
    const HANDOFF_VECTOR: &str = include_str!(
        "../../../../docs/protocol/poco-bft-v0/vectors/joint-handoff-composition-kernel-v0.json"
    );
    const BUSINESS_SEMANTICS_VECTOR: &str = include_str!(
        "../../../../docs/protocol/poco-bft-v0/vectors/poco-business-semantics-v0.json"
    );

    fn envelope(
        kind: PocoSnapshotEntryKindV0,
        revision: u64,
        identity: &[u8],
        payload: &[u8],
    ) -> (Vec<u8>, Vec<u8>) {
        encode_poco_snapshot_value_envelope_v0(kind, revision, identity, payload).unwrap()
    }

    fn production_projection_fixture(
        manifest_height: u64,
    ) -> (BTreeMap<Vec<u8>, Vec<u8>>, PocoSnapshotEntryV0) {
        let identity = nonce_identity();
        let (logical_key, value) = envelope(
            PocoSnapshotEntryKindV0::ConsumerNonce,
            1,
            &identity,
            &nonce_payload(1),
        );
        let entry =
            PocoSnapshotEntryV0::new(PocoSnapshotEntryKindV0::ConsumerNonce, logical_key, value)
                .unwrap();
        let manifest = PocoSnapshotManifestV0::from_entries(
            Height::new(manifest_height),
            std::slice::from_ref(&entry),
        )
        .unwrap();
        let mut live = BTreeMap::new();
        live.insert(poco_snapshot_manifest_key().unwrap(), manifest.encode());
        live.insert(entry.jmt_key().unwrap(), entry.value.clone());
        (live, entry)
    }

    fn parameter_projection_fixture(snapshot_lead_blocks: u64) -> BTreeMap<Vec<u8>, Vec<u8>> {
        let mut fields =
            trnm_consensus_types::ConsensusParametersV0::reference_shadow_v0().fields();
        fields.snapshot_lead_blocks = snapshot_lead_blocks;
        let parameters = trnm_consensus_types::ConsensusParametersV0::new(fields).unwrap();
        let mut identity = vec![1];
        identity.extend_from_slice(&0u64.to_be_bytes());
        let (logical_key, value) = envelope(
            PocoSnapshotEntryKindV0::ConsensusParameters,
            1,
            &identity,
            &parameters.canonical_bytes(),
        );
        let entry = PocoSnapshotEntryV0::new(
            PocoSnapshotEntryKindV0::ConsensusParameters,
            logical_key,
            value,
        )
        .unwrap();
        let manifest =
            PocoSnapshotManifestV0::from_entries(Height::new(1), std::slice::from_ref(&entry))
                .unwrap();
        let mut live = BTreeMap::new();
        live.insert(poco_snapshot_manifest_key().unwrap(), manifest.encode());
        live.insert(entry.jmt_key().unwrap(), entry.value);
        live
    }

    fn unchecked_envelope(
        kind: PocoSnapshotEntryKindV0,
        revision: u64,
        identity: &[u8],
        payload: &[u8],
    ) -> (Vec<u8>, Vec<u8>) {
        let mut value = Vec::new();
        value.extend_from_slice(&SCHEMA_VERSION_V0.to_be_bytes());
        value.push(kind as u8);
        value.extend_from_slice(&revision.to_be_bytes());
        encode_bytes(&mut value, identity);
        encode_bytes(&mut value, payload);
        (semantic_identity_digest(kind, identity).to_vec(), value)
    }

    fn nonce_identity() -> Vec<u8> {
        let mut identity = Vec::new();
        for value in [
            b"consumer-a".as_slice(),
            b"key-a".as_slice(),
            b"provider-a".as_slice(),
        ] {
            encode_bytes(&mut identity, value);
        }
        identity
    }

    fn nonce_payload(nonce: u64) -> Vec<u8> {
        let mut payload = nonce_identity();
        payload.extend_from_slice(&nonce.to_be_bytes());
        payload
    }

    fn composite_identity(parts: &[&[u8]]) -> Vec<u8> {
        let mut identity = Vec::new();
        for part in parts {
            encode_bytes(&mut identity, part);
        }
        identity
    }

    fn assert_layout(
        kind: PocoSnapshotEntryKindV0,
        identity: &[u8],
        payload: &[u8],
    ) -> VerifiedPocoSnapshotValueV0 {
        let (key, value) = envelope(kind, 1, identity, payload);
        let verified = decode_poco_snapshot_value_v0_exact(kind, &key, &value).unwrap();
        assert_eq!(verified.kind(), kind);
        assert_ne!(verified.payload_digest(), [0; 32]);
        verified
    }

    #[test]
    fn consumer_nonce_value_is_exact_and_key_bound() {
        let identity = nonce_identity();
        let payload = nonce_payload(17);
        let (key, value) = envelope(
            PocoSnapshotEntryKindV0::ConsumerNonce,
            1,
            &identity,
            &payload,
        );
        let verified = decode_poco_snapshot_value_v0_exact(
            PocoSnapshotEntryKindV0::ConsumerNonce,
            &key,
            &value,
        )
        .unwrap();
        assert_eq!(verified.revision(), 1);
        let mut wrong = key;
        wrong[0] ^= 1;
        assert!(decode_poco_snapshot_value_v0_exact(
            PocoSnapshotEntryKindV0::ConsumerNonce,
            &wrong,
            &value
        )
        .is_err());
        assert!(decode_poco_snapshot_value_v0_exact(
            PocoSnapshotEntryKindV0::ActiveBond,
            &wrong,
            &value
        )
        .is_err());
        assert!(decode_poco_snapshot_value_v0_exact(
            PocoSnapshotEntryKindV0::ConsumerNonce,
            &verified.identity_digest()[..],
            &[value, vec![0]].concat()
        )
        .is_err());
    }

    #[test]
    fn explicit_manifest_refresh_and_empty_mutation_root_are_version_bound() {
        assert_ne!(
            PocoSnapshotManifestV0::from_entries(Height::new(8), &[])
                .unwrap()
                .encode(),
            PocoSnapshotManifestV0::from_entries(Height::new(9), &[])
                .unwrap()
                .encode()
        );
        assert_ne!(ordered_mutation_root(&[]), [0; 32]);
    }

    #[test]
    fn production_projection_rejects_snapshot_lead_beyond_retained_jmt_history() {
        let mut exact = parameter_projection_fixture(crate::AUTH_PROOF_RETENTION_VERSIONS);
        assert!(
            take_and_validate_production_poco_projection_v0(1, &mut exact)
                .unwrap()
                .is_some()
        );

        let mut over = parameter_projection_fixture(crate::AUTH_PROOF_RETENTION_VERSIONS + 1);
        assert!(take_and_validate_production_poco_projection_v0(1, &mut over).is_err());
    }

    #[test]
    fn malformed_kind_payloads_fail_closed() {
        let cases = [
            (
                PocoSnapshotEntryKindV0::ConsumerKeyAuthorization,
                b"consumer".as_slice(),
            ),
            (
                PocoSnapshotEntryKindV0::ConsumerNonce,
                b"consumer".as_slice(),
            ),
            (
                PocoSnapshotEntryKindV0::MeterDefinition,
                b"meter".as_slice(),
            ),
            (
                PocoSnapshotEntryKindV0::RelationshipClassification,
                b"provider".as_slice(),
            ),
            (
                PocoSnapshotEntryKindV0::ValidatorRegistration,
                b"validator".as_slice(),
            ),
            (PocoSnapshotEntryKindV0::ActiveBond, b"validator".as_slice()),
            (PocoSnapshotEntryKindV0::JailStatus, b"validator".as_slice()),
            (
                PocoSnapshotEntryKindV0::ConsensusParameters,
                b"active".as_slice(),
            ),
        ];
        for (kind, identity) in cases {
            let (key, value) = unchecked_envelope(kind, 1, identity, &[1]);
            assert!(decode_poco_snapshot_value_v0_exact(kind, &key, &value).is_err());
        }
    }

    #[test]
    fn all_fifteen_semantic_layouts_have_positive_exact_witnesses() {
        let certificate: Value = serde_json::from_str(CERTIFICATE_VECTOR).unwrap();
        let certificate_id = hex::decode(
            certificate["fixture"]["certificate_id_hex"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
        let certificate_bytes = hex::decode(
            certificate["fixture"]["certificate_cev0_hex"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
        assert_layout(
            PocoSnapshotEntryKindV0::ConsumptionCertificate,
            &certificate_id,
            &certificate_bytes,
        );

        let consumer = vec![b'c'; 128];
        let consumer_key = vec![b'k'; 128];
        let provider = vec![b'p'; 128];
        let task = vec![b't'; 128];
        let key_identity = composite_identity(&[&consumer, &consumer_key]);
        let mut key_payload = key_identity.clone();
        key_payload.extend_from_slice(&[1; 32]);
        key_payload.extend_from_slice(&10u64.to_be_bytes());
        key_payload.push(0);
        assert_layout(
            PocoSnapshotEntryKindV0::ConsumerKeyAuthorization,
            &key_identity,
            &key_payload,
        );

        let nonce_identity = composite_identity(&[&consumer, &consumer_key, &provider]);
        let mut nonce_payload = nonce_identity.clone();
        nonce_payload.extend_from_slice(&7u64.to_be_bytes());
        assert_layout(
            PocoSnapshotEntryKindV0::ConsumerNonce,
            &nonce_identity,
            &nonce_payload,
        );

        let mut tuple_identity = composite_identity(&[&consumer, &provider, &task]);
        tuple_identity.extend_from_slice(&[2; 32]);
        tuple_identity.extend_from_slice(&3u64.to_be_bytes());
        tuple_identity.extend_from_slice(&4u64.to_be_bytes());
        tuple_identity.extend_from_slice(&5u64.to_be_bytes());
        assert_eq!(tuple_identity.len(), MAX_POCO_SEMANTIC_IDENTITY_BYTES);
        let mut tuple_payload = tuple_identity.clone();
        tuple_payload.extend_from_slice(&certificate_id);
        tuple_payload.extend_from_slice(&6u64.to_be_bytes());
        assert_layout(
            PocoSnapshotEntryKindV0::UniqueConsumptionTuple,
            &tuple_identity,
            &tuple_payload,
        );
        let (tuple_key, tuple_value) = envelope(
            PocoSnapshotEntryKindV0::UniqueConsumptionTuple,
            1,
            &tuple_identity,
            &tuple_payload,
        );
        assert_eq!(
            decode_poco_snapshot_value_parts_v0_exact(
                PocoSnapshotEntryKindV0::UniqueConsumptionTuple,
                &tuple_key,
                &tuple_value,
            )
            .unwrap()
            .fact,
            SemanticFactV0::UniqueConsumptionTuple {
                certificate_id: certificate_id.as_slice().try_into().unwrap(),
                accepted_height: 6,
            }
        );

        let mut meter_identity = Vec::new();
        encode_bytes(&mut meter_identity, b"meter-a");
        meter_identity.extend_from_slice(&0u32.to_be_bytes());
        let mut meter_payload = meter_identity.clone();
        meter_payload.extend_from_slice(&1u128.to_be_bytes());
        meter_payload.extend_from_slice(&2u64.to_be_bytes());
        meter_payload.push(0);
        assert_layout(
            PocoSnapshotEntryKindV0::MeterDefinition,
            &meter_identity,
            &meter_payload,
        );

        let mut settlement = certificate_id.clone();
        settlement.extend_from_slice(&[3; 32]);
        settlement.push(1);
        settlement.extend_from_slice(&9u64.to_be_bytes());
        assert_layout(
            PocoSnapshotEntryKindV0::Settlement,
            &certificate_id,
            &settlement,
        );

        let mut evidence = certificate_id.clone();
        evidence.push(1);
        evidence.extend_from_slice(&[4; 32]);
        evidence.push(1);
        assert_layout(
            PocoSnapshotEntryKindV0::MeasurementEvidence,
            &certificate_id,
            &evidence,
        );

        let relationship_identity = composite_identity(&[&provider, &consumer, &task]);
        let mut relationship = relationship_identity.clone();
        relationship.push(1);
        relationship.extend_from_slice(&20u64.to_be_bytes());
        assert_layout(
            PocoSnapshotEntryKindV0::RelationshipClassification,
            &relationship_identity,
            &relationship,
        );

        let candidate: Value = serde_json::from_str(CANDIDATE_VECTOR).unwrap();
        let pop = &candidate["pop_fixtures"][0];
        let validator_id = hex::decode(pop["validator_id_hex"].as_str().unwrap()).unwrap();
        let validator_key = hex::decode(pop["public_key_hex"].as_str().unwrap()).unwrap();
        let registration_nonce = pop["registration_nonce"]
            .as_str()
            .unwrap()
            .parse::<u64>()
            .unwrap();
        let pop_bytes = hex::decode(pop["cev0_hex"].as_str().unwrap()).unwrap();
        let mut registration = Vec::new();
        encode_bytes(&mut registration, &validator_id);
        registration.extend_from_slice(&validator_key);
        registration.extend_from_slice(&registration_nonce.to_be_bytes());
        registration.push(1);
        encode_bytes(&mut registration, &pop_bytes);
        assert_layout(
            PocoSnapshotEntryKindV0::ValidatorRegistration,
            &validator_id,
            &registration,
        );

        let mut bond = Vec::new();
        encode_bytes(&mut bond, &validator_id);
        bond.extend_from_slice(&1u128.to_be_bytes());
        bond.extend_from_slice(&30u64.to_be_bytes());
        bond.push(1);
        assert_layout(PocoSnapshotEntryKindV0::ActiveBond, &validator_id, &bond);

        let mut jail = Vec::new();
        encode_bytes(&mut jail, &validator_id);
        jail.extend_from_slice(&31u64.to_be_bytes());
        jail.push(1);
        assert_layout(PocoSnapshotEntryKindV0::JailStatus, &validator_id, &jail);

        let mut lifecycle = certificate_id.clone();
        lifecycle.push(1);
        lifecycle.extend_from_slice(&32u64.to_be_bytes());
        assert_layout(
            PocoSnapshotEntryKindV0::RevocationOrChallenge,
            &certificate_id,
            &lifecycle,
        );

        let handoff: Value = serde_json::from_str(HANDOFF_VECTOR).unwrap();
        let raw = &handoff["positive_cases"][0]["raw_bundle"];
        let validator_set =
            hex::decode(raw["old_validator_set_cev0_hex"].as_str().unwrap()).unwrap();
        let decoded_set = decode_validator_set_v0_exact(&validator_set).unwrap();
        let mut set_identity = vec![1];
        set_identity.extend_from_slice(&decoded_set.epoch().get().to_be_bytes());
        assert_layout(
            PocoSnapshotEntryKindV0::ValidatorConfiguration,
            &set_identity,
            &validator_set,
        );

        let parameters =
            hex::decode(raw["old_consensus_parameters_cev0_hex"].as_str().unwrap()).unwrap();
        let mut parameter_identity = vec![1];
        parameter_identity.extend_from_slice(&decoded_set.epoch().get().to_be_bytes());
        assert_layout(
            PocoSnapshotEntryKindV0::ConsensusParameters,
            &parameter_identity,
            &parameters,
        );

        let governance_identity = 1u64.to_be_bytes();
        let mut governance = vec![0];
        governance.extend_from_slice(&[5; 32]);
        governance.extend_from_slice(&40u64.to_be_bytes());
        governance.push(0);
        assert_layout(
            PocoSnapshotEntryKindV0::RolloutOrGovernance,
            &governance_identity,
            &governance,
        );
    }

    #[test]
    fn shared_raw_corpus_admits_all_fifteen_kinds_and_rejects_each_negative() {
        let vector: Value = serde_json::from_str(TRANSITION_VECTOR).unwrap();
        let corpus = &vector["semantic_layout_corpus"];
        let statistics = &corpus["expected_statistics"];
        assert_eq!(statistics["positive_values"], 15);
        assert_eq!(statistics["semantic_negatives"], 15);
        assert_eq!(statistics["external_object_negatives"], 2);
        assert_eq!(statistics["rollout_phase_boundary_values"], 4);
        assert_eq!(statistics["rejected_incomplete_prefixes"], 2_561);
        let positives = corpus["positive_fixtures"].as_array().unwrap();
        assert_eq!(positives.len(), 15);
        let mut rejected_prefixes = 0usize;
        for (index, fixture) in positives.iter().enumerate() {
            let kind_number = fixture["kind"].as_u64().unwrap() as u8;
            assert_eq!(usize::from(kind_number), index + 1);
            let kind = PocoSnapshotEntryKindV0::from_u8(kind_number).unwrap();
            let logical_key = hex::decode(fixture["logical_key_hex"].as_str().unwrap()).unwrap();
            let value = hex::decode(fixture["value_cev0_hex"].as_str().unwrap()).unwrap();
            for prefix_length in 0..value.len() {
                assert!(
                    decode_poco_snapshot_value_v0_exact(
                        kind,
                        &logical_key,
                        &value[..prefix_length],
                    )
                    .is_err(),
                    "shared positive {} accepted incomplete prefix {prefix_length}",
                    fixture["id"],
                );
                rejected_prefixes += 1;
            }
            let verified = decode_poco_snapshot_value_v0_exact(kind, &logical_key, &value)
                .unwrap_or_else(|error| {
                    panic!("shared positive {} failed: {error:#}", fixture["id"])
                });
            assert_eq!(verified.kind(), kind);
            assert_eq!(verified.revision(), fixture["revision"].as_u64().unwrap());
        }
        assert_eq!(rejected_prefixes, 2_561);

        let phase_boundaries = corpus["rollout_phase_boundary_fixtures"]
            .as_array()
            .unwrap();
        assert_eq!(phase_boundaries.len(), 4);
        for (phase, fixture) in phase_boundaries.iter().enumerate() {
            assert_eq!(fixture["phase"].as_u64().unwrap(), phase as u64);
            let logical_key = hex::decode(fixture["logical_key_hex"].as_str().unwrap()).unwrap();
            let value = hex::decode(fixture["value_cev0_hex"].as_str().unwrap()).unwrap();
            decode_poco_snapshot_value_v0_exact(
                PocoSnapshotEntryKindV0::RolloutOrGovernance,
                &logical_key,
                &value,
            )
            .unwrap_or_else(|error| panic!("shared rollout phase {phase} failed: {error:#}"));
        }

        let negatives = corpus["negative_fixtures"].as_array().unwrap();
        assert_eq!(negatives.len(), 15);
        for fixture in negatives {
            let kind =
                PocoSnapshotEntryKindV0::from_u8(fixture["kind"].as_u64().unwrap() as u8).unwrap();
            let logical_key = hex::decode(fixture["logical_key_hex"].as_str().unwrap()).unwrap();
            let value = hex::decode(fixture["value_cev0_hex"].as_str().unwrap()).unwrap();
            assert!(
                decode_poco_snapshot_value_v0_exact(kind, &logical_key, &value).is_err(),
                "shared negative {} was accepted",
                fixture["id"],
            );
        }

        let external_negatives = corpus["external_object_negative_fixtures"]
            .as_array()
            .unwrap();
        assert_eq!(external_negatives.len(), 2);
        for fixture in external_negatives {
            let kind =
                PocoSnapshotEntryKindV0::from_u8(fixture["kind"].as_u64().unwrap() as u8).unwrap();
            let logical_key = hex::decode(fixture["logical_key_hex"].as_str().unwrap()).unwrap();
            let value = hex::decode(fixture["value_cev0_hex"].as_str().unwrap()).unwrap();
            assert!(
                decode_poco_snapshot_value_v0_exact(kind, &logical_key, &value).is_err(),
                "shared imported-object negative {} was accepted",
                fixture["id"],
            );
        }
    }

    #[test]
    fn mutation_revision_transitions_are_exact() {
        let identity = nonce_identity();
        let (key, revision_1) = envelope(
            PocoSnapshotEntryKindV0::ConsumerNonce,
            1,
            &identity,
            &nonce_payload(1),
        );
        let (_, revision_2) = envelope(
            PocoSnapshotEntryKindV0::ConsumerNonce,
            2,
            &identity,
            &nonce_payload(2),
        );
        let (_, revision_3) = envelope(
            PocoSnapshotEntryKindV0::ConsumerNonce,
            3,
            &identity,
            &nonce_payload(3),
        );
        assert!(PocoSnapshotMutationV0::put(
            PocoSnapshotEntryKindV0::ConsumerNonce,
            key.clone(),
            None,
            revision_2.clone(),
        )
        .is_err());
        assert!(PocoSnapshotMutationV0::put(
            PocoSnapshotEntryKindV0::ConsumerNonce,
            key.clone(),
            Some(revision_1.clone()),
            revision_3,
        )
        .is_err());
        assert!(PocoSnapshotMutationV0::put(
            PocoSnapshotEntryKindV0::ConsumerNonce,
            key.clone(),
            Some(revision_1.clone()),
            revision_2,
        )
        .is_ok());
        assert!(PocoSnapshotMutationV0::delete(
            PocoSnapshotEntryKindV0::ConsumerNonce,
            key,
            revision_1,
        )
        .is_err());

        let (max_key, max_revision) = envelope(
            PocoSnapshotEntryKindV0::ConsumerNonce,
            u64::MAX,
            &identity,
            &nonce_payload(3),
        );
        let (_, wrapped_revision) = envelope(
            PocoSnapshotEntryKindV0::ConsumerNonce,
            1,
            &identity,
            &nonce_payload(4),
        );
        assert!(PocoSnapshotMutationV0::put(
            PocoSnapshotEntryKindV0::ConsumerNonce,
            max_key,
            Some(max_revision),
            wrapped_revision,
        )
        .is_err());

        let vector: Value = serde_json::from_str(BUSINESS_SEMANTICS_VECTOR).unwrap();
        let revision_cases = vector["revision_cases"].as_array().unwrap();
        let mut allowed = 0usize;
        for case in revision_cases {
            let expected_revision = case["expected_revision"]
                .as_str()
                .map(|value| value.parse::<u64>().unwrap());
            let next_revision = case["next_revision"]
                .as_str()
                .map(|value| value.parse::<u64>().unwrap());
            let (logical_key, _) = envelope(
                PocoSnapshotEntryKindV0::ConsumerNonce,
                1,
                &identity,
                &nonce_payload(1),
            );
            let expected = expected_revision.map(|revision| {
                envelope(
                    PocoSnapshotEntryKindV0::ConsumerNonce,
                    revision,
                    &identity,
                    &nonce_payload(1),
                )
                .1
            });
            let next = next_revision.map(|revision| {
                envelope(
                    PocoSnapshotEntryKindV0::ConsumerNonce,
                    revision,
                    &identity,
                    &nonce_payload(2),
                )
                .1
            });
            let result = match next {
                Some(next) => PocoSnapshotMutationV0::put(
                    PocoSnapshotEntryKindV0::ConsumerNonce,
                    logical_key,
                    expected,
                    next,
                ),
                None => PocoSnapshotMutationV0::delete(
                    PocoSnapshotEntryKindV0::ConsumerNonce,
                    logical_key,
                    expected.expect("delete revision case has expected value"),
                ),
            };
            let expected_accept = case["expected"] == "accept";
            allowed += usize::from(expected_accept);
            assert_eq!(result.is_ok(), expected_accept, "revision case {case}");
        }
        assert_eq!(
            revision_cases.len(),
            vector["expected_counts"]["revision_cases"]
        );
        assert_eq!(allowed, vector["expected_counts"]["revision_allowed"]);
    }

    #[test]
    fn generic_write_cannot_enter_poco_namespace() {
        let key = poco_snapshot_manifest_key().unwrap();
        assert!(key.starts_with(POCO_KEY_PREFIX));
        assert!(AuthWrite::put(key.clone(), vec![1]).is_err());
        assert!(AuthWrite::delete(key).is_err());
    }

    #[test]
    fn production_projection_requires_one_exact_manifest_and_no_hidden_leaf() {
        let (mut live, entry) = production_projection_fixture(6);
        live.insert(vec![1], vec![2]);
        let projection = take_and_validate_production_poco_projection_v0(7, &mut live)
            .unwrap()
            .unwrap();
        assert_eq!(projection.manifest().cutoff_height(), Height::new(6));
        assert_eq!(projection.entries(), std::slice::from_ref(&entry));
        assert_eq!(live, BTreeMap::from([(vec![1], vec![2])]));

        let (mut missing_manifest, _) = production_projection_fixture(6);
        missing_manifest.remove(&poco_snapshot_manifest_key().unwrap());
        assert!(take_and_validate_production_poco_projection_v0(7, &mut missing_manifest).is_err());

        let (mut hidden_leaf, _) = production_projection_fixture(6);
        let hidden_identity =
            composite_identity(&[b"consumer-hidden", b"key-hidden", b"provider-hidden"]);
        let (hidden_key, hidden_value) = envelope(
            PocoSnapshotEntryKindV0::ConsumerNonce,
            1,
            &hidden_identity,
            &{
                let mut payload = hidden_identity.clone();
                payload.extend_from_slice(&1u64.to_be_bytes());
                payload
            },
        );
        hidden_leaf.insert(
            poco_snapshot_entry_key(PocoSnapshotEntryKindV0::ConsumerNonce, &hidden_key).unwrap(),
            hidden_value,
        );
        assert!(take_and_validate_production_poco_projection_v0(7, &mut hidden_leaf).is_err());

        let (mut future_manifest, _) = production_projection_fixture(8);
        assert!(take_and_validate_production_poco_projection_v0(7, &mut future_manifest).is_err());

        let (mut bad_value, entry) = production_projection_fixture(6);
        bad_value
            .get_mut(&entry.jmt_key().unwrap())
            .unwrap()
            .push(0);
        assert!(take_and_validate_production_poco_projection_v0(7, &mut bad_value).is_err());
    }

    #[test]
    fn mutation_root_commits_order_expected_and_next_values() {
        let identity = nonce_identity();
        let mut payload = nonce_payload(1);
        let (key, old) = envelope(
            PocoSnapshotEntryKindV0::ConsumerNonce,
            1,
            &identity,
            &payload,
        );
        payload.truncate(payload.len() - 8);
        payload.extend_from_slice(&2u64.to_be_bytes());
        let (_, next) = envelope(
            PocoSnapshotEntryKindV0::ConsumerNonce,
            2,
            &identity,
            &payload,
        );
        let mutation = PocoSnapshotMutationV0::put(
            PocoSnapshotEntryKindV0::ConsumerNonce,
            key,
            Some(old),
            next,
        )
        .unwrap();
        assert_ne!(
            ordered_mutation_root(&[]),
            ordered_mutation_root(&[mutation])
        );
    }

    #[test]
    fn committed_transition_vector_matches_rust_projection() {
        let vector: Value = serde_json::from_str(TRANSITION_VECTOR).unwrap();
        let identity = nonce_identity();
        let source_payload = nonce_payload(9);
        let target_payload = nonce_payload(10);
        let (key, source) = encode_poco_snapshot_value_envelope_v0(
            PocoSnapshotEntryKindV0::ConsumerNonce,
            1,
            &identity,
            &source_payload,
        )
        .unwrap();
        let (_, target) = encode_poco_snapshot_value_envelope_v0(
            PocoSnapshotEntryKindV0::ConsumerNonce,
            2,
            &identity,
            &target_payload,
        )
        .unwrap();
        assert_eq!(hex::encode(&key), vector["logical_key_hex"]);
        assert_eq!(hex::encode(&source), vector["source_value_hex"]);
        assert_eq!(hex::encode(&target), vector["target_value_hex"]);
        let mutation = PocoSnapshotMutationV0::put(
            PocoSnapshotEntryKindV0::ConsumerNonce,
            key.clone(),
            Some(source.clone()),
            target.clone(),
        )
        .unwrap();
        assert_eq!(
            hex::encode(mutation.canonical_bytes()),
            vector["mutation_cev0_hex"]
        );
        assert_eq!(
            hex::encode(ordered_mutation_root(&[mutation])),
            vector["mutation_root_hex"]
        );
        assert_eq!(
            hex::encode(ordered_mutation_root(&[])),
            vector["empty_mutation_root_hex"]
        );
        let source_entry =
            PocoSnapshotEntryV0::new(PocoSnapshotEntryKindV0::ConsumerNonce, key.clone(), source)
                .unwrap();
        let target_entry =
            PocoSnapshotEntryV0::new(PocoSnapshotEntryKindV0::ConsumerNonce, key, target).unwrap();
        assert_eq!(
            hex::encode(source_entry.canonical_bytes()),
            vector["source_entry_cev0_hex"]
        );
        assert_eq!(
            hex::encode(target_entry.canonical_bytes()),
            vector["target_entry_cev0_hex"]
        );
        assert_eq!(
            hex::encode(
                PocoSnapshotManifestV0::from_entries(Height::new(6), &[source_entry])
                    .unwrap()
                    .encode()
            ),
            vector["source_manifest_cev0_hex"]
        );
        assert_eq!(
            hex::encode(
                PocoSnapshotManifestV0::from_entries(Height::new(7), &[target_entry])
                    .unwrap()
                    .encode()
            ),
            vector["target_manifest_cev0_hex"]
        );
        let seal = &vector["production_persistence_seal"];
        assert_eq!(
            hex::encode(poco_snapshot_manifest_key().unwrap()),
            seal["manifest_key_hex"]
        );
        assert_eq!(
            hex::encode(
                poco_snapshot_entry_key(
                    PocoSnapshotEntryKindV0::ConsumerNonce,
                    hex::decode(vector["logical_key_hex"].as_str().unwrap())
                        .unwrap()
                        .as_slice(),
                )
                .unwrap()
            ),
            seal["entry_key_hex"]
        );
        assert_eq!(seal["exact_physical_leaf_count"], 2);
        assert_eq!(
            seal["negative_cases"]
                .as_array()
                .unwrap()
                .iter()
                .map(|case| case["id"].as_str().unwrap())
                .collect::<Vec<_>>(),
            vec![
                "missing_manifest",
                "hidden_unreferenced_leaf",
                "manifest_height_ahead_of_state",
                "semantic_value_trailing_byte",
                "malformed_namespace_key",
            ]
        );
    }
}
