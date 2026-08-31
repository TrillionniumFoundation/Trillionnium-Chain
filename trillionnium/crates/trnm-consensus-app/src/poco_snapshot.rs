//! Cutoff-rooted PoCO snapshot namespace proofs.
//!
//! JMT orders key hashes, not key preimages. Prefix range proofs therefore
//! cannot establish namespace completeness. v0 commits one manifest with the
//! canonical entry count and ordered entry root, then proves the manifest and
//! every listed entry at one JMT version/root. Explicit missing queries use
//! ordinary ICS23 non-membership proofs.

use anyhow::{ensure, Context, Result};
use ics23::CommitmentProof;
use jmt::ics23_spec;
use prost::Message;
use sha2::{Digest, Sha256};
use trnm_consensus_types::{
    AuthenticatedFinalizedCutoffHeaderV0, BlockId, CertificateId, Epoch, Height, StateRoot,
};

use crate::auth_tree::{namespaced_key, poco_snapshot_key_components, StateNamespace};

const HASH_PREFIX: &[u8] = b"trnm.cev0.hash.v0";
const ENTRY_DOMAIN: &[u8] = b"trnm.poco-bft.snapshot-entry.v0";
const NODE_DOMAIN: &[u8] = b"trnm.poco-bft.snapshot-node.v0";
const ROOT_DOMAIN: &[u8] = b"trnm.poco-bft.snapshot-root.v0";
pub const MAX_POCO_SNAPSHOT_ENTRIES: usize = 10_000;
pub const MAX_POCO_SNAPSHOT_ABSENCES: usize = 1_000;
pub const MAX_POCO_SNAPSHOT_LOGICAL_KEY_BYTES: usize = 128;
pub const MAX_POCO_SNAPSHOT_VALUE_BYTES: usize = 65_536;
pub const MAX_POCO_SNAPSHOT_ICS23_PROOF_BYTES: usize = 1_048_576;
pub const MAX_POCO_SNAPSHOT_BUNDLE_BYTES: usize = 8 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum PocoSnapshotEntryKindV0 {
    ConsumptionCertificate = 1,
    ConsumerKeyAuthorization = 2,
    ConsumerNonce = 3,
    UniqueConsumptionTuple = 4,
    MeterDefinition = 5,
    Settlement = 6,
    MeasurementEvidence = 7,
    RelationshipClassification = 8,
    ValidatorRegistration = 9,
    ActiveBond = 10,
    JailStatus = 11,
    RevocationOrChallenge = 12,
    ValidatorConfiguration = 13,
    ConsensusParameters = 14,
    RolloutOrGovernance = 15,
    /// H3b2b1 application authority head. Kinds 1..=15 remain byte-for-byte
    /// frozen; this append-only discriminant makes the cross-entry authority,
    /// target-height watermark, and sparse anti-replay root part of the same
    /// manifest-authenticated cutoff projection consumed by H3b2b2.
    ApplicationAuthorityState = 16,
}

impl PocoSnapshotEntryKindV0 {
    pub fn from_u8(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::ConsumptionCertificate),
            2 => Ok(Self::ConsumerKeyAuthorization),
            3 => Ok(Self::ConsumerNonce),
            4 => Ok(Self::UniqueConsumptionTuple),
            5 => Ok(Self::MeterDefinition),
            6 => Ok(Self::Settlement),
            7 => Ok(Self::MeasurementEvidence),
            8 => Ok(Self::RelationshipClassification),
            9 => Ok(Self::ValidatorRegistration),
            10 => Ok(Self::ActiveBond),
            11 => Ok(Self::JailStatus),
            12 => Ok(Self::RevocationOrChallenge),
            13 => Ok(Self::ValidatorConfiguration),
            14 => Ok(Self::ConsensusParameters),
            15 => Ok(Self::RolloutOrGovernance),
            16 => Ok(Self::ApplicationAuthorityState),
            _ => anyhow::bail!("unknown PoCO snapshot entry kind"),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PocoSnapshotEntryV0 {
    pub kind: PocoSnapshotEntryKindV0,
    pub logical_key: Vec<u8>,
    pub value: Vec<u8>,
}

impl PocoSnapshotEntryV0 {
    pub fn new(
        kind: PocoSnapshotEntryKindV0,
        logical_key: Vec<u8>,
        value: Vec<u8>,
    ) -> Result<Self> {
        validate_logical_key(&logical_key)?;
        ensure!(
            !value.is_empty() && value.len() <= MAX_POCO_SNAPSHOT_VALUE_BYTES,
            "snapshot value length is outside bound"
        );
        Ok(Self {
            kind,
            logical_key,
            value,
        })
    }

    pub fn jmt_key(&self) -> Result<Vec<u8>> {
        poco_snapshot_entry_key(self.kind, &self.logical_key)
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        canonical_entry_bytes(self.kind, &self.logical_key, &self.value)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PocoSnapshotManifestV0 {
    cutoff_height: Height,
    entry_count: u32,
    entries_root: [u8; 32],
}

impl PocoSnapshotManifestV0 {
    pub fn from_entries(cutoff_height: Height, entries: &[PocoSnapshotEntryV0]) -> Result<Self> {
        validate_entries(entries)?;
        Ok(Self {
            cutoff_height,
            entry_count: u32::try_from(entries.len()).expect("hard bound fits u32"),
            entries_root: ordered_entries_root(entries),
        })
    }

    pub const fn cutoff_height(self) -> Height {
        self.cutoff_height
    }
    pub const fn entry_count(self) -> u32 {
        self.entry_count
    }
    pub const fn entries_root(self) -> [u8; 32] {
        self.entries_root
    }

    pub fn encode(self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(47);
        bytes.extend_from_slice(&0u16.to_be_bytes());
        bytes.push(StateNamespace::PocoSnapshot as u8);
        bytes.extend_from_slice(&self.cutoff_height.get().to_be_bytes());
        bytes.extend_from_slice(&self.entry_count.to_be_bytes());
        bytes.extend_from_slice(&self.entries_root);
        bytes
    }

    pub(crate) fn decode_exact(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() == 47,
            "snapshot manifest must be exactly 47 bytes"
        );
        ensure!(
            u16::from_be_bytes(bytes[0..2].try_into().expect("manifest length checked")) == 0,
            "snapshot manifest schema version mismatch"
        );
        ensure!(
            bytes[2] == StateNamespace::PocoSnapshot as u8,
            "snapshot manifest namespace mismatch"
        );
        let cutoff_height = Height::new(u64::from_be_bytes(
            bytes[3..11].try_into().expect("manifest length checked"),
        ));
        let entry_count =
            u32::from_be_bytes(bytes[11..15].try_into().expect("manifest length checked"));
        ensure!(
            entry_count as usize <= MAX_POCO_SNAPSHOT_ENTRIES,
            "snapshot manifest entry count exceeds hard bound"
        );
        let entries_root = bytes[15..47]
            .try_into()
            .expect("manifest root length checked");
        Ok(Self {
            cutoff_height,
            entry_count,
            entries_root,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum PocoSnapshotPhysicalKeyV0 {
    Manifest,
    Entry {
        kind: PocoSnapshotEntryKindV0,
        logical_key: Vec<u8>,
    },
}

pub(crate) fn decode_poco_snapshot_physical_key_v0_exact(
    key: &[u8],
) -> Result<Option<PocoSnapshotPhysicalKeyV0>> {
    let Some(components) = poco_snapshot_key_components(key)? else {
        return Ok(None);
    };
    match components.as_slice() {
        [manifest] if *manifest == b"manifest" => Ok(Some(PocoSnapshotPhysicalKeyV0::Manifest)),
        [entry, kind, logical_key] if *entry == b"entry" => {
            ensure!(kind.len() == 1, "PoCO snapshot entry kind is not u8");
            validate_logical_key(logical_key)?;
            Ok(Some(PocoSnapshotPhysicalKeyV0::Entry {
                kind: PocoSnapshotEntryKindV0::from_u8(kind[0])?,
                logical_key: logical_key.to_vec(),
            }))
        }
        _ => anyhow::bail!("unknown PoCO snapshot physical key layout"),
    }
}

#[derive(Clone, Debug)]
pub struct Ics23PointProofV0 {
    pub version: u64,
    pub root_hash: [u8; 32],
    pub key: Vec<u8>,
    pub value: Option<Vec<u8>>,
    pub encoded_commitment_proof: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct PocoSnapshotMemberProofV0 {
    pub entry: PocoSnapshotEntryV0,
    pub proof: Ics23PointProofV0,
}

#[derive(Clone, Debug)]
pub struct PocoSnapshotAbsenceProofV0 {
    pub kind: PocoSnapshotEntryKindV0,
    pub logical_key: Vec<u8>,
    pub proof: Ics23PointProofV0,
}

#[derive(Clone, Debug)]
pub struct PocoSnapshotNamespaceProofV0 {
    pub manifest: PocoSnapshotManifestV0,
    pub manifest_proof: Ics23PointProofV0,
    pub members: Vec<PocoSnapshotMemberProofV0>,
    pub absences: Vec<PocoSnapshotAbsenceProofV0>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedPocoSnapshotNamespaceV0 {
    version: u64,
    root_hash: [u8; 32],
    manifest: PocoSnapshotManifestV0,
    absence_count: u32,
}

impl VerifiedPocoSnapshotNamespaceV0 {
    pub const fn version(self) -> u64 {
        self.version
    }
    pub const fn root_hash(self) -> [u8; 32] {
        self.root_hash
    }
    pub const fn manifest(self) -> PocoSnapshotManifestV0 {
        self.manifest
    }
    pub const fn absence_count(self) -> u32 {
        self.absence_count
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthenticatedPocoSnapshotNamespaceV0 {
    proof_id: CertificateId,
    epoch: Epoch,
    cutoff_height: Height,
    cutoff_block_id: BlockId,
    cutoff_state_root: StateRoot,
    entries_root: [u8; 32],
    entry_count: u32,
    absence_count: u32,
}

impl AuthenticatedPocoSnapshotNamespaceV0 {
    pub const fn proof_id(self) -> CertificateId {
        self.proof_id
    }
    pub const fn epoch(self) -> Epoch {
        self.epoch
    }
    pub const fn cutoff_height(self) -> Height {
        self.cutoff_height
    }
    pub const fn cutoff_block_id(self) -> BlockId {
        self.cutoff_block_id
    }
    pub const fn cutoff_state_root(self) -> StateRoot {
        self.cutoff_state_root
    }
    pub const fn entries_root(self) -> [u8; 32] {
        self.entries_root
    }
    pub const fn entry_count(self) -> u32 {
        self.entry_count
    }
    pub const fn absence_count(self) -> u32 {
        self.absence_count
    }
}

pub fn verify_poco_snapshot_namespace_v0(
    expected_version: u64,
    expected_root: [u8; 32],
    bundle: &PocoSnapshotNamespaceProofV0,
) -> Result<VerifiedPocoSnapshotNamespaceV0> {
    verify_poco_snapshot_projection_v0(expected_version, expected_root, bundle, true)
}

/// Re-verifies a live PoCO projection against a later state head. The
/// manifest's encoded height is the version at which its projection last
/// changed (or was explicitly refreshed), while its membership proof is for
/// `expected_version`. At an actual epoch cutoff the public verifier above
/// still requires exact height equality.
pub(crate) fn verify_live_poco_snapshot_projection_v0(
    expected_version: u64,
    expected_root: [u8; 32],
    bundle: &PocoSnapshotNamespaceProofV0,
) -> Result<VerifiedPocoSnapshotNamespaceV0> {
    verify_poco_snapshot_projection_v0(expected_version, expected_root, bundle, false)
}

fn verify_poco_snapshot_projection_v0(
    expected_version: u64,
    expected_root: [u8; 32],
    bundle: &PocoSnapshotNamespaceProofV0,
    require_exact_manifest_height: bool,
) -> Result<VerifiedPocoSnapshotNamespaceV0> {
    ensure!(
        bundle.members.len() <= MAX_POCO_SNAPSHOT_ENTRIES,
        "too many snapshot members"
    );
    ensure!(
        bundle.absences.len() <= MAX_POCO_SNAPSHOT_ABSENCES,
        "too many snapshot absences"
    );
    validate_bundle_size(bundle)?;
    let entries = bundle
        .members
        .iter()
        .map(|member| member.entry.clone())
        .collect::<Vec<_>>();
    validate_entries(&entries)?;
    if require_exact_manifest_height {
        ensure!(
            bundle.manifest.cutoff_height().get() == expected_version,
            "manifest cutoff/version mismatch"
        );
    } else {
        ensure!(
            bundle.manifest.cutoff_height().get() <= expected_version,
            "live manifest version is ahead of state head"
        );
    }
    ensure!(
        bundle.manifest.entry_count() as usize == entries.len(),
        "manifest entry count mismatch"
    );
    ensure!(
        bundle.manifest.entries_root() == ordered_entries_root(&entries),
        "manifest ordered entry root mismatch"
    );
    verify_membership(
        &bundle.manifest_proof,
        expected_version,
        expected_root,
        &poco_snapshot_manifest_key()?,
        &bundle.manifest.encode(),
    )?;
    for member in &bundle.members {
        verify_membership(
            &member.proof,
            expected_version,
            expected_root,
            &member.entry.jmt_key()?,
            &member.entry.value,
        )?;
    }
    let mut previous_absence = None;
    for absence in &bundle.absences {
        validate_logical_key(&absence.logical_key)?;
        let identity = (absence.kind, absence.logical_key.as_slice());
        if let Some(previous) = previous_absence {
            ensure!(
                previous < identity,
                "snapshot absence queries are not canonical and unique"
            );
        }
        previous_absence = Some(identity);
        ensure!(
            entries
                .binary_search_by(|entry| (entry.kind, entry.logical_key.as_slice()).cmp(&identity))
                .is_err(),
            "absence query names a manifest member"
        );
        verify_non_membership(
            &absence.proof,
            expected_version,
            expected_root,
            &poco_snapshot_entry_key(absence.kind, &absence.logical_key)?,
        )?;
    }
    Ok(VerifiedPocoSnapshotNamespaceV0 {
        version: expected_version,
        root_hash: expected_root,
        manifest: bundle.manifest,
        absence_count: u32::try_from(bundle.absences.len()).expect("hard bound fits u32"),
    })
}

fn validate_bundle_size(bundle: &PocoSnapshotNamespaceProofV0) -> Result<()> {
    let mut total = bundle.manifest.encode().len();
    total = checked_size_add(total, point_size(&bundle.manifest_proof)?)?;
    for member in &bundle.members {
        total = checked_size_add(total, member.entry.logical_key.len())?;
        total = checked_size_add(total, member.entry.value.len())?;
        total = checked_size_add(total, point_size(&member.proof)?)?;
    }
    for absence in &bundle.absences {
        total = checked_size_add(total, absence.logical_key.len())?;
        total = checked_size_add(total, point_size(&absence.proof)?)?;
    }
    ensure!(
        total <= MAX_POCO_SNAPSHOT_BUNDLE_BYTES,
        "snapshot proof bundle exceeds 8 MiB"
    );
    Ok(())
}

fn point_size(point: &Ics23PointProofV0) -> Result<usize> {
    ensure!(
        point.encoded_commitment_proof.len() <= MAX_POCO_SNAPSHOT_ICS23_PROOF_BYTES,
        "ICS23 proof exceeds hard bound"
    );
    let mut total = point.key.len();
    total = checked_size_add(total, point.value.as_ref().map_or(0, Vec::len))?;
    checked_size_add(total, point.encoded_commitment_proof.len())
}

fn checked_size_add(left: usize, right: usize) -> Result<usize> {
    left.checked_add(right)
        .context("snapshot proof bundle size overflow")
}

pub fn bind_poco_snapshot_namespace_to_cutoff_v0(
    verified: VerifiedPocoSnapshotNamespaceV0,
    cutoff: &AuthenticatedFinalizedCutoffHeaderV0,
) -> Result<AuthenticatedPocoSnapshotNamespaceV0> {
    ensure!(
        verified.version == cutoff.cutoff_height().get(),
        "snapshot version does not equal cutoff height"
    );
    ensure!(
        verified.root_hash == *cutoff.cutoff_state_root().as_bytes(),
        "snapshot root does not equal cutoff state root"
    );
    ensure!(
        verified.manifest.cutoff_height() == cutoff.cutoff_height(),
        "manifest does not name cutoff height"
    );
    Ok(AuthenticatedPocoSnapshotNamespaceV0 {
        proof_id: cutoff.proof_id(),
        epoch: cutoff.epoch(),
        cutoff_height: cutoff.cutoff_height(),
        cutoff_block_id: cutoff.cutoff_block_id(),
        cutoff_state_root: cutoff.cutoff_state_root(),
        entries_root: verified.manifest.entries_root(),
        entry_count: verified.manifest.entry_count(),
        absence_count: verified.absence_count,
    })
}

pub fn poco_snapshot_manifest_key() -> Result<Vec<u8>> {
    namespaced_key(StateNamespace::PocoSnapshot, &[b"manifest"])
}

pub fn poco_snapshot_entry_key(
    kind: PocoSnapshotEntryKindV0,
    logical_key: &[u8],
) -> Result<Vec<u8>> {
    validate_logical_key(logical_key)?;
    namespaced_key(
        StateNamespace::PocoSnapshot,
        &[b"entry", &[kind as u8], logical_key],
    )
}

pub(crate) fn validate_logical_key(key: &[u8]) -> Result<()> {
    ensure!(
        !key.is_empty() && key.len() <= MAX_POCO_SNAPSHOT_LOGICAL_KEY_BYTES,
        "snapshot logical key length is outside bound"
    );
    Ok(())
}

pub(crate) fn validate_entries(entries: &[PocoSnapshotEntryV0]) -> Result<()> {
    ensure!(
        entries.len() <= MAX_POCO_SNAPSHOT_ENTRIES,
        "too many snapshot entries"
    );
    let mut previous = None;
    for entry in entries {
        validate_logical_key(&entry.logical_key)?;
        ensure!(
            !entry.value.is_empty() && entry.value.len() <= MAX_POCO_SNAPSHOT_VALUE_BYTES,
            "snapshot value length is outside bound"
        );
        let identity = (entry.kind, entry.logical_key.as_slice());
        if let Some(previous) = previous {
            ensure!(
                previous < identity,
                "snapshot entries are not canonical and unique"
            );
        }
        previous = Some(identity);
    }
    Ok(())
}

fn canonical_entry_bytes(
    kind: PocoSnapshotEntryKindV0,
    logical_key: &[u8],
    value: &[u8],
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(11 + logical_key.len() + value.len());
    bytes.extend_from_slice(&0u16.to_be_bytes());
    bytes.push(kind as u8);
    bytes.extend_from_slice(&(logical_key.len() as u32).to_be_bytes());
    bytes.extend_from_slice(logical_key);
    bytes.extend_from_slice(&(value.len() as u32).to_be_bytes());
    bytes.extend_from_slice(value);
    bytes
}

pub(crate) fn ordered_entries_root(entries: &[PocoSnapshotEntryV0]) -> [u8; 32] {
    let mut layer = entries
        .iter()
        .map(|entry| domain_hash(ENTRY_DOMAIN, &entry.canonical_bytes()))
        .collect::<Vec<_>>();
    let mut level = 0u32;
    while layer.len() > 1 {
        let mut next = Vec::with_capacity(layer.len().div_ceil(2));
        for pair in layer.chunks(2) {
            let left = pair[0];
            let right = pair.get(1).copied().unwrap_or(left);
            let mut encoded = Vec::with_capacity(70);
            encoded.extend_from_slice(&0u16.to_be_bytes());
            encoded.extend_from_slice(&level.to_be_bytes());
            encoded.extend_from_slice(&left);
            encoded.extend_from_slice(&right);
            next.push(domain_hash(NODE_DOMAIN, &encoded));
        }
        layer = next;
        level = level.checked_add(1).expect("hard bound keeps tree finite");
    }
    let mut encoded = Vec::with_capacity(39);
    encoded.extend_from_slice(&0u16.to_be_bytes());
    encoded.extend_from_slice(&(entries.len() as u32).to_be_bytes());
    match layer.first() {
        Some(inner) => {
            encoded.push(1);
            encoded.extend_from_slice(inner);
        }
        None => encoded.push(0),
    }
    domain_hash(ROOT_DOMAIN, &encoded)
}

fn domain_hash(domain: &[u8], encoded: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for frame in [HASH_PREFIX, domain, encoded] {
        hasher.update((frame.len() as u32).to_be_bytes());
        hasher.update(frame);
    }
    hasher.finalize().into()
}

fn decode_proof(point: &Ics23PointProofV0) -> Result<CommitmentProof> {
    ensure!(
        point.encoded_commitment_proof.len() <= MAX_POCO_SNAPSHOT_ICS23_PROOF_BYTES,
        "ICS23 proof exceeds hard bound"
    );
    CommitmentProof::decode(point.encoded_commitment_proof.as_slice()).context("decode ICS23 proof")
}

fn verify_membership(
    point: &Ics23PointProofV0,
    version: u64,
    root: [u8; 32],
    key: &[u8],
    value: &[u8],
) -> Result<()> {
    let root = root.to_vec();
    ensure!(
        point.version == version
            && root == point.root_hash
            && point.key == key
            && point.value.as_deref() == Some(value),
        "membership proof metadata mismatch"
    );
    ensure!(
        ics23::verify_membership::<ics23::HostFunctionsManager>(
            &decode_proof(point)?,
            &ics23_spec(),
            &root,
            key,
            value
        ),
        "ICS23 membership verification failed"
    );
    Ok(())
}

fn verify_non_membership(
    point: &Ics23PointProofV0,
    version: u64,
    root: [u8; 32],
    key: &[u8],
) -> Result<()> {
    let root = root.to_vec();
    ensure!(
        point.version == version
            && root == point.root_hash
            && point.key == key
            && point.value.is_none(),
        "non-membership proof metadata mismatch"
    );
    ensure!(
        ics23::verify_non_membership::<ics23::HostFunctionsManager>(
            &decode_proof(point)?,
            &ics23_spec(),
            &root,
            key
        ),
        "ICS23 non-membership verification failed"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth_tree::{AuthProof, AuthWrite, InMemoryAuthTree};
    use crate::poco_transition::{
        encode_poco_snapshot_value_envelope_v0, plan_poco_snapshot_transition_v0,
        poco_state_head_from_authenticated_cutoff_v0, PocoSnapshotMutationV0, PocoWritePermitV0,
    };
    use serde_json::Value;

    const VECTOR: &str = include_str!(
        "../../../../docs/protocol/poco-bft-v0/vectors/poco-snapshot-namespace-v0.json"
    );

    fn point(proof: AuthProof) -> Ics23PointProofV0 {
        let encoded_commitment_proof = proof.encoded_commitment_proof();
        Ics23PointProofV0 {
            version: proof.version,
            root_hash: proof.root_hash.0,
            key: proof.key,
            value: proof.value,
            encoded_commitment_proof,
        }
    }

    fn fixture() -> (PocoSnapshotNamespaceProofV0, [u8; 32]) {
        let entries = vec![
            PocoSnapshotEntryV0::new(
                PocoSnapshotEntryKindV0::ConsumptionCertificate,
                b"cert-a".to_vec(),
                b"accepted".to_vec(),
            )
            .unwrap(),
            PocoSnapshotEntryV0::new(
                PocoSnapshotEntryKindV0::ConsumerNonce,
                b"consumer-a/provider-a".to_vec(),
                9u64.to_be_bytes().to_vec(),
            )
            .unwrap(),
            PocoSnapshotEntryV0::new(
                PocoSnapshotEntryKindV0::MeterDefinition,
                b"meter-a/7".to_vec(),
                b"active".to_vec(),
            )
            .unwrap(),
        ];
        let manifest = PocoSnapshotManifestV0::from_entries(Height::new(6), &entries).unwrap();
        let mut tree = InMemoryAuthTree::default();
        for version in 0..6 {
            tree.put_value_set(version, std::iter::empty()).unwrap();
        }
        let mut writes = vec![AuthWrite::put_poco_snapshot(
            PocoWritePermitV0::test_only(),
            poco_snapshot_manifest_key().unwrap(),
            manifest.encode(),
        )
        .unwrap()];
        for entry in &entries {
            writes.push(
                AuthWrite::put_poco_snapshot(
                    PocoWritePermitV0::test_only(),
                    entry.jmt_key().unwrap(),
                    entry.value.clone(),
                )
                .unwrap(),
            );
        }
        let root = tree.put_value_set(6, writes).unwrap().0;
        let members = entries
            .into_iter()
            .map(|entry| {
                let proof = point(tree.prove(6, entry.jmt_key().unwrap()).unwrap());
                PocoSnapshotMemberProofV0 { entry, proof }
            })
            .collect();
        let absent_key = b"cert-missing".to_vec();
        let absence = PocoSnapshotAbsenceProofV0 {
            kind: PocoSnapshotEntryKindV0::ConsumptionCertificate,
            logical_key: absent_key.clone(),
            proof: point(
                tree.prove(
                    6,
                    poco_snapshot_entry_key(
                        PocoSnapshotEntryKindV0::ConsumptionCertificate,
                        &absent_key,
                    )
                    .unwrap(),
                )
                .unwrap(),
            ),
        };
        (
            PocoSnapshotNamespaceProofV0 {
                manifest,
                manifest_proof: point(
                    tree.prove(6, poco_snapshot_manifest_key().unwrap())
                        .unwrap(),
                ),
                members,
                absences: vec![absence],
            },
            root,
        )
    }

    fn semantic_nonce_identity(consumer: &[u8], consumer_key: &[u8], provider: &[u8]) -> Vec<u8> {
        let mut identity = Vec::new();
        for value in [consumer, consumer_key, provider] {
            identity.extend_from_slice(&(value.len() as u32).to_be_bytes());
            identity.extend_from_slice(value);
        }
        identity
    }

    fn semantic_nonce_payload(
        consumer: &[u8],
        consumer_key: &[u8],
        provider: &[u8],
        nonce: u64,
    ) -> Vec<u8> {
        let mut payload = semantic_nonce_identity(consumer, consumer_key, provider);
        payload.extend_from_slice(&nonce.to_be_bytes());
        payload
    }

    fn semantic_fixture() -> (
        InMemoryAuthTree,
        PocoSnapshotNamespaceProofV0,
        AuthenticatedPocoSnapshotNamespaceV0,
        Vec<u8>,
        Vec<u8>,
    ) {
        let identity = semantic_nonce_identity(b"consumer-a", b"consumer-key-a", b"provider-a");
        let (logical_key, value) = encode_poco_snapshot_value_envelope_v0(
            PocoSnapshotEntryKindV0::ConsumerNonce,
            1,
            &identity,
            &semantic_nonce_payload(b"consumer-a", b"consumer-key-a", b"provider-a", 9),
        )
        .unwrap();
        let entry = PocoSnapshotEntryV0::new(
            PocoSnapshotEntryKindV0::ConsumerNonce,
            logical_key.clone(),
            value.clone(),
        )
        .unwrap();
        let manifest =
            PocoSnapshotManifestV0::from_entries(Height::new(6), std::slice::from_ref(&entry))
                .unwrap();
        let extra_identity = semantic_nonce_identity(b"consumer-x", b"key-x", b"provider-x");
        let (extra_logical_key, extra_value) = encode_poco_snapshot_value_envelope_v0(
            PocoSnapshotEntryKindV0::ConsumerNonce,
            1,
            &extra_identity,
            &semantic_nonce_payload(b"consumer-x", b"key-x", b"provider-x", 1),
        )
        .unwrap();
        let mut tree = InMemoryAuthTree::default();
        for version in 0..6 {
            tree.put_value_set(version, std::iter::empty()).unwrap();
        }
        let root = tree
            .put_value_set(
                6,
                [
                    AuthWrite::put_poco_snapshot(
                        PocoWritePermitV0::test_only(),
                        poco_snapshot_manifest_key().unwrap(),
                        manifest.encode(),
                    )
                    .unwrap(),
                    AuthWrite::put_poco_snapshot(
                        PocoWritePermitV0::test_only(),
                        entry.jmt_key().unwrap(),
                        value.clone(),
                    )
                    .unwrap(),
                    AuthWrite::put_poco_snapshot(
                        PocoWritePermitV0::test_only(),
                        poco_snapshot_entry_key(
                            PocoSnapshotEntryKindV0::ConsumerNonce,
                            &extra_logical_key,
                        )
                        .unwrap(),
                        extra_value,
                    )
                    .unwrap(),
                ],
            )
            .unwrap()
            .0;
        let bundle = PocoSnapshotNamespaceProofV0 {
            manifest,
            manifest_proof: point(
                tree.prove(6, poco_snapshot_manifest_key().unwrap())
                    .unwrap(),
            ),
            members: vec![PocoSnapshotMemberProofV0 {
                proof: point(tree.prove(6, entry.jmt_key().unwrap()).unwrap()),
                entry,
            }],
            absences: Vec::new(),
        };
        let authenticated = AuthenticatedPocoSnapshotNamespaceV0 {
            proof_id: CertificateId::new([1; 32]),
            epoch: Epoch::new(0),
            cutoff_height: Height::new(6),
            cutoff_block_id: BlockId::new([2; 32]),
            cutoff_state_root: StateRoot::new(root),
            entries_root: manifest.entries_root(),
            entry_count: 1,
            absence_count: 0,
        };
        (tree, bundle, authenticated, logical_key, value)
    }

    #[test]
    fn real_jmt_membership_non_membership_and_manifest_completeness_verify() {
        let (bundle, root) = fixture();
        let verified = verify_poco_snapshot_namespace_v0(6, root, &bundle).unwrap();
        assert_eq!(verified.version(), 6);
        assert_eq!(verified.root_hash(), root);
        assert_eq!(verified.manifest().entry_count(), 3);
        assert_eq!(verified.absence_count(), 1);
    }

    #[test]
    fn committed_manifest_vector_matches_rust_key_and_root_projection() {
        let vector: Value = serde_json::from_str(VECTOR).unwrap();
        let (bundle, _) = fixture();
        assert_eq!(
            hex::encode(bundle.manifest.entries_root()),
            vector["entries_root_hex"].as_str().unwrap()
        );
        assert_eq!(
            hex::encode(bundle.manifest.encode()),
            vector["manifest_cev0_hex"].as_str().unwrap()
        );
        assert_eq!(
            hex::encode(poco_snapshot_manifest_key().unwrap()),
            vector["manifest_jmt_key_hex"].as_str().unwrap()
        );
        for (member, expected) in bundle
            .members
            .iter()
            .zip(vector["entries"].as_array().unwrap())
        {
            assert_eq!(
                hex::encode(member.entry.canonical_bytes()),
                expected["cev0_hex"].as_str().unwrap()
            );
            assert_eq!(
                hex::encode(member.entry.jmt_key().unwrap()),
                expected["jmt_key_hex"].as_str().unwrap()
            );
        }
    }

    #[test]
    fn root_version_manifest_order_and_proof_substitution_fail_closed() {
        let (bundle, root) = fixture();
        assert!(verify_poco_snapshot_namespace_v0(7, root, &bundle).is_err());
        assert!(verify_poco_snapshot_namespace_v0(6, [9; 32], &bundle).is_err());
        let mut omitted = bundle.clone();
        omitted.members.pop();
        assert!(verify_poco_snapshot_namespace_v0(6, root, &omitted).is_err());
        let mut reordered = bundle.clone();
        reordered.members.swap(0, 1);
        assert!(verify_poco_snapshot_namespace_v0(6, root, &reordered).is_err());
        let mut substituted = bundle.clone();
        substituted.members[0].proof = substituted.members[1].proof.clone();
        assert!(verify_poco_snapshot_namespace_v0(6, root, &substituted).is_err());
        let mut bad_manifest = bundle;
        bad_manifest.manifest.entries_root[0] ^= 1;
        assert!(verify_poco_snapshot_namespace_v0(6, root, &bad_manifest).is_err());
    }

    #[test]
    fn aggregate_bundle_bound_precedes_proof_decode() {
        let (mut bundle, root) = fixture();
        let template = bundle.absences[0].clone();
        bundle.absences.clear();
        for index in 0..9u8 {
            let mut absence = template.clone();
            absence.logical_key = vec![b'x', index.saturating_add(1)];
            absence.proof.key =
                poco_snapshot_entry_key(absence.kind, &absence.logical_key).unwrap();
            absence.proof.encoded_commitment_proof = vec![0; MAX_POCO_SNAPSHOT_ICS23_PROOF_BYTES];
            bundle.absences.push(absence);
        }
        let error = verify_poco_snapshot_namespace_v0(6, root, &bundle).unwrap_err();
        assert!(error.to_string().contains("exceeds 8 MiB"));
    }

    #[test]
    fn semantic_compare_and_set_and_manifest_share_one_jmt_version() {
        let (mut tree, bundle, authenticated, logical_key, old_value) = semantic_fixture();
        let identity = semantic_nonce_identity(b"consumer-a", b"consumer-key-a", b"provider-a");
        let (_, next_value) = encode_poco_snapshot_value_envelope_v0(
            PocoSnapshotEntryKindV0::ConsumerNonce,
            2,
            &identity,
            &semantic_nonce_payload(b"consumer-a", b"consumer-key-a", b"provider-a", 10),
        )
        .unwrap();
        let mutation = PocoSnapshotMutationV0::put(
            PocoSnapshotEntryKindV0::ConsumerNonce,
            logical_key.clone(),
            Some(old_value),
            next_value.clone(),
        )
        .unwrap();
        let head = poco_state_head_from_authenticated_cutoff_v0(authenticated);
        let mut alternate_history = InMemoryAuthTree::default();
        let initial_writes = tree
            .verified_live_values(6)
            .unwrap()
            .into_iter()
            .map(|(key, value)| {
                AuthWrite::put_poco_snapshot(PocoWritePermitV0::test_only(), key, value).unwrap()
            })
            .collect::<Vec<_>>();
        alternate_history.put_value_set(0, initial_writes).unwrap();
        for version in 1..=6 {
            alternate_history
                .put_value_set(version, std::iter::empty())
                .unwrap();
        }
        assert_eq!(tree.root_hash(6), alternate_history.root_hash(6));
        let planned = plan_poco_snapshot_transition_v0(
            &tree,
            head,
            &bundle,
            Height::new(7),
            std::slice::from_ref(&mutation),
            false,
            Vec::new(),
        )
        .unwrap();
        let cross_history_plan = plan_poco_snapshot_transition_v0(
            &tree,
            head,
            &bundle,
            Height::new(7),
            std::slice::from_ref(&mutation),
            false,
            Vec::new(),
        )
        .unwrap();
        let committed = planned.apply(&mut tree).unwrap();
        let alternate_committed = cross_history_plan.apply(&mut alternate_history).unwrap();
        assert_eq!(
            alternate_committed.target_state_root(),
            committed.target_state_root()
        );
        assert_eq!(
            alternate_history.verified_live_values(7).unwrap(),
            tree.verified_live_values(7).unwrap(),
            "cross-history apply must re-materialize every unchanged live leaf against the supplied tree history",
        );
        assert_eq!(
            alternate_history
                .prove(
                    7,
                    poco_snapshot_entry_key(PocoSnapshotEntryKindV0::ConsumerNonce, &logical_key,)
                        .unwrap(),
                )
                .unwrap()
                .value,
            Some(next_value.clone())
        );
        assert_eq!(committed.target_height(), Height::new(7));
        assert_eq!(
            tree.prove(
                7,
                poco_snapshot_entry_key(PocoSnapshotEntryKindV0::ConsumerNonce, &logical_key)
                    .unwrap()
            )
            .unwrap()
            .value,
            Some(next_value.clone())
        );
        let entry = PocoSnapshotEntryV0::new(
            PocoSnapshotEntryKindV0::ConsumerNonce,
            logical_key.clone(),
            next_value,
        )
        .unwrap();
        let manifest =
            PocoSnapshotManifestV0::from_entries(Height::new(7), std::slice::from_ref(&entry))
                .unwrap();
        assert_eq!(
            tree.prove(7, poco_snapshot_manifest_key().unwrap())
                .unwrap()
                .value,
            Some(manifest.encode())
        );

        let bundle_7 = PocoSnapshotNamespaceProofV0 {
            manifest,
            manifest_proof: point(
                tree.prove(7, poco_snapshot_manifest_key().unwrap())
                    .unwrap(),
            ),
            members: vec![PocoSnapshotMemberProofV0 {
                proof: point(tree.prove(7, entry.jmt_key().unwrap()).unwrap()),
                entry,
            }],
            absences: Vec::new(),
        };
        let head_7 = committed.state_head();
        let no_op = plan_poco_snapshot_transition_v0(
            &tree,
            head_7,
            &bundle_7,
            Height::new(8),
            &[],
            false,
            Vec::new(),
        )
        .unwrap();
        let applied_8 = no_op.apply(&mut tree).unwrap();
        assert_eq!(
            tree.prove(8, poco_snapshot_manifest_key().unwrap())
                .unwrap()
                .value,
            Some(
                PocoSnapshotManifestV0::from_entries(
                    Height::new(7),
                    &[bundle_7.members[0].entry.clone()]
                )
                .unwrap()
                .encode()
            )
        );

        let entry_8 = bundle_7.members[0].entry.clone();
        let bundle_8 = PocoSnapshotNamespaceProofV0 {
            manifest: bundle_7.manifest,
            manifest_proof: point(
                tree.prove(8, poco_snapshot_manifest_key().unwrap())
                    .unwrap(),
            ),
            members: vec![PocoSnapshotMemberProofV0 {
                proof: point(tree.prove(8, entry_8.jmt_key().unwrap()).unwrap()),
                entry: entry_8.clone(),
            }],
            absences: Vec::new(),
        };
        let head_8 = applied_8.state_head();
        let refresh = plan_poco_snapshot_transition_v0(
            &tree,
            head_8,
            &bundle_8,
            Height::new(9),
            &[],
            true,
            Vec::new(),
        )
        .unwrap();
        let stale_sibling = plan_poco_snapshot_transition_v0(
            &tree,
            head_8,
            &bundle_8,
            Height::new(9),
            &[],
            true,
            Vec::new(),
        )
        .unwrap();
        let applied_9 = refresh.apply(&mut tree).unwrap();
        assert_eq!(applied_9.state_head().manifest_height(), Height::new(9));
        assert!(stale_sibling.apply(&mut tree).is_err());
        assert_eq!(
            tree.prove(9, poco_snapshot_manifest_key().unwrap())
                .unwrap()
                .value,
            Some(
                PocoSnapshotManifestV0::from_entries(Height::new(9), &[entry_8])
                    .unwrap()
                    .encode()
            )
        );
    }

    #[test]
    fn token_laundering_and_generic_namespace_bypass_fail_closed() {
        let (tree, bundle, authenticated, _, _) = semantic_fixture();
        let head = poco_state_head_from_authenticated_cutoff_v0(authenticated);
        let mut substituted = bundle.clone();
        substituted.members[0].entry.value[0] ^= 1;
        assert!(plan_poco_snapshot_transition_v0(
            &tree,
            head,
            &substituted,
            Height::new(7),
            &[],
            false,
            Vec::new(),
        )
        .is_err());
        assert!(AuthWrite::put(poco_snapshot_manifest_key().unwrap(), vec![1]).is_err());
        assert!(plan_poco_snapshot_transition_v0(
            &tree,
            head,
            &bundle,
            Height::new(7),
            &[],
            false,
            vec![AuthWrite::put_poco_snapshot(
                PocoWritePermitV0::test_only(),
                poco_snapshot_manifest_key().unwrap(),
                vec![1],
            )
            .unwrap(),],
        )
        .is_err());

        let extra_identity = semantic_nonce_identity(b"consumer-x", b"key-x", b"provider-x");
        let (extra_key, extra_value) = encode_poco_snapshot_value_envelope_v0(
            PocoSnapshotEntryKindV0::ConsumerNonce,
            1,
            &extra_identity,
            &semantic_nonce_payload(b"consumer-x", b"key-x", b"provider-x", 1),
        )
        .unwrap();
        let overwrite_unmanifested = PocoSnapshotMutationV0::put(
            PocoSnapshotEntryKindV0::ConsumerNonce,
            extra_key,
            None,
            extra_value,
        )
        .unwrap();
        assert!(plan_poco_snapshot_transition_v0(
            &tree,
            head,
            &bundle,
            Height::new(7),
            &[overwrite_unmanifested],
            false,
            Vec::new(),
        )
        .is_err());
    }
}
