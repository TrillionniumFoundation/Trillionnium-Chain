//! Canonical evidence for one isolated stale/rollback startup rejection.
//!
//! This protocol never opens the primary authority root through Node.  It
//! inventories a fully independent snapshot, calls Node's typed deployed-cut
//! reopen entry against that isolated root, and issues evidence only from the
//! actual typed failure.  A successful reopen is a terminal error and cannot
//! produce a verified carrier.  The primary authority root and process-1
//! runtime journal are inventoried before and after the attempt; any change is
//! fail-closed.
//!
//! The module does not copy snapshots, inject faults, start a network, append
//! runtime events, or activate recovery.  The standalone Python runner
//! prepares the isolated, content-addressed mutation before invoking this
//! seam; the live eight-fault scheduler still requires a stable RestartCut
//! join before it may use that runner.

use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    ffi::OsString,
    fmt,
    fs::{self, OpenOptions},
    io::{Read, Write},
    os::unix::{
        ffi::OsStrExt,
        fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::{Path, PathBuf},
};

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use trnm_consensus_types::{ValidatorId, ValidatorSet};

use crate::{
    config::{LoadedValidatorConfig, PublicReportVerifierContext},
    fleet_barrier::{
        CommonCampaignContextV1, FleetStartCertificateV1, MAX_FLEET_START_CERTIFICATE_BYTES_V1,
    },
};

const EVIDENCE_MAGIC_V1: &[u8; 8] = b"TRNMISR1";
const WIRE_VERSION_V1: u16 = 1;
const SIGNING_DOMAIN_V1: &[u8] = b"trnm.poco-g3.isolated-startup-rejection-signature.v1";
const EVIDENCE_DIGEST_DOMAIN_V1: &[u8] = b"trnm.poco-g3.isolated-startup-rejection-evidence.v1";
const ROOT_CONTENT_DOMAIN_V1: &[u8] = b"trnm.poco-g3.isolated-root-content.v1";
const ROOT_INVENTORY_DOMAIN_V1: &[u8] = b"trnm.poco-g3.isolated-root-inventory.v1";
const FILE_CONTENT_DOMAIN_V1: &[u8] = b"trnm.poco-g3.isolated-file-content.v1";
const SIGNATURE_BYTES_V1: usize = 64;
const MAX_EVIDENCE_BYTES_V1: usize = 64 * 1024;
const MAX_CAMPAIGN_BYTES_V1: usize = 16 * 1024;
const MAX_STAGE_BYTES_V1: usize = 128;
const MAX_TREE_ENTRIES_V1: usize = 4_096;
const MAX_FILE_BYTES_V1: u64 = 512 * 1024 * 1024;
const MAX_TREE_BYTES_V1: u64 = 2 * 1024 * 1024 * 1024;
const FLEET_START_CERTIFICATE_FILE_V1: &str = "fleet-start-certificate.bin";
const EVIDENCE_NEXT_SUFFIX_V1: &str = ".next";

pub const MAX_ISOLATED_STARTUP_REJECTION_EVIDENCE_BYTES_V1: usize = MAX_EVIDENCE_BYTES_V1;

/// Operational mutation profiles accepted by the isolated attempt seam.
///
/// A stale snapshot must preserve the exact path/type/mode inventory while
/// changing at least two file contents.  A rollback attempt preserves that
/// inventory and substitutes exactly one file.  This makes the label derived
/// from the observed mutation shape rather than caller-selected prose.  The
/// protocol does not claim an external monotonic proof that substituted bytes
/// are historically older.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum IsolatedStartupFaultKindV1 {
    StaleSnapshot = 1,
    RollbackAttempt = 2,
}

impl IsolatedStartupFaultKindV1 {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::StaleSnapshot => "stale_snapshot",
            Self::RollbackAttempt => "rollback_attempt",
        }
    }

    pub fn parse(value: &str) -> Result<Self, IsolatedStartupRejectionErrorV1> {
        match value {
            "stale_snapshot" => Ok(Self::StaleSnapshot),
            "rollback_attempt" => Ok(Self::RollbackAttempt),
            _ => Err(IsolatedStartupRejectionErrorV1::Malformed("fault kind")),
        }
    }

    fn decode(value: u8) -> Result<Self, IsolatedStartupRejectionErrorV1> {
        match value {
            1 => Ok(Self::StaleSnapshot),
            2 => Ok(Self::RollbackAttempt),
            _ => Err(IsolatedStartupRejectionErrorV1::Malformed("fault kind")),
        }
    }
}

/// Stable class of the real Node entry which rejected the snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum IsolatedNodeStartupErrorClassV1 {
    DeployedOrdinaryReopenV0 = 1,
}

impl IsolatedNodeStartupErrorClassV1 {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DeployedOrdinaryReopenV0 => "deployed_ordinary_reopen_v0",
        }
    }

    fn decode(value: u8) -> Result<Self, IsolatedStartupRejectionErrorV1> {
        match value {
            1 => Ok(Self::DeployedOrdinaryReopenV0),
            _ => Err(IsolatedStartupRejectionErrorV1::Malformed(
                "Node error class",
            )),
        }
    }
}

/// Machine-independent projection of one closed filesystem tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IsolatedRootInventoryFactsV1 {
    content_sha256: [u8; 32],
    inventory_sha256: [u8; 32],
    directory_count: u32,
    file_count: u32,
    total_file_bytes: u64,
}

impl IsolatedRootInventoryFactsV1 {
    pub const fn content_sha256(self) -> [u8; 32] {
        self.content_sha256
    }

    pub const fn inventory_sha256(self) -> [u8; 32] {
        self.inventory_sha256
    }

    pub const fn directory_count(self) -> u32 {
        self.directory_count
    }

    pub const fn file_count(self) -> u32 {
        self.file_count
    }

    pub const fn total_file_bytes(self) -> u64 {
        self.total_file_bytes
    }

    fn validate(self) -> Result<(), IsolatedStartupRejectionErrorV1> {
        if self.content_sha256 == [0; 32]
            || self.inventory_sha256 == [0; 32]
            || self.directory_count == 0
            || self.file_count == 0
            || self.total_file_bytes == 0
        {
            return Err(IsolatedStartupRejectionErrorV1::Malformed(
                "root inventory facts",
            ));
        }
        Ok(())
    }

    fn encode(self, output: &mut Vec<u8>) {
        output.extend_from_slice(&self.content_sha256);
        output.extend_from_slice(&self.inventory_sha256);
        output.extend_from_slice(&self.directory_count.to_be_bytes());
        output.extend_from_slice(&self.file_count.to_be_bytes());
        output.extend_from_slice(&self.total_file_bytes.to_be_bytes());
    }

    fn decode(cursor: &mut RejectionCursor<'_>) -> Result<Self, IsolatedStartupRejectionErrorV1> {
        let value = Self {
            content_sha256: cursor.array()?,
            inventory_sha256: cursor.array()?,
            directory_count: u32::from_be_bytes(cursor.array()?),
            file_count: u32::from_be_bytes(cursor.array()?),
            total_file_bytes: u64::from_be_bytes(cursor.array()?),
        };
        value.validate()?;
        Ok(value)
    }
}

/// Signed canonical attestation produced only after one real typed Node
/// rejection.  Decoding authenticates its signature but does not produce the
/// non-cloneable carrier until the raw FleetStart certificate is joined.
#[derive(Debug, PartialEq, Eq)]
pub struct IsolatedStartupRejectionEvidenceV1 {
    campaign: CommonCampaignContextV1,
    origin: ValidatorId,
    target_config_sha256: [u8; 32],
    fleet_start_certificate_sha256: [u8; 32],
    fault_kind: IsolatedStartupFaultKindV1,
    primary_before: IsolatedRootInventoryFactsV1,
    primary_after: IsolatedRootInventoryFactsV1,
    isolated_before: IsolatedRootInventoryFactsV1,
    isolated_after: IsolatedRootInventoryFactsV1,
    changed_file_count: u32,
    attempt_nonce: [u8; 32],
    node_error_class: IsolatedNodeStartupErrorClassV1,
    node_error_stage: String,
    node_error_detail_sha256: [u8; 32],
    runtime_journal_before_sha256: [u8; 32],
    runtime_journal_after_sha256: [u8; 32],
    runtime_journal_bytes: u64,
    process_instance: u64,
    network_started: bool,
    signature: [u8; SIGNATURE_BYTES_V1],
}

impl IsolatedStartupRejectionEvidenceV1 {
    pub const fn campaign(&self) -> &CommonCampaignContextV1 {
        &self.campaign
    }

    pub const fn origin(&self) -> ValidatorId {
        self.origin
    }

    pub const fn fault_kind(&self) -> IsolatedStartupFaultKindV1 {
        self.fault_kind
    }

    pub const fn target_config_sha256(&self) -> [u8; 32] {
        self.target_config_sha256
    }

    pub const fn fleet_start_certificate_sha256(&self) -> [u8; 32] {
        self.fleet_start_certificate_sha256
    }

    pub const fn source_primary_cut_digest(&self) -> [u8; 32] {
        self.primary_before.content_sha256
    }

    pub const fn isolated_snapshot_content_digest(&self) -> [u8; 32] {
        self.isolated_before.content_sha256
    }

    pub const fn isolated_snapshot_inventory_digest(&self) -> [u8; 32] {
        self.isolated_before.inventory_sha256
    }

    pub const fn changed_file_count(&self) -> u32 {
        self.changed_file_count
    }

    pub const fn attempt_nonce(&self) -> [u8; 32] {
        self.attempt_nonce
    }

    pub const fn node_error_class(&self) -> IsolatedNodeStartupErrorClassV1 {
        self.node_error_class
    }

    pub fn node_error_stage(&self) -> &str {
        &self.node_error_stage
    }

    pub fn primary_unchanged(&self) -> bool {
        facts_equal(self.primary_before, self.primary_after)
    }

    pub fn runtime_journal_unchanged(&self) -> bool {
        self.runtime_journal_before_sha256 == self.runtime_journal_after_sha256
    }

    pub const fn runtime_journal_sha256(&self) -> [u8; 32] {
        self.runtime_journal_before_sha256
    }

    pub const fn runtime_journal_bytes(&self) -> u64 {
        self.runtime_journal_bytes
    }

    pub const fn process_instance(&self) -> u64 {
        self.process_instance
    }

    pub const fn network_started(&self) -> bool {
        self.network_started
    }

    pub fn evidence_sha256(&self) -> [u8; 32] {
        hash_canonical(EVIDENCE_DIGEST_DOMAIN_V1, &self.encode())
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut output = self
            .encode_unsigned()
            .expect("validated isolated rejection evidence fits its wire bound");
        output.extend_from_slice(&self.signature);
        output
    }

    pub fn decode(
        bytes: &[u8],
        validator_set: &ValidatorSet,
    ) -> Result<Self, IsolatedStartupRejectionErrorV1> {
        if bytes.len() <= SIGNATURE_BYTES_V1 || bytes.len() > MAX_EVIDENCE_BYTES_V1 {
            return Err(IsolatedStartupRejectionErrorV1::TooLarge);
        }
        let split = bytes.len() - SIGNATURE_BYTES_V1;
        let unsigned = &bytes[..split];
        let signature = bytes[split..]
            .try_into()
            .map_err(|_| IsolatedStartupRejectionErrorV1::Malformed("signature"))?;
        let mut cursor = RejectionCursor::new(unsigned);
        if cursor.take(8)? != EVIDENCE_MAGIC_V1
            || u16::from_be_bytes(cursor.array()?) != WIRE_VERSION_V1
        {
            return Err(IsolatedStartupRejectionErrorV1::Malformed(
                "evidence header",
            ));
        }
        let campaign_len = u32::from_be_bytes(cursor.array()?) as usize;
        if campaign_len == 0 || campaign_len > MAX_CAMPAIGN_BYTES_V1 {
            return Err(IsolatedStartupRejectionErrorV1::TooLarge);
        }
        let campaign = CommonCampaignContextV1::decode(cursor.take(campaign_len)?)
            .map_err(|_| IsolatedStartupRejectionErrorV1::Malformed("campaign"))?;
        let origin = cursor.validator_id()?;
        let target_config_sha256 = cursor.array()?;
        let fleet_start_certificate_sha256 = cursor.array()?;
        let fault_kind = IsolatedStartupFaultKindV1::decode(cursor.byte()?)?;
        let primary_before = IsolatedRootInventoryFactsV1::decode(&mut cursor)?;
        let primary_after = IsolatedRootInventoryFactsV1::decode(&mut cursor)?;
        let isolated_before = IsolatedRootInventoryFactsV1::decode(&mut cursor)?;
        let isolated_after = IsolatedRootInventoryFactsV1::decode(&mut cursor)?;
        let changed_file_count = u32::from_be_bytes(cursor.array()?);
        let attempt_nonce = cursor.array()?;
        let node_error_class = IsolatedNodeStartupErrorClassV1::decode(cursor.byte()?)?;
        let stage_len = u16::from_be_bytes(cursor.array()?) as usize;
        if stage_len == 0 || stage_len > MAX_STAGE_BYTES_V1 {
            return Err(IsolatedStartupRejectionErrorV1::Malformed(
                "Node error stage",
            ));
        }
        let node_error_stage = std::str::from_utf8(cursor.take(stage_len)?)
            .map_err(|_| IsolatedStartupRejectionErrorV1::Malformed("Node error stage"))?
            .to_owned();
        let node_error_detail_sha256 = cursor.array()?;
        let runtime_journal_before_sha256 = cursor.array()?;
        let runtime_journal_after_sha256 = cursor.array()?;
        let runtime_journal_bytes = u64::from_be_bytes(cursor.array()?);
        let process_instance = u64::from_be_bytes(cursor.array()?);
        let network_started = match cursor.byte()? {
            0 => false,
            1 => true,
            _ => {
                return Err(IsolatedStartupRejectionErrorV1::Malformed(
                    "network-started flag",
                ))
            }
        };
        cursor.finish()?;
        let value = Self {
            campaign,
            origin,
            target_config_sha256,
            fleet_start_certificate_sha256,
            fault_kind,
            primary_before,
            primary_after,
            isolated_before,
            isolated_after,
            changed_file_count,
            attempt_nonce,
            node_error_class,
            node_error_stage,
            node_error_detail_sha256,
            runtime_journal_before_sha256,
            runtime_journal_after_sha256,
            runtime_journal_bytes,
            process_instance,
            network_started,
            signature,
        };
        value.verify(validator_set)?;
        if value.encode() != bytes {
            return Err(IsolatedStartupRejectionErrorV1::NonCanonical);
        }
        Ok(value)
    }

    pub fn verify_owned(
        self,
        fleet_start_certificate: &FleetStartCertificateV1,
        validator_set: &ValidatorSet,
    ) -> Result<VerifiedIsolatedStartupRejectionV1, IsolatedStartupRejectionErrorV1> {
        self.verify(validator_set)?;
        validate_fleet_certificate(&self, fleet_start_certificate, validator_set)?;
        let artifact_sha256 = Sha256::digest(self.encode()).into();
        Ok(VerifiedIsolatedStartupRejectionV1 {
            evidence: self,
            artifact_sha256,
        })
    }

    pub fn decode_verified(
        bytes: &[u8],
        fleet_start_certificate: &FleetStartCertificateV1,
        validator_set: &ValidatorSet,
    ) -> Result<VerifiedIsolatedStartupRejectionV1, IsolatedStartupRejectionErrorV1> {
        Self::decode(bytes, validator_set)?.verify_owned(fleet_start_certificate, validator_set)
    }

    fn verify(&self, validator_set: &ValidatorSet) -> Result<(), IsolatedStartupRejectionErrorV1> {
        validate_campaign(self.campaign(), validator_set)?;
        self.primary_before.validate()?;
        self.primary_after.validate()?;
        self.isolated_before.validate()?;
        self.isolated_after.validate()?;
        validate_stage(&self.node_error_stage)?;
        if self.target_config_sha256 == [0; 32]
            || self.fleet_start_certificate_sha256 == [0; 32]
            || self.attempt_nonce == [0; 32]
            || self.node_error_detail_sha256 == [0; 32]
            || self.runtime_journal_before_sha256 == [0; 32]
            || self.runtime_journal_after_sha256 == [0; 32]
            || self.runtime_journal_bytes == 0
            || self.process_instance != 1
            || self.network_started
            || !self.primary_unchanged()
            || !self.runtime_journal_unchanged()
            || !facts_equal(self.isolated_before, self.isolated_after)
            || self.primary_before.inventory_sha256 != self.isolated_before.inventory_sha256
            || self.primary_before.content_sha256 == self.isolated_before.content_sha256
        {
            return Err(IsolatedStartupRejectionErrorV1::Malformed(
                "rejection invariants",
            ));
        }
        match self.fault_kind {
            IsolatedStartupFaultKindV1::StaleSnapshot if self.changed_file_count < 2 => {
                return Err(IsolatedStartupRejectionErrorV1::WrongFaultShape)
            }
            IsolatedStartupFaultKindV1::RollbackAttempt if self.changed_file_count != 1 => {
                return Err(IsolatedStartupRejectionErrorV1::WrongFaultShape)
            }
            _ => {}
        }
        let validator = validator_set
            .validator(self.origin)
            .ok_or(IsolatedStartupRejectionErrorV1::UnknownOrigin)?;
        let key = VerifyingKey::from_bytes(validator.consensus_key().as_bytes())
            .map_err(|_| IsolatedStartupRejectionErrorV1::InvalidSignature)?;
        let unsigned = self.encode_unsigned()?;
        key.verify_strict(
            &hash_canonical(SIGNING_DOMAIN_V1, &unsigned),
            &Signature::from_bytes(&self.signature),
        )
        .map_err(|_| IsolatedStartupRejectionErrorV1::InvalidSignature)
    }

    fn encode_unsigned(&self) -> Result<Vec<u8>, IsolatedStartupRejectionErrorV1> {
        let campaign = self.campaign.encode();
        if campaign.is_empty() || campaign.len() > MAX_CAMPAIGN_BYTES_V1 {
            return Err(IsolatedStartupRejectionErrorV1::TooLarge);
        }
        validate_stage(&self.node_error_stage)?;
        let mut output = Vec::with_capacity(2_048);
        output.extend_from_slice(EVIDENCE_MAGIC_V1);
        output.extend_from_slice(&WIRE_VERSION_V1.to_be_bytes());
        put_bytes_u32(&mut output, &campaign)?;
        put_validator_id(&mut output, self.origin)?;
        output.extend_from_slice(&self.target_config_sha256);
        output.extend_from_slice(&self.fleet_start_certificate_sha256);
        output.push(self.fault_kind as u8);
        self.primary_before.encode(&mut output);
        self.primary_after.encode(&mut output);
        self.isolated_before.encode(&mut output);
        self.isolated_after.encode(&mut output);
        output.extend_from_slice(&self.changed_file_count.to_be_bytes());
        output.extend_from_slice(&self.attempt_nonce);
        output.push(self.node_error_class as u8);
        output.extend_from_slice(
            &u16::try_from(self.node_error_stage.len())
                .map_err(|_| IsolatedStartupRejectionErrorV1::TooLarge)?
                .to_be_bytes(),
        );
        output.extend_from_slice(self.node_error_stage.as_bytes());
        output.extend_from_slice(&self.node_error_detail_sha256);
        output.extend_from_slice(&self.runtime_journal_before_sha256);
        output.extend_from_slice(&self.runtime_journal_after_sha256);
        output.extend_from_slice(&self.runtime_journal_bytes.to_be_bytes());
        output.extend_from_slice(&self.process_instance.to_be_bytes());
        output.push(u8::from(self.network_started));
        if output.len() + SIGNATURE_BYTES_V1 > MAX_EVIDENCE_BYTES_V1 {
            return Err(IsolatedStartupRejectionErrorV1::TooLarge);
        }
        Ok(output)
    }
}

/// Non-cloneable result of either a local real attempt or independent wire
/// verification joined to the exact raw FleetStart certificate.
#[must_use = "the isolated startup rejection carrier must be retained with the fault evidence"]
pub struct VerifiedIsolatedStartupRejectionV1 {
    evidence: IsolatedStartupRejectionEvidenceV1,
    artifact_sha256: [u8; 32],
}

impl VerifiedIsolatedStartupRejectionV1 {
    pub const fn evidence(&self) -> &IsolatedStartupRejectionEvidenceV1 {
        &self.evidence
    }

    pub const fn artifact_sha256(&self) -> [u8; 32] {
        self.artifact_sha256
    }
}

impl fmt::Debug for VerifiedIsolatedStartupRejectionV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedIsolatedStartupRejectionV1")
            .field("origin", &self.evidence.origin)
            .field("fault_kind", &self.evidence.fault_kind)
            .field("node_error_stage", &self.evidence.node_error_stage)
            .field("artifact_sha256", &self.artifact_sha256)
            .finish_non_exhaustive()
    }
}

/// Non-cloneable proof that the exact rejection evidence is durably visible
/// through its final private path and survived canonical fresh readback.
#[must_use = "the persisted isolated rejection must be retained by the fault runner"]
pub struct PersistedIsolatedStartupRejectionV1 {
    verified: VerifiedIsolatedStartupRejectionV1,
    path: PathBuf,
}

impl PersistedIsolatedStartupRejectionV1 {
    pub const fn verified(&self) -> &VerifiedIsolatedStartupRejectionV1 {
        &self.verified
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl fmt::Debug for PersistedIsolatedStartupRejectionV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PersistedIsolatedStartupRejectionV1")
            .field("path", &self.path)
            .field("artifact_sha256", &self.verified.artifact_sha256())
            .finish_non_exhaustive()
    }
}

/// Loads the exact local FleetStart certificate through the fixed private
/// process-1 path. The read is no-follow, single-link, mode-0600, bounded and
/// metadata-stable; the full canonical N/N certificate is then verified.
pub fn load_local_fleet_start_certificate_for_isolated_rejection_v1(
    config: &LoadedValidatorConfig,
) -> Result<FleetStartCertificateV1, IsolatedStartupRejectionErrorV1> {
    let root = canonical_private_directory(config.run_root())?;
    let path = root.join(FLEET_START_CERTIFICATE_FILE_V1);
    load_fleet_start_certificate(&path, config.validator_set())
}

/// Independently verifies one copied rejection artifact on the secret-free
/// observer. Both the evidence and exact raw FleetStart certificate are
/// pinned mode-0600 files; no validator secret or primary authority root is
/// opened on this path.
pub fn load_and_verify_isolated_startup_rejection_evidence_v1(
    evidence_path: impl AsRef<Path>,
    fleet_start_certificate_path: impl AsRef<Path>,
    public: &PublicReportVerifierContext,
) -> Result<VerifiedIsolatedStartupRejectionV1, IsolatedStartupRejectionErrorV1> {
    let fleet_start = load_fleet_start_certificate(
        fleet_start_certificate_path.as_ref(),
        public.validator_set(),
    )?;
    validate_public_campaign(public, fleet_start.ready_set().context())?;
    let bytes = read_private_file_bytes(evidence_path.as_ref(), MAX_EVIDENCE_BYTES_V1)?;
    let verified = IsolatedStartupRejectionEvidenceV1::decode_verified(
        &bytes,
        &fleet_start,
        public.validator_set(),
    )?;
    let evidence = verified.evidence();
    if evidence.origin() != public.local_validator()
        || evidence.target_config_sha256() != public.config_sha256()
    {
        return Err(IsolatedStartupRejectionErrorV1::WrongCampaign);
    }
    Ok(verified)
}

/// Publishes one verified evidence artifact through a fresh mode-0600 file.
/// Publication uses a synced create-new sidecar and hard-link commit, never
/// overwrites an existing path, and reconstructs the verified carrier from a
/// no-follow fresh read of the final name.
pub fn persist_isolated_startup_rejection_evidence_v1(
    output_path: impl AsRef<Path>,
    verified: VerifiedIsolatedStartupRejectionV1,
    fleet_start_certificate: &FleetStartCertificateV1,
    validator_set: &ValidatorSet,
) -> Result<PersistedIsolatedStartupRejectionV1, IsolatedStartupRejectionErrorV1> {
    let output_path = output_path.as_ref();
    if !output_path.is_absolute() {
        return Err(IsolatedStartupRejectionErrorV1::Malformed(
            "evidence output path",
        ));
    }
    let parent = output_path
        .parent()
        .ok_or(IsolatedStartupRejectionErrorV1::Malformed(
            "evidence output parent",
        ))?;
    let parent = canonical_private_directory(parent)?;
    if output_path.parent() != Some(parent.as_path())
        || output_path.file_name().is_none()
        || output_path
            .file_name()
            .is_some_and(|name| name.as_bytes().is_empty())
    {
        return Err(IsolatedStartupRejectionErrorV1::PathReplaced);
    }
    let mut next_name = OsString::from(output_path.file_name().ok_or(
        IsolatedStartupRejectionErrorV1::Malformed("evidence output name"),
    )?);
    next_name.push(EVIDENCE_NEXT_SUFFIX_V1);
    let next = parent.join(next_name);
    require_absent(output_path, "evidence target already exists")?;
    require_absent(&next, "evidence sidecar already exists")?;

    let bytes = verified.evidence().encode();
    if bytes.is_empty() || bytes.len() > MAX_EVIDENCE_BYTES_V1 {
        return Err(IsolatedStartupRejectionErrorV1::TooLarge);
    }
    let expected_sha256: [u8; 32] = Sha256::digest(&bytes).into();
    if expected_sha256 != verified.artifact_sha256() {
        return Err(IsolatedStartupRejectionErrorV1::NonCanonical);
    }

    publish_new_private_file(&parent, &next, output_path, &bytes)?;
    let observed = read_private_file_bytes(output_path, MAX_EVIDENCE_BYTES_V1)?;
    if observed != bytes {
        return Err(IsolatedStartupRejectionErrorV1::PathReplaced);
    }
    let fresh = IsolatedStartupRejectionEvidenceV1::decode_verified(
        &observed,
        fleet_start_certificate,
        validator_set,
    )?;
    if fresh.artifact_sha256() != expected_sha256 {
        return Err(IsolatedStartupRejectionErrorV1::NonCanonical);
    }
    Ok(PersistedIsolatedStartupRejectionV1 {
        verified: fresh,
        path: output_path.to_path_buf(),
    })
}

/// Attempts one isolated startup with the real typed Node deployed-reopen
/// entry.  No evidence is created if Node unexpectedly accepts the snapshot.
pub fn attempt_isolated_startup_rejection_v1(
    config: &LoadedValidatorConfig,
    campaign: CommonCampaignContextV1,
    fleet_start_certificate: &FleetStartCertificateV1,
    fault_kind: IsolatedStartupFaultKindV1,
    isolated_authority_root: impl AsRef<Path>,
    attempt_nonce: [u8; 32],
) -> Result<VerifiedIsolatedStartupRejectionV1, IsolatedStartupRejectionErrorV1> {
    validate_config_campaign(config, &campaign, fleet_start_certificate)?;
    if attempt_nonce == [0; 32] {
        return Err(IsolatedStartupRejectionErrorV1::Malformed("attempt nonce"));
    }
    let primary_root = config.run_root().join("runtime-authority-v1");
    let isolated_root = isolated_authority_root.as_ref();
    validate_root_separation(&primary_root, isolated_root)?;

    let primary_before = capture_root(&primary_root)?;
    let isolated_before = capture_root(isolated_root)?;
    let changed_file_count = validate_fault_shape(&primary_before, &isolated_before, fault_kind)?;
    let journal_path = config.run_root().join("runtime-events.jsonl");
    let journal_before = capture_single_file(&journal_path)?;

    let node_error = require_actual_node_rejection(
        config
            .attempt_isolated_deployed_ordinary_reopen_v1(isolated_root)
            .map_err(|_| IsolatedStartupRejectionErrorV1::NodeAttemptSetup)?,
    )?;

    let primary_after = capture_root(&primary_root)?;
    let isolated_after = capture_root(isolated_root)?;
    let journal_after = capture_single_file(&journal_path)?;
    if primary_before != primary_after {
        return Err(IsolatedStartupRejectionErrorV1::PrimaryMutated);
    }
    if isolated_before != isolated_after {
        return Err(IsolatedStartupRejectionErrorV1::IsolatedMutated);
    }
    if journal_before != journal_after {
        return Err(IsolatedStartupRejectionErrorV1::RuntimeJournalMutated);
    }

    let node_error_stage = node_error.stage_v0().to_owned();
    validate_stage(&node_error_stage)?;
    let node_error_detail_sha256 = hash_canonical(
        b"trnm.poco-g3.isolated-startup-node-error-detail.v1",
        node_error.to_string().as_bytes(),
    );
    let mut evidence = IsolatedStartupRejectionEvidenceV1 {
        campaign,
        origin: config.local_validator(),
        target_config_sha256: config.config_sha256(),
        fleet_start_certificate_sha256: Sha256::digest(fleet_start_certificate.encode()).into(),
        fault_kind,
        primary_before: primary_before.facts,
        primary_after: primary_after.facts,
        isolated_before: isolated_before.facts,
        isolated_after: isolated_after.facts,
        changed_file_count,
        attempt_nonce,
        node_error_class: IsolatedNodeStartupErrorClassV1::DeployedOrdinaryReopenV0,
        node_error_stage,
        node_error_detail_sha256,
        runtime_journal_before_sha256: journal_before.content_sha256,
        runtime_journal_after_sha256: journal_after.content_sha256,
        runtime_journal_bytes: journal_before.bytes,
        process_instance: 1,
        network_started: false,
        signature: [0; SIGNATURE_BYTES_V1],
    };
    sign_evidence(&mut evidence, config.signing_key(), config.validator_set())?;
    evidence.verify(config.validator_set())?;
    evidence.verify_owned(fleet_start_certificate, config.validator_set())
}

fn require_actual_node_rejection<T, E>(
    result: Result<T, E>,
) -> Result<E, IsolatedStartupRejectionErrorV1> {
    match result {
        Ok(owner) => {
            drop(owner);
            Err(IsolatedStartupRejectionErrorV1::NodeUnexpectedSuccess)
        }
        Err(error) => Ok(error),
    }
}

fn sign_evidence(
    evidence: &mut IsolatedStartupRejectionEvidenceV1,
    key: &SigningKey,
    validator_set: &ValidatorSet,
) -> Result<(), IsolatedStartupRejectionErrorV1> {
    let validator = validator_set
        .validator(evidence.origin)
        .ok_or(IsolatedStartupRejectionErrorV1::UnknownOrigin)?;
    if validator.consensus_key().as_bytes() != &key.verifying_key().to_bytes() {
        return Err(IsolatedStartupRejectionErrorV1::OriginKeyMismatch);
    }
    let unsigned = evidence.encode_unsigned()?;
    evidence.signature = key
        .sign(&hash_canonical(SIGNING_DOMAIN_V1, &unsigned))
        .to_bytes();
    Ok(())
}

fn validate_config_campaign(
    config: &LoadedValidatorConfig,
    campaign: &CommonCampaignContextV1,
    fleet_start_certificate: &FleetStartCertificateV1,
) -> Result<(), IsolatedStartupRejectionErrorV1> {
    validate_campaign(campaign, config.validator_set())?;
    let identity = campaign.identity();
    if identity.run_id() != config.run_id()
        || identity.validator_set_sha256() != config.validator_set_sha256()
        || identity.topology_sha256() != config.topology_sha256()
        || identity.coordinator_manifest_sha256() != config.coordinator_manifest_sha256()
        || identity.candidate_source_sha256() != config.candidate_source_sha256()
        || identity.binary_sha256() != config.binary_sha256()
        || identity.workload_corpus_sha256() != config.workload_corpus_sha256()
        || identity.workload_policy_sha256() != config.workload_policy_sha256()
        || campaign.request().ordinary_start_height() != config.ordinary_start_height()
    {
        return Err(IsolatedStartupRejectionErrorV1::WrongCampaign);
    }
    fleet_start_certificate
        .verify(config.validator_set())
        .map_err(|_| IsolatedStartupRejectionErrorV1::InvalidFleetStartCertificate)?;
    if fleet_start_certificate.ready_set().context() != campaign {
        return Err(IsolatedStartupRejectionErrorV1::InvalidFleetStartCertificate);
    }
    Ok(())
}

fn validate_public_campaign(
    public: &PublicReportVerifierContext,
    campaign: &CommonCampaignContextV1,
) -> Result<(), IsolatedStartupRejectionErrorV1> {
    validate_campaign(campaign, public.validator_set())?;
    let identity = campaign.identity();
    if identity.run_id() != public.run_id()
        || identity.validator_set_sha256() != public.validator_set_sha256()
        || identity.topology_sha256() != public.topology_sha256()
        || identity.coordinator_manifest_sha256() != public.coordinator_manifest_sha256()
        || identity.candidate_source_sha256() != public.candidate_source_sha256()
        || identity.binary_sha256() != public.binary_sha256()
        || identity.workload_corpus_sha256() != public.workload_corpus_sha256()
        || identity.workload_policy_sha256() != public.workload_policy_sha256()
        || campaign.request().ordinary_start_height() != public.ordinary_start_height()
    {
        return Err(IsolatedStartupRejectionErrorV1::WrongCampaign);
    }
    Ok(())
}

fn validate_campaign(
    campaign: &CommonCampaignContextV1,
    validator_set: &ValidatorSet,
) -> Result<(), IsolatedStartupRejectionErrorV1> {
    let identity = campaign.identity();
    if identity.chain_id() != validator_set.chain_id()
        || identity.genesis_hash() != *validator_set.genesis_hash().as_bytes()
        || identity.validator_set_id() != *validator_set.id().as_bytes()
        || usize::try_from(identity.validator_count()).ok()
            != Some(validator_set.validators().len())
        || !matches!(validator_set.validators().len(), 7 | 31 | 100)
    {
        return Err(IsolatedStartupRejectionErrorV1::WrongCampaign);
    }
    Ok(())
}

fn validate_fleet_certificate(
    evidence: &IsolatedStartupRejectionEvidenceV1,
    fleet_start_certificate: &FleetStartCertificateV1,
    validator_set: &ValidatorSet,
) -> Result<(), IsolatedStartupRejectionErrorV1> {
    fleet_start_certificate
        .verify(validator_set)
        .map_err(|_| IsolatedStartupRejectionErrorV1::InvalidFleetStartCertificate)?;
    let artifact_sha256: [u8; 32] = Sha256::digest(fleet_start_certificate.encode()).into();
    if fleet_start_certificate.ready_set().context() != &evidence.campaign
        || artifact_sha256 != evidence.fleet_start_certificate_sha256
    {
        return Err(IsolatedStartupRejectionErrorV1::InvalidFleetStartCertificate);
    }
    Ok(())
}

fn load_fleet_start_certificate(
    path: &Path,
    validator_set: &ValidatorSet,
) -> Result<FleetStartCertificateV1, IsolatedStartupRejectionErrorV1> {
    let bytes = read_private_file_bytes(path, MAX_FLEET_START_CERTIFICATE_BYTES_V1)?;
    let certificate = FleetStartCertificateV1::decode(&bytes, validator_set)
        .map_err(|_| IsolatedStartupRejectionErrorV1::InvalidFleetStartCertificate)?;
    certificate
        .verify(validator_set)
        .map_err(|_| IsolatedStartupRejectionErrorV1::InvalidFleetStartCertificate)?;
    if certificate.encode() != bytes {
        return Err(IsolatedStartupRejectionErrorV1::NonCanonical);
    }
    Ok(certificate)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EntryKindV1 {
    Directory,
    File,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CapturedEntryV1 {
    relative: Vec<u8>,
    kind: EntryKindV1,
    mode: u32,
    bytes: u64,
    content_sha256: [u8; 32],
    device: u64,
    inode: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CapturedRootV1 {
    facts: IsolatedRootInventoryFactsV1,
    entries: Vec<CapturedEntryV1>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CapturedFileV1 {
    content_sha256: [u8; 32],
    bytes: u64,
    device: u64,
    inode: u64,
}

fn validate_root_separation(
    primary: &Path,
    isolated: &Path,
) -> Result<(), IsolatedStartupRejectionErrorV1> {
    let primary = canonical_directory(primary)?;
    let isolated = canonical_directory(isolated)?;
    if primary == isolated || primary.starts_with(&isolated) || isolated.starts_with(&primary) {
        return Err(IsolatedStartupRejectionErrorV1::RootsNotIsolated);
    }
    Ok(())
}

fn capture_root(path: &Path) -> Result<CapturedRootV1, IsolatedStartupRejectionErrorV1> {
    let root = canonical_directory(path)?;
    let root_before = fs::symlink_metadata(&root)
        .map_err(|_| IsolatedStartupRejectionErrorV1::Filesystem("stat root"))?;
    let mut entries = Vec::new();
    capture_directory_entries(&root, &root, &mut entries)?;
    entries.sort_by(|left, right| left.relative.cmp(&right.relative));
    if entries.is_empty() || entries.len() > MAX_TREE_ENTRIES_V1 {
        return Err(IsolatedStartupRejectionErrorV1::Filesystem(
            "tree entry bound",
        ));
    }
    let root_after = fs::symlink_metadata(&root)
        .map_err(|_| IsolatedStartupRejectionErrorV1::Filesystem("restat root"))?;
    if root_before.dev() != root_after.dev()
        || root_before.ino() != root_after.ino()
        || root_before.mode() != root_after.mode()
    {
        return Err(IsolatedStartupRejectionErrorV1::PathReplaced);
    }

    let mut content_preimage = Vec::new();
    let mut inventory_preimage = Vec::new();
    let mut directory_count = 1u32;
    let mut file_count = 0u32;
    let mut total_file_bytes = 0u64;
    for entry in &entries {
        put_bytes_u32(&mut content_preimage, &entry.relative)?;
        content_preimage.push(match entry.kind {
            EntryKindV1::Directory => 1,
            EntryKindV1::File => 2,
        });
        content_preimage.extend_from_slice(&entry.content_sha256);
        put_bytes_u32(&mut inventory_preimage, &entry.relative)?;
        inventory_preimage.push(match entry.kind {
            EntryKindV1::Directory => 1,
            EntryKindV1::File => 2,
        });
        inventory_preimage.extend_from_slice(&entry.mode.to_be_bytes());
        inventory_preimage.extend_from_slice(&entry.bytes.to_be_bytes());
        match entry.kind {
            EntryKindV1::Directory => {
                directory_count = directory_count
                    .checked_add(1)
                    .ok_or(IsolatedStartupRejectionErrorV1::TooLarge)?;
            }
            EntryKindV1::File => {
                file_count = file_count
                    .checked_add(1)
                    .ok_or(IsolatedStartupRejectionErrorV1::TooLarge)?;
                total_file_bytes = total_file_bytes
                    .checked_add(entry.bytes)
                    .ok_or(IsolatedStartupRejectionErrorV1::TooLarge)?;
            }
        }
    }
    if total_file_bytes > MAX_TREE_BYTES_V1 {
        return Err(IsolatedStartupRejectionErrorV1::TooLarge);
    }
    let facts = IsolatedRootInventoryFactsV1 {
        content_sha256: hash_canonical(ROOT_CONTENT_DOMAIN_V1, &content_preimage),
        inventory_sha256: hash_canonical(ROOT_INVENTORY_DOMAIN_V1, &inventory_preimage),
        directory_count,
        file_count,
        total_file_bytes,
    };
    facts.validate()?;
    Ok(CapturedRootV1 { facts, entries })
}

fn capture_directory_entries(
    root: &Path,
    directory: &Path,
    output: &mut Vec<CapturedEntryV1>,
) -> Result<(), IsolatedStartupRejectionErrorV1> {
    let before = fs::symlink_metadata(directory)
        .map_err(|_| IsolatedStartupRejectionErrorV1::Filesystem("stat directory"))?;
    if !before.is_dir() || before.file_type().is_symlink() {
        return Err(IsolatedStartupRejectionErrorV1::UnsupportedFileType);
    }
    let mut children = fs::read_dir(directory)
        .map_err(|_| IsolatedStartupRejectionErrorV1::Filesystem("read directory"))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| IsolatedStartupRejectionErrorV1::Filesystem("read directory entry"))?;
    children.sort_by_key(|entry| entry.file_name());
    for child in children {
        if output.len() >= MAX_TREE_ENTRIES_V1 {
            return Err(IsolatedStartupRejectionErrorV1::TooLarge);
        }
        let path = child.path();
        let metadata = fs::symlink_metadata(&path)
            .map_err(|_| IsolatedStartupRejectionErrorV1::Filesystem("stat tree entry"))?;
        let relative = path
            .strip_prefix(root)
            .map_err(|_| IsolatedStartupRejectionErrorV1::PathReplaced)?
            .as_os_str()
            .as_bytes()
            .to_vec();
        if relative.is_empty() {
            return Err(IsolatedStartupRejectionErrorV1::PathReplaced);
        }
        if metadata.file_type().is_symlink() {
            return Err(IsolatedStartupRejectionErrorV1::SymlinkRejected);
        }
        if metadata.is_dir() {
            output.push(CapturedEntryV1 {
                relative,
                kind: EntryKindV1::Directory,
                mode: metadata.mode() & 0o777,
                bytes: 0,
                content_sha256: [0; 32],
                device: metadata.dev(),
                inode: metadata.ino(),
            });
            capture_directory_entries(root, &path, output)?;
        } else if metadata.is_file() {
            let captured = capture_single_file(&path)?;
            output.push(CapturedEntryV1 {
                relative,
                kind: EntryKindV1::File,
                mode: metadata.mode() & 0o777,
                bytes: captured.bytes,
                content_sha256: captured.content_sha256,
                device: captured.device,
                inode: captured.inode,
            });
        } else {
            return Err(IsolatedStartupRejectionErrorV1::UnsupportedFileType);
        }
    }
    let after = fs::symlink_metadata(directory)
        .map_err(|_| IsolatedStartupRejectionErrorV1::Filesystem("restat directory"))?;
    if before.dev() != after.dev() || before.ino() != after.ino() || before.mode() != after.mode() {
        return Err(IsolatedStartupRejectionErrorV1::PathReplaced);
    }
    Ok(())
}

fn capture_single_file(path: &Path) -> Result<CapturedFileV1, IsolatedStartupRejectionErrorV1> {
    let before = fs::symlink_metadata(path)
        .map_err(|_| IsolatedStartupRejectionErrorV1::Filesystem("stat file"))?;
    if before.file_type().is_symlink() {
        return Err(IsolatedStartupRejectionErrorV1::SymlinkRejected);
    }
    if !before.is_file() {
        return Err(IsolatedStartupRejectionErrorV1::UnsupportedFileType);
    }
    if before.nlink() != 1 {
        return Err(IsolatedStartupRejectionErrorV1::HardlinkRejected);
    }
    if before.len() > MAX_FILE_BYTES_V1 {
        return Err(IsolatedStartupRejectionErrorV1::TooLarge);
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| IsolatedStartupRejectionErrorV1::Filesystem("open pinned file"))?;
    let opened = file
        .metadata()
        .map_err(|_| IsolatedStartupRejectionErrorV1::Filesystem("fstat file"))?;
    if opened.dev() != before.dev()
        || opened.ino() != before.ino()
        || opened.len() != before.len()
        || opened.nlink() != 1
    {
        return Err(IsolatedStartupRejectionErrorV1::PathReplaced);
    }
    let mut hasher = Sha256::new();
    hasher.update(FILE_CONTENT_DOMAIN_V1);
    hasher.update(opened.len().to_be_bytes());
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|_| IsolatedStartupRejectionErrorV1::Filesystem("read pinned file"))?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    let after = fs::symlink_metadata(path)
        .map_err(|_| IsolatedStartupRejectionErrorV1::Filesystem("restat file"))?;
    if opened.dev() != after.dev()
        || opened.ino() != after.ino()
        || opened.len() != after.len()
        || after.nlink() != 1
    {
        return Err(IsolatedStartupRejectionErrorV1::PathReplaced);
    }
    Ok(CapturedFileV1 {
        content_sha256: hasher.finalize().into(),
        bytes: opened.len(),
        device: opened.dev(),
        inode: opened.ino(),
    })
}

fn validate_fault_shape(
    primary: &CapturedRootV1,
    isolated: &CapturedRootV1,
    fault_kind: IsolatedStartupFaultKindV1,
) -> Result<u32, IsolatedStartupRejectionErrorV1> {
    if primary.facts.inventory_sha256 != isolated.facts.inventory_sha256
        || primary.entries.len() != isolated.entries.len()
    {
        return Err(IsolatedStartupRejectionErrorV1::WrongFaultShape);
    }
    let primary_by_path = primary
        .entries
        .iter()
        .map(|entry| (entry.relative.as_slice(), entry))
        .collect::<BTreeMap<_, _>>();
    let mut seen_inodes = BTreeSet::new();
    let mut changed = 0u32;
    for entry in &isolated.entries {
        let source = primary_by_path
            .get(entry.relative.as_slice())
            .ok_or(IsolatedStartupRejectionErrorV1::WrongFaultShape)?;
        if source.kind != entry.kind || source.mode != entry.mode {
            return Err(IsolatedStartupRejectionErrorV1::WrongFaultShape);
        }
        if !seen_inodes.insert((entry.device, entry.inode))
            || (source.device == entry.device && source.inode == entry.inode)
        {
            return Err(IsolatedStartupRejectionErrorV1::HardlinkRejected);
        }
        if entry.kind == EntryKindV1::File && source.content_sha256 != entry.content_sha256 {
            changed = changed
                .checked_add(1)
                .ok_or(IsolatedStartupRejectionErrorV1::TooLarge)?;
        }
    }
    match fault_kind {
        IsolatedStartupFaultKindV1::StaleSnapshot if changed >= 2 => Ok(changed),
        IsolatedStartupFaultKindV1::RollbackAttempt if changed == 1 => Ok(changed),
        _ => Err(IsolatedStartupRejectionErrorV1::WrongFaultShape),
    }
}

fn canonical_directory(path: &Path) -> Result<PathBuf, IsolatedStartupRejectionErrorV1> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| IsolatedStartupRejectionErrorV1::Filesystem("stat root path"))?;
    if metadata.file_type().is_symlink() {
        return Err(IsolatedStartupRejectionErrorV1::SymlinkRejected);
    }
    if !metadata.is_dir() {
        return Err(IsolatedStartupRejectionErrorV1::UnsupportedFileType);
    }
    let canonical = path
        .canonicalize()
        .map_err(|_| IsolatedStartupRejectionErrorV1::Filesystem("canonicalize root"))?;
    let after = fs::symlink_metadata(&canonical)
        .map_err(|_| IsolatedStartupRejectionErrorV1::Filesystem("restat canonical root"))?;
    if metadata.dev() != after.dev() || metadata.ino() != after.ino() {
        return Err(IsolatedStartupRejectionErrorV1::PathReplaced);
    }
    Ok(canonical)
}

fn canonical_private_directory(path: &Path) -> Result<PathBuf, IsolatedStartupRejectionErrorV1> {
    let canonical = canonical_directory(path)?;
    if canonical != path {
        return Err(IsolatedStartupRejectionErrorV1::PathReplaced);
    }
    let metadata = fs::symlink_metadata(&canonical)
        .map_err(|_| IsolatedStartupRejectionErrorV1::Filesystem("stat private directory"))?;
    if metadata.permissions().mode() & 0o777 != 0o700 {
        return Err(IsolatedStartupRejectionErrorV1::Filesystem(
            "private directory mode",
        ));
    }
    Ok(canonical)
}

fn read_private_file_bytes(
    path: &Path,
    maximum: usize,
) -> Result<Vec<u8>, IsolatedStartupRejectionErrorV1> {
    let before = fs::symlink_metadata(path)
        .map_err(|_| IsolatedStartupRejectionErrorV1::Filesystem("stat private file"))?;
    if before.file_type().is_symlink() {
        return Err(IsolatedStartupRejectionErrorV1::SymlinkRejected);
    }
    if !before.is_file() {
        return Err(IsolatedStartupRejectionErrorV1::UnsupportedFileType);
    }
    if before.nlink() != 1 {
        return Err(IsolatedStartupRejectionErrorV1::HardlinkRejected);
    }
    if before.permissions().mode() & 0o777 != 0o600
        || before.len() == 0
        || before.len() > maximum as u64
    {
        return Err(IsolatedStartupRejectionErrorV1::Filesystem(
            "private file shape",
        ));
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| IsolatedStartupRejectionErrorV1::Filesystem("open private file"))?;
    let opened = file
        .metadata()
        .map_err(|_| IsolatedStartupRejectionErrorV1::Filesystem("fstat private file"))?;
    if !same_pinned_file(&before, &opened) {
        return Err(IsolatedStartupRejectionErrorV1::PathReplaced);
    }
    let mut bytes = Vec::with_capacity(opened.len() as usize);
    file.read_to_end(&mut bytes)
        .map_err(|_| IsolatedStartupRejectionErrorV1::Filesystem("read private file"))?;
    if bytes.len() != opened.len() as usize || bytes.len() > maximum {
        return Err(IsolatedStartupRejectionErrorV1::PathReplaced);
    }
    let opened_after = file
        .metadata()
        .map_err(|_| IsolatedStartupRejectionErrorV1::Filesystem("refstat private file"))?;
    let path_after = fs::symlink_metadata(path)
        .map_err(|_| IsolatedStartupRejectionErrorV1::Filesystem("restat private file"))?;
    if !same_pinned_file(&opened, &opened_after) || !same_pinned_file(&opened, &path_after) {
        return Err(IsolatedStartupRejectionErrorV1::PathReplaced);
    }
    Ok(bytes)
}

fn same_pinned_file(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    left.is_file()
        && right.is_file()
        && !right.file_type().is_symlink()
        && left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.len() == right.len()
        && left.nlink() == 1
        && right.nlink() == 1
        && left.permissions().mode() & 0o777 == right.permissions().mode() & 0o777
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
        && left.ctime() == right.ctime()
        && left.ctime_nsec() == right.ctime_nsec()
}

fn require_absent(path: &Path, stage: &'static str) -> Result<(), IsolatedStartupRejectionErrorV1> {
    match fs::symlink_metadata(path) {
        Ok(_) => Err(IsolatedStartupRejectionErrorV1::Filesystem(stage)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(IsolatedStartupRejectionErrorV1::Filesystem(stage)),
    }
}

fn publish_new_private_file(
    parent: &Path,
    next: &Path,
    target: &Path,
    bytes: &[u8],
) -> Result<(), IsolatedStartupRejectionErrorV1> {
    let parent_before = fs::symlink_metadata(parent)
        .map_err(|_| IsolatedStartupRejectionErrorV1::Filesystem("stat output parent"))?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(next)
        .map_err(|_| IsolatedStartupRejectionErrorV1::Filesystem("create evidence sidecar"))?;
    if let Err(error) = (|| {
        file.write_all(bytes)?;
        file.sync_all()?;
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.nlink() != 1
            || metadata.permissions().mode() & 0o777 != 0o600
            || metadata.len() != bytes.len() as u64
        {
            return Err(std::io::Error::other("invalid evidence sidecar shape"));
        }
        Ok::<(), std::io::Error>(())
    })() {
        drop(file);
        let _ = fs::remove_file(next);
        return Err(IsolatedStartupRejectionErrorV1::Filesystem(
            if error.kind() == std::io::ErrorKind::Other {
                "validate evidence sidecar"
            } else {
                "write evidence sidecar"
            },
        ));
    }
    drop(file);
    if fs::hard_link(next, target).is_err() {
        let _ = fs::remove_file(next);
        return Err(IsolatedStartupRejectionErrorV1::Filesystem(
            "publish evidence target",
        ));
    }
    sync_private_directory(parent)?;
    fs::remove_file(next)
        .map_err(|_| IsolatedStartupRejectionErrorV1::Filesystem("remove evidence sidecar"))?;
    sync_private_directory(parent)?;
    let parent_after = fs::symlink_metadata(parent)
        .map_err(|_| IsolatedStartupRejectionErrorV1::Filesystem("restat output parent"))?;
    if parent_before.dev() != parent_after.dev()
        || parent_before.ino() != parent_after.ino()
        || parent_after.permissions().mode() & 0o777 != 0o700
    {
        return Err(IsolatedStartupRejectionErrorV1::PathReplaced);
    }
    Ok(())
}

fn sync_private_directory(path: &Path) -> Result<(), IsolatedStartupRejectionErrorV1> {
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| IsolatedStartupRejectionErrorV1::Filesystem("open output parent"))?;
    directory
        .sync_all()
        .map_err(|_| IsolatedStartupRejectionErrorV1::Filesystem("sync output parent"))
}

fn facts_equal(left: IsolatedRootInventoryFactsV1, right: IsolatedRootInventoryFactsV1) -> bool {
    left.content_sha256 == right.content_sha256
        && left.inventory_sha256 == right.inventory_sha256
        && left.directory_count == right.directory_count
        && left.file_count == right.file_count
        && left.total_file_bytes == right.total_file_bytes
}

fn validate_stage(stage: &str) -> Result<(), IsolatedStartupRejectionErrorV1> {
    if stage.is_empty()
        || stage.len() > MAX_STAGE_BYTES_V1
        || !stage.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._-".contains(&byte)
        })
    {
        return Err(IsolatedStartupRejectionErrorV1::Malformed(
            "Node error stage",
        ));
    }
    Ok(())
}

fn hash_canonical(domain: &[u8], canonical: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update((canonical.len() as u64).to_be_bytes());
    hasher.update(canonical);
    hasher.finalize().into()
}

fn put_bytes_u32(
    output: &mut Vec<u8>,
    value: &[u8],
) -> Result<(), IsolatedStartupRejectionErrorV1> {
    output.extend_from_slice(
        &u32::try_from(value.len())
            .map_err(|_| IsolatedStartupRejectionErrorV1::TooLarge)?
            .to_be_bytes(),
    );
    output.extend_from_slice(value);
    Ok(())
}

fn put_validator_id(
    output: &mut Vec<u8>,
    value: ValidatorId,
) -> Result<(), IsolatedStartupRejectionErrorV1> {
    output.extend_from_slice(
        &u16::try_from(value.as_bytes().len())
            .map_err(|_| IsolatedStartupRejectionErrorV1::TooLarge)?
            .to_be_bytes(),
    );
    output.extend_from_slice(value.as_bytes());
    Ok(())
}

struct RejectionCursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> RejectionCursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], IsolatedStartupRejectionErrorV1> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(IsolatedStartupRejectionErrorV1::TooLarge)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(IsolatedStartupRejectionErrorV1::Malformed("truncated wire"))?;
        self.offset = end;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], IsolatedStartupRejectionErrorV1> {
        self.take(N)?
            .try_into()
            .map_err(|_| IsolatedStartupRejectionErrorV1::Malformed("array"))
    }

    fn byte(&mut self) -> Result<u8, IsolatedStartupRejectionErrorV1> {
        self.take(1)?
            .first()
            .copied()
            .ok_or(IsolatedStartupRejectionErrorV1::Malformed("byte"))
    }

    fn validator_id(&mut self) -> Result<ValidatorId, IsolatedStartupRejectionErrorV1> {
        let length = u16::from_be_bytes(self.array()?) as usize;
        ValidatorId::from_bytes(self.take(length)?)
            .map_err(|_| IsolatedStartupRejectionErrorV1::Malformed("validator ID"))
    }

    fn finish(self) -> Result<(), IsolatedStartupRejectionErrorV1> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(IsolatedStartupRejectionErrorV1::Malformed("trailing wire"))
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IsolatedStartupRejectionErrorV1 {
    Malformed(&'static str),
    TooLarge,
    WrongCampaign,
    InvalidFleetStartCertificate,
    UnknownOrigin,
    OriginKeyMismatch,
    InvalidSignature,
    NonCanonical,
    WrongFaultShape,
    RootsNotIsolated,
    SymlinkRejected,
    HardlinkRejected,
    UnsupportedFileType,
    PathReplaced,
    Filesystem(&'static str),
    NodeAttemptSetup,
    NodeUnexpectedSuccess,
    PrimaryMutated,
    IsolatedMutated,
    RuntimeJournalMutated,
}

impl fmt::Display for IsolatedStartupRejectionErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed(field) => write!(formatter, "malformed isolated rejection {field}"),
            Self::TooLarge => formatter.write_str("isolated rejection input crosses its bound"),
            Self::WrongCampaign => formatter.write_str("isolated rejection campaign differs"),
            Self::InvalidFleetStartCertificate => {
                formatter.write_str("isolated rejection FleetStart certificate is invalid")
            }
            Self::UnknownOrigin => formatter.write_str("isolated rejection origin is unknown"),
            Self::OriginKeyMismatch => {
                formatter.write_str("isolated rejection signing key differs from origin")
            }
            Self::InvalidSignature => {
                formatter.write_str("isolated rejection signature is invalid")
            }
            Self::NonCanonical => formatter.write_str("isolated rejection wire is non-canonical"),
            Self::WrongFaultShape => {
                formatter.write_str("isolated snapshot differs from the selected fault shape")
            }
            Self::RootsNotIsolated => {
                formatter.write_str("primary and isolated authority roots overlap")
            }
            Self::SymlinkRejected => formatter.write_str("isolated rejection rejects symlinks"),
            Self::HardlinkRejected => formatter.write_str("isolated rejection rejects hardlinks"),
            Self::UnsupportedFileType => {
                formatter.write_str("isolated rejection root contains an unsupported file type")
            }
            Self::PathReplaced => {
                formatter.write_str("isolated rejection path identity changed while pinned")
            }
            Self::Filesystem(stage) => {
                write!(
                    formatter,
                    "isolated rejection filesystem failure at {stage}"
                )
            }
            Self::NodeAttemptSetup => {
                formatter.write_str("isolated Node startup attempt could not be configured")
            }
            Self::NodeUnexpectedSuccess => {
                formatter.write_str("isolated Node startup unexpectedly succeeded")
            }
            Self::PrimaryMutated => {
                formatter.write_str("primary authority root changed during isolated attempt")
            }
            Self::IsolatedMutated => {
                formatter.write_str("isolated authority root changed during Node rejection")
            }
            Self::RuntimeJournalMutated => {
                formatter.write_str("process-1 runtime journal changed during isolated attempt")
            }
        }
    }
}

impl Error for IsolatedStartupRejectionErrorV1 {}

// The standalone snapshot-preparation/typed-attempt runner is wired.  It is
// not yet joined to the live eight-fault scheduler's stable RestartCut, and no
// real campaign observation is inferred from implementation reachability.
pub const ISOLATED_STARTUP_REJECTION_CARRIER_V1: bool = true;
pub const ISOLATED_STARTUP_REJECTION_RUNNER_WIRED_V1: bool = true;
pub const STALE_SNAPSHOT_FAULT_CAMPAIGN_OBSERVED_V1: bool = false;
pub const ROLLBACK_ATTEMPT_FAULT_CAMPAIGN_OBSERVED_V1: bool = false;

#[cfg(test)]
mod tests {
    use std::{
        os::unix::fs::{symlink, PermissionsExt},
        sync::{Arc, Mutex},
    };

    use tempfile::{tempdir, TempDir};
    use trnm_consensus_signer_journal::{
        ExternalMonotonicWatermarkV0, ExternalWatermarkErrorV0, SignerWatermarkV0,
    };
    use trnm_consensus_types::{
        ChainId, ConsensusParametersV0, ConsensusPublicKey, Epoch, GenesisHash, ProtocolVersion,
        Validator, VotingPower,
    };
    use trnm_poco_node::{
        commission_native_h1_ordinary_lab_test_bundle_v0, reopen_deployed_lab_ordinary_cut_v0,
    };

    use crate::fleet_barrier::{
        CommonChainCutV1, FleetBarrierTransportV1, FleetCampaignCapacitiesV1,
        FleetCampaignIdentityV1, FleetCampaignRequestV1,
    };

    use super::*;

    #[derive(Debug, Clone, Default)]
    struct SharedWatermarkV1 {
        value: Arc<Mutex<Option<SignerWatermarkV0>>>,
    }

    impl ExternalMonotonicWatermarkV0 for SharedWatermarkV1 {
        fn load(
            &mut self,
            scope: [u8; 32],
        ) -> Result<Option<SignerWatermarkV0>, ExternalWatermarkErrorV0> {
            let value = *self
                .value
                .lock()
                .map_err(|_| ExternalWatermarkErrorV0::Unavailable)?;
            if value.is_some_and(|watermark| watermark.scope() != scope) {
                return Err(ExternalWatermarkErrorV0::InvalidPersistedState);
            }
            Ok(value)
        }

        fn compare_and_advance(
            &mut self,
            expected: Option<SignerWatermarkV0>,
            target: SignerWatermarkV0,
        ) -> Result<(), ExternalWatermarkErrorV0> {
            let mut value = self
                .value
                .lock()
                .map_err(|_| ExternalWatermarkErrorV0::Unavailable)?;
            if *value != expected {
                return Err(ExternalWatermarkErrorV0::CompareFailed);
            }
            match expected {
                None if target.sequence() == 0 => {}
                Some(previous)
                    if previous.scope() == target.scope()
                        && previous.journal_id() == target.journal_id()
                        && previous.sequence().checked_add(1) == Some(target.sequence()) => {}
                _ => return Err(ExternalWatermarkErrorV0::InvalidPersistedState),
            }
            *value = Some(target);
            Ok(())
        }
    }

    #[test]
    fn canonical_signed_rejection_rejects_forged_stage_fault_signature_and_trailing_v1() {
        let (set, keys) = validator_fixture();
        let campaign_value = campaign(&set);
        let roots = simple_mutation_fixture(1);
        let primary = capture_root(&roots.primary).unwrap();
        let isolated = capture_root(&roots.isolated).unwrap();
        let mut evidence = synthetic_evidence(
            campaign_value,
            set.validators()[2].id(),
            primary.facts,
            isolated.facts,
            IsolatedStartupFaultKindV1::RollbackAttempt,
            1,
        );
        sign_evidence(&mut evidence, &keys[2], &set).unwrap();
        let encoded = evidence.encode();
        let decoded = IsolatedStartupRejectionEvidenceV1::decode(&encoded, &set).unwrap();
        assert_eq!(decoded.node_error_stage(), "safety.open_existing");
        assert!(decoded.primary_unchanged());
        assert!(decoded.runtime_journal_unchanged());
        assert!(!decoded.network_started());

        let mut forged_stage = decoded;
        forged_stage.node_error_stage = "filesystem.paths".to_owned();
        assert_eq!(
            forged_stage.verify(&set),
            Err(IsolatedStartupRejectionErrorV1::InvalidSignature)
        );

        let mut wrong_fault = synthetic_evidence(
            campaign(&set),
            set.validators()[2].id(),
            primary.facts,
            isolated.facts,
            IsolatedStartupFaultKindV1::StaleSnapshot,
            1,
        );
        sign_evidence(&mut wrong_fault, &keys[2], &set).unwrap();
        assert_eq!(
            wrong_fault.verify(&set),
            Err(IsolatedStartupRejectionErrorV1::WrongFaultShape)
        );

        let mut primary_mutation = synthetic_evidence(
            campaign(&set),
            set.validators()[2].id(),
            primary.facts,
            isolated.facts,
            IsolatedStartupFaultKindV1::RollbackAttempt,
            1,
        );
        primary_mutation.primary_after = isolated.facts;
        sign_evidence(&mut primary_mutation, &keys[2], &set).unwrap();
        assert!(matches!(
            primary_mutation.verify(&set),
            Err(IsolatedStartupRejectionErrorV1::Malformed(
                "rejection invariants"
            ))
        ));

        assert_eq!(
            require_actual_node_rejection::<(), &'static str>(Ok(())),
            Err(IsolatedStartupRejectionErrorV1::NodeUnexpectedSuccess)
        );

        let mut signature_tamper = encoded.clone();
        let last = signature_tamper.len() - 1;
        signature_tamper[last] ^= 1;
        assert_eq!(
            IsolatedStartupRejectionEvidenceV1::decode(&signature_tamper, &set),
            Err(IsolatedStartupRejectionErrorV1::InvalidSignature)
        );
        let mut trailing = encoded;
        trailing.push(0);
        assert!(IsolatedStartupRejectionEvidenceV1::decode(&trailing, &set).is_err());
    }

    #[test]
    fn root_inventory_derives_fault_kind_and_rejects_links_and_overlap_v1() {
        let rollback = simple_mutation_fixture(1);
        let rollback_primary = capture_root(&rollback.primary).unwrap();
        let rollback_isolated = capture_root(&rollback.isolated).unwrap();
        assert_eq!(
            validate_fault_shape(
                &rollback_primary,
                &rollback_isolated,
                IsolatedStartupFaultKindV1::RollbackAttempt,
            )
            .unwrap(),
            1
        );
        assert_eq!(
            validate_fault_shape(
                &rollback_primary,
                &rollback_isolated,
                IsolatedStartupFaultKindV1::StaleSnapshot,
            ),
            Err(IsolatedStartupRejectionErrorV1::WrongFaultShape)
        );

        let stale = simple_mutation_fixture(2);
        assert_eq!(
            validate_fault_shape(
                &capture_root(&stale.primary).unwrap(),
                &capture_root(&stale.isolated).unwrap(),
                IsolatedStartupFaultKindV1::StaleSnapshot,
            )
            .unwrap(),
            2
        );

        let linked = simple_mutation_fixture(1);
        let linked_path = linked.isolated.join("b.sqlite3");
        fs::remove_file(&linked_path).unwrap();
        fs::hard_link(linked.primary.join("b.sqlite3"), &linked_path).unwrap();
        assert_eq!(
            capture_root(&linked.isolated),
            Err(IsolatedStartupRejectionErrorV1::HardlinkRejected)
        );

        let symlinked = simple_mutation_fixture(1);
        symlink(
            symlinked.primary.join("a.sqlite3"),
            symlinked.isolated.join("escape"),
        )
        .unwrap();
        assert_eq!(
            capture_root(&symlinked.isolated),
            Err(IsolatedStartupRejectionErrorV1::SymlinkRejected)
        );
        assert_eq!(
            validate_root_separation(&symlinked.primary, &symlinked.primary),
            Err(IsolatedStartupRejectionErrorV1::RootsNotIsolated)
        );
    }

    #[test]
    fn private_evidence_publication_is_create_new_synced_and_no_follow_v1() {
        let temporary = tempdir().unwrap();
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let parent = temporary.path().canonicalize().unwrap();
        let target = parent.join("rejection.bin");
        let next = parent.join("rejection.bin.next");
        let bytes = b"canonical-isolated-rejection";
        publish_new_private_file(&parent, &next, &target, bytes).unwrap();
        assert_eq!(read_private_file_bytes(&target, 1024).unwrap(), bytes);
        let metadata = fs::symlink_metadata(&target).unwrap();
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        assert_eq!(metadata.nlink(), 1);
        assert!(!next.exists());
        assert!(require_absent(&target, "existing evidence target").is_err());

        let linked = parent.join("linked.bin");
        fs::hard_link(&target, &linked).unwrap();
        assert_eq!(
            read_private_file_bytes(&target, 1024),
            Err(IsolatedStartupRejectionErrorV1::HardlinkRejected)
        );
        fs::remove_file(&linked).unwrap();

        let symlinked = parent.join("symlinked.bin");
        symlink(&target, &symlinked).unwrap();
        assert_eq!(
            read_private_file_bytes(&symlinked, 1024),
            Err(IsolatedStartupRejectionErrorV1::SymlinkRejected)
        );
    }

    #[test]
    fn real_node_reopen_rejects_fresh_fixture_rollback_and_stale_mutants_v1() {
        run_large_stack_test("isolated-startup-real-node", || {
            let temporary = tempdir().unwrap();
            fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700)).unwrap();
            let primary = temporary.path().join("primary");
            private_dir(&primary);
            let watermark = SharedWatermarkV1::default();
            let bundle =
                commission_native_h1_ordinary_lab_test_bundle_v0(&primary, watermark.clone(), 7, 3)
                    .unwrap();
            let (core_config, rollback_application_config, runtime) =
                bundle.into_recovery_test_parts_v0();
            drop(runtime);

            // NativeApplicationConfigV0 is deliberately linear.  Author a
            // second independent fixture with the same deterministic chain
            // context so each isolated reopen attempt consumes its own fresh
            // config instead of weakening that boundary with Clone.
            let config_donor = temporary.path().join("config-donor");
            private_dir(&config_donor);
            let donor = commission_native_h1_ordinary_lab_test_bundle_v0(
                &config_donor,
                SharedWatermarkV1::default(),
                7,
                3,
            )
            .unwrap();
            let (donor_core_config, stale_application_config, donor_runtime) =
                donor.into_recovery_test_parts_v0();
            assert_eq!(donor_core_config, core_config);
            drop(donor_runtime);

            let rollback = temporary.path().join("rollback");
            copy_tree(&primary, &rollback);
            flip_file(&rollback.join("target-safety/safety.sqlite3"));
            let rollback_before = capture_root(&rollback).unwrap();
            assert_eq!(
                validate_fault_shape(
                    &capture_root(&primary).unwrap(),
                    &rollback_before,
                    IsolatedStartupFaultKindV1::RollbackAttempt,
                )
                .unwrap(),
                1
            );
            let rollback_error = reopen_deployed_lab_ordinary_cut_v0(
                &rollback,
                core_config.clone(),
                rollback_application_config,
                |_path| Ok::<_, ExternalWatermarkErrorV0>(watermark.clone()),
            )
            .expect_err("real Node must reject the isolated rollback mutant");
            assert!(!rollback_error.stage_v0().is_empty());
            assert_eq!(capture_root(&rollback).unwrap(), rollback_before);

            let stale = temporary.path().join("stale");
            copy_tree(&primary, &stale);
            flip_file(&stale.join("target-safety/safety.sqlite3"));
            let second =
                first_regular_file_except(&stale, Path::new("target-safety/safety.sqlite3"));
            flip_file(&second);
            let stale_before = capture_root(&stale).unwrap();
            assert_eq!(
                validate_fault_shape(
                    &capture_root(&primary).unwrap(),
                    &stale_before,
                    IsolatedStartupFaultKindV1::StaleSnapshot,
                )
                .unwrap(),
                2
            );
            let stale_error = reopen_deployed_lab_ordinary_cut_v0(
                &stale,
                core_config,
                stale_application_config,
                |_path| Ok::<_, ExternalWatermarkErrorV0>(watermark),
            )
            .expect_err("real Node must reject the isolated stale snapshot mutant");
            assert!(!stale_error.stage_v0().is_empty());
            assert_eq!(capture_root(&stale).unwrap(), stale_before);
        });
    }

    fn synthetic_evidence(
        campaign: CommonCampaignContextV1,
        origin: ValidatorId,
        primary: IsolatedRootInventoryFactsV1,
        isolated: IsolatedRootInventoryFactsV1,
        fault_kind: IsolatedStartupFaultKindV1,
        changed_file_count: u32,
    ) -> IsolatedStartupRejectionEvidenceV1 {
        IsolatedStartupRejectionEvidenceV1 {
            campaign,
            origin,
            target_config_sha256: [0x71; 32],
            fleet_start_certificate_sha256: [0x72; 32],
            fault_kind,
            primary_before: primary,
            primary_after: primary,
            isolated_before: isolated,
            isolated_after: isolated,
            changed_file_count,
            attempt_nonce: [0x73; 32],
            node_error_class: IsolatedNodeStartupErrorClassV1::DeployedOrdinaryReopenV0,
            node_error_stage: "safety.open_existing".to_owned(),
            node_error_detail_sha256: [0x74; 32],
            runtime_journal_before_sha256: [0x75; 32],
            runtime_journal_after_sha256: [0x75; 32],
            runtime_journal_bytes: 1_024,
            process_instance: 1,
            network_started: false,
            signature: [0; SIGNATURE_BYTES_V1],
        }
    }

    struct SimpleMutationFixture {
        _temporary: TempDir,
        primary: PathBuf,
        isolated: PathBuf,
    }

    fn simple_mutation_fixture(changed_files: usize) -> SimpleMutationFixture {
        let temporary = tempdir().unwrap();
        let primary = temporary.path().join("primary");
        let isolated = temporary.path().join("isolated");
        private_dir(&primary);
        private_dir(&isolated);
        for (name, byte) in [("a.sqlite3", 0x11), ("b.sqlite3", 0x22)] {
            fs::write(primary.join(name), vec![byte; 64]).unwrap();
            fs::write(isolated.join(name), vec![byte; 64]).unwrap();
            fs::set_permissions(primary.join(name), fs::Permissions::from_mode(0o600)).unwrap();
            fs::set_permissions(isolated.join(name), fs::Permissions::from_mode(0o600)).unwrap();
        }
        if changed_files >= 1 {
            flip_file(&isolated.join("a.sqlite3"));
        }
        if changed_files >= 2 {
            flip_file(&isolated.join("b.sqlite3"));
        }
        SimpleMutationFixture {
            _temporary: temporary,
            primary,
            isolated,
        }
    }

    fn validator_fixture() -> (ValidatorSet, Vec<SigningKey>) {
        let keys = (0..7)
            .map(|index| SigningKey::from_bytes(&[0x31 + index; 32]))
            .collect::<Vec<_>>();
        let parameters = ConsensusParametersV0::reference_shadow_v0();
        let validators = keys
            .iter()
            .enumerate()
            .map(|(index, key)| {
                Validator::new(
                    ValidatorId::new([0x11 + u8::try_from(index).unwrap(); 32]),
                    ConsensusPublicKey::new(key.verifying_key().to_bytes()),
                    VotingPower::new(1).unwrap(),
                )
                .unwrap()
            })
            .collect();
        let set = ValidatorSet::new(
            GenesisHash::new([0x21; 32]),
            ChainId::new("trnm-poco-g3-isolated-rejection-test").unwrap(),
            ProtocolVersion::V0,
            Epoch::new(0),
            parameters.hash(),
            validators,
        )
        .unwrap();
        (set, keys)
    }

    fn campaign(set: &ValidatorSet) -> CommonCampaignContextV1 {
        CommonCampaignContextV1::new(
            FleetCampaignIdentityV1::new(
                "poco-g3-7-20260814T000000Z-778899aa".to_owned(),
                set.chain_id(),
                *set.genesis_hash().as_bytes(),
                *set.id().as_bytes(),
                [0x41; 32],
                [0x42; 32],
                [0x43; 32],
                [0x44; 32],
                [0x45; 32],
                [0x46; 32],
                [0x47; 32],
                u32::try_from(set.validators().len()).unwrap(),
            )
            .unwrap(),
            FleetCampaignRequestV1::new(
                1,
                4,
                60,
                2,
                30,
                30,
                100,
                103,
                FleetBarrierTransportV1::Direct,
            )
            .unwrap(),
            FleetCampaignCapacitiesV1::new(4_096, 60, 163, 160, 60, 220, 8_192, 160, 161, 321, 108)
                .unwrap(),
            CommonChainCutV1::new(
                3, 4, 0, [0x50; 32], 3, 3, [0x51; 32], 1, [0x52; 32], 3, [0x53; 32], 3, [0x53; 32],
                [0x54; 32], 5, 2, 5,
            )
            .unwrap(),
        )
        .unwrap()
    }

    fn private_dir(path: &Path) {
        fs::create_dir(path).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }

    fn copy_tree(source: &Path, target: &Path) {
        fs::create_dir(target).unwrap();
        fs::set_permissions(
            target,
            fs::Permissions::from_mode(
                fs::symlink_metadata(source).unwrap().permissions().mode() & 0o777,
            ),
        )
        .unwrap();
        for entry in fs::read_dir(source).unwrap() {
            let entry = entry.unwrap();
            let source_path = entry.path();
            let target_path = target.join(entry.file_name());
            let metadata = fs::symlink_metadata(&source_path).unwrap();
            if metadata.is_dir() {
                copy_tree(&source_path, &target_path);
            } else {
                fs::copy(&source_path, &target_path).unwrap();
                fs::set_permissions(
                    &target_path,
                    fs::Permissions::from_mode(metadata.permissions().mode() & 0o777),
                )
                .unwrap();
            }
        }
    }

    fn flip_file(path: &Path) {
        let mut bytes = fs::read(path).unwrap();
        assert!(!bytes.is_empty());
        bytes[0] ^= 0xff;
        fs::write(path, bytes).unwrap();
    }

    fn first_regular_file_except(root: &Path, excluded: &Path) -> PathBuf {
        capture_root(root)
            .unwrap()
            .entries
            .into_iter()
            .find(|entry| {
                entry.kind == EntryKindV1::File
                    && Path::new(std::str::from_utf8(&entry.relative).unwrap()) != excluded
            })
            .map(|entry| root.join(Path::new(std::str::from_utf8(&entry.relative).unwrap())))
            .unwrap()
    }

    fn run_large_stack_test(name: &str, test: impl FnOnce() + Send + 'static) {
        let result = std::thread::Builder::new()
            .name(name.to_owned())
            .stack_size(64 * 1024 * 1024)
            .spawn(test)
            .unwrap()
            .join();
        if let Err(payload) = result {
            std::panic::resume_unwind(payload);
        }
    }
}
