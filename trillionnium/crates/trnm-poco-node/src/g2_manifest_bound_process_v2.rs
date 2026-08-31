//! Candidate-only process owner for the manifest-bound G2 inert join.
//!
//! This module is deliberately narrower than a Node runtime. An explicit
//! `prepare` command creates only a private T0-D anchor, an independent
//! process-pin anchor, and a stable lifetime-lock record. The `run` command
//! then reopens every source and the canonical Order store through
//! existing-only entry points, reproduces the complete typed issuer chain,
//! consumes the exact join at T0-D, advances the independent process pin, and
//! waits for control-stdin EOF while retaining every live owner.
//!
//! There is no network, signer, vote, application, Core, finality, activation,
//! or production interface here. The external process-pin checksum is still
//! required on every start. Descriptor-bound `openat`, namespace ownership,
//! same-UID rename exclusion, and coherent whole-authority rollback protection
//! remain unavailable and must not be inferred from this bounded candidate.

use std::{
    collections::BTreeSet,
    error::Error,
    fmt,
    fs::{self, File, Metadata, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

use borsh::{BorshDeserialize, BorshSerialize};
use sha2::{Digest, Sha256};
use trnm_poco_agent_market_v1::{
    AgentMarketFreshGenesisTrustBundleV1, AgentMarketStoreConfigV1, Hash32V1 as AgentHash32V1,
    PocoAgentMarketStoreV1,
};
use trnm_poco_consumption_settlement_v1::{
    ConsumptionSettlementFreshGenesisTrustBundleV1, ConsumptionSettlementStoreConfigV1,
    ConsumptionSettlementStoreV1,
};
use trnm_poco_da_v1::{
    AvailabilityCertificateIdV1, BatchIdV1, DaCommitteeDescriptorV1, DaPolicyV1, DaStoreConfigV1,
    Hash32V1 as DaHash32V1, PocoDaStoreV1,
};
use trnm_poco_global_execution_v1::{
    G2CandidateLocalFinalizeJoinV2, GlobalExecutionSourcesV1, ManifestBoundGlobalExecutionBatchV2,
    ManifestBoundGlobalExecutionInputV2,
};
use trnm_poco_mvcc_fee_v1::{MvccFeeGenesisV1, MvccFeeStoreV1};
use trnm_poco_order_application_v1::OrderHeaderTemplateV1;
use trnm_poco_order_state_v1::{CanonicalOrderStateHeadPinV1, PocoCanonicalOrderStateStoreV1};
use trnm_poco_order_types_v1::{
    BlockIdV1, BlockKindV1, EpochDescriptorIdV1, ParentBlockRefV1, ProtocolContextV1,
    QuorumCertificateIdV1,
};
use trnm_poco_verify_challenge_v1::{
    VerifyChallengeFreshGenesisTrustBundleV1, VerifyChallengeStoreConfigV1, VerifyChallengeStoreV1,
};

use crate::g2_manifest_bound_v2::{
    exact_finalize_join_commitment_v2, PocoNodeG2ManifestBoundCandidateLocalOwnerV2,
    PocoNodeG2ManifestBoundCandidateLocalStoreV2, PocoNodeG2ManifestBoundJournalNamespaceV2,
    PocoNodeG2ManifestBoundJournalPhaseV2, PocoNodeG2ManifestBoundJournalPinV2,
};

const PROCESS_MANIFEST_SCHEMA_V2: u16 = 2;
const PROCESS_PIN_SCHEMA_V2: u16 = 2;
const PROCESS_LOCK_SCHEMA_V2: u16 = 2;
const PROCESS_PIN_MAGIC_V2: [u8; 8] = *b"TRNMG2P2";
const PROCESS_LOCK_MAGIC_V2: [u8; 8] = *b"TRNMG2L2";
const PROCESS_PIN_FILE_NAME_V2: &str = "g2-manifest-bound-process-pin-v2.bin";
const PROCESS_LOCK_FILE_NAME_V2: &str = "g2-manifest-bound-process-v2.lock";
const PROCESS_PIN_TEMP_FILE_NAME_V2: &str = ".g2-manifest-bound-process-pin-v2.tmp";
const PROCESS_PIN_DOMAIN_V2: &str = "trnm.poco-ai.node-g2-process-pin.v2";
const PROCESS_LOCK_DOMAIN_V2: &str = "trnm.poco-ai.node-g2-process-lock.v2";
const MAX_MANIFEST_BYTES_V2: u64 = 16 * 1024 * 1024;
const MAX_PROCESS_RECORD_BYTES_V2: u64 = 64 * 1024;
const MAX_SOURCE_DATABASE_BYTES_V2: u64 = 2 * 1024 * 1024 * 1024;
const MAX_PROPOSER_ID_BYTES_V2: usize = 128;

/// Cloneable candidate material. It is not a process owner, a store handle,
/// or an authorization record. Every path is revalidated and every store is
/// reopened from its independently committed configuration before use.
#[derive(Clone, Debug, BorshDeserialize, BorshSerialize, Eq, PartialEq)]
pub struct PocoNodeG2CandidateProcessManifestV2 {
    pub schema_version: u16,
    pub process_scope: [u8; 32],

    pub da_path: String,
    pub da_scope_id: DaHash32V1,
    pub da_store_id: DaHash32V1,
    pub da_committee: DaCommitteeDescriptorV1,
    pub da_policy: DaPolicyV1,
    pub da_local_attestor_id: DaHash32V1,

    pub agent_market_path: String,
    pub agent_market_store_id: AgentHash32V1,
    pub agent_market_trust_bundle: AgentMarketFreshGenesisTrustBundleV1,

    pub verify_challenge_path: String,
    pub verify_challenge_store_id: AgentHash32V1,
    pub verify_challenge_trust_bundle: VerifyChallengeFreshGenesisTrustBundleV1,

    pub mvcc_fee_path: String,
    pub mvcc_fee_genesis: MvccFeeGenesisV1,

    pub consumption_settlement_path: String,
    pub consumption_settlement_store_id: AgentHash32V1,
    pub consumption_settlement_trust_bundle: ConsumptionSettlementFreshGenesisTrustBundleV1,

    pub canonical_order_state_path: String,
    pub canonical_order_state_store_id: [u8; 32],
    pub canonical_order_state_height: u64,
    pub canonical_order_state_block_id: [u8; 32],
    pub canonical_order_state_root: [u8; 32],
    pub canonical_order_state_history_checksum: [u8; 32],

    pub t0d_namespace_path: String,
    pub t0d_journal_id: [u8; 32],
    pub t0d_scope: [u8; 32],

    pub certified_batch: ManifestBoundGlobalExecutionBatchV2,
    pub da_batch_id: BatchIdV1,
    pub da_certificate_id: AvailabilityCertificateIdV1,

    pub order_header_schema_version: u16,
    pub order_epoch: u64,
    pub order_view: u64,
    pub order_proposer_id: Vec<u8>,
    pub order_epoch_descriptor_id: [u8; 32],
    pub order_justify_qc_id: [u8; 32],
}

impl PocoNodeG2CandidateProcessManifestV2 {
    fn validate_v2(&self) -> ProcessResultV2<()> {
        require_v2(
            self.schema_version == PROCESS_MANIFEST_SCHEMA_V2
                && self.process_scope != [0; 32]
                && self.t0d_journal_id != [0; 32]
                && self.t0d_scope == self.process_scope,
            "manifest schema, process scope, or T0-D identity differs",
        )?;
        self.certified_batch.revalidate().map_err(|cause| {
            rejected_v2(format!("certified manifest batch is invalid: {cause}"))
        })?;
        require_v2(
            *self.da_batch_id.as_bytes() != [0; 32]
                && *self.da_certificate_id.as_bytes() != [0; 32]
                && self.canonical_order_state_store_id != [0; 32]
                && self.canonical_order_state_height > 0
                && self.canonical_order_state_block_id != [0; 32]
                && self.canonical_order_state_root != [0; 32]
                && self.canonical_order_state_history_checksum != [0; 32],
            "manifest DA or canonical Order pin contains a zero fact",
        )?;
        require_v2(
            self.certified_batch.parent_height() == self.canonical_order_state_height
                && self.certified_batch.parent_block_id().to_bytes()
                    == self.canonical_order_state_block_id
                && self.certified_batch.parent_state_root().0 == self.canonical_order_state_root
                && self.certified_batch.candidate_height()
                    == self
                        .canonical_order_state_height
                        .checked_add(1)
                        .ok_or_else(|| rejected_v2("canonical Order height overflows"))?,
            "certified batch is not the direct successor of the pinned canonical Order head",
        )?;
        require_v2(
            self.order_header_schema_version == 1
                && !self.order_proposer_id.is_empty()
                && self.order_proposer_id.len() <= MAX_PROPOSER_ID_BYTES_V2
                && self.order_epoch_descriptor_id != [0; 32]
                && self.order_justify_qc_id != [0; 32],
            "ordinary Order header authority facts are empty or out of bounds",
        )?;
        for (label, value) in [
            ("DA", self.da_path.as_str()),
            ("Agent/Market", self.agent_market_path.as_str()),
            ("Verify/Challenge", self.verify_challenge_path.as_str()),
            ("MVCC/Fee", self.mvcc_fee_path.as_str()),
            (
                "Consumption/Settlement",
                self.consumption_settlement_path.as_str(),
            ),
            (
                "canonical Order state",
                self.canonical_order_state_path.as_str(),
            ),
            ("T0-D namespace", self.t0d_namespace_path.as_str()),
        ] {
            require_v2(!value.is_empty(), format!("{label} path is empty"))?;
        }
        Ok(())
    }

    fn canonical_pin_v2(&self) -> ProcessResultV2<CanonicalOrderStateHeadPinV1> {
        CanonicalOrderStateHeadPinV1::from_external_trusted_parts_v1(
            self.canonical_order_state_store_id,
            self.canonical_order_state_height,
            BlockIdV1::new(self.canonical_order_state_block_id),
            self.canonical_order_state_root,
            self.canonical_order_state_history_checksum,
        )
        .map_err(|cause| rejected_v2(format!("canonical Order pin is invalid: {cause}")))
    }

    fn order_template_v2(&self) -> OrderHeaderTemplateV1 {
        let context = self.certified_batch.context();
        OrderHeaderTemplateV1 {
            schema_version: self.order_header_schema_version,
            context: ProtocolContextV1 {
                schema_version: context.schema_version,
                genesis_hash: context.genesis_hash.0,
                chain_id: context.chain_id.clone(),
                protocol_version: context.protocol_version,
                stack_profile_hash: context.stack_profile_hash.0,
            },
            epoch: self.order_epoch,
            view: self.order_view,
            height: self.certified_batch.candidate_height(),
            block_kind: BlockKindV1::Ordinary,
            parent: ParentBlockRefV1::V1Block(self.certified_batch.parent_block_id()),
            proposer_id: self.order_proposer_id.clone(),
            epoch_descriptor_id: EpochDescriptorIdV1::new(self.order_epoch_descriptor_id),
            justify_qc_id: Some(QuorumCertificateIdV1::new(self.order_justify_qc_id)),
            timeout_certificate_id: None,
            next_epoch_descriptor_id: None,
            upgrade_plan_id: None,
            epoch_handoff_id: None,
        }
    }
}

#[derive(Debug)]
pub struct PocoNodeG2CandidateProcessErrorV2 {
    detail: String,
}

impl fmt::Display for PocoNodeG2CandidateProcessErrorV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "G2 candidate-only process refused: {}",
            self.detail
        )
    }
}

impl Error for PocoNodeG2CandidateProcessErrorV2 {}

type ProcessResultV2<T> = Result<T, PocoNodeG2CandidateProcessErrorV2>;

fn rejected_v2(detail: impl Into<String>) -> PocoNodeG2CandidateProcessErrorV2 {
    PocoNodeG2CandidateProcessErrorV2 {
        detail: detail.into(),
    }
}

fn reject_v2<T>(detail: impl Into<String>) -> ProcessResultV2<T> {
    Err(rejected_v2(detail))
}

fn require_v2(condition: bool, detail: impl Into<String>) -> ProcessResultV2<()> {
    if condition {
        Ok(())
    } else {
        reject_v2(detail)
    }
}

fn sha256_v2(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn domain_digest_v2(domain: &str, bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(
        u32::try_from(domain.len())
            .expect("bounded process-pin domain length fits u32")
            .to_le_bytes(),
    );
    hasher.update(domain.as_bytes());
    hasher.update(bytes);
    hasher.finalize().into()
}

fn parse_sha256_v2(value: &str, label: &str) -> ProcessResultV2<[u8; 32]> {
    require_v2(
        value.len() == 64 && value.as_bytes().iter().all(u8::is_ascii_hexdigit),
        format!("{label} must be exactly 64 hexadecimal characters"),
    )?;
    let mut output = [0_u8; 32];
    for (index, byte) in output.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|cause| rejected_v2(format!("cannot parse {label}: {cause}")))?;
    }
    Ok(output)
}

fn hex_v2(value: [u8; 32]) -> String {
    use fmt::Write as _;
    let mut output = String::with_capacity(64);
    for byte in value {
        write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DirectoryIdentityV2 {
    device: u64,
    inode: u64,
    owner: u32,
    mode: u32,
}

#[cfg(unix)]
fn directory_identity_v2(path: &Path) -> ProcessResultV2<DirectoryIdentityV2> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let metadata = fs::symlink_metadata(path)
        .map_err(|cause| rejected_v2(format!("directory identity unavailable: {cause}")))?;
    require_v2(
        metadata.is_dir()
            && !metadata.file_type().is_symlink()
            && metadata.permissions().mode() & 0o777 == 0o700,
        format!("directory must be direct and mode 0700: {}", path.display()),
    )?;
    let canonical = fs::canonicalize(path)
        .map_err(|cause| rejected_v2(format!("directory cannot canonicalize: {cause}")))?;
    require_v2(
        canonical == path,
        format!(
            "directory path is not already canonical: {}",
            path.display()
        ),
    )?;
    Ok(DirectoryIdentityV2 {
        device: metadata.dev(),
        inode: metadata.ino(),
        owner: metadata.uid(),
        mode: metadata.permissions().mode() & 0o777,
    })
}

#[cfg(not(unix))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DirectoryIdentityV2;

#[cfg(not(unix))]
fn directory_identity_v2(_path: &Path) -> ProcessResultV2<DirectoryIdentityV2> {
    reject_v2("candidate-only G2 process identity checks require a Unix host")
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ExistingFileIdentityV2 {
    device: u64,
    inode: u64,
    owner: u32,
    links: u64,
    mode: u32,
    length: u64,
    content_sha256: [u8; 32],
}

#[cfg(not(unix))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ExistingFileIdentityV2;

#[cfg(unix)]
fn metadata_identity_v2(metadata: &Metadata, content_sha256: [u8; 32]) -> ExistingFileIdentityV2 {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    ExistingFileIdentityV2 {
        device: metadata.dev(),
        inode: metadata.ino(),
        owner: metadata.uid(),
        links: metadata.nlink(),
        mode: metadata.permissions().mode() & 0o777,
        length: metadata.len(),
        content_sha256,
    }
}

#[cfg(unix)]
fn existing_file_identity_v2(
    path: &Path,
    maximum: u64,
    exact_mode: Option<u32>,
    expected_owner: u32,
) -> ProcessResultV2<ExistingFileIdentityV2> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let path_before = fs::symlink_metadata(path)
        .map_err(|cause| rejected_v2(format!("file identity unavailable: {cause}")))?;
    require_v2(
        path_before.is_file()
            && !path_before.file_type().is_symlink()
            && path_before.nlink() == 1
            && path_before.uid() == expected_owner
            && path_before.len() > 0
            && path_before.len() <= maximum
            && path_before.permissions().mode() & 0o022 == 0
            && exact_mode.is_none_or(|mode| path_before.permissions().mode() & 0o777 == mode),
        format!(
            "file type/owner/link/mode/size is unsafe: {}",
            path.display()
        ),
    )?;
    let mut file = File::open(path)
        .map_err(|cause| rejected_v2(format!("file bytes unavailable: {cause}")))?;
    let opened_before = file
        .metadata()
        .map_err(|cause| rejected_v2(format!("opened file identity unavailable: {cause}")))?;
    require_v2(
        opened_before.dev() == path_before.dev()
            && opened_before.ino() == path_before.ino()
            && opened_before.uid() == path_before.uid()
            && opened_before.nlink() == 1
            && opened_before.len() == path_before.len(),
        format!("file changed while opening: {}", path.display()),
    )?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    let mut total = 0_u64;
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|cause| rejected_v2(format!("file hash read failed: {cause}")))?;
        if count == 0 {
            break;
        }
        total = total
            .checked_add(u64::try_from(count).expect("fixed hash buffer length fits u64"))
            .ok_or_else(|| rejected_v2("file hash length overflows"))?;
        require_v2(
            total <= maximum,
            format!("file grew beyond its hash bound: {}", path.display()),
        )?;
        hasher.update(&buffer[..count]);
    }
    let opened_after = file
        .metadata()
        .map_err(|cause| rejected_v2(format!("file post-hash identity unavailable: {cause}")))?;
    let path_after = fs::symlink_metadata(path)
        .map_err(|cause| rejected_v2(format!("file post-hash path unavailable: {cause}")))?;
    require_v2(
        opened_after.dev() == opened_before.dev()
            && opened_after.ino() == opened_before.ino()
            && opened_after.len() == opened_before.len()
            && total == opened_before.len()
            && path_after.dev() == opened_before.dev()
            && path_after.ino() == opened_before.ino()
            && path_after.uid() == expected_owner
            && path_after.nlink() == 1,
        format!("file changed while hashing: {}", path.display()),
    )?;
    Ok(metadata_identity_v2(
        &opened_after,
        hasher.finalize().into(),
    ))
}

#[cfg(not(unix))]
fn existing_file_identity_v2(
    _path: &Path,
    _maximum: u64,
    _exact_mode: Option<u32>,
    _expected_owner: u32,
) -> ProcessResultV2<ExistingFileIdentityV2> {
    reject_v2("candidate-only G2 process identity checks require a Unix host")
}

#[cfg(unix)]
fn require_open_file_identity_v2(
    file: &File,
    expected: ExistingFileIdentityV2,
) -> ProcessResultV2<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let metadata = file
        .metadata()
        .map_err(|cause| rejected_v2(format!("open lock identity unavailable: {cause}")))?;
    require_v2(
        metadata.dev() == expected.device
            && metadata.ino() == expected.inode
            && metadata.uid() == expected.owner
            && metadata.nlink() == expected.links
            && metadata.permissions().mode() & 0o777 == expected.mode
            && metadata.len() == expected.length,
        "retained open lock descriptor identity changed",
    )
}

#[cfg(not(unix))]
fn require_open_file_identity_v2(
    _file: &File,
    _expected: ExistingFileIdentityV2,
) -> ProcessResultV2<()> {
    reject_v2("candidate-only G2 process identity checks require a Unix host")
}

fn canonical_existing_descendant_v2(
    root: &Path,
    raw: &str,
    label: &str,
) -> ProcessResultV2<PathBuf> {
    let path = PathBuf::from(raw);
    require_v2(
        path.is_absolute() && path.strip_prefix(root).is_ok() && path != root,
        format!("{label} path is not an absolute run-root descendant"),
    )?;
    let canonical = fs::canonicalize(&path)
        .map_err(|cause| rejected_v2(format!("{label} path cannot canonicalize: {cause}")))?;
    require_v2(
        canonical == path && canonical.strip_prefix(root).is_ok(),
        format!("{label} path is not already canonical inside the run root"),
    )?;
    Ok(canonical)
}

#[cfg(unix)]
fn directory_owner_v2(identity: DirectoryIdentityV2) -> u32 {
    identity.owner
}

#[cfg(not(unix))]
fn directory_owner_v2(_identity: DirectoryIdentityV2) -> u32 {
    0
}

fn read_bounded_file_v2(path: &Path, maximum: u64, label: &str) -> ProcessResultV2<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|cause| rejected_v2(format!("{label} metadata unavailable: {cause}")))?;
    require_v2(
        metadata.is_file()
            && !metadata.file_type().is_symlink()
            && metadata.len() > 0
            && metadata.len() <= maximum,
        format!("{label} type or size is invalid"),
    )?;
    let capacity = usize::try_from(metadata.len())
        .map_err(|_| rejected_v2(format!("{label} length exceeds usize")))?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(capacity)
        .map_err(|cause| rejected_v2(format!("cannot reserve {label} bytes: {cause}")))?;
    let limit = maximum
        .checked_add(1)
        .ok_or_else(|| rejected_v2(format!("{label} read bound overflows")))?;
    File::open(path)
        .and_then(|mut file| (&mut file).take(limit).read_to_end(&mut bytes))
        .map_err(|cause| rejected_v2(format!("cannot read {label}: {cause}")))?;
    require_v2(
        bytes.len() == capacity && u64::try_from(bytes.len()).is_ok_and(|length| length <= maximum),
        format!("{label} length changed during read"),
    )?;
    Ok(bytes)
}

#[cfg(unix)]
fn require_identity_content_sha256_v2(
    identity: ExistingFileIdentityV2,
    expected: [u8; 32],
    label: &str,
) -> ProcessResultV2<()> {
    require_v2(
        identity.content_sha256 == expected,
        format!("{label} identity hash differs from separately read bytes"),
    )
}

#[cfg(not(unix))]
fn require_identity_content_sha256_v2(
    _identity: ExistingFileIdentityV2,
    _expected: [u8; 32],
    _label: &str,
) -> ProcessResultV2<()> {
    reject_v2("candidate-only G2 process identity checks require a Unix host")
}

fn path_exists_no_follow_v2(path: &Path, label: &str) -> ProcessResultV2<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(cause) if cause.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(cause) => reject_v2(format!("{label} path unavailable: {cause}")),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PrepareDurablePrefixV2 {
    Empty,
    LockOnly,
    LockAndT0dAnchor,
    CompleteAnchors,
}

fn classify_prepare_durable_prefix_v2(
    process_lock_exists: bool,
    t0d_journal_exists: bool,
    process_pin_exists: bool,
    process_pin_temp_exists: bool,
) -> ProcessResultV2<PrepareDurablePrefixV2> {
    require_v2(
        !process_pin_temp_exists,
        "prepare found a process-pin temporary transition state",
    )?;
    match (process_lock_exists, t0d_journal_exists, process_pin_exists) {
        (false, false, false) => Ok(PrepareDurablePrefixV2::Empty),
        (true, false, false) => Ok(PrepareDurablePrefixV2::LockOnly),
        (true, true, false) => Ok(PrepareDurablePrefixV2::LockAndT0dAnchor),
        (true, true, true) => Ok(PrepareDurablePrefixV2::CompleteAnchors),
        _ => reject_v2(
            "prepare durable files are not an exact lock -> T0-D anchor -> process-pin prefix",
        ),
    }
}

#[derive(Clone, Debug)]
struct ProcessPathsV2 {
    da: PathBuf,
    agent_market: PathBuf,
    verify_challenge: PathBuf,
    mvcc_fee: PathBuf,
    consumption_settlement: PathBuf,
    canonical_order_state: PathBuf,
    t0d_namespace: PathBuf,
    process_pin: PathBuf,
    process_lock: PathBuf,
    process_pin_temp: PathBuf,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SourceFileIdentitiesV2 {
    da: ExistingFileIdentityV2,
    agent_market: ExistingFileIdentityV2,
    verify_challenge: ExistingFileIdentityV2,
    mvcc_fee: ExistingFileIdentityV2,
    consumption_settlement: ExistingFileIdentityV2,
    canonical_order_state: ExistingFileIdentityV2,
}

impl SourceFileIdentitiesV2 {
    fn capture_v2(paths: &ProcessPathsV2, expected_owner: u32) -> ProcessResultV2<Self> {
        Ok(Self {
            da: existing_file_identity_v2(
                &paths.da,
                MAX_SOURCE_DATABASE_BYTES_V2,
                None,
                expected_owner,
            )?,
            agent_market: existing_file_identity_v2(
                &paths.agent_market,
                MAX_SOURCE_DATABASE_BYTES_V2,
                None,
                expected_owner,
            )?,
            verify_challenge: existing_file_identity_v2(
                &paths.verify_challenge,
                MAX_SOURCE_DATABASE_BYTES_V2,
                None,
                expected_owner,
            )?,
            mvcc_fee: existing_file_identity_v2(
                &paths.mvcc_fee,
                MAX_SOURCE_DATABASE_BYTES_V2,
                None,
                expected_owner,
            )?,
            consumption_settlement: existing_file_identity_v2(
                &paths.consumption_settlement,
                MAX_SOURCE_DATABASE_BYTES_V2,
                None,
                expected_owner,
            )?,
            canonical_order_state: existing_file_identity_v2(
                &paths.canonical_order_state,
                MAX_SOURCE_DATABASE_BYTES_V2,
                None,
                expected_owner,
            )?,
        })
    }

    fn require_fresh_exact_v2(
        &self,
        paths: &ProcessPathsV2,
        expected_owner: u32,
    ) -> ProcessResultV2<()> {
        require_v2(
            *self == Self::capture_v2(paths, expected_owner)?,
            "one of the six existing source/Order files changed",
        )
    }
}

#[derive(Debug)]
struct LoadedProcessManifestV2 {
    manifest: PocoNodeG2CandidateProcessManifestV2,
    manifest_path: PathBuf,
    manifest_sha256: [u8; 32],
    manifest_identity: ExistingFileIdentityV2,
    run_root: PathBuf,
    run_root_identity: DirectoryIdentityV2,
    t0d_namespace_identity: DirectoryIdentityV2,
    source_identities: SourceFileIdentitiesV2,
    paths: ProcessPathsV2,
}

impl LoadedProcessManifestV2 {
    fn load_existing_v2(
        run_root: &Path,
        manifest_path: &Path,
        expected_manifest_sha256: &str,
    ) -> ProcessResultV2<Self> {
        require_v2(
            run_root.is_absolute() && manifest_path.is_absolute(),
            "run root and manifest path must be absolute",
        )?;
        let requested_run_root = run_root.to_path_buf();
        let run_root = fs::canonicalize(run_root)
            .map_err(|cause| rejected_v2(format!("run root cannot canonicalize: {cause}")))?;
        require_v2(
            run_root == requested_run_root,
            "run root path is not already canonical",
        )?;
        let run_root_identity = directory_identity_v2(&run_root)?;
        let expected_owner = directory_owner_v2(run_root_identity);
        let requested_manifest_path = manifest_path.to_path_buf();
        let manifest_path = fs::canonicalize(manifest_path)
            .map_err(|cause| rejected_v2(format!("manifest cannot canonicalize: {cause}")))?;
        require_v2(
            manifest_path == requested_manifest_path
                && manifest_path.strip_prefix(&run_root).is_ok()
                && manifest_path != run_root,
            "manifest path is not canonical inside the run root",
        )?;
        let manifest_identity =
            existing_file_identity_v2(&manifest_path, MAX_MANIFEST_BYTES_V2, None, expected_owner)?;
        let raw = read_bounded_file_v2(&manifest_path, MAX_MANIFEST_BYTES_V2, "process manifest")?;
        let manifest_sha256 = sha256_v2(&raw);
        require_identity_content_sha256_v2(manifest_identity, manifest_sha256, "process manifest")?;
        require_v2(
            existing_file_identity_v2(&manifest_path, MAX_MANIFEST_BYTES_V2, None, expected_owner)?
                == manifest_identity,
            "process manifest identity changed across its bounded second read",
        )?;
        require_v2(
            manifest_sha256 == parse_sha256_v2(expected_manifest_sha256, "manifest SHA-256")?,
            "manifest SHA-256 differs from the externally retained value",
        )?;
        let manifest =
            PocoNodeG2CandidateProcessManifestV2::try_from_slice(&raw).map_err(|cause| {
                rejected_v2(format!("manifest strict Borsh decode failed: {cause}"))
            })?;
        let recoded = borsh::to_vec(&manifest)
            .map_err(|cause| rejected_v2(format!("manifest Borsh re-encode failed: {cause}")))?;
        require_v2(recoded == raw, "manifest is not exact canonical Borsh")?;
        manifest.validate_v2()?;

        let paths = ProcessPathsV2 {
            da: canonical_existing_descendant_v2(&run_root, &manifest.da_path, "DA")?,
            agent_market: canonical_existing_descendant_v2(
                &run_root,
                &manifest.agent_market_path,
                "Agent/Market",
            )?,
            verify_challenge: canonical_existing_descendant_v2(
                &run_root,
                &manifest.verify_challenge_path,
                "Verify/Challenge",
            )?,
            mvcc_fee: canonical_existing_descendant_v2(
                &run_root,
                &manifest.mvcc_fee_path,
                "MVCC/Fee",
            )?,
            consumption_settlement: canonical_existing_descendant_v2(
                &run_root,
                &manifest.consumption_settlement_path,
                "Consumption/Settlement",
            )?,
            canonical_order_state: canonical_existing_descendant_v2(
                &run_root,
                &manifest.canonical_order_state_path,
                "canonical Order state",
            )?,
            t0d_namespace: canonical_existing_descendant_v2(
                &run_root,
                &manifest.t0d_namespace_path,
                "T0-D namespace",
            )?,
            process_pin: run_root.join(PROCESS_PIN_FILE_NAME_V2),
            process_lock: run_root.join(PROCESS_LOCK_FILE_NAME_V2),
            process_pin_temp: run_root.join(PROCESS_PIN_TEMP_FILE_NAME_V2),
        };
        let t0d_namespace_identity = directory_identity_v2(&paths.t0d_namespace)?;
        require_v2(
            directory_owner_v2(t0d_namespace_identity) == expected_owner,
            "T0-D namespace owner differs from the run root owner",
        )?;
        let source_paths = [
            &paths.da,
            &paths.agent_market,
            &paths.verify_challenge,
            &paths.mvcc_fee,
            &paths.consumption_settlement,
            &paths.canonical_order_state,
        ];
        let unique = source_paths
            .iter()
            .map(|path| path.as_os_str().to_owned())
            .collect::<BTreeSet<_>>();
        require_v2(
            unique.len() == source_paths.len()
                && !source_paths
                    .iter()
                    .any(|path| path.starts_with(&paths.t0d_namespace))
                && !source_paths.iter().any(|path| {
                    path.as_path() == manifest_path.as_path()
                        || path.as_path() == paths.process_pin.as_path()
                        || path.as_path() == paths.process_lock.as_path()
                        || path.as_path() == paths.process_pin_temp.as_path()
                })
                && !manifest_path.starts_with(&paths.t0d_namespace)
                && manifest_path != paths.process_pin
                && manifest_path != paths.process_lock,
            "source, canonical, manifest, T0-D, pin, or lock namespaces overlap",
        )?;
        let source_identities = SourceFileIdentitiesV2::capture_v2(&paths, expected_owner)?;
        Ok(Self {
            manifest,
            manifest_path,
            manifest_sha256,
            manifest_identity,
            run_root,
            run_root_identity,
            t0d_namespace_identity,
            source_identities,
            paths,
        })
    }

    fn expected_owner_v2(&self) -> u32 {
        directory_owner_v2(self.run_root_identity)
    }

    fn revalidate_static_paths_v2(&self) -> ProcessResultV2<()> {
        require_v2(
            directory_identity_v2(&self.run_root)? == self.run_root_identity
                && directory_identity_v2(&self.paths.t0d_namespace)? == self.t0d_namespace_identity
                && existing_file_identity_v2(
                    &self.manifest_path,
                    MAX_MANIFEST_BYTES_V2,
                    None,
                    self.expected_owner_v2(),
                )? == self.manifest_identity,
            "run root, T0-D namespace, or manifest identity changed",
        )?;
        self.source_identities
            .require_fresh_exact_v2(&self.paths, self.expected_owner_v2())
    }
}

#[derive(Clone, Debug, BorshDeserialize, BorshSerialize, Eq, PartialEq)]
struct T0dJournalPinDataV2 {
    journal_id: [u8; 32],
    scope: [u8; 32],
    generation: u64,
    phase: u8,
    checksum: [u8; 32],
}

impl T0dJournalPinDataV2 {
    fn from_pin_v2(pin: &PocoNodeG2ManifestBoundJournalPinV2) -> Self {
        Self {
            journal_id: pin.journal_id_v2(),
            scope: pin.scope_v2(),
            generation: pin.generation_v2(),
            phase: match pin.phase_v2() {
                PocoNodeG2ManifestBoundJournalPhaseV2::Anchor => 0,
                PocoNodeG2ManifestBoundJournalPhaseV2::Persisted => 1,
            },
            checksum: pin.checksum_v2(),
        }
    }

    fn to_pin_v2(&self) -> ProcessResultV2<PocoNodeG2ManifestBoundJournalPinV2> {
        let phase = match self.phase {
            0 => PocoNodeG2ManifestBoundJournalPhaseV2::Anchor,
            1 => PocoNodeG2ManifestBoundJournalPhaseV2::Persisted,
            _ => return reject_v2("process pin names an unsupported T0-D phase"),
        };
        PocoNodeG2ManifestBoundJournalPinV2::from_external_trusted_parts_v2(
            self.journal_id,
            self.scope,
            self.generation,
            phase,
            self.checksum,
        )
        .map_err(|cause| rejected_v2(format!("process pin contains an invalid T0-D pin: {cause}")))
    }
}

#[derive(Clone, Debug, BorshDeserialize, BorshSerialize, Eq, PartialEq)]
struct ProcessTargetV2 {
    predecessor_process_checksum: [u8; 32],
    t0d_target: T0dJournalPinDataV2,
    exact_join_commitment: [u8; 32],
    input_id: [u8; 32],
    candidate_height: u64,
    candidate_block_id: [u8; 32],
    canonical_store_id: [u8; 32],
    canonical_height: u64,
    canonical_block_id: [u8; 32],
    canonical_state_root: [u8; 32],
    canonical_history_checksum: [u8; 32],
}

impl ProcessTargetV2 {
    fn from_exact_join_v2(
        predecessor_process_checksum: [u8; 32],
        t0d_target: &PocoNodeG2ManifestBoundJournalPinV2,
        exact_join: &G2CandidateLocalFinalizeJoinV2,
        exact_join_commitment: [u8; 32],
        canonical_pin: &CanonicalOrderStateHeadPinV1,
    ) -> ProcessResultV2<Self> {
        Self::from_exact_join_facts_v2(
            predecessor_process_checksum,
            t0d_target,
            *exact_join.input_id().as_bytes(),
            exact_join.candidate_height(),
            exact_join.candidate_block_id().to_bytes(),
            exact_join_commitment,
            canonical_pin,
        )
    }

    fn from_exact_join_facts_v2(
        predecessor_process_checksum: [u8; 32],
        t0d_target: &PocoNodeG2ManifestBoundJournalPinV2,
        input_id: [u8; 32],
        candidate_height: u64,
        candidate_block_id: [u8; 32],
        exact_join_commitment: [u8; 32],
        canonical_pin: &CanonicalOrderStateHeadPinV1,
    ) -> ProcessResultV2<Self> {
        require_v2(
            predecessor_process_checksum != [0; 32]
                && exact_join_commitment != [0; 32]
                && input_id != [0; 32]
                && candidate_height > 0
                && candidate_block_id != [0; 32]
                && t0d_target.phase_v2() == PocoNodeG2ManifestBoundJournalPhaseV2::Persisted,
            "process target predecessor, join commitment, or T0-D phase is invalid",
        )?;
        Ok(Self {
            predecessor_process_checksum,
            t0d_target: T0dJournalPinDataV2::from_pin_v2(t0d_target),
            exact_join_commitment,
            input_id,
            candidate_height,
            candidate_block_id,
            canonical_store_id: canonical_pin.store_id(),
            canonical_height: canonical_pin.height(),
            canonical_block_id: canonical_pin.block_id().to_bytes(),
            canonical_state_root: canonical_pin.state_root(),
            canonical_history_checksum: canonical_pin.history_checksum(),
        })
    }
}

#[derive(Clone, Debug, BorshDeserialize, BorshSerialize, Eq, PartialEq)]
struct ProcessPinBodyV2 {
    magic: [u8; 8],
    schema_version: u16,
    process_scope: [u8; 32],
    manifest_sha256: [u8; 32],
    t0d_anchor: T0dJournalPinDataV2,
    prepared_exact_join_commitment: [u8; 32],
    target: Option<ProcessTargetV2>,
}

#[derive(Clone, Debug, BorshDeserialize, BorshSerialize, Eq, PartialEq)]
struct ProcessPinRecordV2 {
    body: ProcessPinBodyV2,
    checksum: [u8; 32],
}

impl ProcessPinRecordV2 {
    fn anchor_v2(
        process_scope: [u8; 32],
        manifest_sha256: [u8; 32],
        t0d_anchor: &PocoNodeG2ManifestBoundJournalPinV2,
        prepared_exact_join_commitment: [u8; 32],
    ) -> ProcessResultV2<Self> {
        let body = ProcessPinBodyV2 {
            magic: PROCESS_PIN_MAGIC_V2,
            schema_version: PROCESS_PIN_SCHEMA_V2,
            process_scope,
            manifest_sha256,
            t0d_anchor: T0dJournalPinDataV2::from_pin_v2(t0d_anchor),
            prepared_exact_join_commitment,
            target: None,
        };
        Self::from_body_v2(body)
    }

    fn from_body_v2(body: ProcessPinBodyV2) -> ProcessResultV2<Self> {
        let raw = borsh::to_vec(&body)
            .map_err(|cause| rejected_v2(format!("process pin body encode failed: {cause}")))?;
        require_v2(
            !raw.is_empty()
                && u64::try_from(raw.len())
                    .is_ok_and(|length| length < MAX_PROCESS_RECORD_BYTES_V2.saturating_sub(32)),
            "process pin body exceeds its hard bound",
        )?;
        let value = Self {
            body,
            checksum: domain_digest_v2(PROCESS_PIN_DOMAIN_V2, &raw),
        };
        value.validate_v2()?;
        Ok(value)
    }

    fn anchor_checksum_v2(&self) -> ProcessResultV2<[u8; 32]> {
        Ok(self.anchor_record_v2()?.checksum)
    }

    fn anchor_record_v2(&self) -> ProcessResultV2<Self> {
        let mut anchor = self.body.clone();
        anchor.target = None;
        Self::from_body_v2(anchor)
    }

    fn successor_v2(&self, target: ProcessTargetV2) -> ProcessResultV2<Self> {
        require_v2(
            self.body.target.is_none() && target.predecessor_process_checksum == self.checksum,
            "process pin target is not the unique anchor successor",
        )?;
        let mut body = self.body.clone();
        body.target = Some(target);
        Self::from_body_v2(body)
    }

    fn validate_v2(&self) -> ProcessResultV2<()> {
        require_v2(
            self.body.magic == PROCESS_PIN_MAGIC_V2
                && self.body.schema_version == PROCESS_PIN_SCHEMA_V2
                && self.body.process_scope != [0; 32]
                && self.body.manifest_sha256 != [0; 32]
                && self.body.prepared_exact_join_commitment != [0; 32],
            "process pin header or identity is invalid",
        )?;
        let t0d_anchor = self.body.t0d_anchor.to_pin_v2()?;
        require_v2(
            t0d_anchor.phase_v2() == PocoNodeG2ManifestBoundJournalPhaseV2::Anchor
                && t0d_anchor.generation_v2() == 0
                && t0d_anchor.scope_v2() == self.body.process_scope,
            "process pin does not retain the generation-zero T0-D anchor for its process scope",
        )?;
        let raw = borsh::to_vec(&self.body)
            .map_err(|cause| rejected_v2(format!("process pin body re-encode failed: {cause}")))?;
        require_v2(
            self.checksum == domain_digest_v2(PROCESS_PIN_DOMAIN_V2, &raw),
            "process pin checksum differs",
        )?;
        if let Some(target) = &self.body.target {
            let target_t0d = target.t0d_target.to_pin_v2()?;
            let expected_target_generation = t0d_anchor
                .generation_v2()
                .checked_add(1)
                .ok_or_else(|| rejected_v2("T0-D anchor generation overflows"))?;
            let expected_candidate_height = target
                .canonical_height
                .checked_add(1)
                .ok_or_else(|| rejected_v2("canonical target height overflows"))?;
            require_v2(
                target.predecessor_process_checksum == self.anchor_checksum_v2()?
                    && target.exact_join_commitment == self.body.prepared_exact_join_commitment
                    && target.input_id != [0; 32]
                    && target.candidate_height > 0
                    && target.candidate_block_id != [0; 32]
                    && target.canonical_store_id != [0; 32]
                    && target.canonical_height > 0
                    && target.canonical_block_id != [0; 32]
                    && target.canonical_state_root != [0; 32]
                    && target.canonical_history_checksum != [0; 32]
                    && target.candidate_height == expected_candidate_height
                    && target_t0d.phase_v2() == PocoNodeG2ManifestBoundJournalPhaseV2::Persisted
                    && target_t0d.journal_id_v2() == t0d_anchor.journal_id_v2()
                    && target_t0d.scope_v2() == t0d_anchor.scope_v2()
                    && target_t0d.scope_v2() == self.body.process_scope
                    && target_t0d.generation_v2() == expected_target_generation
                    && target_t0d.checksum_v2() != t0d_anchor.checksum_v2(),
                "process pin target facts are invalid",
            )?;
        }
        Ok(())
    }

    fn encode_exact_v2(&self) -> ProcessResultV2<Vec<u8>> {
        self.validate_v2()?;
        let raw = borsh::to_vec(self)
            .map_err(|cause| rejected_v2(format!("process pin encode failed: {cause}")))?;
        require_v2(
            !raw.is_empty()
                && u64::try_from(raw.len())
                    .is_ok_and(|length| length <= MAX_PROCESS_RECORD_BYTES_V2),
            "process pin record exceeds its hard bound",
        )?;
        Ok(raw)
    }

    fn decode_exact_v2(raw: &[u8]) -> ProcessResultV2<Self> {
        require_v2(
            !raw.is_empty()
                && u64::try_from(raw.len())
                    .is_ok_and(|length| length <= MAX_PROCESS_RECORD_BYTES_V2),
            "process pin record exceeds its hard bound",
        )?;
        let value = Self::try_from_slice(raw)
            .map_err(|cause| rejected_v2(format!("process pin strict decode failed: {cause}")))?;
        value.validate_v2()?;
        require_v2(
            value.encode_exact_v2()? == raw,
            "process pin is not exact Borsh",
        )?;
        Ok(value)
    }
}

#[derive(Clone, Debug, BorshDeserialize, BorshSerialize, Eq, PartialEq)]
struct ProcessLockBodyV2 {
    magic: [u8; 8],
    schema_version: u16,
    process_scope: [u8; 32],
    manifest_sha256: [u8; 32],
}

#[derive(Clone, Debug, BorshDeserialize, BorshSerialize, Eq, PartialEq)]
struct ProcessLockRecordV2 {
    body: ProcessLockBodyV2,
    checksum: [u8; 32],
}

impl ProcessLockRecordV2 {
    fn new_v2(process_scope: [u8; 32], manifest_sha256: [u8; 32]) -> ProcessResultV2<Self> {
        require_v2(
            process_scope != [0; 32] && manifest_sha256 != [0; 32],
            "process lock identity contains a zero fact",
        )?;
        let body = ProcessLockBodyV2 {
            magic: PROCESS_LOCK_MAGIC_V2,
            schema_version: PROCESS_LOCK_SCHEMA_V2,
            process_scope,
            manifest_sha256,
        };
        let raw = borsh::to_vec(&body)
            .map_err(|cause| rejected_v2(format!("process lock body encode failed: {cause}")))?;
        Ok(Self {
            body,
            checksum: domain_digest_v2(PROCESS_LOCK_DOMAIN_V2, &raw),
        })
    }

    fn validate_v2(&self) -> ProcessResultV2<()> {
        require_v2(
            self.body.magic == PROCESS_LOCK_MAGIC_V2
                && self.body.schema_version == PROCESS_LOCK_SCHEMA_V2
                && self.body.process_scope != [0; 32]
                && self.body.manifest_sha256 != [0; 32],
            "process lock header or identity is invalid",
        )?;
        let raw = borsh::to_vec(&self.body)
            .map_err(|cause| rejected_v2(format!("process lock body re-encode failed: {cause}")))?;
        require_v2(
            self.checksum == domain_digest_v2(PROCESS_LOCK_DOMAIN_V2, &raw),
            "process lock checksum differs",
        )
    }

    fn encode_exact_v2(&self) -> ProcessResultV2<Vec<u8>> {
        self.validate_v2()?;
        let raw = borsh::to_vec(self)
            .map_err(|cause| rejected_v2(format!("process lock encode failed: {cause}")))?;
        require_v2(
            !raw.is_empty()
                && u64::try_from(raw.len())
                    .is_ok_and(|length| length <= MAX_PROCESS_RECORD_BYTES_V2),
            "process lock record exceeds its hard bound",
        )?;
        Ok(raw)
    }

    fn decode_exact_v2(raw: &[u8]) -> ProcessResultV2<Self> {
        let value = Self::try_from_slice(raw)
            .map_err(|cause| rejected_v2(format!("process lock strict decode failed: {cause}")))?;
        value.validate_v2()?;
        require_v2(
            value.encode_exact_v2()? == raw,
            "process lock is not exact Borsh",
        )?;
        Ok(value)
    }
}

fn private_create_new_v2(path: &Path) -> ProcessResultV2<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
        .open(path)
        .map_err(|cause| rejected_v2(format!("cannot create private file: {cause}")))
}

fn write_new_private_v2(path: &Path, raw: &[u8]) -> ProcessResultV2<File> {
    require_v2(
        !raw.is_empty()
            && u64::try_from(raw.len()).is_ok_and(|length| length <= MAX_PROCESS_RECORD_BYTES_V2),
        "private record bytes exceed their hard bound",
    )?;
    let mut file = private_create_new_v2(path)?;
    file.write_all(raw)
        .and_then(|()| file.sync_all())
        .map_err(|cause| rejected_v2(format!("cannot persist private file: {cause}")))?;
    Ok(file)
}

fn sync_directory_v2(path: &Path) -> ProcessResultV2<()> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|cause| rejected_v2(format!("cannot fsync process directory: {cause}")))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExternalProcessPinAuthenticationV2 {
    CurrentRecord,
    AnchorOfCurrentUniqueSuccessor,
}

#[derive(Debug)]
struct ProcessPinStoreV2 {
    path: PathBuf,
    expected_owner: u32,
    identity: ExistingFileIdentityV2,
}

impl ProcessPinStoreV2 {
    fn initialize_new_v2(
        path: PathBuf,
        expected_owner: u32,
        anchor: &ProcessPinRecordV2,
    ) -> ProcessResultV2<Self> {
        let raw = anchor.encode_exact_v2()?;
        let file = write_new_private_v2(&path, &raw)?;
        drop(file);
        sync_directory_v2(
            path.parent()
                .ok_or_else(|| rejected_v2("process pin path has no parent"))?,
        )?;
        let store = Self {
            identity: existing_file_identity_v2(
                &path,
                MAX_PROCESS_RECORD_BYTES_V2,
                Some(0o600),
                expected_owner,
            )?,
            path,
            expected_owner,
        };
        require_v2(
            store.audit_fresh_v2()? == *anchor,
            "fresh process pin anchor differs",
        )?;
        Ok(store)
    }

    fn open_existing_v2(
        path: PathBuf,
        expected_owner: u32,
        expected_checksum: [u8; 32],
    ) -> ProcessResultV2<(Self, ProcessPinRecordV2)> {
        let (store, record) = Self::open_existing_current_v2(path, expected_owner)?;
        require_v2(
            record.checksum == expected_checksum,
            "process pin differs from the externally retained checksum",
        )?;
        Ok((store, record))
    }

    fn open_existing_authenticated_v2(
        path: PathBuf,
        expected_owner: u32,
        externally_retained_checksum: [u8; 32],
    ) -> ProcessResultV2<(Self, ProcessPinRecordV2, ExternalProcessPinAuthenticationV2)> {
        let (store, record) = Self::open_existing_current_v2(path, expected_owner)?;
        let authentication = if record.checksum == externally_retained_checksum {
            ExternalProcessPinAuthenticationV2::CurrentRecord
        } else if record.body.target.is_some()
            && record.anchor_checksum_v2()? == externally_retained_checksum
        {
            ExternalProcessPinAuthenticationV2::AnchorOfCurrentUniqueSuccessor
        } else {
            return reject_v2(
                "process pin is neither the externally retained record nor its unique target successor",
            );
        };
        Ok((store, record, authentication))
    }

    fn open_existing_current_v2(
        path: PathBuf,
        expected_owner: u32,
    ) -> ProcessResultV2<(Self, ProcessPinRecordV2)> {
        let identity = existing_file_identity_v2(
            &path,
            MAX_PROCESS_RECORD_BYTES_V2,
            Some(0o600),
            expected_owner,
        )?;
        let store = Self {
            path,
            expected_owner,
            identity,
        };
        let record = store.audit_fresh_v2()?;
        Ok((store, record))
    }

    fn audit_fresh_v2(&self) -> ProcessResultV2<ProcessPinRecordV2> {
        let identity = existing_file_identity_v2(
            &self.path,
            MAX_PROCESS_RECORD_BYTES_V2,
            Some(0o600),
            self.expected_owner,
        )?;
        require_v2(
            identity == self.identity,
            "process pin file identity changed",
        )?;
        let raw = read_bounded_file_v2(&self.path, MAX_PROCESS_RECORD_BYTES_V2, "process pin")?;
        ProcessPinRecordV2::decode_exact_v2(&raw)
    }

    fn temporary_record_v2(
        &self,
        temporary_path: &Path,
    ) -> ProcessResultV2<Option<(ExistingFileIdentityV2, ProcessPinRecordV2)>> {
        match fs::symlink_metadata(temporary_path) {
            Err(cause) if cause.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(cause) => reject_v2(format!(
                "process pin CAS temporary path unavailable: {cause}"
            )),
            Ok(_) => {
                let identity = existing_file_identity_v2(
                    temporary_path,
                    MAX_PROCESS_RECORD_BYTES_V2,
                    Some(0o600),
                    self.expected_owner,
                )?;
                let record = ProcessPinRecordV2::decode_exact_v2(&read_bounded_file_v2(
                    temporary_path,
                    MAX_PROCESS_RECORD_BYTES_V2,
                    "process pin CAS target",
                )?)?;
                Ok(Some((identity, record)))
            }
        }
    }

    fn advance_or_reconcile_v2(
        &mut self,
        expected: &ProcessPinRecordV2,
        target: &ProcessPinRecordV2,
        temporary_path: &Path,
    ) -> ProcessResultV2<()> {
        require_v2(
            expected.body.target.is_none()
                && target.body.target.is_some()
                && target.anchor_checksum_v2()? == expected.checksum,
            "process pin CAS source or target differs",
        )?;
        require_v2(
            self.path.parent() == temporary_path.parent(),
            "process pin and CAS temporary file do not share one directory",
        )?;
        let current = self.audit_fresh_v2()?;
        let temporary = self.temporary_record_v2(temporary_path)?;

        if current == *target {
            if let Some((_identity, temporary_record)) = temporary {
                require_v2(
                    temporary_record == *target,
                    "current process target is accompanied by a foreign temporary state",
                )?;
                fs::remove_file(temporary_path).map_err(|cause| {
                    rejected_v2(format!(
                        "cannot remove exact duplicate process-pin temporary state: {cause}"
                    ))
                })?;
                sync_directory_v2(
                    self.path
                        .parent()
                        .ok_or_else(|| rejected_v2("process pin path has no parent"))?,
                )?;
                require_v2(
                    !path_exists_no_follow_v2(temporary_path, "reconciled process-pin temporary")?
                        && self.audit_fresh_v2()? == *target,
                    "exact duplicate process-pin temporary cleanup did not persist",
                )?;
            }
            return Ok(());
        }

        require_v2(
            current == *expected,
            "process pin is neither the exact CAS anchor nor its exact target",
        )?;
        let temporary_identity = match temporary {
            Some((identity, record)) => {
                require_v2(
                    record == *target,
                    "process pin CAS temporary state is not the unique expected successor",
                )?;
                identity
            }
            None => {
                let raw = target.encode_exact_v2()?;
                let file = write_new_private_v2(temporary_path, &raw)?;
                drop(file);
                sync_directory_v2(
                    temporary_path
                        .parent()
                        .ok_or_else(|| rejected_v2("process-pin temporary path has no parent"))?,
                )?;
                let identity = existing_file_identity_v2(
                    temporary_path,
                    MAX_PROCESS_RECORD_BYTES_V2,
                    Some(0o600),
                    self.expected_owner,
                )?;
                require_v2(
                    self.temporary_record_v2(temporary_path)? == Some((identity, target.clone())),
                    "process pin CAS target readback differs before rename",
                )?;
                identity
            }
        };
        require_v2(
            self.audit_fresh_v2()? == *expected,
            "process pin changed before atomic rename",
        )?;
        fs::rename(temporary_path, &self.path)
            .map_err(|cause| rejected_v2(format!("process pin atomic rename failed: {cause}")))?;
        sync_directory_v2(
            self.path
                .parent()
                .ok_or_else(|| rejected_v2("process pin path has no parent"))?,
        )?;
        self.identity = existing_file_identity_v2(
            &self.path,
            MAX_PROCESS_RECORD_BYTES_V2,
            Some(0o600),
            self.expected_owner,
        )?;
        require_v2(
            self.identity == temporary_identity && self.audit_fresh_v2()? == *target,
            "process pin target identity or fresh readback differs after CAS",
        )
    }
}

#[derive(Debug)]
struct ProcessLifetimeLockV2 {
    file: File,
    path: PathBuf,
    expected_owner: u32,
    identity: ExistingFileIdentityV2,
    record: ProcessLockRecordV2,
}

impl ProcessLifetimeLockV2 {
    fn initialize_new_v2(
        path: PathBuf,
        expected_owner: u32,
        record: ProcessLockRecordV2,
    ) -> ProcessResultV2<Self> {
        let raw = record.encode_exact_v2()?;
        let file = write_new_private_v2(&path, &raw)?;
        file.try_lock()
            .map_err(|cause| rejected_v2(format!("cannot acquire new process lock: {cause}")))?;
        sync_directory_v2(
            path.parent()
                .ok_or_else(|| rejected_v2("process lock path has no parent"))?,
        )?;
        let identity = existing_file_identity_v2(
            &path,
            MAX_PROCESS_RECORD_BYTES_V2,
            Some(0o600),
            expected_owner,
        )?;
        Ok(Self {
            file,
            path,
            expected_owner,
            identity,
            record,
        })
    }

    fn open_existing_v2(
        path: PathBuf,
        expected_owner: u32,
        expected_record: ProcessLockRecordV2,
    ) -> ProcessResultV2<Self> {
        let preflight = existing_file_identity_v2(
            &path,
            MAX_PROCESS_RECORD_BYTES_V2,
            Some(0o600),
            expected_owner,
        )?;
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .map_err(|cause| rejected_v2(format!("process lock open failed: {cause}")))?;
        file.try_lock().map_err(|cause| {
            rejected_v2(format!(
                "process lock is already held or unavailable: {cause}"
            ))
        })?;
        let mut raw = Vec::new();
        let read_limit = MAX_PROCESS_RECORD_BYTES_V2
            .checked_add(1)
            .ok_or_else(|| rejected_v2("process lock read bound overflows"))?;
        file.seek(SeekFrom::Start(0))
            .and_then(|_| (&mut file).take(read_limit).read_to_end(&mut raw))
            .map_err(|cause| rejected_v2(format!("process lock read failed: {cause}")))?;
        require_v2(
            !raw.is_empty()
                && u64::try_from(raw.len())
                    .is_ok_and(|length| length <= MAX_PROCESS_RECORD_BYTES_V2),
            "process lock record exceeds its hard bound",
        )?;
        let record = ProcessLockRecordV2::decode_exact_v2(&raw)?;
        require_v2(record == expected_record, "process lock record differs")?;
        let identity = existing_file_identity_v2(
            &path,
            MAX_PROCESS_RECORD_BYTES_V2,
            Some(0o600),
            expected_owner,
        )?;
        require_v2(
            identity == preflight,
            "process lock identity changed while acquiring",
        )?;
        Ok(Self {
            file,
            path,
            expected_owner,
            identity,
            record,
        })
    }

    fn revalidate_fresh_v2(&self) -> ProcessResultV2<()> {
        require_open_file_identity_v2(&self.file, self.identity)?;
        require_v2(
            existing_file_identity_v2(
                &self.path,
                MAX_PROCESS_RECORD_BYTES_V2,
                Some(0o600),
                self.expected_owner,
            )? == self.identity
                && ProcessLockRecordV2::decode_exact_v2(&read_bounded_file_v2(
                    &self.path,
                    MAX_PROCESS_RECORD_BYTES_V2,
                    "process lock",
                )?)? == self.record,
            "retained process lock path or record changed",
        )
    }
}

#[derive(Debug)]
struct ExistingSourceStoresV2 {
    da: PocoDaStoreV1,
    agent_market: PocoAgentMarketStoreV1,
    verify_challenge: VerifyChallengeStoreV1,
    mvcc_fee: MvccFeeStoreV1,
    consumption_settlement: ConsumptionSettlementStoreV1,
}

impl ExistingSourceStoresV2 {
    fn open_v2(
        manifest: &PocoNodeG2CandidateProcessManifestV2,
        paths: &ProcessPathsV2,
    ) -> ProcessResultV2<Self> {
        let da_config = DaStoreConfigV1::new(
            paths.da.clone(),
            manifest.da_scope_id,
            manifest.da_store_id,
            manifest.da_committee.clone(),
            manifest.da_policy.clone(),
            manifest.da_local_attestor_id,
        )
        .map_err(|cause| rejected_v2(format!("DA configuration rejected: {cause}")))?;
        let da = PocoDaStoreV1::open_existing(da_config)
            .map_err(|cause| rejected_v2(format!("existing DA store rejected: {cause}")))?;
        let agent_market = PocoAgentMarketStoreV1::open_existing(AgentMarketStoreConfigV1 {
            path: paths.agent_market.clone(),
            store_id: manifest.agent_market_store_id,
            trust_bundle: manifest.agent_market_trust_bundle.clone(),
        })
        .map_err(|cause| rejected_v2(format!("existing Agent/Market store rejected: {cause}")))?;
        let verify_challenge =
            VerifyChallengeStoreV1::open_existing(VerifyChallengeStoreConfigV1 {
                path: paths.verify_challenge.clone(),
                store_id: manifest.verify_challenge_store_id,
                trust_bundle: manifest.verify_challenge_trust_bundle.clone(),
            })
            .map_err(|cause| {
                rejected_v2(format!("existing Verify/Challenge store rejected: {cause}"))
            })?;
        let mvcc_fee = MvccFeeStoreV1::open_existing(
            paths.mvcc_fee.clone(),
            manifest.mvcc_fee_genesis.clone(),
        )
        .map_err(|cause| rejected_v2(format!("existing MVCC/Fee store rejected: {cause}")))?;
        let consumption_settlement =
            ConsumptionSettlementStoreV1::open_existing(ConsumptionSettlementStoreConfigV1 {
                path: paths.consumption_settlement.clone(),
                store_id: manifest.consumption_settlement_store_id,
                trust_bundle: manifest.consumption_settlement_trust_bundle.clone(),
            })
            .map_err(|cause| {
                rejected_v2(format!(
                    "existing Consumption/Settlement store rejected: {cause}"
                ))
            })?;
        Ok(Self {
            da,
            agent_market,
            verify_challenge,
            mvcc_fee,
            consumption_settlement,
        })
    }
}

fn issue_exact_finalize_join_v2(
    manifest: &PocoNodeG2CandidateProcessManifestV2,
    sources: &mut ExistingSourceStoresV2,
    canonical_store: &PocoCanonicalOrderStateStoreV1,
    canonical_pin: &CanonicalOrderStateHeadPinV1,
) -> ProcessResultV2<G2CandidateLocalFinalizeJoinV2> {
    let mut source_set = GlobalExecutionSourcesV1 {
        da: &mut sources.da,
        agent_market: &mut sources.agent_market,
        verify_challenge: &mut sources.verify_challenge,
        mvcc_fee: &mut sources.mvcc_fee,
        consumption_settlement: &mut sources.consumption_settlement,
    };
    let input = ManifestBoundGlobalExecutionInputV2::from_certified_batch_and_fresh_sources_v2(
        manifest.certified_batch.clone(),
        manifest.da_batch_id,
        manifest.da_certificate_id,
        &mut source_set,
    )
    .map_err(|cause| rejected_v2(format!("fresh manifest input issuer rejected: {cause}")))?;
    let preview = input
        .preview_five_plane_inert_v2(&mut source_set)
        .map_err(|cause| rejected_v2(format!("fresh five-source preview rejected: {cause}")))?;
    let (order_input, order_plan, binding) = preview.into_order_material_v2();
    let recovered_parent = canonical_store
        .recover_order_application_parent_v1(canonical_pin)
        .map_err(|cause| {
            rejected_v2(format!("canonical Order parent recovery rejected: {cause}"))
        })?;
    let sealed = canonical_store
        .seal_manifest_bound_g2_from_recovered_parent_v2(
            &recovered_parent,
            manifest.order_template_v2(),
            order_input,
            order_plan,
        )
        .map_err(|cause| rejected_v2(format!("canonical Order G2 seal rejected: {cause}")))?;
    let request = sealed
        .into_finalize_binding_request_v2()
        .map_err(|cause| rejected_v2(format!("Order finalize request rejected: {cause}")))?;
    binding
        .join_finalize_request_v2(request)
        .map_err(|cause| rejected_v2(format!("exact global finalize join rejected: {cause}")))
}

fn open_existing_sources_and_order_v2(
    loaded: &LoadedProcessManifestV2,
) -> ProcessResultV2<(
    ExistingSourceStoresV2,
    PocoCanonicalOrderStateStoreV1,
    CanonicalOrderStateHeadPinV1,
)> {
    loaded.revalidate_static_paths_v2()?;
    let sources = ExistingSourceStoresV2::open_v2(&loaded.manifest, &loaded.paths)?;
    let canonical_pin = loaded.manifest.canonical_pin_v2()?;
    let canonical_store = PocoCanonicalOrderStateStoreV1::open_existing_pinned(
        loaded.paths.canonical_order_state.clone(),
        loaded.manifest.canonical_order_state_store_id,
        &canonical_pin,
    )
    .map_err(|cause| rejected_v2(format!("existing canonical Order store rejected: {cause}")))?;
    loaded.revalidate_static_paths_v2()?;
    Ok((sources, canonical_store, canonical_pin))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PocoNodeG2CandidatePreparedFactsV2 {
    manifest_sha256: [u8; 32],
    process_pin_checksum: [u8; 32],
    t0d_anchor_checksum: [u8; 32],
}

impl PocoNodeG2CandidatePreparedFactsV2 {
    pub fn manifest_sha256_hex_v2(&self) -> String {
        hex_v2(self.manifest_sha256)
    }

    pub fn process_pin_checksum_hex_v2(&self) -> String {
        hex_v2(self.process_pin_checksum)
    }

    pub fn t0d_anchor_checksum_hex_v2(&self) -> String {
        hex_v2(self.t0d_anchor_checksum)
    }
}

fn prepare_durable_prefix_from_paths_v2(
    loaded: &LoadedProcessManifestV2,
    t0d_journal_path: &Path,
) -> ProcessResultV2<PrepareDurablePrefixV2> {
    classify_prepare_durable_prefix_v2(
        path_exists_no_follow_v2(&loaded.paths.process_lock, "process lock")?,
        path_exists_no_follow_v2(t0d_journal_path, "T0-D journal")?,
        path_exists_no_follow_v2(&loaded.paths.process_pin, "process pin")?,
        path_exists_no_follow_v2(&loaded.paths.process_pin_temp, "process-pin temporary")?,
    )
}

/// Reconcile only a durable prefix of the candidate process's anchor state.
/// Every retry first acquires the exact stable lock and then reruns the full
/// existing-source issuer. Only `none -> lock -> T0-D anchor -> process-pin
/// anchor` is accepted; a mutant, reordered prefix, temporary transition, or
/// already-targeted record fails closed.
pub fn prepare_g2_manifest_bound_candidate_process_v2(
    run_root: &Path,
    manifest_path: &Path,
    expected_manifest_sha256: &str,
) -> Result<PocoNodeG2CandidatePreparedFactsV2, PocoNodeG2CandidateProcessErrorV2> {
    let loaded = LoadedProcessManifestV2::load_existing_v2(
        run_root,
        manifest_path,
        expected_manifest_sha256,
    )?;
    let t0d_namespace =
        PocoNodeG2ManifestBoundJournalNamespaceV2::new_v2(loaded.paths.t0d_namespace.clone())
            .map_err(|cause| rejected_v2(format!("T0-D namespace rejected: {cause}")))?;
    let t0d_journal_path = t0d_namespace.journal_path_v2();
    let initial_prefix = prepare_durable_prefix_from_paths_v2(&loaded, &t0d_journal_path)?;
    let lock_record =
        ProcessLockRecordV2::new_v2(loaded.manifest.process_scope, loaded.manifest_sha256)?;
    let lifetime_lock = match initial_prefix {
        PrepareDurablePrefixV2::Empty => ProcessLifetimeLockV2::initialize_new_v2(
            loaded.paths.process_lock.clone(),
            loaded.expected_owner_v2(),
            lock_record,
        )?,
        PrepareDurablePrefixV2::LockOnly
        | PrepareDurablePrefixV2::LockAndT0dAnchor
        | PrepareDurablePrefixV2::CompleteAnchors => ProcessLifetimeLockV2::open_existing_v2(
            loaded.paths.process_lock.clone(),
            loaded.expected_owner_v2(),
            lock_record,
        )?,
    };
    let locked_prefix = prepare_durable_prefix_from_paths_v2(&loaded, &t0d_journal_path)?;
    let expected_locked_prefix = match initial_prefix {
        PrepareDurablePrefixV2::Empty => PrepareDurablePrefixV2::LockOnly,
        existing => existing,
    };
    require_v2(
        locked_prefix == expected_locked_prefix,
        "prepare durable prefix changed while acquiring its stable lock",
    )?;
    lifetime_lock.revalidate_fresh_v2()?;

    let (mut sources, canonical_store, canonical_pin) =
        open_existing_sources_and_order_v2(&loaded)?;
    let prepared_exact_join_commitment = {
        let exact_join = issue_exact_finalize_join_v2(
            &loaded.manifest,
            &mut sources,
            &canonical_store,
            &canonical_pin,
        )?;
        exact_finalize_join_commitment_v2(&exact_join)
            .map_err(|cause| rejected_v2(format!("exact join commitment rejected: {cause}")))?
    };
    loaded.revalidate_static_paths_v2()?;

    let expected_t0d_anchor = PocoNodeG2ManifestBoundCandidateLocalStoreV2::expected_anchor_pin_v2(
        loaded.manifest.t0d_journal_id,
        loaded.manifest.t0d_scope,
    )
    .map_err(|cause| rejected_v2(format!("T0-D anchor derivation rejected: {cause}")))?;
    let t0d_store = match locked_prefix {
        PrepareDurablePrefixV2::LockOnly => {
            let (store, initialized_anchor) =
                PocoNodeG2ManifestBoundCandidateLocalStoreV2::initialize_new_v2(
                    &t0d_namespace,
                    loaded.manifest.t0d_journal_id,
                    loaded.manifest.t0d_scope,
                )
                .map_err(|cause| {
                    rejected_v2(format!("T0-D anchor initialization rejected: {cause}"))
                })?;
            require_v2(
                initialized_anchor == expected_t0d_anchor,
                "initialized T0-D anchor differs from deterministic expectation",
            )?;
            store
        }
        PrepareDurablePrefixV2::LockAndT0dAnchor | PrepareDurablePrefixV2::CompleteAnchors => {
            PocoNodeG2ManifestBoundCandidateLocalStoreV2::open_existing_v2(
                &t0d_namespace,
                &expected_t0d_anchor,
            )
            .map_err(|cause| {
                rejected_v2(format!("existing prepare T0-D anchor rejected: {cause}"))
            })?
        }
        PrepareDurablePrefixV2::Empty => {
            return reject_v2("stable lock acquisition did not advance the empty prepare prefix")
        }
    };
    t0d_store
        .revalidate_fresh_anchor_only_v2()
        .map_err(|cause| rejected_v2(format!("prepare T0-D anchor rejected: {cause}")))?;
    let after_t0d_prefix = prepare_durable_prefix_from_paths_v2(&loaded, &t0d_journal_path)?;
    require_v2(
        after_t0d_prefix
            == if locked_prefix == PrepareDurablePrefixV2::CompleteAnchors {
                PrepareDurablePrefixV2::CompleteAnchors
            } else {
                PrepareDurablePrefixV2::LockAndT0dAnchor
            },
        "prepare prefix differs after exact T0-D anchor reconciliation",
    )?;
    let process_anchor = ProcessPinRecordV2::anchor_v2(
        loaded.manifest.process_scope,
        loaded.manifest_sha256,
        &expected_t0d_anchor,
        prepared_exact_join_commitment,
    )?;
    let (process_pin, durable_process_anchor) = match after_t0d_prefix {
        PrepareDurablePrefixV2::LockAndT0dAnchor => {
            let store = ProcessPinStoreV2::initialize_new_v2(
                loaded.paths.process_pin.clone(),
                loaded.expected_owner_v2(),
                &process_anchor,
            )?;
            (store, process_anchor.clone())
        }
        PrepareDurablePrefixV2::CompleteAnchors => ProcessPinStoreV2::open_existing_v2(
            loaded.paths.process_pin.clone(),
            loaded.expected_owner_v2(),
            process_anchor.checksum,
        )?,
        PrepareDurablePrefixV2::Empty | PrepareDurablePrefixV2::LockOnly => {
            return reject_v2("prepare process pin is not after an exact T0-D anchor")
        }
    };
    require_v2(
        durable_process_anchor == process_anchor
            && durable_process_anchor.body.target.is_none()
            && process_pin.audit_fresh_v2()? == process_anchor
            && prepare_durable_prefix_from_paths_v2(&loaded, &t0d_journal_path)?
                == PrepareDurablePrefixV2::CompleteAnchors,
        "fresh or recovered prepared process anchor differs",
    )?;
    t0d_store
        .revalidate_fresh_anchor_only_v2()
        .map_err(|cause| rejected_v2(format!("final prepare T0-D anchor rejected: {cause}")))?;
    lifetime_lock.revalidate_fresh_v2()?;
    loaded.revalidate_static_paths_v2()?;
    Ok(PocoNodeG2CandidatePreparedFactsV2 {
        manifest_sha256: loaded.manifest_sha256,
        process_pin_checksum: process_anchor.checksum,
        t0d_anchor_checksum: expected_t0d_anchor.checksum_v2(),
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ProcessReadyFactsV2 {
    manifest_sha256: [u8; 32],
    process_pin_checksum: [u8; 32],
    exact_join_commitment: [u8; 32],
    input_id: [u8; 32],
    candidate_height: u64,
    candidate_block_id: [u8; 32],
}

/// Private, non-Clone aggregate retaining all five existing source handles,
/// the canonical Order store, the T0-D exact owner and live journal, the
/// independent process-pin store, and the lifetime OS lock.
#[must_use = "the candidate-only process owner must remain alive while READY"]
struct PocoNodeG2CandidateProcessOwnerV2 {
    loaded: LoadedProcessManifestV2,
    sources: ExistingSourceStoresV2,
    canonical_store: PocoCanonicalOrderStateStoreV1,
    canonical_pin: CanonicalOrderStateHeadPinV1,
    t0d_owner: PocoNodeG2ManifestBoundCandidateLocalOwnerV2,
    process_pin_store: ProcessPinStoreV2,
    process_pin_record: ProcessPinRecordV2,
    lifetime_lock: ProcessLifetimeLockV2,
}

impl PocoNodeG2CandidateProcessOwnerV2 {
    fn revalidate_fresh_before_ready_v2(&mut self) -> ProcessResultV2<ProcessReadyFactsV2> {
        self.lifetime_lock.revalidate_fresh_v2()?;
        self.loaded.revalidate_static_paths_v2()?;
        require_v2(
            self.canonical_store.fresh_head_pin_v1().map_err(|cause| {
                rejected_v2(format!("canonical Order fresh head rejected: {cause}"))
            })? == self.canonical_pin,
            "canonical Order head differs before READY",
        )?;
        self.t0d_owner
            .revalidate_fresh_exact_v2()
            .map_err(|cause| rejected_v2(format!("T0-D owner revalidation rejected: {cause}")))?;
        require_v2(
            self.process_pin_store.audit_fresh_v2()? == self.process_pin_record,
            "independent process pin differs before READY",
        )?;

        let exact_join = issue_exact_finalize_join_v2(
            &self.loaded.manifest,
            &mut self.sources,
            &self.canonical_store,
            &self.canonical_pin,
        )?;
        let exact_join_commitment =
            exact_finalize_join_commitment_v2(&exact_join).map_err(|cause| {
                rejected_v2(format!("fresh exact join commitment rejected: {cause}"))
            })?;
        let t0d_target = self.t0d_owner.journal_pin_v2();
        let expected_target = ProcessTargetV2::from_exact_join_v2(
            self.process_pin_record.anchor_checksum_v2()?,
            &t0d_target,
            &exact_join,
            exact_join_commitment,
            &self.canonical_pin,
        )?;
        require_v2(
            self.process_pin_record.body.target.as_ref() == Some(&expected_target),
            "fresh exact issuer facts differ from the independent process target",
        )?;
        let facts = ProcessReadyFactsV2 {
            manifest_sha256: self.loaded.manifest_sha256,
            process_pin_checksum: self.process_pin_record.checksum,
            exact_join_commitment,
            input_id: *exact_join.input_id().as_bytes(),
            candidate_height: exact_join.candidate_height(),
            candidate_block_id: exact_join.candidate_block_id().to_bytes(),
        };
        self.t0d_owner
            .revalidate_fresh_exact_v2()
            .map_err(|cause| {
                rejected_v2(format!("T0-D post-issuer revalidation rejected: {cause}"))
            })?;
        require_v2(
            self.process_pin_store.audit_fresh_v2()? == self.process_pin_record,
            "independent process pin changed across READY revalidation",
        )?;
        self.loaded.revalidate_static_paths_v2()?;
        self.lifetime_lock.revalidate_fresh_v2()?;
        Ok(facts)
    }
}

fn open_g2_manifest_bound_candidate_process_owner_v2(
    run_root: &Path,
    manifest_path: &Path,
    expected_manifest_sha256: &str,
    expected_process_pin_checksum: &str,
) -> ProcessResultV2<PocoNodeG2CandidateProcessOwnerV2> {
    let loaded = LoadedProcessManifestV2::load_existing_v2(
        run_root,
        manifest_path,
        expected_manifest_sha256,
    )?;
    let lock_record =
        ProcessLockRecordV2::new_v2(loaded.manifest.process_scope, loaded.manifest_sha256)?;
    let lifetime_lock = ProcessLifetimeLockV2::open_existing_v2(
        loaded.paths.process_lock.clone(),
        loaded.expected_owner_v2(),
        lock_record,
    )?;
    let expected_process_pin_checksum = parse_sha256_v2(
        expected_process_pin_checksum,
        "externally retained process-pin checksum",
    )?;
    let (mut process_pin_store, observed_process_pin_record, process_pin_authentication) =
        ProcessPinStoreV2::open_existing_authenticated_v2(
            loaded.paths.process_pin.clone(),
            loaded.expected_owner_v2(),
            expected_process_pin_checksum,
        )?;
    require_v2(
        observed_process_pin_record.body.process_scope == loaded.manifest.process_scope
            && observed_process_pin_record.body.manifest_sha256 == loaded.manifest_sha256,
        "process pin is bound to another scope or manifest",
    )?;
    let expected_t0d_anchor = PocoNodeG2ManifestBoundCandidateLocalStoreV2::expected_anchor_pin_v2(
        loaded.manifest.t0d_journal_id,
        loaded.manifest.t0d_scope,
    )
    .map_err(|cause| rejected_v2(format!("T0-D anchor derivation rejected: {cause}")))?;
    require_v2(
        observed_process_pin_record.body.t0d_anchor
            == T0dJournalPinDataV2::from_pin_v2(&expected_t0d_anchor),
        "process pin T0-D anchor differs from the deterministic manifest anchor",
    )?;
    let trusted_t0d_pin = observed_process_pin_record
        .body
        .target
        .as_ref()
        .map(|target| target.t0d_target.to_pin_v2())
        .transpose()?
        .unwrap_or(expected_t0d_anchor.clone());
    let t0d_namespace =
        PocoNodeG2ManifestBoundJournalNamespaceV2::new_v2(loaded.paths.t0d_namespace.clone())
            .map_err(|cause| rejected_v2(format!("T0-D namespace rejected: {cause}")))?;
    let t0d_store = PocoNodeG2ManifestBoundCandidateLocalStoreV2::open_existing_v2(
        &t0d_namespace,
        &trusted_t0d_pin,
    )
    .map_err(|cause| rejected_v2(format!("existing T0-D journal rejected: {cause}")))?;

    let (mut sources, canonical_store, canonical_pin) =
        open_existing_sources_and_order_v2(&loaded)?;
    let exact_join = issue_exact_finalize_join_v2(
        &loaded.manifest,
        &mut sources,
        &canonical_store,
        &canonical_pin,
    )?;
    let exact_join_commitment = exact_finalize_join_commitment_v2(&exact_join)
        .map_err(|cause| rejected_v2(format!("exact join commitment rejected: {cause}")))?;
    require_v2(
        exact_join_commitment
            == observed_process_pin_record
                .body
                .prepared_exact_join_commitment,
        "fresh exact join differs from the commitment sealed by process prepare",
    )?;
    let input_id = *exact_join.input_id().as_bytes();
    let candidate_height = exact_join.candidate_height();
    let candidate_block_id = exact_join.candidate_block_id().to_bytes();
    let t0d_owner = t0d_store
        .consume_exact_finalize_join_v2(exact_join)
        .map_err(|cause| rejected_v2(format!("T0-D exact join consumption rejected: {cause}")))?;
    let t0d_target = t0d_owner.journal_pin_v2();

    let process_anchor = observed_process_pin_record.anchor_record_v2()?;
    let target = ProcessTargetV2::from_exact_join_facts_v2(
        process_anchor.checksum,
        &t0d_target,
        input_id,
        candidate_height,
        candidate_block_id,
        exact_join_commitment,
        &canonical_pin,
    )?;
    require_v2(
        target.input_id == input_id
            && target.candidate_height == candidate_height
            && target.candidate_block_id == candidate_block_id,
        "process target projection differs from the exact typed join",
    )?;
    let process_successor = process_anchor.successor_v2(target)?;
    require_v2(
        observed_process_pin_record == process_anchor
            || observed_process_pin_record == process_successor,
        "durable process pin is not the byte-exact anchor or unique replayed target",
    )?;
    if process_pin_authentication
        == ExternalProcessPinAuthenticationV2::AnchorOfCurrentUniqueSuccessor
    {
        require_v2(
            observed_process_pin_record == process_successor
                && expected_process_pin_checksum == process_anchor.checksum,
            "old external anchor did not authenticate the exact durable successor",
        )?;
    }
    process_pin_store.advance_or_reconcile_v2(
        &process_anchor,
        &process_successor,
        &loaded.paths.process_pin_temp,
    )?;
    let process_pin_record = process_successor;
    let mut owner = PocoNodeG2CandidateProcessOwnerV2 {
        loaded,
        sources,
        canonical_store,
        canonical_pin,
        t0d_owner,
        process_pin_store,
        process_pin_record,
        lifetime_lock,
    };
    owner.revalidate_fresh_before_ready_v2()?;
    Ok(owner)
}

fn wait_for_control_eof_v2(owner: &mut PocoNodeG2CandidateProcessOwnerV2) -> ProcessResultV2<()> {
    let stdin = io::stdin();
    let mut control = stdin.lock();
    let mut byte = [0_u8; 1];
    loop {
        match control.read(&mut byte) {
            Ok(0) => {
                owner.revalidate_fresh_before_ready_v2()?;
                return Ok(());
            }
            Ok(_) => {
                return reject_v2("candidate-only control channel accepts EOF clean shutdown only")
            }
            Err(cause) if cause.kind() == io::ErrorKind::Interrupted => {}
            Err(cause) => {
                return reject_v2(format!("candidate-only control channel failed: {cause}"))
            }
        }
    }
}

/// Reopen the candidate-only owner, print one machine-readable `READY` line
/// only after complete fresh revalidation, then retain every owner and the
/// exclusive lifetime lock until control-stdin EOF requests a clean shutdown.
/// This is the sole normal-build entry used by the explicit candidate command
/// in `main.rs`.
pub fn run_g2_manifest_bound_candidate_process_v2(
    run_root: &Path,
    manifest_path: &Path,
    expected_manifest_sha256: &str,
    expected_process_pin_checksum: &str,
) -> Result<(), PocoNodeG2CandidateProcessErrorV2> {
    let mut owner = open_g2_manifest_bound_candidate_process_owner_v2(
        run_root,
        manifest_path,
        expected_manifest_sha256,
        expected_process_pin_checksum,
    )?;
    let facts = owner.revalidate_fresh_before_ready_v2()?;
    {
        let stdout = io::stdout();
        let mut output = stdout.lock();
        writeln!(
            output,
            "READY candidate_only=true pid={} manifest_sha256={} process_pin_checksum={} exact_join_commitment={} input_id={} candidate_height={} candidate_block_id={} network=false signing=false voting=false core=false production=false",
            std::process::id(),
            hex_v2(facts.manifest_sha256),
            hex_v2(facts.process_pin_checksum),
            hex_v2(facts.exact_join_commitment),
            hex_v2(facts.input_id),
            facts.candidate_height,
            hex_v2(facts.candidate_block_id),
        )
        .and_then(|()| output.flush())
        .map_err(|cause| rejected_v2(format!("cannot emit READY line: {cause}")))?;
    }
    wait_for_control_eof_v2(&mut owner)
}

#[cfg(all(test, unix))]
mod tests {
    use std::{
        fs,
        os::unix::fs::{symlink, MetadataExt},
    };

    use tempfile::TempDir;

    use super::*;

    fn private_root_v2() -> TempDir {
        let root = tempfile::tempdir().expect("create private process test root");
        fs::set_permissions(
            root.path(),
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .expect("set private process test root mode");
        root
    }

    fn owner_v2(root: &TempDir) -> u32 {
        fs::metadata(root.path())
            .expect("read process test root metadata")
            .uid()
    }

    fn valid_process_pin_pair_v2() -> (ProcessPinRecordV2, ProcessPinRecordV2) {
        let scope = [1_u8; 32];
        let journal_id = [2_u8; 32];
        let t0d_anchor = PocoNodeG2ManifestBoundJournalPinV2::from_external_trusted_parts_v2(
            journal_id,
            scope,
            0,
            PocoNodeG2ManifestBoundJournalPhaseV2::Anchor,
            [3_u8; 32],
        )
        .expect("construct test T0-D anchor");
        let anchor = ProcessPinRecordV2::anchor_v2(scope, [4_u8; 32], &t0d_anchor, [5_u8; 32])
            .expect("construct test process anchor");
        let t0d_target = PocoNodeG2ManifestBoundJournalPinV2::from_external_trusted_parts_v2(
            journal_id,
            scope,
            1,
            PocoNodeG2ManifestBoundJournalPhaseV2::Persisted,
            [6_u8; 32],
        )
        .expect("construct test T0-D target");
        let target = ProcessTargetV2 {
            predecessor_process_checksum: anchor.checksum,
            t0d_target: T0dJournalPinDataV2::from_pin_v2(&t0d_target),
            exact_join_commitment: anchor.body.prepared_exact_join_commitment,
            input_id: [7_u8; 32],
            candidate_height: 12,
            candidate_block_id: [8_u8; 32],
            canonical_store_id: [9_u8; 32],
            canonical_height: 11,
            canonical_block_id: [10_u8; 32],
            canonical_state_root: [11_u8; 32],
            canonical_history_checksum: [12_u8; 32],
        };
        let successor = anchor
            .successor_v2(target)
            .expect("construct unique test process successor");
        (anchor, successor)
    }

    fn require_mutant_rejected_v2(mutator: impl FnOnce(&mut ProcessPinBodyV2)) {
        let (_anchor, successor) = valid_process_pin_pair_v2();
        let mut body = successor.body;
        mutator(&mut body);
        assert!(ProcessPinRecordV2::from_body_v2(body).is_err());
    }

    #[test]
    fn prepare_accepts_only_exact_durable_prefixes_v2() {
        assert_eq!(
            classify_prepare_durable_prefix_v2(false, false, false, false).expect("empty prefix"),
            PrepareDurablePrefixV2::Empty
        );
        assert_eq!(
            classify_prepare_durable_prefix_v2(true, false, false, false).expect("lock prefix"),
            PrepareDurablePrefixV2::LockOnly
        );
        assert_eq!(
            classify_prepare_durable_prefix_v2(true, true, false, false).expect("T0-D prefix"),
            PrepareDurablePrefixV2::LockAndT0dAnchor
        );
        assert_eq!(
            classify_prepare_durable_prefix_v2(true, true, true, false).expect("complete prefix"),
            PrepareDurablePrefixV2::CompleteAnchors
        );
        for invalid in [
            (false, true, false, false),
            (false, false, true, false),
            (true, false, true, false),
            (false, true, true, false),
            (true, true, true, true),
        ] {
            assert!(
                classify_prepare_durable_prefix_v2(invalid.0, invalid.1, invalid.2, invalid.3)
                    .is_err(),
                "invalid prepare prefix was accepted: {invalid:?}"
            );
        }
    }

    #[test]
    fn process_target_schema_binds_t0d_anchor_and_canonical_successor_v2() {
        let (_anchor, successor) = valid_process_pin_pair_v2();
        successor.validate_v2().expect("valid target schema");

        require_mutant_rejected_v2(|body| {
            body.target.as_mut().expect("target").t0d_target.journal_id = [20_u8; 32];
        });
        require_mutant_rejected_v2(|body| {
            body.target.as_mut().expect("target").t0d_target.scope = [21_u8; 32];
        });
        require_mutant_rejected_v2(|body| {
            body.target.as_mut().expect("target").t0d_target.generation = 2;
        });
        require_mutant_rejected_v2(|body| {
            let target = body.target.as_mut().expect("target");
            target.t0d_target.generation = 0;
            target.t0d_target.phase = 0;
        });
        require_mutant_rejected_v2(|body| {
            let anchor_checksum = body.t0d_anchor.checksum;
            body.target.as_mut().expect("target").t0d_target.checksum = anchor_checksum;
        });
        require_mutant_rejected_v2(|body| {
            body.target
                .as_mut()
                .expect("target")
                .predecessor_process_checksum = [22_u8; 32];
        });
        require_mutant_rejected_v2(|body| {
            body.target.as_mut().expect("target").candidate_height += 1;
        });
    }

    #[test]
    fn exact_temporary_successor_finishes_cas_and_duplicate_is_cleaned_v2() {
        let root = private_root_v2();
        let owner = owner_v2(&root);
        let pin_path = root.path().join("pin.bin");
        let temporary_path = root.path().join("pin.tmp");
        let (anchor, target) = valid_process_pin_pair_v2();
        let mut store = ProcessPinStoreV2::initialize_new_v2(pin_path.clone(), owner, &anchor)
            .expect("initialize process anchor");

        let temporary = write_new_private_v2(
            &temporary_path,
            &target.encode_exact_v2().expect("encode target"),
        )
        .expect("persist exact temporary target");
        drop(temporary);
        sync_directory_v2(root.path()).expect("persist exact temporary directory entry");
        store
            .advance_or_reconcile_v2(&anchor, &target, &temporary_path)
            .expect("finish exact temporary successor");
        assert_eq!(store.audit_fresh_v2().expect("audit target"), target);
        assert!(!temporary_path.exists());

        let duplicate = write_new_private_v2(
            &temporary_path,
            &target.encode_exact_v2().expect("encode duplicate target"),
        )
        .expect("persist exact duplicate temporary target");
        drop(duplicate);
        sync_directory_v2(root.path()).expect("persist duplicate directory entry");
        store
            .advance_or_reconcile_v2(&anchor, &target, &temporary_path)
            .expect("clean exact duplicate temporary target");
        assert_eq!(store.audit_fresh_v2().expect("reaudit target"), target);
        assert!(!temporary_path.exists());
    }

    #[test]
    fn malformed_temporary_state_fails_without_advancing_anchor_v2() {
        let root = private_root_v2();
        let owner = owner_v2(&root);
        let pin_path = root.path().join("pin.bin");
        let temporary_path = root.path().join("pin.tmp");
        let (anchor, target) = valid_process_pin_pair_v2();
        let mut store = ProcessPinStoreV2::initialize_new_v2(pin_path, owner, &anchor)
            .expect("initialize process anchor");
        let temporary = write_new_private_v2(&temporary_path, b"not-an-exact-process-target")
            .expect("persist malformed temporary state");
        drop(temporary);
        sync_directory_v2(root.path()).expect("persist malformed temporary entry");
        assert!(store
            .advance_or_reconcile_v2(&anchor, &target, &temporary_path)
            .is_err());
        assert_eq!(store.audit_fresh_v2().expect("anchor remains"), anchor);
        assert!(temporary_path.exists());
    }

    #[test]
    fn old_anchor_authenticates_only_the_current_unique_successor_v2() {
        let root = private_root_v2();
        let owner = owner_v2(&root);
        let pin_path = root.path().join("pin.bin");
        let temporary_path = root.path().join("pin.tmp");
        let (anchor, target) = valid_process_pin_pair_v2();
        let mut store = ProcessPinStoreV2::initialize_new_v2(pin_path.clone(), owner, &anchor)
            .expect("initialize process anchor");
        store
            .advance_or_reconcile_v2(&anchor, &target, &temporary_path)
            .expect("advance process target");
        drop(store);

        let (_store, observed, authentication) = ProcessPinStoreV2::open_existing_authenticated_v2(
            pin_path.clone(),
            owner,
            anchor.checksum,
        )
        .expect("old anchor authenticates target response loss");
        assert_eq!(observed, target);
        assert_eq!(
            authentication,
            ExternalProcessPinAuthenticationV2::AnchorOfCurrentUniqueSuccessor
        );
        assert!(
            ProcessPinStoreV2::open_existing_authenticated_v2(pin_path, owner, [99_u8; 32])
                .is_err()
        );
    }

    #[test]
    fn duplicate_lifetime_lock_and_symlink_pin_fail_closed_v2() {
        let root = private_root_v2();
        let owner = owner_v2(&root);
        let lock_path = root.path().join("process.lock");
        let lock_record =
            ProcessLockRecordV2::new_v2([31_u8; 32], [32_u8; 32]).expect("construct lock record");
        let held =
            ProcessLifetimeLockV2::initialize_new_v2(lock_path.clone(), owner, lock_record.clone())
                .expect("hold first process lock");
        assert!(ProcessLifetimeLockV2::open_existing_v2(
            lock_path.clone(),
            owner,
            lock_record.clone()
        )
        .is_err());
        drop(held);
        drop(
            ProcessLifetimeLockV2::open_existing_v2(lock_path, owner, lock_record)
                .expect("reopen released exact lock"),
        );

        let (anchor, _target) = valid_process_pin_pair_v2();
        let direct_pin = root.path().join("direct-pin.bin");
        drop(
            ProcessPinStoreV2::initialize_new_v2(direct_pin.clone(), owner, &anchor)
                .expect("create direct process pin"),
        );
        let symlink_pin = root.path().join("symlink-pin.bin");
        symlink(&direct_pin, &symlink_pin).expect("create process pin symlink");
        assert!(ProcessPinStoreV2::open_existing_v2(symlink_pin, owner, anchor.checksum).is_err());
    }

    #[test]
    fn externally_observed_target_rejects_process_pin_rollback_v2() {
        let root = private_root_v2();
        let owner = owner_v2(&root);
        let pin_path = root.path().join("pin.bin");
        let temporary_path = root.path().join("pin.tmp");
        let (anchor, target) = valid_process_pin_pair_v2();
        let mut store = ProcessPinStoreV2::initialize_new_v2(pin_path.clone(), owner, &anchor)
            .expect("initialize process anchor");
        store
            .advance_or_reconcile_v2(&anchor, &target, &temporary_path)
            .expect("advance process target");
        drop(store);
        fs::write(
            &pin_path,
            anchor.encode_exact_v2().expect("encode rolled-back anchor"),
        )
        .expect("simulate process-pin rollback");
        assert!(ProcessPinStoreV2::open_existing_authenticated_v2(
            pin_path,
            owner,
            target.checksum
        )
        .is_err());
    }
}
