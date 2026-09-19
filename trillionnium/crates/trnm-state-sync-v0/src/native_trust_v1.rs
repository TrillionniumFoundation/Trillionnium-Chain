//! Native PoCO trust path. Peers supply bytes and target claims; an independently
//! pinned positive-height checkpoint supplies trust. The native epoch-zero case
//! is deliberately separate from the unchanged generic weak-subjectivity API.

use crate::{
    CheckpointLinkV0, Digest32V0, SnapshotChunkV0, SnapshotManifestV0, StateRootRecomputerV0,
    StateSyncErrorV0, StateSyncHostErrorV0, StateSyncSessionV0, VerifiedSnapshotV0,
    VerifiedTrustPathV0, WeakSubjectivityAnchorV0, MAX_TRUST_PATH_LINKS_V0,
};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension, TransactionBehavior};
use sha2::{Digest, Sha256};
use std::{error::Error, fmt, path::PathBuf};
use trnm_consensus_crypto::{
    decode_verify_epoch_first_finality_strict_v1, decode_verify_finality_proof_strict_v0,
    validate_validator_set_strict_ed25519_v0, FinalityExpectationV0, StrictFinalityErrorV0,
    POCO_THREE_CHAIN_PROOF_CLASS_V0,
};
use trnm_consensus_types::{
    decode_block_header_v0_exact, decode_consensus_parameters_v0_exact,
    decode_validator_set_v0_exact, BlockHeader, Cev0AdmissionBudgetV0, ConsensusParametersV0,
    DecodeError, EpochActivationEvidencePreimagesV0, ValidationError, ValidatorSet,
};

/// Local admission ceilings; these allocate no consensus wire identifiers.
pub const MAX_NATIVE_ANCHOR_BYTES_V1: usize = 4 * 1024 * 1024;
pub const MAX_NATIVE_TRUST_PATH_BYTES_V1: usize = 64 * 1024 * 1024;

/// Compute the exact configured anchor pin. Obtaining this digest from the same
/// peer that supplies the bytes establishes no trust. Operators must provision
/// it independently, including their checkpoint freshness policy.
pub fn native_trust_anchor_pin_v1(
    header: &[u8],
    set: &[u8],
    parameters: &[u8],
) -> Result<Digest32V0, NativeTrustErrorV1> {
    checked_size(&[header, set, parameters], MAX_NATIVE_ANCHOR_BYTES_V1)?;
    Ok(Digest32V0::hash(
        b"trnm.state-sync.native-anchor.v1",
        &[header, set, parameters],
    ))
}

#[derive(Debug)]
pub struct NativeTrustAnchorV1 {
    header: BlockHeader,
    set: ValidatorSet,
    parameters: ConsensusParametersV0,
    pin: Digest32V0,
}

impl NativeTrustAnchorV1 {
    /// Admits an explicit trust root, not a peer-derived proof of this root.
    /// Canonical decoders reject trailing bytes; all keys receive strict checks.
    pub fn from_pinned_bytes(
        header: &[u8],
        set: &[u8],
        parameters: &[u8],
        independently_configured_pin: Digest32V0,
    ) -> Result<Self, NativeTrustErrorV1> {
        let pin = native_trust_anchor_pin_v1(header, set, parameters)?;
        if independently_configured_pin == Digest32V0([0; 32])
            || pin != independently_configured_pin
        {
            return Err(NativeTrustErrorV1::AnchorPinMismatch);
        }
        let header = decode_block_header_v0_exact(header).map_err(NativeTrustErrorV1::Decode)?;
        let set = decode_validator_set_v0_exact(set).map_err(NativeTrustErrorV1::Decode)?;
        let parameters =
            decode_consensus_parameters_v0_exact(parameters).map_err(NativeTrustErrorV1::Decode)?;
        set.validate_against_parameters(&parameters)
            .map_err(NativeTrustErrorV1::Consensus)?;
        validate_validator_set_strict_ed25519_v0(&set).map_err(NativeTrustErrorV1::Consensus)?;
        if header.height().get() == 0
            || header.state_root().as_bytes() == &[0; 32]
            || !matches_context(&header, &set, &parameters)
        {
            return Err(NativeTrustErrorV1::AnchorContextMismatch);
        }
        Ok(Self {
            header,
            set,
            parameters,
            pin,
        })
    }
    pub fn header(&self) -> &BlockHeader {
        &self.header
    }
    pub fn validator_set(&self) -> &ValidatorSet {
        &self.set
    }
    pub fn parameters(&self) -> &ConsensusParametersV0 {
        &self.parameters
    }
    pub fn pin(&self) -> Digest32V0 {
        self.pin
    }
}

/// An untrusted step; `expected` is a checked target claim, never authority.
/// Ordinary proofs must extend the current header by one. Epoch steps carry
/// all eight evidence preimages and join the current application checkpoint
/// through its two old-epoch seal blocks to the first new block (height + 3).
#[derive(Clone, Copy)]
pub enum NativeTrustStepV1<'a> {
    Ordinary {
        proof: &'a [u8],
        expected: FinalityExpectationV0,
    },
    EpochFirst {
        evidence: EpochActivationEvidencePreimagesV0<'a>,
        proof: &'a [u8],
        expected: FinalityExpectationV0,
    },
}

#[derive(Clone, Copy, Debug)]
pub struct NativeTrustPathLimitsV1 {
    pub maximum_links: usize,
    pub maximum_total_bytes: usize,
}
impl Default for NativeTrustPathLimitsV1 {
    fn default() -> Self {
        Self {
            maximum_links: MAX_TRUST_PATH_LINKS_V0,
            maximum_total_bytes: MAX_NATIVE_TRUST_PATH_BYTES_V1,
        }
    }
}

/// Only successful strict signature, exact-parent and complete epoch evidence
/// verification can issue this result. The projection allows the existing
/// non-destructive snapshot session to consume the same authenticated target.
///
/// ```compile_fail
/// use trnm_state_sync_v0::VerifiedNativeTrustPathV1;
/// let forged = VerifiedNativeTrustPathV1 {};
/// ```
#[derive(Clone, Debug)]
pub struct VerifiedNativeTrustPathV1 {
    header: BlockHeader,
    set: ValidatorSet,
    parameters: ConsensusParametersV0,
    projection: VerifiedTrustPathV0,
}
impl VerifiedNativeTrustPathV1 {
    pub fn terminal_header(&self) -> &BlockHeader {
        &self.header
    }
    pub fn terminal_validator_set(&self) -> &ValidatorSet {
        &self.set
    }
    pub fn terminal_parameters(&self) -> &ConsensusParametersV0 {
        &self.parameters
    }
    pub fn snapshot_trust_path(&self) -> &VerifiedTrustPathV0 {
        &self.projection
    }
    pub fn into_snapshot_trust_path(self) -> VerifiedTrustPathV0 {
        self.projection
    }
}

#[derive(Debug)]
pub enum NativeTrustErrorV1 {
    Bounds,
    AnchorPinMismatch,
    AnchorContextMismatch,
    DisconnectedStep,
    Decode(DecodeError),
    Consensus(ValidationError),
    Finality(StrictFinalityErrorV0),
}
impl fmt::Display for NativeTrustErrorV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bounds => f.write_str("native trust path exceeds its admission bounds"),
            Self::AnchorPinMismatch => {
                f.write_str("native anchor does not match independently configured pin")
            }
            Self::AnchorContextMismatch => f.write_str("native anchor header/context mismatch"),
            Self::DisconnectedStep => {
                f.write_str("native proof does not extend the authenticated current head")
            }
            Self::Decode(e) => write!(f, "native canonical decoding: {e}"),
            Self::Consensus(e) => write!(f, "native context: {e}"),
            Self::Finality(e) => write!(f, "native strict finality: {e}"),
        }
    }
}
impl Error for NativeTrustErrorV1 {}

fn checked_size(parts: &[&[u8]], maximum: usize) -> Result<usize, NativeTrustErrorV1> {
    let size = parts
        .iter()
        .try_fold(0usize, |sum, bytes| {
            if bytes.is_empty() {
                None
            } else {
                sum.checked_add(bytes.len())
            }
        })
        .ok_or(NativeTrustErrorV1::Bounds)?;
    if size > maximum {
        return Err(NativeTrustErrorV1::Bounds);
    }
    Ok(size)
}
fn evidence_parts(e: EpochActivationEvidencePreimagesV0<'_>) -> [&[u8]; 8] {
    [
        e.old_checkpoint_finality,
        e.next_epoch_commitment,
        e.authorization_kernel,
        e.old_validator_set,
        e.old_consensus_parameters,
        e.new_validator_set,
        e.new_consensus_parameters,
        e.authenticated_checkpoint_parent_header,
    ]
}
fn step_digest(step: NativeTrustStepV1<'_>) -> Result<(usize, Digest32V0), NativeTrustErrorV1> {
    let mut parts = Vec::with_capacity(9);
    let domain: &[u8] = match step {
        NativeTrustStepV1::Ordinary { proof, .. } => {
            parts.push(proof);
            b"trnm.state-sync.native-ordinary-proof.v1"
        }
        NativeTrustStepV1::EpochFirst {
            evidence, proof, ..
        } => {
            parts.extend(evidence_parts(evidence));
            parts.push(proof);
            b"trnm.state-sync.native-epoch-proof.v1"
        }
    };
    let size = checked_size(&parts, MAX_NATIVE_TRUST_PATH_BYTES_V1)?;
    Ok((size, Digest32V0::hash(domain, &parts)))
}
fn matches_context(
    header: &BlockHeader,
    set: &ValidatorSet,
    params: &ConsensusParametersV0,
) -> bool {
    header.genesis_hash() == set.genesis_hash()
        && header.chain_id() == set.chain_id()
        && header.protocol_version() == set.protocol_version()
        && header.epoch() == set.epoch()
        && header.validator_set_id() == set.id()
        && header.consensus_parameters_hash() == params.hash()
}

/// All bytes/link counts are bounded before signature work. The caller supplies
/// one mutable CEV0 work budget across the complete path; failures never refund
/// work. No parser fallback, peer-selected trust set, clock freshness assertion,
/// application installation or signer activation is performed by this API.
pub fn verify_native_trust_path_v1(
    anchor: &NativeTrustAnchorV1,
    steps: &[NativeTrustStepV1<'_>],
    limits: NativeTrustPathLimitsV1,
    budget: &mut Cev0AdmissionBudgetV0,
) -> Result<VerifiedNativeTrustPathV1, NativeTrustErrorV1> {
    if steps.is_empty() || steps.len() > limits.maximum_links.min(MAX_TRUST_PATH_LINKS_V0) {
        return Err(NativeTrustErrorV1::Bounds);
    }
    let mut total = 0usize;
    let mut digests = Vec::with_capacity(steps.len());
    for step in steps {
        let (size, digest) = step_digest(*step)?;
        total = total.checked_add(size).ok_or(NativeTrustErrorV1::Bounds)?;
        if total
            > limits
                .maximum_total_bytes
                .min(MAX_NATIVE_TRUST_PATH_BYTES_V1)
        {
            return Err(NativeTrustErrorV1::Bounds);
        }
        digests.push(digest);
    }
    let chain = Digest32V0::hash(
        b"trnm.state-sync.native-chain.v1",
        &[
            anchor.header.genesis_hash().as_bytes(),
            anchor.header.chain_id().as_bytes(),
        ],
    );
    let protocol = Digest32V0::hash(
        b"trnm.state-sync.native-protocol.v1",
        &[&anchor.header.protocol_version().get().to_be_bytes()],
    );
    let projected_anchor = WeakSubjectivityAnchorV0 {
        chain_id: chain,
        protocol_digest: protocol,
        epoch: anchor.header.epoch().get(),
        height: anchor.header.height().get(),
        checkpoint_digest: anchor.pin,
        validator_set_digest: Digest32V0(*anchor.set.id().as_bytes()),
    };
    let mut header = anchor.header.clone();
    let mut set = anchor.set.clone();
    let mut parameters = anchor.parameters;
    let mut previous_digest = anchor.pin;
    let mut terminal = None;
    let mut hasher = Sha256::new();
    hasher.update(b"trnm.state-sync.trust-path.v0");
    hasher.update(anchor.pin.0);
    for (step, digest) in steps.iter().zip(digests) {
        let old_set_id = set.id();
        let old_epoch = header.epoch();
        let old_height = header.height();
        match *step {
            NativeTrustStepV1::Ordinary { proof, expected } => {
                if expected.parent_id != header.id()
                    || expected.parent_height != header.height()
                    || expected.parent_timestamp_ms != header.timestamp_ms()
                    || old_height.get().checked_add(1) != Some(expected.height.get())
                {
                    return Err(NativeTrustErrorV1::DisconnectedStep);
                }
                let verified = decode_verify_finality_proof_strict_v0(
                    POCO_THREE_CHAIN_PROOF_CLASS_V0,
                    proof,
                    &set,
                    &parameters,
                    expected,
                    budget,
                )
                .map_err(NativeTrustErrorV1::Finality)?;
                header = verified.proof().finalized_block().header().clone();
                if header.epoch() != old_epoch {
                    return Err(NativeTrustErrorV1::DisconnectedStep);
                }
            }
            NativeTrustStepV1::EpochFirst {
                evidence,
                proof,
                expected,
            } => {
                if old_height.get().checked_add(3) != Some(expected.height.get()) {
                    return Err(NativeTrustErrorV1::DisconnectedStep);
                }
                let verified = decode_verify_epoch_first_finality_strict_v1(
                    evidence,
                    proof,
                    &set,
                    &parameters,
                    expected,
                    budget,
                )
                .map_err(NativeTrustErrorV1::Finality)?;
                if verified.checkpoint_header() != &header
                    || old_epoch.get().checked_add(1)
                        != Some(verified.new_validator_set().epoch().get())
                {
                    return Err(NativeTrustErrorV1::DisconnectedStep);
                }
                header = verified.proof().finalized_block().header().clone();
                set = verified.new_validator_set().clone();
                parameters = *verified.new_consensus_parameters();
            }
        }
        if !matches_context(&header, &set, &parameters)
            || header.genesis_hash() != anchor.header.genesis_hash()
            || header.chain_id() != anchor.header.chain_id()
            || header.protocol_version() != anchor.header.protocol_version()
            || header.state_root().as_bytes() == &[0; 32]
        {
            return Err(NativeTrustErrorV1::DisconnectedStep);
        }
        let mut link = CheckpointLinkV0 {
            chain_id: chain,
            protocol_digest: protocol,
            epoch: header.epoch().get(),
            height: header.height().get(),
            state_root: Digest32V0(*header.state_root().as_bytes()),
            validator_set_digest: Digest32V0(*old_set_id.as_bytes()),
            next_validator_set_digest: Digest32V0(*set.id().as_bytes()),
            parent_checkpoint_digest: previous_digest,
            finality_proof_digest: digest,
            checkpoint_digest: Digest32V0([0; 32]),
        };
        link.checkpoint_digest = link.canonical_digest();
        previous_digest = link.checkpoint_digest;
        hasher.update(link.checkpoint_digest.0);
        terminal = Some(link);
    }
    Ok(VerifiedNativeTrustPathV1 {
        header,
        set,
        parameters,
        projection: VerifiedTrustPathV0 {
            anchor: projected_anchor,
            terminal: terminal.ok_or(NativeTrustErrorV1::Bounds)?,
            link_count: steps.len() as u32,
            path_digest: Digest32V0(hasher.finalize().into()),
        },
    })
}

/// Application-facing checkpoint facts that must travel with a native trust
/// path. `application_version` is an M07-owned monotonic version retained in
/// this binding so a peer cannot replay a session under another schema/version.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeApplicationCheckpointV1 {
    pub schema_digest: Digest32V0,
    pub application_version: u64,
}

/// Immutable identity of a native state-sync session. It binds the exact
/// verified proof path, terminal block/checkpoint, manifest and application
/// schema/version. The digest is the persistence adapter's session foreign key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeStateSyncBindingV1 {
    pub trust_path_digest: Digest32V0,
    pub terminal_block_digest: Digest32V0,
    pub checkpoint_digest: Digest32V0,
    pub manifest_digest: Digest32V0,
    pub height: u64,
    pub epoch: u64,
    pub state_root: Digest32V0,
    pub schema_digest: Digest32V0,
    pub application_version: u64,
    pub binding_digest: Digest32V0,
}

impl NativeStateSyncBindingV1 {
    fn from_path_manifest(
        path: &VerifiedNativeTrustPathV1,
        manifest: &SnapshotManifestV0,
        application: NativeApplicationCheckpointV1,
    ) -> Result<Self, StateSyncErrorV0> {
        manifest.validate(path.snapshot_trust_path())?;
        if application.schema_digest == Digest32V0([0; 32]) || application.application_version == 0
        {
            return Err(StateSyncErrorV0::NativeApplicationBindingMismatch);
        }
        let terminal = path.terminal_header();
        let trust = path.snapshot_trust_path();
        if manifest.height != terminal.height().get()
            || manifest.epoch != terminal.epoch().get()
            || manifest.state_root != Digest32V0(*terminal.state_root().as_bytes())
            || manifest.checkpoint_digest != trust.terminal().checkpoint_digest
        {
            return Err(StateSyncErrorV0::NativeApplicationBindingMismatch);
        }
        let terminal_block_digest = Digest32V0(*terminal.id().as_bytes());
        let mut binding = Self {
            trust_path_digest: trust.path_digest(),
            terminal_block_digest,
            checkpoint_digest: manifest.checkpoint_digest,
            manifest_digest: manifest.manifest_digest,
            height: manifest.height,
            epoch: manifest.epoch,
            state_root: manifest.state_root,
            schema_digest: application.schema_digest,
            application_version: application.application_version,
            binding_digest: Digest32V0([0; 32]),
        };
        binding.binding_digest = binding.canonical_digest();
        Ok(binding)
    }

    #[must_use]
    pub fn canonical_digest(&self) -> Digest32V0 {
        Digest32V0::hash(
            b"trnm.state-sync.native-session-binding.v1",
            &[
                &self.trust_path_digest.0,
                &self.terminal_block_digest.0,
                &self.checkpoint_digest.0,
                &self.manifest_digest.0,
                &self.height.to_be_bytes(),
                &self.epoch.to_be_bytes(),
                &self.state_root.0,
                &self.schema_digest.0,
                &self.application_version.to_be_bytes(),
            ],
        )
    }
}

/// The minimal durable readback required before resuming a download. A bitmap
/// without the content-derived `progress_digest` is insufficient: restart must
/// revalidate every retained chunk under the same manifest.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeStateSyncReadbackV1 {
    pub binding_digest: Digest32V0,
    pub manifest_digest: Digest32V0,
    pub received_chunk_count: u32,
    pub received_bytes: u64,
    pub progress_digest: Digest32V0,
}

const NATIVE_SYNC_STORE_APP_ID_V1: i64 = 0x5453_594e;
const NATIVE_SYNC_STORE_USER_VERSION_V1: i64 = 1;
const NATIVE_SYNC_META_SQL_V1: &str = "CREATE TABLE native_state_sync_meta_v1 (singleton INTEGER PRIMARY KEY CHECK(singleton=1), binding_digest BLOB NOT NULL CHECK(length(binding_digest)=32), trust_path_digest BLOB NOT NULL CHECK(length(trust_path_digest)=32), terminal_block_digest BLOB NOT NULL CHECK(length(terminal_block_digest)=32), checkpoint_digest BLOB NOT NULL CHECK(length(checkpoint_digest)=32), manifest_digest BLOB NOT NULL CHECK(length(manifest_digest)=32), manifest_binding_digest BLOB NOT NULL CHECK(length(manifest_binding_digest)=32), height INTEGER NOT NULL CHECK(height>0), epoch INTEGER NOT NULL CHECK(epoch>=0), state_root BLOB NOT NULL CHECK(length(state_root)=32), schema_digest BLOB NOT NULL CHECK(length(schema_digest)=32), application_version INTEGER NOT NULL CHECK(application_version>0), received_chunk_count INTEGER NOT NULL CHECK(received_chunk_count>=0), received_bytes INTEGER NOT NULL CHECK(received_bytes>=0), progress_digest BLOB NOT NULL CHECK(length(progress_digest)=32)) STRICT";
const NATIVE_SYNC_CHUNKS_SQL_V1: &str = "CREATE TABLE native_state_sync_chunks_v1 (chunk_index INTEGER PRIMARY KEY CHECK(chunk_index>=0), manifest_digest BLOB NOT NULL CHECK(length(manifest_digest)=32), bytes BLOB NOT NULL, chunk_digest BLOB NOT NULL CHECK(length(chunk_digest)=32)) WITHOUT ROWID";

/// Errors from the candidate durable native state-sync adapter.  A SQLite
/// success is not treated as a trusted source: every reopen revalidates the
/// closed-world metadata, chunk digests and caller-supplied verified path.
#[derive(Debug)]
pub enum NativeStateSyncStoreErrorV1 {
    Protocol(StateSyncErrorV0),
    Sqlite(String),
    Io(String),
    StoreAlreadyInitialized,
    StoreSchemaMismatch,
    BindingMismatch,
    DurableReadbackMismatch,
}

impl fmt::Display for NativeStateSyncStoreErrorV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Protocol(error) => {
                write!(f, "native state-sync protocol rejected input: {error}")
            }
            Self::Sqlite(error) => write!(f, "native state-sync sqlite failure: {error}"),
            Self::Io(error) => write!(f, "native state-sync filesystem failure: {error}"),
            Self::StoreAlreadyInitialized => f.write_str("native state-sync store already exists"),
            Self::StoreSchemaMismatch => f.write_str("native state-sync store schema mismatch"),
            Self::BindingMismatch => f.write_str("native state-sync durable binding mismatch"),
            Self::DurableReadbackMismatch => {
                f.write_str("native state-sync durable readback mismatch")
            }
        }
    }
}

impl Error for NativeStateSyncStoreErrorV1 {}

/// Native proof-bound download session. This composes the existing bounded
/// chunk session; it does not choose peers, issue anchors, or perform a
/// production install. Restart requires the same independently verified path,
/// exact manifest, application schema/version and every retained chunk.
#[derive(Clone)]
pub struct NativeStateSyncSessionV1 {
    binding: NativeStateSyncBindingV1,
    session: StateSyncSessionV0,
}

impl NativeStateSyncSessionV1 {
    pub fn begin(
        path: VerifiedNativeTrustPathV1,
        manifest: SnapshotManifestV0,
        application: NativeApplicationCheckpointV1,
    ) -> Result<Self, StateSyncErrorV0> {
        let binding = NativeStateSyncBindingV1::from_path_manifest(&path, &manifest, application)?;
        let session = StateSyncSessionV0::new(path.into_snapshot_trust_path(), manifest)?;
        Ok(Self { binding, session })
    }

    pub fn resume(
        path: VerifiedNativeTrustPathV1,
        manifest: SnapshotManifestV0,
        application: NativeApplicationCheckpointV1,
        readback: NativeStateSyncReadbackV1,
        retained_chunks: &[SnapshotChunkV0],
    ) -> Result<Self, StateSyncErrorV0> {
        let mut resumed = Self::begin(path, manifest, application)?;
        if readback.binding_digest != resumed.binding.binding_digest
            || readback.manifest_digest != resumed.binding.manifest_digest
        {
            return Err(StateSyncErrorV0::NativeSessionReadbackMismatch);
        }
        for chunk in retained_chunks {
            resumed.session.accept_chunk(chunk.clone())?;
        }
        let actual = resumed.readback();
        if actual != readback {
            return Err(StateSyncErrorV0::NativeSessionReadbackMismatch);
        }
        Ok(resumed)
    }

    pub fn accept_chunk(&mut self, chunk: SnapshotChunkV0) -> Result<(), StateSyncErrorV0> {
        self.session.accept_chunk(chunk)
    }

    #[must_use]
    pub fn missing_chunks(&self) -> Vec<u32> {
        self.session.missing_chunks()
    }

    #[must_use]
    pub(crate) fn retained_chunks_v1(&self) -> Vec<SnapshotChunkV0> {
        self.session.retained_chunks_v0()
    }

    #[must_use]
    pub const fn binding(&self) -> NativeStateSyncBindingV1 {
        self.binding
    }

    #[must_use]
    pub fn readback(&self) -> NativeStateSyncReadbackV1 {
        NativeStateSyncReadbackV1 {
            binding_digest: self.binding.binding_digest,
            manifest_digest: self.binding.manifest_digest,
            received_chunk_count: self.session.received_chunk_count(),
            received_bytes: self.session.received_bytes(),
            progress_digest: self.session.progress_digest(),
        }
    }

    #[must_use]
    fn manifest_binding_digest(&self) -> Digest32V0 {
        self.session.manifest_binding_digest()
    }

    pub fn verify_complete<R>(
        &self,
        recomputer: &R,
    ) -> Result<NativeVerifiedSnapshotV1, StateSyncHostErrorV0<R::Error>>
    where
        R: StateRootRecomputerV0,
    {
        let snapshot = self.session.verify_complete(recomputer)?;
        if snapshot.manifest_digest() != self.binding.manifest_digest
            || snapshot.height() != self.binding.height
            || snapshot.epoch() != self.binding.epoch
            || snapshot.state_root() != self.binding.state_root
        {
            return Err(StateSyncHostErrorV0::Protocol(
                StateSyncErrorV0::NativeApplicationBindingMismatch,
            ));
        }
        Ok(NativeVerifiedSnapshotV1 {
            snapshot,
            binding: self.binding,
        })
    }
}

/// A closed-world SQLite persistence adapter for one native state-sync
/// session.  It stores only the verified session binding, immutable accepted
/// chunks, and a content-derived readback.  Reopening it never creates a
/// trust path: `resume_existing_v1` requires the caller to supply a freshly
/// verified native path and exact manifest/application checkpoint again.
#[derive(Clone, Debug)]
pub struct SqliteNativeStateSyncStoreV1 {
    path: PathBuf,
    #[cfg(test)]
    test_max_page_count: Option<i64>,
}

#[derive(Clone, Copy, Debug)]
struct NativeDurableMetadataV1 {
    binding: NativeStateSyncBindingV1,
    manifest_binding_digest: Digest32V0,
    readback: NativeStateSyncReadbackV1,
}

impl SqliteNativeStateSyncStoreV1 {
    /// Create a new store from the current in-memory session.  Existing paths
    /// are rejected so a stale or substituted database cannot be adopted.
    pub fn initialize(
        path: impl Into<PathBuf>,
        session: &NativeStateSyncSessionV1,
    ) -> Result<Self, NativeStateSyncStoreErrorV1> {
        let path = path.into();
        if path.exists() {
            return Err(NativeStateSyncStoreErrorV1::StoreAlreadyInitialized);
        }
        let mut connection = Connection::open(&path)
            .map_err(|error| NativeStateSyncStoreErrorV1::Sqlite(error.to_string()))?;
        configure_native_connection_v1(&connection, true)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| NativeStateSyncStoreErrorV1::Sqlite(error.to_string()))?;
        transaction
            .execute_batch(&format!(
                "{NATIVE_SYNC_META_SQL_V1};{NATIVE_SYNC_CHUNKS_SQL_V1};"
            ))
            .map_err(|error| NativeStateSyncStoreErrorV1::Sqlite(error.to_string()))?;
        let binding = session.binding();
        let readback = session.readback();
        insert_metadata_v1(
            &transaction,
            binding,
            session.manifest_binding_digest(),
            readback,
        )?;
        for chunk in session.retained_chunks_v1() {
            transaction
                .execute(
                    "INSERT INTO native_state_sync_chunks_v1(chunk_index,manifest_digest,bytes,chunk_digest) VALUES(?1,?2,?3,?4)",
                    params![
                        i64::from(chunk.index),
                        &chunk.manifest_digest.0[..],
                        &chunk.bytes,
                        &chunk.chunk_digest.0[..]
                    ],
                )
                .map_err(|error| NativeStateSyncStoreErrorV1::Sqlite(error.to_string()))?;
        }
        transaction
            .commit()
            .map_err(|error| NativeStateSyncStoreErrorV1::Sqlite(error.to_string()))?;
        let store = Self {
            path,
            #[cfg(test)]
            test_max_page_count: None,
        };
        let actual = store.readback_v1()?;
        if actual != readback {
            return Err(NativeStateSyncStoreErrorV1::DurableReadbackMismatch);
        }
        Ok(store)
    }

    /// Open an existing closed-world store and validate its metadata and all
    /// retained chunk bytes.  This is intentionally independent of a trust
    /// path; source authority is re-established only by `resume_existing_v1`.
    pub fn open_existing(path: impl Into<PathBuf>) -> Result<Self, NativeStateSyncStoreErrorV1> {
        let store = Self {
            path: path.into(),
            #[cfg(test)]
            test_max_page_count: None,
        };
        let _ = store.readback_v1()?;
        Ok(store)
    }

    /// Apply a real SQLite page ceiling to the next writer connections. This
    /// is test-only fault injection: production callers cannot lower a store's
    /// durable resource policy through this API.
    #[cfg(test)]
    pub(crate) fn with_test_max_page_count_v1(mut self, pages: i64) -> Self {
        self.test_max_page_count = Some(pages);
        self
    }

    /// Read the durable identity and progress from one fresh SQLite snapshot.
    /// Every retained chunk is rehashed before either value is returned, so a
    /// caller cannot join a binding from one read with progress from another.
    pub fn binding_and_readback_v1(
        &self,
    ) -> Result<(NativeStateSyncBindingV1, NativeStateSyncReadbackV1), NativeStateSyncStoreErrorV1>
    {
        let (metadata, _) = self.read_validated_snapshot_v1()?;
        Ok((metadata.binding, metadata.readback))
    }

    /// Return the immutable session identity after a complete fresh readback.
    #[must_use]
    pub fn binding_v1(&self) -> Result<NativeStateSyncBindingV1, NativeStateSyncStoreErrorV1> {
        self.binding_and_readback_v1().map(|(binding, _)| binding)
    }

    /// Read the durable progress after checking every retained chunk's
    /// canonical digest, manifest binding, byte bound and metadata digest.
    pub fn readback_v1(&self) -> Result<NativeStateSyncReadbackV1, NativeStateSyncStoreErrorV1> {
        self.binding_and_readback_v1().map(|(_, readback)| readback)
    }

    /// Return the exact retained bytes in canonical index order after a full
    /// digest/readback check.  The caller must still bind them to a fresh
    /// verified path and manifest before resuming.
    pub fn retained_chunks_v1(&self) -> Result<Vec<SnapshotChunkV0>, NativeStateSyncStoreErrorV1> {
        self.read_validated_snapshot_v1().map(|(_, chunks)| chunks)
    }

    /// Revalidate a freshly authenticated native path, exact manifest and
    /// application checkpoint against the persisted source binding, then
    /// reconstruct the in-memory session from every retained chunk.
    pub fn resume_existing_v1(
        &self,
        path: VerifiedNativeTrustPathV1,
        manifest: SnapshotManifestV0,
        application: NativeApplicationCheckpointV1,
    ) -> Result<NativeStateSyncSessionV1, NativeStateSyncStoreErrorV1> {
        let (metadata, chunks) = self.read_validated_snapshot_v1()?;
        let resumed = NativeStateSyncSessionV1::begin(path.clone(), manifest.clone(), application)
            .map_err(NativeStateSyncStoreErrorV1::Protocol)?;
        let binding = resumed.binding();
        if binding != metadata.binding
            || manifest.chunk_binding_digest() != metadata.manifest_binding_digest
        {
            return Err(NativeStateSyncStoreErrorV1::BindingMismatch);
        }
        NativeStateSyncSessionV1::resume(path, manifest, application, metadata.readback, &chunks)
            .map_err(NativeStateSyncStoreErrorV1::Protocol)
    }

    fn read_validated_snapshot_v1(
        &self,
    ) -> Result<(NativeDurableMetadataV1, Vec<SnapshotChunkV0>), NativeStateSyncStoreErrorV1> {
        let mut connection = self.open_connection_v1()?;
        // A connection alone is not a SQLite snapshot. Without BEGIN, a writer
        // can commit between the metadata and chunk SELECTs and a valid append
        // is then misclassified as corrupt durable progress. A deferred read
        // transaction pins one WAL snapshot without blocking the append owner.
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Deferred)
            .map_err(|error| NativeStateSyncStoreErrorV1::Sqlite(error.to_string()))?;
        let metadata = read_metadata_v1(&transaction)?;
        #[cfg(test)]
        tests::pause_after_metadata_read_v1();
        let chunks = read_chunks_v1(&transaction, metadata.manifest_binding_digest)?;
        let actual = readback_from_chunks_v1(
            metadata.binding.binding_digest,
            metadata.binding.manifest_digest,
            &chunks,
        )?;
        if actual != metadata.readback {
            return Err(NativeStateSyncStoreErrorV1::DurableReadbackMismatch);
        }
        transaction
            .commit()
            .map_err(|error| NativeStateSyncStoreErrorV1::Sqlite(error.to_string()))?;
        Ok((metadata, chunks))
    }

    /// Validate and durably append one chunk.  The in-memory session is
    /// replaced only after SQLite commit succeeds, so an I/O error cannot
    /// advance process-local accounting past the durable state.
    pub fn append_chunk_v1(
        &self,
        session: &mut NativeStateSyncSessionV1,
        chunk: SnapshotChunkV0,
    ) -> Result<(), NativeStateSyncStoreErrorV1> {
        // Acquire the writer lock before reading any state.  A deferred
        // transaction here would allow two callers to validate against the
        // same snapshot and then one caller could overwrite the other's
        // progress bookkeeping.  The session check below is deliberately
        // inside this IMMEDIATE transaction, making the in-memory session a
        // conditional-CAS witness for the durable row set.
        let mut connection = self.open_connection_v1()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| NativeStateSyncStoreErrorV1::Sqlite(error.to_string()))?;
        let metadata = read_metadata_v1(&transaction)?;
        let current = read_chunks_v1(&transaction, metadata.manifest_binding_digest)?;
        let actual = readback_from_chunks_v1(
            metadata.binding.binding_digest,
            metadata.binding.manifest_digest,
            &current,
        )?;
        if actual != metadata.readback
            || actual != session.readback()
            || session.binding() != metadata.binding
            || session.manifest_binding_digest() != metadata.manifest_binding_digest
        {
            return Err(NativeStateSyncStoreErrorV1::DurableReadbackMismatch);
        }

        let mut next = session.clone();
        next.accept_chunk(chunk.clone())
            .map_err(NativeStateSyncStoreErrorV1::Protocol)?;
        let existing: Option<(Vec<u8>, Vec<u8>, Vec<u8>)> = transaction
            .query_row(
                "SELECT manifest_digest,bytes,chunk_digest FROM native_state_sync_chunks_v1 WHERE chunk_index=?1",
                params![i64::from(chunk.index)],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(|error| NativeStateSyncStoreErrorV1::Sqlite(error.to_string()))?;
        if let Some((manifest_digest, bytes, chunk_digest)) = existing {
            if manifest_digest != chunk.manifest_digest.0
                || bytes != chunk.bytes
                || chunk_digest != chunk.chunk_digest.0
            {
                return Err(NativeStateSyncStoreErrorV1::Protocol(
                    StateSyncErrorV0::ChunkSubstitution,
                ));
            }
        } else {
            transaction
                .execute(
                    "INSERT INTO native_state_sync_chunks_v1(chunk_index,manifest_digest,bytes,chunk_digest) VALUES(?1,?2,?3,?4)",
                    params![
                        i64::from(chunk.index),
                        &chunk.manifest_digest.0[..],
                        &chunk.bytes,
                        &chunk.chunk_digest.0[..]
                    ],
                )
                .map_err(|error| NativeStateSyncStoreErrorV1::Sqlite(error.to_string()))?;
        }
        let next_readback = next.readback();
        update_metadata_readback_v1(&transaction, next_readback)?;
        transaction
            .commit()
            .map_err(|error| NativeStateSyncStoreErrorV1::Sqlite(error.to_string()))?;
        *session = next;
        Ok(())
    }

    fn open_connection_v1(&self) -> Result<Connection, NativeStateSyncStoreErrorV1> {
        let connection = Connection::open_with_flags(&self.path, OpenFlags::SQLITE_OPEN_READ_WRITE)
            .map_err(|error| NativeStateSyncStoreErrorV1::Sqlite(error.to_string()))?;
        configure_native_connection_v1(&connection, false)?;
        #[cfg(test)]
        if let Some(pages) = self.test_max_page_count {
            connection
                .pragma_update(None, "max_page_count", pages)
                .map_err(|error| NativeStateSyncStoreErrorV1::Sqlite(error.to_string()))?;
        }
        verify_native_schema_v1(&connection)?;
        Ok(connection)
    }
}

fn configure_native_connection_v1(
    connection: &Connection,
    initialize: bool,
) -> Result<(), NativeStateSyncStoreErrorV1> {
    if initialize {
        connection
            .pragma_update(None, "application_id", NATIVE_SYNC_STORE_APP_ID_V1)
            .map_err(|error| NativeStateSyncStoreErrorV1::Sqlite(error.to_string()))?;
        connection
            .pragma_update(None, "user_version", NATIVE_SYNC_STORE_USER_VERSION_V1)
            .map_err(|error| NativeStateSyncStoreErrorV1::Sqlite(error.to_string()))?;
        connection
            .pragma_update(None, "journal_mode", "WAL")
            .map_err(|error| NativeStateSyncStoreErrorV1::Sqlite(error.to_string()))?;
        connection
            .pragma_update(None, "synchronous", "FULL")
            .map_err(|error| NativeStateSyncStoreErrorV1::Sqlite(error.to_string()))?;
    }
    let application_id: i64 = connection
        .pragma_query_value(None, "application_id", |row| row.get(0))
        .map_err(|error| NativeStateSyncStoreErrorV1::Sqlite(error.to_string()))?;
    let user_version: i64 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(|error| NativeStateSyncStoreErrorV1::Sqlite(error.to_string()))?;
    let journal_mode: String = connection
        .pragma_query_value(None, "journal_mode", |row| row.get(0))
        .map_err(|error| NativeStateSyncStoreErrorV1::Sqlite(error.to_string()))?;
    let synchronous: i64 = connection
        .pragma_query_value(None, "synchronous", |row| row.get(0))
        .map_err(|error| NativeStateSyncStoreErrorV1::Sqlite(error.to_string()))?;
    if application_id != NATIVE_SYNC_STORE_APP_ID_V1
        || user_version != NATIVE_SYNC_STORE_USER_VERSION_V1
        || journal_mode.to_ascii_lowercase() != "wal"
        || synchronous != 2
    {
        return Err(NativeStateSyncStoreErrorV1::StoreSchemaMismatch);
    }
    connection
        .busy_timeout(std::time::Duration::from_millis(250))
        .map_err(|error| NativeStateSyncStoreErrorV1::Sqlite(error.to_string()))?;
    Ok(())
}

fn verify_native_schema_v1(connection: &Connection) -> Result<(), NativeStateSyncStoreErrorV1> {
    let mut statement = connection
        .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")
        .map_err(|error| NativeStateSyncStoreErrorV1::Sqlite(error.to_string()))?;
    let names = statement
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(|error| NativeStateSyncStoreErrorV1::Sqlite(error.to_string()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| NativeStateSyncStoreErrorV1::Sqlite(error.to_string()))?;
    if names
        != [
            "native_state_sync_chunks_v1".to_owned(),
            "native_state_sync_meta_v1".to_owned(),
        ]
    {
        return Err(NativeStateSyncStoreErrorV1::StoreSchemaMismatch);
    }
    Ok(())
}

fn digest_from_blob_v1(bytes: Vec<u8>) -> Result<Digest32V0, NativeStateSyncStoreErrorV1> {
    <[u8; 32]>::try_from(bytes.as_slice())
        .map(Digest32V0)
        .map_err(|_| NativeStateSyncStoreErrorV1::StoreSchemaMismatch)
}

fn u64_from_i64_v1(value: i64) -> Result<u64, NativeStateSyncStoreErrorV1> {
    u64::try_from(value).map_err(|_| NativeStateSyncStoreErrorV1::StoreSchemaMismatch)
}

fn u64_to_i64_v1(value: u64) -> Result<i64, NativeStateSyncStoreErrorV1> {
    i64::try_from(value)
        .map_err(|_| NativeStateSyncStoreErrorV1::Protocol(StateSyncErrorV0::SnapshotTooLarge))
}

fn read_metadata_v1(
    connection: &Connection,
) -> Result<NativeDurableMetadataV1, NativeStateSyncStoreErrorV1> {
    let row = connection
        .query_row(
            "SELECT binding_digest,trust_path_digest,terminal_block_digest,checkpoint_digest,manifest_digest,manifest_binding_digest,height,epoch,state_root,schema_digest,application_version,received_chunk_count,received_bytes,progress_digest FROM native_state_sync_meta_v1 WHERE singleton=1",
            [],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                    row.get::<_, Vec<u8>>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, i64>(7)?,
                    row.get::<_, Vec<u8>>(8)?,
                    row.get::<_, Vec<u8>>(9)?,
                    row.get::<_, i64>(10)?,
                    row.get::<_, i64>(11)?,
                    row.get::<_, i64>(12)?,
                    row.get::<_, Vec<u8>>(13)?,
                ))
            },
        )
        .optional()
        .map_err(|error| NativeStateSyncStoreErrorV1::Sqlite(error.to_string()))?
        .ok_or(NativeStateSyncStoreErrorV1::StoreSchemaMismatch)?;
    let binding = NativeStateSyncBindingV1 {
        binding_digest: digest_from_blob_v1(row.0.clone())?,
        trust_path_digest: digest_from_blob_v1(row.1)?,
        terminal_block_digest: digest_from_blob_v1(row.2)?,
        checkpoint_digest: digest_from_blob_v1(row.3)?,
        manifest_digest: digest_from_blob_v1(row.4)?,
        height: u64_from_i64_v1(row.6)?,
        epoch: u64_from_i64_v1(row.7)?,
        state_root: digest_from_blob_v1(row.8)?,
        schema_digest: digest_from_blob_v1(row.9)?,
        application_version: u64_from_i64_v1(row.10)?,
    };
    if binding.binding_digest == Digest32V0([0; 32])
        || binding.canonical_digest() != binding.binding_digest
        || binding.height == 0
        || binding.schema_digest == Digest32V0([0; 32])
        || binding.application_version == 0
    {
        return Err(NativeStateSyncStoreErrorV1::BindingMismatch);
    }
    let received_chunk_count = u32::try_from(u64_from_i64_v1(row.11)?)
        .map_err(|_| NativeStateSyncStoreErrorV1::StoreSchemaMismatch)?;
    let readback = NativeStateSyncReadbackV1 {
        binding_digest: binding.binding_digest,
        manifest_digest: binding.manifest_digest,
        received_chunk_count,
        received_bytes: u64_from_i64_v1(row.12)?,
        progress_digest: digest_from_blob_v1(row.13)?,
    };
    Ok(NativeDurableMetadataV1 {
        binding,
        manifest_binding_digest: digest_from_blob_v1(row.5)?,
        readback,
    })
}

fn read_chunks_v1(
    connection: &Connection,
    expected_manifest_binding: Digest32V0,
) -> Result<Vec<SnapshotChunkV0>, NativeStateSyncStoreErrorV1> {
    if expected_manifest_binding == Digest32V0([0; 32]) {
        return Err(NativeStateSyncStoreErrorV1::BindingMismatch);
    }
    let mut statement = connection
        .prepare("SELECT chunk_index,manifest_digest,bytes,chunk_digest FROM native_state_sync_chunks_v1 ORDER BY chunk_index")
        .map_err(|error| NativeStateSyncStoreErrorV1::Sqlite(error.to_string()))?;
    let mapped = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, Vec<u8>>(3)?,
            ))
        })
        .map_err(|error| NativeStateSyncStoreErrorV1::Sqlite(error.to_string()))?;
    let mut chunks = Vec::new();
    let mut total_bytes = 0_u64;
    for item in mapped {
        if chunks.len() >= crate::MAX_CHUNK_COUNT_V0 as usize {
            return Err(NativeStateSyncStoreErrorV1::Protocol(
                StateSyncErrorV0::SnapshotTooLarge,
            ));
        }
        let (index, manifest_digest, bytes, chunk_digest) =
            item.map_err(|error| NativeStateSyncStoreErrorV1::Sqlite(error.to_string()))?;
        let index = u32::try_from(u64_from_i64_v1(index)?)
            .map_err(|_| NativeStateSyncStoreErrorV1::StoreSchemaMismatch)?;
        if bytes.is_empty() || bytes.len() > crate::MAX_CHUNK_BYTES_V0 {
            return Err(NativeStateSyncStoreErrorV1::Protocol(
                StateSyncErrorV0::InvalidChunk,
            ));
        }
        total_bytes = total_bytes.checked_add(bytes.len() as u64).ok_or(
            NativeStateSyncStoreErrorV1::Protocol(StateSyncErrorV0::SnapshotTooLarge),
        )?;
        if total_bytes > crate::MAX_SNAPSHOT_BYTES_V0 {
            return Err(NativeStateSyncStoreErrorV1::Protocol(
                StateSyncErrorV0::SnapshotTooLarge,
            ));
        }
        let manifest_digest = digest_from_blob_v1(manifest_digest)?;
        let chunk_digest = digest_from_blob_v1(chunk_digest)?;
        if manifest_digest != expected_manifest_binding
            || chunk_digest != SnapshotChunkV0::canonical_digest(manifest_digest, index, &bytes)
        {
            return Err(NativeStateSyncStoreErrorV1::Protocol(
                StateSyncErrorV0::InvalidChunk,
            ));
        }
        chunks.push(SnapshotChunkV0 {
            manifest_digest,
            index,
            bytes,
            chunk_digest,
        });
    }
    Ok(chunks)
}

fn readback_from_chunks_v1(
    binding_digest: Digest32V0,
    manifest_digest: Digest32V0,
    chunks: &[SnapshotChunkV0],
) -> Result<NativeStateSyncReadbackV1, NativeStateSyncStoreErrorV1> {
    let mut previous = None;
    let mut received_bytes = 0_u64;
    let mut parts = Vec::with_capacity(chunks.len() * 2 + 1);
    parts.push(manifest_digest.0.to_vec());
    for chunk in chunks {
        if previous.is_some_and(|index| index >= chunk.index) {
            return Err(NativeStateSyncStoreErrorV1::StoreSchemaMismatch);
        }
        previous = Some(chunk.index);
        received_bytes = received_bytes.checked_add(chunk.bytes.len() as u64).ok_or(
            NativeStateSyncStoreErrorV1::Protocol(StateSyncErrorV0::SnapshotTooLarge),
        )?;
        parts.push(chunk.index.to_be_bytes().to_vec());
        parts.push(chunk.chunk_digest.0.to_vec());
    }
    let refs: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
    Ok(NativeStateSyncReadbackV1 {
        binding_digest,
        manifest_digest,
        received_chunk_count: u32::try_from(chunks.len())
            .map_err(|_| NativeStateSyncStoreErrorV1::StoreSchemaMismatch)?,
        received_bytes,
        progress_digest: Digest32V0::hash(b"trnm.state-sync.session-progress.v0", &refs),
    })
}

fn insert_metadata_v1(
    transaction: &rusqlite::Transaction<'_>,
    binding: NativeStateSyncBindingV1,
    manifest_binding_digest: Digest32V0,
    readback: NativeStateSyncReadbackV1,
) -> Result<(), NativeStateSyncStoreErrorV1> {
    transaction
        .execute(
            "INSERT INTO native_state_sync_meta_v1(singleton,binding_digest,trust_path_digest,terminal_block_digest,checkpoint_digest,manifest_digest,manifest_binding_digest,height,epoch,state_root,schema_digest,application_version,received_chunk_count,received_bytes,progress_digest) VALUES(1,?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14)",
            params![
                &binding.binding_digest.0[..],
                &binding.trust_path_digest.0[..],
                &binding.terminal_block_digest.0[..],
                &binding.checkpoint_digest.0[..],
                &binding.manifest_digest.0[..],
                &manifest_binding_digest.0[..],
                u64_to_i64_v1(binding.height)?,
                u64_to_i64_v1(binding.epoch)?,
                &binding.state_root.0[..],
                &binding.schema_digest.0[..],
                u64_to_i64_v1(binding.application_version)?,
                i64::from(readback.received_chunk_count),
                u64_to_i64_v1(readback.received_bytes)?,
                &readback.progress_digest.0[..],
            ],
        )
        .map_err(|error| NativeStateSyncStoreErrorV1::Sqlite(error.to_string()))?;
    Ok(())
}

fn update_metadata_readback_v1(
    transaction: &rusqlite::Transaction<'_>,
    readback: NativeStateSyncReadbackV1,
) -> Result<(), NativeStateSyncStoreErrorV1> {
    let updated = transaction
        .execute(
            "UPDATE native_state_sync_meta_v1 SET received_chunk_count=?1,received_bytes=?2,progress_digest=?3 WHERE singleton=1 AND binding_digest=?4 AND manifest_digest=?5",
            params![
                i64::from(readback.received_chunk_count),
                u64_to_i64_v1(readback.received_bytes)?,
                &readback.progress_digest.0[..],
                &readback.binding_digest.0[..],
                &readback.manifest_digest.0[..],
            ],
        )
        .map_err(|error| NativeStateSyncStoreErrorV1::Sqlite(error.to_string()))?;
    if updated != 1 {
        return Err(NativeStateSyncStoreErrorV1::BindingMismatch);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeVerifiedSnapshotV1 {
    snapshot: VerifiedSnapshotV0,
    binding: NativeStateSyncBindingV1,
}

impl NativeVerifiedSnapshotV1 {
    #[must_use]
    pub const fn snapshot(&self) -> VerifiedSnapshotV0 {
        self.snapshot
    }

    #[must_use]
    pub const fn binding(&self) -> NativeStateSyncBindingV1 {
        self.binding
    }
}

#[cfg(test)]
#[path = "native_trust_v1_tests.rs"]
mod tests;
