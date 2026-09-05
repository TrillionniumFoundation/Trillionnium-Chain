#![forbid(unsafe_code)]
//! Authenticated, bounded and non-destructive state-sync protocol core.
//!
//! Network peers provide bytes, never trust.  A caller supplies an
//! independently configured weak-subjectivity anchor, verifies every
//! checkpoint link, recomputes both the chunk commitment and application state
//! root, writes only to a staging generation, and swaps that generation into
//! service with an expected-current-root compare-and-swap.

use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, error::Error, fmt};

pub const STATE_SYNC_VERSION_V0: u16 = 0;
pub const MAX_TRUST_PATH_LINKS_V0: usize = 4096;
pub const MAX_CHUNK_COUNT_V0: u32 = 65_536;
pub const MAX_CHUNK_BYTES_V0: usize = 4 * 1024 * 1024;
pub const MAX_SNAPSHOT_BYTES_V0: u64 = 512 * 1024 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Digest32V0(pub [u8; 32]);

impl Digest32V0 {
    #[must_use]
    pub fn hash(domain: &[u8], parts: &[&[u8]]) -> Self {
        let mut h = Sha256::new();
        h.update((domain.len() as u64).to_be_bytes());
        h.update(domain);
        for part in parts {
            h.update((part.len() as u64).to_be_bytes());
            h.update(part);
        }
        Self(h.finalize().into())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WeakSubjectivityAnchorV0 {
    pub chain_id: Digest32V0,
    pub protocol_digest: Digest32V0,
    pub epoch: u64,
    pub height: u64,
    pub checkpoint_digest: Digest32V0,
    pub validator_set_digest: Digest32V0,
}

impl WeakSubjectivityAnchorV0 {
    pub fn validate(self) -> Result<Self, StateSyncErrorV0> {
        if self.chain_id == Digest32V0([0; 32])
            || self.protocol_digest == Digest32V0([0; 32])
            || self.epoch == 0
            || self.height == 0
            || self.checkpoint_digest == Digest32V0([0; 32])
            || self.validator_set_digest == Digest32V0([0; 32])
        {
            return Err(StateSyncErrorV0::InvalidTrustAnchor);
        }
        Ok(self)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CheckpointLinkV0 {
    pub chain_id: Digest32V0,
    pub protocol_digest: Digest32V0,
    pub epoch: u64,
    pub height: u64,
    pub state_root: Digest32V0,
    pub validator_set_digest: Digest32V0,
    pub next_validator_set_digest: Digest32V0,
    pub parent_checkpoint_digest: Digest32V0,
    pub finality_proof_digest: Digest32V0,
    pub checkpoint_digest: Digest32V0,
}

impl CheckpointLinkV0 {
    #[must_use]
    pub fn canonical_digest(&self) -> Digest32V0 {
        Digest32V0::hash(
            b"trnm.state-sync.checkpoint-link.v0",
            &[
                &self.chain_id.0,
                &self.protocol_digest.0,
                &self.epoch.to_be_bytes(),
                &self.height.to_be_bytes(),
                &self.state_root.0,
                &self.validator_set_digest.0,
                &self.next_validator_set_digest.0,
                &self.parent_checkpoint_digest.0,
                &self.finality_proof_digest.0,
            ],
        )
    }
}

pub trait CheckpointProofVerifierV0 {
    type Error: Error + Send + Sync + 'static;

    fn verify_link(&self, link: &CheckpointLinkV0) -> Result<(), Self::Error>;
}

/// An immutable result issued only after the complete checkpoint path verifies.
///
/// The verifier remains a trusted adapter supplied by the composition. This type
/// prevents bypassing that adapter or changing a result after it returns; it is
/// not a replacement for cryptographic verification or trust-anchor selection.
///
/// External callers cannot manufacture a verified path:
///
/// ```compile_fail,E0451
/// use trnm_state_sync_v0::{
///     CheckpointLinkV0, Digest32V0, VerifiedTrustPathV0, WeakSubjectivityAnchorV0,
/// };
/// fn forge(anchor: WeakSubjectivityAnchorV0, terminal: CheckpointLinkV0) -> VerifiedTrustPathV0 {
///     VerifiedTrustPathV0 { anchor, terminal, link_count: 1, path_digest: Digest32V0([1; 32]) }
/// }
/// ```
///
/// Nor may they retarget a genuine result to an unverified checkpoint:
///
/// ```compile_fail,E0616
/// use trnm_state_sync_v0::{CheckpointLinkV0, VerifiedTrustPathV0};
/// fn retarget(path: &mut VerifiedTrustPathV0, unverified: CheckpointLinkV0) {
///     path.terminal = unverified;
/// }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedTrustPathV0 {
    anchor: WeakSubjectivityAnchorV0,
    terminal: CheckpointLinkV0,
    link_count: u32,
    path_digest: Digest32V0,
}

impl VerifiedTrustPathV0 {
    #[must_use]
    pub const fn anchor(&self) -> WeakSubjectivityAnchorV0 {
        self.anchor
    }

    #[must_use]
    pub const fn terminal(&self) -> CheckpointLinkV0 {
        self.terminal
    }

    #[must_use]
    pub const fn link_count(&self) -> u32 {
        self.link_count
    }

    #[must_use]
    pub const fn path_digest(&self) -> Digest32V0 {
        self.path_digest
    }
}

pub fn verify_trust_path_v0<V>(
    verifier: &V,
    anchor: WeakSubjectivityAnchorV0,
    links: &[CheckpointLinkV0],
) -> Result<VerifiedTrustPathV0, StateSyncHostErrorV0<V::Error>>
where
    V: CheckpointProofVerifierV0,
{
    let anchor = anchor.validate().map_err(StateSyncHostErrorV0::Protocol)?;
    if links.is_empty() || links.len() > MAX_TRUST_PATH_LINKS_V0 {
        return Err(StateSyncHostErrorV0::Protocol(
            StateSyncErrorV0::TrustPathOutOfBounds,
        ));
    }

    let mut previous_digest = anchor.checkpoint_digest;
    let mut previous_height = anchor.height;
    let mut previous_epoch = anchor.epoch;
    let mut expected_validator_set = anchor.validator_set_digest;
    let mut path_hasher = Sha256::new();
    path_hasher.update(b"trnm.state-sync.trust-path.v0");
    path_hasher.update(anchor.checkpoint_digest.0);

    for link in links {
        if link.chain_id != anchor.chain_id
            || link.protocol_digest != anchor.protocol_digest
            || link.parent_checkpoint_digest != previous_digest
            || link.height <= previous_height
            || link.epoch < previous_epoch
            || link.epoch > previous_epoch.saturating_add(1)
            || link.state_root == Digest32V0([0; 32])
            || link.validator_set_digest != expected_validator_set
            || link.next_validator_set_digest == Digest32V0([0; 32])
            || (link.epoch == previous_epoch
                && link.next_validator_set_digest != expected_validator_set)
            || link.finality_proof_digest == Digest32V0([0; 32])
            || link.checkpoint_digest == Digest32V0([0; 32])
            || link.checkpoint_digest != link.canonical_digest()
        {
            return Err(StateSyncHostErrorV0::Protocol(
                StateSyncErrorV0::InvalidTrustPath,
            ));
        }
        verifier
            .verify_link(link)
            .map_err(StateSyncHostErrorV0::CheckpointProof)?;
        path_hasher.update(link.checkpoint_digest.0);
        previous_digest = link.checkpoint_digest;
        previous_height = link.height;
        if link.epoch > previous_epoch {
            previous_epoch = link.epoch;
            expected_validator_set = link.next_validator_set_digest;
        }
    }

    let terminal = *links.last().ok_or(StateSyncHostErrorV0::Protocol(
        StateSyncErrorV0::TrustPathOutOfBounds,
    ))?;
    Ok(VerifiedTrustPathV0 {
        anchor,
        terminal,
        link_count: u32::try_from(links.len())
            .map_err(|_| StateSyncHostErrorV0::Protocol(StateSyncErrorV0::TrustPathOutOfBounds))?,
        path_digest: Digest32V0(path_hasher.finalize().into()),
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SnapshotManifestV0 {
    pub chain_id: Digest32V0,
    pub protocol_digest: Digest32V0,
    pub height: u64,
    pub epoch: u64,
    pub state_root: Digest32V0,
    pub chunk_root: Digest32V0,
    pub chunk_count: u32,
    pub maximum_chunk_bytes: u32,
    pub total_bytes: u64,
    pub schema_digest: Digest32V0,
    pub checkpoint_digest: Digest32V0,
    pub manifest_digest: Digest32V0,
}

impl SnapshotManifestV0 {
    /// Stable digest bound into every chunk. It deliberately excludes both
    /// `chunk_root` and `manifest_digest`, preventing a hash self-reference.
    #[must_use]
    pub fn chunk_binding_digest(&self) -> Digest32V0 {
        Digest32V0::hash(
            b"trnm.state-sync.snapshot-header.v0",
            &[
                &self.chain_id.0,
                &self.protocol_digest.0,
                &self.height.to_be_bytes(),
                &self.epoch.to_be_bytes(),
                &self.state_root.0,
                &self.chunk_count.to_be_bytes(),
                &self.maximum_chunk_bytes.to_be_bytes(),
                &self.total_bytes.to_be_bytes(),
                &self.schema_digest.0,
                &self.checkpoint_digest.0,
            ],
        )
    }

    #[must_use]
    pub fn canonical_digest(&self) -> Digest32V0 {
        Digest32V0::hash(
            b"trnm.state-sync.snapshot-manifest.v0",
            &[&self.chunk_binding_digest().0, &self.chunk_root.0],
        )
    }

    pub fn validate(&self, trust_path: &VerifiedTrustPathV0) -> Result<(), StateSyncErrorV0> {
        if self.chain_id != trust_path.anchor.chain_id
            || self.protocol_digest != trust_path.anchor.protocol_digest
            || self.height != trust_path.terminal.height
            || self.epoch != trust_path.terminal.epoch
            || self.state_root != trust_path.terminal.state_root
            || self.checkpoint_digest != trust_path.terminal.checkpoint_digest
        {
            return Err(StateSyncErrorV0::ManifestTrustMismatch);
        }
        let declared_capacity = u64::from(self.chunk_count)
            .checked_mul(u64::from(self.maximum_chunk_bytes))
            .ok_or(StateSyncErrorV0::InvalidManifest)?;
        if self.chunk_count == 0
            || self.chunk_count > MAX_CHUNK_COUNT_V0
            || self.maximum_chunk_bytes == 0
            || self.maximum_chunk_bytes as usize > MAX_CHUNK_BYTES_V0
            || self.total_bytes < u64::from(self.chunk_count)
            || self.total_bytes > MAX_SNAPSHOT_BYTES_V0
            || self.total_bytes > declared_capacity
            || self.state_root == Digest32V0([0; 32])
            || self.chunk_root == Digest32V0([0; 32])
            || self.schema_digest == Digest32V0([0; 32])
            || self.checkpoint_digest == Digest32V0([0; 32])
            || self.manifest_digest == Digest32V0([0; 32])
            || self.manifest_digest != self.canonical_digest()
        {
            return Err(StateSyncErrorV0::InvalidManifest);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SnapshotChunkV0 {
    pub manifest_digest: Digest32V0,
    pub index: u32,
    pub bytes: Vec<u8>,
    pub chunk_digest: Digest32V0,
}

impl SnapshotChunkV0 {
    #[must_use]
    pub fn canonical_digest(manifest_digest: Digest32V0, index: u32, bytes: &[u8]) -> Digest32V0 {
        Digest32V0::hash(
            b"trnm.state-sync.snapshot-chunk.v0",
            &[&manifest_digest.0, &index.to_be_bytes(), bytes],
        )
    }

    pub fn validate(&self, manifest: &SnapshotManifestV0) -> Result<(), StateSyncErrorV0> {
        if self.manifest_digest != manifest.chunk_binding_digest()
            || self.index >= manifest.chunk_count
            || self.bytes.is_empty()
            || self.bytes.len() > manifest.maximum_chunk_bytes as usize
            || self.chunk_digest
                != Self::canonical_digest(self.manifest_digest, self.index, &self.bytes)
        {
            return Err(StateSyncErrorV0::InvalidChunk);
        }
        Ok(())
    }
}

#[must_use]
pub fn chunk_merkle_root_v0(digests: &[Digest32V0]) -> Digest32V0 {
    if digests.is_empty() {
        return Digest32V0::hash(b"trnm.state-sync.empty-chunk-root.v0", &[]);
    }
    let mut level = digests.to_vec();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            let left = pair[0];
            let right = pair.get(1).copied().unwrap_or(left);
            next.push(Digest32V0::hash(
                b"trnm.state-sync.chunk-node.v0",
                &[&left.0, &right.0],
            ));
        }
        level = next;
    }
    level[0]
}

pub trait StateRootRecomputerV0 {
    type Error: Error + Send + Sync + 'static;

    fn recompute_state_root<'a, I>(
        &self,
        schema_digest: Digest32V0,
        ordered_chunks: I,
    ) -> Result<Digest32V0, Self::Error>
    where
        I: IntoIterator<Item = &'a [u8]>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StagingIdentityV0 {
    pub generation: u64,
    pub staging_digest: Digest32V0,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InstallReceiptV0 {
    pub previous_root: Digest32V0,
    pub installed_root: Digest32V0,
    pub installed_height: u64,
    pub generation: u64,
    pub durable_receipt_digest: Digest32V0,
}

pub trait NonDestructiveInstallTargetV0 {
    type Error: Error + Send + Sync + 'static;

    fn begin_staging(
        &mut self,
        manifest: &SnapshotManifestV0,
    ) -> Result<StagingIdentityV0, Self::Error>;
    fn write_chunk(
        &mut self,
        staging: StagingIdentityV0,
        index: u32,
        bytes: &[u8],
    ) -> Result<(), Self::Error>;
    fn commit_staging_cas(
        &mut self,
        staging: StagingIdentityV0,
        expected_current_root: Digest32V0,
        manifest: &SnapshotManifestV0,
    ) -> Result<InstallReceiptV0, Self::Error>;
    fn abort_staging(&mut self, staging: StagingIdentityV0) -> Result<(), Self::Error>;
}

pub struct StateSyncSessionV0 {
    trust_path: VerifiedTrustPathV0,
    manifest: SnapshotManifestV0,
    chunks: BTreeMap<u32, SnapshotChunkV0>,
    received_bytes: u64,
}

impl StateSyncSessionV0 {
    pub fn new(
        trust_path: VerifiedTrustPathV0,
        manifest: SnapshotManifestV0,
    ) -> Result<Self, StateSyncErrorV0> {
        manifest.validate(&trust_path)?;
        Ok(Self {
            trust_path,
            manifest,
            chunks: BTreeMap::new(),
            received_bytes: 0,
        })
    }

    pub fn accept_chunk(&mut self, chunk: SnapshotChunkV0) -> Result<(), StateSyncErrorV0> {
        chunk.validate(&self.manifest)?;
        if let Some(existing) = self.chunks.get(&chunk.index) {
            return if existing == &chunk {
                Ok(())
            } else {
                Err(StateSyncErrorV0::ChunkSubstitution)
            };
        }
        let next_received_bytes = self
            .received_bytes
            .checked_add(
                u64::try_from(chunk.bytes.len()).map_err(|_| StateSyncErrorV0::SnapshotTooLarge)?,
            )
            .ok_or(StateSyncErrorV0::SnapshotTooLarge)?;
        if next_received_bytes > self.manifest.total_bytes
            || next_received_bytes > MAX_SNAPSHOT_BYTES_V0
        {
            return Err(StateSyncErrorV0::SnapshotTooLarge);
        }
        self.chunks.insert(chunk.index, chunk);
        self.received_bytes = next_received_bytes;
        Ok(())
    }

    #[must_use]
    pub fn missing_chunks(&self) -> Vec<u32> {
        (0..self.manifest.chunk_count)
            .filter(|index| !self.chunks.contains_key(index))
            .collect()
    }

    pub fn verify_complete<R>(
        &self,
        recomputer: &R,
    ) -> Result<VerifiedSnapshotV0, StateSyncHostErrorV0<R::Error>>
    where
        R: StateRootRecomputerV0,
    {
        if self.chunks.len() != self.manifest.chunk_count as usize
            || self.received_bytes != self.manifest.total_bytes
        {
            return Err(StateSyncHostErrorV0::Protocol(
                StateSyncErrorV0::IncompleteSnapshot,
            ));
        }
        let ordered: Vec<&SnapshotChunkV0> = (0..self.manifest.chunk_count)
            .map(|index| {
                self.chunks
                    .get(&index)
                    .ok_or(StateSyncHostErrorV0::Protocol(
                        StateSyncErrorV0::IncompleteSnapshot,
                    ))
            })
            .collect::<Result<_, _>>()?;
        let digests: Vec<Digest32V0> = ordered.iter().map(|chunk| chunk.chunk_digest).collect();
        if chunk_merkle_root_v0(&digests) != self.manifest.chunk_root {
            return Err(StateSyncHostErrorV0::Protocol(
                StateSyncErrorV0::ChunkRootMismatch,
            ));
        }
        let state_root = recomputer
            .recompute_state_root(
                self.manifest.schema_digest,
                ordered.iter().map(|chunk| chunk.bytes.as_slice()),
            )
            .map_err(StateSyncHostErrorV0::StateRoot)?;
        if state_root != self.manifest.state_root {
            return Err(StateSyncHostErrorV0::Protocol(
                StateSyncErrorV0::StateRootMismatch,
            ));
        }
        Ok(VerifiedSnapshotV0 {
            manifest_digest: self.manifest.manifest_digest,
            trust_path_digest: self.trust_path.path_digest,
            state_root,
            chunk_root: self.manifest.chunk_root,
            height: self.manifest.height,
            epoch: self.manifest.epoch,
        })
    }

    pub fn install<R, T>(
        &self,
        recomputer: &R,
        target: &mut T,
        expected_current_root: Digest32V0,
    ) -> Result<InstallReceiptV0, StateSyncInstallErrorV0<R::Error, T::Error>>
    where
        R: StateRootRecomputerV0,
        T: NonDestructiveInstallTargetV0,
    {
        self.verify_complete(recomputer)
            .map_err(StateSyncInstallErrorV0::Verification)?;
        if expected_current_root == Digest32V0([0; 32]) {
            return Err(StateSyncInstallErrorV0::Protocol(
                StateSyncErrorV0::InvalidExpectedCurrentRoot,
            ));
        }
        let staging = target
            .begin_staging(&self.manifest)
            .map_err(StateSyncInstallErrorV0::Target)?;
        // Never pass an untrusted staging identity to writes, commit, or abort.
        // The target must reconcile any allocation made before this rejection.
        if staging.generation == 0 || staging.staging_digest == Digest32V0([0; 32]) {
            return Err(StateSyncInstallErrorV0::Protocol(
                StateSyncErrorV0::InvalidStagingIdentity,
            ));
        }
        for index in 0..self.manifest.chunk_count {
            let chunk = match self.chunks.get(&index) {
                Some(chunk) => chunk,
                None => {
                    if let Err(abort_error) = target.abort_staging(staging) {
                        return Err(StateSyncInstallErrorV0::Abort(abort_error));
                    }
                    return Err(StateSyncInstallErrorV0::Protocol(
                        StateSyncErrorV0::IncompleteSnapshot,
                    ));
                }
            };
            if let Err(write_error) = target.write_chunk(staging, index, &chunk.bytes) {
                return match target.abort_staging(staging) {
                    Ok(()) => Err(StateSyncInstallErrorV0::Write(write_error)),
                    Err(abort_error) => Err(StateSyncInstallErrorV0::WriteAndAbort {
                        write_error,
                        abort_error,
                    }),
                };
            }
        }

        // Once commit starts, the caller must treat any error or receipt
        // mismatch as uncertain durable state. Never issue a destructive abort.
        let receipt = target
            .commit_staging_cas(staging, expected_current_root, &self.manifest)
            .map_err(StateSyncInstallErrorV0::CommitUncertain)?;
        if receipt.previous_root != expected_current_root
            || receipt.installed_root != self.manifest.state_root
            || receipt.installed_height != self.manifest.height
            || receipt.generation != staging.generation
            || receipt.durable_receipt_digest == Digest32V0([0; 32])
        {
            return Err(StateSyncInstallErrorV0::CommitReceiptMismatch(
                StateSyncErrorV0::InstallReceiptMismatch,
            ));
        }
        Ok(receipt)
    }
}

/// An immutable result issued only after all chunks and the state root verify.
///
/// Cloning or copying this value preserves its verified facts. Accessors return
/// values, not mutable access to the receipt. It does not grant storage deletion,
/// make an untrusted root recomputer authoritative, or prove physical durability.
///
/// ```compile_fail,E0451
/// use trnm_state_sync_v0::{Digest32V0, VerifiedSnapshotV0};
/// let digest = Digest32V0([1; 32]);
/// let forged = VerifiedSnapshotV0 {
///     manifest_digest: digest, trust_path_digest: digest, state_root: digest,
///     chunk_root: digest, height: 1, epoch: 1,
/// };
/// ```
///
/// ```compile_fail,E0616
/// use trnm_state_sync_v0::{Digest32V0, VerifiedSnapshotV0};
/// fn retarget(snapshot: &mut VerifiedSnapshotV0) {
///     snapshot.state_root = Digest32V0([9; 32]);
/// }
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedSnapshotV0 {
    manifest_digest: Digest32V0,
    trust_path_digest: Digest32V0,
    state_root: Digest32V0,
    chunk_root: Digest32V0,
    height: u64,
    epoch: u64,
}

impl VerifiedSnapshotV0 {
    #[must_use]
    pub const fn manifest_digest(&self) -> Digest32V0 {
        self.manifest_digest
    }

    #[must_use]
    pub const fn trust_path_digest(&self) -> Digest32V0 {
        self.trust_path_digest
    }

    #[must_use]
    pub const fn state_root(&self) -> Digest32V0 {
        self.state_root
    }

    #[must_use]
    pub const fn chunk_root(&self) -> Digest32V0 {
        self.chunk_root
    }

    #[must_use]
    pub const fn height(&self) -> u64 {
        self.height
    }

    #[must_use]
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StateSyncErrorV0 {
    InvalidTrustAnchor,
    TrustPathOutOfBounds,
    InvalidTrustPath,
    ManifestTrustMismatch,
    InvalidManifest,
    InvalidChunk,
    ChunkSubstitution,
    SnapshotTooLarge,
    IncompleteSnapshot,
    ChunkRootMismatch,
    StateRootMismatch,
    InvalidExpectedCurrentRoot,
    InvalidStagingIdentity,
    InstallReceiptMismatch,
}

impl fmt::Display for StateSyncErrorV0 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidTrustAnchor => "invalid weak-subjectivity anchor",
            Self::TrustPathOutOfBounds => "checkpoint trust path is outside the protocol bound",
            Self::InvalidTrustPath => "checkpoint trust path is discontinuous or misbound",
            Self::ManifestTrustMismatch => {
                "snapshot manifest does not match the verified checkpoint"
            }
            Self::InvalidManifest => "snapshot manifest violates closed bounds or digest binding",
            Self::InvalidChunk => "snapshot chunk violates manifest bounds or digest binding",
            Self::ChunkSubstitution => "a retained chunk index was supplied with different bytes",
            Self::SnapshotTooLarge => "snapshot exceeds the declared or protocol byte bound",
            Self::IncompleteSnapshot => "snapshot is incomplete",
            Self::ChunkRootMismatch => "snapshot chunk Merkle root mismatch",
            Self::StateRootMismatch => "recomputed application state root mismatch",
            Self::InvalidExpectedCurrentRoot => "expected current state root is invalid",
            Self::InvalidStagingIdentity => "snapshot staging identity is invalid",
            Self::InstallReceiptMismatch => "non-destructive install receipt mismatch",
        })
    }
}

impl Error for StateSyncErrorV0 {}

#[derive(Debug)]
pub enum StateSyncHostErrorV0<AdapterError> {
    Protocol(StateSyncErrorV0),
    CheckpointProof(AdapterError),
    StateRoot(AdapterError),
}

impl<A: fmt::Display> fmt::Display for StateSyncHostErrorV0<A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Protocol(error) => write!(f, "state-sync protocol rejected input: {error}"),
            Self::CheckpointProof(error) => {
                write!(f, "checkpoint proof verification failed: {error}")
            }
            Self::StateRoot(error) => write!(f, "state-root recomputation failed: {error}"),
        }
    }
}

impl<A> Error for StateSyncHostErrorV0<A> where A: Error + 'static {}

#[derive(Debug)]
pub enum StateSyncInstallErrorV0<RootError, TargetError> {
    Protocol(StateSyncErrorV0),
    Verification(StateSyncHostErrorV0<RootError>),
    Target(TargetError),
    Write(TargetError),
    Abort(TargetError),
    WriteAndAbort {
        write_error: TargetError,
        abort_error: TargetError,
    },
    CommitUncertain(TargetError),
    CommitReceiptMismatch(StateSyncErrorV0),
}

impl<R: fmt::Display, T: fmt::Display> fmt::Display for StateSyncInstallErrorV0<R, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Protocol(error) => write!(f, "state-sync installation rejected: {error}"),
            Self::Verification(error) => write!(f, "snapshot verification failed: {error}"),
            Self::Target(error) => write!(f, "staging target failed before writes: {error}"),
            Self::Write(error) => write!(f, "staging write failed and was aborted: {error}"),
            Self::Abort(error) => write!(f, "staging abort failed: {error}"),
            Self::WriteAndAbort {
                write_error,
                abort_error,
            } => write!(
                f,
                "staging write failed ({write_error}) and abort also failed ({abort_error})"
            ),
            Self::CommitUncertain(error) => {
                write!(f, "state-sync commit outcome is uncertain: {error}")
            }
            Self::CommitReceiptMismatch(error) => {
                write!(f, "state-sync commit receipt is untrusted: {error}")
            }
        }
    }
}

impl<R, T> Error for StateSyncInstallErrorV0<R, T>
where
    R: Error + 'static,
    T: Error + 'static,
{
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::convert::Infallible;

    fn d(byte: u8) -> Digest32V0 {
        Digest32V0([byte; 32])
    }

    struct AcceptProof;

    impl CheckpointProofVerifierV0 for AcceptProof {
        type Error = Infallible;

        fn verify_link(&self, _link: &CheckpointLinkV0) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    struct HashRoot;

    impl StateRootRecomputerV0 for HashRoot {
        type Error = Infallible;

        fn recompute_state_root<'a, I>(
            &self,
            schema_digest: Digest32V0,
            ordered_chunks: I,
        ) -> Result<Digest32V0, Self::Error>
        where
            I: IntoIterator<Item = &'a [u8]>,
        {
            let chunks: Vec<&[u8]> = ordered_chunks.into_iter().collect();
            let mut h = Sha256::new();
            h.update(b"test.state-root");
            h.update(schema_digest.0);
            for chunk in chunks {
                h.update((chunk.len() as u64).to_be_bytes());
                h.update(chunk);
            }
            Ok(Digest32V0(h.finalize().into()))
        }
    }

    fn link(anchor: WeakSubjectivityAnchorV0, state_root: Digest32V0) -> CheckpointLinkV0 {
        let mut value = CheckpointLinkV0 {
            chain_id: anchor.chain_id,
            protocol_digest: anchor.protocol_digest,
            epoch: anchor.epoch,
            height: anchor.height + 1,
            state_root,
            validator_set_digest: anchor.validator_set_digest,
            next_validator_set_digest: anchor.validator_set_digest,
            parent_checkpoint_digest: anchor.checkpoint_digest,
            finality_proof_digest: d(9),
            checkpoint_digest: d(0),
        };
        value.checkpoint_digest = value.canonical_digest();
        value
    }

    fn fixture() -> (
        VerifiedTrustPathV0,
        SnapshotManifestV0,
        Vec<SnapshotChunkV0>,
    ) {
        let schema = d(7);
        let chunk_bytes = [b"alpha".as_slice(), b"beta".as_slice()];
        let state_root = HashRoot.recompute_state_root(schema, chunk_bytes).unwrap();
        let anchor = WeakSubjectivityAnchorV0 {
            chain_id: d(1),
            protocol_digest: d(2),
            epoch: 3,
            height: 4,
            checkpoint_digest: d(5),
            validator_set_digest: d(6),
        };
        let terminal = link(anchor, state_root);
        let trust = verify_trust_path_v0(&AcceptProof, anchor, &[terminal]).unwrap();
        let mut manifest = SnapshotManifestV0 {
            chain_id: anchor.chain_id,
            protocol_digest: anchor.protocol_digest,
            height: terminal.height,
            epoch: terminal.epoch,
            state_root,
            chunk_root: d(0),
            chunk_count: 2,
            maximum_chunk_bytes: 1024,
            total_bytes: 9,
            schema_digest: schema,
            checkpoint_digest: terminal.checkpoint_digest,
            manifest_digest: d(0),
        };
        let binding = manifest.chunk_binding_digest();
        let chunks: Vec<SnapshotChunkV0> = chunk_bytes
            .iter()
            .enumerate()
            .map(|(index, bytes)| SnapshotChunkV0 {
                manifest_digest: binding,
                index: index as u32,
                bytes: bytes.to_vec(),
                chunk_digest: SnapshotChunkV0::canonical_digest(binding, index as u32, bytes),
            })
            .collect();
        manifest.chunk_root = chunk_merkle_root_v0(
            &chunks
                .iter()
                .map(|chunk| chunk.chunk_digest)
                .collect::<Vec<_>>(),
        );
        manifest.manifest_digest = manifest.canonical_digest();
        (trust, manifest, chunks)
    }

    #[test]
    fn trust_path_rejects_network_selected_discontinuity() {
        let anchor = WeakSubjectivityAnchorV0 {
            chain_id: d(1),
            protocol_digest: d(2),
            epoch: 3,
            height: 4,
            checkpoint_digest: d(5),
            validator_set_digest: d(6),
        };
        let mut invalid = link(anchor, d(99));
        invalid.parent_checkpoint_digest = d(99);
        invalid.checkpoint_digest = invalid.canonical_digest();
        assert!(matches!(
            verify_trust_path_v0(&AcceptProof, anchor, &[invalid]),
            Err(StateSyncHostErrorV0::Protocol(
                StateSyncErrorV0::InvalidTrustPath
            ))
        ));
    }

    #[test]
    fn chunk_substitution_and_incompleteness_fail_closed() {
        let (trust, manifest, chunks) = fixture();
        let mut session = StateSyncSessionV0::new(trust, manifest).unwrap();
        session.accept_chunk(chunks[0].clone()).unwrap();
        let mut substituted = chunks[0].clone();
        substituted.bytes.push(0);
        substituted.chunk_digest = SnapshotChunkV0::canonical_digest(
            substituted.manifest_digest,
            substituted.index,
            &substituted.bytes,
        );
        assert_eq!(
            session.accept_chunk(substituted).unwrap_err(),
            StateSyncErrorV0::ChunkSubstitution
        );
        assert!(matches!(
            session.verify_complete(&HashRoot),
            Err(StateSyncHostErrorV0::Protocol(
                StateSyncErrorV0::IncompleteSnapshot
            ))
        ));
    }

    #[derive(Debug)]
    struct TargetFailure;

    impl fmt::Display for TargetFailure {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("injected target failure")
        }
    }

    impl Error for TargetFailure {}

    struct TrackingTarget {
        aborts: u32,
        commit_fails: bool,
        bad_receipt: bool,
    }

    impl NonDestructiveInstallTargetV0 for TrackingTarget {
        type Error = TargetFailure;

        fn begin_staging(
            &mut self,
            _manifest: &SnapshotManifestV0,
        ) -> Result<StagingIdentityV0, Self::Error> {
            Ok(StagingIdentityV0 {
                generation: 7,
                staging_digest: d(40),
            })
        }

        fn write_chunk(
            &mut self,
            _staging: StagingIdentityV0,
            _index: u32,
            _bytes: &[u8],
        ) -> Result<(), Self::Error> {
            Ok(())
        }

        fn commit_staging_cas(
            &mut self,
            staging: StagingIdentityV0,
            expected_current_root: Digest32V0,
            manifest: &SnapshotManifestV0,
        ) -> Result<InstallReceiptV0, Self::Error> {
            if self.commit_fails {
                return Err(TargetFailure);
            }
            Ok(InstallReceiptV0 {
                previous_root: expected_current_root,
                installed_root: if self.bad_receipt {
                    d(99)
                } else {
                    manifest.state_root
                },
                installed_height: manifest.height,
                generation: staging.generation,
                durable_receipt_digest: d(41),
            })
        }

        fn abort_staging(&mut self, _staging: StagingIdentityV0) -> Result<(), Self::Error> {
            self.aborts += 1;
            Ok(())
        }
    }

    fn complete_session() -> StateSyncSessionV0 {
        let (trust, manifest, chunks) = fixture();
        let mut session = StateSyncSessionV0::new(trust, manifest).unwrap();
        for chunk in chunks {
            session.accept_chunk(chunk).unwrap();
        }
        session
    }

    #[test]
    fn oversized_chunk_attempt_does_not_mutate_session_accounting() {
        let (trust, mut manifest, _) = fixture();
        manifest.total_bytes = u64::from(manifest.chunk_count);
        manifest.manifest_digest = manifest.canonical_digest();
        let binding = manifest.chunk_binding_digest();
        let bytes = b"alpha".to_vec();
        let chunk = SnapshotChunkV0 {
            manifest_digest: binding,
            index: 0,
            chunk_digest: SnapshotChunkV0::canonical_digest(binding, 0, &bytes),
            bytes,
        };
        let mut session = StateSyncSessionV0::new(trust, manifest).unwrap();
        assert_eq!(
            session.accept_chunk(chunk).unwrap_err(),
            StateSyncErrorV0::SnapshotTooLarge
        );
        assert_eq!(session.received_bytes, 0);
        assert_eq!(session.missing_chunks(), vec![0, 1]);
    }

    #[test]
    fn commit_error_never_triggers_destructive_abort() {
        let session = complete_session();
        let mut target = TrackingTarget {
            aborts: 0,
            commit_fails: true,
            bad_receipt: false,
        };
        assert!(matches!(
            session.install(&HashRoot, &mut target, d(50)),
            Err(StateSyncInstallErrorV0::CommitUncertain(_))
        ));
        assert_eq!(target.aborts, 0);
    }

    #[test]
    fn commit_receipt_mismatch_never_triggers_destructive_abort() {
        let session = complete_session();
        let mut target = TrackingTarget {
            aborts: 0,
            commit_fails: false,
            bad_receipt: true,
        };
        assert!(matches!(
            session.install(&HashRoot, &mut target, d(50)),
            Err(StateSyncInstallErrorV0::CommitReceiptMismatch(
                StateSyncErrorV0::InstallReceiptMismatch
            ))
        ));
        assert_eq!(target.aborts, 0);
    }
}
