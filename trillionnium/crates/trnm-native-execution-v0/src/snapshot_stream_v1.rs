//! Verify native snapshot chunks against an independently trusted strict PoCO
//! proof, using the actual native Borsh/JMT implementation rather than a hash
//! fixture. This is read verification, not whole-node installation or recovery.

use sha2::{Digest, Sha256};
use std::{
    error::Error,
    fmt,
    io::{self, Read},
};
use trnm_consensus_crypto::StrictFinalityProofV0;
use trnm_finality_types::hash_domain;
use trnm_native_application::NativeSnapshotManifestV0;

use crate::{NativeApplicationConfigV0, NativeExecutionStoreV0};

const CHUNK_DOMAIN: &str = "trnm.native-application.snapshot-chunk.v0";
const MANIFEST_DOMAIN: &str = "trnm.native-application.snapshot-manifest.v0";

/// Local verification budgets, not new transaction or consensus validity rules.
/// Decoded JMT collections remain resident; this is not constant-memory state
/// restoration. A transport must also bound each chunk before allocating it.
#[derive(Clone, Copy, Debug)]
pub struct NativeSnapshotReadLimitsV1 {
    pub(crate) maximum_bytes: u64,
    maximum_entries: u32,
    maximum_record_bytes: usize,
}

impl NativeSnapshotReadLimitsV1 {
    pub fn new(
        maximum_bytes: u64,
        maximum_entries: u32,
        maximum_record_bytes: usize,
    ) -> Result<Self, NativeSnapshotStreamErrorV1> {
        if maximum_bytes == 0
            || maximum_bytes > 4 * 1024 * 1024 * 1024_u64
            || maximum_entries == 0
            || maximum_entries > 2_000_000
            || maximum_record_bytes == 0
            || maximum_record_bytes > 16 * 1024 * 1024
            || maximum_record_bytes as u64 > maximum_bytes
        {
            return Err(NativeSnapshotStreamErrorV1::InvalidLimits);
        }
        Ok(Self {
            maximum_bytes,
            maximum_entries,
            maximum_record_bytes,
        })
    }
}

#[derive(Debug)]
pub enum NativeSnapshotStreamErrorV1 {
    InvalidLimits,
    ContextMismatch,
    ManifestMismatch,
    ChunkMismatch,
    Incomplete,
    TrailingInput,
    LimitExceeded,
    Transport(io::Error),
    InvalidSnapshot(anyhow::Error),
}
impl fmt::Display for NativeSnapshotStreamErrorV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimits => f.write_str("invalid local native snapshot read limits"),
            Self::ContextMismatch => {
                f.write_str("native snapshot does not bind trusted finality/context")
            }
            Self::ManifestMismatch => {
                f.write_str("native snapshot manifest does not bind exact bytes")
            }
            Self::ChunkMismatch => {
                f.write_str("native snapshot chunk length/index/digest mismatch")
            }
            Self::Incomplete => f.write_str("native snapshot transport ended early"),
            Self::TrailingInput => f.write_str("native snapshot has trailing transport input"),
            Self::LimitExceeded => {
                f.write_str("native snapshot exceeds local verification resources")
            }
            Self::Transport(error) => write!(f, "native snapshot transport unavailable: {error}"),
            Self::InvalidSnapshot(error) => {
                write!(f, "native snapshot verification failed: {error}")
            }
        }
    }
}
impl Error for NativeSnapshotStreamErrorV1 {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Transport(error) => Some(error),
            Self::InvalidSnapshot(error) => Some(error.as_ref()),
            _ => None,
        }
    }
}

/// Read-only result. Only the current root, block, height and context are
/// authenticated by finality. Historical roots are internally audited, not
/// individually certified. The local manifest's commit_id is intentionally not
/// exposed as trusted data. Replay floors, Safety and signer state are absent.
///
/// ```compile_fail
/// use trnm_native_execution_v0::VerifiedNativeSnapshotReadV1;
/// fn require_clone<T: Clone>() {}
/// require_clone::<VerifiedNativeSnapshotReadV1>();
/// ```
#[derive(Debug)]
pub struct VerifiedNativeSnapshotReadV1 {
    height: u64,
    block_id: [u8; 32],
    state_root: [u8; 32],
    snapshot_digest: [u8; 32],
    finality_proof_id: [u8; 32],
    total_bytes: u64,
}
impl VerifiedNativeSnapshotReadV1 {
    pub const fn height(&self) -> u64 {
        self.height
    }
    pub const fn block_id(&self) -> &[u8; 32] {
        &self.block_id
    }
    pub const fn state_root(&self) -> &[u8; 32] {
        &self.state_root
    }
    pub const fn snapshot_digest(&self) -> &[u8; 32] {
        &self.snapshot_digest
    }
    pub const fn finality_proof_id(&self) -> &[u8; 32] {
        &self.finality_proof_id
    }
    pub const fn total_bytes(&self) -> u64 {
        self.total_bytes
    }
}

struct ChunkReader<'a, I> {
    input: I,
    manifest: &'a NativeSnapshotManifestV0,
    chunk: Vec<u8>,
    offset: usize,
    next: usize,
    bytes: u64,
    digest: Sha256,
    exhausted: bool,
    failure: Option<NativeSnapshotStreamErrorV1>,
}
impl<I: Iterator<Item = io::Result<Vec<u8>>>> ChunkReader<'_, I> {
    fn fail(&mut self, failure: NativeSnapshotStreamErrorV1) -> io::Error {
        self.failure = Some(failure);
        io::Error::other("native chunk verification failed; see retained typed result")
    }
}
impl<I: Iterator<Item = io::Result<Vec<u8>>>> Read for ChunkReader<'_, I> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        if self.failure.is_some() {
            return Err(io::Error::other("native chunk reader is poisoned"));
        }
        if self.offset == self.chunk.len() {
            // Drop the previous allocation before requesting the next chunk.
            self.chunk = Vec::new();
            self.offset = 0;
            if self.next == self.manifest.chunks().len() {
                if !self.exhausted {
                    match self.input.next() {
                        Some(Err(error)) => {
                            return Err(self.fail(NativeSnapshotStreamErrorV1::Transport(error)))
                        }
                        Some(Ok(_)) => {
                            return Err(self.fail(NativeSnapshotStreamErrorV1::TrailingInput))
                        }
                        None => self.exhausted = true,
                    }
                }
                return Ok(0);
            }
            let bytes = match self.input.next() {
                Some(Ok(bytes)) => bytes,
                Some(Err(error)) => {
                    return Err(self.fail(NativeSnapshotStreamErrorV1::Transport(error)))
                }
                None => return Err(self.fail(NativeSnapshotStreamErrorV1::Incomplete)),
            };
            let descriptor = &self.manifest.chunks()[self.next];
            let index = descriptor.index().to_be_bytes();
            if bytes.len() != descriptor.byte_length() as usize
                || bytes.len() > self.manifest.request().maximum_chunk_bytes() as usize
                || hash_domain(CHUNK_DOMAIN, &[&index, &bytes]) != descriptor.digest().into_bytes()
            {
                return Err(self.fail(NativeSnapshotStreamErrorV1::ChunkMismatch));
            }
            let Some(total) = self.bytes.checked_add(bytes.len() as u64) else {
                return Err(self.fail(NativeSnapshotStreamErrorV1::LimitExceeded));
            };
            if total > self.manifest.total_bytes() {
                return Err(self.fail(NativeSnapshotStreamErrorV1::ManifestMismatch));
            }
            self.bytes = total;
            self.next += 1;
            self.chunk = bytes;
        }
        let count = output.len().min(self.chunk.len() - self.offset);
        output[..count].copy_from_slice(&self.chunk[self.offset..self.offset + count]);
        self.digest.update(&output[..count]);
        self.offset += count;
        Ok(count)
    }
}

/// Source chunks use native-v0 snapshot domains, not generic M13 chunk domains.
/// The strict proof must already have been checked against a trusted earlier
/// context. This function rebinds that proof to `config` and never lets the
/// incoming manifest choose a validator set or a trust anchor.
///
/// No install target, signer, consensus owner, replay floor or mutable source is
/// accepted. Every error leaves authoritative state untouched. In particular,
/// local budget/transport failure is not a transaction-invalidity decision.
pub fn verify_native_snapshot_stream_v1<I>(
    config: &NativeApplicationConfigV0,
    proof: &StrictFinalityProofV0,
    manifest: &NativeSnapshotManifestV0,
    input: I,
    limits: NativeSnapshotReadLimitsV1,
) -> Result<VerifiedNativeSnapshotReadV1, NativeSnapshotStreamErrorV1>
where
    I: IntoIterator<Item = io::Result<Vec<u8>>>,
{
    let header = proof.proof().finalized_block().header();
    let set = config.validator_set_v0();
    let head = manifest.request().head();
    if header.genesis_hash() != set.genesis_hash()
        || header.chain_id() != set.chain_id()
        || header.protocol_version() != set.protocol_version()
        || header.epoch() != set.epoch()
        || header.validator_set_id() != set.id()
        || header.consensus_parameters_hash() != config.consensus_parameters_v0().hash()
        || header.height().get() != head.height().get()
        || header.id().as_bytes() != head.block_id().as_bytes()
        || header.state_root().as_bytes() != head.state_root().as_bytes()
    {
        return Err(NativeSnapshotStreamErrorV1::ContextMismatch);
    }
    // Re-run the native manifest's constructor contract without trusting cached
    // total lengths or transport metadata. It does not certify local commit_id.
    let rebuilt = NativeSnapshotManifestV0::new(
        manifest.request().clone(),
        manifest.chunks().to_vec(),
        manifest.manifest_digest(),
    )
    .map_err(|_| NativeSnapshotStreamErrorV1::ManifestMismatch)?;
    if rebuilt.total_bytes() != manifest.total_bytes() {
        return Err(NativeSnapshotStreamErrorV1::ManifestMismatch);
    }
    if manifest.total_bytes() > limits.maximum_bytes {
        return Err(NativeSnapshotStreamErrorV1::LimitExceeded);
    }
    let mut reader = ChunkReader {
        input: input.into_iter(),
        manifest,
        chunk: Vec::new(),
        offset: 0,
        next: 0,
        bytes: 0,
        digest: Sha256::new(),
        exhausted: false,
        failure: None,
    };
    let decoded = config.decode_snapshot_reader_v1(
        &mut reader,
        crate::store::SnapshotReadLimitsV1 {
            maximum_entries: limits.maximum_entries,
            maximum_record_bytes: limits.maximum_record_bytes,
        },
    );
    if let Some(error) = reader.failure.take() {
        return Err(error);
    }
    let store = decoded.map_err(|error| {
        if error.chain().any(|cause| {
            cause
                .downcast_ref::<crate::store::SnapshotReadLimitV1>()
                .is_some()
                || cause.downcast_ref::<io::Error>().is_some_and(|error| {
                    error
                        .get_ref()
                        .is_some_and(|inner| inner.is::<crate::store::SnapshotReadLimitV1>())
                })
        }) {
            NativeSnapshotStreamErrorV1::LimitExceeded
        } else {
            NativeSnapshotStreamErrorV1::InvalidSnapshot(error)
        }
    })?;
    if !reader.exhausted
        || reader.next != manifest.chunks().len()
        || reader.bytes != manifest.total_bytes()
        || reader.offset != reader.chunk.len()
    {
        return Err(NativeSnapshotStreamErrorV1::Incomplete);
    }
    let digest: [u8; 32] = reader.digest.finalize().into();
    let chunk_digests = manifest
        .chunks()
        .iter()
        .map(|chunk| chunk.digest().into_bytes())
        .collect::<Vec<_>>();
    let mut parts: Vec<&[u8]> = Vec::with_capacity(chunk_digests.len() + 1);
    parts.push(&digest);
    parts.extend(chunk_digests.iter().map(<[u8; 32]>::as_slice));
    if hash_domain(MANIFEST_DOMAIN, &parts) != manifest.manifest_digest().into_bytes() {
        return Err(NativeSnapshotStreamErrorV1::ManifestMismatch);
    }
    let verify_root = || -> anyhow::Result<()> {
        anyhow::ensure!(
            store.parent_version_v0()? == header.height().get(),
            "snapshot version mismatch"
        );
        anyhow::ensure!(
            store.parent_root_v0()?.0 == *header.state_root().as_bytes(),
            "snapshot root differs from strict finality"
        );
        let lifecycle_key = crate::auth_tree::validator_state_key()?;
        let lifecycle_value = store
            .verified_raw_value_v0(header.height().get(), &lifecycle_key)?
            .ok_or_else(|| anyhow::anyhow!("snapshot lacks authenticated validator lifecycle"))?;
        let live = std::collections::BTreeMap::from([(lifecycle_key, lifecycle_value)]);
        let lifecycle =
            crate::complete::load_validator_lifecycle_from_live_v0(&live, header.height().get())?;
        anyhow::ensure!(
            lifecycle.chain_id == config.chain_id_v0(),
            "lifecycle chain mismatch"
        );
        anyhow::ensure!(
            lifecycle.authorized_signers_hash_hex
                == hex::encode(config.signer_policy_commitment_v0()),
            "lifecycle signer policy mismatch"
        );
        crate::complete::validate_application_validator_projection_v0(
            set,
            &lifecycle.active_validators,
        )?;
        Ok(())
    };
    verify_root().map_err(NativeSnapshotStreamErrorV1::InvalidSnapshot)?;
    Ok(VerifiedNativeSnapshotReadV1 {
        height: header.height().get(),
        block_id: *header.id().as_bytes(),
        state_root: *header.state_root().as_bytes(),
        snapshot_digest: digest,
        finality_proof_id: *proof.proof().id().as_bytes(),
        total_bytes: manifest.total_bytes(),
    })
}
