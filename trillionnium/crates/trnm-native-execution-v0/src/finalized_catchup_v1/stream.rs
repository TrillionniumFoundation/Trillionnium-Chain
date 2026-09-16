//! Candidate length-delimited transfer adapter; not a consensus wire version.
//!
//! A stream supplies neither a trust anchor nor validator keys. The receiving
//! session already owns a strictly verified target and a recovered application.
//! Only the existing per-block finality/execution/commit path can advance it.
//! Snapshot equality and an exact trailer/EOF are required before owner release.
//! Error drops the session: a finalized prefix may remain durable and must be
//! resumed by reopening with its real proof. No network error undoes finality.

use super::*;
use crate::PinnedNativeSnapshotExportV1;
use std::io::{self, Read, Write};
use trnm_consensus_types::{
    decode_block_header_v0_exact, ApplicationPayloadV0, MAX_CEV0_ROOT_BYTES_V0,
};
use trnm_native_application::{
    ApplicationCommitIdV0, NativeSnapshotChunkV0, NativeSnapshotRequestV0, MAX_SNAPSHOT_CHUNKS_V0,
};

const MAGIC: &[u8; 8] = b"TRNMCU01";
const END: &[u8; 8] = b"ENDNCU01";
const MANIFEST_FIXED: usize = 144;
const DESCRIPTOR_BYTES: usize = 40;
const MAX_MANIFEST_BYTES: usize = MANIFEST_FIXED + DESCRIPTOR_BYTES * MAX_SNAPSHOT_CHUNKS_V0;

/// Local transfer limits, in addition to the existing execution, signature and
/// snapshot budgets. These do not change block validity. They bound retained
/// frame allocations and wire work, not native decoded state or full-history I/O.
#[derive(Debug, Clone, Copy)]
pub struct NativeCatchupStreamLimitsV1 {
    maximum_bytes: u64,
    maximum_frame_bytes: usize,
    maximum_blocks: u32,
}
impl NativeCatchupStreamLimitsV1 {
    pub fn new(
        maximum_bytes: u64,
        maximum_frame_bytes: usize,
        maximum_blocks: u32,
    ) -> Result<Self, NativeCatchupStreamErrorV1> {
        if maximum_bytes == 0
            || maximum_bytes > 16 * 1024 * 1024 * 1024
            || maximum_frame_bytes == 0
            || maximum_frame_bytes > MAX_CEV0_ROOT_BYTES_V0
            || maximum_blocks > 4096
        {
            return Err(NativeCatchupStreamErrorV1::Limit);
        }
        Ok(Self {
            maximum_bytes,
            maximum_frame_bytes,
            maximum_blocks,
        })
    }
}

#[derive(Debug)]
pub enum NativeCatchupStreamErrorV1 {
    Limit,
    Framing,
    Context,
    Transport(io::Error),
    Source(NativeApplicationExecutionErrorV0),
    SourceProof(PocoFinalityCommitErrorV0),
    Catchup(NativeCatchupErrorV1),
}
impl fmt::Display for NativeCatchupStreamErrorV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport(e) => write!(f, "catch-up transport unavailable: {e}"),
            Self::Source(e) => write!(f, "catch-up source unavailable: {e}"),
            Self::SourceProof(e) => write!(f, "catch-up source proof rejected: {e}"),
            Self::Catchup(e) => write!(f, "catch-up owner must reopen: {e}"),
            other => write!(f, "native catch-up stream: {other:?}"),
        }
    }
}
impl Error for NativeCatchupStreamErrorV1 {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Transport(e) => Some(e),
            Self::Source(e) => Some(e),
            Self::SourceProof(e) => Some(e),
            Self::Catchup(e) => Some(e),
            _ => None,
        }
    }
}
type StreamResult<T> = Result<T, NativeCatchupStreamErrorV1>;

/// One freshly read, strictly finality-verified source block. No public raw
/// constructor, no peer-supplied local commit ID. The receiver re-verifies all
/// bytes: possession of this transfer object alone grants no receiver authority.
pub struct NativeCatchupBlockV1 {
    header: BlockHeader,
    payload: Vec<u8>,
    proof: Vec<u8>,
}
impl DurableNativeApplicationV0 {
    pub fn read_finalized_catchup_block_v1(
        &self,
        proof: &[u8],
        height: HeightV0,
        parent_timestamp_ms: u64,
        budget: &mut Cev0AdmissionBudgetV0,
    ) -> StreamResult<NativeCatchupBlockV1> {
        let read = self
            .read_poco_finalized_bytes_v0(
                POCO_THREE_CHAIN_PROOF_CLASS_V0,
                proof,
                height,
                parent_timestamp_ms,
                budget,
            )
            .map_err(NativeCatchupStreamErrorV1::SourceProof)?;
        let header = read.finality().proof().finalized_block().header().clone();
        if header.block_kind() != BlockKind::Regular || header.epoch().get() != 0 {
            return Err(NativeCatchupStreamErrorV1::Context);
        }
        let payload = ApplicationPayloadV0::new(
            read.application()
                .executed_v0()
                .request()
                .transactions()
                .to_vec(),
        )
        .and_then(|body| body.try_cev0_bytes())
        .map_err(|_| NativeCatchupStreamErrorV1::Framing)?;
        Ok(NativeCatchupBlockV1 {
            header,
            payload,
            proof: proof.to_vec(),
        })
    }
}

struct Wire<T> {
    inner: T,
    limits: NativeCatchupStreamLimitsV1,
    remaining: u64,
}
impl<T> Wire<T> {
    fn new(inner: T, limits: NativeCatchupStreamLimitsV1) -> Self {
        Self {
            inner,
            limits,
            remaining: limits.maximum_bytes,
        }
    }
    fn charge(&mut self, bytes: usize) -> StreamResult<()> {
        self.remaining = self
            .remaining
            .checked_sub(bytes as u64)
            .ok_or(NativeCatchupStreamErrorV1::Limit)?;
        Ok(())
    }
}
impl<R: Read> Wire<R> {
    fn exact<const N: usize>(&mut self) -> StreamResult<[u8; N]> {
        self.charge(N)?;
        let mut bytes = [0; N];
        self.inner
            .read_exact(&mut bytes)
            .map_err(NativeCatchupStreamErrorV1::Transport)?;
        Ok(bytes)
    }
    fn frame(&mut self, cap: usize) -> StreamResult<Vec<u8>> {
        let length = u32::from_be_bytes(self.exact()?) as usize;
        if length == 0 || length > cap || length > self.limits.maximum_frame_bytes {
            return Err(NativeCatchupStreamErrorV1::Limit);
        }
        // Charge before allocation/read, including malformed/failed attempts.
        self.charge(length)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(length)
            .map_err(|_| NativeCatchupStreamErrorV1::Limit)?;
        bytes.resize(length, 0);
        self.inner
            .read_exact(&mut bytes)
            .map_err(NativeCatchupStreamErrorV1::Transport)?;
        Ok(bytes)
    }
    fn end(&mut self) -> StreamResult<()> {
        if &self.exact::<8>()? != END {
            return Err(NativeCatchupStreamErrorV1::Framing);
        }
        // EOF is not an authenticated fact, but delimits this exact one-shot
        // transfer. A socket owner MUST bound reads with an absolute deadline.
        let mut extra = [0];
        loop {
            match self.inner.read(&mut extra) {
                Ok(0) => return Ok(()),
                Ok(_) => return Err(NativeCatchupStreamErrorV1::Framing),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(NativeCatchupStreamErrorV1::Transport(e)),
            }
        }
    }
}
impl<W: Write> Wire<W> {
    fn put(&mut self, bytes: &[u8]) -> StreamResult<()> {
        self.charge(bytes.len())?;
        self.inner
            .write_all(bytes)
            .map_err(NativeCatchupStreamErrorV1::Transport)
    }
    fn put_frame(&mut self, bytes: &[u8]) -> StreamResult<()> {
        if bytes.is_empty() || bytes.len() > self.limits.maximum_frame_bytes {
            return Err(NativeCatchupStreamErrorV1::Limit);
        }
        self.put(&(bytes.len() as u32).to_be_bytes())?;
        self.put(bytes)
    }
}

fn encode_manifest(manifest: &NativeSnapshotManifestV0) -> Vec<u8> {
    let head = manifest.request().head();
    let mut bytes = Vec::with_capacity(MANIFEST_FIXED + manifest.chunks().len() * DESCRIPTOR_BYTES);
    bytes.extend_from_slice(&head.height().get().to_be_bytes());
    bytes.extend_from_slice(head.block_id().as_bytes());
    bytes.extend_from_slice(head.state_root().as_bytes());
    // Correlation only; the receiving application constructs its own commit ID.
    bytes.extend_from_slice(head.commit_id().as_bytes());
    bytes.extend_from_slice(&manifest.request().maximum_chunk_bytes().to_be_bytes());
    bytes.extend_from_slice(&(manifest.chunks().len() as u32).to_be_bytes());
    bytes.extend_from_slice(manifest.manifest_digest().as_bytes());
    for chunk in manifest.chunks() {
        bytes.extend_from_slice(&chunk.index().to_be_bytes());
        bytes.extend_from_slice(&chunk.byte_length().to_be_bytes());
        bytes.extend_from_slice(chunk.digest().as_bytes());
    }
    bytes
}
fn decode_manifest(bytes: &[u8]) -> StreamResult<NativeSnapshotManifestV0> {
    fn take<const N: usize>(input: &mut &[u8]) -> StreamResult<[u8; N]> {
        let part = input.get(..N).ok_or(NativeCatchupStreamErrorV1::Framing)?;
        let out = part
            .try_into()
            .map_err(|_| NativeCatchupStreamErrorV1::Framing)?;
        *input = &input[N..];
        Ok(out)
    }
    let mut input = bytes;
    let height = u64::from_be_bytes(take(&mut input)?);
    let block =
        BlockIdV0::new(take(&mut input)?).map_err(|_| NativeCatchupStreamErrorV1::Framing)?;
    let root =
        StateRootV0::new(take(&mut input)?).map_err(|_| NativeCatchupStreamErrorV1::Framing)?;
    let commit = ApplicationCommitIdV0::new(take(&mut input)?)
        .map_err(|_| NativeCatchupStreamErrorV1::Framing)?;
    let maximum_chunk = u32::from_be_bytes(take(&mut input)?);
    let count = u32::from_be_bytes(take(&mut input)?) as usize;
    let digest = Hash32V0::new(take(&mut input)?);
    if count == 0 || count > MAX_SNAPSHOT_CHUNKS_V0 || input.len() != count * DESCRIPTOR_BYTES {
        return Err(NativeCatchupStreamErrorV1::Framing);
    }
    let head = ApplicationHeadV0::new(HeightV0::new(height), block, root, commit);
    let request = NativeSnapshotRequestV0::new(head, maximum_chunk)
        .map_err(|_| NativeCatchupStreamErrorV1::Framing)?;
    let mut chunks = Vec::with_capacity(count);
    for _ in 0..count {
        let index = u32::from_be_bytes(take(&mut input)?);
        let length = u32::from_be_bytes(take(&mut input)?);
        chunks.push(
            NativeSnapshotChunkV0::new(index, length, Hash32V0::new(take(&mut input)?))
                .map_err(|_| NativeCatchupStreamErrorV1::Framing)?,
        );
    }
    NativeSnapshotManifestV0::new(request, chunks, digest)
        .map_err(|_| NativeCatchupStreamErrorV1::Framing)
}

/// Emits a one-shot candidate transfer from real source readbacks and a pinned
/// snapshot. The source must half-close/finish its byte stream after success.
/// A write/flush success is NOT a receiver commit acknowledgement.
pub fn write_native_catchup_stream_v1<W, I>(
    output: W,
    base: &ApplicationHeadV0,
    snapshot: &PinnedNativeSnapshotExportV1,
    blocks: I,
    limits: NativeCatchupStreamLimitsV1,
) -> StreamResult<()>
where
    W: Write,
    I: IntoIterator<Item = StreamResult<NativeCatchupBlockV1>>,
{
    let target = snapshot.manifest().request().head();
    let count = target
        .height()
        .get()
        .checked_sub(base.height().get())
        .filter(|n| *n <= limits.maximum_blocks as u64)
        .ok_or(NativeCatchupStreamErrorV1::Context)?;
    let mut wire = Wire::new(output, limits);
    wire.put(MAGIC)?;
    wire.put(&base.height().get().to_be_bytes())?;
    wire.put(base.block_id().as_bytes())?;
    wire.put(&target.height().get().to_be_bytes())?;
    wire.put(target.block_id().as_bytes())?;
    wire.put(&(count as u32).to_be_bytes())?;
    wire.put_frame(&encode_manifest(snapshot.manifest()))?;
    let mut blocks = blocks.into_iter();
    let mut parent = *base.block_id().as_bytes();
    for ordinal in 1..=count {
        let block = blocks.next().ok_or(NativeCatchupStreamErrorV1::Framing)??;
        if block.header.height().get() != base.height().get() + ordinal
            || block.header.parent_id().as_bytes() != &parent
        {
            return Err(NativeCatchupStreamErrorV1::Context);
        }
        parent = *block.header.id().as_bytes();
        let header = block
            .header
            .try_cev0_bytes()
            .map_err(|_| NativeCatchupStreamErrorV1::Framing)?;
        wire.put_frame(&header)?;
        wire.put_frame(&block.payload)?;
        wire.put_frame(&block.proof)?;
    }
    if blocks.next().is_some() || parent != *target.block_id().as_bytes() {
        return Err(NativeCatchupStreamErrorV1::Context);
    }
    for descriptor in snapshot.manifest().chunks() {
        wire.put_frame(
            snapshot
                .chunk(descriptor.index())
                .map_err(NativeCatchupStreamErrorV1::Source)?,
        )?;
    }
    wire.put(END)?;
    wire.inner
        .flush()
        .map_err(NativeCatchupStreamErrorV1::Transport)
}

struct Chunks<'a, R> {
    wire: &'a mut Wire<R>,
    manifest: &'a NativeSnapshotManifestV0,
    next: usize,
    terminal: bool,
}
impl<R: Read> Iterator for Chunks<'_, R> {
    type Item = io::Result<Vec<u8>>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.terminal {
            return None;
        }
        if let Some(descriptor) = self.manifest.chunks().get(self.next) {
            self.next += 1;
            let result = self
                .wire
                .frame(descriptor.byte_length() as usize)
                .and_then(|bytes| {
                    if bytes.len() != descriptor.byte_length() as usize {
                        Err(NativeCatchupStreamErrorV1::Framing)
                    } else {
                        Ok(bytes)
                    }
                });
            if result.is_err() {
                self.terminal = true;
            }
            Some(result.map_err(io::Error::other))
        } else {
            self.terminal = true;
            self.wire.end().err().map(|e| Err(io::Error::other(e)))
        }
    }
}

impl NativeFinalizedCatchupV1 {
    /// Consumes one exact source-to-target stream. `Read` itself has no time
    /// bound: socket callers must impose an absolute operation deadline (not a
    /// resettable timeout per frame). Rejected streams consume this owner;
    /// independently finalized prefix commits remain and are resumable only by
    /// reopening with the matching current proof. No peer chooses trust/config,
    /// local commit IDs, nonce floors or a new signing/consensus capability.
    pub fn receive_framed_stream_v1<R: Read>(
        mut self,
        input: R,
        limits: NativeCatchupStreamLimitsV1,
        snapshot_limits: NativeSnapshotReadLimitsV1,
        budget: &mut Cev0AdmissionBudgetV0,
    ) -> StreamResult<RestoredNativeApplicationV1> {
        let mut wire = Wire::new(input, limits);
        if &wire.exact::<8>()? != MAGIC {
            return Err(NativeCatchupStreamErrorV1::Framing);
        }
        let base_height = u64::from_be_bytes(wire.exact()?);
        let base_id = wire.exact::<32>()?;
        let target_height = u64::from_be_bytes(wire.exact()?);
        let target_id = wire.exact::<32>()?;
        let count = u32::from_be_bytes(wire.exact()?);
        if count > limits.maximum_blocks || count as u64 > self.limits.maximum_blocks {
            return Err(NativeCatchupStreamErrorV1::Limit);
        }
        if base_height != self.head.height().get()
            || &base_id != self.head.block_id().as_bytes()
            || target_height != self.target.finalized_height().get()
            || &target_id != self.target.finalized_block_id().as_bytes()
            || base_height.checked_add(count as u64) != Some(target_height)
        {
            return Err(NativeCatchupStreamErrorV1::Context);
        }
        let manifest = decode_manifest(&wire.frame(MAX_MANIFEST_BYTES)?)?;
        let head = manifest.request().head();
        if head.height().get() != target_height
            || head.block_id().as_bytes() != &target_id
            || head.state_root().as_bytes()
                != self
                    .target
                    .proof()
                    .finalized_block()
                    .header()
                    .state_root()
                    .as_bytes()
        {
            return Err(NativeCatchupStreamErrorV1::Context);
        }
        if manifest.total_bytes() > snapshot_limits.maximum_bytes
            || manifest
                .chunks()
                .iter()
                .any(|c| c.byte_length() as usize > limits.maximum_frame_bytes)
        {
            return Err(NativeCatchupStreamErrorV1::Limit);
        }
        let snapshot_wire_bytes = manifest
            .total_bytes()
            .checked_add(manifest.chunks().len() as u64 * 4 + END.len() as u64)
            .ok_or(NativeCatchupStreamErrorV1::Limit)?;
        if snapshot_wire_bytes > wire.remaining {
            return Err(NativeCatchupStreamErrorV1::Limit);
        }
        for _ in 0..count {
            let header = decode_block_header_v0_exact(&wire.frame(MAX_CEV0_ROOT_BYTES_V0)?)
                .map_err(|_| NativeCatchupStreamErrorV1::Framing)?;
            let payload = wire.frame(MAX_BLOCK_BYTES_V0)?;
            let proof = wire.frame(MAX_CEV0_ROOT_BYTES_V0)?;
            // Reserve the still-required snapshot/trailer before touching state.
            if snapshot_wire_bytes > wire.remaining {
                return Err(NativeCatchupStreamErrorV1::Limit);
            }
            self.apply(&header, &payload, &proof, budget)
                .map_err(NativeCatchupStreamErrorV1::Catchup)?;
        }
        let chunks = Chunks {
            wire: &mut wire,
            manifest: &manifest,
            next: 0,
            terminal: false,
        };
        self.finish_with_snapshot(&manifest, chunks, snapshot_limits)
            .map_err(NativeCatchupStreamErrorV1::Catchup)
    }
}
