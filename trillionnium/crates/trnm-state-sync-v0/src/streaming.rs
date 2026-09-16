//! Single-pass snapshot installation without retaining all downloaded chunks.
//!
//! This is an adapter-facing ordered stream, not a new wire format. The caller
//! supplies a previously verified trust path and a trusted schema-specific root
//! recomputer. Its accumulator must use disposable state, never the live state
//! database. The transport controls its own deadlines and allocation bounds.

use crate::{
    chunk_merkle_root_v0, Digest32V0, InstallReceiptV0, NonDestructiveInstallTargetV0,
    SnapshotChunkV0, SnapshotManifestV0, StagingIdentityV0, StateSyncErrorV0, VerifiedTrustPathV0,
};
use std::{error::Error, fmt};

/// Incremental application-root computation over canonical, ordered chunks.
/// No method here may mutate the currently installed application. The core
/// bounds downloaded data, not the implementation's internal scratch storage.
pub trait StateRootAccumulatorV1 {
    type Error;
    fn absorb(&mut self, index: u32, bytes: &[u8]) -> Result<(), Self::Error>;
    fn finish(self) -> Result<Digest32V0, Self::Error>;
}

pub trait StreamingStateRootRecomputerV1 {
    type Error;
    type Accumulator: StateRootAccumulatorV1<Error = Self::Error>;
    fn begin(&self, manifest: &SnapshotManifestV0) -> Result<Self::Accumulator, Self::Error>;
}

/// These are local installation dispositions, not new consensus/wire errors.
#[derive(Debug)]
pub enum StreamingFailureV1<I, R, T> {
    Protocol(StateSyncErrorV0),
    Input(I),
    Root(R),
    Begin(T),
    Write(T),
    /// The bounded ordered-stream adapter got a duplicate/reordered index.
    ChunkOrder {
        expected: u32,
        actual: u32,
    },
    /// Only one look-ahead item is consumed; an unbounded suffix is not read.
    ExcessChunks,
    Allocation,
}

#[derive(Debug)]
pub enum StreamingInstallErrorV1<I, R, T> {
    /// CURRENT has not been intentionally switched. Failed abort is retained
    /// separately, rather than hiding the original input/root/write failure.
    BeforeCommit {
        failure: StreamingFailureV1<I, R, T>,
        abort_error: Option<T>,
    },
    /// A target may have committed. No destructive cleanup is attempted.
    CommitUncertain(T),
    /// A successful-looking target response did not bind the requested effect.
    ReceiptMismatch(StateSyncErrorV0),
}

impl<I: fmt::Debug, R: fmt::Debug, T: fmt::Debug> fmt::Display
    for StreamingInstallErrorV1<I, R, T>
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "streamed snapshot installation: {self:?}")
    }
}
impl<I: fmt::Debug, R: fmt::Debug, T: fmt::Debug> Error for StreamingInstallErrorV1<I, R, T> {}

fn before_commit<I, R, T>(
    failure: StreamingFailureV1<I, R, T>,
) -> StreamingInstallErrorV1<I, R, T> {
    StreamingInstallErrorV1::BeforeCommit {
        failure,
        abort_error: None,
    }
}

/// Install one manifest's chunks from a bounded ordered source.
///
/// Auxiliary transport memory is one caller-supplied chunk plus at most
/// `chunk_count` digests (2 MiB at the protocol cap), and the Merkle helper's
/// bounded working levels. Unlike `StateSyncSessionV0`, chunk payloads are
/// dropped on every iteration. Accumulator/target memory and transient source
/// allocation are separate obligations; this does not claim total node memory
/// is bounded or that native JMT snapshot decoding is incremental.
///
/// A malformed/short/extra stream, wrong application root or failed write aborts
/// only staging. Once CAS starts, errors or mismatched receipts remain uncertain
/// and never call abort. A panicking adapter similarly unwinds without invoking
/// destructive automatic cleanup; its target must recover retained staging.
///
/// No download resume or crash-qualification claim follows from this function.
/// The real file target revalidates persisted chunk bytes before publishing.
#[allow(clippy::type_complexity)]
pub fn install_streaming_snapshot_v1<I, InputError, R, T>(
    trust_path: &VerifiedTrustPathV0,
    manifest: &SnapshotManifestV0,
    source: I,
    recomputer: &R,
    target: &mut T,
    expected_current_root: Digest32V0,
) -> Result<InstallReceiptV0, StreamingInstallErrorV1<InputError, R::Error, T::Error>>
where
    I: IntoIterator<Item = Result<SnapshotChunkV0, InputError>>,
    R: StreamingStateRootRecomputerV1,
    T: NonDestructiveInstallTargetV0,
{
    manifest
        .validate(trust_path)
        .map_err(|error| before_commit(StreamingFailureV1::Protocol(error)))?;
    if expected_current_root == Digest32V0([0; 32]) {
        return Err(before_commit(StreamingFailureV1::Protocol(
            StateSyncErrorV0::InvalidExpectedCurrentRoot,
        )));
    }
    // Allocate bounded bookkeeping before the target can create anything.
    let mut digests = Vec::new();
    digests
        .try_reserve_exact(manifest.chunk_count as usize)
        .map_err(|_| before_commit(StreamingFailureV1::Allocation))?;
    let mut accumulator = recomputer
        .begin(manifest)
        .map_err(|error| before_commit(StreamingFailureV1::Root(error)))?;
    let staging = target
        .begin_staging(manifest)
        .map_err(|error| before_commit(StreamingFailureV1::Begin(error)))?;
    if staging.generation == 0 || staging.staging_digest == Digest32V0([0; 32]) {
        // Never hand an untrusted identity to abort or any mutation method.
        return Err(before_commit(StreamingFailureV1::Protocol(
            StateSyncErrorV0::InvalidStagingIdentity,
        )));
    }
    let mut source = source.into_iter();
    let fill = (|| {
        let mut received = 0u64;
        for expected in 0..manifest.chunk_count {
            let chunk = source
                .next()
                .ok_or(StreamingFailureV1::Protocol(
                    StateSyncErrorV0::IncompleteSnapshot,
                ))?
                .map_err(StreamingFailureV1::Input)?;
            chunk
                .validate(manifest)
                .map_err(StreamingFailureV1::Protocol)?;
            if chunk.index != expected {
                return Err(StreamingFailureV1::ChunkOrder {
                    expected,
                    actual: chunk.index,
                });
            }
            received = received.checked_add(chunk.bytes.len() as u64).ok_or(
                StreamingFailureV1::Protocol(StateSyncErrorV0::SnapshotTooLarge),
            )?;
            if received > manifest.total_bytes {
                return Err(StreamingFailureV1::Protocol(
                    StateSyncErrorV0::SnapshotTooLarge,
                ));
            }
            accumulator
                .absorb(expected, &chunk.bytes)
                .map_err(StreamingFailureV1::Root)?;
            target
                .write_chunk(staging, expected, &chunk.bytes)
                .map_err(StreamingFailureV1::Write)?;
            digests.push(chunk.chunk_digest);
            // `chunk` is dropped before requesting the next input.
        }
        match source.next() {
            None => {}
            Some(Err(error)) => return Err(StreamingFailureV1::Input(error)),
            Some(Ok(_)) => return Err(StreamingFailureV1::ExcessChunks),
        }
        if received != manifest.total_bytes {
            return Err(StreamingFailureV1::Protocol(
                StateSyncErrorV0::IncompleteSnapshot,
            ));
        }
        if chunk_merkle_root_v0(&digests) != manifest.chunk_root {
            return Err(StreamingFailureV1::Protocol(
                StateSyncErrorV0::ChunkRootMismatch,
            ));
        }
        Ok(())
    })();
    if let Err(failure) = fill {
        return Err(abort_before_commit(target, staging, failure));
    }
    let state_root = match accumulator.finish() {
        Ok(root) => root,
        Err(error) => {
            return Err(abort_before_commit(
                target,
                staging,
                StreamingFailureV1::Root(error),
            ))
        }
    };
    if state_root != manifest.state_root {
        return Err(abort_before_commit(
            target,
            staging,
            StreamingFailureV1::Protocol(StateSyncErrorV0::StateRootMismatch),
        ));
    }
    let receipt = target
        .commit_staging_cas(staging, expected_current_root, manifest)
        .map_err(StreamingInstallErrorV1::CommitUncertain)?;
    if receipt.previous_root != expected_current_root
        || receipt.installed_root != manifest.state_root
        || receipt.installed_height != manifest.height
        || receipt.generation != staging.generation
        || receipt.durable_receipt_digest == Digest32V0([0; 32])
    {
        return Err(StreamingInstallErrorV1::ReceiptMismatch(
            StateSyncErrorV0::InstallReceiptMismatch,
        ));
    }
    Ok(receipt)
}

fn abort_before_commit<I, R, T: NonDestructiveInstallTargetV0>(
    target: &mut T,
    staging: StagingIdentityV0,
    failure: StreamingFailureV1<I, R, T::Error>,
) -> StreamingInstallErrorV1<I, R, T::Error> {
    StreamingInstallErrorV1::BeforeCommit {
        failure,
        abort_error: target.abort_staging(staging).err(),
    }
}
