//! Streams into the actual file target. The SHA fixture below is an application
//! root test implementation, not the native JMT or an independent light client.
use super::*;
use sha2::{Digest, Sha256};
use std::convert::Infallible;
use trnm_state_sync_v0::{
    chunk_merkle_root_v0, install_streaming_snapshot_v1, verify_trust_path_v0, CheckpointLinkV0,
    CheckpointProofVerifierV0, SnapshotChunkV0, StateRootAccumulatorV1, StreamingInstallErrorV1,
    StreamingStateRootRecomputerV1, VerifiedTrustPathV0, WeakSubjectivityAnchorV0,
};
struct Proof;
impl CheckpointProofVerifierV0 for Proof {
    type Error = Infallible;
    fn verify_link(&self, _: &CheckpointLinkV0) -> Result<(), Self::Error> {
        Ok(())
    }
}
struct Root;
struct Acc(Sha256);
impl StreamingStateRootRecomputerV1 for Root {
    type Error = Infallible;
    type Accumulator = Acc;
    fn begin(&self, manifest: &SnapshotManifestV0) -> Result<Acc, Self::Error> {
        let mut h = Sha256::new();
        h.update(b"file-stream-fixture");
        h.update(manifest.schema_digest.0);
        Ok(Acc(h))
    }
}
impl StateRootAccumulatorV1 for Acc {
    type Error = Infallible;
    fn absorb(&mut self, _: u32, bytes: &[u8]) -> Result<(), Self::Error> {
        self.0.update((bytes.len() as u64).to_be_bytes());
        self.0.update(bytes);
        Ok(())
    }
    fn finish(self) -> Result<SyncDigestV0, Self::Error> {
        Ok(SyncDigestV0(self.0.finalize().into()))
    }
}
fn d(b: u8) -> SyncDigestV0 {
    SyncDigestV0([b; 32])
}
fn fixture() -> (
    VerifiedTrustPathV0,
    SnapshotManifestV0,
    Vec<SnapshotChunkV0>,
) {
    let anchor = WeakSubjectivityAnchorV0 {
        chain_id: d(1),
        protocol_digest: d(2),
        epoch: 1,
        height: 1,
        checkpoint_digest: d(3),
        validator_set_digest: d(4),
    };
    let mut manifest = SnapshotManifestV0 {
        chain_id: d(1),
        protocol_digest: d(2),
        epoch: 1,
        height: 2,
        state_root: d(5),
        chunk_root: d(6),
        chunk_count: 3,
        maximum_chunk_bytes: 64,
        total_bytes: 14,
        schema_digest: d(7),
        checkpoint_digest: d(8),
        manifest_digest: d(0),
    };
    let data = [b"alpha".as_slice(), b"beta".as_slice(), b"gamma".as_slice()];
    let mut accumulator = Root.begin(&manifest).unwrap();
    for (i, bytes) in data.iter().enumerate() {
        accumulator.absorb(i as u32, bytes).unwrap();
    }
    manifest.state_root = accumulator.finish().unwrap();
    let mut terminal = CheckpointLinkV0 {
        chain_id: anchor.chain_id,
        protocol_digest: anchor.protocol_digest,
        epoch: 1,
        height: 2,
        state_root: manifest.state_root,
        validator_set_digest: d(4),
        next_validator_set_digest: d(4),
        parent_checkpoint_digest: anchor.checkpoint_digest,
        finality_proof_digest: d(9),
        checkpoint_digest: d(0),
    };
    terminal.checkpoint_digest = terminal.canonical_digest();
    manifest.checkpoint_digest = terminal.checkpoint_digest;
    let binding = manifest.chunk_binding_digest();
    let chunks: Vec<_> = data
        .iter()
        .enumerate()
        .map(|(i, bytes)| SnapshotChunkV0 {
            manifest_digest: binding,
            index: i as u32,
            bytes: bytes.to_vec(),
            chunk_digest: SnapshotChunkV0::canonical_digest(binding, i as u32, bytes),
        })
        .collect();
    manifest.chunk_root =
        chunk_merkle_root_v0(&chunks.iter().map(|c| c.chunk_digest).collect::<Vec<_>>());
    manifest.manifest_digest = manifest.canonical_digest();
    (
        verify_trust_path_v0(&Proof, anchor, &[terminal]).unwrap(),
        manifest,
        chunks,
    )
}
#[test]
fn actual_file_target_accepts_a_stream_then_revalidates_it_on_reopen() {
    let directory = tests::TestDirectory::new("stream-install");
    let (trust, manifest, chunks) = fixture();
    let mut target =
        AtomicSnapshotFileTargetV0::open_or_initialize(directory.path(), d(10), 1, 1).unwrap();
    let receipt = install_streaming_snapshot_v1(
        &trust,
        &manifest,
        chunks.into_iter().map(Ok::<_, Infallible>),
        &Root,
        &mut target,
        d(10),
    )
    .unwrap();
    assert_eq!(receipt.installed_root, manifest.state_root);
    drop(target);
    let reopened =
        AtomicSnapshotFileTargetV0::open_or_initialize(directory.path(), d(10), 1, 1).unwrap();
    assert_eq!(reopened.current_state_root(), manifest.state_root);
    assert_eq!(
        fs::read(
            directory
                .path()
                .join("generations/generation-2/chunk-00000002.bin")
        )
        .unwrap(),
        b"gamma"
    );
}
#[test]
fn late_bad_input_preserves_current_file_and_all_committed_state() {
    let directory = tests::TestDirectory::new("stream-reject");
    let (trust, manifest, mut chunks) = fixture();
    chunks[2].bytes[0] ^= 1;
    let mut target =
        AtomicSnapshotFileTargetV0::open_or_initialize(directory.path(), d(10), 1, 1).unwrap();
    let before = fs::read(directory.path().join("CURRENT.v0")).unwrap();
    assert!(install_streaming_snapshot_v1(
        &trust,
        &manifest,
        chunks.into_iter().map(Ok::<_, Infallible>),
        &Root,
        &mut target,
        d(10)
    )
    .is_err());
    assert_eq!(
        fs::read(directory.path().join("CURRENT.v0")).unwrap(),
        before
    );
    assert_eq!(target.current_state_root(), d(10));
}
#[test]
fn streamed_pointer_response_loss_recovers_the_committed_target_without_abort() {
    use super::snapshot_recovery_tests::{SnapshotFaultV1, SnapshotPointV1};
    let directory = tests::TestDirectory::new("stream-lost-reply");
    let (trust, manifest, chunks) = fixture();
    let mut target =
        AtomicSnapshotFileTargetV0::open_or_initialize(directory.path(), d(10), 1, 1).unwrap();
    target.fault = Some(SnapshotFaultV1::Error(SnapshotPointV1::PointerPublished));
    assert!(matches!(
        install_streaming_snapshot_v1(
            &trust,
            &manifest,
            chunks.into_iter().map(Ok::<_, Infallible>),
            &Root,
            &mut target,
            d(10)
        ),
        Err(StreamingInstallErrorV1::CommitUncertain(_))
    ));
    drop(target);
    let reopened =
        AtomicSnapshotFileTargetV0::open_or_initialize(directory.path(), d(10), 1, 1).unwrap();
    assert_eq!(reopened.current_state_root(), manifest.state_root);
    assert!(directory
        .path()
        .join("generations/generation-2/MANIFEST.v0")
        .is_file());
}
