//! Public verification-result boundary tests. The counted proof adapter is a
//! fixture, not independent consensus or cryptographic acceptance evidence.
use std::{cell::Cell, io};

use trnm_state_sync_v0::*;

fn d(byte: u8) -> Digest32V0 {
    Digest32V0([byte; 32])
}

struct CountingProof {
    calls: Cell<usize>,
    reject: bool,
}

impl CheckpointProofVerifierV0 for CountingProof {
    type Error = io::Error;

    fn verify_link(&self, _link: &CheckpointLinkV0) -> Result<(), Self::Error> {
        self.calls.set(self.calls.get() + 1);
        if self.reject {
            return Err(io::Error::other("rejected proof fixture"));
        }
        Ok(())
    }
}

fn fixture_root<'a, I>(schema: Digest32V0, chunks: I) -> Digest32V0
where
    I: IntoIterator<Item = &'a [u8]>,
{
    let mut root = schema;
    for bytes in chunks {
        root = Digest32V0::hash(b"trnm.test.verification-seal-root.v0", &[&root.0, bytes]);
    }
    root
}

struct CountingRoot {
    calls: Cell<usize>,
    mismatch: bool,
}

impl StateRootRecomputerV0 for CountingRoot {
    type Error = io::Error;

    fn recompute_state_root<'a, I>(
        &self,
        schema: Digest32V0,
        chunks: I,
    ) -> Result<Digest32V0, Self::Error>
    where
        I: IntoIterator<Item = &'a [u8]>,
    {
        self.calls.set(self.calls.get() + 1);
        if self.mismatch {
            return Ok(d(99));
        }
        Ok(fixture_root(schema, chunks))
    }
}

fn checkpoint() -> (WeakSubjectivityAnchorV0, CheckpointLinkV0) {
    let anchor = WeakSubjectivityAnchorV0 {
        chain_id: d(1),
        protocol_digest: d(2),
        epoch: 1,
        height: 1,
        checkpoint_digest: d(3),
        validator_set_digest: d(4),
    };
    let mut link = CheckpointLinkV0 {
        chain_id: anchor.chain_id,
        protocol_digest: anchor.protocol_digest,
        epoch: anchor.epoch,
        height: 2,
        state_root: fixture_root(d(5), [b"a".as_slice(), b"b".as_slice()]),
        validator_set_digest: anchor.validator_set_digest,
        next_validator_set_digest: anchor.validator_set_digest,
        parent_checkpoint_digest: anchor.checkpoint_digest,
        finality_proof_digest: d(6),
        checkpoint_digest: d(0),
    };
    link.checkpoint_digest = link.canonical_digest();
    (anchor, link)
}

fn snapshot_fixture() -> (VerifiedTrustPathV0, SnapshotManifestV0, Vec<SnapshotChunkV0>) {
    let (anchor, link) = checkpoint();
    let proof = CountingProof {
        calls: Cell::new(0),
        reject: false,
    };
    let verified = verify_trust_path_v0(&proof, anchor, &[link]).unwrap();
    assert_eq!(proof.calls.get(), 1);
    let mut manifest = SnapshotManifestV0 {
        chain_id: anchor.chain_id,
        protocol_digest: anchor.protocol_digest,
        height: link.height,
        epoch: link.epoch,
        state_root: link.state_root,
        chunk_root: d(0),
        chunk_count: 2,
        maximum_chunk_bytes: 1,
        total_bytes: 2,
        schema_digest: d(5),
        checkpoint_digest: link.checkpoint_digest,
        manifest_digest: d(0),
    };
    let binding = manifest.chunk_binding_digest();
    let chunks: Vec<_> = [b"a".as_slice(), b"b".as_slice()]
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
    (verified, manifest, chunks)
}

#[test]
fn verified_path_accessors_preserve_issued_facts_and_isolate_copies() {
    let (anchor, link) = checkpoint();
    let proof = CountingProof {
        calls: Cell::new(0),
        reject: false,
    };
    let verified = verify_trust_path_v0(&proof, anchor, &[link]).unwrap();
    assert_eq!(proof.calls.get(), 1);
    assert_eq!(verified.anchor(), anchor);
    assert_eq!(verified.terminal(), link);
    assert_eq!(verified.link_count(), 1);
    assert_ne!(verified.path_digest(), d(0));
    let cloned = verified.clone();
    let mut detached = cloned.terminal();
    detached.state_root = d(99);
    assert_ne!(detached, verified.terminal());
    assert_eq!(cloned, verified);
}

#[test]
fn invalid_path_cannot_reach_the_proof_adapter_or_issue_a_result() {
    let (anchor, mut link) = checkpoint();
    let proof = CountingProof {
        calls: Cell::new(0),
        reject: false,
    };
    link.parent_checkpoint_digest = d(99);
    link.checkpoint_digest = link.canonical_digest();
    assert!(matches!(
        verify_trust_path_v0(&proof, anchor, &[link]),
        Err(StateSyncHostErrorV0::Protocol(
            StateSyncErrorV0::InvalidTrustPath
        ))
    ));
    assert_eq!(proof.calls.get(), 0);
}

#[test]
fn failed_proof_adapter_cannot_issue_a_verified_path() {
    let (anchor, link) = checkpoint();
    let proof = CountingProof {
        calls: Cell::new(0),
        reject: true,
    };
    assert!(matches!(
        verify_trust_path_v0(&proof, anchor, &[link]),
        Err(StateSyncHostErrorV0::CheckpointProof(_))
    ));
    assert_eq!(proof.calls.get(), 1);
}

#[test]
fn verified_snapshot_accessors_bind_the_complete_issued_result() {
    let (trust, manifest, chunks) = snapshot_fixture();
    let trust_digest = trust.path_digest();
    let root = CountingRoot {
        calls: Cell::new(0),
        mismatch: false,
    };
    let mut session = StateSyncSessionV0::new(trust, manifest.clone()).unwrap();
    for chunk in chunks {
        session.accept_chunk(chunk).unwrap();
    }
    let verified = session.verify_complete(&root).unwrap();
    assert_eq!(root.calls.get(), 1);
    assert_eq!(verified.manifest_digest(), manifest.manifest_digest);
    assert_eq!(verified.trust_path_digest(), trust_digest);
    assert_eq!(verified.state_root(), manifest.state_root);
    assert_eq!(verified.chunk_root(), manifest.chunk_root);
    assert_eq!(verified.height(), manifest.height);
    assert_eq!(verified.epoch(), manifest.epoch);
    let copied = verified;
    let mut detached = copied.state_root();
    detached.0[0] ^= 1;
    assert_ne!(detached, verified.state_root());
    assert_eq!(copied, verified);
}

#[test]
fn recomputed_root_mismatch_cannot_issue_a_verified_snapshot() {
    let (trust, manifest, chunks) = snapshot_fixture();
    let root = CountingRoot {
        calls: Cell::new(0),
        mismatch: true,
    };
    let mut session = StateSyncSessionV0::new(trust, manifest).unwrap();
    for chunk in chunks {
        session.accept_chunk(chunk).unwrap();
    }
    assert!(matches!(
        session.verify_complete(&root),
        Err(StateSyncHostErrorV0::Protocol(
            StateSyncErrorV0::StateRootMismatch
        ))
    ));
    assert_eq!(root.calls.get(), 1);
}

#[test]
fn chunk_commitment_mismatch_is_rejected_before_root_recomputation() {
    let (trust, manifest, mut chunks) = snapshot_fixture();
    let root = CountingRoot {
        calls: Cell::new(0),
        mismatch: false,
    };
    chunks[0].bytes[0] ^= 1;
    chunks[0].chunk_digest = SnapshotChunkV0::canonical_digest(
        chunks[0].manifest_digest,
        chunks[0].index,
        &chunks[0].bytes,
    );
    let mut session = StateSyncSessionV0::new(trust, manifest).unwrap();
    for chunk in chunks {
        session.accept_chunk(chunk).unwrap();
    }
    assert!(matches!(
        session.verify_complete(&root),
        Err(StateSyncHostErrorV0::Protocol(
            StateSyncErrorV0::ChunkRootMismatch
        ))
    ));
    assert_eq!(root.calls.get(), 0);
}
