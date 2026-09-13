//! Public M13 contract tests. The proof verifier is deliberately a fixture;
//! these tests do not establish consensus, filesystem or physical durability.
use std::{convert::Infallible, io};

use sha2::{Digest, Sha256};
use trnm_state_sync_v0::*;

fn d(byte: u8) -> Digest32V0 {
    Digest32V0([byte; 32])
}

struct ProofFixture;
impl CheckpointProofVerifierV0 for ProofFixture {
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
        schema: Digest32V0,
        chunks: I,
    ) -> Result<Digest32V0, Self::Error>
    where
        I: IntoIterator<Item = &'a [u8]>,
    {
        let mut hash = Sha256::new();
        hash.update(b"trnm.test.staging-admission.v0");
        hash.update(schema.0);
        for bytes in chunks {
            hash.update((bytes.len() as u64).to_be_bytes());
            hash.update(bytes);
        }
        Ok(Digest32V0(hash.finalize().into()))
    }
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
    let bytes: [&[u8]; 2] = [b"a", b"b"];
    let state_root = HashRoot.recompute_state_root(d(5), bytes).unwrap();
    let mut link = CheckpointLinkV0 {
        chain_id: anchor.chain_id,
        protocol_digest: anchor.protocol_digest,
        epoch: anchor.epoch,
        height: 2,
        state_root,
        validator_set_digest: anchor.validator_set_digest,
        next_validator_set_digest: anchor.validator_set_digest,
        parent_checkpoint_digest: anchor.checkpoint_digest,
        finality_proof_digest: d(6),
        checkpoint_digest: d(0),
    };
    link.checkpoint_digest = link.canonical_digest();
    let trust = verify_trust_path_v0(&ProofFixture, anchor, &[link]).unwrap();
    let mut manifest = SnapshotManifestV0 {
        chain_id: anchor.chain_id,
        protocol_digest: anchor.protocol_digest,
        height: link.height,
        epoch: link.epoch,
        state_root,
        chunk_root: d(0),
        chunk_count: 2,
        maximum_chunk_bytes: 1,
        total_bytes: 2,
        schema_digest: d(5),
        checkpoint_digest: link.checkpoint_digest,
        manifest_digest: d(0),
    };
    let binding = manifest.chunk_binding_digest();
    let chunks: Vec<_> = bytes
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

fn complete_session() -> StateSyncSessionV0 {
    let (trust, manifest, chunks) = fixture();
    let mut session = StateSyncSessionV0::new(trust, manifest).unwrap();
    for chunk in chunks {
        session.accept_chunk(chunk).unwrap();
    }
    session.verify_complete(&HashRoot).unwrap();
    session
}

#[derive(Clone, Copy, PartialEq)]
enum Failure {
    None,
    Write,
    Commit,
}

struct Target {
    identity: StagingIdentityV0,
    calls: Vec<&'static str>,
    serving_root: Digest32V0,
    failure: Failure,
}

impl Target {
    fn new(generation: u64, digest: Digest32V0) -> Self {
        Self {
            identity: StagingIdentityV0 {
                generation,
                staging_digest: digest,
            },
            calls: Vec::new(),
            serving_root: d(90),
            failure: Failure::None,
        }
    }
}

impl NonDestructiveInstallTargetV0 for Target {
    type Error = io::Error;
    fn begin_staging(
        &mut self,
        _manifest: &SnapshotManifestV0,
    ) -> Result<StagingIdentityV0, io::Error> {
        self.calls.push("begin");
        Ok(self.identity)
    }
    fn write_chunk(
        &mut self,
        staging: StagingIdentityV0,
        _index: u32,
        _bytes: &[u8],
    ) -> Result<(), io::Error> {
        self.calls.push("write");
        assert_eq!(staging, self.identity);
        if self.failure == Failure::Write {
            return Err(io::Error::other("write failure fixture"));
        }
        Ok(())
    }
    fn commit_staging_cas(
        &mut self,
        staging: StagingIdentityV0,
        expected: Digest32V0,
        manifest: &SnapshotManifestV0,
    ) -> Result<InstallReceiptV0, io::Error> {
        self.calls.push("commit");
        assert_eq!(staging, self.identity);
        assert_eq!(expected, self.serving_root);
        if self.failure == Failure::Commit {
            return Err(io::Error::other("uncertain commit fixture"));
        }
        self.serving_root = manifest.state_root;
        Ok(InstallReceiptV0 {
            previous_root: expected,
            installed_root: self.serving_root,
            installed_height: manifest.height,
            generation: staging.generation,
            durable_receipt_digest: d(91),
        })
    }
    fn abort_staging(&mut self, staging: StagingIdentityV0) -> Result<(), io::Error> {
        self.calls.push("abort");
        assert_eq!(staging, self.identity);
        Ok(())
    }
}

#[test]
fn impossible_nonempty_chunk_totals_are_rejected_before_session_creation() {
    let (trust, manifest, _) = fixture();
    manifest.validate(&trust).unwrap();
    for total in [0, 1] {
        let mut invalid = manifest.clone();
        invalid.total_bytes = total;
        invalid.manifest_digest = invalid.canonical_digest();
        assert_eq!(
            invalid.validate(&trust),
            Err(StateSyncErrorV0::InvalidManifest)
        );
        assert!(matches!(
            StateSyncSessionV0::new(trust.clone(), invalid),
            Err(StateSyncErrorV0::InvalidManifest)
        ));
    }
    // One byte per chunk is the inclusive lower bound, not an off-by-one rejection.
    complete_session();
}

#[test]
fn zero_staging_identity_never_reaches_write_commit_or_abort() {
    let session = complete_session();
    for (generation, digest) in [(0, d(7)), (7, d(0)), (0, d(0))] {
        let mut target = Target::new(generation, digest);
        assert!(matches!(
            session.install(&HashRoot, &mut target, d(90)),
            Err(StateSyncInstallErrorV0::Protocol(
                StateSyncErrorV0::InvalidStagingIdentity
            ))
        ));
        assert_eq!(target.calls, ["begin"]);
        assert_eq!(target.serving_root, d(90));
    }
}

#[test]
fn valid_staging_identity_still_installs_the_verified_snapshot() {
    let session = complete_session();
    for generation in [1, u64::MAX] {
        let mut target = Target::new(generation, d(7));
        let receipt = session.install(&HashRoot, &mut target, d(90)).unwrap();
        assert_eq!(receipt.generation, generation);
        assert_eq!(
            receipt.installed_root,
            session.verify_complete(&HashRoot).unwrap().state_root()
        );
        assert_eq!(target.calls, ["begin", "write", "write", "commit"]);
        assert_eq!(target.serving_root, receipt.installed_root);
    }
}

#[test]
fn precommit_write_failure_aborts_only_valid_staging() {
    let mut target = Target::new(7, d(7));
    target.failure = Failure::Write;
    assert!(matches!(
        complete_session().install(&HashRoot, &mut target, d(90)),
        Err(StateSyncInstallErrorV0::Write(_))
    ));
    assert_eq!(target.calls, ["begin", "write", "abort"]);
    assert_eq!(target.serving_root, d(90));
}

#[test]
fn uncertain_commit_never_aborts_staging() {
    let mut target = Target::new(7, d(7));
    target.failure = Failure::Commit;
    assert!(matches!(
        complete_session().install(&HashRoot, &mut target, d(90)),
        Err(StateSyncInstallErrorV0::CommitUncertain(_))
    ));
    assert_eq!(target.calls, ["begin", "write", "write", "commit"]);
}
