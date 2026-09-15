// Native-v0 epoch-zero compatibility. The local proof adapter here records
// invocation only; this is not an implementation of a cryptographic verifier.
use super::*;
use std::cell::Cell;

#[derive(Debug)]
struct ProofRejected;
impl std::fmt::Display for ProofRejected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("proof rejected")
    }
}
impl std::error::Error for ProofRejected {}

struct CountProof {
    calls: Cell<u32>,
    reject: bool,
}
impl CheckpointProofVerifierV0 for CountProof {
    type Error = ProofRejected;
    fn verify_link(&self, _: &CheckpointLinkV0) -> Result<(), Self::Error> {
        self.calls.set(self.calls.get() + 1);
        if self.reject {
            Err(ProofRejected)
        } else {
            Ok(())
        }
    }
}
fn anchor_zero() -> WeakSubjectivityAnchorV0 {
    WeakSubjectivityAnchorV0 {
        chain_id: d(1),
        protocol_digest: d(2),
        epoch: 0,
        height: 4,
        checkpoint_digest: d(5),
        validator_set_digest: d(6),
    }
}

#[test]
fn epoch_zero_anchor_requires_positive_height_and_trust_identity() {
    let anchor = anchor_zero();
    assert_eq!(anchor.validate().unwrap(), anchor);
    for invalid in [
        WeakSubjectivityAnchorV0 {
            height: 0,
            ..anchor
        },
        WeakSubjectivityAnchorV0 {
            checkpoint_digest: d(0),
            ..anchor
        },
        WeakSubjectivityAnchorV0 {
            validator_set_digest: d(0),
            ..anchor
        },
    ] {
        assert_eq!(
            invalid.validate(),
            Err(StateSyncErrorV0::InvalidTrustAnchor)
        );
    }
}

#[test]
fn epoch_zero_path_still_invokes_and_obeys_proof_verifier() {
    let anchor = anchor_zero();
    let terminal = link(anchor, d(99));
    let verifier = CountProof {
        calls: Cell::new(0),
        reject: true,
    };
    assert!(matches!(
        verify_trust_path_v0(&verifier, anchor, &[terminal]),
        Err(StateSyncHostErrorV0::CheckpointProof(ProofRejected))
    ));
    assert_eq!(verifier.calls.get(), 1);
    let verifier = CountProof {
        calls: Cell::new(0),
        reject: false,
    };
    assert!(verify_trust_path_v0(&verifier, anchor, &[terminal]).is_ok());
    assert_eq!(verifier.calls.get(), 1);
}

#[test]
fn epoch_zero_cannot_skip_epochs_change_same_epoch_set_or_select_parent() {
    let anchor = anchor_zero();
    let good = link(anchor, d(99));
    for mut invalid in [
        CheckpointLinkV0 { epoch: 2, ..good },
        CheckpointLinkV0 {
            next_validator_set_digest: d(77),
            ..good
        },
        CheckpointLinkV0 {
            parent_checkpoint_digest: d(77),
            ..good
        },
    ] {
        invalid.checkpoint_digest = invalid.canonical_digest();
        let verifier = CountProof {
            calls: Cell::new(0),
            reject: false,
        };
        assert!(verify_trust_path_v0(&verifier, anchor, &[invalid]).is_err());
        assert_eq!(verifier.calls.get(), 0);
    }
}

#[test]
fn first_epoch_transition_requires_proof_and_cannot_reverse_epoch() {
    let anchor = anchor_zero();
    let mut terminal = link(anchor, d(99));
    terminal.epoch = 1;
    terminal.next_validator_set_digest = d(77);
    terminal.checkpoint_digest = terminal.canonical_digest();
    let rejecting = CountProof {
        calls: Cell::new(0),
        reject: true,
    };
    assert!(matches!(
        verify_trust_path_v0(&rejecting, anchor, &[terminal]),
        Err(StateSyncHostErrorV0::CheckpointProof(ProofRejected))
    ));
    assert_eq!(rejecting.calls.get(), 1);
    let next_anchor = WeakSubjectivityAnchorV0 { epoch: 1, ..anchor };
    let mut backwards = link(next_anchor, d(99));
    backwards.epoch = 0;
    backwards.checkpoint_digest = backwards.canonical_digest();
    let accepting = CountProof {
        calls: Cell::new(0),
        reject: false,
    };
    assert!(verify_trust_path_v0(&accepting, next_anchor, &[backwards]).is_err());
    assert_eq!(accepting.calls.get(), 0);
}

#[test]
fn epoch_zero_snapshot_verifies_exact_chunk_and_root_contract() {
    let anchor = anchor_zero();
    let schema = d(7);
    let bytes = b"native epoch zero";
    let state_root = HashRoot
        .recompute_state_root(schema, [bytes.as_slice()])
        .unwrap();
    let terminal = link(anchor, state_root);
    let verifier = CountProof {
        calls: Cell::new(0),
        reject: false,
    };
    let trust = verify_trust_path_v0(&verifier, anchor, &[terminal]).unwrap();
    let mut manifest = SnapshotManifestV0 {
        chain_id: anchor.chain_id,
        protocol_digest: anchor.protocol_digest,
        height: terminal.height,
        epoch: 0,
        state_root,
        chunk_root: d(0),
        chunk_count: 1,
        maximum_chunk_bytes: 1024,
        total_bytes: bytes.len() as u64,
        schema_digest: schema,
        checkpoint_digest: terminal.checkpoint_digest,
        manifest_digest: d(0),
    };
    let binding = manifest.chunk_binding_digest();
    let chunk = SnapshotChunkV0 {
        manifest_digest: binding,
        index: 0,
        bytes: bytes.to_vec(),
        chunk_digest: SnapshotChunkV0::canonical_digest(binding, 0, bytes),
    };
    manifest.chunk_root = chunk_merkle_root_v0(&[chunk.chunk_digest]);
    manifest.manifest_digest = manifest.canonical_digest();
    manifest.validate(&trust).unwrap();
    let mut session = StateSyncSessionV0::new(trust, manifest).unwrap();
    session.accept_chunk(chunk).unwrap();
    assert_eq!(
        session.verify_complete(&HashRoot).unwrap().state_root(),
        state_root
    );
    assert_eq!(verifier.calls.get(), 1);
}
