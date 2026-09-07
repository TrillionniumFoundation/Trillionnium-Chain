#![cfg(feature = "candidate-networked-authority")]

use std::{convert::Infallible, path::Path};

use trnm_durable_file_adapters_v0::{
    candidate_frame_for_bound_ingress_v0, CandidatePersistentPeerAdmissionV0,
};
use trnm_node_boundary_v0::{
    AuthorityReceiptV0, AuthorityStageV0, BoundIngressV0, Digest32V0, IngressFrameV0,
    NodeIdentityV0, OperationBindingV0,
};
use trnm_poco_node_host::{
    CandidatePersistentP2pIngressBridgeErrorV0, CandidatePersistentP2pIngressBridgeV0,
};
use trnm_poco_node_io::{
    AuthenticatedPeerFrameV0, IoDigest32V0, PeerFrameSourceV0, PeerReplayStateV0,
    PeerSessionIdentityV0,
};
use trnm_poco_node_production_v0::AuthorityIngressSourceV0;

fn d(byte: u8) -> Digest32V0 {
    Digest32V0([byte; 32])
}

fn io_d(byte: u8) -> IoDigest32V0 {
    IoDigest32V0::new([byte; 32]).expect("nonzero I/O digest")
}

fn identity() -> NodeIdentityV0 {
    NodeIdentityV0 {
        chain_id: d(1),
        validator_id: d(2),
        application_id: d(3),
        generation: 1,
    }
}

fn session() -> PeerSessionIdentityV0 {
    PeerSessionIdentityV0::new(io_d(1), io_d(8), io_d(4), io_d(9), io_d(5), 1)
        .expect("peer session")
}

fn ingress(height: u64, block: u8, parent: u8, nonce: u64) -> BoundIngressV0 {
    let frame = IngressFrameV0::new(d(4), d(5), nonce, vec![block]).expect("frame");
    BoundIngressV0::derive(identity(), height, height, d(block), d(parent), frame)
        .expect("bound ingress")
}

fn prepared(ingress: &BoundIngressV0) -> AuthorityReceiptV0 {
    AuthorityReceiptV0 {
        binding: ingress.binding,
        durable_stage: AuthorityStageV0::Prepared,
        durable_sequence: 0,
        facts_digest: ingress.ingress_digest(),
        record_digest: d(90),
    }
}

struct AcceptFrame;

impl PeerFrameSourceV0 for AcceptFrame {
    type Error = Infallible;

    fn verify_frame(
        &mut self,
        _state: PeerReplayStateV0,
        _frame: &AuthenticatedPeerFrameV0,
    ) -> Result<(), Self::Error> {
        Ok(())
    }
}

fn open_and_stage(root: &Path, ingress: &BoundIngressV0) -> CandidatePersistentPeerAdmissionV0 {
    let mut admission = CandidatePersistentPeerAdmissionV0::open(root, identity(), session())
        .expect("open persistent replay");
    let frame = candidate_frame_for_bound_ingress_v0(identity(), session(), ingress)
        .expect("canonical peer frame");
    let verified = admission
        .verify_frame(frame, &mut AcceptFrame)
        .expect("verify peer frame");
    admission
        .admit_verified(verified, ingress)
        .expect("persist pending frame");
    admission
}

#[test]
fn crash_before_ack_reopens_pending_and_exact_ack_is_idempotent() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let ingress = ingress(1, 10, 9, 1);
    let frame = candidate_frame_for_bound_ingress_v0(identity(), session(), &ingress)
        .expect("canonical peer frame");

    {
        let admission = open_and_stage(directory.path(), &ingress);
        let mut bridge =
            CandidatePersistentP2pIngressBridgeV0::new(identity(), admission, ingress.clone())
                .expect("bridge");
        bridge
            .verify_ingress(identity(), None, &ingress)
            .expect("initial authority ingress");
        assert_eq!(bridge.peer_recovery_state().pending(), Some(frame));
    }

    {
        let admission =
            CandidatePersistentPeerAdmissionV0::open(directory.path(), identity(), session())
                .expect("reopen pending replay");
        let mut bridge =
            CandidatePersistentP2pIngressBridgeV0::new(identity(), admission, ingress.clone())
                .expect("reopened bridge");
        bridge
            .verify_ingress(identity(), None, &ingress)
            .expect("replayed authority ingress");
        let receipt = prepared(&ingress);
        let state = bridge
            .acknowledge_prepared(receipt)
            .expect("acknowledge Prepared");
        assert_eq!(state.highest_acknowledged_nonce(), 1);
        assert_eq!(state.pending(), None);
        assert_eq!(
            bridge
                .acknowledge_prepared(receipt)
                .expect("idempotent acknowledgement replay"),
            state
        );
    }

    let reopened =
        CandidatePersistentPeerAdmissionV0::open(directory.path(), identity(), session())
            .expect("reopen acknowledged replay");
    assert_eq!(reopened.recovery_state().highest_acknowledged_nonce(), 1);
    assert_eq!(reopened.recovery_state().pending(), None);
    assert_eq!(
        reopened
            .last_prepared_acknowledgement()
            .expect("durable acknowledgement")
            .receipt(),
        prepared(&ingress)
    );
}

#[test]
fn wrong_receipt_never_advances_the_durable_peer_floor() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let ingress = ingress(1, 10, 9, 1);
    {
        let admission = open_and_stage(directory.path(), &ingress);
        let mut bridge =
            CandidatePersistentP2pIngressBridgeV0::new(identity(), admission, ingress.clone())
                .expect("bridge");
        let wrong_stage = AuthorityReceiptV0 {
            durable_stage: AuthorityStageV0::ApplicationSealed,
            ..prepared(&ingress)
        };
        assert!(matches!(
            bridge.acknowledge_prepared(wrong_stage),
            Err(CandidatePersistentP2pIngressBridgeErrorV0::PreparedReceiptMismatch)
        ));
        let wrong_binding = AuthorityReceiptV0 {
            binding: OperationBindingV0::derive(identity(), 2, 2, d(11), d(10), d(12)),
            ..prepared(&ingress)
        };
        assert!(matches!(
            bridge.acknowledge_prepared(wrong_binding),
            Err(CandidatePersistentP2pIngressBridgeErrorV0::PreparedReceiptMismatch)
        ));
        assert_eq!(bridge.peer_recovery_state().highest_acknowledged_nonce(), 0);
        assert!(bridge.peer_recovery_state().pending().is_some());
    }

    let reopened =
        CandidatePersistentPeerAdmissionV0::open(directory.path(), identity(), session())
            .expect("reopen after rejected receipt");
    assert_eq!(reopened.recovery_state().highest_acknowledged_nonce(), 0);
    assert!(reopened.recovery_state().pending().is_some());
    assert_eq!(reopened.last_prepared_acknowledgement(), None);
}

#[test]
fn terminal_predecessor_accepts_only_parent_bound_next_height() {
    let first = ingress(1, 10, 9, 1);
    let terminal = AuthorityReceiptV0 {
        binding: first.binding,
        durable_stage: AuthorityStageV0::OutboundPublished,
        durable_sequence: 7,
        facts_digest: d(70),
        record_digest: d(71),
    };
    let directory = tempfile::tempdir().expect("temporary directory");
    let second = ingress(2, 11, 10, 2);
    let admission = open_and_stage(directory.path(), &second);
    let mut bridge =
        CandidatePersistentP2pIngressBridgeV0::new(identity(), admission, second.clone())
            .expect("bridge");
    bridge
        .verify_ingress(identity(), Some(terminal), &second)
        .expect("parent-bound successor");

    let nonterminal = AuthorityReceiptV0 {
        durable_stage: AuthorityStageV0::CheckpointConfirmed,
        ..terminal
    };
    assert!(matches!(
        bridge.verify_ingress(identity(), Some(nonterminal), &second),
        Err(CandidatePersistentP2pIngressBridgeErrorV0::PreparedReceiptMismatch)
    ));
}
