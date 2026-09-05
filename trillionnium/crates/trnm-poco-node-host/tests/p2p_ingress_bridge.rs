#![cfg(feature = "candidate-networked-authority")]

use std::convert::Infallible;

use trnm_node_boundary_v0::{
    AuthorityReceiptV0, AuthorityStageV0, BoundIngressV0, Digest32V0, IngressFrameV0,
    NodeIdentityV0,
};
use trnm_poco_node_host::{CandidateP2pIngressBridgeErrorV0, CandidateP2pIngressBridgeV0};
use trnm_poco_node_io::{
    AuthenticatedPeerFrameV0, CandidateP2pAdmissionV0, IoDigest32V0, PeerFrameSourceV0,
    PeerReplayRecoverySourceV0, PeerReplayStateV0, PeerSessionIdentityV0,
};
use trnm_poco_node_production_v0::AuthorityIngressSourceV0;

fn d(byte: u8) -> Digest32V0 {
    Digest32V0([byte; 32])
}

fn io_d(byte: u8) -> IoDigest32V0 {
    IoDigest32V0::new([byte; 32]).unwrap()
}

fn identity() -> NodeIdentityV0 {
    NodeIdentityV0 {
        chain_id: d(1),
        validator_id: d(2),
        application_id: d(3),
        generation: 1,
    }
}

fn node_frame(nonce: u64, payload: u8) -> IngressFrameV0 {
    IngressFrameV0::new(d(4), d(5), nonce, vec![payload]).unwrap()
}

fn bound_ingress(height: u64, block: u8, parent: u8, nonce: u64) -> BoundIngressV0 {
    BoundIngressV0::derive(
        identity(),
        height,
        height,
        d(block),
        d(parent),
        node_frame(nonce, block),
    )
    .unwrap()
}

fn peer_session() -> PeerSessionIdentityV0 {
    PeerSessionIdentityV0::new(io_d(1), io_d(8), io_d(4), io_d(9), io_d(5), 1).unwrap()
}

fn peer_frame(nonce: u64, payload: u8) -> AuthenticatedPeerFrameV0 {
    let frame = node_frame(nonce, payload);
    let payload_digest = Digest32V0::hash(b"trnm.p2p-frame-payload.v0", &[&frame.payload]);
    AuthenticatedPeerFrameV0::new(
        peer_session(),
        nonce,
        IoDigest32V0::new(payload_digest.0).unwrap(),
        frame.payload.len(),
    )
    .unwrap()
}

struct AcceptRecovery;

impl PeerReplayRecoverySourceV0 for AcceptRecovery {
    type Error = Infallible;

    fn verify_recovery(&mut self, _state: &PeerReplayStateV0) -> Result<(), Self::Error> {
        Ok(())
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

fn pending_admission(highest: u64, nonce: u64, payload: u8) -> CandidateP2pAdmissionV0 {
    let mut admission = CandidateP2pAdmissionV0::recover_verified(
        PeerReplayStateV0::new(peer_session(), highest, None).unwrap(),
        &mut AcceptRecovery,
    )
    .unwrap();
    let frame = peer_frame(nonce, payload);
    let verified = admission.verify_frame(frame, &mut AcceptFrame).unwrap();
    admission.admit_verified(verified).unwrap();
    admission
}

fn bridge(
    highest: u64,
    height: u64,
    block: u8,
    parent: u8,
    nonce: u64,
) -> CandidateP2pIngressBridgeV0 {
    CandidateP2pIngressBridgeV0::new(
        identity(),
        pending_admission(highest, nonce, block),
        &node_frame(nonce, block),
        bound_ingress(height, block, parent, nonce),
    )
    .unwrap()
}

#[test]
fn initial_and_prepared_replay_sources_accept_only_the_exact_mapping() {
    let mut bridge = bridge(0, 1, 10, 9, 1);
    let ingress = bridge.ingress().clone();
    bridge.verify_ingress(identity(), None, &ingress).unwrap();

    let prepared = AuthorityReceiptV0 {
        binding: ingress.binding,
        durable_stage: AuthorityStageV0::Prepared,
        durable_sequence: 0,
        facts_digest: ingress.ingress_digest(),
        record_digest: d(20),
    };
    bridge
        .verify_ingress(identity(), Some(prepared), &ingress)
        .unwrap();

    let mut changed = ingress.clone();
    changed.binding.block_id = d(99);
    assert!(matches!(
        bridge.verify_ingress(identity(), Some(prepared), &changed),
        Err(CandidateP2pIngressBridgeErrorV0::IngressMismatch)
    ));
}

#[test]
fn terminal_predecessor_allows_only_the_parent_bound_next_height() {
    let first = bound_ingress(1, 10, 9, 1);
    let terminal = AuthorityReceiptV0 {
        binding: first.binding,
        durable_stage: AuthorityStageV0::OutboundPublished,
        durable_sequence: 7,
        facts_digest: d(30),
        record_digest: d(31),
    };
    let mut second = bridge(1, 2, 11, 10, 2);
    let ingress = second.ingress().clone();
    second
        .verify_ingress(identity(), Some(terminal), &ingress)
        .unwrap();

    let nonterminal = AuthorityReceiptV0 {
        durable_stage: AuthorityStageV0::CheckpointConfirmed,
        ..terminal
    };
    assert!(matches!(
        second.verify_ingress(identity(), Some(nonterminal), &ingress),
        Err(CandidateP2pIngressBridgeErrorV0::PreparedReceiptMismatch)
    ));

    let wrong_parent = AuthorityReceiptV0 {
        binding: BoundIngressV0::derive(identity(), 1, 1, d(12), d(9), node_frame(1, 12))
            .unwrap()
            .binding,
        ..terminal
    };
    assert!(matches!(
        second.verify_ingress(identity(), Some(wrong_parent), &ingress),
        Err(CandidateP2pIngressBridgeErrorV0::PreparedReceiptMismatch)
    ));
}

#[test]
fn peer_nonce_clears_only_for_the_exact_prepared_receipt() {
    let mut bridge = bridge(0, 1, 10, 9, 1);
    let ingress = bridge.ingress().clone();
    let prepared = AuthorityReceiptV0 {
        binding: ingress.binding,
        durable_stage: AuthorityStageV0::Prepared,
        durable_sequence: 0,
        facts_digest: ingress.ingress_digest(),
        record_digest: d(40),
    };
    let state = bridge.acknowledge_prepared(prepared).unwrap();
    assert_eq!(state.highest_acknowledged_nonce(), 1);
    assert_eq!(state.pending(), None);

    let mut other = bridge(0, 1, 10, 9, 1);
    let wrong = AuthorityReceiptV0 {
        facts_digest: d(41),
        ..prepared
    };
    assert!(matches!(
        other.acknowledge_prepared(wrong),
        Err(CandidateP2pIngressBridgeErrorV0::PreparedReceiptMismatch)
    ));
    assert_eq!(other.peer_recovery_state().highest_acknowledged_nonce(), 0);
    assert_eq!(
        other.peer_recovery_state().pending(),
        Some(peer_frame(1, 10))
    );
}
