//! Candidate bridge from authenticated P2P replay admission to authority ingress.
//!
//! This module owns no socket, cryptographic handshake, durable replay store or
//! production activation. It binds one already-authenticated pending peer frame
//! to one exact `BoundIngressV0` and clears the peer replay nonce only after an
//! exact durable `Prepared` receipt is observed.

use std::{error::Error, fmt};

use trnm_node_boundary_v0::{
    AuthorityReceiptV0, AuthorityStageV0, BoundIngressV0, BoundaryErrorV0, Digest32V0,
    IngressFrameV0, NodeIdentityV0,
};
use trnm_poco_node_io::{
    AuthenticatedPeerFrameV0, CandidateP2pAdmissionV0, IoDigest32V0, PeerAdmissionErrorV0,
    PeerReplayStateV0,
};
use trnm_poco_node_production_v0::AuthorityIngressSourceV0;

#[derive(Debug)]
pub enum CandidateP2pIngressBridgeErrorV0 {
    Boundary(BoundaryErrorV0),
    Peer(PeerAdmissionErrorV0),
    NoPendingFrame,
    SessionMismatch,
    FrameMismatch,
    IngressMismatch,
    PreparedReceiptMismatch,
}

impl fmt::Display for CandidateP2pIngressBridgeErrorV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Boundary(error) => write!(formatter, "P2P ingress boundary failed: {error}"),
            Self::Peer(error) => write!(formatter, "P2P replay state failed: {error}"),
            Self::NoPendingFrame => formatter.write_str("P2P admission has no pending frame"),
            Self::SessionMismatch => {
                formatter.write_str("P2P session does not match node identity or ingress frame")
            }
            Self::FrameMismatch => {
                formatter.write_str("P2P frame does not match ingress bytes or replay identity")
            }
            Self::IngressMismatch => {
                formatter.write_str("authority ingress differs from the authenticated mapping")
            }
            Self::PreparedReceiptMismatch => formatter
                .write_str("prior authority receipt differs from authenticated ingress mapping"),
        }
    }
}

impl Error for CandidateP2pIngressBridgeErrorV0 {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Boundary(error) => Some(error),
            Self::Peer(error) => Some(error),
            _ => None,
        }
    }
}

pub struct CandidateP2pIngressBridgeV0 {
    identity: NodeIdentityV0,
    admission: CandidateP2pAdmissionV0,
    pending: AuthenticatedPeerFrameV0,
    ingress: BoundIngressV0,
    ingress_digest: Digest32V0,
}

impl CandidateP2pIngressBridgeV0 {
    pub fn new(
        identity: NodeIdentityV0,
        admission: CandidateP2pAdmissionV0,
        frame: &IngressFrameV0,
        ingress: BoundIngressV0,
    ) -> Result<Self, CandidateP2pIngressBridgeErrorV0> {
        identity
            .validate()
            .map_err(CandidateP2pIngressBridgeErrorV0::Boundary)?;
        ingress
            .validate(identity)
            .map_err(CandidateP2pIngressBridgeErrorV0::Boundary)?;
        let pending = admission
            .pending_frame()
            .ok_or(CandidateP2pIngressBridgeErrorV0::NoPendingFrame)?;
        let session = pending.session();
        if session.chain_id().bytes() != identity.chain_id.0
            || session.peer_id().bytes() != frame.peer_id.0
            || session.profile_digest().bytes() != frame.profile_digest.0
            || pending.replay_nonce() != frame.replay_nonce
        {
            return Err(CandidateP2pIngressBridgeErrorV0::SessionMismatch);
        }
        let expected_payload = Digest32V0::hash(b"trnm.p2p-frame-payload.v0", &[&frame.payload]);
        if pending.payload_digest().bytes() != expected_payload.0
            || pending.payload_bytes() != frame.payload.len()
        {
            return Err(CandidateP2pIngressBridgeErrorV0::FrameMismatch);
        }
        let rebound = BoundIngressV0::derive(
            identity,
            ingress.binding.height,
            ingress.binding.view,
            ingress.binding.block_id,
            ingress.binding.parent_id,
            frame.clone(),
        )
        .map_err(CandidateP2pIngressBridgeErrorV0::Boundary)?;
        if rebound.binding != ingress.binding
            || rebound.ingress_digest() != ingress.ingress_digest()
        {
            return Err(CandidateP2pIngressBridgeErrorV0::IngressMismatch);
        }
        let ingress_digest = ingress.ingress_digest();
        Ok(Self {
            identity,
            admission,
            pending,
            ingress,
            ingress_digest,
        })
    }

    #[must_use]
    pub const fn ingress(&self) -> &BoundIngressV0 {
        &self.ingress
    }

    #[must_use]
    pub const fn peer_recovery_state(&self) -> PeerReplayStateV0 {
        self.admission.recovery_state()
    }

    #[must_use]
    pub const fn pending_peer_frame(&self) -> AuthenticatedPeerFrameV0 {
        self.pending
    }

    /// Clear the peer replay nonce only after exact durable Prepared readback.
    pub fn acknowledge_prepared(
        &mut self,
        receipt: AuthorityReceiptV0,
    ) -> Result<PeerReplayStateV0, CandidateP2pIngressBridgeErrorV0> {
        if receipt.binding != self.ingress.binding
            || receipt.durable_stage != AuthorityStageV0::Prepared
            || receipt.facts_digest != self.ingress_digest
            || receipt.record_digest == Digest32V0([0; 32])
        {
            return Err(CandidateP2pIngressBridgeErrorV0::PreparedReceiptMismatch);
        }
        self.admission
            .acknowledge(self.pending)
            .map_err(CandidateP2pIngressBridgeErrorV0::Peer)
    }
}

impl AuthorityIngressSourceV0 for CandidateP2pIngressBridgeV0 {
    type Error = CandidateP2pIngressBridgeErrorV0;

    fn verify_ingress(
        &mut self,
        identity: NodeIdentityV0,
        prior: Option<AuthorityReceiptV0>,
        ingress: &BoundIngressV0,
    ) -> Result<(), Self::Error> {
        if identity != self.identity
            || ingress.binding != self.ingress.binding
            || ingress.ingress_digest() != self.ingress_digest
            || self.admission.pending_frame() != Some(self.pending)
        {
            return Err(CandidateP2pIngressBridgeErrorV0::IngressMismatch);
        }
        if let Some(receipt) = prior {
            receipt
                .binding
                .validate(identity)
                .map_err(CandidateP2pIngressBridgeErrorV0::Boundary)?;
            if receipt.facts_digest == Digest32V0([0; 32])
                || receipt.record_digest == Digest32V0([0; 32])
            {
                return Err(CandidateP2pIngressBridgeErrorV0::PreparedReceiptMismatch);
            }

            let exact_prepared_replay = receipt.binding == ingress.binding
                && receipt.durable_stage == AuthorityStageV0::Prepared
                && receipt.facts_digest == self.ingress_digest;
            if !exact_prepared_replay {
                let expected_height = receipt
                    .binding
                    .height
                    .checked_add(1)
                    .ok_or(CandidateP2pIngressBridgeErrorV0::PreparedReceiptMismatch)?;
                if receipt.durable_stage != AuthorityStageV0::OutboundPublished
                    || ingress.binding.height != expected_height
                    || ingress.binding.parent_id != receipt.binding.block_id
                    || ingress.binding.operation_id == receipt.binding.operation_id
                {
                    return Err(CandidateP2pIngressBridgeErrorV0::PreparedReceiptMismatch);
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::convert::Infallible;
    use trnm_node_boundary_v0::{
        AuthorityReceiptV0, IngressFrameV0, OperationBindingV0, ReferenceAuthorityCoordinatorV0,
    };
    use trnm_poco_node_io::{PeerFrameSourceV0, PeerReplayRecoverySourceV0, PeerSessionIdentityV0};
    use trnm_poco_node_production_v0::{AuthoritySessionReadinessV0, ProductionAuthoritySessionV0};

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

    fn node_frame() -> IngressFrameV0 {
        IngressFrameV0::new(d(4), d(5), 1, b"proposal".to_vec()).unwrap()
    }

    fn ingress() -> BoundIngressV0 {
        BoundIngressV0::derive(identity(), 1, 1, d(6), d(7), node_frame()).unwrap()
    }

    fn peer_session() -> PeerSessionIdentityV0 {
        PeerSessionIdentityV0::new(io_d(1), io_d(8), io_d(4), io_d(9), io_d(5), 1).unwrap()
    }

    fn peer_frame() -> AuthenticatedPeerFrameV0 {
        let frame = node_frame();
        let payload = Digest32V0::hash(b"trnm.p2p-frame-payload.v0", &[&frame.payload]);
        AuthenticatedPeerFrameV0::new(
            peer_session(),
            frame.replay_nonce,
            IoDigest32V0::new(payload.0).unwrap(),
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

    fn pending_admission() -> CandidateP2pAdmissionV0 {
        let mut admission = CandidateP2pAdmissionV0::recover_verified(
            PeerReplayStateV0::new(peer_session(), 0, None).unwrap(),
            &mut AcceptRecovery,
        )
        .unwrap();
        let frame = peer_frame();
        let verified = admission.verify_frame(frame, &mut AcceptFrame).unwrap();
        admission.admit_verified(verified).unwrap();
        admission
    }

    type Session = ProductionAuthoritySessionV0<
        ReferenceAuthorityCoordinatorV0,
        fn(&ReferenceAuthorityCoordinatorV0) -> Option<AuthorityReceiptV0>,
    >;

    fn session() -> Session {
        let mut session = ProductionAuthoritySessionV0::new(
            ReferenceAuthorityCoordinatorV0::new(identity()),
            ReferenceAuthorityCoordinatorV0::current,
        )
        .unwrap();
        assert_eq!(
            session.recover().unwrap(),
            AuthoritySessionReadinessV0::Ready
        );
        session
    }

    #[test]
    fn prepared_acknowledgement_advances_peer_nonce_only_after_durable_receipt() {
        let mut bridge = CandidateP2pIngressBridgeV0::new(
            identity(),
            pending_admission(),
            &node_frame(),
            ingress(),
        )
        .unwrap();
        let mut session = session();
        let verified = session
            .verify_ingress(bridge.ingress().clone(), &mut bridge)
            .unwrap();
        assert_eq!(bridge.peer_recovery_state().highest_acknowledged_nonce(), 0);
        let prepared = session.begin_verified(verified).unwrap();
        assert_eq!(bridge.peer_recovery_state().pending(), Some(peer_frame()));
        let state = bridge.acknowledge_prepared(prepared).unwrap();
        assert_eq!(state.highest_acknowledged_nonce(), 1);
        assert_eq!(state.pending(), None);
    }

    #[test]
    fn lost_ack_before_peer_clear_recovers_and_replays_exactly() {
        let mut bridge = CandidateP2pIngressBridgeV0::new(
            identity(),
            pending_admission(),
            &node_frame(),
            ingress(),
        )
        .unwrap();
        let mut first = session();
        let verified = first
            .verify_ingress(bridge.ingress().clone(), &mut bridge)
            .unwrap();
        let prepared = first.begin_verified(verified).unwrap();
        let coordinator = first.into_coordinator();

        let mut recovered = ProductionAuthoritySessionV0::new(
            coordinator,
            ReferenceAuthorityCoordinatorV0::current,
        )
        .unwrap();
        recovered.recover().unwrap();
        let replay = recovered
            .verify_ingress(bridge.ingress().clone(), &mut bridge)
            .unwrap();
        assert_eq!(recovered.begin_verified(replay).unwrap(), prepared);
        bridge.acknowledge_prepared(prepared).unwrap();
    }

    #[test]
    fn mismatched_payload_session_or_receipt_cannot_consume_peer_nonce() {
        let admission = pending_admission();
        let mut wrong_frame = node_frame();
        wrong_frame.payload.push(0);
        assert!(matches!(
            CandidateP2pIngressBridgeV0::new(identity(), admission, &wrong_frame, ingress()),
            Err(CandidateP2pIngressBridgeErrorV0::FrameMismatch)
        ));

        let mut bridge = CandidateP2pIngressBridgeV0::new(
            identity(),
            pending_admission(),
            &node_frame(),
            ingress(),
        )
        .unwrap();
        let bad = AuthorityReceiptV0 {
            binding: OperationBindingV0::derive(identity(), 2, 2, d(8), d(6), d(9)),
            durable_stage: AuthorityStageV0::Prepared,
            durable_sequence: 0,
            facts_digest: d(10),
            record_digest: d(11),
        };
        assert!(matches!(
            bridge.acknowledge_prepared(bad),
            Err(CandidateP2pIngressBridgeErrorV0::PreparedReceiptMismatch)
        ));
        assert_eq!(bridge.peer_recovery_state().highest_acknowledged_nonce(), 0);
        assert_eq!(bridge.peer_recovery_state().pending(), Some(peer_frame()));
    }
}
