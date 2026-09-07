//! Crash-consistent candidate bridge from durable peer replay to authority ingress.
//!
//! This module intentionally does not claim a cross-store atomic transaction. It
//! requires the peer frame to be durably pending before authority admission and
//! advances the durable peer replay floor only after an exact `Prepared` receipt
//! is supplied. A crash before the acknowledgement therefore reopens with the
//! same pending frame and repeats the authority operation idempotently.
//!
//! The bridge owns no socket, handshake, peer discovery, pacemaker, production
//! activation, signing, voting or finality authority.

use std::{error::Error, fmt};

use trnm_durable_file_adapters_v0::{
    candidate_frame_for_bound_ingress_v0, CandidatePeerReplayErrorV0,
    CandidatePersistentPeerAdmissionV0, PreparedPeerAcknowledgementV0,
};
use trnm_node_boundary_v0::{
    AuthorityReceiptV0, AuthorityStageV0, BoundIngressV0, BoundaryErrorV0, Digest32V0,
    NodeIdentityV0,
};
use trnm_poco_node_io::{AuthenticatedPeerFrameV0, PeerReplayStateV0};
use trnm_poco_node_production_v0::AuthorityIngressSourceV0;

#[derive(Debug)]
pub enum CandidatePersistentP2pIngressBridgeErrorV0 {
    Boundary(BoundaryErrorV0),
    Peer(CandidatePeerReplayErrorV0),
    NoPendingFrame,
    FrameMismatch,
    IngressMismatch,
    PreparedReceiptMismatch,
}

impl fmt::Display for CandidatePersistentP2pIngressBridgeErrorV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Boundary(error) => write!(formatter, "persistent P2P boundary failed: {error}"),
            Self::Peer(error) => write!(formatter, "persistent peer replay failed: {error}"),
            Self::NoPendingFrame => {
                formatter.write_str("persistent peer admission has no pending frame")
            }
            Self::FrameMismatch => formatter
                .write_str("durable pending peer frame differs from the bound ingress mapping"),
            Self::IngressMismatch => {
                formatter.write_str("authority ingress differs from the persistent peer mapping")
            }
            Self::PreparedReceiptMismatch => formatter
                .write_str("authority receipt is not the exact durable Prepared acknowledgement"),
        }
    }
}

impl Error for CandidatePersistentP2pIngressBridgeErrorV0 {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Boundary(error) => Some(error),
            Self::Peer(error) => Some(error),
            _ => None,
        }
    }
}

pub struct CandidatePersistentP2pIngressBridgeV0 {
    identity: NodeIdentityV0,
    admission: CandidatePersistentPeerAdmissionV0,
    pending: AuthenticatedPeerFrameV0,
    ingress: BoundIngressV0,
    ingress_digest: Digest32V0,
}

impl CandidatePersistentP2pIngressBridgeV0 {
    pub fn new(
        identity: NodeIdentityV0,
        admission: CandidatePersistentPeerAdmissionV0,
        ingress: BoundIngressV0,
    ) -> Result<Self, CandidatePersistentP2pIngressBridgeErrorV0> {
        identity
            .validate()
            .map_err(CandidatePersistentP2pIngressBridgeErrorV0::Boundary)?;
        ingress
            .validate(identity)
            .map_err(CandidatePersistentP2pIngressBridgeErrorV0::Boundary)?;

        let replay = admission.recovery_state();
        let pending = replay
            .pending()
            .ok_or(CandidatePersistentP2pIngressBridgeErrorV0::NoPendingFrame)?;
        let expected = candidate_frame_for_bound_ingress_v0(identity, replay.session(), &ingress)
            .map_err(CandidatePersistentP2pIngressBridgeErrorV0::Peer)?;
        if pending != expected {
            return Err(CandidatePersistentP2pIngressBridgeErrorV0::FrameMismatch);
        }

        let ingress_digest = ingress.ingress_digest();
        if ingress_digest == Digest32V0([0; 32]) {
            return Err(CandidatePersistentP2pIngressBridgeErrorV0::IngressMismatch);
        }
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
    pub const fn pending_peer_frame(&self) -> AuthenticatedPeerFrameV0 {
        self.pending
    }

    #[must_use]
    pub const fn peer_recovery_state(&self) -> PeerReplayStateV0 {
        self.admission.recovery_state()
    }

    #[must_use]
    pub const fn last_prepared_acknowledgement(&self) -> Option<PreparedPeerAcknowledgementV0> {
        self.admission.last_prepared_acknowledgement()
    }

    #[must_use]
    pub const fn admission(&self) -> &CandidatePersistentPeerAdmissionV0 {
        &self.admission
    }

    #[must_use]
    pub fn into_admission(self) -> CandidatePersistentPeerAdmissionV0 {
        self.admission
    }

    pub fn acknowledge_prepared(
        &mut self,
        receipt: AuthorityReceiptV0,
    ) -> Result<PeerReplayStateV0, CandidatePersistentP2pIngressBridgeErrorV0> {
        if receipt.binding != self.ingress.binding
            || receipt.durable_stage != AuthorityStageV0::Prepared
            || receipt.facts_digest != self.ingress_digest
            || receipt.record_digest == Digest32V0([0; 32])
        {
            return Err(CandidatePersistentP2pIngressBridgeErrorV0::PreparedReceiptMismatch);
        }
        self.admission
            .acknowledge_prepared(self.pending, receipt)
            .map_err(CandidatePersistentP2pIngressBridgeErrorV0::Peer)
    }
}

impl AuthorityIngressSourceV0 for CandidatePersistentP2pIngressBridgeV0 {
    type Error = CandidatePersistentP2pIngressBridgeErrorV0;

    fn verify_ingress(
        &mut self,
        identity: NodeIdentityV0,
        prior: Option<AuthorityReceiptV0>,
        ingress: &BoundIngressV0,
    ) -> Result<(), Self::Error> {
        if identity != self.identity
            || ingress.binding != self.ingress.binding
            || ingress.ingress_digest() != self.ingress_digest
            || self.admission.recovery_state().pending() != Some(self.pending)
        {
            return Err(CandidatePersistentP2pIngressBridgeErrorV0::IngressMismatch);
        }

        if let Some(receipt) = prior {
            receipt
                .binding
                .validate(identity)
                .map_err(CandidatePersistentP2pIngressBridgeErrorV0::Boundary)?;
            if receipt.facts_digest == Digest32V0([0; 32])
                || receipt.record_digest == Digest32V0([0; 32])
            {
                return Err(CandidatePersistentP2pIngressBridgeErrorV0::PreparedReceiptMismatch);
            }

            let exact_prepared_replay = receipt.binding == ingress.binding
                && receipt.durable_stage == AuthorityStageV0::Prepared
                && receipt.facts_digest == self.ingress_digest;
            if !exact_prepared_replay {
                let expected_height =
                    receipt.binding.height.checked_add(1).ok_or(
                        CandidatePersistentP2pIngressBridgeErrorV0::PreparedReceiptMismatch,
                    )?;
                if receipt.durable_stage != AuthorityStageV0::OutboundPublished
                    || ingress.binding.height != expected_height
                    || ingress.binding.parent_id != receipt.binding.block_id
                    || ingress.binding.operation_id == receipt.binding.operation_id
                {
                    return Err(
                        CandidatePersistentP2pIngressBridgeErrorV0::PreparedReceiptMismatch,
                    );
                }
            }
        }
        Ok(())
    }
}
