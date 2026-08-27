//! Bounded consensus-message routing below the future validator owner.
//!
//! The router joins strict authenticated-frame decoding with the real weighted
//! QC/TC collectors. Its output is suitable for submission to a Node-owned
//! Core driver, but this type intentionally owns no Core or signing-capable
//! resource and cannot advance safety state by itself.

use trnm_consensus_types::{
    CertificateId, ConsensusParametersV0, QcReferenceV0, QuorumCertificate, TimeoutCertificateV0,
    TimeoutVote, ValidatorSet, View, Vote,
};

use crate::{
    collector::{
        decode_authenticated_consensus_frame_v0, required_pending_coordinate_capacity_v0,
        AdmittedConsensusMessageV0, CollectorAdmissionV0, ConsensusCertificateCollectorV0,
        ConsensusIngressErrorV0,
    },
    frame::AuthenticatedFrame,
    relay::{
        ConsensusRelayAdmissionWindowV0, ConsensusRelayEnvelopeV0, ConsensusRelayErrorV0,
        RelayAdmissionV0,
    },
    wire::{ConsensusWireError, UnboundProposalV0},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoutedConsensusActionV0 {
    Proposal(Box<UnboundProposalV0>),
    Vote {
        vote: Box<Vote>,
        formed_qc: Option<Box<QuorumCertificate>>,
    },
    TimeoutVote {
        vote: Box<TimeoutVote>,
        formed_tc: Option<Box<TimeoutCertificateV0>>,
    },
    QuorumCertificate(Box<QuorumCertificate>),
    TimeoutCertificate(Box<TimeoutCertificateV0>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutedConsensusRelayV0 {
    /// Present only for the first verified copy. An exact replay is
    /// authenticated and deduplicated without touching the consensus
    /// collector a second time.
    pub action: Option<RoutedConsensusActionV0>,
    pub admission: RelayAdmissionV0,
    pub message_id: [u8; 32],
    /// Present only when the first verified copy still has a positive hop
    /// budget. Exact replays are never forwarded again.
    pub forward: Option<ConsensusRelayEnvelopeV0>,
}

#[derive(Debug)]
pub enum ConsensusRelayIngressErrorV0 {
    Envelope(ConsensusRelayErrorV0),
    Consensus(ConsensusIngressErrorV0),
}

impl std::fmt::Display for ConsensusRelayIngressErrorV0 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Envelope(error) => write!(formatter, "relay envelope: {error}"),
            Self::Consensus(error) => write!(formatter, "relayed consensus statement: {error}"),
        }
    }
}

impl std::error::Error for ConsensusRelayIngressErrorV0 {}

pub struct BoundedConsensusIngressLoopV0 {
    validator_set: ValidatorSet,
    consensus_parameters: ConsensusParametersV0,
    collector: ConsensusCertificateCollectorV0,
}

impl BoundedConsensusIngressLoopV0 {
    pub fn new_for_retained_views(
        validator_set: ValidatorSet,
        consensus_parameters: ConsensusParametersV0,
        retained_views: usize,
    ) -> Result<Self, ConsensusIngressErrorV0> {
        let capacity = required_pending_coordinate_capacity_v0(
            validator_set.validators().len(),
            retained_views,
        )?;
        Self::new(validator_set, consensus_parameters, capacity)
    }

    pub fn new(
        validator_set: ValidatorSet,
        consensus_parameters: ConsensusParametersV0,
        max_pending_coordinates: usize,
    ) -> Result<Self, ConsensusIngressErrorV0> {
        validator_set
            .validate_against_parameters(&consensus_parameters)
            .map_err(|error| ConsensusIngressErrorV0::InvalidCertificate(format!("{error:?}")))?;
        let collector =
            ConsensusCertificateCollectorV0::new(validator_set.clone(), max_pending_coordinates)?;
        Ok(Self {
            validator_set,
            consensus_parameters,
            collector,
        })
    }

    pub fn admit_authenticated_frame(
        &mut self,
        frame: &AuthenticatedFrame,
    ) -> Result<RoutedConsensusActionV0, ConsensusIngressErrorV0> {
        require_authenticated_session_v0(frame)?;
        let message = decode_authenticated_consensus_frame_v0(
            frame,
            &self.validator_set,
            &self.consensus_parameters,
        )?;
        self.admit_decoded_consensus_message(message)
    }

    /// Admits one locally produced Vote through the exact same strict
    /// collector path as a decoded remote Vote. Local statements have no
    /// synthetic transport sender/session: the typed Vote carries its author
    /// and is independently verified against the validator set before exact
    /// replay/equivocation handling and deterministic QC aggregation.
    pub fn admit_local_vote_v0(
        &mut self,
        vote: Vote,
    ) -> Result<RoutedConsensusActionV0, ConsensusIngressErrorV0> {
        self.admit_decoded_consensus_message(AdmittedConsensusMessageV0::Vote(vote))
    }

    /// Admits one locally produced TimeoutVote through the exact same strict
    /// collector path as a decoded remote TimeoutVote. No self transport
    /// identity is manufactured; certificate-reference validation, exact
    /// replay/equivocation handling, and TC aggregation remain collector-owned.
    pub fn admit_local_timeout_vote_v0(
        &mut self,
        vote: TimeoutVote,
    ) -> Result<RoutedConsensusActionV0, ConsensusIngressErrorV0> {
        self.admit_decoded_consensus_message(AdmittedConsensusMessageV0::TimeoutVote(vote))
    }

    /// Seeds one complete, strictly verified authoritative QC carrier from a
    /// consumed Node owner. A bare QcRef/ID is intentionally insufficient,
    /// and callers cannot manufacture a self-authenticated transport frame.
    /// Exact replay is an inert collector admission.
    pub(crate) fn seed_verified_qc_reference_v0(
        &mut self,
        reference: QcReferenceV0,
    ) -> Result<CollectorAdmissionV0, ConsensusIngressErrorV0> {
        self.collector.register_qc_reference(reference)
    }

    /// Retries timeout-certificate formation for all retained timeout views.
    ///
    /// TimeoutVotes are independently authenticated and may be observed
    /// before the complete QC carrier they reference.  The strict collector
    /// keeps those votes, while this event-loop helper treats only a missing
    /// carrier as pending and returns certificates once a later QC admission
    /// makes them fully resolvable.
    pub(crate) fn retry_pending_timeout_certificates_v0(
        &mut self,
    ) -> Result<Vec<TimeoutCertificateV0>, ConsensusIngressErrorV0> {
        let views = self.collector.pending_timeout_views();
        let mut formed = Vec::new();
        for view in views {
            let already_formed = self.collector.canonical_timeout_certificate(view).is_some();
            if !already_formed {
                if let Some(certificate) = self.collector.try_timeout_certificate_if_ready(view)? {
                    formed.push(certificate);
                }
            }
        }
        Ok(formed)
    }

    fn admit_decoded_consensus_message(
        &mut self,
        message: AdmittedConsensusMessageV0,
    ) -> Result<RoutedConsensusActionV0, ConsensusIngressErrorV0> {
        match message {
            AdmittedConsensusMessageV0::Proposal(proposal) => {
                // Proposal witnesses carry the same authority-bearing QC/TC
                // values as standalone frames.  Stage their collector
                // admission before returning the proposal so the subsequent
                // Node authority call cannot bypass watermark, capacity, or
                // frozen-certificate checks. Same-coordinate alternate QCs
                // remain exact protocol evidence and are forwarded unchanged
                // to Core, which owns the digest-ordering semantics.
                let mut staged = self.collector.clone();
                if let Some(certificate) = proposal.justify_qc().as_ordinary() {
                    staged.register_qc_reference(QcReferenceV0::ordinary(certificate.clone()))?;
                } else {
                    staged.register_qc_reference(proposal.justify_qc().clone())?;
                }
                if let Some(certificate) = proposal.timeout_certificate() {
                    staged.register_timeout_certificate(certificate.clone())?;
                }
                // Do not commit the staged snapshot yet.  A Proposal may be
                // buffered by the pending-proposal gate and therefore may
                // never become an authority event; freezing its embedded
                // carriers at ingress would suppress a later actionable
                // standalone QC/TC.  The staged clone still performs all
                // validation and bounded-capacity checks without mutating the
                // live collector.
                Ok(RoutedConsensusActionV0::Proposal(proposal))
            }
            AdmittedConsensusMessageV0::Vote(vote) => {
                self.collector.admit_vote(vote.clone())?;
                let formed_qc = self
                    .collector
                    .try_quorum_certificate(vote.view(), vote.height(), vote.block_id())?
                    .map(Box::new);
                Ok(RoutedConsensusActionV0::Vote {
                    vote: Box::new(vote),
                    formed_qc,
                })
            }
            AdmittedConsensusMessageV0::TimeoutVote(vote) => {
                self.collector.admit_timeout_vote(vote.clone())?;
                let formed_tc = self
                    .collector
                    .try_timeout_certificate_if_ready(vote.view())?
                    .map(Box::new);
                Ok(RoutedConsensusActionV0::TimeoutVote {
                    vote: Box::new(vote),
                    formed_tc,
                })
            }
            AdmittedConsensusMessageV0::QuorumCertificate(certificate) => {
                let view = certificate.view();
                let height = certificate.height();
                let block_id = certificate.block_id();
                self.collector.register_qc_reference(
                    trnm_consensus_types::QcReferenceV0::ordinary(certificate.clone()),
                )?;
                // Route the first frozen representation into the runtime
                // archive lane. Same-coordinate signer-subset alternates are
                // retained as exact collector evidence, but must not create a
                // second append-only archive record or a second authority
                // transition.
                let exact = self
                    .collector
                    .canonical_quorum_certificate(view, height, block_id)
                    .cloned()
                    .unwrap_or(certificate);
                Ok(RoutedConsensusActionV0::QuorumCertificate(Box::new(exact)))
            }
            AdmittedConsensusMessageV0::TimeoutCertificate(certificate) => {
                let exact = self
                    .collector
                    .register_timeout_certificate(certificate.clone())?;
                Ok(RoutedConsensusActionV0::TimeoutCertificate(Box::new(exact)))
            }
        }
    }

    pub fn collector(&self) -> &ConsensusCertificateCollectorV0 {
        &self.collector
    }

    pub fn prune_before_view(
        &mut self,
        minimum_retained_view: View,
        retain_qc_references: impl IntoIterator<Item = CertificateId>,
    ) -> Result<(), ConsensusIngressErrorV0> {
        self.collector
            .prune_before_view(minimum_retained_view, retain_qc_references)
    }

    /// Verifies one hop-authenticated relay frame, then independently verifies
    /// the embedded statement under its original author before changing either
    /// the consensus collector or relay-dedup state.
    ///
    /// The caller owns the bounded dedup window because its lifetime is the
    /// validator process, not one QC/TC collector coordinate.
    pub fn admit_consensus_relay_frame(
        &mut self,
        outer: &AuthenticatedFrame,
        relay_window: &mut ConsensusRelayAdmissionWindowV0,
    ) -> Result<RoutedConsensusRelayV0, ConsensusRelayIngressErrorV0> {
        require_authenticated_session_v0(outer).map_err(ConsensusRelayIngressErrorV0::Consensus)?;
        if outer.kind != crate::frame::FrameKind::ConsensusRelay
            || self.validator_set.validator(outer.sender).is_none()
        {
            return Err(ConsensusRelayIngressErrorV0::Consensus(
                ConsensusIngressErrorV0::UnsupportedFrameKind,
            ));
        }
        let envelope = ConsensusRelayEnvelopeV0::decode(&outer.payload, &self.validator_set)
            .map_err(ConsensusRelayIngressErrorV0::Envelope)?;
        let embedded = envelope.embedded_statement_frame();
        let message = decode_authenticated_consensus_frame_v0(
            &embedded,
            &self.validator_set,
            &self.consensus_parameters,
        )
        .map_err(ConsensusRelayIngressErrorV0::Consensus)?;
        let statement_view = decoded_message_view_v0(&message);
        let preflight = relay_window
            .preflight_at_view(&envelope, statement_view)
            .map_err(ConsensusRelayIngressErrorV0::Envelope)?;
        if preflight == RelayAdmissionV0::ExactReplay {
            return Ok(RoutedConsensusRelayV0 {
                action: None,
                admission: RelayAdmissionV0::ExactReplay,
                message_id: envelope.message_id(),
                forward: None,
            });
        }
        // A strict, independently verified statement consumes its process-
        // local relay identity before collector routing. If the bounded
        // collector subsequently fail-stops (for example on capacity), the
        // same signed statement cannot repeatedly mutate or re-run it.
        let admission = relay_window
            .admit_verified_at_view(&envelope, statement_view)
            .map_err(ConsensusRelayIngressErrorV0::Envelope)?;
        debug_assert_eq!(admission, preflight);
        let action = self
            .admit_decoded_consensus_message(message)
            .map_err(ConsensusRelayIngressErrorV0::Consensus)?;
        let forward = match admission {
            RelayAdmissionV0::New => envelope.forwarded(),
            RelayAdmissionV0::ExactReplay => None,
        };
        Ok(RoutedConsensusRelayV0 {
            action: Some(action),
            admission,
            message_id: envelope.message_id(),
            forward,
        })
    }
}

/// The lower-level collector APIs receive a plain frame value rather than a
/// transport-owned connection.  The real mesh path validates the session in
/// `frame::decode`, but retaining this check at the collector boundary keeps a
/// synthetic/partially-authenticated zero-session frame from being mistaken
/// for a live consensus ingress when a caller bypasses that path.
fn require_authenticated_session_v0(
    frame: &AuthenticatedFrame,
) -> Result<(), ConsensusIngressErrorV0> {
    if frame.session == [0; 32] {
        return Err(ConsensusIngressErrorV0::Wire(
            ConsensusWireError::Malformed("zero authenticated session"),
        ));
    }
    Ok(())
}

fn decoded_message_view_v0(message: &AdmittedConsensusMessageV0) -> View {
    match message {
        AdmittedConsensusMessageV0::Proposal(proposal) => proposal.block().header().view(),
        AdmittedConsensusMessageV0::Vote(vote) => vote.view(),
        AdmittedConsensusMessageV0::TimeoutVote(vote) => vote.view(),
        AdmittedConsensusMessageV0::QuorumCertificate(certificate) => certificate.view(),
        AdmittedConsensusMessageV0::TimeoutCertificate(certificate) => certificate.timed_out_view(),
    }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer, SigningKey};
    use trnm_consensus_types::{
        BlockId, ChainId, ConsensusPublicKey, Epoch, GenesisHash, Height, ProtocolVersion, QcRef,
        QcReferenceV0, SignatureBytes, Validator, ValidatorId, View, VotingPower,
    };

    use super::*;
    use crate::{
        frame::FrameKind,
        wire::{encode_quorum_certificate, encode_timeout_vote, encode_vote},
    };

    fn fixture() -> (Vec<SigningKey>, ValidatorSet, ConsensusParametersV0) {
        let keys: Vec<_> = (1u8..=7)
            .map(|seed| SigningKey::from_bytes(&[seed; 32]))
            .collect();
        // reference_shadow_v0 requires max-validator-power share <=25%.
        let powers = [4u64, 3, 3, 2, 2, 1, 1];
        let parameters = ConsensusParametersV0::reference_shadow_v0();
        let validators = keys
            .iter()
            .enumerate()
            .map(|(index, key)| {
                Validator::new(
                    ValidatorId::new([u8::try_from(index + 1).unwrap(); 32]),
                    ConsensusPublicKey::new(key.verifying_key().to_bytes()),
                    VotingPower::new(powers[index]).unwrap(),
                )
                .unwrap()
            })
            .collect();
        let set = ValidatorSet::new(
            GenesisHash::new([0x51; 32]),
            ChainId::new("trnm-g3-ingress-loop-test").unwrap(),
            ProtocolVersion::V0,
            Epoch::new(0),
            parameters.hash(),
            validators,
        )
        .unwrap();
        (keys, set, parameters)
    }

    fn vote(keys: &[SigningKey], set: &ValidatorSet, index: usize, block: BlockId) -> Vote {
        let root = Vote::signing_root_for_set(set, View::new(2), Height::new(1), block).unwrap();
        Vote::new(
            set.chain_id(),
            set.protocol_version(),
            set.epoch(),
            View::new(2),
            Height::new(1),
            block,
            set.id(),
            set.validators()[index].id(),
            SignatureBytes::from_array(keys[index].sign(root.as_bytes()).to_bytes()),
            set,
        )
        .unwrap()
    }

    fn timeout_vote(
        keys: &[SigningKey],
        set: &ValidatorSet,
        index: usize,
        high_qc: QcRef,
    ) -> TimeoutVote {
        let root = TimeoutVote::signing_root_for_set(set, View::new(3), high_qc).unwrap();
        TimeoutVote::new(
            set.chain_id(),
            set.protocol_version(),
            set.epoch(),
            View::new(3),
            set.id(),
            high_qc,
            set.validators()[index].id(),
            SignatureBytes::from_array(keys[index].sign(root.as_bytes()).to_bytes()),
            set,
        )
        .unwrap()
    }

    fn quorum_certificate(
        keys: &[SigningKey],
        set: &ValidatorSet,
        block: BlockId,
    ) -> QuorumCertificate {
        QuorumCertificate::new(
            set.chain_id(),
            set.protocol_version(),
            set.epoch(),
            View::new(2),
            Height::new(1),
            block,
            set.id(),
            (0..4).map(|index| vote(keys, set, index, block)).collect(),
            set,
        )
        .unwrap()
    }

    #[test]
    fn verified_qc_seed_is_exact_replay_inert_and_rejects_foreign_carrier() {
        let (keys, set, parameters) = fixture();
        let certificate = quorum_certificate(&keys, &set, BlockId::new([0x60; 32]));
        let reference = QcReferenceV0::ordinary(certificate);
        let mut router = BoundedConsensusIngressLoopV0::new(set.clone(), parameters, 16).unwrap();
        assert_eq!(
            router
                .seed_verified_qc_reference_v0(reference.clone())
                .unwrap(),
            CollectorAdmissionV0::Inserted
        );
        assert_eq!(
            router.seed_verified_qc_reference_v0(reference).unwrap(),
            CollectorAdmissionV0::ExactReplay
        );

        let foreign = ValidatorSet::new(
            GenesisHash::new([0x5f; 32]),
            ChainId::new("trnm-g3-ingress-foreign").unwrap(),
            ProtocolVersion::V0,
            Epoch::new(0),
            parameters.hash(),
            set.validators().to_vec(),
        )
        .unwrap();
        let foreign_certificate = quorum_certificate(&keys, &foreign, BlockId::new([0x5e; 32]));
        assert!(matches!(
            router.seed_verified_qc_reference_v0(QcReferenceV0::ordinary(foreign_certificate)),
            Err(ConsensusIngressErrorV0::InvalidCertificate(_))
        ));
    }

    #[test]
    fn local_vote_uses_exact_validation_dedup_and_qc_aggregation() {
        let (keys, set, parameters) = fixture();
        let block = BlockId::new([0x61; 32]);
        let mut router = BoundedConsensusIngressLoopV0::new(set.clone(), parameters, 16).unwrap();

        let root = Vote::signing_root_for_set(&set, View::new(2), Height::new(1), block).unwrap();
        let invalid = Vote::new(
            set.chain_id(),
            set.protocol_version(),
            set.epoch(),
            View::new(2),
            Height::new(1),
            block,
            set.id(),
            set.validators()[0].id(),
            SignatureBytes::from_array(keys[1].sign(root.as_bytes()).to_bytes()),
            &set,
        )
        .unwrap();
        assert!(matches!(
            router.admit_local_vote_v0(invalid),
            Err(ConsensusIngressErrorV0::InvalidCertificate(_))
        ));

        let first = vote(&keys, &set, 0, block);
        for replay in [first.clone(), first] {
            let RoutedConsensusActionV0::Vote { formed_qc, .. } =
                router.admit_local_vote_v0(replay).unwrap()
            else {
                panic!("local Vote routed to wrong action");
            };
            assert!(formed_qc.is_none());
        }
        for index in 1..4 {
            let RoutedConsensusActionV0::Vote { formed_qc, .. } = router
                .admit_local_vote_v0(vote(&keys, &set, index, block))
                .unwrap()
            else {
                panic!("local Vote routed to wrong action");
            };
            if index < 3 {
                assert!(formed_qc.is_none());
            } else {
                let certificate = formed_qc.unwrap();
                assert_eq!(certificate.votes().len(), 4);
                assert_eq!(certificate.block_id(), block);
            }
        }
    }

    #[test]
    fn local_timeout_vote_uses_exact_validation_dedup_and_tc_aggregation() {
        let (keys, set, parameters) = fixture();
        let block = BlockId::new([0x63; 32]);
        let mut router = BoundedConsensusIngressLoopV0::new(set.clone(), parameters, 16).unwrap();
        let qc = quorum_certificate(&keys, &set, block);
        let high_qc = QcRef::from(&qc);
        assert_eq!(
            router
                .seed_verified_qc_reference_v0(QcReferenceV0::ordinary(qc.clone()))
                .unwrap(),
            CollectorAdmissionV0::Inserted
        );

        let root = TimeoutVote::signing_root_for_set(&set, View::new(3), high_qc).unwrap();
        let invalid = TimeoutVote::new(
            set.chain_id(),
            set.protocol_version(),
            set.epoch(),
            View::new(3),
            set.id(),
            high_qc,
            set.validators()[0].id(),
            SignatureBytes::from_array(keys[1].sign(root.as_bytes()).to_bytes()),
            &set,
        )
        .unwrap();
        assert!(matches!(
            router.admit_local_timeout_vote_v0(invalid),
            Err(ConsensusIngressErrorV0::InvalidCertificate(_))
        ));

        let first = timeout_vote(&keys, &set, 0, high_qc);
        for replay in [first.clone(), first] {
            let RoutedConsensusActionV0::TimeoutVote { formed_tc, .. } =
                router.admit_local_timeout_vote_v0(replay).unwrap()
            else {
                panic!("local TimeoutVote routed to wrong action");
            };
            assert!(formed_tc.is_none());
        }
        for index in 1..4 {
            let RoutedConsensusActionV0::TimeoutVote { formed_tc, .. } = router
                .admit_local_timeout_vote_v0(timeout_vote(&keys, &set, index, high_qc))
                .unwrap()
            else {
                panic!("local TimeoutVote routed to wrong action");
            };
            if index < 3 {
                assert!(formed_tc.is_none());
            } else {
                let certificate = formed_tc.unwrap();
                assert_eq!(certificate.entries().len(), 4);
                assert_eq!(certificate.selected_high_qc_digest(), qc.id());
                assert_eq!(
                    certificate.referenced_qcs(),
                    &[QcReferenceV0::ordinary(qc.clone())]
                );
            }
        }
    }

    #[test]
    fn router_forms_weighted_qc_only_at_quorum_and_registers_it() {
        let (keys, set, parameters) = fixture();
        let block = BlockId::new([0x62; 32]);
        let mut router = BoundedConsensusIngressLoopV0::new(set.clone(), parameters, 16).unwrap();
        for index in 0..4 {
            let vote = vote(&keys, &set, index, block);
            let frame = AuthenticatedFrame {
                sender: vote.author(),
                session: [u8::try_from(index + 1).unwrap(); 32],
                sequence: 0,
                kind: FrameKind::Vote,
                payload: encode_vote(&vote),
            };
            let RoutedConsensusActionV0::Vote { formed_qc, .. } =
                router.admit_authenticated_frame(&frame).unwrap()
            else {
                panic!("vote frame routed to wrong action");
            };
            if index < 3 {
                assert!(formed_qc.is_none());
            } else {
                let certificate = formed_qc.unwrap();
                assert_eq!(certificate.votes().len(), 4);
                assert_eq!(certificate.block_id(), block);
            }
        }
    }

    #[test]
    fn timeout_votes_wait_for_a_late_exact_qc_carrier() {
        let (keys, set, parameters) = fixture();
        let block = BlockId::new([0x64; 32]);
        let qc = quorum_certificate(&keys, &set, block);
        let high_qc = QcRef::from(&qc);
        let mut router = BoundedConsensusIngressLoopV0::new(set.clone(), parameters, 16).unwrap();

        // The timeout quorum is intentionally delivered before the QC frame.
        // Each TimeoutVote is still authenticated and retained, but the
        // event-loop route must defer certificate formation rather than turn
        // a transport ordering difference into a validator failure.
        for index in 0..4 {
            let timeout = timeout_vote(&keys, &set, index, high_qc);
            let frame = AuthenticatedFrame {
                sender: timeout.author(),
                session: [u8::try_from(index + 0x20).unwrap(); 32],
                sequence: 0,
                kind: FrameKind::TimeoutVote,
                payload: encode_timeout_vote(&timeout),
            };
            let RoutedConsensusActionV0::TimeoutVote { formed_tc, .. } =
                router.admit_authenticated_frame(&frame).unwrap()
            else {
                panic!("timeout frame reached the wrong action");
            };
            assert!(formed_tc.is_none());
        }
        assert!(router
            .collector()
            .canonical_timeout_certificate(View::new(3))
            .is_none());

        // The strict collector API continues to expose a missing carrier to
        // callers that explicitly request a fail-closed diagnostic.
        assert!(matches!(
            router
                .collector()
                .clone()
                .try_timeout_certificate(View::new(3)),
            Err(ConsensusIngressErrorV0::MissingQcReference(_))
        ));

        let qc_frame = AuthenticatedFrame {
            sender: set.validators()[0].id(),
            session: [0x2f; 32],
            sequence: 0,
            kind: FrameKind::QuorumCertificate,
            payload: encode_quorum_certificate(&qc).unwrap(),
        };
        assert!(matches!(
            router.admit_authenticated_frame(&qc_frame).unwrap(),
            RoutedConsensusActionV0::QuorumCertificate(_)
        ));

        let formed = router
            .retry_pending_timeout_certificates_v0()
            .expect("late QC should release the retained timeout quorum");
        assert_eq!(formed.len(), 1);
        assert_eq!(formed[0].timed_out_view(), View::new(3));
        assert_eq!(formed[0].selected_high_qc_digest(), qc.id());
        assert!(router
            .retry_pending_timeout_certificates_v0()
            .expect("formed TC retry is idempotent")
            .is_empty());
    }

    #[test]
    fn zero_session_transport_frames_fail_closed_before_admission() {
        let (keys, set, parameters) = fixture();
        let block = BlockId::new([0x70; 32]);
        let vote = vote(&keys, &set, 0, block);
        let direct = AuthenticatedFrame {
            sender: vote.author(),
            session: [0; 32],
            sequence: 0,
            kind: FrameKind::Vote,
            payload: encode_vote(&vote),
        };
        let mut router = BoundedConsensusIngressLoopV0::new(set.clone(), parameters, 16).unwrap();
        assert!(matches!(
            router.admit_authenticated_frame(&direct),
            Err(ConsensusIngressErrorV0::Wire(
                ConsensusWireError::Malformed("zero authenticated session")
            ))
        ));

        let envelope = ConsensusRelayEnvelopeV0::new(
            vote.author(),
            FrameKind::Vote,
            1,
            encode_vote(&vote),
            &set,
            &keys[0],
        )
        .unwrap();
        let relay = AuthenticatedFrame {
            sender: set.validators()[1].id(),
            session: [0; 32],
            sequence: 0,
            kind: FrameKind::ConsensusRelay,
            payload: envelope.encode(),
        };
        let mut relay_window = ConsensusRelayAdmissionWindowV0::new(16).unwrap();
        assert!(matches!(
            router.admit_consensus_relay_frame(&relay, &mut relay_window),
            Err(ConsensusRelayIngressErrorV0::Consensus(
                ConsensusIngressErrorV0::Wire(ConsensusWireError::Malformed(
                    "zero authenticated session"
                ))
            ))
        ));
        assert!(relay_window.is_empty());
    }

    #[test]
    fn relay_preserves_original_author_verification_and_forwards_once() {
        let (keys, set, parameters) = fixture();
        let block = BlockId::new([0x72; 32]);
        let vote = vote(&keys, &set, 0, block);
        let envelope = ConsensusRelayEnvelopeV0::new(
            vote.author(),
            FrameKind::Vote,
            3,
            encode_vote(&vote),
            &set,
            &keys[0],
        )
        .unwrap();
        // The authenticated hop is deliberately a different validator from
        // the statement author.
        let outer = AuthenticatedFrame {
            sender: set.validators()[4].id(),
            session: [0x81; 32],
            sequence: 0,
            kind: FrameKind::ConsensusRelay,
            payload: envelope.encode(),
        };
        let mut router = BoundedConsensusIngressLoopV0::new(set, parameters, 16).unwrap();
        let mut window = ConsensusRelayAdmissionWindowV0::new(16).unwrap();
        let first = router
            .admit_consensus_relay_frame(&outer, &mut window)
            .unwrap();
        assert_eq!(first.admission, RelayAdmissionV0::New);
        assert_eq!(first.forward.as_ref().unwrap().remaining_hops(), 2);
        let RoutedConsensusActionV0::Vote {
            vote: routed,
            formed_qc,
        } = first.action.unwrap()
        else {
            panic!("relay routed to wrong action");
        };
        assert_eq!(*routed, vote);
        assert!(formed_qc.is_none());

        let replay = router
            .admit_consensus_relay_frame(&outer, &mut window)
            .unwrap();
        assert_eq!(replay.admission, RelayAdmissionV0::ExactReplay);
        assert!(replay.action.is_none());
        assert!(replay.forward.is_none());
        assert_eq!(window.len(), 1);

        router
            .prune_before_view(View::new(3), std::iter::empty())
            .unwrap();
        window.prune_before_view(View::new(3)).unwrap();
        assert!(matches!(
            router.admit_consensus_relay_frame(&outer, &mut window),
            Err(ConsensusRelayIngressErrorV0::Envelope(
                ConsensusRelayErrorV0::StaleView
            ))
        ));
        assert!(window.is_empty());
    }

    #[test]
    fn invalid_relay_statement_does_not_consume_dedup_capacity() {
        let (keys, set, parameters) = fixture();
        let block = BlockId::new([0x73; 32]);
        let mut bytes = encode_vote(&vote(&keys, &set, 0, block));
        *bytes.last_mut().unwrap() ^= 1;
        let envelope = ConsensusRelayEnvelopeV0::new(
            set.validators()[0].id(),
            FrameKind::Vote,
            1,
            bytes,
            &set,
            &keys[0],
        )
        .unwrap();
        let outer = AuthenticatedFrame {
            sender: set.validators()[1].id(),
            session: [0x82; 32],
            sequence: 0,
            kind: FrameKind::ConsensusRelay,
            payload: envelope.encode(),
        };
        let mut router = BoundedConsensusIngressLoopV0::new(set, parameters, 16).unwrap();
        let mut window = ConsensusRelayAdmissionWindowV0::new(1).unwrap();
        assert!(router
            .admit_consensus_relay_frame(&outer, &mut window)
            .is_err());
        assert!(window.is_empty());
    }

    #[test]
    fn strictly_verified_relay_is_deduplicated_even_if_collector_fail_stops() {
        let (keys, set, parameters) = fixture();
        let mut router = BoundedConsensusIngressLoopV0::new(set.clone(), parameters, 1).unwrap();
        let admitted = vote(&keys, &set, 0, BlockId::new([0x74; 32]));
        let direct = AuthenticatedFrame {
            sender: admitted.author(),
            session: [0x83; 32],
            sequence: 0,
            kind: FrameKind::Vote,
            payload: encode_vote(&admitted),
        };
        router.admit_authenticated_frame(&direct).unwrap();

        let capacity_vote = vote(&keys, &set, 1, BlockId::new([0x75; 32]));
        let envelope = ConsensusRelayEnvelopeV0::new(
            capacity_vote.author(),
            FrameKind::Vote,
            2,
            encode_vote(&capacity_vote),
            &set,
            &keys[1],
        )
        .unwrap();
        let outer = AuthenticatedFrame {
            sender: set.validators()[4].id(),
            session: [0x84; 32],
            sequence: 0,
            kind: FrameKind::ConsensusRelay,
            payload: envelope.encode(),
        };
        let mut window = ConsensusRelayAdmissionWindowV0::new(1).unwrap();
        assert!(matches!(
            router.admit_consensus_relay_frame(&outer, &mut window),
            Err(ConsensusRelayIngressErrorV0::Consensus(
                ConsensusIngressErrorV0::Capacity
            ))
        ));
        assert_eq!(window.len(), 1);

        let replay = router
            .admit_consensus_relay_frame(&outer, &mut window)
            .unwrap();
        assert_eq!(replay.admission, RelayAdmissionV0::ExactReplay);
        assert!(replay.action.is_none());
        assert!(replay.forward.is_none());
    }
}
