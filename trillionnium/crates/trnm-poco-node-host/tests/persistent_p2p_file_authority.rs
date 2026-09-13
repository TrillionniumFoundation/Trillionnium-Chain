#![cfg(feature = "candidate-networked-authority")]

use std::{convert::Infallible, fs, path::Path};

use trnm_durable_file_adapters_v0::{
    candidate_frame_for_bound_ingress_v0, CandidatePersistentPeerAdmissionV0,
};
use trnm_node_boundary_v0::{
    AuthorityCommandV0, AuthorityCoordinatorV0, AuthorityReceiptV0, AuthorityStageV0,
    BoundIngressV0, BoundaryErrorV0, Digest32V0, IngressFrameV0, NodeIdentityV0,
    RecoveryDispositionV0,
};
use trnm_poco_node_authority::{NodeAuthorityCoordinatorV0, NodeAuthorityErrorV0};
use trnm_poco_node_host::CandidatePersistentP2pIngressBridgeV0;
use trnm_poco_node_io::{
    AuthenticatedPeerFrameV0, IoDigest32V0, PeerFrameSourceV0, PeerReplayStateV0,
    PeerSessionIdentityV0,
};
use trnm_poco_node_production_v0::{AuthoritySessionReadinessV0, ProductionAuthoritySessionV0};

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

fn peer_session() -> PeerSessionIdentityV0 {
    PeerSessionIdentityV0::new(io_d(1), io_d(8), io_d(4), io_d(9), io_d(5), 1)
        .expect("peer session")
}

fn ingress() -> BoundIngressV0 {
    let frame = IngressFrameV0::new(d(4), d(5), 1, b"proposal".to_vec()).expect("frame");
    BoundIngressV0::derive(identity(), 1, 1, d(10), d(9), frame).expect("bound ingress")
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

fn stage_peer(root: &Path, ingress: &BoundIngressV0) -> CandidatePersistentPeerAdmissionV0 {
    let mut admission = CandidatePersistentPeerAdmissionV0::open(root, identity(), peer_session())
        .expect("open peer replay");
    let frame = candidate_frame_for_bound_ingress_v0(identity(), peer_session(), ingress)
        .expect("canonical frame");
    let verified = admission
        .verify_frame(frame, &mut AcceptFrame)
        .expect("verify frame");
    admission
        .admit_verified(verified, ingress)
        .expect("persist pending frame");
    admission
}

// This test-only adapter binds Begin to the complete fixture ingress. The
// production facade deliberately has no raw-digest coordinator implementation.
// No generic journal trait implementation or production authority is added.
struct ExactIngressCoordinator {
    inner: NodeAuthorityCoordinatorV0,
    ingress: BoundIngressV0,
}

impl ExactIngressCoordinator {
    fn open(root: &Path) -> Self {
        fs::create_dir_all(root).expect("create fixture authority directory");
        Self {
            inner: NodeAuthorityCoordinatorV0::open_candidate(root, identity())
                .expect("open authority"),
            ingress: ingress(),
        }
    }

    fn current_receipt(&self) -> Option<AuthorityReceiptV0> {
        self.inner.current_receipt()
    }
}

impl AuthorityCoordinatorV0 for ExactIngressCoordinator {
    type Error = NodeAuthorityErrorV0;

    fn identity(&self) -> NodeIdentityV0 {
        self.inner.identity().expect("bound authority identity")
    }

    fn recover(&mut self) -> Result<RecoveryDispositionV0, Self::Error> {
        self.inner.recover()
    }

    fn apply(&mut self, command: AuthorityCommandV0) -> Result<AuthorityReceiptV0, Self::Error> {
        match command {
            AuthorityCommandV0::Begin {
                binding,
                ingress_digest,
            } => {
                if binding != self.ingress.binding
                    || ingress_digest != self.ingress.ingress_digest()
                {
                    return Err(NodeAuthorityErrorV0::Boundary(
                        BoundaryErrorV0::OperationBindingMismatch,
                    ));
                }
                self.inner.prepare_bound_ingress(&self.ingress)
            }
            AuthorityCommandV0::Advance { .. } => Err(NodeAuthorityErrorV0::Boundary(
                BoundaryErrorV0::InvalidStageTransition,
            )),
        }
    }
}

fn authority_session(
    root: &Path,
) -> ProductionAuthoritySessionV0<
    ExactIngressCoordinator,
    impl Fn(&ExactIngressCoordinator) -> Option<AuthorityReceiptV0>,
> {
    let coordinator = ExactIngressCoordinator::open(root);
    ProductionAuthoritySessionV0::new(coordinator, ExactIngressCoordinator::current_receipt)
        .expect("authority session")
}

#[test]
fn fixture_preserves_recovery_and_exact_ingress_boundaries() {
    let root = tempfile::tempdir().expect("root");
    let mut coordinator = ExactIngressCoordinator::open(root.path());
    let exact = ingress();
    let begin = AuthorityCommandV0::Begin {
        binding: exact.binding,
        ingress_digest: exact.ingress_digest(),
    };
    assert!(matches!(
        coordinator.apply(begin.clone()),
        Err(NodeAuthorityErrorV0::RecoveryRequired)
    ));
    assert_eq!(coordinator.current_receipt(), None);
    let recovered = coordinator.recover().expect("recover");
    assert_eq!(recovered, RecoveryDispositionV0::Clean);

    let mut wrong_binding = exact.binding;
    wrong_binding.block_id = d(99);
    for command in [
        AuthorityCommandV0::Begin {
            binding: wrong_binding,
            ingress_digest: exact.ingress_digest(),
        },
        AuthorityCommandV0::Begin {
            binding: exact.binding,
            ingress_digest: d(99),
        },
        AuthorityCommandV0::Advance {
            binding: exact.binding,
            expected_stage: AuthorityStageV0::Prepared,
            next_stage: AuthorityStageV0::ApplicationSealed,
            facts_digest: d(99),
        },
    ] {
        assert!(coordinator.apply(command).is_err());
        assert_eq!(coordinator.current_receipt(), None);
    }
    let receipt = coordinator.apply(begin.clone()).expect("exact Begin");
    assert_eq!(receipt.binding, exact.binding);
    assert_eq!(receipt.facts_digest, exact.ingress_digest());
    assert_eq!(receipt.durable_stage, AuthorityStageV0::Prepared);
    assert_eq!(coordinator.apply(begin).expect("idempotent Begin"), receipt);
}

#[test]
fn lost_peer_ack_reopens_both_journals_and_replays_one_exact_prepared_receipt() {
    let root = tempfile::tempdir().expect("root");
    let peer_root = root.path().join("peer");
    let authority_root = root.path().join("authority");
    let ingress = ingress();
    let prepared;

    {
        let admission = stage_peer(&peer_root, &ingress);
        let mut bridge =
            CandidatePersistentP2pIngressBridgeV0::new(identity(), admission, ingress.clone())
                .expect("bridge");
        let mut authority = authority_session(&authority_root);
        assert_eq!(
            authority.recover().expect("recover authority"),
            AuthoritySessionReadinessV0::Ready
        );
        let verified = authority
            .verify_ingress(ingress.clone(), &mut bridge)
            .expect("verify ingress");
        prepared = authority
            .begin_verified(verified)
            .expect("persist Prepared");
        assert!(bridge.peer_recovery_state().pending().is_some());
    }

    {
        let admission =
            CandidatePersistentPeerAdmissionV0::open(&peer_root, identity(), peer_session())
                .expect("reopen peer replay");
        let mut bridge =
            CandidatePersistentP2pIngressBridgeV0::new(identity(), admission, ingress.clone())
                .expect("reopened bridge");
        let mut authority = authority_session(&authority_root);
        assert_eq!(
            authority.recover().expect("recover Prepared"),
            AuthoritySessionReadinessV0::Ready
        );
        assert_eq!(authority.current_receipt(), Some(prepared));
        let replay = authority
            .verify_ingress(ingress.clone(), &mut bridge)
            .expect("verify exact replay");
        assert_eq!(
            authority.begin_verified(replay).expect("replay Prepared"),
            prepared
        );
        let state = bridge
            .acknowledge_prepared(prepared)
            .expect("persist peer acknowledgement");
        assert_eq!(state.highest_acknowledged_nonce(), 1);
        assert_eq!(state.pending(), None);
    }

    let peer = CandidatePersistentPeerAdmissionV0::open(&peer_root, identity(), peer_session())
        .expect("final peer reopen");
    assert_eq!(peer.recovery_state().highest_acknowledged_nonce(), 1);
    assert_eq!(peer.recovery_state().pending(), None);
    assert_eq!(
        peer.last_prepared_acknowledgement()
            .expect("durable peer acknowledgement")
            .receipt(),
        prepared
    );
}
