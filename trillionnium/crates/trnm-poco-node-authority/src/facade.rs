#![forbid(unsafe_code)]
//! Wiring-only readiness facade. Durable domain state belongs to the optional
//! candidate file-adapter owner, never to this composition package.
//!
//! The default build contains no storage constructor or stage-mutation API.
//! `persistent-authority-candidate` is an explicit non-activating consumer seam.

#[cfg(feature = "persistent-authority-candidate")]
use std::path::Path;

#[cfg(feature = "persistent-authority-candidate")]
pub use trnm_durable_file_adapters_v0::CandidateAuthorityErrorV0 as NodeAuthorityErrorV0;
#[cfg(feature = "persistent-authority-candidate")]
use trnm_durable_file_adapters_v0::CandidateAuthorityJournalV0;
pub use trnm_node_boundary_v0::{
    AuthorityReceiptV0, AuthorityStageV0, BoundIngressV0, Digest32V0, IngressFrameV0,
    NodeIdentityV0, OperationBindingV0, RecoveryDispositionV0,
};
use trnm_poco_node::{
    production_activation_gate_v0, ProductionActivationBlockedV0, HOST_IMPLEMENTATION_COMPLETE_V0,
    PRODUCTION_CANDIDATE_V0, UNWIRED_PRODUCTION_CONTRACTS_V0,
};

/// Immutable readiness facts visible to the composition layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NodeAuthorityReadinessV0 {
    production_candidate: bool,
    host_implementation_complete: bool,
    unwired_contract_count: usize,
    persistent_authority_bound: bool,
    recovery_barrier_satisfied: bool,
    durable_stage: Option<AuthorityStageV0>,
}

impl NodeAuthorityReadinessV0 {
    pub const fn production_candidate(self) -> bool {
        self.production_candidate
    }

    pub const fn host_implementation_complete(self) -> bool {
        self.host_implementation_complete
    }

    pub const fn unwired_contract_count(self) -> usize {
        self.unwired_contract_count
    }

    pub const fn persistent_authority_bound(self) -> bool {
        self.persistent_authority_bound
    }

    pub const fn recovery_barrier_satisfied(self) -> bool {
        self.recovery_barrier_satisfied
    }

    pub const fn durable_stage(self) -> Option<AuthorityStageV0> {
        self.durable_stage
    }

    pub const fn activation_permitted(self) -> bool {
        self.production_candidate
            && self.host_implementation_complete
            && self.unwired_contract_count == 0
            && self.persistent_authority_bound
            && self.recovery_barrier_satisfied
    }
}

/// Immutable readiness projection plus optional delegation to a candidate owner.
#[derive(Debug, Default)]
#[cfg_attr(
    not(feature = "persistent-authority-candidate"),
    doc = "```compile_fail\nuse trnm_poco_node_authority::NodeAuthorityCoordinatorV0;\nlet _ = NodeAuthorityCoordinatorV0::recover;\n```"
)]
pub struct NodeAuthorityCoordinatorV0 {
    #[cfg(feature = "persistent-authority-candidate")]
    candidate: CandidateAuthorityJournalV0,
}

impl NodeAuthorityCoordinatorV0 {
    pub const fn new() -> Self {
        Self {
            #[cfg(feature = "persistent-authority-candidate")]
            candidate: CandidateAuthorityJournalV0::new(),
        }
    }

    pub fn readiness(&self) -> NodeAuthorityReadinessV0 {
        #[cfg(feature = "persistent-authority-candidate")]
        let (bound, recovered, stage) = (
            self.candidate.persistent_authority_bound(),
            self.candidate.recovery_barrier_satisfied(),
            self.candidate
                .current_receipt()
                .map(|receipt| receipt.durable_stage),
        );
        #[cfg(not(feature = "persistent-authority-candidate"))]
        let (bound, recovered, stage) = (false, false, None);
        NodeAuthorityReadinessV0 {
            production_candidate: PRODUCTION_CANDIDATE_V0,
            host_implementation_complete: HOST_IMPLEMENTATION_COMPLETE_V0,
            unwired_contract_count: UNWIRED_PRODUCTION_CONTRACTS_V0.len(),
            persistent_authority_bound: bound,
            recovery_barrier_satisfied: recovered,
            durable_stage: stage,
        }
    }

    pub const fn production_activation_gate(&self) -> Result<(), ProductionActivationBlockedV0> {
        production_activation_gate_v0()
    }
}

#[cfg(feature = "persistent-authority-candidate")]
impl NodeAuthorityCoordinatorV0 {
    pub fn open_candidate(
        root: impl AsRef<Path>,
        identity: NodeIdentityV0,
    ) -> Result<Self, NodeAuthorityErrorV0> {
        Ok(Self {
            candidate: CandidateAuthorityJournalV0::open_candidate(root, identity)?,
        })
    }

    pub fn canonical_root(&self) -> Option<&Path> {
        self.candidate.canonical_root()
    }

    pub fn identity(&self) -> Option<NodeIdentityV0> {
        self.candidate.identity()
    }

    pub fn current_receipt(&self) -> Option<AuthorityReceiptV0> {
        self.candidate.current_receipt()
    }

    pub fn recover(&mut self) -> Result<RecoveryDispositionV0, NodeAuthorityErrorV0> {
        self.candidate.recover()
    }

    pub fn prepare_bound_ingress(
        &mut self,
        ingress: &BoundIngressV0,
    ) -> Result<AuthorityReceiptV0, NodeAuthorityErrorV0> {
        self.candidate.prepare_bound_ingress(ingress)
    }

    /// Candidate-only inert fact recording; not a proof of domain authority.
    pub fn advance_exact(
        &mut self,
        binding: OperationBindingV0,
        expected_stage: AuthorityStageV0,
        next_stage: AuthorityStageV0,
        facts_digest: Digest32V0,
    ) -> Result<AuthorityReceiptV0, NodeAuthorityErrorV0> {
        self.candidate
            .advance_exact(binding, expected_stage, next_stage, facts_digest)
    }
}

#[cfg(test)]
mod default_tests {
    use super::*;

    #[test]
    fn unbound_facade_never_grants_activation() {
        let coordinator = NodeAuthorityCoordinatorV0::new();
        let readiness = coordinator.readiness();
        assert!(!readiness.persistent_authority_bound());
        assert!(!readiness.recovery_barrier_satisfied());
        assert!(!readiness.activation_permitted());
        assert_eq!(readiness.durable_stage(), None);
        assert!(coordinator.production_activation_gate().is_err());
    }
}

#[cfg(all(test, feature = "persistent-authority-candidate"))]
mod candidate_tests {
    use super::*;
    use trnm_durable_file_adapters_v0::DurableFileErrorV0;
    use trnm_node_boundary_v0::BoundaryErrorV0;

    fn identity() -> NodeIdentityV0 {
        NodeIdentityV0 {
            chain_id: Digest32V0([1; 32]),
            validator_id: Digest32V0([2; 32]),
            application_id: Digest32V0([3; 32]),
            generation: 1,
        }
    }

    fn ingress() -> BoundIngressV0 {
        let frame = IngressFrameV0::new(
            Digest32V0([4; 32]),
            Digest32V0([5; 32]),
            1,
            b"proposal".to_vec(),
        )
        .expect("frame");
        BoundIngressV0::derive(
            identity(),
            1,
            0,
            Digest32V0([6; 32]),
            Digest32V0([7; 32]),
            frame,
        )
        .expect("bound ingress")
    }

    fn facts(stage: AuthorityStageV0) -> Digest32V0 {
        Digest32V0::hash(b"trnm.authority-test-fact.v0", &[&[stage as u8]])
    }

    #[test]
    fn inert_coordinator_remains_fail_closed() {
        let mut coordinator = NodeAuthorityCoordinatorV0::new();
        let readiness = coordinator.readiness();
        assert!(!readiness.production_candidate());
        assert!(!readiness.host_implementation_complete());
        assert!(readiness.unwired_contract_count() > 0);
        assert!(!readiness.persistent_authority_bound());
        assert!(!readiness.recovery_barrier_satisfied());
        assert_eq!(readiness.durable_stage(), None);
        assert!(!readiness.activation_permitted());
        assert!(coordinator.production_activation_gate().is_err());
        assert!(matches!(
            coordinator.recover(),
            Err(NodeAuthorityErrorV0::Inert)
        ));
    }

    #[test]
    fn recovery_is_required_before_the_first_mutation() {
        let directory = tempfile::tempdir().expect("tempdir");
        let mut coordinator =
            NodeAuthorityCoordinatorV0::open_candidate(directory.path(), identity()).expect("open");
        let error = coordinator
            .prepare_bound_ingress(&ingress())
            .expect_err("must recover first");
        assert!(matches!(error, NodeAuthorityErrorV0::RecoveryRequired));
    }

    #[test]
    fn exact_stage_chain_is_durable_and_reopens() {
        let directory = tempfile::tempdir().expect("tempdir");
        let terminal = {
            let mut coordinator =
                NodeAuthorityCoordinatorV0::open_candidate(directory.path(), identity())
                    .expect("open");
            assert_eq!(
                coordinator.recover().expect("recover"),
                RecoveryDispositionV0::Clean
            );
            let prepared = coordinator
                .prepare_bound_ingress(&ingress())
                .expect("prepare");
            assert_eq!(prepared.durable_stage, AuthorityStageV0::Prepared);
            assert_eq!(prepared.durable_sequence, 0);

            let stages = [
                AuthorityStageV0::ApplicationSealed,
                AuthorityStageV0::SafetyPersisted,
                AuthorityStageV0::SignIntentPersisted,
                AuthorityStageV0::SignatureConfirmed,
                AuthorityStageV0::FinalityApplied,
                AuthorityStageV0::CheckpointConfirmed,
                AuthorityStageV0::OutboundPublished,
            ];
            let mut expected = AuthorityStageV0::Prepared;
            let mut last = prepared;
            for next in stages {
                last = coordinator
                    .advance_exact(prepared.binding, expected, next, facts(next))
                    .expect("advance");
                assert_eq!(last.durable_stage, next);
                expected = next;
            }
            assert_eq!(last.durable_sequence, 7);
            last
        };

        let mut reopened = NodeAuthorityCoordinatorV0::open_candidate(directory.path(), identity())
            .expect("reopen");
        assert_eq!(
            reopened.recover().expect("recover reopened"),
            RecoveryDispositionV0::Resume {
                binding: terminal.binding,
                durable_stage: AuthorityStageV0::OutboundPublished,
                durable_sequence: 7,
            }
        );
        assert_eq!(reopened.current_receipt(), Some(terminal));
        assert_eq!(
            reopened.readiness().durable_stage(),
            Some(AuthorityStageV0::OutboundPublished)
        );
        assert!(!reopened.readiness().activation_permitted());
    }

    #[test]
    fn exact_retry_is_idempotent_and_substitution_is_rejected() {
        let directory = tempfile::tempdir().expect("tempdir");
        let mut coordinator =
            NodeAuthorityCoordinatorV0::open_candidate(directory.path(), identity()).expect("open");
        coordinator.recover().expect("recover");
        let prepared = coordinator
            .prepare_bound_ingress(&ingress())
            .expect("prepare");
        let expected_facts = facts(AuthorityStageV0::ApplicationSealed);
        let applied = coordinator
            .advance_exact(
                prepared.binding,
                AuthorityStageV0::Prepared,
                AuthorityStageV0::ApplicationSealed,
                expected_facts,
            )
            .expect("advance");
        let replayed = coordinator
            .advance_exact(
                prepared.binding,
                AuthorityStageV0::Prepared,
                AuthorityStageV0::ApplicationSealed,
                expected_facts,
            )
            .expect("replay");
        assert_eq!(replayed, applied);

        let substituted = coordinator.advance_exact(
            prepared.binding,
            AuthorityStageV0::Prepared,
            AuthorityStageV0::ApplicationSealed,
            Digest32V0([9; 32]),
        );
        assert!(matches!(
            substituted,
            Err(NodeAuthorityErrorV0::Durable(
                DurableFileErrorV0::InvalidAuthorityCommand(BoundaryErrorV0::ReceiptSubstitution)
            ))
        ));
    }

    #[test]
    fn skipped_stage_and_zero_fact_are_rejected_before_persistence() {
        let directory = tempfile::tempdir().expect("tempdir");
        let mut coordinator =
            NodeAuthorityCoordinatorV0::open_candidate(directory.path(), identity()).expect("open");
        coordinator.recover().expect("recover");
        let prepared = coordinator
            .prepare_bound_ingress(&ingress())
            .expect("prepare");

        assert!(matches!(
            coordinator.advance_exact(
                prepared.binding,
                AuthorityStageV0::Prepared,
                AuthorityStageV0::SafetyPersisted,
                facts(AuthorityStageV0::SafetyPersisted),
            ),
            Err(NodeAuthorityErrorV0::Boundary(
                BoundaryErrorV0::InvalidStageTransition
            ))
        ));
        assert!(matches!(
            coordinator.advance_exact(
                prepared.binding,
                AuthorityStageV0::Prepared,
                AuthorityStageV0::ApplicationSealed,
                Digest32V0([0; 32]),
            ),
            Err(NodeAuthorityErrorV0::ZeroFactsDigest)
        ));
        assert_eq!(coordinator.current_receipt(), Some(prepared));
    }
}
