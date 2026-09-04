#![forbid(unsafe_code)]
//! Durable authority-journal boundary for the production-shaped PoCO node.
//!
//! The crate now owns one explicit candidate binding to the reviewed file
//! authority adapter. It can recover, persist exact `BoundIngressV0 ->
//! Prepared`, and append only the strict successor stages defined by
//! `trnm-node-boundary-v0`. It never creates application, SafetyRules, signing,
//! finality, checkpoint, or publication facts; callers must supply a non-zero
//! digest produced by the independently owned domain adapter.
//!
//! Production activation remains delegated to the repository-wide fail-closed
//! gate. Binding a durable journal therefore does not make the node a
//! production candidate and does not permit the composition to start.

use std::{
    error::Error,
    fmt, fs, io,
    path::{Path, PathBuf},
};

use trnm_durable_file_adapters_v0::{DurableFileErrorV0, FileAuthorityCoordinatorV0};
use trnm_node_boundary_v0::{
    AuthorityCommandV0, AuthorityCoordinatorV0, AuthorityReceiptV0, AuthorityStageV0,
    BoundIngressV0, BoundaryErrorV0, Digest32V0, NodeIdentityV0, OperationBindingV0,
    RecoveryDispositionV0,
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

/// Authority-journal owner used by the host composition.
///
/// `new()` is deliberately inert. `open_candidate()` binds an already-existing
/// absolute non-symlink directory to the reviewed durable file adapter. The
/// object exposes no private-key, vote-construction, application-execution,
/// finality, networking, or activation API.
pub struct NodeAuthorityCoordinatorV0 {
    inner: Option<FileAuthorityCoordinatorV0>,
    canonical_root: Option<PathBuf>,
    recovered: bool,
}

impl NodeAuthorityCoordinatorV0 {
    pub const fn new() -> Self {
        Self {
            inner: None,
            canonical_root: None,
            recovered: false,
        }
    }

    pub fn open_candidate(
        root: impl AsRef<Path>,
        identity: NodeIdentityV0,
    ) -> Result<Self, NodeAuthorityErrorV0> {
        identity
            .validate()
            .map_err(NodeAuthorityErrorV0::Boundary)?;
        let root = root.as_ref();
        if !root.is_absolute() {
            return Err(NodeAuthorityErrorV0::RelativeRoot(root.to_path_buf()));
        }
        let metadata = fs::symlink_metadata(root).map_err(NodeAuthorityErrorV0::RootIo)?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(NodeAuthorityErrorV0::InvalidRoot(root.to_path_buf()));
        }
        let canonical_root = fs::canonicalize(root).map_err(NodeAuthorityErrorV0::RootIo)?;
        if !canonical_root.is_dir() {
            return Err(NodeAuthorityErrorV0::InvalidRoot(canonical_root));
        }
        let inner = FileAuthorityCoordinatorV0::open(&canonical_root, identity)
            .map_err(NodeAuthorityErrorV0::Durable)?;
        Ok(Self {
            inner: Some(inner),
            canonical_root: Some(canonical_root),
            recovered: false,
        })
    }

    pub fn readiness(&self) -> NodeAuthorityReadinessV0 {
        NodeAuthorityReadinessV0 {
            production_candidate: PRODUCTION_CANDIDATE_V0,
            host_implementation_complete: HOST_IMPLEMENTATION_COMPLETE_V0,
            unwired_contract_count: UNWIRED_PRODUCTION_CONTRACTS_V0.len(),
            persistent_authority_bound: self.inner.is_some(),
            recovery_barrier_satisfied: self.recovered,
            durable_stage: self.current_receipt().map(|receipt| receipt.durable_stage),
        }
    }

    pub const fn production_activation_gate(&self) -> Result<(), ProductionActivationBlockedV0> {
        production_activation_gate_v0()
    }

    pub fn canonical_root(&self) -> Option<&Path> {
        self.canonical_root.as_deref()
    }

    pub fn identity(&self) -> Option<NodeIdentityV0> {
        self.inner.as_ref().map(AuthorityCoordinatorV0::identity)
    }

    pub fn current_receipt(&self) -> Option<AuthorityReceiptV0> {
        self.inner
            .as_ref()
            .and_then(FileAuthorityCoordinatorV0::current_receipt)
    }

    /// Reconcile and authenticate the complete journal before any mutation.
    pub fn recover(&mut self) -> Result<RecoveryDispositionV0, NodeAuthorityErrorV0> {
        let identity = self.identity().ok_or(NodeAuthorityErrorV0::Inert)?;
        let disposition = self
            .inner
            .as_mut()
            .ok_or(NodeAuthorityErrorV0::Inert)?
            .recover()
            .map_err(NodeAuthorityErrorV0::Durable)?;
        match disposition {
            RecoveryDispositionV0::Clean => {
                self.recovered = true;
            }
            RecoveryDispositionV0::Resume { binding, .. } => {
                binding
                    .validate(identity)
                    .map_err(NodeAuthorityErrorV0::Boundary)?;
                self.recovered = true;
            }
            RecoveryDispositionV0::Quarantine { .. } => {
                self.recovered = false;
            }
        }
        Ok(disposition)
    }

    /// Persist the exact ingress digest as the first `Prepared` record.
    pub fn prepare_bound_ingress(
        &mut self,
        ingress: &BoundIngressV0,
    ) -> Result<AuthorityReceiptV0, NodeAuthorityErrorV0> {
        self.require_recovered()?;
        let identity = self.identity().ok_or(NodeAuthorityErrorV0::Inert)?;
        ingress
            .validate(identity)
            .map_err(NodeAuthorityErrorV0::Boundary)?;
        let facts_digest = ingress.ingress_digest();
        let receipt = self
            .inner
            .as_mut()
            .ok_or(NodeAuthorityErrorV0::Inert)?
            .apply(AuthorityCommandV0::Begin {
                binding: ingress.binding,
                ingress_digest: facts_digest,
            })
            .map_err(NodeAuthorityErrorV0::Durable)?;
        validate_receipt_v0(
            identity,
            receipt,
            ingress.binding,
            AuthorityStageV0::Prepared,
            facts_digest,
            false,
        )?;
        Ok(receipt)
    }

    /// Append exactly one authority successor stage.
    ///
    /// This method persists only a digest. It does not validate or manufacture
    /// the domain fact represented by that digest. A production composition
    /// must keep the corresponding typed receipt non-forgeable in its domain
    /// crate and call this boundary only after that domain operation returns a
    /// trusted result.
    pub fn advance_exact(
        &mut self,
        binding: OperationBindingV0,
        expected_stage: AuthorityStageV0,
        next_stage: AuthorityStageV0,
        facts_digest: Digest32V0,
    ) -> Result<AuthorityReceiptV0, NodeAuthorityErrorV0> {
        self.require_recovered()?;
        let identity = self.identity().ok_or(NodeAuthorityErrorV0::Inert)?;
        binding
            .validate(identity)
            .map_err(NodeAuthorityErrorV0::Boundary)?;
        if expected_stage.successor() != Some(next_stage) {
            return Err(NodeAuthorityErrorV0::Boundary(
                BoundaryErrorV0::InvalidStageTransition,
            ));
        }
        if facts_digest == Digest32V0([0; 32]) {
            return Err(NodeAuthorityErrorV0::ZeroFactsDigest);
        }
        let receipt = self
            .inner
            .as_mut()
            .ok_or(NodeAuthorityErrorV0::Inert)?
            .apply(AuthorityCommandV0::Advance {
                binding,
                expected_stage,
                next_stage,
                facts_digest,
            })
            .map_err(NodeAuthorityErrorV0::Durable)?;
        validate_receipt_v0(identity, receipt, binding, next_stage, facts_digest, true)?;
        Ok(receipt)
    }

    fn require_recovered(&self) -> Result<(), NodeAuthorityErrorV0> {
        if self.inner.is_none() {
            return Err(NodeAuthorityErrorV0::Inert);
        }
        if !self.recovered {
            return Err(NodeAuthorityErrorV0::RecoveryRequired);
        }
        Ok(())
    }
}

impl Default for NodeAuthorityCoordinatorV0 {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for NodeAuthorityCoordinatorV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NodeAuthorityCoordinatorV0")
            .field("persistent_authority_bound", &self.inner.is_some())
            .field("canonical_root", &self.canonical_root)
            .field("recovered", &self.recovered)
            .field(
                "durable_stage",
                &self.current_receipt().map(|receipt| receipt.durable_stage),
            )
            .finish()
    }
}

fn validate_receipt_v0(
    identity: NodeIdentityV0,
    receipt: AuthorityReceiptV0,
    expected_binding: OperationBindingV0,
    expected_stage: AuthorityStageV0,
    expected_facts_digest: Digest32V0,
    require_nonzero_sequence: bool,
) -> Result<(), NodeAuthorityErrorV0> {
    receipt
        .binding
        .validate(identity)
        .map_err(NodeAuthorityErrorV0::Boundary)?;
    if receipt.binding != expected_binding
        || receipt.durable_stage != expected_stage
        || receipt.facts_digest != expected_facts_digest
        || receipt.record_digest == Digest32V0([0; 32])
        || (require_nonzero_sequence && receipt.durable_sequence == 0)
    {
        return Err(NodeAuthorityErrorV0::Boundary(
            BoundaryErrorV0::ReceiptSubstitution,
        ));
    }
    Ok(())
}

#[derive(Debug)]
pub enum NodeAuthorityErrorV0 {
    Inert,
    RecoveryRequired,
    RelativeRoot(PathBuf),
    InvalidRoot(PathBuf),
    RootIo(io::Error),
    ZeroFactsDigest,
    Boundary(BoundaryErrorV0),
    Durable(DurableFileErrorV0),
}

impl fmt::Display for NodeAuthorityErrorV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Inert => formatter.write_str("node authority coordinator is inert"),
            Self::RecoveryRequired => {
                formatter.write_str("node authority recovery barrier is not satisfied")
            }
            Self::RelativeRoot(path) => write!(
                formatter,
                "node authority root must be absolute: {}",
                path.display()
            ),
            Self::InvalidRoot(path) => write!(
                formatter,
                "node authority root must be an existing non-symlink directory: {}",
                path.display()
            ),
            Self::RootIo(error) => write!(formatter, "node authority root I/O failed: {error}"),
            Self::ZeroFactsDigest => {
                formatter.write_str("node authority facts digest may not be zero")
            }
            Self::Boundary(error) => write!(formatter, "node authority boundary rejected: {error}"),
            Self::Durable(error) => write!(formatter, "node authority persistence failed: {error}"),
        }
    }
}

impl Error for NodeAuthorityErrorV0 {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::RootIo(error) => Some(error),
            Self::Boundary(error) => Some(error),
            Self::Durable(error) => Some(error),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use trnm_node_boundary_v0::IngressFrameV0;

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
