#![forbid(unsafe_code)]
//! Thin production composition for PoCO-BFT v0 node services.
//!
//! This crate performs dependency injection and lifecycle wiring only.  It
//! does not implement consensus rules, persistence, networking, execution,
//! signing, state-root construction, migration projection, governance, or lab
//! fixtures.

use std::{error::Error, fmt};
use trnm_control_plane_v0::{
    ControlPlaneErrorV0, Digest32V0 as ControlDigestV0, LocalPlanGuardV0, ParameterBoundV0,
    PlanSignatureVerifierV0,
};
use trnm_node_boundary_v0::{
    AuthorityCoordinatorV0, BoundaryErrorV0, HostErrorV0, HostReadinessV0, HostStepV0, IoRuntimeV0,
    NodeLayerRoleV0, PersistentValidatorHostV0, StepBudgetV0,
};
use trnm_tx_lifecycle_v0::{AuthorizationVerifierV0, Digest32V0 as TxDigestV0, TxLifecycleV0};

pub const PRODUCTION_COMPOSITION_VERSION_V0: u16 = 0;
pub const PRODUCTION_COMPOSITION_ROLE_V0: NodeLayerRoleV0 = NodeLayerRoleV0::Composition;

pub struct ProductionNodeCompositionV0<C, I, A, P> {
    host: PersistentValidatorHostV0<C, I>,
    transactions: TxLifecycleV0<A>,
    control_guard: LocalPlanGuardV0<P>,
}

impl<C, I, A, P> ProductionNodeCompositionV0<C, I, A, P>
where
    C: AuthorityCoordinatorV0,
    I: IoRuntimeV0,
    A: AuthorizationVerifierV0,
    P: PlanSignatureVerifierV0,
{
    pub fn new(
        coordinator: C,
        io: I,
        step_budget: StepBudgetV0,
        chain_id: TxDigestV0,
        authorization_verifier: A,
        plan_signature_verifier: P,
        source_graph_digest: ControlDigestV0,
        contract_set_digest: ControlDigestV0,
        control_generation: u64,
        parameter_bounds: Vec<ParameterBoundV0>,
    ) -> Result<Self, CompositionErrorV0> {
        if PRODUCTION_COMPOSITION_ROLE_V0.may_own_domain_state()
            || !PRODUCTION_COMPOSITION_ROLE_V0.production_allowed()
        {
            return Err(CompositionErrorV0::InvalidLayerRole);
        }
        let host = PersistentValidatorHostV0::new(coordinator, io, step_budget)
            .map_err(CompositionErrorV0::HostBoundary)?;
        let control_guard = LocalPlanGuardV0::new(
            plan_signature_verifier,
            source_graph_digest,
            contract_set_digest,
            control_generation,
            parameter_bounds,
        )
        .map_err(CompositionErrorV0::ControlBoundary)?;
        Ok(Self {
            host,
            transactions: TxLifecycleV0::new(chain_id, authorization_verifier),
            control_guard,
        })
    }

    pub fn recover_host(&mut self) -> Result<HostReadinessV0, HostErrorV0<C::Error, I::Error>> {
        self.host.recover()
    }

    pub fn host_step(&mut self) -> Result<HostStepV0, HostErrorV0<C::Error, I::Error>> {
        self.host.step()
    }

    #[must_use]
    pub fn transactions(&self) -> &TxLifecycleV0<A> {
        &self.transactions
    }

    pub fn transactions_mut(&mut self) -> &mut TxLifecycleV0<A> {
        &mut self.transactions
    }

    #[must_use]
    pub fn control_guard(&self) -> &LocalPlanGuardV0<P> {
        &self.control_guard
    }

    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        PersistentValidatorHostV0<C, I>,
        TxLifecycleV0<A>,
        LocalPlanGuardV0<P>,
    ) {
        (self.host, self.transactions, self.control_guard)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompositionErrorV0 {
    InvalidLayerRole,
    HostBoundary(BoundaryErrorV0),
    ControlBoundary(ControlPlaneErrorV0),
}

impl fmt::Display for CompositionErrorV0 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLayerRole => f.write_str("production composition layer owns domain state"),
            Self::HostBoundary(error) => write!(f, "invalid persistent-host boundary: {error}"),
            Self::ControlBoundary(error) => write!(f, "invalid local control guard: {error}"),
        }
    }
}

impl Error for CompositionErrorV0 {}

/// Marker used by source and dependency-closure gates.  State sync and
/// migration are session-scoped operations and are intentionally not hidden
/// behind a global singleton in the composition root.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SessionScopedServiceSetV0 {
    pub state_sync_protocol_version: u16,
    pub migration_protocol_version: u16,
}

impl Default for SessionScopedServiceSetV0 {
    fn default() -> Self {
        Self {
            state_sync_protocol_version: trnm_state_sync_v0::STATE_SYNC_VERSION_V0,
            migration_protocol_version: trnm_migration_v0::MIGRATION_VERSION_V0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::convert::Infallible;
    use trnm_control_plane_v0::Digest32V0 as ControlDigest;
    use trnm_node_boundary_v0::{
        Digest32V0 as NodeDigest, IoPollV0, NodeIdentityV0, RecoveryDispositionV0,
        ReferenceAuthorityCoordinatorV0,
    };
    use trnm_tx_lifecycle_v0::{AccountIdV0, Digest32V0 as TxDigest};

    struct IdleIo;
    impl IoRuntimeV0 for IdleIo {
        type Error = Infallible;
        fn poll_ingress(&mut self, _budget: StepBudgetV0) -> Result<IoPollV0, Self::Error> {
            Ok(IoPollV0::Idle)
        }
        fn publish(
            &mut self,
            _frame: trnm_node_boundary_v0::OutboundFrameV0,
            _budget: StepBudgetV0,
        ) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    struct AcceptAuthorization;
    impl AuthorizationVerifierV0 for AcceptAuthorization {
        type Error = Infallible;
        fn verify(
            &self,
            _sender: AccountIdV0,
            _signing_digest: TxDigest,
            _authorization: &[u8],
        ) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    struct AcceptPlan;
    impl PlanSignatureVerifierV0 for AcceptPlan {
        type Error = Infallible;
        fn verify_plan_signature(
            &self,
            _plan: &trnm_control_plane_v0::OptimizationPlanV1,
        ) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    #[test]
    fn composition_is_thin_and_requires_recovery_before_polling() {
        let identity = NodeIdentityV0 {
            chain_id: NodeDigest([1; 32]),
            validator_id: NodeDigest([2; 32]),
            application_id: NodeDigest([3; 32]),
            generation: 1,
        };
        let coordinator = ReferenceAuthorityCoordinatorV0::new(identity);
        let mut composition = ProductionNodeCompositionV0::new(
            coordinator,
            IdleIo,
            StepBudgetV0::default(),
            TxDigest([1; 32]),
            AcceptAuthorization,
            AcceptPlan,
            ControlDigest([2; 32]),
            ControlDigest([3; 32]),
            1,
            vec![],
        )
        .unwrap();
        assert!(composition.host_step().is_err());
        assert_eq!(composition.recover_host().unwrap(), HostReadinessV0::Ready);
        assert_eq!(composition.host_step().unwrap(), HostStepV0::Idle);
        assert_eq!(
            SessionScopedServiceSetV0::default(),
            SessionScopedServiceSetV0 {
                state_sync_protocol_version: 0,
                migration_protocol_version: 0,
            }
        );
    }

    #[test]
    fn reference_coordinator_recovery_disposition_remains_explicit() {
        let identity = NodeIdentityV0 {
            chain_id: NodeDigest([1; 32]),
            validator_id: NodeDigest([2; 32]),
            application_id: NodeDigest([3; 32]),
            generation: 1,
        };
        let mut coordinator = ReferenceAuthorityCoordinatorV0::new(identity);
        assert_eq!(coordinator.recover().unwrap(), RecoveryDispositionV0::Clean);
    }
}
