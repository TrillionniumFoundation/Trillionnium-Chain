#![forbid(unsafe_code)]
//! Wiring-only production-shaped composition for PoCO-BFT v0.
//!
//! This crate owns no transaction lifecycle, control-plane state, consensus
//! rules, persistence, networking, execution, signing, state-root construction,
//! migration projection, governance, or laboratory fixture. Domain owners are
//! constructed outside this root and cross only versioned ports.

use std::{error::Error, fmt};
use trnm_node_boundary_v0::{
    AuthorityCoordinatorV0, BoundaryErrorV0, HostErrorV0, HostReadinessV0, HostStepV0, IoRuntimeV0,
    NodeLayerRoleV0, PersistentValidatorHostV0, StepBudgetV0,
};

pub const PRODUCTION_COMPOSITION_VERSION_V0: u16 = 0;
pub const PRODUCTION_COMPOSITION_ROLE_V0: NodeLayerRoleV0 = NodeLayerRoleV0::Composition;
pub const PRODUCTION_COMPOSITION_OWNS_DOMAIN_STATE_V0: bool = false;
pub const PRODUCTION_COMPOSITION_ACTIVATION_V0: bool = false;

pub struct ProductionNodeCompositionV0<C, I> {
    host: PersistentValidatorHostV0<C, I>,
}

impl<C, I> ProductionNodeCompositionV0<C, I>
where
    C: AuthorityCoordinatorV0,
    I: IoRuntimeV0,
{
    pub fn new(
        coordinator: C,
        io: I,
        step_budget: StepBudgetV0,
    ) -> Result<Self, CompositionErrorV0> {
        if PRODUCTION_COMPOSITION_ROLE_V0.may_own_domain_state()
            || !PRODUCTION_COMPOSITION_ROLE_V0.production_allowed()
            || PRODUCTION_COMPOSITION_OWNS_DOMAIN_STATE_V0
            || PRODUCTION_COMPOSITION_ACTIVATION_V0
        {
            return Err(CompositionErrorV0::InvalidLayerRole);
        }
        let host = PersistentValidatorHostV0::new(coordinator, io, step_budget)
            .map_err(CompositionErrorV0::HostBoundary)?;
        Ok(Self { host })
    }

    pub fn recover_host(&mut self) -> Result<HostReadinessV0, HostErrorV0<C::Error, I::Error>> {
        self.host.recover()
    }

    pub fn host_step(&mut self) -> Result<HostStepV0, HostErrorV0<C::Error, I::Error>> {
        self.host.step()
    }

    pub const fn host(&self) -> &PersistentValidatorHostV0<C, I> {
        &self.host
    }

    pub fn host_mut(&mut self) -> &mut PersistentValidatorHostV0<C, I> {
        &mut self.host
    }

    pub fn into_host(self) -> PersistentValidatorHostV0<C, I> {
        self.host
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompositionErrorV0 {
    InvalidLayerRole,
    HostBoundary(BoundaryErrorV0),
}

impl fmt::Display for CompositionErrorV0 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLayerRole => f.write_str("production composition layer owns domain state"),
            Self::HostBoundary(error) => write!(f, "invalid persistent-host boundary: {error}"),
        }
    }
}

impl Error for CompositionErrorV0 {}

/// Compile-time contract surface. These are protocol versions, not service
/// instances, global singletons, activation records, or ownership transfers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SessionScopedServiceSetV0 {
    pub transaction_lifecycle_protocol_version: u16,
    pub state_sync_protocol_version: u16,
    pub migration_protocol_version: u16,
    pub control_plane_protocol_version: u16,
}

impl Default for SessionScopedServiceSetV0 {
    fn default() -> Self {
        Self {
            transaction_lifecycle_protocol_version: trnm_tx_lifecycle_v0::TX_LIFECYCLE_VERSION_V0,
            state_sync_protocol_version: trnm_state_sync_v0::STATE_SYNC_VERSION_V0,
            migration_protocol_version: trnm_migration_v0::MIGRATION_VERSION_V0,
            control_plane_protocol_version: trnm_control_plane_v0::CONTROL_PLANE_VERSION_V0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::convert::Infallible;
    use trnm_node_boundary_v0::{
        Digest32V0 as NodeDigest, IoPollV0, NodeIdentityV0, RecoveryDispositionV0,
        ReferenceAuthorityCoordinatorV0,
    };

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

    fn identity() -> NodeIdentityV0 {
        NodeIdentityV0 {
            chain_id: NodeDigest([1; 32]),
            validator_id: NodeDigest([2; 32]),
            application_id: NodeDigest([3; 32]),
            generation: 1,
        }
    }

    #[test]
    fn composition_is_wiring_only_and_requires_recovery_before_polling() {
        let coordinator = ReferenceAuthorityCoordinatorV0::new(identity());
        let mut composition =
            ProductionNodeCompositionV0::new(coordinator, IdleIo, StepBudgetV0::default()).unwrap();
        const {
            assert!(!PRODUCTION_COMPOSITION_OWNS_DOMAIN_STATE_V0);
            assert!(!PRODUCTION_COMPOSITION_ACTIVATION_V0);
        }
        assert!(composition.host_step().is_err());
        assert_eq!(composition.recover_host().unwrap(), HostReadinessV0::Ready);
        assert_eq!(composition.host_step().unwrap(), HostStepV0::Idle);
        assert_eq!(
            SessionScopedServiceSetV0::default(),
            SessionScopedServiceSetV0 {
                transaction_lifecycle_protocol_version: 0,
                state_sync_protocol_version: 0,
                migration_protocol_version: 0,
                control_plane_protocol_version: 0,
            }
        );
    }

    #[test]
    fn reference_coordinator_recovery_disposition_remains_explicit() {
        let mut coordinator = ReferenceAuthorityCoordinatorV0::new(identity());
        assert_eq!(coordinator.recover().unwrap(), RecoveryDispositionV0::Clean);
    }
}
