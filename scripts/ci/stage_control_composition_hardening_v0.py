#!/usr/bin/env python3
"""One-shot hardening of the observer-only control plane and composition root."""

from pathlib import Path


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


def replace_once(text: str, old: str, new: str, message: str) -> str:
    require(old in text, message)
    return text.replace(old, new, 1)


control_path = Path("trillionnium/crates/trnm-control-plane-v0/src/lib.rs")
control = control_path.read_text()
control = replace_once(
    control,
    "use std::{collections::BTreeMap, error::Error, fmt};",
    "use std::{collections::{BTreeMap, BTreeSet}, error::Error, fmt};",
    "control-plane collection import changed",
)
control = replace_once(
    control,
    """            || self.dependency_graph_digest == Digest32V0([0; 32])
            || self.invariant_digest == Digest32V0([0; 32])
""",
    """            || self.dependency_graph_digest == Digest32V0([0; 32])
            || self.configuration_digest == Digest32V0([0; 32])
            || self.invariant_digest == Digest32V0([0; 32])
""",
    "control-plane descriptor validation changed",
)
control = replace_once(
    control,
    "#[derive(Clone, Copy, Debug, Eq, PartialEq)]\npub enum ParameterClassV0 {",
    "#[derive(Clone, Copy, Debug, Eq, PartialEq)]\n#[repr(u8)]\npub enum ParameterClassV0 {",
    "parameter class representation changed",
)
control = replace_once(
    control,
    "#[derive(Clone, Copy, Debug, Eq, PartialEq)]\npub enum ForbiddenAuthorityActionV0 {",
    "#[derive(Clone, Copy, Debug, Eq, PartialEq)]\n#[repr(u8)]\npub enum ForbiddenAuthorityActionV0 {",
    "forbidden action representation changed",
)
old_shape = """        for action in &self.actions {
            if let PlanActionV0::SetBoundedInteger { parameter, .. } = action {
                if parameter.is_empty() || parameter.len() > MAX_PARAMETER_NAME_BYTES_V0 {
                    return Err(ControlPlaneErrorV0::InvalidParameter);
                }
            }
        }
        Ok(())
"""
new_shape = """        let mut action_digests = BTreeSet::new();
        let mut parameter_targets = BTreeSet::new();
        for action in &self.actions {
            if !action_digests.insert(action.canonical_digest()) {
                return Err(ControlPlaneErrorV0::DuplicatePlanAction);
            }
            match action {
                PlanActionV0::SetBoundedInteger {
                    module_id,
                    parameter,
                    class,
                    ..
                } => {
                    if *module_id >= MAX_MODULES_V0 as u16
                        || parameter.is_empty()
                        || parameter.len() > MAX_PARAMETER_NAME_BYTES_V0
                    {
                        return Err(ControlPlaneErrorV0::InvalidParameter);
                    }
                    if *class != ParameterClassV0::OperationalLocal {
                        return Err(ControlPlaneErrorV0::UnsupportedPlanAction);
                    }
                    if !parameter_targets.insert((*module_id, parameter.clone())) {
                        return Err(ControlPlaneErrorV0::DuplicatePlanAction);
                    }
                }
                PlanActionV0::PlaceIsolatedWorker { .. } => {
                    return Err(ControlPlaneErrorV0::UnsupportedPlanAction);
                }
                PlanActionV0::Forbidden(_) => {
                    return Err(ControlPlaneErrorV0::ForbiddenAuthorityAction);
                }
            }
        }
        Ok(())
"""
control = replace_once(control, old_shape, new_shape, "control-plane plan shape changed")
control = replace_once(
    control,
    """            || self.minimum > self.maximum
        {
""",
    """            || self.minimum > self.maximum
            || self.class != ParameterClassV0::OperationalLocal
        {
""",
    "control-plane bound validation changed",
)
control = replace_once(
    control,
    """        governance: Option<GovernanceAuthorizationV0>,
        determinism: Option<DeterminismEvidenceV0>,
""",
    """        _governance: Option<GovernanceAuthorizationV0>,
        _determinism: Option<DeterminismEvidenceV0>,
""",
    "control-plane evidence parameters changed",
)
control = replace_once(
    control,
    """        if plan.issued_generation != self.current_generation.saturating_add(1) {
            return Err(ControlPlaneHostErrorV0::Protocol(
                ControlPlaneErrorV0::GenerationMismatch,
            ));
        }
""",
    """        let expected_generation = self
            .current_generation
            .checked_add(1)
            .ok_or(ControlPlaneHostErrorV0::Protocol(
                ControlPlaneErrorV0::GenerationOverflow,
            ))?;
        if plan.issued_generation != expected_generation {
            return Err(ControlPlaneHostErrorV0::Protocol(
                ControlPlaneErrorV0::GenerationMismatch,
            ));
        }
""",
    "control-plane generation check changed",
)
old_placement = """                PlanActionV0::PlaceIsolatedWorker {
                    module_id,
                    worker_profile_digest,
                    placement_digest,
                } => {
                    if *module_id >= MAX_MODULES_V0 as u16
                        || *worker_profile_digest == Digest32V0([0; 32])
                        || *placement_digest == Digest32V0([0; 32])
                    {
                        ActionDecisionV0::Rejected(ControlPlaneErrorV0::InvalidPlacement)
                    } else {
                        ActionDecisionV0::Accepted
                    }
                }
"""
new_placement = """                PlanActionV0::PlaceIsolatedWorker { .. } => {
                    ActionDecisionV0::Rejected(ControlPlaneErrorV0::UnsupportedPlanAction)
                }
"""
control = replace_once(control, old_placement, new_placement, "control-plane placement branch changed")
old_class_match = """                    if *class != bound.class || *value < bound.minimum || *value > bound.maximum {
                        ActionDecisionV0::Rejected(ControlPlaneErrorV0::ParameterOutOfBounds)
                    } else {
                        match class {
                            ParameterClassV0::OperationalLocal => ActionDecisionV0::Accepted,
                            ParameterClassV0::DeterminismCritical => match determinism {
                                Some(evidence)
                                    if evidence.plan_digest == plan.canonical_plan_digest
                                        && evidence.shadow_replay_digest != Digest32V0([0; 32])
                                        && evidence.worker_invariance_digest
                                            != Digest32V0([0; 32])
                                        && evidence.pre_root == evidence.post_root =>
                                {
                                    ActionDecisionV0::Accepted
                                }
                                _ => ActionDecisionV0::Rejected(
                                    ControlPlaneErrorV0::MissingDeterminismEvidence,
                                ),
                            },
                            ParameterClassV0::ConsensusCritical => match governance {
                                Some(authorization)
                                    if authorization.plan_digest == plan.canonical_plan_digest
                                        && authorization.activation_height
                                            >= plan.not_before_height
                                        && authorization.activation_height
                                            <= plan.expires_after_height
                                        && authorization.validator_set_digest
                                            != Digest32V0([0; 32])
                                        && authorization.authorization_digest
                                            != Digest32V0([0; 32]) =>
                                {
                                    ActionDecisionV0::Accepted
                                }
                                _ => ActionDecisionV0::Rejected(
                                    ControlPlaneErrorV0::MissingGovernanceAuthorization,
                                ),
                            },
                        }
                    }
"""
new_class_match = """                    if *class != bound.class || *value < bound.minimum || *value > bound.maximum {
                        ActionDecisionV0::Rejected(ControlPlaneErrorV0::ParameterOutOfBounds)
                    } else if *class != ParameterClassV0::OperationalLocal {
                        ActionDecisionV0::Rejected(ControlPlaneErrorV0::UnsupportedPlanAction)
                    } else {
                        ActionDecisionV0::Accepted
                    }
"""
control = replace_once(control, old_class_match, new_class_match, "control-plane class branch changed")
control = replace_once(
    control,
    """        h.update(self.invariant_result_digest.0);
        h.update([u8::from(self.accepted)]);
        for result in &self.action_results {
""",
    """        h.update(self.invariant_result_digest.0);
        h.update([u8::from(self.accepted)]);
        h.update((self.action_results.len() as u64).to_be_bytes());
        for result in &self.action_results {
""",
    "control-plane receipt cardinality binding changed",
)
control = replace_once(
    control,
    """    MissingGovernanceAuthorization = 22,
    ReceiptOutOfBounds = 23,
}
""",
    """    MissingGovernanceAuthorization = 22,
    ReceiptOutOfBounds = 23,
    DuplicatePlanAction = 24,
    UnsupportedPlanAction = 25,
    GenerationOverflow = 26,
}
""",
    "control-plane error enum changed",
)
control = replace_once(
    control,
    """            Self::ReceiptOutOfBounds => "action receipt exceeds its result bound",
        })
""",
    """            Self::ReceiptOutOfBounds => "action receipt exceeds its result bound",
            Self::DuplicatePlanAction => "optimization plan repeats an action target or digest",
            Self::UnsupportedPlanAction => {
                "control-plane v0 permits only bounded operational-local parameters"
            }
            Self::GenerationOverflow => "control-plane generation cannot advance",
        })
""",
    "control-plane error display changed",
)
old_forbidden_test = """    #[test]
    fn forbidden_authority_is_explicitly_rejected() {
        let plan = plan(PlanActionV0::Forbidden(
            ForbiddenAuthorityActionV0::Finalize,
        ));
        let receipt = guard()
            .evaluate(&plan, 150, None, None, d(9), d(10))
            .unwrap();
        assert!(!receipt.accepted);
        assert_eq!(
            receipt.action_results[0].decision,
            ActionDecisionV0::Rejected(ControlPlaneErrorV0::ForbiddenAuthorityAction)
        );
    }
"""
new_forbidden_test = """    #[test]
    fn forbidden_authority_is_rejected_before_evaluation() {
        let plan = plan(PlanActionV0::Forbidden(
            ForbiddenAuthorityActionV0::Finalize,
        ));
        assert!(matches!(
            guard().evaluate(&plan, 150, None, None, d(9), d(10)),
            Err(ControlPlaneHostErrorV0::Protocol(
                ControlPlaneErrorV0::ForbiddenAuthorityAction
            ))
        ));
    }

    #[test]
    fn placement_and_critical_parameters_remain_uncommissioned() {
        let placement = plan(PlanActionV0::PlaceIsolatedWorker {
            module_id: 4,
            worker_profile_digest: d(20),
            placement_digest: d(21),
        });
        assert!(matches!(
            guard().evaluate(&placement, 150, None, None, d(9), d(10)),
            Err(ControlPlaneHostErrorV0::Protocol(
                ControlPlaneErrorV0::UnsupportedPlanAction
            ))
        ));
        let critical = plan(PlanActionV0::SetBoundedInteger {
            module_id: 4,
            parameter: b"ingress_queue_items".to_vec(),
            value: 1024,
            class: ParameterClassV0::DeterminismCritical,
        });
        assert!(matches!(
            guard().evaluate(&critical, 150, None, None, d(9), d(10)),
            Err(ControlPlaneHostErrorV0::Protocol(
                ControlPlaneErrorV0::UnsupportedPlanAction
            ))
        ));
    }

    #[test]
    fn duplicate_parameter_targets_fail_closed() {
        let action = PlanActionV0::SetBoundedInteger {
            module_id: 4,
            parameter: b"ingress_queue_items".to_vec(),
            value: 1024,
            class: ParameterClassV0::OperationalLocal,
        };
        let mut duplicate = plan(action.clone());
        duplicate.actions.push(action);
        duplicate.canonical_plan_digest = duplicate.canonical_digest();
        assert!(matches!(
            guard().evaluate(&duplicate, 150, None, None, d(9), d(10)),
            Err(ControlPlaneHostErrorV0::Protocol(
                ControlPlaneErrorV0::DuplicatePlanAction
            ))
        ));
    }
"""
control = replace_once(control, old_forbidden_test, new_forbidden_test, "control-plane tests changed")
control_path.write_text(control)


composition_path = Path("trillionnium/crates/trnm-poco-node-production-v0/src/lib.rs")
composition_path.write_text(r'''#![forbid(unsafe_code)]
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
            ProductionNodeCompositionV0::new(coordinator, IdleIo, StepBudgetV0::default())
                .unwrap();
        assert!(!PRODUCTION_COMPOSITION_OWNS_DOMAIN_STATE_V0);
        assert!(!PRODUCTION_COMPOSITION_ACTIVATION_V0);
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
''')
