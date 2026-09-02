#![forbid(unsafe_code)]
//! Observer-first, non-authoritative control-plane protocol core.
//!
//! The control plane can register immutable descriptors, compare bounded
//! measurements, and propose signed plans.  A node-local guard is the final
//! authority for accepting a plan.  No API in this crate can sign, vote,
//! finalize, modify SafetyRules, create a state root, erase evidence, rewrite
//! history, bypass admission, or activate production.

use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, error::Error, fmt};

pub const CONTROL_PLANE_VERSION_V0: u16 = 0;
pub const MAX_MODULES_V0: usize = 64;
pub const MAX_PLAN_ACTIONS_V0: usize = 128;
pub const MAX_PARAMETER_NAME_BYTES_V0: usize = 128;
pub const MAX_DESCRIPTOR_CAPABILITIES_V0: usize = 256;
pub const MAX_RECEIPT_RESULTS_V0: usize = 128;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Digest32V0(pub [u8; 32]);

impl Digest32V0 {
    #[must_use]
    pub fn hash(domain: &[u8], parts: &[&[u8]]) -> Self {
        let mut h = Sha256::new();
        h.update((domain.len() as u64).to_be_bytes());
        h.update(domain);
        for part in parts {
            h.update((part.len() as u64).to_be_bytes());
            h.update(part);
        }
        Self(h.finalize().into())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModuleDescriptorV0 {
    pub module_id: u16,
    pub generation: u64,
    pub contract_digest: Digest32V0,
    pub implementation_digest: Digest32V0,
    pub dependency_graph_digest: Digest32V0,
    pub configuration_digest: Digest32V0,
    pub capability_digests: Vec<Digest32V0>,
    pub invariant_digest: Digest32V0,
    pub descriptor_digest: Digest32V0,
}

impl ModuleDescriptorV0 {
    #[must_use]
    pub fn canonical_digest(&self) -> Digest32V0 {
        let mut capabilities = self.capability_digests.clone();
        capabilities.sort_unstable();
        let mut h = Sha256::new();
        h.update(b"trnm.control.module-descriptor.v0");
        h.update(self.module_id.to_be_bytes());
        h.update(self.generation.to_be_bytes());
        h.update(self.contract_digest.0);
        h.update(self.implementation_digest.0);
        h.update(self.dependency_graph_digest.0);
        h.update(self.configuration_digest.0);
        h.update((capabilities.len() as u64).to_be_bytes());
        for capability in capabilities {
            h.update(capability.0);
        }
        h.update(self.invariant_digest.0);
        Digest32V0(h.finalize().into())
    }

    pub fn validate(&self) -> Result<(), ControlPlaneErrorV0> {
        if self.module_id >= MAX_MODULES_V0 as u16
            || self.generation == 0
            || self.capability_digests.len() > MAX_DESCRIPTOR_CAPABILITIES_V0
            || self.contract_digest == Digest32V0([0; 32])
            || self.implementation_digest == Digest32V0([0; 32])
            || self.dependency_graph_digest == Digest32V0([0; 32])
            || self.invariant_digest == Digest32V0([0; 32])
            || self.descriptor_digest != self.canonical_digest()
        {
            return Err(ControlPlaneErrorV0::InvalidDescriptor);
        }
        let mut sorted = self.capability_digests.clone();
        sorted.sort_unstable();
        sorted.dedup();
        if sorted.len() != self.capability_digests.len() {
            return Err(ControlPlaneErrorV0::DuplicateCapability);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WorkloadMeasurementV0 {
    pub workload_digest: Digest32V0,
    pub validity_region_digest: Digest32V0,
    pub committed_goodput_milli: u64,
    pub finality_p50_micros: u64,
    pub finality_p95_micros: u64,
    pub finality_p99_micros: u64,
    pub cpu_milli: u64,
    pub memory_bytes: u64,
    pub disk_bytes: u64,
    pub network_bytes: u64,
    pub queue_pressure_milli: u32,
    pub error_count: u64,
    pub drop_count: u64,
    pub recovery_cost_milli: u64,
    pub evidence_digest: Digest32V0,
}

impl WorkloadMeasurementV0 {
    pub fn validate(self) -> Result<Self, ControlPlaneErrorV0> {
        if self.workload_digest == Digest32V0([0; 32])
            || self.validity_region_digest == Digest32V0([0; 32])
            || self.evidence_digest == Digest32V0([0; 32])
            || self.finality_p50_micros > self.finality_p95_micros
            || self.finality_p95_micros > self.finality_p99_micros
            || self.queue_pressure_milli > 1000
        {
            return Err(ControlPlaneErrorV0::InvalidMeasurement);
        }
        Ok(self)
    }
}

#[derive(Default)]
pub struct ObserverRegistryV0 {
    modules: BTreeMap<u16, ModuleDescriptorV0>,
    measurements: BTreeMap<(u16, Digest32V0), WorkloadMeasurementV0>,
}

impl ObserverRegistryV0 {
    pub fn register(&mut self, descriptor: ModuleDescriptorV0) -> Result<(), ControlPlaneErrorV0> {
        descriptor.validate()?;
        if let Some(existing) = self.modules.get(&descriptor.module_id) {
            if descriptor.generation < existing.generation {
                return Err(ControlPlaneErrorV0::GenerationRollback);
            }
            if descriptor.generation == existing.generation {
                return if descriptor == *existing {
                    Ok(())
                } else {
                    Err(ControlPlaneErrorV0::DescriptorSubstitution)
                };
            }
        }
        self.modules.insert(descriptor.module_id, descriptor);
        Ok(())
    }

    pub fn observe(
        &mut self,
        module_id: u16,
        measurement: WorkloadMeasurementV0,
    ) -> Result<(), ControlPlaneErrorV0> {
        if !self.modules.contains_key(&module_id) {
            return Err(ControlPlaneErrorV0::UnknownModule);
        }
        let measurement = measurement.validate()?;
        let key = (module_id, measurement.workload_digest);
        if let Some(existing) = self.measurements.get(&key) {
            return if *existing == measurement {
                Ok(())
            } else {
                Err(ControlPlaneErrorV0::MeasurementSubstitution)
            };
        }
        self.measurements.insert(key, measurement);
        Ok(())
    }

    #[must_use]
    pub fn descriptor(&self, module_id: u16) -> Option<&ModuleDescriptorV0> {
        self.modules.get(&module_id)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParameterClassV0 {
    OperationalLocal,
    DeterminismCritical,
    ConsensusCritical,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ForbiddenAuthorityActionV0 {
    Sign,
    Vote,
    Finalize,
    ModifySafetyRules,
    CreateStateRoot,
    BypassAdmission,
    EraseEvidence,
    RewriteHistory,
    ForceIncompatibleStartup,
    ActivateProduction,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PlanActionV0 {
    SetBoundedInteger {
        module_id: u16,
        parameter: Vec<u8>,
        value: i128,
        class: ParameterClassV0,
    },
    PlaceIsolatedWorker {
        module_id: u16,
        worker_profile_digest: Digest32V0,
        placement_digest: Digest32V0,
    },
    Forbidden(ForbiddenAuthorityActionV0),
}

impl PlanActionV0 {
    #[must_use]
    pub fn canonical_digest(&self) -> Digest32V0 {
        match self {
            Self::SetBoundedInteger {
                module_id,
                parameter,
                value,
                class,
            } => Digest32V0::hash(
                b"trnm.control.action.set-bounded-integer.v0",
                &[
                    &module_id.to_be_bytes(),
                    parameter,
                    &value.to_be_bytes(),
                    &[match class {
                        ParameterClassV0::OperationalLocal => 0,
                        ParameterClassV0::DeterminismCritical => 1,
                        ParameterClassV0::ConsensusCritical => 2,
                    }],
                ],
            ),
            Self::PlaceIsolatedWorker {
                module_id,
                worker_profile_digest,
                placement_digest,
            } => Digest32V0::hash(
                b"trnm.control.action.place-worker.v0",
                &[
                    &module_id.to_be_bytes(),
                    &worker_profile_digest.0,
                    &placement_digest.0,
                ],
            ),
            Self::Forbidden(action) => {
                Digest32V0::hash(b"trnm.control.action.forbidden.v0", &[&[*action as u8]])
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OptimizationPlanV1 {
    pub plan_id: Digest32V0,
    pub source_graph_digest: Digest32V0,
    pub contract_set_digest: Digest32V0,
    pub workload_assumption_digest: Digest32V0,
    pub expected_effect_digest: Digest32V0,
    pub rollback_plan_digest: Digest32V0,
    pub issued_generation: u64,
    pub not_before_height: u64,
    pub expires_after_height: u64,
    pub actions: Vec<PlanActionV0>,
    pub signer_id: Digest32V0,
    pub signature_digest: Digest32V0,
    pub canonical_plan_digest: Digest32V0,
}

impl OptimizationPlanV1 {
    #[must_use]
    pub fn canonical_digest(&self) -> Digest32V0 {
        let mut h = Sha256::new();
        h.update(b"trnm.control.optimization-plan.v1");
        h.update(self.plan_id.0);
        h.update(self.source_graph_digest.0);
        h.update(self.contract_set_digest.0);
        h.update(self.workload_assumption_digest.0);
        h.update(self.expected_effect_digest.0);
        h.update(self.rollback_plan_digest.0);
        h.update(self.issued_generation.to_be_bytes());
        h.update(self.not_before_height.to_be_bytes());
        h.update(self.expires_after_height.to_be_bytes());
        h.update((self.actions.len() as u64).to_be_bytes());
        for action in &self.actions {
            h.update(action.canonical_digest().0);
        }
        h.update(self.signer_id.0);
        Digest32V0(h.finalize().into())
    }

    pub fn validate_shape(&self) -> Result<(), ControlPlaneErrorV0> {
        if self.plan_id == Digest32V0([0; 32])
            || self.source_graph_digest == Digest32V0([0; 32])
            || self.contract_set_digest == Digest32V0([0; 32])
            || self.workload_assumption_digest == Digest32V0([0; 32])
            || self.expected_effect_digest == Digest32V0([0; 32])
            || self.rollback_plan_digest == Digest32V0([0; 32])
            || self.issued_generation == 0
            || self.not_before_height == 0
            || self.expires_after_height < self.not_before_height
            || self.actions.is_empty()
            || self.actions.len() > MAX_PLAN_ACTIONS_V0
            || self.signer_id == Digest32V0([0; 32])
            || self.signature_digest == Digest32V0([0; 32])
            || self.canonical_plan_digest != self.canonical_digest()
        {
            return Err(ControlPlaneErrorV0::InvalidPlan);
        }
        for action in &self.actions {
            if let PlanActionV0::SetBoundedInteger { parameter, .. } = action {
                if parameter.is_empty() || parameter.len() > MAX_PARAMETER_NAME_BYTES_V0 {
                    return Err(ControlPlaneErrorV0::InvalidParameter);
                }
            }
        }
        Ok(())
    }
}

pub trait PlanSignatureVerifierV0 {
    type Error: Error + Send + Sync + 'static;

    fn verify_plan_signature(&self, plan: &OptimizationPlanV1) -> Result<(), Self::Error>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GovernanceAuthorizationV0 {
    pub plan_digest: Digest32V0,
    pub activation_height: u64,
    pub validator_set_digest: Digest32V0,
    pub authorization_digest: Digest32V0,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeterminismEvidenceV0 {
    pub plan_digest: Digest32V0,
    pub shadow_replay_digest: Digest32V0,
    pub worker_invariance_digest: Digest32V0,
    pub pre_root: Digest32V0,
    pub post_root: Digest32V0,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParameterBoundV0 {
    pub module_id: u16,
    pub parameter: Vec<u8>,
    pub minimum: i128,
    pub maximum: i128,
    pub class: ParameterClassV0,
}

impl ParameterBoundV0 {
    pub fn validate(&self) -> Result<(), ControlPlaneErrorV0> {
        if self.module_id >= MAX_MODULES_V0 as u16
            || self.parameter.is_empty()
            || self.parameter.len() > MAX_PARAMETER_NAME_BYTES_V0
            || self.minimum > self.maximum
        {
            return Err(ControlPlaneErrorV0::InvalidParameterBound);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActionDecisionV0 {
    Accepted,
    Rejected(ControlPlaneErrorV0),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActionResultV0 {
    pub action_digest: Digest32V0,
    pub decision: ActionDecisionV0,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActionReceiptV1 {
    pub plan_digest: Digest32V0,
    pub accepted_generation: u64,
    pub source_graph_digest: Digest32V0,
    pub resulting_configuration_digest: Digest32V0,
    pub invariant_result_digest: Digest32V0,
    pub action_results: Vec<ActionResultV0>,
    pub accepted: bool,
    pub receipt_digest: Digest32V0,
}

impl ActionReceiptV1 {
    #[must_use]
    pub fn canonical_digest(&self) -> Digest32V0 {
        let mut h = Sha256::new();
        h.update(b"trnm.control.action-receipt.v1");
        h.update(self.plan_digest.0);
        h.update(self.accepted_generation.to_be_bytes());
        h.update(self.source_graph_digest.0);
        h.update(self.resulting_configuration_digest.0);
        h.update(self.invariant_result_digest.0);
        h.update([u8::from(self.accepted)]);
        for result in &self.action_results {
            h.update(result.action_digest.0);
            match result.decision {
                ActionDecisionV0::Accepted => h.update([0]),
                ActionDecisionV0::Rejected(error) => {
                    h.update([1]);
                    h.update((error as u16).to_be_bytes());
                }
            }
        }
        Digest32V0(h.finalize().into())
    }
}

pub struct LocalPlanGuardV0<V> {
    signature_verifier: V,
    source_graph_digest: Digest32V0,
    contract_set_digest: Digest32V0,
    current_generation: u64,
    bounds: BTreeMap<(u16, Vec<u8>), ParameterBoundV0>,
}

impl<V> LocalPlanGuardV0<V>
where
    V: PlanSignatureVerifierV0,
{
    pub fn new(
        signature_verifier: V,
        source_graph_digest: Digest32V0,
        contract_set_digest: Digest32V0,
        current_generation: u64,
        bounds: Vec<ParameterBoundV0>,
    ) -> Result<Self, ControlPlaneErrorV0> {
        if source_graph_digest == Digest32V0([0; 32])
            || contract_set_digest == Digest32V0([0; 32])
            || current_generation == 0
        {
            return Err(ControlPlaneErrorV0::InvalidGuardConfiguration);
        }
        let mut bound_map = BTreeMap::new();
        for bound in bounds {
            bound.validate()?;
            let key = (bound.module_id, bound.parameter.clone());
            if bound_map.insert(key, bound).is_some() {
                return Err(ControlPlaneErrorV0::DuplicateParameterBound);
            }
        }
        Ok(Self {
            signature_verifier,
            source_graph_digest,
            contract_set_digest,
            current_generation,
            bounds: bound_map,
        })
    }

    pub fn evaluate(
        &self,
        plan: &OptimizationPlanV1,
        current_height: u64,
        governance: Option<GovernanceAuthorizationV0>,
        determinism: Option<DeterminismEvidenceV0>,
        resulting_configuration_digest: Digest32V0,
        invariant_result_digest: Digest32V0,
    ) -> Result<ActionReceiptV1, ControlPlaneHostErrorV0<V::Error>> {
        plan.validate_shape()
            .map_err(ControlPlaneHostErrorV0::Protocol)?;
        self.signature_verifier
            .verify_plan_signature(plan)
            .map_err(ControlPlaneHostErrorV0::Signature)?;
        if plan.source_graph_digest != self.source_graph_digest
            || plan.contract_set_digest != self.contract_set_digest
        {
            return Err(ControlPlaneHostErrorV0::Protocol(
                ControlPlaneErrorV0::SourceGraphMismatch,
            ));
        }
        if plan.issued_generation != self.current_generation.saturating_add(1) {
            return Err(ControlPlaneHostErrorV0::Protocol(
                ControlPlaneErrorV0::GenerationMismatch,
            ));
        }
        if current_height < plan.not_before_height || current_height > plan.expires_after_height {
            return Err(ControlPlaneHostErrorV0::Protocol(
                ControlPlaneErrorV0::PlanOutsideActivationWindow,
            ));
        }
        if resulting_configuration_digest == Digest32V0([0; 32])
            || invariant_result_digest == Digest32V0([0; 32])
        {
            return Err(ControlPlaneHostErrorV0::Protocol(
                ControlPlaneErrorV0::InvalidReceiptFacts,
            ));
        }

        let mut results = Vec::with_capacity(plan.actions.len());
        let mut all_accepted = true;
        for action in &plan.actions {
            let decision = match action {
                PlanActionV0::Forbidden(_) => {
                    ActionDecisionV0::Rejected(ControlPlaneErrorV0::ForbiddenAuthorityAction)
                }
                PlanActionV0::PlaceIsolatedWorker {
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
                PlanActionV0::SetBoundedInteger {
                    module_id,
                    parameter,
                    value,
                    class,
                } => {
                    let Some(bound) = self.bounds.get(&(*module_id, parameter.clone())) else {
                        results.push(ActionResultV0 {
                            action_digest: action.canonical_digest(),
                            decision: ActionDecisionV0::Rejected(
                                ControlPlaneErrorV0::UnknownParameter,
                            ),
                        });
                        all_accepted = false;
                        continue;
                    };
                    if *class != bound.class || *value < bound.minimum || *value > bound.maximum {
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
                }
            };
            if !matches!(decision, ActionDecisionV0::Accepted) {
                all_accepted = false;
            }
            results.push(ActionResultV0 {
                action_digest: action.canonical_digest(),
                decision,
            });
        }
        if results.len() > MAX_RECEIPT_RESULTS_V0 {
            return Err(ControlPlaneHostErrorV0::Protocol(
                ControlPlaneErrorV0::ReceiptOutOfBounds,
            ));
        }
        let mut receipt = ActionReceiptV1 {
            plan_digest: plan.canonical_plan_digest,
            accepted_generation: plan.issued_generation,
            source_graph_digest: self.source_graph_digest,
            resulting_configuration_digest,
            invariant_result_digest,
            action_results: results,
            accepted: all_accepted,
            receipt_digest: Digest32V0([0; 32]),
        };
        receipt.receipt_digest = receipt.canonical_digest();
        Ok(receipt)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum ControlPlaneErrorV0 {
    InvalidDescriptor = 1,
    DuplicateCapability = 2,
    GenerationRollback = 3,
    DescriptorSubstitution = 4,
    InvalidMeasurement = 5,
    UnknownModule = 6,
    MeasurementSubstitution = 7,
    InvalidPlan = 8,
    InvalidParameter = 9,
    InvalidParameterBound = 10,
    DuplicateParameterBound = 11,
    InvalidGuardConfiguration = 12,
    SourceGraphMismatch = 13,
    GenerationMismatch = 14,
    PlanOutsideActivationWindow = 15,
    InvalidReceiptFacts = 16,
    ForbiddenAuthorityAction = 17,
    InvalidPlacement = 18,
    UnknownParameter = 19,
    ParameterOutOfBounds = 20,
    MissingDeterminismEvidence = 21,
    MissingGovernanceAuthorization = 22,
    ReceiptOutOfBounds = 23,
}

impl fmt::Display for ControlPlaneErrorV0 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidDescriptor => "invalid module descriptor",
            Self::DuplicateCapability => "module descriptor repeats a capability",
            Self::GenerationRollback => "module descriptor generation rollback",
            Self::DescriptorSubstitution => "same-generation module descriptor substitution",
            Self::InvalidMeasurement => "invalid workload measurement",
            Self::UnknownModule => "measurement references an unknown module",
            Self::MeasurementSubstitution => "same workload measurement key has different facts",
            Self::InvalidPlan => "invalid optimization plan",
            Self::InvalidParameter => "invalid parameter name",
            Self::InvalidParameterBound => "invalid local parameter bound",
            Self::DuplicateParameterBound => "duplicate local parameter bound",
            Self::InvalidGuardConfiguration => "invalid local guard configuration",
            Self::SourceGraphMismatch => "plan source graph or contract set mismatch",
            Self::GenerationMismatch => "plan generation is not the exact successor",
            Self::PlanOutsideActivationWindow => "plan is outside its bounded activation window",
            Self::InvalidReceiptFacts => "resulting configuration or invariant facts are invalid",
            Self::ForbiddenAuthorityAction => {
                "control plane requested a forbidden authority action"
            }
            Self::InvalidPlacement => "invalid isolated-worker placement",
            Self::UnknownParameter => "parameter is not locally allowlisted",
            Self::ParameterOutOfBounds => "parameter value or class is outside the local bound",
            Self::MissingDeterminismEvidence => {
                "determinism-critical action lacks root-invariance evidence"
            }
            Self::MissingGovernanceAuthorization => {
                "consensus-critical action lacks governance authorization"
            }
            Self::ReceiptOutOfBounds => "action receipt exceeds its result bound",
        })
    }
}

impl Error for ControlPlaneErrorV0 {}

#[derive(Debug)]
pub enum ControlPlaneHostErrorV0<SignatureError> {
    Protocol(ControlPlaneErrorV0),
    Signature(SignatureError),
}

impl<S: fmt::Display> fmt::Display for ControlPlaneHostErrorV0<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Protocol(error) => write!(f, "local control-plane guard rejected plan: {error}"),
            Self::Signature(error) => write!(f, "optimization-plan signature failed: {error}"),
        }
    }
}

impl<S> Error for ControlPlaneHostErrorV0<S> where S: Error + 'static {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::convert::Infallible;

    fn d(byte: u8) -> Digest32V0 {
        Digest32V0([byte; 32])
    }

    struct AcceptSignature;
    impl PlanSignatureVerifierV0 for AcceptSignature {
        type Error = Infallible;
        fn verify_plan_signature(&self, _plan: &OptimizationPlanV1) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    fn plan(action: PlanActionV0) -> OptimizationPlanV1 {
        let mut value = OptimizationPlanV1 {
            plan_id: d(1),
            source_graph_digest: d(2),
            contract_set_digest: d(3),
            workload_assumption_digest: d(4),
            expected_effect_digest: d(5),
            rollback_plan_digest: d(6),
            issued_generation: 8,
            not_before_height: 100,
            expires_after_height: 200,
            actions: vec![action],
            signer_id: d(7),
            signature_digest: d(8),
            canonical_plan_digest: d(0),
        };
        value.canonical_plan_digest = value.canonical_digest();
        value
    }

    fn guard() -> LocalPlanGuardV0<AcceptSignature> {
        LocalPlanGuardV0::new(
            AcceptSignature,
            d(2),
            d(3),
            7,
            vec![ParameterBoundV0 {
                module_id: 4,
                parameter: b"ingress_queue_items".to_vec(),
                minimum: 32,
                maximum: 4096,
                class: ParameterClassV0::OperationalLocal,
            }],
        )
        .unwrap()
    }

    #[test]
    fn bounded_operational_plan_is_accepted() {
        let plan = plan(PlanActionV0::SetBoundedInteger {
            module_id: 4,
            parameter: b"ingress_queue_items".to_vec(),
            value: 1024,
            class: ParameterClassV0::OperationalLocal,
        });
        let receipt = guard()
            .evaluate(&plan, 150, None, None, d(9), d(10))
            .unwrap();
        assert!(receipt.accepted);
        assert_eq!(receipt.receipt_digest, receipt.canonical_digest());
    }

    #[test]
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

    #[test]
    fn same_generation_descriptor_substitution_fails_closed() {
        let mut descriptor = ModuleDescriptorV0 {
            module_id: 4,
            generation: 1,
            contract_digest: d(1),
            implementation_digest: d(2),
            dependency_graph_digest: d(3),
            configuration_digest: d(4),
            capability_digests: vec![d(5)],
            invariant_digest: d(6),
            descriptor_digest: d(0),
        };
        descriptor.descriptor_digest = descriptor.canonical_digest();
        let mut registry = ObserverRegistryV0::default();
        registry.register(descriptor.clone()).unwrap();
        descriptor.configuration_digest = d(9);
        descriptor.descriptor_digest = descriptor.canonical_digest();
        assert_eq!(
            registry.register(descriptor).unwrap_err(),
            ControlPlaneErrorV0::DescriptorSubstitution
        );
    }
}
