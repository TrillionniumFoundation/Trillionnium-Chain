#![forbid(unsafe_code)]
//! Non-authoritative coordinator boundary for the production-shaped PoCO node.
//!
//! This crate owns no consensus state machine, key material, network listener,
//! storage namespace, or activation switch. It can only report the exact
//! fail-closed readiness exported by `trnm-poco-node` and delegate its static
//! activation gate.

use trnm_poco_node::{
    production_activation_gate_v0, ProductionActivationBlockedV0,
    HOST_IMPLEMENTATION_COMPLETE_V0, PRODUCTION_CANDIDATE_V0,
    UNWIRED_PRODUCTION_CONTRACTS_V0,
};

/// Immutable readiness facts visible to the composition layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NodeAuthorityReadinessV0 {
    production_candidate: bool,
    host_implementation_complete: bool,
    unwired_contract_count: usize,
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

    pub const fn activation_permitted(self) -> bool {
        self.production_candidate
            && self.host_implementation_complete
            && self.unwired_contract_count == 0
    }
}

/// The only authority-facing object available to the host composition crate.
///
/// The private field prevents callers from attaching hidden state. The type
/// deliberately exposes no sign, vote, finalize, apply, or state-root method.
#[derive(Debug, Default)]
pub struct NodeAuthorityCoordinatorV0 {
    _private: (),
}

impl NodeAuthorityCoordinatorV0 {
    pub const fn new() -> Self {
        Self { _private: () }
    }

    pub const fn readiness(&self) -> NodeAuthorityReadinessV0 {
        NodeAuthorityReadinessV0 {
            production_candidate: PRODUCTION_CANDIDATE_V0,
            host_implementation_complete: HOST_IMPLEMENTATION_COMPLETE_V0,
            unwired_contract_count: UNWIRED_PRODUCTION_CONTRACTS_V0.len(),
        }
    }

    pub const fn production_activation_gate(
        &self,
    ) -> Result<(), ProductionActivationBlockedV0> {
        production_activation_gate_v0()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coordinator_reports_the_underlying_fail_closed_truth() {
        let coordinator = NodeAuthorityCoordinatorV0::new();
        let readiness = coordinator.readiness();
        assert!(!readiness.production_candidate());
        assert!(!readiness.host_implementation_complete());
        assert!(readiness.unwired_contract_count() > 0);
        assert!(!readiness.activation_permitted());
        assert!(coordinator.production_activation_gate().is_err());
    }
}
