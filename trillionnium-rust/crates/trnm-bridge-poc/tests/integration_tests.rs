use trnm_bridge_poc::bridge_status::{
    BridgeStatus, CapabilityToken, SettlementCapability, SettlementError, SettlementRequest,
};

#[path = "integration_tests/workflow.rs"]
mod integration_tests_workflow;

#[path = "integration_tests/finalize.rs"]
mod integration_tests_finalize;

#[path = "integration_tests/revert.rs"]
mod integration_tests_revert;

#[path = "integration_tests/transition.rs"]
mod integration_tests_transition;

#[path = "integration_tests/validation.rs"]
mod integration_tests_validation;
