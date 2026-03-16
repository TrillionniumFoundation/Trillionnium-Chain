use trnm_bridge_poc::bridge_status::{
    BridgeStatus, CapabilityToken, SettlementCapability, SettlementRequest,
};
use trnm_bridge_poc::relay_heartbeat::{HeartbeatOutcome, RelayHeartbeat};
use trnm_bridge_poc::x2_settlement_loop::{
    current_status, drive_minimal_settlement, SettlementConfirm, SettlementStep,
};

fn operator_token() -> CapabilityToken {
    CapabilityToken {
        subject: "did:trn:settlement-operator".to_string(),
        capabilities: vec![SettlementCapability::Finalize, SettlementCapability::Revert],
    }
}

#[path = "x3_compensation_matrix/x3_compensation_matrix_core.rs"]
mod x3_compensation_matrix_core;

#[path = "x3_compensation_matrix/x3_compensation_matrix_sanitization.rs"]
mod x3_compensation_matrix_sanitization;
