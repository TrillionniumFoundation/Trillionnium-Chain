use trnm_bridge_poc::bridge_status::{
    BridgeStatus, CapabilityToken, SettlementCapability, SettlementRequest,
};
use trnm_bridge_poc::relay_heartbeat::{RelayHeartbeatConfig, RelayHeartbeatMonitor};
use trnm_bridge_poc::x2_settlement_loop::{
    current_status, drive_minimal_settlement, SettlementConfirm, SettlementStep,
};

fn operator_token() -> CapabilityToken {
    CapabilityToken {
        subject: "did:trn:settlement-operator".to_string(),
        capabilities: vec![SettlementCapability::Finalize, SettlementCapability::Revert],
    }
}

#[path = "x2_settlement_loop/x2_core.rs"]
mod x2_settlement_loop_x2_core;

#[path = "x2_settlement_loop/x3_transition_guards.rs"]
mod x2_settlement_loop_x3_transition_guards;

#[path = "x2_settlement_loop/x3_confirm_reasons.rs"]
mod x2_settlement_loop_x3_confirm_reasons;

#[path = "x2_settlement_loop/x3_heartbeat_reasons.rs"]
mod x2_settlement_loop_x3_heartbeat_reasons;
