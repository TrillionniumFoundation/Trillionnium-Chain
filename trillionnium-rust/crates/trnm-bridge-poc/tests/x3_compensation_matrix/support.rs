pub use trnm_bridge_poc::bridge_status::{
    BridgeStatus, CapabilityToken, SettlementCapability, SettlementRequest,
};
pub use trnm_bridge_poc::relay_heartbeat::{HeartbeatOutcome, RelayHeartbeat};
pub use trnm_bridge_poc::x2_settlement_loop::{
    current_status, drive_minimal_settlement, SettlementConfirm, SettlementStep,
};

pub fn operator_token() -> CapabilityToken {
    CapabilityToken {
        subject: "did:trn:settlement-operator".to_string(),
        capabilities: vec![SettlementCapability::Finalize, SettlementCapability::Revert],
    }
}
