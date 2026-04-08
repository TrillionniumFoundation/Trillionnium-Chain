pub(crate) use trnm_bridge_poc::bridge_status::{
    BridgeStatus, CapabilityToken, SettlementCapability, SettlementRequest,
};
pub(crate) use trnm_bridge_poc::relay_heartbeat::{RelayHeartbeatConfig, RelayHeartbeatMonitor};
pub(crate) use trnm_bridge_poc::x2_settlement_loop::{
    current_status, drive_minimal_settlement, SettlementConfirm, SettlementStep,
};

pub(crate) fn operator_token() -> CapabilityToken {
    CapabilityToken {
        subject: "did:trn:settlement-operator".to_string(),
        capabilities: vec![SettlementCapability::Finalize, SettlementCapability::Revert],
    }
}
