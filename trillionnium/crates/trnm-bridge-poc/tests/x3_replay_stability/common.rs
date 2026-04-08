pub(super) use trnm_bridge_poc::bridge_status::{
    BridgeStatus, CapabilityToken, SettlementCapability, SettlementRequest,
};
pub(super) use trnm_bridge_poc::relay_heartbeat::{
    HeartbeatOutcome, RelayHeartbeatConfig, RelayHeartbeatMonitor,
};
pub(super) use trnm_bridge_poc::x2_settlement_loop::{
    current_status, drive_minimal_settlement, SettlementConfirm, SettlementStep,
};

pub(super) fn operator_token() -> CapabilityToken {
    CapabilityToken {
        subject: "did:trn:settlement-operator".to_string(),
        capabilities: vec![SettlementCapability::Finalize, SettlementCapability::Revert],
    }
}

pub(super) fn healthy_outcome() -> HeartbeatOutcome {
    HeartbeatOutcome {
        heartbeat: None,
        should_retry: false,
        degraded: false,
        message: "healthy".to_string(),
    }
}
