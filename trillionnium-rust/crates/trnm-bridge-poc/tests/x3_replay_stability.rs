use trnm_bridge_poc::bridge_status::{
    BridgeStatus, CapabilityToken, SettlementCapability, SettlementRequest,
};
use trnm_bridge_poc::relay_heartbeat::{
    HeartbeatOutcome, RelayHeartbeatConfig, RelayHeartbeatMonitor,
};
use trnm_bridge_poc::x2_settlement_loop::{
    current_status, drive_minimal_settlement, SettlementConfirm, SettlementStep,
};

fn operator_token() -> CapabilityToken {
    CapabilityToken {
        subject: "did:trn:settlement-operator".to_string(),
        capabilities: vec![SettlementCapability::Finalize, SettlementCapability::Revert],
    }
}

#[path = "x3_replay_stability/x3_replay_stability_degraded.rs"]
mod x3_replay_stability_x3_replay_stability_degraded;

#[path = "x3_replay_stability/x3_replay_stability_confirm.rs"]
mod x3_replay_stability_x3_replay_stability_confirm;

#[path = "x3_replay_stability/x3_replay_stability_finalize.rs"]
mod x3_replay_stability_x3_replay_stability_finalize;
