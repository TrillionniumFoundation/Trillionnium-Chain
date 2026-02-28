use crate::bridge_status::{BridgeStatus, CapabilityToken, SettlementError, SettlementRequest};
use crate::relay_heartbeat::HeartbeatOutcome;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SettlementConfirm {
    Confirmed { height: u64 },
    Failed { reason: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SettlementStep {
    Finalized { height: u64 },
    Compensated { reason: String },
}

pub fn drive_minimal_settlement(
    request: &mut SettlementRequest,
    token: &CapabilityToken,
    heartbeat: &HeartbeatOutcome,
    confirm: SettlementConfirm,
) -> Result<SettlementStep, SettlementError> {
    if heartbeat.degraded {
        let reason = format!("heartbeat degraded: {}", heartbeat.message);
        request.revert_authorized(token, reason.clone())?;
        return Ok(SettlementStep::Compensated { reason });
    }

    match confirm {
        SettlementConfirm::Confirmed { height } => {
            request.settle_authorized(token, height)?;
            Ok(SettlementStep::Finalized { height })
        }
        SettlementConfirm::Failed { reason } => {
            let reason = format!("settlement confirm failed: {reason}");
            request.revert_authorized(token, reason.clone())?;
            Ok(SettlementStep::Compensated { reason })
        }
    }
}

pub fn current_status(request: &SettlementRequest) -> &BridgeStatus {
    &request.status
}
